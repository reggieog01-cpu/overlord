//! Streaming pipeline: DXGI Desktop Duplication of the virtual display,
//! GPU BGRA→NV12 conversion via the D3D11 video processor, and H.264 encode
//! through the Media Foundation H.264 MFT (hardware preferred, software
//! fallback). Everything COM lives and dies on the capture thread.
//!
//! Latency rules: never queue frames (encode the newest, drop the rest),
//! no B-frames, IDR on start/join/loss, base64 JSON events out.

use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::Receiver;

use base64::Engine;
use windows::core::Interface;
use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{CoCreateInstance, CoTaskMemFree, CLSCTX_INPROC_SERVER};
use windows::Win32::System::Variant::{VARIANT, VARIANT_0_0_0, VT_I4, VT_BOOL};

use crate::display;
use crate::{send_json, status};

pub struct StreamConfig {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
    /// Side-channel binary WS for frames (empty = fall back to plugin events).
    pub ws_url: String,
}

pub enum Command {
    Stop,
}

pub static KEYFRAME_REQUESTED: AtomicBool = AtomicBool::new(false);
pub static STREAMING: AtomicBool = AtomicBool::new(false);
pub static FRAMES_SENT: AtomicU32 = AtomicU32::new(0);
pub static FRAMES_ACQUIRED: AtomicU32 = AtomicU32::new(0);

fn variant_bool(b: bool) -> VARIANT {
    unsafe {
        let mut v: VARIANT = std::mem::zeroed();
        let inner = &mut *v.Anonymous.Anonymous;
        inner.vt = VT_BOOL;
        inner.Anonymous = VARIANT_0_0_0 {
            boolVal: windows::Win32::Foundation::VARIANT_BOOL(if b { -1 } else { 0 }),
        };
        v
    }
}

fn variant_i32(n: i32) -> VARIANT {
    unsafe {
        let mut v: VARIANT = std::mem::zeroed();
        let inner = &mut *v.Anonymous.Anonymous;
        inner.vt = VT_I4;
        inner.Anonymous = VARIANT_0_0_0 { lVal: n };
        v
    }
}

/// Entry point — runs on its own thread until a Stop command or fatal error.
pub fn run(cfg: StreamConfig, cmd_rx: Receiver<Command>) {
    run_with_target(cfg, cmd_rx, None);
}

/// Dev harness variant: duplicate a specific output by device name instead of
/// attaching the virtual display.
pub fn run_with_target(cfg: StreamConfig, cmd_rx: Receiver<Command>, target: Option<String>) {
    STREAMING.store(true, Ordering::SeqCst);
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_inner(cfg, cmd_rx, target)));
    STREAMING.store(false, Ordering::SeqCst);
    // Always return the machine to its original display topology.
    display::detach_display();
    match result {
        Ok(Ok(())) => status("stopped"),
        Ok(Err(e)) => {
            send_json("vmon_status", &serde_json::json!({ "stage": "error", "message": e }))
        }
        Err(_) => send_json(
            "vmon_status",
            &serde_json::json!({ "stage": "error", "message": "capture thread panicked" }),
        ),
    }
}

fn run_inner(cfg: StreamConfig, cmd_rx: Receiver<Command>, target: Option<String>) -> Result<(), String> {
    let (disp_name, far_x, far_y) = if let Some(t) = target {
        (t, i32::MIN, i32::MIN)
    } else {
        status("attach_display");
        let (name, x, y) = display::ensure_display(cfg.width, cfg.height)?;
        send_json(
            "vmon_status",
            &serde_json::json!({ "stage": "display", "device": name, "x": x, "y": y }),
        );
        (name, x, y)
    };
    let disp_name = disp_name;

    status("init_capture");
    let mut cap = Duplication::new(&disp_name, far_x, far_y)?;
    crate::DISP_X.store(cap.pos_x, Ordering::SeqCst);
    crate::DISP_Y.store(cap.pos_y, Ordering::SeqCst);
    crate::DISP_W.store(cap.width as i32, Ordering::SeqCst);
    crate::DISP_H.store(cap.height as i32, Ordering::SeqCst);

    status("init_encoder");
    let mut enc = Encoder::new(cap.width, cap.height, cfg.fps, cfg.bitrate_kbps)?;
    if let Some(sh) = enc.sequence_header() {
        send_json(
            "vmon_config",
            &serde_json::json!({
                "codec": "h264",
                "width": cap.width,
                "height": cap.height,
                "seqhdr": base64::engine::general_purpose::STANDARD.encode(sh),
            }),
        );
    }
    status("streaming");

    // Side-channel binary transport for frames; plugin events stay for
    // control/status. If it won't connect, we simply stream nothing on the
    // side channel and report it.
    let mut channel = if cfg.ws_url.is_empty() {
        None
    } else {
        let ch = crate::wsclient::SideChannel::connect(&cfg.ws_url);
        if ch.is_none() {
            send_json("vmon_status", &serde_json::json!({ "stage": "error", "message": "side-channel connect failed" }));
        }
        ch
    };

    let frame_interval = std::time::Duration::from_millis((1000 / cfg.fps.max(1)) as u64);
    let mut seq: u32 = 0;
    let mut last_frame: Option<Vec<u8>> = None;

    loop {
        match cmd_rx.try_recv() {
            Ok(Command::Stop) => return Ok(()),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return Ok(()),
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }

        let nv12_opt = cap.acquire(frame_interval)?;
        let nv12 = match nv12_opt {
            Some(f) => {
                FRAMES_ACQUIRED.fetch_add(1, Ordering::SeqCst);
                last_frame = Some(f.clone());
                Some(f)
            }
            None => {
                // No desktop change. If the MFT still owes us frames (its
                // lookahead) OR a viewer just requested a keyframe (e.g. a
                // late-joining panel), re-feed the last frame to produce it;
                // identical inputs compress to tiny deltas. Otherwise go
                // fully idle — zero work on a static screen.
                if enc.pending() > 0 || KEYFRAME_REQUESTED.load(Ordering::SeqCst) {
                    last_frame.clone()
                } else {
                    None
                }
            }
        };

        if let Some(nv12) = nv12 {
            if KEYFRAME_REQUESTED.swap(false, Ordering::SeqCst) {
                enc.force_keyframe();
                // Re-emit the decoder config too: late-joining viewers need
                // the sequence header before they can decode anything.
                if let Some(sh) = enc.sequence_header() {
                    send_json(
                        "vmon_config",
                        &serde_json::json!({
                            "codec": "h264",
                            "width": cap.width,
                            "height": cap.height,
                            "seqhdr": base64::engine::general_purpose::STANDARD.encode(sh),
                        }),
                    );
                }
            }
            if let Some(au) = enc.encode(&nv12)? {
                seq = seq.wrapping_add(1);
                let mut delivered = false;
                if let Some(ch) = channel.as_mut() {
                    if crate::wsclient::SideChannel::degraded() {
                        // Link is backing up - drop this frame, never queue.
                        continue;
                    }
                    // Frame format: [key:u8][annexb access unit]
                    let mut framed = Vec::with_capacity(au.data.len() + 1);
                    framed.push(if au.keyframe { 1u8 } else { 0u8 });
                    framed.extend_from_slice(&au.data);
                    delivered = ch.send_binary(&framed);
                }
                if !delivered && channel.is_none() {
                    // No side channel: fall back to the base64 event path.
                    send_json(
                        "vmon_frame",
                        &serde_json::json!({
                            "seq": seq,
                            "key": au.keyframe,
                            "ts": au.timestamp_ms,
                            "data": base64::engine::general_purpose::STANDARD.encode(&au.data),
                        }),
                    );
                }
                FRAMES_SENT.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DXGI Desktop Duplication
// ---------------------------------------------------------------------------

struct Duplication {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    output: IDXGIOutput,
    dup: IDXGIOutputDuplication,
    staging: ID3D11Texture2D,
    // GPU color-conversion path (None when the adapter lacks video support —
    // e.g. the indirect display adapter — and we convert on CPU instead).
    vp: Option<ID3D11VideoProcessor>,
    vp_enum: Option<ID3D11VideoProcessorEnumerator>,
    vp_ctx: Option<ID3D11VideoContext1>,
    vp_dev: Option<ID3D11VideoDevice>,
    nv12_out: Option<ID3D11Texture2D>,
    staging_bgra: Option<ID3D11Texture2D>,
    width: u32,
    height: u32,
    // Actual output size before even-rounding (frames from duplication come
    // in at this size; NV12 buffers are width?-height).
    real_w: u32,
    real_h: u32,
    // Actual desktop position of the output — input translation and window
    // placement must use this, NOT the requested attach position.
    pos_x: i32,
    pos_y: i32,
}

impl Duplication {
    pub fn new(device_name: &str, far_x: i32, far_y: i32) -> Result<Self, String> {
        unsafe {
            // Find the DXGI output matching our virtual display.
            let dxgi: IDXGIFactory1 =
                CreateDXGIFactory1().map_err(|e| format!("CreateDXGIFactory1: {}", e))?;
            let mut adapter_out: Option<IDXGIAdapter1> = None;
            let mut output_out: Option<IDXGIOutput> = None;
            'outer: for ai in 0..16 {
                let Ok(adapter) = dxgi.EnumAdapters1(ai) else { break };
                for oi in 0..16 {
                    let Ok(output) = adapter.EnumOutputs(oi) else { break };
                    let desc = output.GetDesc().map_err(|e| e.to_string())?;
                    let name_len = desc
                        .DeviceName
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(desc.DeviceName.len());
                    let name = String::from_utf16_lossy(&desc.DeviceName[..name_len]);
                    let r = desc.DesktopCoordinates;
                    // Tolerant match: exact name, trailing DISPLAYn token, or
                    // the far-off coordinates of our virtual display.
                    let name_hit = name == device_name
                        || (device_name.len() >= 8
                            && name
                                .to_uppercase()
                                .ends_with(&device_name[device_name.len() - 8..].to_uppercase()));
                    if name_hit || (r.left == far_x && r.top == far_y) {
                        adapter_out = Some(adapter.clone());
                        output_out = Some(output);
                        break 'outer;
                    }
                }
            }
            // Fallback: no name/coord match - take the attached output whose
            // ADAPTER description marks it as the virtual/indirect display.
            if output_out.is_none() {
                'outer2: for ai in 0..16 {
                    let Ok(adapter) = dxgi.EnumAdapters1(ai) else { break };
                    let adesc = adapter.GetDesc1().map_err(|e| e.to_string())?;
                    let dlen = adesc
                        .Description
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(adesc.Description.len());
                    let adname = String::from_utf16_lossy(&adesc.Description[..dlen]).to_lowercase();
                    if !(adname.contains("virtual") || adname.contains("mttvdd") || adname.contains("indirect")) {
                        continue;
                    }
                    for oi in 0..16 {
                        let Ok(output) = adapter.EnumOutputs(oi) else { break };
                        let desc = output.GetDesc().map_err(|e| e.to_string())?;
                        if desc.AttachedToDesktop.as_bool() {
                            adapter_out = Some(adapter.clone());
                            output_out = Some(output);
                            break 'outer2;
                        }
                    }
                }
            }
            let adapter = adapter_out.ok_or("virtual output not found on any adapter")?;
            let output = output_out.ok_or("virtual output missing")?;

            let flag_candidates = [
                D3D11_CREATE_DEVICE_VIDEO_SUPPORT | D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                D3D11_CREATE_DEVICE_FLAG(0),
            ];
            let mut device: Option<ID3D11Device> = None;
            let mut context: Option<ID3D11DeviceContext> = None;
            let mut has_video = true;
            let mut last_err = String::new();
            for (i, flags) in flag_candidates.iter().enumerate() {
                let mut d: Option<ID3D11Device> = None;
                let mut c: Option<ID3D11DeviceContext> = None;
                match D3D11CreateDevice(
                    &adapter,
                    D3D_DRIVER_TYPE_UNKNOWN,
                    windows::Win32::Foundation::HMODULE::default(),
                    *flags,
                    None,
                    D3D11_SDK_VERSION,
                    Some(&mut d),
                    None,
                    Some(&mut c),
                ) {
                    Ok(()) if d.is_some() && c.is_some() => {
                        device = d;
                        context = c;
                        has_video = i == 0;
                        break;
                    }
                    r => {
                        last_err = r.err().map(|e| e.to_string()).unwrap_or_default();
                    }
                }
            }
            let device = device.ok_or_else(|| format!("D3D11CreateDevice: {}", last_err))?;
            let context = context.ok_or("no d3d11 context")?;

            let output1: IDXGIOutput1 = output.cast().map_err(|e| e.to_string())?;
            let dup = output1
                .DuplicateOutput(&device)
                .map_err(|e| format!("DuplicateOutput: {}", e))?;

            let out_desc = output.GetDesc().map_err(|e| e.to_string())?;
            let real_w =
                (out_desc.DesktopCoordinates.right - out_desc.DesktopCoordinates.left) as u32;
            let real_h =
                (out_desc.DesktopCoordinates.bottom - out_desc.DesktopCoordinates.top) as u32;
            // NV12 requires even dimensions; round up and crop the odd pixel.
            let width = (real_w + 1) & !1;
            let height = (real_h + 1) & !1;

            // NV12 render target (video processor output). Only needed for the
            // GPU conversion path, but create it unconditionally so failure
            // here doesn't mask the CPU fallback.
            let nv12_rt_desc = D3D11_TEXTURE2D_DESC {
                Width: width,
                Height: height,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_NV12,
                SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: D3D11_BIND_RENDER_TARGET.0 as u32,
                CPUAccessFlags: 0,
                MiscFlags: 0,
            };
            let mut nv12_out_tex: Option<ID3D11Texture2D> = None;
            device
                .CreateTexture2D(&nv12_rt_desc, None, Some(&mut nv12_out_tex))
                .map_err(|e| format!("nv12 texture: {}", e))?;
            let nv12_out_tex = nv12_out_tex.ok_or("no nv12 texture")?;

            // NV12 staging texture (CPU readback after GPU conversion).
            let staging_desc = D3D11_TEXTURE2D_DESC {
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                ..nv12_rt_desc
            };
            let mut staging: Option<ID3D11Texture2D> = None;
            device
                .CreateTexture2D(&staging_desc, None, Some(&mut staging))
                .map_err(|e| format!("staging texture: {}", e))?;
            let staging = staging.ok_or("no staging texture")?;

            // Video processor for GPU BGRA→NV12 conversion (only when the
            // device has video support).
            let mut vp_dev = None;
            let mut vp_ctx = None;
            let mut vp_enum = None;
            let mut vp = None;
            let mut nv12_out = None;
            let mut staging_bgra = None;
            if has_video {
                let vd: ID3D11VideoDevice = device.cast().map_err(|e| e.to_string())?;
                let vc: ID3D11VideoContext1 = context.cast().map_err(|e| e.to_string())?;
                let rate = DXGI_RATIONAL {
                    Numerator: 60,
                    Denominator: 1,
                };
                let content = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
                    InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
                    InputFrameRate: rate,
                    InputWidth: width,
                    InputHeight: height,
                    OutputFrameRate: rate,
                    OutputWidth: width,
                    OutputHeight: height,
                    Usage: D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
                };
                let ve = vd
                    .CreateVideoProcessorEnumerator(&content)
                    .map_err(|e| format!("vp enumerator: {}", e))?;
                let v = vd
                    .CreateVideoProcessor(&ve, 0)
                    .map_err(|e| format!("video processor: {}", e))?;
                vp_dev = Some(vd);
                vp_ctx = Some(vc);
                vp_enum = Some(ve);
                vp = Some(v);
                nv12_out = Some(nv12_out_tex);
            } else {
                // CPU path: read back the raw BGRA frame instead.
                let bgra_desc = D3D11_TEXTURE2D_DESC {
                    Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                    ..staging_desc
                };
                let mut sb: Option<ID3D11Texture2D> = None;
                device
                    .CreateTexture2D(&bgra_desc, None, Some(&mut sb))
                    .map_err(|e| format!("bgra staging texture: {}", e))?;
                staging_bgra = Some(sb.ok_or("no bgra staging")?);
            }

            Ok(Self {
                device,
                context,
                output,
                dup,
                staging,
                vp,
                vp_enum,
                vp_ctx,
                vp_dev,
                nv12_out,
                staging_bgra,
                width,
                height,
                real_w,
                real_h,
                pos_x: out_desc.DesktopCoordinates.left,
                pos_y: out_desc.DesktopCoordinates.top,
            })
        }
    }

    /// Wait up to `wait` for a desktop change; returns the frame as NV12
    /// system-memory bytes (Y plane then UV plane) or None on timeout.
    fn acquire(&mut self, wait: std::time::Duration) -> Result<Option<Vec<u8>>, String> {
        unsafe {
            let ms = wait.as_millis().min(1000) as u32;
            let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut resource: Option<IDXGIResource> = None;
            match self.dup.AcquireNextFrame(ms, &mut info, &mut resource) {
                Ok(()) => {}
                Err(e) => {
                    let hr = e.code();
                    if hr == DXGI_ERROR_WAIT_TIMEOUT {
                        return Ok(None);
                    }
                    if hr == DXGI_ERROR_ACCESS_LOST {
                        // Display topology changed - recreate the duplication
                        // on the same output instead of dying.
                        let output1: IDXGIOutput1 = self
                            .output
                            .cast()
                            .map_err(|e| e.to_string())?;
                        self.dup = output1
                            .DuplicateOutput(&self.device)
                            .map_err(|e| format!("re-duplication after access lost: {}", e))?;
                        return Ok(None);
                    }
                    return Err(format!("AcquireNextFrame: {}", e));
                }
            }
            let frame_tex: ID3D11Texture2D = match resource.and_then(|r| r.cast().ok()) {
                Some(t) => t,
                None => {
                    let _ = self.dup.ReleaseFrame();
                    return Ok(None);
                }
            };

            if let (Some(vp), Some(vp_enum), Some(vp_ctx), Some(vp_dev), Some(nv12_out)) = (
                self.vp.as_ref(),
                self.vp_enum.as_ref(),
                self.vp_ctx.as_ref(),
                self.vp_dev.as_ref(),
                self.nv12_out.as_ref(),
            ) {
                // GPU convert BGRA → NV12 via the video processor.
                let mut in_view: Option<ID3D11VideoProcessorInputView> = None;
                vp_dev
                    .CreateVideoProcessorInputView(
                        &frame_tex,
                        vp_enum,
                        &D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
                            FourCC: 0,
                            ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
                            Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                                Texture2D: D3D11_TEX2D_VPIV {
                                    MipSlice: 0,
                                    ArraySlice: 0,
                                },
                            },
                        },
                        Some(&mut in_view),
                    )
                    .map_err(|e| format!("input view: {}", e))?;
                let in_view = in_view.ok_or("no input view")?;

                let mut out_view: Option<ID3D11VideoProcessorOutputView> = None;
                vp_dev
                    .CreateVideoProcessorOutputView(
                        nv12_out,
                        vp_enum,
                        &D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
                            ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
                            Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 {
                                Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 },
                            },
                        },
                        Some(&mut out_view),
                    )
                    .map_err(|e| format!("output view: {}", e))?;
                let out_view = out_view.ok_or("no output view")?;

                vp_ctx.VideoProcessorSetOutputTargetRect(
                    vp,
                    true,
                    Some(&RECT {
                        left: 0,
                        top: 0,
                        right: self.width as i32,
                        bottom: self.height as i32,
                    }),
                );
                let stream = D3D11_VIDEO_PROCESSOR_STREAM {
                    Enable: true.into(),
                    pInputSurface: ManuallyDrop::new(Some(in_view)),
                    ..Default::default()
                };
                vp_ctx
                    .VideoProcessorBlt(vp, &out_view, 0, std::slice::from_ref(&stream))
                    .map_err(|e| format!("VideoProcessorBlt: {}", e))?;
                let _ = self.dup.ReleaseFrame();

                // Read back NV12 (Y plane + interleaved UV plane).
                self.context.CopyResource(&self.staging, nv12_out);
                let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                self.context
                    .Map(&self.staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                    .map_err(|e| format!("map staging: {}", e))?;
                let w = self.width as usize;
                let h = self.height as usize;
                let pitch = mapped.RowPitch as usize;
                let mut out = Vec::with_capacity(w * h * 3 / 2);
                let base = mapped.pData as *const u8;
                for row in 0..h {
                    out.extend_from_slice(std::slice::from_raw_parts(base.add(row * pitch), w));
                }
                let uv_base = base.add(h * pitch);
                for row in 0..h / 2 {
                    out.extend_from_slice(std::slice::from_raw_parts(uv_base.add(row * pitch), w));
                }
                self.context.Unmap(&self.staging, 0);
                return Ok(Some(out));
            }

            // CPU path: read back raw BGRA, convert to NV12 on CPU. The frame
            // is real_w?-real_h; buffers are even-sized, so clamp reads.
            let staging_bgra = self.staging_bgra.clone().ok_or("no bgra staging")?;
            self.context.CopyResource(&staging_bgra, &frame_tex);
            let _ = self.dup.ReleaseFrame();
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            self.context
                .Map(&staging_bgra, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .map_err(|e| format!("map bgra staging: {}", e))?;
            let out = bgra_to_nv12(
                mapped.pData as *const u8,
                mapped.RowPitch as usize,
                self.width as usize,
                self.height as usize,
                (self.real_w as usize).min(self.width as usize),
                (self.real_h as usize).min(self.height as usize),
            );
            self.context.Unmap(&staging_bgra, 0);
            Ok(Some(out))
        }
    }
}

// ---------------------------------------------------------------------------
// Media Foundation H.264 encoder
// ---------------------------------------------------------------------------

pub struct EncodedAU {
    pub data: Vec<u8>,
    pub keyframe: bool,
    pub timestamp_ms: i64,
}

pub struct Encoder {
    mft: IMFTransform,
    width: u32,
    height: u32,
    fps: u32,
    seq_header: Option<Vec<u8>>,
    out_buf_size: u32,
    start: std::time::Instant,
    in_count: i64,
    out_count: i64,
}

impl Encoder {
    /// Frames the MFT has swallowed but not yet emitted — the lookahead we
    /// need to drain for low latency.
    pub fn pending(&self) -> i64 {
        self.in_count - self.out_count
    }
}

impl Encoder {
    pub fn new(width: u32, height: u32, fps: u32, bitrate_kbps: u32) -> Result<Self, String> {
        unsafe {
            MFStartup(MF_VERSION, MFSTARTUP_FULL).map_err(|e| format!("MFStartup: {}", e))?;

            // Prefer hardware H.264 encoder MFTs.
            let mut activates: *mut Option<IMFActivate> = std::ptr::null_mut();
            let mut count = 0u32;
            let out_info = MFT_REGISTER_TYPE_INFO {
                guidMajorType: MFMediaType_Video,
                guidSubtype: MFVideoFormat_H264,
            };
            MFTEnumEx(
                MFT_CATEGORY_VIDEO_ENCODER,
                MFT_ENUM_FLAG_HARDWARE,
                None,
                Some(&out_info),
                &mut activates,
                &mut count,
            )
            .map_err(|e| format!("MFTEnumEx hw: {}", e))?;

            let mut mft: Option<IMFTransform> = None;
            if !activates.is_null() {
                let list = std::slice::from_raw_parts(activates, count as usize);
                for a in list.iter().flatten() {
                    if let Ok(candidate) = a.ActivateObject::<IMFTransform>() {
                        if Self::configure(&candidate, width, height, fps, bitrate_kbps).is_ok() {
                            mft = Some(candidate);
                            break;
                        }
                    }
                }
                CoTaskMemFree(Some(activates as *const _));
            }

            let mft = match mft {
                Some(m) => m,
                None => {
                    // Software fallback: the stock Windows H.264 encoder MFT.
                    CoCreateInstance(&CMSH264EncoderMFT, None, CLSCTX_INPROC_SERVER)
                        .map_err(|e| format!("create sw encoder: {}", e))?
                }
            };

            let mut enc = Self {
                mft,
                width,
                height,
                fps,
                seq_header: None,
                out_buf_size: width * height * 2,
                start: std::time::Instant::now(),
                in_count: 0,
                out_count: 0,
            };
            // Software fallback still needs configuring.
            Self::configure(&enc.mft, width, height, fps, bitrate_kbps)
                .map_err(|e| format!("configure encoder: {}", e))?;
            // Honor the MFT's own output buffer requirement (worst-case AUs).
            if let Ok(info) = enc.mft.GetOutputStreamInfo(0) {
                if info.cbSize > 0 {
                    enc.out_buf_size = info.cbSize;
                }
            }
            enc.pull_sequence_header();
            Ok(enc)
        }
    }

    fn configure(
        mft: &IMFTransform,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_kbps: u32,
    ) -> Result<(), String> {
        unsafe {
            // Low-latency codec knobs first — some MFTs reject changes once
            // types are negotiated.
            if let Ok(codec) = mft.cast::<ICodecAPI>() {
                let _ = codec.SetValue(&CODECAPI_AVEncCommonLowLatency, &variant_bool(true));
                let _ = codec.SetValue(&CODECAPI_AVEncMPVDefaultBPictureCount, &variant_i32(0));
            }

            // Output: H.264 annexb, progressive, CBR-ish.
            let out_type = MFCreateMediaType().map_err(|e| e.to_string())?;
            out_type
                .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                .map_err(|e| e.to_string())?;
            out_type
                .SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)
                .map_err(|e| e.to_string())?;
            out_type
                .SetUINT32(&MF_MT_AVG_BITRATE, bitrate_kbps * 1000)
                .map_err(|e| e.to_string())?;
            out_type
                .SetUINT64(&MF_MT_FRAME_SIZE, ((width as u64) << 32) | height as u64)
                .map_err(|e| e.to_string())?;
            out_type
                .SetUINT64(&MF_MT_FRAME_RATE, ((fps as u64) << 32) | 1)
                .map_err(|e| e.to_string())?;
            out_type
                .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .map_err(|e| e.to_string())?;
            out_type
                .SetUINT32(&MF_MT_ALL_SAMPLES_INDEPENDENT, 0)
                .map_err(|e| e.to_string())?;
            mft.SetOutputType(0, &out_type, 0)
                .map_err(|e| format!("SetOutputType: {}", e))?;

            // Input: NV12.
            let in_type = MFCreateMediaType().map_err(|e| e.to_string())?;
            in_type
                .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                .map_err(|e| e.to_string())?;
            in_type
                .SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)
                .map_err(|e| e.to_string())?;
            in_type
                .SetUINT64(&MF_MT_FRAME_SIZE, ((width as u64) << 32) | height as u64)
                .map_err(|e| e.to_string())?;
            in_type
                .SetUINT64(&MF_MT_FRAME_RATE, ((fps as u64) << 32) | 1)
                .map_err(|e| e.to_string())?;
            in_type
                .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .map_err(|e| e.to_string())?;
            in_type
                .SetUINT32(&MF_MT_DEFAULT_STRIDE, width)
                .map_err(|e| e.to_string())?;
            mft.SetInputType(0, &in_type, 0)
                .map_err(|e| format!("SetInputType: {}", e))?;

            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0).ok();
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0).ok();
            Ok(())
        }
    }

    fn pull_sequence_header(&mut self) {
        unsafe {
            if let Ok(t) = self.mft.GetOutputCurrentType(0) {
                if let Ok(size) = t.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER) {
                    if size > 0 {
                        let mut buf = vec![0u8; size as usize];
                        if t.GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut buf, None).is_ok() {
                            self.seq_header = Some(buf);
                        }
                    }
                }
            }
        }
    }

    pub fn sequence_header(&self) -> Option<&[u8]> {
        self.seq_header.as_deref()
    }

    fn force_keyframe(&mut self) {
        unsafe {
            if let Ok(codec) = self.mft.cast::<ICodecAPI>() {
                let _ = codec.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &variant_bool(true));
            }
        }
    }

    /// Feed one NV12 frame; returns an access unit when the MFT emits one.
    pub fn encode(&mut self, nv12: &[u8]) -> Result<Option<EncodedAU>, String> {
        unsafe {
            let frame_len = nv12.len() as u32;
            let buf = MFCreateMemoryBuffer(frame_len).map_err(|e| e.to_string())?;
            let mut dst: *mut u8 = std::ptr::null_mut();
            buf.Lock(&mut dst, None, None).map_err(|e| e.to_string())?;
            std::ptr::copy_nonoverlapping(nv12.as_ptr(), dst, frame_len as usize);
            buf.Unlock().ok();
            buf.SetCurrentLength(frame_len).ok();

            let sample = MFCreateSample().map_err(|e| e.to_string())?;
            sample.AddBuffer(&buf).map_err(|e| e.to_string())?;
            let ts_100ns = self.in_count * 10_000_000 / self.fps.max(1) as i64;
            sample.SetSampleTime(ts_100ns).ok();
            sample
                .SetSampleDuration(10_000_000 / self.fps.max(1) as i64)
                .ok();
            self.in_count += 1;

            self.mft
                .ProcessInput(0, &sample, 0)
                .map_err(|e| format!("ProcessInput: {}", e))?;

            // Drain output. Provide a sample with a pre-allocated buffer —
            // the H.264 MFT writes into caller-provided storage and rejects
            // bare/empty samples with E_INVALIDARG.
            let out_sample_in = MFCreateSample().map_err(|e| e.to_string())?;
            let out_storage =
                MFCreateMemoryBuffer(self.out_buf_size).map_err(|e| e.to_string())?;
            out_sample_in.AddBuffer(&out_storage).map_err(|e| e.to_string())?;
            let mut out_buf = MFT_OUTPUT_DATA_BUFFER {
                pSample: ManuallyDrop::new(Some(out_sample_in)),
                ..Default::default()
            };
            let mut status_flags = 0u32;
            let status = self
                .mft
                .ProcessOutput(0, std::slice::from_mut(&mut out_buf), &mut status_flags);
            match status {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                Err(e) => return Err(format!("ProcessOutput: {}", e)),
            }
            let Some(out_sample) = ManuallyDrop::take(&mut out_buf.pSample) else {
                return Ok(None);
            };
            let total = out_sample.GetTotalLength().unwrap_or(0);
            if total == 0 {
                return Ok(None);
            }
            let mut data = Vec::with_capacity(total as usize);
            let nbuf = out_sample.GetBufferCount().unwrap_or(0);
            for i in 0..nbuf {
                let b = out_sample.GetBufferByIndex(i).map_err(|e| e.to_string())?;
                let mut p: *mut u8 = std::ptr::null_mut();
                b.Lock(&mut p, None, None).map_err(|e| e.to_string())?;
                let len = b.GetCurrentLength().unwrap_or(0) as usize;
                data.extend_from_slice(std::slice::from_raw_parts(p, len));
                b.Unlock().ok();
            }
            let keyframe = out_sample
                .GetUINT32(&MFSampleExtension_CleanPoint)
                .unwrap_or(0)
                != 0;
            self.out_count += 1;
            Ok(Some(EncodedAU {
                data,
                keyframe,
                timestamp_ms: self.start.elapsed().as_millis() as i64,
            }))
        }
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        unsafe {
            self.mft.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0).ok();
            self.mft
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0)
                .ok();
            let _ = MFShutdown();
        }
    }
}

// ---------------------------------------------------------------------------
// CPU BGRA→NV12 fallback (BT.601 studio swing, 2x2 box-sampled chroma).
// (w,h) is the even-sized NV12 output; (src_w,src_h) is the actual frame size
// — reads are clamped so an odd-sized source never overruns.
fn bgra_to_nv12(
    base: *const u8,
    pitch: usize,
    w: usize,
    h: usize,
    src_w: usize,
    src_h: usize,
) -> Vec<u8> {
    let mut out = vec![0u8; w * h * 3 / 2];
    unsafe {
        // Y plane.
        for row in 0..src_h {
            let src = base.add(row * pitch);
            let dst = out.as_mut_ptr().add(row * w);
            for x in 0..src_w {
                let px = src.add(x * 4);
                let b = *px as i32;
                let g = *px.add(1) as i32;
                let r = *px.add(2) as i32;
                let y = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
                *dst.add(x) = y.clamp(0, 255) as u8;
            }
        }
        // UV plane (interleaved U,V), 2x2 box average over the source.
        let uv_base = out.as_mut_ptr().add(w * h);
        for row in (0..src_h).step_by(2) {
            for col in (0..src_w).step_by(2) {
                let mut cb: i64 = 0;
                let mut cr: i64 = 0;
                let mut n: i64 = 0;
                for dy in 0..2usize {
                    for dx in 0..2usize {
                        let px = col + dx;
                        let py = row + dy;
                        if px < src_w && py < src_h {
                            let p = base.add(py * pitch + px * 4);
                            let b = *p as i64;
                            let g = *p.add(1) as i64;
                            let r = *p.add(2) as i64;
                            cb += -38 * r - 74 * g + 112 * b;
                            cr += 112 * r - 94 * g - 18 * b;
                            n += 1;
                        }
                    }
                }
                let u = (((cb / n) >> 8) + 128).clamp(0, 255) as u8;
                let v = (((cr / n) >> 8) + 128).clamp(0, 255) as u8;
                let idx = (row / 2) * w + col;
                *uv_base.add(idx) = u;
                *uv_base.add(idx + 1) = v;
            }
        }
    }
    out
}

/// Dev harness: raw duplication diagnostics — what AcquireNextFrame says.
pub fn dup_diag() -> Result<(), String> {
    use windows::Win32::Graphics::Dxgi::*;
    use windows::core::Interface;
    unsafe {
        let (name, active) = crate::display::find_virtual_display().ok_or("no vdd device")?;
        println!("device {} active={}", name, active);
        let factory: IDXGIFactory1 = CreateDXGIFactory1().map_err(|e| e.to_string())?;
        let mut target_adapter = None;
        let mut target_output = None;
        'outer: for ai in 0..16 {
            let Ok(adapter) = factory.EnumAdapters1(ai) else { break };
            for oi in 0..16 {
                let Ok(output) = adapter.EnumOutputs(oi) else { break };
                let desc = output.GetDesc().map_err(|e| e.to_string())?;
                let len = desc.DeviceName.iter().position(|&c| c == 0).unwrap_or(desc.DeviceName.len());
                let oname = String::from_utf16_lossy(&desc.DeviceName[..len]);
                println!(
                    "adapter {} output {}: {} attached={} coords=({},{})({},{})",
                    ai, oi, oname, desc.AttachedToDesktop.as_bool(),
                    desc.DesktopCoordinates.left, desc.DesktopCoordinates.top,
                    desc.DesktopCoordinates.right, desc.DesktopCoordinates.bottom
                );
                if oname == name {
                    target_adapter = Some(adapter.clone());
                    target_output = Some(output);
                    break 'outer;
                }
            }
        }
        let adapter = target_adapter.ok_or("output not found")?;
        let output = target_output.unwrap();
        let mut device: Option<windows::Win32::Graphics::Direct3D11::ID3D11Device> = None;
        let mut context: Option<windows::Win32::Graphics::Direct3D11::ID3D11DeviceContext> = None;
        windows::Win32::Graphics::Direct3D11::D3D11CreateDevice(
            &adapter,
            windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN,
            windows::Win32::Foundation::HMODULE::default(),
            windows::Win32::Graphics::Direct3D11::D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            7,
            Some(&mut device),
            None,
            Some(&mut context),
        )
        .map_err(|e| format!("D3D11CreateDevice: {}", e))?;
        let device = device.ok_or("no device")?;
        let output1: IDXGIOutput1 = output.cast().map_err(|e| e.to_string())?;
        let dup = output1.DuplicateOutput(&device).map_err(|e| format!("DuplicateOutput: {}", e))?;
        println!("duplication created; acquiring for 6s...");
        let start = std::time::Instant::now();
        while start.elapsed().as_secs() < 6 {
            let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut res: Option<IDXGIResource> = None;
            match dup.AcquireNextFrame(500, &mut info, &mut res) {
                Ok(()) => {
                    println!(
                        "FRAME: res={} lastPresent={} lastUpdate={} accumFrames={}",
                        res.is_some(),
                        info.LastPresentTime,
                        info.LastMouseUpdateTime,
                        info.AccumulatedFrames
                    );
                    let _ = dup.ReleaseFrame();
                }
                Err(e) => println!("acquire: {}", e.code()),
            }
        }
        Ok(())
    }
}
