//! vmon-cli — dev harness for the vmon DLL's code paths. Includes the DLL's
//! modules directly so the same code can be run elevated and debugged as a
//! plain exe. Normal (native-TLS) build — the emulated TLS shim is only
//! needed for the in-memory-loaded DLL.

use std::sync::atomic::AtomicI32;

fn send_json(event: &str, value: &serde_json::Value) {
    if event == "vmon_frame" {
        println!(
            "frame seq={} key={} bytes={}",
            value.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
            value.get("key").and_then(|v| v.as_bool()).unwrap_or(false),
            value.get("data").and_then(|v| v.as_str()).map(|s| s.len()).unwrap_or(0),
        );
    } else {
        println!("{}: {}", event, value);
    }
}
fn status(stage: &str) {
    println!("stage: {}", stage);
}

pub static DISP_X: AtomicI32 = AtomicI32::new(0);
pub static DISP_Y: AtomicI32 = AtomicI32::new(0);
pub static DISP_W: AtomicI32 = AtomicI32::new(1920);
pub static DISP_H: AtomicI32 = AtomicI32::new(1080);

#[path = "../../native/src/display.rs"]
mod display;
#[path = "../../native/src/stream.rs"]
mod stream;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("install") => {
            // Optional: install <x> <y> <w> <h> to test attach variants.
            let x = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(30_000);
            let y = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(30_000);
            let w = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(1920);
            let h = args.get(5).and_then(|v| v.parse().ok()).unwrap_or(1080);
            match display::ensure_display_at(w, h, x, y) {
                Ok((name, x, y)) => println!("display attached: {} at ({}, {})", name, x, y),
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some("find") => println!("{:?}", display::find_virtual_display()),
        Some("modes") => display::list_modes(),
        Some("displays") => display::dump_displays(),
        Some("dupdiag") => { let r = stream::dup_diag(); println!("{:?}", r); }
        Some("paths") => display::dump_paths(),
        Some("ccd") => { let r = display::ccd_attach(1920, 1080, 30000, 30000); println!("{:?}", r); }
        Some("ccdset") => {
            let x: i32 = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(1920);
            let y: i32 = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(0);
            let w: u32 = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(1920);
            let h: u32 = args.get(5).and_then(|v| v.parse().ok()).unwrap_or(1080);
            let r = display::ccd_set_mode(w, h, x, y);
            println!("{:?}", r);
        }
        Some("mkdev") => {
            // Try several device-instance name forms; print each result.
            let cases: [(&str, bool); 4] = [
                ("Root\\MttVDD", true),
                ("ROOT\\MttVDD", true),
                ("Root\\MttVDD\\0000", false),
                ("ROOT\\MttVDD\\0001", false),
            ];
            for (name, gen) in cases {
                let r = display::try_create_device_node(
                    name,
                    r"C:\Users\vboxuser\AppData\Local\Temp\vmon-drv\MttVDD.inf",
                    gen,
                );
                match r {
                    Ok(()) => println!("mkdev {:?} gen={} -> OK", name, gen),
                    Err(e) => println!("mkdev {:?} gen={} -> {}", name, gen, e),
                }
            }
            unsafe {
                let code = windows::Win32::Foundation::GetLastError();
                println!("GetLastError: {:?}", code);
            }
        }
        Some("stream") => {
            // Optional arg: device name to duplicate instead of the virtual
            // display (e.g. stream \\.\DISPLAY1 captures the primary).
            let target = args.get(2).cloned();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                stream::run_with_target(
                    stream::StreamConfig {
                        width: 1920,
                        height: 1080,
                        fps: 30,
                        bitrate_kbps: 4000,
                    },
                    rx,
                    target,
                )
            });
            std::thread::sleep(std::time::Duration::from_secs(15));
            println!(
                "frames sent: {} acquired: {}",
                stream::FRAMES_SENT.load(std::sync::atomic::Ordering::Relaxed), stream::FRAMES_ACQUIRED.load(std::sync::atomic::Ordering::Relaxed)
            );
            let _ = tx.send(stream::Command::Stop);
        }
        _ if args.get(1).map(|s| s.as_str()) == Some("selftest") => {
            // Encode 60 synthetic NV12 frames (moving pattern) to validate the
            // MF H.264 pipeline without any capture hardware.
            let w = 1280u32;
            let h = 720u32;
            match stream::Encoder::new(w, h, 30, 4000) {
                Err(e) => println!("encoder init failed: {}", e),
                Ok(mut enc) => {
                    println!(
                        "seqhdr: {} bytes",
                        enc.sequence_header().map(|s| s.len()).unwrap_or(0)
                    );
                    let mut produced = 0u32;
                    for f in 0..60u32 {
                        let mut frame = vec![0u8; (w * h * 3 / 2) as usize];
                        for y in 0..h as usize {
                            for x in 0..w as usize {
                                let bar = ((x as u32 + f * 8) % 200) < 100;
                                frame[y * w as usize + x] = if bar { 200 } else { 30 };
                            }
                        }
                        match enc.encode(&frame) {
                            Ok(Some(au)) => {
                                produced += 1;
                                if produced <= 3 || produced % 20 == 0 {
                                    println!(
                                        "au {}: {} bytes key={}",
                                        produced,
                                        au.data.len(),
                                        au.keyframe
                                    );
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                println!("encode error at frame {}: {}", f, e);
                                break;
                            }
                        }
                    }
                    println!("selftest: {} access units from 60 frames", produced);
                }
            }
        }
        _ => println!("usage: vmon-cli [install|find|mkdev|stream|selftest]"),
    }
}
