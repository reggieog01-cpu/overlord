/*
 * botkiller — defensive bot/malware remediation plugin for Overlord.
 *
 * Exports the standard Overlord native plugin ABI. All work is synchronous
 * inside PluginOnLoad / PluginOnEvent; the host serializes plugin calls.
 *
 * Events handled:
 *   "scan"          → full enumeration + scoring, replies "scan_result".
 *   "remediate"     payload {"targets": [id...], "dry_run": bool}
 *                   → kill processes, delete binaries, remove persistence;
 *                   replies "remediate_result".
 *   "whitelist_add" payload {"paths": [...], "names": [...]}
 *                   → extend the runtime whitelist, replies "whitelist_result".
 *   "ping"          → replies "pong".
 *
 * In-memory PE loader notes (plugins/docs/legacy-native-plugins.md):
 * C-style globals only, no std::sync::Mutex statics; built with emulated TLS
 * (-Ztls-model=emulated + build-std, see .cargo/config.toml and emutls.rs).
 */

use std::os::raw::c_int;
use std::slice;

mod com;
mod detect;
mod emutls;
mod enumerate;
mod remediate;
mod report;
mod taskscom;
mod whitelist;
mod wmicom;

type HostCallback = unsafe extern "stdcall" fn(
    event: *const u8,
    event_len: usize,
    payload: *const u8,
    payload_len: usize,
);

static mut G_CALLBACK: Option<HostCallback> = None;

unsafe fn send_event(event: &str, payload: &[u8]) {
    if let Some(cb) = G_CALLBACK {
        cb(event.as_ptr(), event.len(), payload.as_ptr(), payload.len());
    }
}

fn send_json(event: &str, value: &serde_json::Value) {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    unsafe { send_event(event, &bytes) };
}

fn bytes_to_slice<'a>(p: *const u8, len: c_int) -> &'a [u8] {
    if p.is_null() || len <= 0 {
        return &[];
    }
    unsafe { slice::from_raw_parts(p, len as usize) }
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
    whitelist::init();
    send_json(
        "ready",
        &serde_json::json!({ "message": "botkiller plugin ready" }),
    );
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
    let ev = bytes_to_slice(event, event_len);
    let pl = bytes_to_slice(payload, payload_len);

    match ev {
        b"scan" => {
            let report = report::build_scan();
            let value = serde_json::to_value(&report)
                .unwrap_or_else(|_| serde_json::json!({ "error": "serialize" }));
            send_json("scan_result", &value);
            0
        }
        b"remediate" => {
            let parsed: serde_json::Value =
                serde_json::from_slice(pl).unwrap_or(serde_json::Value::Null);
            let targets: Vec<String> = parsed
                .get("targets")
                .and_then(|t| t.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| {
                            v.as_str()
                                .map(str::to_string)
                                .or_else(|| v.as_u64().map(|n| n.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            if targets.is_empty() {
                send_json(
                    "remediate_result",
                    &serde_json::json!({
                        "dry_run": false,
                        "results": [],
                        "summary": { "error": "no targets supplied" },
                    }),
                );
                return 0;
            }
            let dry_run = parsed
                .get("dry_run")
                .and_then(|d| d.as_bool())
                .unwrap_or(false);
            let result = remediate::remediate(&targets, dry_run);
            let value = serde_json::to_value(&result)
                .unwrap_or_else(|_| serde_json::json!({ "error": "serialize" }));
            send_json("remediate_result", &value);
            0
        }
        b"whitelist_add" => {
            let parsed: serde_json::Value =
                serde_json::from_slice(pl).unwrap_or(serde_json::Value::Null);
            let strings = |key: &str| -> Vec<String> {
                parsed
                    .get(key)
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let (paths, names) = whitelist::add_operator(strings("paths"), strings("names"));
            send_json(
                "whitelist_result",
                &serde_json::json!({ "added_paths": paths, "added_names": names }),
            );
            0
        }
        b"ping" => {
            send_json("pong", &serde_json::json!({}));
            0
        }
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn PluginOnUnload() {
    G_CALLBACK = None;
}
