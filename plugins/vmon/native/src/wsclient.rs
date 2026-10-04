//! Side-channel transport: a raw binary WebSocket from the DLL straight to
//! the Overlord server, bypassing the base64-JSON plugin event channel.
//! Video frames ride this; control and status stay on the plugin channel.
//!
//! Implemented with WinHTTP's native WebSocket support. TLS certificate
//! validation is relaxed (the server uses a self-signed cert, same posture
//! as the agent's own connection).

use std::sync::atomic::{AtomicUsize, Ordering};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Networking::WinHttp::*;

pub struct SideChannel {
    session: *mut core::ffi::c_void,
    connect: *mut core::ffi::c_void,
    request: *mut core::ffi::c_void,
    socket: *mut core::ffi::c_void,
}

static SEND_FAILS: AtomicUsize = AtomicUsize::new(0);

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Split a wss://host[:port]/path URL into (host, port, path).
fn parse_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("wss://").or_else(|| url.strip_prefix("ws://"))?;
    let (hostport, path) = rest.split_once('/')?;
    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (hostport.to_string(), 443),
    };
    Some((host, port, format!("/{}", path)))
}

impl SideChannel {
    /// Connect and upgrade. Returns None on any failure (caller falls back to
    /// the plugin event channel).
    pub fn connect(url: &str) -> Option<SideChannel> {
        let (host, port, path) = parse_url(url)?;
        unsafe {
            let session = WinHttpOpen(
                PCWSTR::null(),
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                0,
            );
            if session.is_null() {
                return None;
            }
            let host_w = to_wide(&host);
            let connect = WinHttpConnect(session, PCWSTR(host_w.as_ptr()), port, 0);
            if connect.is_null() {
                let _ = WinHttpCloseHandle(session);
                return None;
            }
            let path_w = to_wide(&path);
            let request = WinHttpOpenRequest(
                connect,
                PCWSTR(to_wide("GET").as_ptr()),
                PCWSTR(path_w.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                std::ptr::null(),
                WINHTTP_FLAG_SECURE,
            );
            if request.is_null() {
                let _ = WinHttpCloseHandle(connect);
                let _ = WinHttpCloseHandle(session);
                return None;
            }

            // Self-signed server cert: relax validation (agent posture).
            let flags: u32 = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            let flag_bytes = flags.to_le_bytes();
            let _ = WinHttpSetOption(
                Some(request),
                WINHTTP_OPTION_SECURITY_FLAGS,
                Some(&flag_bytes),
            );

            // Request the WebSocket upgrade before sending.
            let _ = WinHttpSetOption(Some(request), WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, None);

            // WebSocket upgrade handshake.
            let ok = (|| -> Option<()> {
                WinHttpSendRequest(request, None, None, 0, 0, 0).ok()?;
                WinHttpReceiveResponse(request, std::ptr::null_mut()).ok()?;
                Some(())
            })();
            if ok.is_none() {
                let _ = WinHttpCloseHandle(request);
                let _ = WinHttpCloseHandle(connect);
                let _ = WinHttpCloseHandle(session);
                return None;
            }

            let socket = WinHttpWebSocketCompleteUpgrade(request, None);
            if socket.is_null() {
                let _ = WinHttpCloseHandle(request);
                let _ = WinHttpCloseHandle(connect);
                let _ = WinHttpCloseHandle(session);
                return None;
            }
            SEND_FAILS.store(0, Ordering::SeqCst);
            Some(SideChannel {
                session,
                connect,
                request,
                socket,
            })
        }
    }

    /// Send one binary message. Never queues: a failure increments the fail
    /// counter so the caller can drop frames instead of backing up.
    pub fn send_binary(&mut self, data: &[u8]) -> bool {
        unsafe {
            let r = WinHttpWebSocketSend(
                self.socket,
                WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
                Some(data),
            );
            if r == 0 {
                SEND_FAILS.store(0, Ordering::SeqCst);
                true
            } else {
                SEND_FAILS.fetch_add(1, Ordering::SeqCst);
                false
            }
        }
    }

    /// True when recent sends have failed — caller should drop frames and
    /// consider the channel degraded (never queue rule).
    pub fn degraded() -> bool {
        SEND_FAILS.load(Ordering::SeqCst) > 4
    }
}

impl Drop for SideChannel {
    fn drop(&mut self) {
        unsafe {
            if !self.socket.is_null() {
                let _ = WinHttpCloseHandle(self.socket);
            }
            if !self.request.is_null() {
                let _ = WinHttpCloseHandle(self.request);
            }
            if !self.connect.is_null() {
                let _ = WinHttpCloseHandle(self.connect);
            }
            if !self.session.is_null() {
                let _ = WinHttpCloseHandle(self.session);
            }
        }
    }
}
