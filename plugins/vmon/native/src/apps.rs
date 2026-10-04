//! App enumeration and launching onto the virtual display.
//!
//! list_apps walks the Start Menu shortcut dirs and resolves each .lnk to its
//! target. launch starts the process, waits for its windows, then moves them
//! onto the virtual display so they never appear on the user's screen.

use std::path::Path;
use std::sync::atomic::Ordering;

use windows::core::{Interface, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM};
use windows::Win32::System::Com::STGM_READ;
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED};
use windows::Win32::System::Threading::{
    CreateProcessW, CREATE_NO_WINDOW, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
use windows::Win32::UI::WindowsAndMessaging::*;

use crate::{send_json, DISP_H, DISP_W, DISP_X, DISP_Y};

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn resolve_lnk(lnk: &Path) -> Option<String> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
        let persist: IPersistFile = link.cast().ok()?;
        let wide = to_wide(&lnk.to_string_lossy());
        persist.Load(PCWSTR(wide.as_ptr()), STGM_READ).ok()?;
        let mut buf = [0u16; 1024];
        link.GetPath(&mut buf, std::ptr::null_mut(), 0).ok()?;
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let path = String::from_utf16_lossy(&buf[..end]);
        if path.is_empty() {
            None
        } else {
            Some(path)
        }
    }
}

/// Collect Start Menu shortcuts → [{name, path}].
pub fn list_apps() {
    let mut apps: Vec<serde_json::Value> = Vec::new();
    let mut roots = vec![Path::new(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs").to_path_buf()];
    if let Ok(appdata) = std::env::var("APPDATA") {
        roots.push(Path::new(&appdata).join(r"Microsoft\Windows\Start Menu\Programs"));
    }
    for root in roots {
        collect_lnks(&root, 3, &mut apps);
    }
    apps.sort_by(|a, b| {
        a.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(b.get("name").and_then(|v| v.as_str()).unwrap_or(""))
    });
    apps.dedup_by(|a, b| {
        a.get("name").and_then(|v| v.as_str()) == b.get("name").and_then(|v| v.as_str())
    });
    send_json("vmon_apps", &serde_json::json!({ "apps": apps }));
}

fn collect_lnks(dir: &Path, depth: u32, out: &mut Vec<serde_json::Value>) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_lnks(&path, depth - 1, out);
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.to_lowercase().ends_with(".lnk") {
            continue;
        }
        let lower = name.to_lowercase();
        if lower.contains("uninstall") || lower.contains("help") {
            continue;
        }
        if let Some(target) = resolve_lnk(&path) {
            let display = name.trim_end_matches(".lnk").to_string();
            out.push(serde_json::json!({ "name": display, "path": target }));
        }
    }
}

// ---------------------------------------------------------------------------
// Launch + window relocation
// ---------------------------------------------------------------------------

struct MoveCtx {
    exe_name: String,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    moved: u32,
}

/// True when the window's owning process image ends with ctx.exe_name —
/// robust against single-instance apps (notepad) handing windows to a
/// different pid than the one CreateProcess returned.
fn window_matches_exe(hwnd: HWND, exe_name: &str) -> bool {
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    let mut pid = 0u32;
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid == 0 {
            return false;
        }
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let mut buf = [0u16; 260];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, windows::core::PWSTR(buf.as_mut_ptr()), &mut len).is_ok();
        let _ = windows::Win32::Foundation::CloseHandle(h);
        if !ok || len == 0 {
            return false;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]).to_lowercase();
        path.ends_with(exe_name)
    }
}

/// Remove a window's taskbar button — the whole point of the virtual display
/// is that the user never sees what we open, and by default Windows shows
/// taskbar buttons for windows on every display (including ours). The window
/// itself is untouched; only its taskbar entry disappears.
fn hide_from_taskbar(hwnd: HWND) {
    use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED};
    use windows::Win32::UI::Shell::{ITaskbarList, TaskbarList};
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if let Ok(tl) = CoCreateInstance::<_, ITaskbarList>(&TaskbarList, None, CLSCTX_INPROC_SERVER) {
            let _ = tl.HrInit();
            let _ = tl.DeleteTab(hwnd);
        }
    }
}

unsafe extern "system" fn move_proc(hwnd: HWND, lparam: LPARAM) -> windows::core::BOOL {
    let ctx = &mut *(lparam.0 as *mut MoveCtx);
    if !IsWindowVisible(hwnd).as_bool() || !window_matches_exe(hwnd, &ctx.exe_name) {
        return true.into();
    }
    // Skip owned popups/dialogs — only relocate top-level windows.
    if !GetWindow(hwnd, GW_OWNER).unwrap_or_default().0.is_null() {
        return true.into();
    }
    let _ = SetWindowPos(
        hwnd,
        Some(HWND_TOP),
        ctx.x,
        ctx.y,
        ctx.w,
        ctx.h,
        SWP_SHOWWINDOW,
    );
    hide_from_taskbar(hwnd);
    // Exclude from Alt+Tab / Task View too — toolwindow windows are skipped
    // by the switcher. The thinner caption is cosmetic and only ever shows
    // on the hidden display.
    let cur = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;
    if cur & WS_EX_TOOLWINDOW.0 == 0 {
        SetWindowLongW(hwnd, GWL_EXSTYLE, (cur | WS_EX_TOOLWINDOW.0) as i32);
        // Re-apply frame so the style change takes effect.
        let _ = SetWindowPos(
            hwnd,
            None,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
        );
    }
    ctx.moved += 1;
    true.into()
}

/// Launch a process and move its windows onto the virtual display.
pub fn launch(path: &str, args: Option<&str>) {
    let path = if path.to_lowercase().ends_with(".lnk") {
        match resolve_lnk(Path::new(path)) {
            Some(t) => t,
            None => {
                send_json("vmon_status", &serde_json::json!({ "stage": "error", "message": "could not resolve shortcut" }));
                return;
            }
        }
    } else {
        path.to_string()
    };

    let mut cmd = format!("\"{}\"", path);
    if let Some(a) = args {
        if !a.is_empty() {
            cmd.push(' ');
            cmd.push_str(a);
        }
    }
    let mut cmd_wide = to_wide(&cmd);
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    let spawned = unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(windows::core::PWSTR(cmd_wide.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        )
    };
    match spawned {
        Ok(()) => {
            let pid = pi.dwProcessId;
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(pi.hProcess);
                let _ = windows::Win32::Foundation::CloseHandle(pi.hThread);
            }
            // Windows can take a moment to appear; try for ~5s.
            let (dx, dy, dw, dh) = (
                DISP_X.load(Ordering::Relaxed),
                DISP_Y.load(Ordering::Relaxed),
                DISP_W.load(Ordering::Relaxed),
                DISP_H.load(Ordering::Relaxed),
            );
            let exe_name = std::path::Path::new(&path)
                .file_name()
                .map(|f| f.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            std::thread::spawn(move || {
                for _ in 0..10 {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let mut ctx = MoveCtx {
                        exe_name: exe_name.clone(),
                        x: dx + 60,
                        y: dy + 60,
                        w: (dw as f32 * 0.8) as i32,
                        h: (dh as f32 * 0.8) as i32,
                        moved: 0,
                    };
                    unsafe {
                        let _ = EnumWindows(Some(move_proc), LPARAM(&mut ctx as *mut MoveCtx as isize));
                    }
                    if ctx.moved > 0 {
                        break;
                    }
                }
            });
            send_json("vmon_status", &serde_json::json!({ "stage": "launched", "pid": pid }));
        }
        Err(e) => {
            send_json("vmon_status", &serde_json::json!({ "stage": "error", "message": format!("launch failed: {}", e) }));
        }
    }
}

/// Well-known browser install locations → (family, name, path).
const KNOWN_BROWSERS: [(&str, &str, &str); 10] = [
    ("chromium", "Chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    ("chromium", "Brave", r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"),
    ("chromium", "Edge", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    ("chromium", "Opera", r"C:\Users\{user}\AppData\Local\Programs\Opera\opera.exe"),
    ("chromium", "Opera GX", r"C:\Users\{user}\AppData\Local\Programs\Opera GX\opera.exe"),
    ("chromium", "Vivaldi", r"C:\Users\{user}\AppData\Local\Vivaldi\Application\vivaldi.exe"),
    ("chromium", "Yandex", r"C:\Users\{user}\AppData\Local\Yandex\YandexBrowser\Application\browser.exe"),
    ("chromium", "Arc", r"C:\Users\{user}\AppData\Local\Programs\Arc\Application\arc.exe"),
    ("firefox", "Firefox", r"C:\Program Files\Mozilla Firefox\firefox.exe"),
    ("firefox", "Waterfox", r"C:\Program Files\Waterfox\waterfox.exe"),
];

/// Report which well-known browsers exist on this machine.
pub fn browser_check() {
    let user = std::env::var("USERNAME").unwrap_or_default();
    let mut out: Vec<serde_json::Value> = Vec::new();
    for (family, name, path) in KNOWN_BROWSERS {
        let real = path.replace("{user}", &user);
        let found = std::path::Path::new(&real).exists();
        out.push(serde_json::json!({
            "family": family,
            "name": name,
            "path": real,
            "found": found,
        }));
    }
    send_json("vmon_browsers", &serde_json::json!({ "browsers": out }));
}
