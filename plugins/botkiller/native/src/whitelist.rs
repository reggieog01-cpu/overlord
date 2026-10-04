//! Whitelist of everything the plugin must never touch: the Overlord agent
//! itself, its install/state directories, its persistence entry names, and
//! critical system processes / OS paths. Re-checked before every destructive
//! action in remediate.rs.

use std::cell::UnsafeCell;

use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptHashData, BCryptOpenAlgorithmProvider, BCRYPT_SHA256_ALGORITHM,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, QueryFullProcessImageNameW,
};

/// Normalize for comparison: lowercase + forward slashes to backslashes.
pub fn normalize_path(path: &str) -> String {
    path.trim().replace('/', "\\").to_ascii_lowercase()
}

fn dir_prefix(dir: &str) -> String {
    let mut d = normalize_path(dir);
    while d.ends_with('\\') {
        d.pop();
    }
    d.push('\\');
    d
}

pub fn file_name(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

pub const CRITICAL_PROCESSES: [&str; 13] = [
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "dwm.exe",
    "taskhostw.exe",
    "conhost.exe",
];

pub struct Whitelist {
    pub self_pid: u32,
    /// SHA-256 of the host process's own image file. Anchors the whitelist
    /// to the agent binary itself, surviving renames/relocations of the
    /// installed copy on disk.
    pub self_hash: Option<[u8; 32]>,
    /// path → sha256 cache (None = hashed-and-different or unhashable).
    /// Scans are one-shot and host-serialized, so a plain Vec is fine.
    pub hash_cache: UnsafeCell<Vec<(String, Option<[u8; 32]>)>>,
    /// Normalized directory prefixes (trailing '\').
    pub dirs: Vec<String>,
    /// %TEMP%\backstage_* — paths directly under %TEMP% starting with this.
    pub temp_backstage_prefix: String,
    /// %APPDATA% prefix for the ovd_*.exe file-name rule.
    pub appdata: String,
    /// Normalized OS directory prefix (e.g. c:\windows\).
    pub windir: String,
    /// Operator-added exact paths / directory prefixes (normalized).
    pub operator_paths: Vec<String>,
    /// Operator-added entry names (lowercase; trailing '*' = prefix match).
    pub operator_names: Vec<String>,
}

static mut G_WHITELIST: Option<Whitelist> = None;

pub unsafe fn get() -> Option<&'static Whitelist> {
    G_WHITELIST.as_ref().map(|w| &*(w as *const Whitelist))
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

fn self_image_path() -> String {
    unsafe {
        let h = GetCurrentProcess();
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        if QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0 {
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            String::new()
        }
    }
}

// ---------------------------------------------------------------------------
// SHA-256 of a file via CNG (bcrypt.dll) — hash-only anchoring for the agent
// binary so a renamed/relocated install copy still matches.
// ---------------------------------------------------------------------------

/// Max file size we bother hashing.
const HASH_MAX_SIZE: u64 = 200 * 1024 * 1024;
const HASHABLE_EXTS: [&str; 6] = ["exe", "dll", "sys", "scr", "com", "cpl"];

fn hashable_path(path: &str) -> bool {
    let ext = path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    path.contains('\\') && HASHABLE_EXTS.contains(&ext.as_str())
}

pub fn sha256_file(path: &str) -> Option<[u8; 32]> {
    if !hashable_path(path) {
        return None;
    }
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > HASH_MAX_SIZE {
        return None;
    }
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    unsafe {
        let mut alg: *mut core::ffi::c_void = std::ptr::null_mut();
        if BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_SHA256_ALGORITHM, std::ptr::null(), 0) != 0 {
            return None;
        }
        let mut hash: *mut core::ffi::c_void = std::ptr::null_mut();
        if BCryptCreateHash(alg, &mut hash, std::ptr::null_mut(), 0, std::ptr::null(), 0, 0) != 0 {
            BCryptCloseAlgorithmProvider(alg, 0);
            return None;
        }
        // Heap buffer: a 1 MB stack array overflows the Windows default
        // 1 MB main-thread stack.
        let mut buf = vec![0u8; 1024 * 1024];
        let mut ok = true;
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if BCryptHashData(hash, buf.as_ptr(), n as u32, 0) != 0 {
                        ok = false;
                        break;
                    }
                }
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        let mut out = [0u8; 32];
        if ok && BCryptFinishHash(hash, out.as_mut_ptr(), 32, 0) != 0 {
            ok = false;
        }
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        if ok {
            Some(out)
        } else {
            None
        }
    }
}

/// True when `path` hashes to the host process's own image hash.
/// Cached per normalized path; hashing failures never match.
pub fn is_self_hash(wl: &Whitelist, path: &str) -> bool {
    let Some(self_hash) = wl.self_hash else {
        return false;
    };
    if !hashable_path(path) {
        return false;
    }
    let key = normalize_path(path);
    let cache = unsafe { &mut *wl.hash_cache.get() };
    if let Some((_, cached)) = cache.iter().find(|(p, _)| *p == key) {
        return *cached == Some(self_hash);
    }
    let digest = sha256_file(path);
    let matched = digest == Some(self_hash);
    cache.push((key, digest));
    matched
}

pub unsafe fn init() {
    let appdata = env("APPDATA");
    let localappdata = env("LOCALAPPDATA");
    let temp = env("TEMP");
    let windir = {
        let w = env("SystemRoot");
        if w.is_empty() {
            "C:\\Windows".to_string()
        } else {
            w
        }
    };

    let mut dirs = Vec::new();
    if !appdata.is_empty() {
        dirs.push(dir_prefix(&format!("{appdata}\\Microsoft\\DeviceSync")));
        dirs.push(dir_prefix(&format!("{appdata}\\Overlord")));
    }
    if !localappdata.is_empty() {
        dirs.push(dir_prefix(&format!("{localappdata}\\Overlord")));
    }
    if !temp.is_empty() {
        dirs.push(dir_prefix(&format!("{temp}\\Overlord\\backstage")));
    }
    dirs.push(dir_prefix("C:\\Recovery\\OEM"));

    let temp_backstage_prefix = if temp.is_empty() {
        String::new()
    } else {
        format!("{}backstage_", dir_prefix(&temp))
    };

    let self_path = normalize_path(&self_image_path());
    let self_hash = if self_path.is_empty() {
        None
    } else {
        sha256_file(&self_path)
    };

    G_WHITELIST = Some(Whitelist {
        self_pid: GetCurrentProcessId(),
        self_hash,
        hash_cache: UnsafeCell::new(Vec::new()),
        dirs,
        temp_backstage_prefix,
        appdata: if appdata.is_empty() {
            String::new()
        } else {
            dir_prefix(&appdata)
        },
        windir: dir_prefix(&windir),
        operator_paths: Vec::new(),
        operator_names: Vec::new(),
    });
}

pub unsafe fn add_operator(paths: Vec<String>, names: Vec<String>) -> (usize, usize) {
    if let Some(wl) = G_WHITELIST.as_mut() {
        let mut added_p = 0;
        let mut added_n = 0;
        for p in paths {
            let n = normalize_path(&p);
            if !n.is_empty() && !wl.operator_paths.contains(&n) {
                wl.operator_paths.push(n);
                added_p += 1;
            }
        }
        for n in names {
            let n = n.trim().to_ascii_lowercase();
            if !n.is_empty() && !wl.operator_names.contains(&n) {
                wl.operator_names.push(n);
                added_n += 1;
            }
        }
        (added_p, added_n)
    } else {
        (0, 0)
    }
}

/// Path-based whitelist check. Returns Some(reason) when untouchable.
pub fn whitelisted_path_reason(wl: &Whitelist, path: &str) -> Option<&'static str> {
    if path.is_empty() {
        return None;
    }
    let p = normalize_path(path);
    if p.is_empty() {
        return None;
    }
    for d in &wl.dirs {
        if p.starts_with(d.as_str()) {
            return Some("whitelisted: overlord agent");
        }
    }
    if !wl.temp_backstage_prefix.is_empty() && p.starts_with(&wl.temp_backstage_prefix) {
        return Some("whitelisted: overlord agent");
    }
    // ovd_*.exe anywhere under %APPDATA%.
    if !wl.appdata.is_empty() && p.starts_with(&wl.appdata) {
        let name = file_name(&p);
        if name.starts_with("ovd_") && name.ends_with(".exe") {
            return Some("whitelisted: overlord agent");
        }
    }
    for op in &wl.operator_paths {
        if p == *op || p.starts_with(&format!("{op}\\")) {
            return Some("whitelisted: operator");
        }
    }
    // Binary-content anchor: identical bytes to the host image, regardless of
    // where the copy lives or what it is named.
    if is_self_hash(wl, path) {
        return Some("whitelisted: overlord agent (binary match)");
    }
    None
}

/// OS path rule: anything under %SystemRoot% is report-only.
pub fn is_system_path(wl: &Whitelist, path: &str) -> bool {
    let p = normalize_path(path);
    !p.is_empty() && p.starts_with(&wl.windir)
}

pub fn is_critical_process_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    CRITICAL_PROCESSES.contains(&n.as_str())
}

pub fn is_overlord_run_value(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "overlordagent" || n.starts_with("overlordagent-")
}

pub fn is_overlord_task_name(name: &str) -> bool {
    file_name(&name.to_ascii_lowercase()).starts_with("ovd_")
}

pub fn is_overlord_wmi_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("ovd_f") || n.starts_with("ovd_c")
}

pub fn is_operator_name(wl: &Whitelist, name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    wl.operator_names.iter().any(|op| {
        if let Some(prefix) = op.strip_suffix('*') {
            n.starts_with(prefix)
        } else {
            n == *op
        }
    })
}
