//! Heuristic scoring for scan findings. A finding at or above
//! SUSPICIOUS_THRESHOLD is reported as "suspicious"; whitelisted findings are
//! always "trusted" with score 0.

use std::ffi::c_void;
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

use crate::enumerate;
use crate::whitelist::{self, Whitelist};

pub const SUSPICIOUS_THRESHOLD: u32 = 3;

pub struct EnvDirs {
    pub temp: String,
    pub public: String,
    pub userprofile: String,
    pub appdata: String,
    pub localappdata: String,
    pub programdata: String,
    pub program_files: Vec<String>,
}

fn lower_env(key: &str) -> String {
    std::env::var(key)
        .unwrap_or_default()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

impl EnvDirs {
    pub fn capture() -> Self {
        let mut program_files = Vec::new();
        for key in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            let v = lower_env(key);
            if !v.is_empty() && !program_files.contains(&v) {
                program_files.push(v);
            }
        }
        EnvDirs {
            temp: lower_env("TEMP"),
            public: lower_env("PUBLIC"),
            userprofile: lower_env("USERPROFILE"),
            appdata: lower_env("APPDATA"),
            localappdata: lower_env("LOCALAPPDATA"),
            programdata: lower_env("ProgramData"),
            program_files,
        }
    }
}

pub struct Score {
    pub points: u32,
    pub reasons: Vec<String>,
    pub signed: Option<bool>,
}

impl Score {
    fn new() -> Self {
        Score {
            points: 0,
            reasons: Vec::new(),
            signed: None,
        }
    }
    /// Empty score for findings that skip scoring (whitelisted, .lnk stubs).
    pub fn placeholder() -> Self {
        Self::new()
    }
    fn add(&mut self, points: u32, reason: String) {
        self.points += points;
        self.reasons.push(reason);
    }
}

pub fn verdict(whitelisted: Option<String>, score: u32) -> (String, Vec<String>) {
    if let Some(reason) = whitelisted {
        return ("trusted".to_string(), vec![reason]);
    }
    if score >= SUSPICIOUS_THRESHOLD {
        ("suspicious".to_string(), Vec::new())
    } else {
        ("clean".to_string(), Vec::new())
    }
}

fn starts_with_any(path: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|p| !p.is_empty() && path.starts_with(p.as_str()))
}

/// Location score for an executable path. Returns (points, reason).
fn location_score(env: &EnvDirs, path: &str) -> (u32, Option<String>) {
    let p = whitelist::normalize_path(path);
    if p.is_empty() {
        return (0, None);
    }
    let in_dir = |dir: &str| !dir.is_empty() && p.starts_with(&format!("{}\\", dir.trim_end_matches('\\')));

    let parent = p.rsplit_once('\\').map(|(d, _)| d).unwrap_or("");
    let browser_cache = (p.contains("\\google\\chrome\\") && p.contains("\\cache"))
        || (p.contains("\\mozilla\\firefox\\") && p.contains("cache"))
        || (p.contains("\\microsoft\\edge\\") && p.contains("\\cache"));

    if in_dir(&env.temp) {
        return (3, Some("executable in %TEMP%".into()));
    }
    if in_dir(&env.public) {
        return (3, Some("executable in %PUBLIC%".into()));
    }
    if !env.userprofile.is_empty() && parent == env.userprofile {
        return (3, Some("executable in user profile root".into()));
    }
    if p.contains("\\$recycle.bin\\") || p.contains("\\recycler\\") {
        return (3, Some("executable in recycle bin".into()));
    }
    if p.contains("temporary internet files") || browser_cache {
        return (3, Some("executable in browser cache".into()));
    }
    if in_dir(&env.appdata) {
        return (2, Some("executable in %APPDATA%".into()));
    }
    if in_dir(&env.localappdata) {
        return (2, Some("executable in %LOCALAPPDATA%".into()));
    }
    if in_dir(&env.programdata) {
        return (2, Some("executable in C:\\ProgramData".into()));
    }
    (0, None)
}

fn in_program_files(env: &EnvDirs, path: &str) -> bool {
    let p = whitelist::normalize_path(path);
    starts_with_any(&p, &env.program_files)
}

/// Authenticode verification. None when the path is not a checkable file.
pub fn verify_signature(path: &str) -> Option<bool> {
    let lower = path.to_ascii_lowercase();
    if !(lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".sys")) {
        return None;
    }
    if !std::path::Path::new(path).is_file() {
        return None;
    }
    let wpath = enumerate::wide(path);
    unsafe {
        let mut file_info = WINTRUST_FILE_INFO::default();
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = wpath.as_ptr();

        let mut data = WINTRUST_DATA::default();
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut file_info;
        data.dwStateAction = WTD_STATEACTION_VERIFY;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let rc = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        );

        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        );
        Some(rc == 0)
    }
}

const SYSTEM_BINARY_NAMES: [&str; 8] = [
    "svchost.exe",
    "explorer.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "taskhostw.exe",
    "rundll32.exe",
    "conhost.exe",
];

/// Process masquerading as a Windows binary from a non-system location.
fn is_masquerading(wl: &Whitelist, name: &str, path: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if !SYSTEM_BINARY_NAMES.contains(&n.as_str()) {
        return false;
    }
    if path.is_empty() {
        return false;
    }
    !whitelist::is_system_path(wl, path)
}

/// Long hex / alphanumeric blob names on persistence entries.
pub fn looks_random(name: &str) -> bool {
    let stem = name
        .rsplit('\\')
        .next()
        .unwrap_or(name)
        .split('.')
        .next()
        .unwrap_or(name);
    let chars: Vec<char> = stem.chars().collect();
    if chars.len() >= 8 && chars.iter().all(|c| c.is_ascii_hexdigit()) && chars.iter().any(|c| c.is_ascii_digit()) && chars.iter().any(|c| c.is_ascii_alphabetic()) {
        return true;
    }
    if chars.len() >= 14
        && chars.iter().all(|c| c.is_ascii_alphanumeric())
        && chars.iter().filter(|c| c.is_ascii_digit()).count() >= 4
    {
        return true;
    }
    false
}

/// Score a process finding. `has_persistence` = any persistence entry points
/// at this binary.
pub fn score_process(
    env: &EnvDirs,
    wl: &Whitelist,
    name: &str,
    path: &str,
    has_persistence: bool,
) -> Score {
    let mut s = Score::new();
    let (pts, reason) = location_score(env, path);
    if let Some(r) = reason {
        s.add(pts, r);
    }
    if has_persistence && pts >= 2 {
        s.add(3, "has persistence entry pointing into a user-writable/temp location".into());
    }
    if !path.is_empty() && !whitelist::is_system_path(wl, path) && !in_program_files(env, path) {
        s.signed = verify_signature(path);
        if s.signed == Some(false) {
            s.add(2, "unsigned or invalid Authenticode signature".into());
        }
    }
    if is_masquerading(wl, name, path) {
        s.add(2, format!("process name matches system binary {name} but image path is not the legitimate location"));
    }
    s
}

/// Score a persistence finding targeting `target_path`.
pub fn score_persistence(
    env: &EnvDirs,
    wl: &Whitelist,
    entry_name: &str,
    target_path: &str,
) -> Score {
    let mut s = Score::new();
    let (pts, reason) = location_score(env, target_path);
    if let Some(r) = reason {
        s.add(pts, format!("persistence target: {r}"));
    }
    if pts >= 2 {
        s.add(3, "persistence entry points into a user-writable/temp location".into());
    }
    if !target_path.is_empty()
        && !whitelist::is_system_path(wl, target_path)
        && !in_program_files(env, target_path)
    {
        s.signed = verify_signature(target_path);
        if s.signed == Some(false) {
            s.add(2, "persistence target unsigned or invalid signature".into());
        }
    }
    if pts >= 2 && looks_random(entry_name) {
        s.add(1, "randomized-looking persistence entry name".into());
    }
    s
}
