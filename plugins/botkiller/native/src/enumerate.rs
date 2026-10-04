//! Read-only enumeration of processes, autostart registry values, scheduled
//! tasks, startup folders, services, and WMI event subscriptions.

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Registry::{
    RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ,
    KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
    ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub parent_pid: u32,
}

fn image_path_for_pid(pid: u32) -> String {
    if pid == 0 || pid == 4 {
        return String::new();
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return String::new();
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let path = if QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0 {
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            String::new()
        };
        CloseHandle(h);
        path
    }
}

pub fn processes() -> Vec<ProcInfo> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut pe = PROCESSENTRY32W::default();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut pe) != 0 {
            loop {
                let pid = pe.th32ProcessID;
                let end = pe
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(pe.szExeFile.len());
                out.push(ProcInfo {
                    pid,
                    name: String::from_utf16_lossy(&pe.szExeFile[..end]),
                    path: image_path_for_pid(pid),
                    parent_pid: pe.th32ParentProcessID,
                });
                if Process32NextW(snap, &mut pe) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

// ---------------------------------------------------------------------------
// Registry autostart (Run / RunOnce / RunOnceEx)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RunKeyEntry {
    pub hive: String,
    pub view: u32,
    pub subkey: String,
    pub value_name: String,
    pub command: String,
}

const RUN_SUBKEYS: [&str; 3] = [
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
];

fn enum_run_key(root: HKEY, hive: &str, view: u32, subkey: &str, out: &mut Vec<RunKeyEntry>) {
    unsafe {
        let wsub = wide(subkey);
        let mut hkey: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(root, wsub.as_ptr(), 0, KEY_READ | view, &mut hkey) != 0 {
            return;
        }
        let mut name_buf = [0u16; 512];
        let mut data_buf = [0u8; 8192];
        let mut index = 0u32;
        loop {
            let mut name_len = name_buf.len() as u32;
            let mut data_len = data_buf.len() as u32;
            let mut vtype = 0u32;
            let rc = RegEnumValueW(
                hkey,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null(),
                &mut vtype,
                data_buf.as_mut_ptr(),
                &mut data_len,
            );
            if rc != 0 {
                break;
            }
            index += 1;
            if vtype != REG_SZ && vtype != REG_EXPAND_SZ {
                continue;
            }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let words = data_len as usize / 2;
            let data_u16 = std::slice::from_raw_parts(data_buf.as_ptr() as *const u16, words);
            let end = data_u16
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(data_u16.len());
            out.push(RunKeyEntry {
                hive: hive.to_string(),
                view: if view == KEY_WOW64_32KEY { 32 } else { 64 },
                subkey: subkey.to_string(),
                value_name: name,
                command: String::from_utf16_lossy(&data_u16[..end]),
            });
        }
        windows_sys::Win32::System::Registry::RegCloseKey(hkey);
    }
}

pub fn run_keys() -> Vec<RunKeyEntry> {
    let mut out = Vec::new();
    for subkey in RUN_SUBKEYS {
        enum_run_key(HKEY_CURRENT_USER, "HKCU", KEY_WOW64_64KEY, subkey, &mut out);
        enum_run_key(HKEY_LOCAL_MACHINE, "HKLM", KEY_WOW64_64KEY, subkey, &mut out);
        enum_run_key(HKEY_LOCAL_MACHINE, "HKLM", KEY_WOW64_32KEY, subkey, &mut out);
    }
    out
}

/// HKCU\Environment values — UserInitMprLogonScript-style logon persistence
/// (used by the x86 agent variant). All string values are collected; the
/// path-based whitelist decides which ones are ours.
pub fn environment_values() -> Vec<RunKeyEntry> {
    let mut out = Vec::new();
    enum_run_key(HKEY_CURRENT_USER, "HKCU", KEY_WOW64_64KEY, "Environment", &mut out);
    out
}

// ---------------------------------------------------------------------------
// Scheduled tasks (in-process Task Scheduler COM — no schtasks.exe)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TaskInfo {
    pub name: String,
    pub execs: Vec<String>,
}

pub fn scheduled_tasks() -> Vec<TaskInfo> {
    match crate::taskscom::connect() {
        Some(svc) => svc
            .enumerate()
            .into_iter()
            .map(|(name, execs)| TaskInfo { name, execs })
            .collect(),
        None => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Startup folders
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct StartupItem {
    pub path: String,
    /// Resolved shortcut target; None for .lnk (resolution optional in v1).
    pub target: Option<String>,
}

pub fn startup_items() -> Vec<StartupItem> {
    let mut out = Vec::new();
    let mut dirs = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        dirs.push(format!("{appdata}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    if let Ok(pd) = std::env::var("ProgramData") {
        dirs.push(format!("{pd}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    for dir in dirs {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !matches!(ext.as_str(), "lnk" | "exe" | "bat" | "cmd") {
                continue;
            }
            let target = if ext == "lnk" {
                None
            } else {
                Some(path.to_string_lossy().into_owned())
            };
            out.push(StartupItem {
                path: path.to_string_lossy().into_owned(),
                target,
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Services (report-only)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub binary_path: String,
    pub state: String,
}

fn service_state_str(state: u32) -> &'static str {
    match state {
        1 => "stopped",
        4 => "running",
        2 => "start_pending",
        3 => "stop_pending",
        _ => "other",
    }
}

pub fn services() -> Vec<ServiceInfo> {
    let mut out = Vec::new();
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            return out;
        }
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            std::ptr::null_mut(),
            0,
            &mut needed,
            &mut count,
            &mut resume,
            std::ptr::null(),
        );
        if needed == 0 {
            CloseServiceHandle(scm);
            return out;
        }
        let mut buf = vec![0u8; needed as usize + 4096];
        resume = 0;
        if EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut needed,
            &mut count,
            &mut resume,
            std::ptr::null(),
        ) != 0
        {
            let entries = std::slice::from_raw_parts(
                buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                count as usize,
            );
            for e in entries {
                let name = from_wide(e.lpServiceName);
                let mut binary_path = String::new();
                let wname = wide(&name);
                let svc = OpenServiceW(scm, wname.as_ptr(), SERVICE_QUERY_CONFIG);
                if !svc.is_null() {
                    let mut cfg_needed = 0u32;
                    QueryServiceConfigW(svc, std::ptr::null_mut(), 0, &mut cfg_needed);
                    if cfg_needed > 0 {
                        let mut cfg_buf = vec![0u8; cfg_needed as usize];
                        let cfg = cfg_buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
                        if QueryServiceConfigW(svc, cfg, cfg_needed, &mut cfg_needed) != 0 {
                            binary_path = from_wide((*cfg).lpBinaryPathName);
                        }
                    }
                    CloseServiceHandle(svc);
                }
                out.push(ServiceInfo {
                    name,
                    display_name: from_wide(e.lpDisplayName),
                    binary_path,
                    state: service_state_str(e.ServiceStatusProcess.dwCurrentState)
                        .to_string(),
                });
            }
        }
        CloseServiceHandle(scm);
    }
    out
}

// ---------------------------------------------------------------------------
// WMI persistence (root\subscription, in-process WMI COM — no powershell.exe)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct WmiObject {
    pub class_name: String,
    pub name: String,
    pub detail: String,
}

fn wmi_objects_of_class(
    svc: &crate::wmicom::WmiSvc,
    class: &str,
    fields: &[&str],
) -> Vec<WmiObject> {
    let mut out = Vec::new();
    for row in svc.query(class, fields) {
        let get = |k: &str| crate::wmicom::row_prop(&row, k);
        let name = get("Name");
        let detail = match class {
            "__EventFilter" => get("Query"),
            "CommandLineEventConsumer" => {
                let exe = get("ExecutablePath");
                let tpl = get("CommandLineTemplate");
                if !exe.is_empty() {
                    format!("{exe} {tpl}").trim().to_string()
                } else {
                    tpl
                }
            }
            "__FilterToConsumerBinding" => {
                format!("{} -> {}", get("Filter"), get("Consumer"))
            }
            _ => String::new(),
        };
        out.push(WmiObject {
            class_name: class.to_string(),
            name,
            detail,
        });
    }
    out
}

pub fn wmi_persistence() -> Vec<WmiObject> {
    let Some(svc) = crate::wmicom::connect() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(wmi_objects_of_class(&svc, "__EventFilter", &["Name", "Query"]));
    out.extend(wmi_objects_of_class(
        &svc,
        "CommandLineEventConsumer",
        &["Name", "ExecutablePath", "CommandLineTemplate"],
    ));
    out.extend(wmi_objects_of_class(
        &svc,
        "__FilterToConsumerBinding",
        &["Filter", "Consumer"],
    ));
    out
}

// ---------------------------------------------------------------------------
// Command-line target extraction
// ---------------------------------------------------------------------------

fn expand_env(path: &str) -> String {
    if !path.contains('%') {
        return path.to_string();
    }
    let wsrc = wide(path);
    let mut buf = [0u16; 2048];
    unsafe {
        let n = windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW(
            wsrc.as_ptr(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        if n == 0 || n as usize > buf.len() {
            return path.to_string();
        }
        String::from_utf16_lossy(&buf[..(n as usize).saturating_sub(1)])
    }
}

/// Best-effort extraction of the executable path from a command line
/// (Run value, task action, service binary path, WMI command line).
pub fn extract_exe_path(command: &str) -> Option<String> {
    let cmd = command.trim();
    if cmd.is_empty() {
        return None;
    }
    let mut candidate = if let Some(rest) = cmd.strip_prefix('"') {
        match rest.find('"') {
            Some(end) => rest[..end].to_string(),
            None => rest.to_string(),
        }
    } else {
        let lower = cmd.to_ascii_lowercase();
        match lower.find(".exe") {
            Some(pos) => cmd[..pos + 4].trim().to_string(),
            None => cmd
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches('"')
                .to_string(),
        }
    };
    if candidate.is_empty() {
        return None;
    }
    candidate = expand_env(&candidate);
    Some(candidate)
}
