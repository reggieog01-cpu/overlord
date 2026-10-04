//! Destructive remediation: kill processes, delete binaries, remove
//! persistence. Every action re-checks the whitelist immediately before it
//! runs; whitelisted/system targets are refused outright.

use serde::Serialize;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Storage::FileSystem::{DeleteFileW, MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_SET_VALUE, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
};
use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

use crate::enumerate::wide;
use crate::report::{Finding, PersistenceRef, ScanReport};
use crate::whitelist::{self, Whitelist};

#[derive(Serialize)]
pub struct TargetOutcome {
    pub id: String,
    pub ok: bool,
    pub actions: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Serialize)]
pub struct RemediateReport {
    pub dry_run: bool,
    pub results: Vec<TargetOutcome>,
    pub summary: serde_json::Value,
}

struct Outcome {
    actions: Vec<String>,
    errors: Vec<String>,
}

impl Outcome {
    fn new() -> Self {
        Outcome {
            actions: Vec::new(),
            errors: Vec::new(),
        }
    }
    fn act(&mut self, s: String) {
        self.actions.push(s);
    }
    fn err(&mut self, s: String) {
        self.errors.push(s);
    }
}

/// Lazily-opened COM connections shared across one remediate run.
struct ComState {
    tasks: Option<crate::taskscom::TaskSvc>,
    wmi: Option<crate::wmicom::WmiSvc>,
}

impl ComState {
    fn new() -> Self {
        ComState {
            tasks: None,
            wmi: None,
        }
    }
    fn tasks(&mut self) -> Option<&crate::taskscom::TaskSvc> {
        if self.tasks.is_none() {
            self.tasks = crate::taskscom::connect();
        }
        self.tasks.as_ref()
    }
    fn wmi(&mut self) -> Option<&crate::wmicom::WmiSvc> {
        if self.wmi.is_none() {
            self.wmi = crate::wmicom::connect();
        }
        self.wmi.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Destructive primitives (each re-checks the whitelist first)
// ---------------------------------------------------------------------------

fn kill_pid(wl: &Whitelist, pid: u32, image_path: &str, dry_run: bool, out: &mut Outcome) {
    if pid == wl.self_pid {
        out.err(format!("refused to kill pid {pid}: overlord agent process"));
        return;
    }
    if whitelist::whitelisted_path_reason(wl, image_path).is_some()
        || whitelist::is_system_path(wl, image_path)
    {
        out.err(format!("refused to kill pid {pid}: whitelisted path {image_path}"));
        return;
    }
    if dry_run {
        out.act(format!("plan: terminate pid {pid} ({image_path})"));
        return;
    }
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            out.err(format!("OpenProcess({pid}) failed (error {})", std::io::Error::last_os_error()));
            return;
        }
        if TerminateProcess(h, 1) != 0 {
            out.act(format!("terminated pid {pid}"));
        } else {
            out.err(format!("TerminateProcess({pid}) failed (error {})", std::io::Error::last_os_error()));
        }
        CloseHandle(h);
    }
}

fn delete_binary(wl: &Whitelist, path: &str, dry_run: bool, out: &mut Outcome) {
    if path.is_empty() {
        return;
    }
    if whitelist::whitelisted_path_reason(wl, path).is_some()
        || whitelist::is_system_path(wl, path)
    {
        out.err(format!("refused to delete {path}: whitelisted"));
        return;
    }
    if dry_run {
        out.act(format!("plan: delete file {path}"));
        return;
    }
    let wpath = wide(path);
    unsafe {
        if DeleteFileW(wpath.as_ptr()) != 0 {
            out.act(format!("deleted file {path}"));
            return;
        }
        // In use or locked: schedule deletion at next reboot.
        if MoveFileExW(wpath.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) != 0 {
            out.act(format!("file in use; {path} scheduled for deletion at reboot"));
        } else {
            out.err(format!(
                "delete {path} failed (error {})",
                std::io::Error::last_os_error()
            ));
        }
    }
}

fn remove_run_key(
    wl: &Whitelist,
    hive: &str,
    view: u32,
    subkey: &str,
    value_name: &str,
    dry_run: bool,
    out: &mut Outcome,
) {
    if whitelist::is_overlord_run_value(value_name) || whitelist::is_operator_name(wl, value_name) {
        out.err(format!("refused to remove Run value {value_name}: whitelisted"));
        return;
    }
    if dry_run {
        out.act(format!("plan: delete Run value {hive}\\{subkey}\\{value_name} (view {view})"));
        return;
    }
    let root: HKEY = if hive.eq_ignore_ascii_case("HKLM") {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    };
    let view_flag = if view == 32 { KEY_WOW64_32KEY } else { KEY_WOW64_64KEY };
    unsafe {
        let wsub = wide(subkey);
        let mut hkey: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(root, wsub.as_ptr(), 0, KEY_SET_VALUE | view_flag, &mut hkey) != 0 {
            out.err(format!("RegOpenKeyExW {hive}\\{subkey} failed"));
            return;
        }
        let wname = wide(value_name);
        if RegDeleteValueW(hkey, wname.as_ptr()) == 0 {
            out.act(format!("deleted Run value {hive}\\{subkey}\\{value_name}"));
        } else {
            out.err(format!("RegDeleteValueW {value_name} failed"));
        }
        RegCloseKey(hkey);
    }
}

fn delete_task(
    com: &mut ComState,
    wl: &Whitelist,
    name: &str,
    dry_run: bool,
    out: &mut Outcome,
) {
    if whitelist::is_overlord_task_name(name) || whitelist::is_operator_name(wl, name) {
        out.err(format!("refused to delete task {name}: whitelisted"));
        return;
    }
    if dry_run {
        out.act(format!("plan: delete scheduled task {name}"));
        return;
    }
    match com.tasks() {
        Some(svc) => match svc.delete(name) {
            Ok(()) => out.act(format!("deleted scheduled task {name}")),
            Err(e) => out.err(format!("delete task {name}: {e}")),
        },
        None => out.err(format!("delete task {name}: task scheduler COM unavailable")),
    }
}

fn delete_startup_file(wl: &Whitelist, path: &str, dry_run: bool, out: &mut Outcome) {
    if whitelist::whitelisted_path_reason(wl, path).is_some()
        || whitelist::is_system_path(wl, path)
        || whitelist::is_operator_name(wl, whitelist::file_name(path))
    {
        out.err(format!("refused to delete startup item {path}: whitelisted"));
        return;
    }
    if dry_run {
        out.act(format!("plan: delete startup item {path}"));
        return;
    }
    let wpath = wide(path);
    unsafe {
        if DeleteFileW(wpath.as_ptr()) != 0 {
            out.act(format!("deleted startup item {path}"));
        } else {
            out.err(format!(
                "delete startup item {path} failed (error {})",
                std::io::Error::last_os_error()
            ));
        }
    }
}

fn remove_wmi(
    com: &mut ComState,
    wl: &Whitelist,
    class: &str,
    name: &str,
    dry_run: bool,
    out: &mut Outcome,
) {
    if whitelist::is_overlord_wmi_name(name) || whitelist::is_operator_name(wl, name) {
        out.err(format!("refused to remove WMI {class} {name}: whitelisted"));
        return;
    }
    if dry_run {
        out.act(format!("plan: remove WMI {class} {name}"));
        return;
    }
    let Some(svc) = com.wmi() else {
        out.err(format!("remove WMI {class} {name}: WMI COM unavailable"));
        return;
    };
    if class == "__FilterToConsumerBinding" {
        // name carries "Filter -> Consumer" raw references.
        let mut parts = name.splitn(2, " -> ");
        let filter = parts.next().unwrap_or("");
        let consumer = parts.next().unwrap_or("");
        let mut found = false;
        for row in svc.query("__FilterToConsumerBinding", &["Filter", "Consumer"]) {
            if crate::wmicom::row_prop(&row, "Filter") == filter
                && crate::wmicom::row_prop(&row, "Consumer") == consumer
            {
                found = true;
                match svc.delete_instance(&crate::wmicom::row_prop(&row, "__PATH")) {
                    Ok(()) => out.act(format!("removed WMI {class} {name}")),
                    Err(e) => out.err(format!("remove WMI {class} {name}: {e}")),
                }
            }
        }
        if !found {
            out.err(format!("remove WMI {class} {name}: binding not found"));
        }
        return;
    }
    // Drop bindings referencing the object first, then the object itself.
    let needle = format!("Name=\"{name}\"");
    for row in svc.query("__FilterToConsumerBinding", &["Filter", "Consumer"]) {
        if crate::wmicom::row_prop(&row, "Filter").contains(&needle)
            || crate::wmicom::row_prop(&row, "Consumer").contains(&needle)
        {
            let path = crate::wmicom::row_prop(&row, "__PATH");
            if let Err(e) = svc.delete_instance(&path) {
                out.err(format!("remove binding for {name}: {e}"));
            } else {
                out.act(format!("removed binding referencing {name}"));
            }
        }
    }
    let mut found = false;
    for row in svc.query(class, &["Name"]) {
        if crate::wmicom::row_prop(&row, "Name").eq_ignore_ascii_case(name) {
            found = true;
            match svc.delete_instance(&crate::wmicom::row_prop(&row, "__PATH")) {
                Ok(()) => out.act(format!("removed WMI {class} {name}")),
                Err(e) => out.err(format!("remove WMI {class} {name}: {e}")),
            }
        }
    }
    if !found {
        out.err(format!("remove WMI {class} {name}: instance not found"));
    }
}

fn remove_persistence(
    com: &mut ComState,
    wl: &Whitelist,
    pref: &PersistenceRef,
    dry_run: bool,
    out: &mut Outcome,
) {
    match pref.kind.as_str() {
        "run_key" | "environment_logon_script" => remove_run_key(
            wl,
            pref.hive.as_deref().unwrap_or("HKCU"),
            pref.view.unwrap_or(64),
            pref.subkey.as_deref().unwrap_or(""),
            &pref.name,
            dry_run,
            out,
        ),
        "scheduled_task" => delete_task(com, wl, &pref.name, dry_run, out),
        "startup_item" => {
            if let Some(p) = &pref.file_path {
                delete_startup_file(wl, p, dry_run, out);
            }
        }
        "wmi_subscription" => remove_wmi(
            com,
            wl,
            pref.wmi_class.as_deref().unwrap_or(""),
            &pref.name,
            dry_run,
            out,
        ),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

/// Reason a target must not be touched, checked fresh at remediate time.
fn refusal_reason(wl: &Whitelist, f: &Finding) -> Option<String> {
    match f.kind.as_str() {
        "process" => {
            if whitelist::is_critical_process_name(&f.name) {
                return Some("critical system process".into());
            }
            if whitelist::is_system_path(wl, &f.path) {
                return Some("system path".into());
            }
            if let Some(r) = whitelist::whitelisted_path_reason(wl, &f.path) {
                return Some(r.into());
            }
            None
        }
        "run_key" => {
            if whitelist::is_overlord_run_value(&f.self_ref_name()) {
                return Some("whitelisted: overlord agent".into());
            }
            path_refusal(wl, f)
        }
        "scheduled_task" => {
            if whitelist::is_overlord_task_name(&f.self_ref_name()) {
                return Some("whitelisted: overlord agent".into());
            }
            path_refusal(wl, f)
        }
        "wmi_subscription" => {
            if whitelist::is_overlord_wmi_name(&f.self_ref_name()) {
                return Some("whitelisted: overlord agent".into());
            }
            path_refusal(wl, f)
        }
        "startup_item" => path_refusal(wl, f),
        "environment_logon_script" => path_refusal(wl, f),
        "service" => Some("services are report-only in v1".into()),
        _ => Some("unknown finding kind".into()),
    }
}

fn path_refusal(wl: &Whitelist, f: &Finding) -> Option<String> {
    if whitelist::is_operator_name(wl, &f.self_ref_name()) {
        return Some("whitelisted: operator".into());
    }
    if whitelist::is_system_path(wl, &f.path) {
        return Some("system path".into());
    }
    if let Some(r) = whitelist::whitelisted_path_reason(wl, &f.path) {
        return Some(r.into());
    }
    None
}

fn remediate_one(
    com: &mut ComState,
    wl: &Whitelist,
    report: &ScanReport,
    id: &str,
    dry_run: bool,
) -> TargetOutcome {
    let mut out = Outcome::new();
    let Some(f) = report.findings.iter().find(|f| f.id == id) else {
        out.err("target id not found; re-scan required".into());
        return TargetOutcome {
            id: id.to_string(),
            ok: false,
            actions: out.actions,
            errors: out.errors,
        };
    };

    if let Some(reason) = refusal_reason(wl, f) {
        out.err(format!("refused: {reason}"));
        return TargetOutcome {
            id: id.to_string(),
            ok: false,
            actions: out.actions,
            errors: out.errors,
        };
    }

    let target_path = whitelist::normalize_path(&f.path);

    // 1. Kill processes: the finding's pid plus every process running the
    //    same binary.
    let mut pids: Vec<(u32, String)> = Vec::new();
    for p in report.findings.iter().filter(|x| x.kind == "process") {
        if let (Some(pid), path) = (p.pid, &p.path) {
            let matches = p.id == f.id
                || (!target_path.is_empty() && whitelist::normalize_path(path) == target_path);
            if matches && !pids.iter().any(|(e, _)| *e == pid) {
                pids.push((pid, path.clone()));
            }
        }
    }
    for (pid, path) in pids {
        kill_pid(wl, pid, &path, dry_run, &mut out);
    }

    // 2. Delete the binary.
    if !target_path.is_empty() {
        delete_binary(wl, &f.path, dry_run, &mut out);
    }

    // 3. Remove persistence: entries linked to this finding plus every
    //    persistence finding resolving to the same binary.
    let mut refs: Vec<PersistenceRef> = f.persistence.clone();
    if let Some(r) = &f.self_ref {
        refs.push(r.clone());
    }
    for g in report.findings.iter() {
        if g.id == f.id || g.self_ref.is_none() {
            continue;
        }
        if !target_path.is_empty() && whitelist::normalize_path(&g.path) == target_path {
            if let Some(r) = &g.self_ref {
                refs.push(r.clone());
            }
        }
    }
    // Dedupe identical entries.
    let mut seen: Vec<String> = Vec::new();
    for r in refs {
        let key = format!("{}|{}|{:?}|{:?}", r.kind, r.name, r.subkey, r.file_path);
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        remove_persistence(com, wl, &r, dry_run, &mut out);
    }

    if out.actions.is_empty() && out.errors.is_empty() {
        out.act("nothing to do".into());
    }
    TargetOutcome {
        id: id.to_string(),
        ok: out.errors.is_empty(),
        actions: out.actions,
        errors: out.errors,
    }
}

pub fn remediate(targets: &[String], dry_run: bool) -> RemediateReport {
    let report = crate::report::build_scan();
    let wl = unsafe { whitelist::get() };
    let mut results = Vec::new();
    match wl {
        Some(wl) => {
            let mut com = ComState::new();
            for id in targets {
                results.push(remediate_one(&mut com, wl, &report, id, dry_run));
            }
        }
        None => {
            for id in targets {
                results.push(TargetOutcome {
                    id: id.clone(),
                    ok: false,
                    actions: Vec::new(),
                    errors: vec!["whitelist not initialized".into()],
                });
            }
        }
    }
    let ok_count = results.iter().filter(|r| r.ok).count();
    RemediateReport {
        dry_run,
        summary: serde_json::json!({
            "targets": results.len(),
            "succeeded": ok_count,
            "failed": results.len() - ok_count,
        }),
        results,
    }
}
