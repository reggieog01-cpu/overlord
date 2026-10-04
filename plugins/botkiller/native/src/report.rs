//! Scan report model and the scan pipeline that turns raw enumeration into
//! scored findings. `build_scan` is shared by the `scan` event and by
//! remediation (targets are resolved against a fresh scan so whitelist and
//! process state are re-checked at action time).

use serde::Serialize;

use crate::detect::{self, EnvDirs};
use crate::enumerate;
use crate::whitelist::{self, Whitelist};

#[derive(Serialize, Clone)]
pub struct PersistenceRef {
    pub kind: String, // "run_key" | "environment_logon_script" | "scheduled_task" | "startup_item" | "wmi_subscription"
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hive: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wmi_class: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct Finding {
    pub id: String,
    pub kind: String, // "process" | "run_key" | "environment_logon_script" | "scheduled_task" | "startup_item" | "service" | "wmi_subscription"
    pub name: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    pub score: u32,
    pub verdict: String,
    pub reasons: Vec<String>,
    pub persistence: Vec<PersistenceRef>,
    /// Copy of the persistence descriptor when this finding is itself a
    /// persistence entry (used by remediation).
    #[serde(skip)]
    pub self_ref: Option<PersistenceRef>,
}

impl Finding {
    pub fn self_ref_name(&self) -> String {
        self.self_ref
            .as_ref()
            .map(|r| r.name.clone())
            .unwrap_or_else(|| self.name.clone())
    }
}

#[derive(Serialize)]
pub struct ScanReport {    pub generated_at: u64,
    pub findings: Vec<Finding>,
    pub whitelisted_count: usize,
}

fn fnv64(parts: &[&str]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for &b in part.as_bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

pub fn finding_id(kind: &str, name: &str, path: &str) -> String {
    format!("{:016x}", fnv64(&[kind, name, &whitelist::normalize_path(path)]))
}

fn untouchable_reason(wl: &Whitelist, path: &str) -> Option<String> {
    // System check first: cheap, and keeps C:\Windows files out of the
    // hashing path inside whitelisted_path_reason.
    if whitelist::is_system_path(wl, path) {
        return Some("system path".to_string());
    }
    if let Some(r) = whitelist::whitelisted_path_reason(wl, path) {
        return Some(r.to_string());
    }
    None
}

fn finalize(mut f: Finding, whitelisted: Option<String>, score: detect::Score) -> Finding {
    let (verdict, mut reasons) = detect::verdict(whitelisted, score.points);
    if reasons.is_empty() {
        reasons = score.reasons;
    }
    f.signed = score.signed;
    f.verdict = verdict;
    f.score = if f.verdict == "trusted" { 0 } else { score.points };
    f.reasons = reasons;
    f
}

pub fn build_scan() -> ScanReport {
    let env = EnvDirs::capture();
    let wl = unsafe { whitelist::get() };
    let Some(wl) = wl else {
        return ScanReport {
            generated_at: 0,
            findings: Vec::new(),
            whitelisted_count: 0,
        };
    };

    let procs = enumerate::processes();
    let run_keys = enumerate::run_keys();
    let env_values = enumerate::environment_values();
    let tasks = enumerate::scheduled_tasks();
    let startup = enumerate::startup_items();
    let services = enumerate::services();
    let wmi = enumerate::wmi_persistence();

    let mut findings: Vec<Finding> = Vec::new();
    let mut whitelisted_count = 0usize;

    // Persistence findings first so processes can reference them.
    let mut persistence_targets: Vec<(PersistenceRef, String)> = Vec::new();

    for rk in &run_keys {
        let target = enumerate::extract_exe_path(&rk.command).unwrap_or_default();
        let pref = PersistenceRef {
            kind: "run_key".into(),
            name: rk.value_name.clone(),
            hive: Some(rk.hive.clone()),
            view: Some(rk.view),
            subkey: Some(rk.subkey.clone()),
            file_path: None,
            wmi_class: None,
        };
        let whitelisted = if whitelist::is_overlord_run_value(&rk.value_name)
            || whitelist::is_operator_name(wl, &rk.value_name)
        {
            Some("whitelisted: overlord agent".to_string())
        } else {
            untouchable_reason(wl, &target)
        };
        let score = if whitelisted.is_some() {
            detect::Score::placeholder()
        } else {
            detect::score_persistence(&env, wl, &rk.value_name, &target)
        };
        if whitelisted.is_some() {
            whitelisted_count += 1;
        }
        let name = format!("{}\\{}\\{}", rk.hive, rk.subkey, rk.value_name);
        let id = finding_id("run_key", &name, &target);
        persistence_targets.push((pref.clone(), whitelist::normalize_path(&target)));
        let mut f = finalize(
            Finding {
                id,
                kind: "run_key".into(),
                name,
                path: target,
                pid: None,
                ppid: None,
                signed: None,
                score: 0,
                verdict: String::new(),
                reasons: Vec::new(),
                persistence: Vec::new(),
                self_ref: Some(pref),
            },
            whitelisted,
            score,
        );
        f.reasons
            .insert(0, format!("command: {}", rk.command));
        findings.push(f);
    }

    for ev in &env_values {
        let target = enumerate::extract_exe_path(&ev.command).unwrap_or_default();
        let pref = PersistenceRef {
            kind: "environment_logon_script".into(),
            name: ev.value_name.clone(),
            hive: Some(ev.hive.clone()),
            view: Some(ev.view),
            subkey: Some(ev.subkey.clone()),
            file_path: None,
            wmi_class: None,
        };
        // No name-based agent rule (entry names are random per build); the
        // path check anchors to the agent's install dir / own image.
        let whitelisted = if whitelist::is_operator_name(wl, &ev.value_name) {
            Some("whitelisted: operator".to_string())
        } else {
            untouchable_reason(wl, &target)
        };
        let score = if whitelisted.is_some() {
            detect::Score::placeholder()
        } else {
            detect::score_persistence(&env, wl, &ev.value_name, &target)
        };
        if whitelisted.is_some() {
            whitelisted_count += 1;
        }
        let name = format!("{}\\{}\\{}", ev.hive, ev.subkey, ev.value_name);
        let id = finding_id("environment_logon_script", &name, &target);
        persistence_targets.push((pref.clone(), whitelist::normalize_path(&target)));
        let mut f = finalize(
            Finding {
                id,
                kind: "environment_logon_script".into(),
                name,
                path: target,
                pid: None,
                ppid: None,
                signed: None,
                score: 0,
                verdict: String::new(),
                reasons: Vec::new(),
                persistence: Vec::new(),
                self_ref: Some(pref),
            },
            whitelisted,
            score,
        );
        f.reasons
            .insert(0, format!("command: {}", ev.command));
        findings.push(f);
    }

    for t in &tasks {
        let target = t
            .execs
            .iter()
            .find_map(|e| enumerate::extract_exe_path(e))
            .unwrap_or_default();
        let pref = PersistenceRef {
            kind: "scheduled_task".into(),
            name: t.name.clone(),
            hive: None,
            view: None,
            subkey: None,
            file_path: None,
            wmi_class: None,
        };
        let whitelisted = if whitelist::is_overlord_task_name(&t.name)
            || whitelist::is_operator_name(wl, &t.name)
        {
            Some("whitelisted: overlord agent".to_string())
        } else {
            untouchable_reason(wl, &target)
        };
        let score = if whitelisted.is_some() {
            detect::Score::placeholder()
        } else {
            detect::score_persistence(&env, wl, &t.name, &target)
        };
        if whitelisted.is_some() {
            whitelisted_count += 1;
        }
        let id = finding_id("scheduled_task", &t.name, &target);
        persistence_targets.push((pref.clone(), whitelist::normalize_path(&target)));
        findings.push(finalize(
            Finding {
                id,
                kind: "scheduled_task".into(),
                name: t.name.clone(),
                path: target,
                pid: None,
                ppid: None,
                signed: None,
                score: 0,
                verdict: String::new(),
                reasons: Vec::new(),
                persistence: Vec::new(),
                self_ref: Some(pref),
            },
            whitelisted,
            score,
        ));
    }

    for s in &startup {
        let target = s.target.clone().unwrap_or_default();
        let name = whitelist::file_name(&s.path).to_string();
        let pref = PersistenceRef {
            kind: "startup_item".into(),
            name: name.clone(),
            hive: None,
            view: None,
            subkey: None,
            file_path: Some(s.path.clone()),
            wmi_class: None,
        };
        let whitelisted = if whitelist::is_operator_name(wl, &name) {
            Some("whitelisted: operator".to_string())
        } else {
            // For .lnk the target is unresolved; the link file itself is the
            // path-based check.
            untouchable_reason(wl, if target.is_empty() { &s.path } else { &target })
        };
        let score = if whitelisted.is_some() || target.is_empty() {
            detect::Score::placeholder()
        } else {
            detect::score_persistence(&env, wl, &name, &target)
        };
        if whitelisted.is_some() {
            whitelisted_count += 1;
        }
        let id = finding_id("startup_item", &s.path, &target);
        persistence_targets.push((pref.clone(), whitelist::normalize_path(&target)));
        findings.push(finalize(
            Finding {
                id,
                kind: "startup_item".into(),
                name,
                path: if target.is_empty() { s.path.clone() } else { target },
                pid: None,
                ppid: None,
                signed: None,
                score: 0,
                verdict: String::new(),
                reasons: Vec::new(),
                persistence: Vec::new(),
                self_ref: Some(pref),
            },
            whitelisted,
            score,
        ));
    }

    for w in &wmi {
        let target = if w.class_name == "CommandLineEventConsumer" {
            enumerate::extract_exe_path(&w.detail).unwrap_or_default()
        } else {
            String::new()
        };
        let pref = PersistenceRef {
            kind: "wmi_subscription".into(),
            // Bindings have no Name; carry the "Filter -> Consumer" reference
            // pair so remediation can target the object.
            name: if w.class_name == "__FilterToConsumerBinding" {
                w.detail.clone()
            } else {
                w.name.clone()
            },
            hive: None,
            view: None,
            subkey: None,
            file_path: None,
            wmi_class: Some(w.class_name.clone()),
        };
        let whitelisted = if whitelist::is_overlord_wmi_name(&w.name)
            || whitelist::is_operator_name(wl, &w.name)
        {
            Some("whitelisted: overlord agent".to_string())
        } else if !target.is_empty() {
            untouchable_reason(wl, &target)
        } else {
            None
        };
        let score = if whitelisted.is_some() {
            detect::Score::placeholder()
        } else {
            detect::score_persistence(&env, wl, &w.name, &target)
        };
        if whitelisted.is_some() {
            whitelisted_count += 1;
        }
        let name = if w.name.is_empty() {
            format!("{} (unnamed)", w.class_name)
        } else {
            w.name.clone()
        };
        let id = finding_id("wmi_subscription", &format!("{}:{}", w.class_name, name), &target);
        persistence_targets.push((pref.clone(), whitelist::normalize_path(&target)));
        let mut f = finalize(
            Finding {
                id,
                kind: "wmi_subscription".into(),
                name,
                path: target,
                pid: None,
                ppid: None,
                signed: None,
                score: 0,
                verdict: String::new(),
                reasons: Vec::new(),
                persistence: Vec::new(),
                self_ref: Some(pref),
            },
            whitelisted,
            score,
        );
        if !w.detail.is_empty() {
            f.reasons.insert(0, format!("{}: {}", w.class_name, w.detail));
        }
        findings.push(f);
    }

    // Processes, linked to the persistence entries that point at their binary.
    for p in &procs {
        let npath = whitelist::normalize_path(&p.path);
        let linked: Vec<PersistenceRef> = persistence_targets
            .iter()
            .filter(|(_, target)| !target.is_empty() && *target == npath)
            .map(|(r, _)| r.clone())
            .collect();
        let whitelisted = if whitelist::is_critical_process_name(&p.name) {
            Some("system process".to_string())
        } else {
            untouchable_reason(wl, &p.path)
        };
        let score = if whitelisted.is_some() {
            detect::Score::placeholder()
        } else {
            detect::score_process(&env, wl, &p.name, &p.path, !linked.is_empty())
        };
        if whitelisted.is_some() {
            whitelisted_count += 1;
        }
        let id = finding_id("process", &p.name, &p.path);
        findings.push(finalize(
            Finding {
                id,
                kind: "process".into(),
                name: p.name.clone(),
                path: p.path.clone(),
                pid: Some(p.pid),
                ppid: Some(p.parent_pid),
                signed: None,
                score: 0,
                verdict: String::new(),
                reasons: Vec::new(),
                persistence: linked,
                self_ref: None,
            },
            whitelisted,
            score,
        ));
    }

    // Services: report-only in v1, still scored for visibility.
    for s in &services {
        let target = enumerate::extract_exe_path(&s.binary_path).unwrap_or_default();
        let whitelisted = untouchable_reason(wl, &target);
        let score = if whitelisted.is_some() {
            detect::Score::placeholder()
        } else {
            detect::score_persistence(&env, wl, &s.name, &target)
        };
        if whitelisted.is_some() {
            whitelisted_count += 1;
        }
        let id = finding_id("service", &s.name, &target);
        let mut f = finalize(
            Finding {
                id,
                kind: "service".into(),
                name: format!("{} ({})", s.display_name, s.name),
                path: target,
                pid: None,
                ppid: None,
                signed: None,
                score: 0,
                verdict: String::new(),
                reasons: Vec::new(),
                persistence: Vec::new(),
                self_ref: None,
            },
            whitelisted,
            score,
        );
        f.reasons
            .insert(0, format!("service {} — report-only", s.state));
        findings.push(f);
    }

    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    ScanReport {
        generated_at,
        findings,
        whitelisted_count,
    }
}
