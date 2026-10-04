//! WMI persistence enumeration and instance removal via in-process WMI COM
//! (no powershell.exe child processes). Raw vtables:
//!   IWbemLocator:         [3] ConnectServer
//!   IWbemServices:        [16] DeleteInstance  [20] ExecQuery
//!   IEnumWbemClassObject: [4] Next
//!   IWbemClassObject:     [4] Get

use windows_sys::core::{BSTR, GUID, PCWSTR};

use crate::com::{
    bstr, bstr_free, bstr_to_string, co_create, co_init, release, vtbl, Apartment, VariantRaw,
    VT_BSTR,
};

const CLSID_WBEM_LOCATOR: GUID = GUID::from_u128(0x4590f811_1d3a_11d0_891f_00aa004b2e39);
const IID_IWBEM_LOCATOR: GUID = GUID::from_u128(0xdc12a687_737f_11cf_884d_00aa004b2e24);

const WBEM_FLAG_FORWARD_ONLY: i32 = 0x20;
const WBEM_FLAG_RETURN_IMMEDIATELY: i32 = 0x10;
const WBEM_INFINITE: i32 = -1;

const RPC_C_AUTHN_WINNT: u32 = 10;
const RPC_C_AUTHZ_NONE: u32 = 0;
const RPC_C_AUTHN_LEVEL_DEFAULT: u32 = 0;
const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
const EOAC_NONE: u32 = 0;

pub struct WmiSvc {
    _apt: Apartment,
    svc: *mut usize,
}

pub fn connect() -> Option<WmiSvc> {
    let apt = co_init()?;
    unsafe {
        let loc = co_create(&CLSID_WBEM_LOCATOR, &IID_IWBEM_LOCATOR);
        if loc.is_null() {
            return None;
        }
        let ns = bstr("root\\subscription");
        let mut svc: *mut usize = std::ptr::null_mut();
        type FnConnect = unsafe extern "system" fn(
            *mut usize,
            BSTR,
            BSTR,
            BSTR,
            BSTR,
            i32,
            BSTR,
            *mut usize,
            *mut *mut usize,
        ) -> i32;
        let f: FnConnect = std::mem::transmute(vtbl(loc, 3));
        let hr = f(
            loc,
            ns,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut svc,
        );
        bstr_free(ns);
        release(loc);
        if hr != 0 || svc.is_null() {
            return None;
        }
        windows_sys::Win32::System::Com::CoSetProxyBlanket(
            svc as *mut core::ffi::c_void,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            std::ptr::null(),
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            std::ptr::null(),
            EOAC_NONE,
        );
        Some(WmiSvc { _apt: apt, svc })
    }
}

impl Drop for WmiSvc {
    fn drop(&mut self) {
        unsafe { release(self.svc) };
    }
}

/// One result row: (property name, string value) pairs, always ending with
/// the object's "__PATH".
pub type Row = Vec<(String, String)>;

pub fn row_prop(row: &Row, key: &str) -> String {
    row.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

unsafe fn get_prop_str(obj: *mut usize, name: &str) -> String {
    let w = crate::enumerate::wide(name);
    let mut v = VariantRaw::empty();
    type Fn = unsafe extern "system" fn(
        *mut usize,
        PCWSTR,
        i32,
        *mut VariantRaw,
        *mut i32,
        *mut i32,
    ) -> i32;
    let f: Fn = std::mem::transmute(vtbl(obj, 4));
    if f(obj, w.as_ptr(), 0, &mut v, std::ptr::null_mut(), std::ptr::null_mut()) != 0 {
        return String::new();
    }
    let s = if v.vt == VT_BSTR {
        let b = *(v.data.as_ptr() as *const BSTR);
        bstr_to_string(b)
    } else {
        String::new()
    };
    windows_sys::Win32::System::Variant::VariantClear(
        &mut v as *mut VariantRaw as *mut windows_sys::Win32::System::Variant::VARIANT,
    );
    s
}

impl WmiSvc {
    /// SELECT * FROM `class`, returning the requested props plus __PATH.
    pub fn query(&self, class: &str, props: &[&str]) -> Vec<Row> {
        let mut rows = Vec::new();
        unsafe {
            let lang = bstr("WQL");
            let q = bstr(&format!("SELECT * FROM {class}"));
            let mut en: *mut usize = std::ptr::null_mut();
            type Fn = unsafe extern "system" fn(
                *mut usize,
                BSTR,
                BSTR,
                i32,
                *mut usize,
                *mut *mut usize,
            ) -> i32;
            let f: Fn = std::mem::transmute(vtbl(self.svc, 20));
            let hr = f(
                self.svc,
                lang,
                q,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                std::ptr::null_mut(),
                &mut en,
            );
            bstr_free(lang);
            bstr_free(q);
            if hr != 0 || en.is_null() {
                return rows;
            }
            loop {
                let mut obj: *mut usize = std::ptr::null_mut();
                let mut n: u32 = 0;
                type FnNext = unsafe extern "system" fn(
                    *mut usize,
                    i32,
                    u32,
                    *mut *mut usize,
                    *mut u32,
                ) -> i32;
                let next: FnNext = std::mem::transmute(vtbl(en, 4));
                let hr = next(en, WBEM_INFINITE, 1, &mut obj, &mut n);
                if hr != 0 || n == 0 || obj.is_null() {
                    break;
                }
                let mut row: Row = Vec::with_capacity(props.len() + 1);
                for p in props {
                    row.push((p.to_string(), get_prop_str(obj, p)));
                }
                row.push(("__PATH".to_string(), get_prop_str(obj, "__PATH")));
                rows.push(row);
                release(obj);
            }
            release(en);
        }
        rows
    }

    pub fn delete_instance(&self, path: &str) -> Result<(), String> {
        unsafe {
            let b = bstr(path);
            type Fn = unsafe extern "system" fn(
                *mut usize,
                BSTR,
                i32,
                *mut usize,
                *mut usize,
            ) -> i32;
            let f: Fn = std::mem::transmute(vtbl(self.svc, 16));
            let hr = f(self.svc, b, 0, std::ptr::null_mut(), std::ptr::null_mut());
            bstr_free(b);
            if hr == 0 {
                Ok(())
            } else {
                Err(format!("DeleteInstance hr=0x{hr:08x}"))
            }
        }
    }
}
