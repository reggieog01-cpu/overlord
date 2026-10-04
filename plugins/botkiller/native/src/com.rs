//! Minimal COM plumbing shared by the Task Scheduler (taskscom.rs) and WMI
//! (wmicom.rs) modules: apartment guard, BSTR helpers, a raw 24-byte VARIANT,
//! and vtable access. All COM work is in-process — the plugin never spawns
//! child processes.
//!
//! windows-sys 0.61 does not expose ITaskService / IWbem* interfaces, so both
//! consumers call through raw vtables (same technique as the agent's own
//! persist code); only CLSID/IID GUIDs are needed here.

use windows_sys::core::{BSTR, GUID};
use windows_sys::Win32::Foundation::{SysAllocString, SysFreeString};
use windows_sys::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoUninitialize};

pub const RPC_E_CHANGED_MODE: i32 = 0x80010106u32 as i32;
/// CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER
pub const CLSCTX_INPROC_LOCAL: u32 = 5;

pub struct Apartment {
    uninit: bool,
}

pub fn co_init() -> Option<Apartment> {
    unsafe {
        const COINIT_MULTITHREADED: u32 = 0;
        let hr = CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED);
        if hr == 0 || hr == 1 {
            // S_OK / S_FALSE — we own (or share) the apartment.
            Some(Apartment { uninit: true })
        } else if hr == RPC_E_CHANGED_MODE {
            // Host already initialized STA; COM still usable, no uninit.
            Some(Apartment { uninit: false })
        } else {
            None
        }
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.uninit {
            unsafe { CoUninitialize() };
        }
    }
}

pub fn bstr(s: &str) -> BSTR {
    let w = crate::enumerate::wide(s);
    unsafe { SysAllocString(w.as_ptr()) }
}

pub unsafe fn bstr_free(b: BSTR) {
    if !b.is_null() {
        SysFreeString(b);
    }
}

pub unsafe fn bstr_to_string(b: BSTR) -> String {
    if b.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *b.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(b, len))
}

/// Raw x64 VARIANT (24 bytes). Structs > 8 bytes are passed by hidden
/// pointer on the x64 ABI, so `*const VariantRaw` is how callees receive
/// by-value VARIANT arguments.
#[repr(C)]
pub struct VariantRaw {
    pub vt: u16,
    pub r1: u16,
    pub r2: u16,
    pub r3: u16,
    pub data: [u8; 16],
}

pub const VT_EMPTY: u16 = 0;
pub const VT_I4: u16 = 3;
pub const VT_BSTR: u16 = 8;

impl VariantRaw {
    pub fn empty() -> Self {
        VariantRaw {
            vt: VT_EMPTY,
            r1: 0,
            r2: 0,
            r3: 0,
            data: [0; 16],
        }
    }
    pub fn i4(v: i32) -> Self {
        let mut r = Self::empty();
        r.vt = VT_I4;
        r.data[..4].copy_from_slice(&v.to_le_bytes());
        r
    }
}

pub unsafe fn vtbl(obj: *mut usize, idx: usize) -> usize {
    let vt = *(obj as *const *const usize);
    *vt.add(idx)
}

pub unsafe fn release(obj: *mut usize) {
    if obj.is_null() {
        return;
    }
    let f: unsafe extern "system" fn(*mut usize) -> u32 = std::mem::transmute(vtbl(obj, 2));
    f(obj);
}

pub unsafe fn co_create(clsid: &GUID, iid: &GUID) -> *mut usize {
    let mut obj: *mut core::ffi::c_void = std::ptr::null_mut();
    let hr = CoCreateInstance(clsid, std::ptr::null_mut(), CLSCTX_INPROC_LOCAL, iid, &mut obj);
    if hr != 0 {
        return std::ptr::null_mut();
    }
    obj as *mut usize
}

// ---------------------------------------------------------------------------
// IDispatch helpers (for the SWbem* scripting interfaces, which are pure
// IDispatch; the classic IWbem* vtable interfaces are not registered on
// every Windows build).
// ---------------------------------------------------------------------------

pub const IID_IDISPATCH: GUID = GUID::from_u128(0x00020400_0000_0000_c000_000000000046);

pub const VT_DISPATCH: u16 = 9;
const DISPATCH_METHOD: u16 = 1;
const DISPATCH_PROPERTYGET: u16 = 2;
const DISPID_NEWENUM: i32 = -4;
const LOCALE_SYSTEM_DEFAULT: u32 = 0x0800;

impl VariantRaw {
    pub fn bstr_val(b: BSTR) -> Self {
        let mut v = Self::empty();
        v.vt = VT_BSTR;
        v.data[..8].copy_from_slice(&(b as usize).to_le_bytes());
        v
    }
    pub fn as_dispatch(&self) -> *mut usize {
        if self.vt != VT_DISPATCH {
            return std::ptr::null_mut();
        }
        usize::from_le_bytes(self.data[..8].try_into().unwrap()) as *mut usize
    }
    pub fn as_bstr(&self) -> BSTR {
        if self.vt != VT_BSTR {
            return std::ptr::null();
        }
        usize::from_le_bytes(self.data[..8].try_into().unwrap()) as BSTR
    }
}

pub unsafe fn variant_clear(v: &mut VariantRaw) {
    windows_sys::Win32::System::Variant::VariantClear(
        v as *mut VariantRaw as *mut windows_sys::Win32::System::Variant::VARIANT,
    );
}

#[repr(C)]
struct DispParams {
    rgvarg: *const VariantRaw,
    rgdispid_named: *const i32,
    c_args: u32,
    c_named: u32,
}

unsafe fn dispid_of(obj: *mut usize, name: &str) -> Option<i32> {
    let wname = crate::enumerate::wide(name);
    let null_guid = GUID::from_u128(0);
    let mut id: i32 = 0;
    type Fn = unsafe extern "system" fn(
        *mut usize,
        *const GUID,
        *const windows_sys::core::PCWSTR,
        u32,
        u32,
        *mut i32,
    ) -> i32;
    let f: Fn = std::mem::transmute(vtbl(obj, 5));
    if f(obj, &null_guid, &wname.as_ptr(), 1, LOCALE_SYSTEM_DEFAULT, &mut id) != 0 {
        return None;
    }
    Some(id)
}

/// Invoke an IDispatch method. `args` in natural order (reversed on the wire
/// as COM expects). Returns the result VARIANT on success.
pub unsafe fn invoke(
    obj: *mut usize,
    name: &str,
    wflags: u16,
    args: &[VariantRaw],
) -> Option<VariantRaw> {
    let dispid = dispid_of(obj, name)?;
    // COM wants arguments last-first.
    let mut rev: Vec<VariantRaw> = args.iter().rev().map(|a| VariantRaw { ..*a }).collect();
    let params = DispParams {
        rgvarg: if rev.is_empty() {
            std::ptr::null()
        } else {
            rev.as_ptr()
        },
        rgdispid_named: std::ptr::null(),
        c_args: rev.len() as u32,
        c_named: 0,
    };
    let null_guid = GUID::from_u128(0);
    let mut result = VariantRaw::empty();
    type Fn = unsafe extern "system" fn(
        *mut usize,
        i32,
        *const GUID,
        u32,
        u16,
        *const DispParams,
        *mut VariantRaw,
        *mut core::ffi::c_void,
        *mut u32,
    ) -> i32;
    let f: Fn = std::mem::transmute(vtbl(obj, 6));
    if f(
        obj,
        dispid,
        &null_guid,
        LOCALE_SYSTEM_DEFAULT,
        wflags,
        &params,
        &mut result,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    ) != 0
    {
        return None;
    }
    Some(result)
}

pub unsafe fn invoke_method(obj: *mut usize, name: &str, args: &[VariantRaw]) -> Option<VariantRaw> {
    invoke(obj, name, DISPATCH_METHOD, args)
}

pub unsafe fn invoke_get(obj: *mut usize, name: &str) -> Option<VariantRaw> {
    invoke(obj, name, DISPATCH_PROPERTYGET, &[])
}

/// Property getter that returns its result as a String (BSTR-valued).
pub unsafe fn get_string(obj: *mut usize, name: &str) -> String {
    let mut v = match invoke_get(obj, name) {
        Some(v) => v,
        None => return String::new(),
    };
    let s = bstr_to_string(v.as_bstr());
    variant_clear(&mut v);
    s
}

/// _NewEnum → IEnumVARIANT for a collection object.
pub unsafe fn enum_variant(coll: *mut usize) -> *mut usize {
    let mut v = match invoke_get(coll, "_NewEnum") {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let en = v.as_dispatch();
    if en.is_null() {
        variant_clear(&mut v);
        return std::ptr::null_mut();
    }
    en
}

/// IEnumVARIANT::Next (single item). Returned VARIANT must be cleared by the
/// caller. None at end of enumeration.
pub unsafe fn enum_next(en: *mut usize) -> Option<VariantRaw> {
    let mut v = VariantRaw::empty();
    let mut fetched: u32 = 0;
    type Fn = unsafe extern "system" fn(*mut usize, u32, *mut VariantRaw, *mut u32) -> i32;
    let f: Fn = std::mem::transmute(vtbl(en, 3));
    if f(en, 1, &mut v, &mut fetched) != 0 || fetched == 0 {
        return None;
    }
    Some(v)
}
