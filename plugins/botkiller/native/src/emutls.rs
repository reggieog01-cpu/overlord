//! Emulated-TLS runtime: provides `__emutls_get_address`, the only runtime
//! symbol LLVM needs when the crate (and std, via -Zbuild-std) is compiled
//! with `-Ztls-model=emulated`.
//!
//! Why emulated TLS: Overlord's in-memory PE loader cannot wire compiler-
//! emitted native TLS. `#[thread_local]` access reads the TEB's
//! ThreadLocalStoragePointer array (gs:[0x58]) at `_tls_index` — an array
//! ntdll owns and rewrites whenever a late-loaded DLL claims the same
//! module-TLS index. With emulated TLS every thread-local goes through this
//! function, which uses plain Win32 TlsAlloc/TlsGetValue — per-thread storage
//! ntdll never touches — so the DLL no longer depends on the loader's TLS
//! provisioning at all.
//!
//! Layout of LLVM's control struct (verified from emitted COFF objects):
//!   +0x00 size: usize
//!   +0x08 align: usize
//!   +0x10 index: usize   (0 until first use; assigned here, 1-based)
//!   +0x18 initial: *const u8  (points at `__emutls_t.*`, or null = zero-init)
//!
//! This file must not use any thread-local state itself (it would recurse):
//! plain atomics, the System allocator (HeapAlloc — no TLS on Windows), and
//! Win32 TLS APIs only. Per-thread arrays and object allocations are
//! deliberately leaked at thread exit (few short-lived threads).

use std::alloc::{alloc, dealloc, Layout};
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

extern "system" {
    fn TlsAlloc() -> u32;
    fn TlsGetValue(index: u32) -> *mut c_void;
    fn TlsSetValue(index: u32, value: *mut c_void) -> i32;
}

#[repr(C)]
pub struct EmutlsControl {
    size: usize,
    align: usize,
    index: AtomicUsize,
    initial: *const u8,
}

const TLS_OUT_OF_INDEXES: u32 = 0xFFFF_FFFF;

static SLOT: AtomicU32 = AtomicU32::new(TLS_OUT_OF_INDEXES);
static NEXT_INDEX: AtomicUsize = AtomicUsize::new(1);

const INITIAL_CAPACITY: usize = 64;

/// Per-thread address array header: [capacity][data...].
fn array_data(arr: *mut c_void) -> *mut usize {
    unsafe { (arr as *mut usize).add(1) }
}

fn array_cap(arr: *const c_void) -> usize {
    unsafe { *(arr as *const usize) }
}

unsafe fn new_array(cap: usize) -> *mut c_void {
    let layout = match Layout::from_size_align((cap + 1) * std::mem::size_of::<usize>(), 16) {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };
    let p = alloc(layout) as *mut usize;
    if p.is_null() {
        return std::ptr::null_mut();
    }
    std::ptr::write_bytes(p, 0, cap + 1);
    *p = cap;
    p as *mut c_void
}

unsafe fn tls_slot() -> Option<u32> {
    let published = SLOT.load(Ordering::Acquire);
    if published != TLS_OUT_OF_INDEXES {
        return Some(published);
    }
    let idx = TlsAlloc();
    if idx == TLS_OUT_OF_INDEXES {
        return None;
    }
    SLOT.store(idx, Ordering::SeqCst);
    Some(idx)
}

#[no_mangle]
pub unsafe extern "C" fn __emutls_get_address(control: *mut EmutlsControl) -> usize {
    if control.is_null() {
        return 0;
    }
    let c = &*control;

    // Assign a global index on first use (1-based).
    let mut index = c.index.load(Ordering::Acquire);
    if index == 0 {
        let new = NEXT_INDEX.fetch_add(1, Ordering::SeqCst);
        index = match c
            .index
            .compare_exchange(0, new, Ordering::SeqCst, Ordering::Acquire)
        {
            Ok(_) => new,
            Err(cur) => cur,
        };
    }

    let slot_idx = match tls_slot() {
        Some(s) => s,
        None => return 0,
    };

    // Per-thread address array.
    let mut arr = TlsGetValue(slot_idx);
    if arr.is_null() {
        arr = new_array(INITIAL_CAPACITY);
        if arr.is_null() || TlsSetValue(slot_idx, arr) == 0 {
            return 0;
        }
    }
    if index > array_cap(arr) {
        // Grow: new capacity covers the index with headroom.
        let new_cap = (array_cap(arr) * 2).max(index + 16);
        let bigger = new_array(new_cap);
        if bigger.is_null() {
            return 0;
        }
        std::ptr::copy_nonoverlapping(array_data(arr), array_data(bigger), array_cap(arr));
        if TlsSetValue(slot_idx, bigger) == 0 {
            return 0;
        }
        dealloc(
            arr as *mut u8,
            Layout::from_size_align((array_cap(arr) + 1) * std::mem::size_of::<usize>(), 16)
                .unwrap_unchecked(),
        );
        arr = bigger;
    }

    let data = array_data(arr);
    let existing = *data.add(index - 1);
    if existing != 0 {
        return existing;
    }

    // First use on this thread: allocate and initialize the object.
    let size = c.size.max(1);
    let align = c.align.clamp(1, 4096);
    let layout = match Layout::from_size_align(size, align) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let p = alloc(layout);
    if p.is_null() {
        return 0;
    }
    if c.initial.is_null() {
        std::ptr::write_bytes(p, 0, c.size);
    } else {
        std::ptr::copy_nonoverlapping(c.initial, p, c.size);
    }
    *data.add(index - 1) = p as usize;
    p as usize
}
