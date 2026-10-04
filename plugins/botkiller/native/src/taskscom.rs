//! Scheduled task enumeration and deletion via in-process Task Scheduler COM
//! (no schtasks.exe child processes). Raw vtables — vtable indices verified
//! against the agent's own persist code and the taskschd IDL:
//!   ITaskService:              [7] GetFolder          [10] Connect
//!   ITaskFolder:               [8] get_Path  [10] GetFolders  [14] GetTasks
//!                              [15] DeleteTask
//!   ITaskFolderCollection /
//!   IRegisteredTaskCollection: [7] get_Count  [8] get_Item
//!   IRegisteredTask:           [7] get_Name   [19] get_Xml

use windows_sys::core::{BSTR, GUID};

use crate::com::{
    bstr, bstr_free, bstr_to_string, co_create, co_init, release, vtbl, Apartment, VariantRaw,
};

const CLSID_TASK_SCHEDULER: GUID = GUID::from_u128(0x0f87369f_a4e5_4cfc_bd3e_73e6154572dd);
const IID_ITASK_SERVICE: GUID = GUID::from_u128(0x2faba4c7_4da9_4013_9697_20cc3fd40f85);

const TASK_ENUM_HIDDEN: i32 = 1;

pub struct TaskSvc {
    _apt: Apartment,
    svc: *mut usize,
}

pub fn connect() -> Option<TaskSvc> {
    let apt = co_init()?;
    let svc = unsafe { co_create(&CLSID_TASK_SCHEDULER, &IID_ITASK_SERVICE) };
    if svc.is_null() {
        return None;
    }
    unsafe {
        let ev = VariantRaw::empty();
        type FnConnect = unsafe extern "system" fn(
            *mut usize,
            *const VariantRaw,
            *const VariantRaw,
            *const VariantRaw,
            *const VariantRaw,
        ) -> i32;
        let connect: FnConnect = std::mem::transmute(vtbl(svc, 10));
        if connect(svc, &ev, &ev, &ev, &ev) != 0 {
            release(svc);
            return None;
        }
    }
    Some(TaskSvc { _apt: apt, svc })
}

impl Drop for TaskSvc {
    fn drop(&mut self) {
        unsafe { release(self.svc) };
    }
}

unsafe fn get_count(coll: *mut usize) -> i32 {
    let mut n: i32 = 0;
    type Fn = unsafe extern "system" fn(*mut usize, *mut i32) -> i32;
    let f: Fn = std::mem::transmute(vtbl(coll, 7));
    f(coll, &mut n);
    n
}

unsafe fn collection_item(coll: *mut usize, index: i32) -> *mut usize {
    let mut obj: *mut usize = std::ptr::null_mut();
    let idx = VariantRaw::i4(index);
    type Fn = unsafe extern "system" fn(*mut usize, *const VariantRaw, *mut *mut usize) -> i32;
    let f: Fn = std::mem::transmute(vtbl(coll, 8));
    if f(coll, &idx, &mut obj) != 0 {
        return std::ptr::null_mut();
    }
    obj
}

unsafe fn get_bstr_prop(obj: *mut usize, idx: usize) -> String {
    let mut b: BSTR = std::ptr::null();
    type Fn = unsafe extern "system" fn(*mut usize, *mut BSTR) -> i32;
    let f: Fn = std::mem::transmute(vtbl(obj, idx));
    if f(obj, &mut b) != 0 {
        return String::new();
    }
    let s = bstr_to_string(b);
    bstr_free(b);
    s
}

fn xml_unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn extract_tag_values(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        match after.find(&close) {
            Some(end) => {
                out.push(xml_unescape(after[..end].trim()));
                rest = &after[end + close.len()..];
            }
            None => break,
        }
    }
    out
}

/// get_Xml with vtable-layout tolerance. Documented IRegisteredTask puts
/// get_Xml at slot 19, but on current Windows 11 builds the interface has an
/// extra method (Xml observed at slot 20, Definition at 19). Slot 19 is tried
/// first; only a *successful* slot-19 call that does not yield XML is treated
/// as a shifted layout (the returned pointer is then get_Definition's
/// ITaskDefinition, which is released) and slot 20 is tried. A failed slot-19
/// call means the standard layout with an erroring get_Xml — slot 20 would be
/// GetSecurityDescriptor with a different signature, so we stop there.
unsafe fn get_task_xml(task: *mut usize) -> String {
    for slot in [19usize, 20] {
        let mut b: BSTR = std::ptr::null();
        type Fn = unsafe extern "system" fn(*mut usize, *mut BSTR) -> i32;
        let f: Fn = std::mem::transmute(vtbl(task, slot));
        if f(task, &mut b) != 0 || b.is_null() {
            return String::new();
        }
        let byte_len = *(b as *const u32).sub(1) as usize;
        if byte_len % 2 == 0 && (10..=16 * 1024 * 1024).contains(&byte_len) && *b == b'<' as u16 {
            let s = bstr_to_string(b);
            bstr_free(b);
            return s;
        }
        if slot == 20 {
            return String::new();
        }
        release(b as *mut usize);
    }
    String::new()
}

impl TaskSvc {
    fn folder(&self, path: &str) -> *mut usize {
        unsafe {
            let b = bstr(path);
            let mut folder: *mut usize = std::ptr::null_mut();
            type Fn = unsafe extern "system" fn(*mut usize, BSTR, *mut *mut usize) -> i32;
            let f: Fn = std::mem::transmute(vtbl(self.svc, 7));
            let hr = f(self.svc, b, &mut folder);
            bstr_free(b);
            if hr != 0 {
                return std::ptr::null_mut();
            }
            folder
        }
    }

    /// (full task name, exec commands) for every task, recursively.
    pub fn enumerate(&self) -> Vec<(String, Vec<String>)> {
        let mut out = Vec::new();
        unsafe {
            let root = self.folder("\\");
            if !root.is_null() {
                self.enum_folder(root, 0, &mut out);
                release(root);
            }
        }
        out
    }

    unsafe fn enum_folder(&self, folder: *mut usize, depth: u32, out: &mut Vec<(String, Vec<String>)>) {
        if folder.is_null() || depth > 8 {
            return;
        }
        let folder_path = get_bstr_prop(folder, 8); // get_Path

        let mut coll: *mut usize = std::ptr::null_mut();
        type FnGetTasks = unsafe extern "system" fn(*mut usize, i32, *mut *mut usize) -> i32;
        let gt: FnGetTasks = std::mem::transmute(vtbl(folder, 14));
        if gt(folder, TASK_ENUM_HIDDEN, &mut coll) == 0 && !coll.is_null() {
            let count = get_count(coll);
            for i in 1..=count.max(0) {
                let task = collection_item(coll, i);
                if task.is_null() {
                    continue;
                }
                let name = get_bstr_prop(task, 7); // get_Name
                let xml = get_task_xml(task);
                let full = if folder_path == "\\" {
                    format!("\\{name}")
                } else {
                    format!("{folder_path}\\{name}")
                };
                let mut execs = extract_tag_values(&xml, "Command");
                execs.retain(|e| !e.is_empty());
                execs.sort();
                execs.dedup();
                out.push((full, execs));
                release(task);
            }
            release(coll);
        }

        let mut subs: *mut usize = std::ptr::null_mut();
        type FnGetFolders = unsafe extern "system" fn(*mut usize, i32, *mut *mut usize) -> i32;
        let gf: FnGetFolders = std::mem::transmute(vtbl(folder, 10));
        if gf(folder, 0, &mut subs) == 0 && !subs.is_null() {
            let count = get_count(subs);
            for i in 1..=count.max(0) {
                let sub = collection_item(subs, i);
                if sub.is_null() {
                    continue;
                }
                self.enum_folder(sub, depth + 1, out);
                release(sub);
            }
            release(subs);
        }
    }

    /// Delete a task by its full name (e.g. "\Microsoft\X\Y" or "\Z").
    pub fn delete(&self, full_name: &str) -> Result<(), String> {
        let (dir, leaf) = match full_name.rsplit_once('\\') {
            Some((d, l)) => (
                if d.is_empty() { "\\".to_string() } else { d.to_string() },
                l.to_string(),
            ),
            None => ("\\".to_string(), full_name.to_string()),
        };
        unsafe {
            let folder = self.folder(&dir);
            if folder.is_null() {
                return Err(format!("open folder {dir} failed"));
            }
            let b = bstr(&leaf);
            type Fn = unsafe extern "system" fn(*mut usize, BSTR, i32) -> i32;
            let f: Fn = std::mem::transmute(vtbl(folder, 15));
            let hr = f(folder, b, 0);
            bstr_free(b);
            release(folder);
            if hr == 0 {
                Ok(())
            } else {
                Err(format!("DeleteTask hr=0x{hr:08x}"))
            }
        }
    }
}
