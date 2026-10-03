//! Operator input → windows living on the virtual display.
//!
//! All injection is message-based (PostMessageW) aimed at the topmost window
//! under the translated point (mouse) or the last clicked window (keyboard).
//! Nothing touches the real desktop's input stream: the physical cursor never
//! moves and the user sees nothing.

use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use windows::Win32::Foundation::{HWND, LPARAM, POINT, WPARAM};
use windows::Win32::Graphics::Gdi::ScreenToClient;
use windows::Win32::UI::WindowsAndMessaging::*;

use crate::{DISP_H, DISP_W, DISP_X, DISP_Y};

// Win32 modifier-key flags (MK_*), defined locally to keep the feature set small.
const MK_LBUTTON: usize = 0x0001;
const MK_RBUTTON: usize = 0x0002;
const MK_MBUTTON: usize = 0x0010;

fn display_rect() -> (i32, i32, i32, i32) {
    (
        DISP_X.load(Ordering::Relaxed),
        DISP_Y.load(Ordering::Relaxed),
        DISP_W.load(Ordering::Relaxed),
        DISP_H.load(Ordering::Relaxed),
    )
}

// Last mouse position (display-local) and the window that last received a
// click — keyboard input goes there, matching how a real user behaves.
static LAST_X: AtomicI32 = AtomicI32::new(100);
static LAST_Y: AtomicI32 = AtomicI32::new(100);
static FOCUS_HWND: AtomicUsize = AtomicUsize::new(0);
static BUTTONS_DOWN: AtomicUsize = AtomicUsize::new(0);

struct EnumCtx {
    x: i32,
    y: i32,
    found: HWND,
}

unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> windows::core::BOOL {
    let ctx = &mut *(lparam.0 as *mut EnumCtx);
    if !IsWindowVisible(hwnd).as_bool() {
        return true.into();
    }
    let mut rc = std::mem::zeroed::<windows::Win32::Foundation::RECT>();
    if GetWindowRect(hwnd, &mut rc).is_err() {
        return true.into();
    }
    if ctx.x >= rc.left && ctx.x < rc.right && ctx.y >= rc.top && ctx.y < rc.bottom {
        // EnumWindows is z-order top-first: first hit is the topmost window.
        ctx.found = hwnd;
        return false.into();
    }
    true.into()
}

/// Topmost visible window at virtual-display-local coordinates (lx, ly),
/// drilled down to the deepest child under the point (top-level frames of
/// Chromium/WinUI apps ignore posted clicks; the render child needs them).
/// Returned with the point translated to the CHILD's client coordinates.
fn window_at(lx: i32, ly: i32) -> Option<(HWND, i32, i32)> {
    let (dx, dy, _, _) = display_rect();
    let sx = dx + lx;
    let sy = dy + ly;
    let mut ctx = EnumCtx {
        x: sx,
        y: sy,
        found: HWND::default(),
    };
    unsafe {
        let _ = EnumWindows(Some(enum_proc), LPARAM(&mut ctx as *mut EnumCtx as isize));
        if ctx.found.0.is_null() {
            return None;
        }
        let mut pt = POINT { x: sx, y: sy };
        let _ = ScreenToClient(ctx.found, &mut pt);
        let child = ChildWindowFromPointEx(
            ctx.found,
            pt,
            CWP_SKIPINVISIBLE | CWP_SKIPTRANSPARENT,
        );
        let target = if child.0.is_null() { ctx.found } else { child };
        let mut pt2 = POINT { x: sx, y: sy };
        let _ = ScreenToClient(target, &mut pt2);
        Some((target, pt2.x, pt2.y))
    }
}

/// Keyboard target: the last clicked window if it still exists, else whatever
/// is under the last mouse position.
fn key_target() -> Option<HWND> {
    let hwnd = HWND(FOCUS_HWND.load(Ordering::Relaxed) as *mut _);
    unsafe {
        if !hwnd.0.is_null() && IsWindow(Some(hwnd)).as_bool() {
            return Some(hwnd);
        }
    }
    window_at(
        LAST_X.load(Ordering::Relaxed),
        LAST_Y.load(Ordering::Relaxed),
    )
    .map(|(h, _, _)| h)
}

fn lparam_xy(x: i32, y: i32) -> LPARAM {
    LPARAM(((y as u32) << 16 | (x as u32 & 0xFFFF)) as isize)
}

fn post(hwnd: Option<HWND>, msg: u32, wparam: WPARAM, lparam: LPARAM) {
    unsafe {
        let _ = PostMessageW(hwnd, msg, wparam, lparam);
    }
}

fn button_bits(button: &str) -> (u32, u32, usize) {
    match button {
        "right" => (WM_RBUTTONDOWN, WM_RBUTTONUP, MK_RBUTTON),
        "middle" => (WM_MBUTTONDOWN, WM_MBUTTONUP, MK_MBUTTON),
        _ => (WM_LBUTTONDOWN, WM_LBUTTONUP, MK_LBUTTON),
    }
}

/// Handle one input event payload from the panel.
pub fn handle(body: &serde_json::Value) {
    let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let lx = body.get("x").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let ly = body.get("y").and_then(|v| v.as_i64()).unwrap_or(0) as i32;

    match kind {
        "mouse_move" => {
            LAST_X.store(lx, Ordering::Relaxed);
            LAST_Y.store(ly, Ordering::Relaxed);
            if let Some((hwnd, cx, cy)) = window_at(lx, ly) {
                let mk = BUTTONS_DOWN.load(Ordering::Relaxed);
                post(Some(hwnd), WM_MOUSEMOVE, WPARAM(mk), lparam_xy(cx, cy));
            }
        }
        "mouse_down" | "mouse_up" => {
            let button = body.get("button").and_then(|v| v.as_str()).unwrap_or("left");
            let (down_msg, up_msg, mk) = button_bits(button);
            if let Some((hwnd, cx, cy)) = window_at(lx, ly) {
                if kind == "mouse_down" {
                    BUTTONS_DOWN.fetch_or(mk, Ordering::Relaxed);
                    FOCUS_HWND.store(hwnd.0 as usize, Ordering::Relaxed);
                    post(Some(hwnd), WM_ACTIVATE, WPARAM(WA_ACTIVE as usize), LPARAM(0));
                    post(Some(hwnd), down_msg, WPARAM(mk), lparam_xy(cx, cy));
                } else {
                    BUTTONS_DOWN.fetch_and(!mk, Ordering::Relaxed);
                    post(Some(hwnd), up_msg, WPARAM(0), lparam_xy(cx, cy));
                }
            }
        }
        "wheel" => {
            let delta = body.get("delta").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            if let Some((hwnd, cx, cy)) = window_at(lx, ly) {
                // WM_MOUSEWHEEL wants screen coordinates, not client.
                let (dx, dy, _, _) = display_rect();
                let wparam = (((delta as u32) & 0xFFFF) << 16) as usize
                    | BUTTONS_DOWN.load(Ordering::Relaxed);
                post(Some(hwnd), WM_MOUSEWHEEL, WPARAM(wparam), lparam_xy(dx + cx, dy + cy));
            }
        }
        "key" => {
            let vk = body.get("vk").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let down = body.get("down").and_then(|v| v.as_bool()).unwrap_or(true);
            if vk == 0 {
                return;
            }
            if let Some(hwnd) = key_target() {
                let msg = if down { WM_KEYDOWN } else { WM_KEYUP };
                post(Some(hwnd), msg, WPARAM(vk as usize), LPARAM(0));
            }
        }
        "text" => {
            let text = body.get("text").and_then(|v| v.as_str()).unwrap_or("");
            if text.is_empty() {
                return;
            }
            if let Some(hwnd) = key_target() {
                for ch in text.chars() {
                    post(Some(hwnd), WM_CHAR, WPARAM(ch as usize), LPARAM(0));
                }
            }
        }
        _ => {}
    }
}
