//! Compile-time string obfuscation.
//!
//! `obf!("literal")` stores only XOR-mixed bytes in the image and decodes to
//! a `String` on use. The key byte is derived from the literal's own FNV-1a
//! hash, so every literal uses a different key and no plaintext (and no
//! single global key) survives into the binary. Each byte is additionally
//! mixed with its position, so single-byte-XOR sweeps recover nothing.

/// Derive a non-zero per-literal key byte from the literal itself.
pub const fn key_for(s: &str) -> u8 {
    (crate::resolve::fnv1a(s) as u8) | 1
}

/// XOR-encode `s` at compile time: byte i becomes `s[i] ^ key ^ (i * 0xA7)`.
pub const fn xor_enc<const N: usize>(s: &str, key: u8) -> [u8; N] {
    let b = s.as_bytes();
    assert!(b.len() == N);
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = b[i] ^ key ^ (i as u8).wrapping_mul(0xA7);
        i += 1;
    }
    out
}

/// Runtime decoder. All call sites pass ASCII/UTF-8 literals, but fall back
/// to lossy decoding rather than panic if that ever changes.
pub fn dec(enc: &[u8], key: u8) -> String {
    let mut v = Vec::with_capacity(enc.len());
    for (i, &b) in enc.iter().enumerate() {
        v.push(b ^ key ^ (i as u8).wrapping_mul(0xA7));
    }
    String::from_utf8(v).unwrap_or_default()
}

/// Obfuscated string literal: `obf!("Login Data")` expands to a fresh
/// `String` decoded from compile-time-encrypted bytes. The plaintext literal
/// is consumed entirely at compile time and never appears in the binary.
#[macro_export]
macro_rules! obf {
    ($s:literal) => {{
        const KEY: u8 = $crate::strcrypt::key_for($s);
        const ENC: [u8; $s.len()] = $crate::strcrypt::xor_enc($s, KEY);
        $crate::strcrypt::dec(&ENC, KEY)
    }};
}
