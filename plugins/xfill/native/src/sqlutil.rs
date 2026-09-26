//! SQLite opening that honors WAL sidecars, fully in-memory.
//!
//! Browsers keep their profile databases in WAL mode; rows written since the
//! last checkpoint live only in `<db>-wal` and are invisible to a bare file
//! image. The WAL is parsed here and its committed frames are applied to the
//! in-memory database image, which is then deserialized read-only. Rollback-
//! mode images deserialize directly. Nothing is ever written to disk.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

/// An opened database.
pub struct Db {
    conn: Connection,
}

impl std::ops::Deref for Db {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.conn
    }
}

fn wal_sidecar(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push("-wal");
    PathBuf::from(s)
}

/// Open a SQLite database file, replaying its WAL sidecar in memory if present.
pub fn open(path: &Path) -> Option<Db> {
    let bytes = crate::fsutil::read_file(path)?;
    if bytes.is_empty() {
        return None;
    }
    if is_wal_image(&bytes) {
        return open_wal_image(path, &bytes);
    }
    open_mem(&bytes)
}

/// True if the database image is in WAL mode (header read/write version 2).
fn is_wal_image(bytes: &[u8]) -> bool {
    bytes.len() > 19 && (bytes[18] == 2 || bytes[19] == 2)
}

fn open_wal_image(path: &Path, bytes: &[u8]) -> Option<Db> {
    let wal_path = wal_sidecar(path);
    if wal_path.is_file() {
        if let Some(wal) = crate::fsutil::read_file(&wal_path) {
            if let Some(image) = apply_wal(bytes, &wal) {
                return open_mem(&image);
            }
        }
    }
    // No usable WAL: the checkpointed image alone is still a valid database
    // (rows still in the WAL are lost). Relabel it rollback-mode so the
    // deserialized pager does not look for a wal-index.
    let mut image = bytes.to_vec();
    mark_rollback(&mut image);
    open_mem(&image)
}

// ---------------------------------------------------------------------------
// WAL replay (SQLite WAL format: 32-byte header, then frames of a 24-byte
// header followed by one page).
// ---------------------------------------------------------------------------

const WAL_HDR: usize = 32;
const FRAME_HDR: usize = 24;
/// Magic 0x377f0682: checksums are little-endian; 0x377f0683: big-endian.
const WAL_MAGIC_LE: u32 = 0x377f_0682;
const WAL_MAGIC_BE: u32 = 0x377f_0683;

/// Apply the committed frames of `wal` to the database image `db`, returning
/// the merged image relabeled as rollback-mode. Returns None if the WAL is
/// malformed or contains no valid commit frame.
fn apply_wal(db: &[u8], wal: &[u8]) -> Option<Vec<u8>> {
    if wal.len() < WAL_HDR {
        return None;
    }
    let little_endian = match be32(wal, 0)? {
        WAL_MAGIC_LE => true,
        WAL_MAGIC_BE => false,
        _ => return None,
    };
    let page_size = match be32(wal, 8)? {
        1 => 65536usize,
        n if (512..=65536).contains(&n) && n.is_power_of_two() => n as usize,
        _ => return None,
    };
    let salt1 = be32(wal, 16)?;
    let salt2 = be32(wal, 20)?;
    let (mut ck1, mut ck2) = wal_cksum(little_endian, 0, 0, &wal[0..24]);
    if ck1 != be32(wal, 24)? || ck2 != be32(wal, 28)? {
        return None;
    }

    // Validate frames in order; data past the first salt/checksum mismatch
    // belongs to a torn write or an older checkpoint epoch and is ignored.
    // Only frames up to and including the last valid commit frame are
    // replayed.
    //
    // Hard size bound: any page past the checkpointed image must come from a
    // wal frame, and each frame carries exactly one page — so the merged
    // database can never exceed base + wal + one page. Checksums are only
    // self-consistent (a corrupt or crafted wal can legitimately "validate"
    // absurd page numbers), so without this cap a garbage commit frame could
    // demand a multi-hundred-GB allocation and stall or kill the host.
    let frame_size = FRAME_HDR + page_size;
    let max_len = db.len().checked_add(wal.len())?.checked_add(page_size)?;
    let mut frames: Vec<(u32, usize)> = Vec::new(); // (page number, offset of page data)
    let mut commit: Option<(usize, u32)> = None; // (frame count, db size in pages)
    let mut off = WAL_HDR;
    while off + frame_size <= wal.len() {
        let pgno = be32(wal, off)?;
        let db_pages = be32(wal, off + 4)?;
        if pgno == 0 || be32(wal, off + 8)? != salt1 || be32(wal, off + 12)? != salt2 {
            break;
        }
        let (n1, n2) = wal_cksum(little_endian, ck1, ck2, &wal[off..off + 8]);
        let (n1, n2) = wal_cksum(little_endian, n1, n2, &wal[off + FRAME_HDR..off + frame_size]);
        if n1 != be32(wal, off + 16)? || n2 != be32(wal, off + 20)? {
            break;
        }
        ck1 = n1;
        ck2 = n2;
        // Reject frames that point past the reachable image size.
        if (pgno as usize).checked_mul(page_size)? > max_len {
            return None;
        }
        if db_pages != 0 && (db_pages as usize).checked_mul(page_size)? > max_len {
            return None;
        }
        frames.push((pgno, off + FRAME_HDR));
        if db_pages != 0 {
            commit = Some((frames.len(), db_pages));
        }
        off += frame_size;
    }
    let (count, db_pages) = commit?;
    let db_len = (db_pages as usize).checked_mul(page_size)?;
    if db_len == 0 {
        return None;
    }

    let mut image = db.to_vec();
    for &(pgno, data_off) in &frames[..count] {
        let start = (pgno as usize - 1).checked_mul(page_size)?;
        let end = start.checked_add(page_size)?;
        if end > image.len() {
            image.resize(end, 0);
        }
        image[start..end].copy_from_slice(&wal[data_off..data_off + page_size]);
    }
    // The commit frame's db size is authoritative (the checkpointed image may
    // be larger or smaller than the database after the replayed transactions).
    image.resize(db_len, 0);
    mark_rollback(&mut image);
    Some(image)
}

/// Relabel a database image as rollback-journal mode (header bytes 18/19).
fn mark_rollback(image: &mut [u8]) {
    if image.len() > 19 {
        image[18] = 1;
        image[19] = 1;
    }
}

fn be32(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

/// The WAL checksum: pairs of 32-bit words, endianness per the header magic.
fn wal_cksum(little_endian: bool, s1: u32, s2: u32, data: &[u8]) -> (u32, u32) {
    let (mut s1, mut s2) = (s1, s2);
    for pair in data.chunks_exact(8) {
        let (a, b) = if little_endian {
            (le32(pair, 0), le32(pair, 4))
        } else {
            (
                u32::from_be_bytes([pair[0], pair[1], pair[2], pair[3]]),
                u32::from_be_bytes([pair[4], pair[5], pair[6], pair[7]]),
            )
        };
        s1 = s1.wrapping_add(a).wrapping_add(s2);
        s2 = s2.wrapping_add(b).wrapping_add(s1);
    }
    (s1, s2)
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn open_mem(bytes: &[u8]) -> Option<Db> {
    if bytes.is_empty() {
        return None;
    }
    let conn = Connection::open_in_memory().ok()?;
    unsafe {
        let sz = bytes.len();
        let ptr = rusqlite::ffi::sqlite3_malloc(sz as i32) as *mut u8;
        if ptr.is_null() {
            return None;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, sz);
        let rc = rusqlite::ffi::sqlite3_deserialize(
            conn.handle(),
            b"main\0".as_ptr().cast(),
            ptr,
            sz as i64,
            sz as i64,
            rusqlite::ffi::SQLITE_DESERIALIZE_FREEONCLOSE
                | rusqlite::ffi::SQLITE_DESERIALIZE_READONLY,
        );
        if rc != rusqlite::ffi::SQLITE_OK as i32 {
            rusqlite::ffi::sqlite3_free(ptr.cast());
            return None;
        }
    }
    Some(Db { conn })
}
