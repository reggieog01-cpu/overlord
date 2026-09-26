//! In-memory ZIP writer wrapping the `zip` crate (deflate).

use std::io::{Cursor, Write};

pub struct ZipBuilder {
    writer: zip::ZipWriter<Cursor<Vec<u8>>>,
    /// Set on any start_file/write_all failure: the archive may be corrupt,
    /// so finish() must refuse to hand it out.
    failed: bool,
}

impl ZipBuilder {
    pub fn new() -> Self {
        Self {
            writer: zip::ZipWriter::new(Cursor::new(Vec::new())),
            failed: false,
        }
    }

    /// Add a file at a zip-internal path (forward slashes).
    pub fn add_file(&mut self, path: &str, data: &[u8]) {
        if self.failed {
            return;
        }
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        if self.writer.start_file(path, opts).is_err() {
            self.failed = true;
            return;
        }
        if self.writer.write_all(data).is_err() {
            self.failed = true;
        }
    }

    pub fn finish(self) -> Result<Vec<u8>, String> {
        if self.failed {
            return Err("zip write error".to_string());
        }
        self.writer
            .finish()
            .map(|c| c.into_inner())
            .map_err(|e| e.to_string())
    }
}
