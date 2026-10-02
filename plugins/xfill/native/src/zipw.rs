//! In-memory ZIP writer wrapping the `zip` crate (deflate).

use std::io::{Cursor, Write};

pub struct ZipBuilder {
    writer: zip::ZipWriter<Cursor<Vec<u8>>>,
    names: std::collections::HashSet<String>,
    /// Set on any start_file/write_all failure: the archive may be corrupt,
    /// so finish() must refuse to hand it out. Records the failing path.
    failed: Option<String>,
}

impl ZipBuilder {
    pub fn new() -> Self {
        Self {
            writer: zip::ZipWriter::new(Cursor::new(Vec::new())),
            names: std::collections::HashSet::new(),
            failed: None,
        }
    }

    /// Add a file at a zip-internal path (forward slashes).
    pub fn add_file(&mut self, path: &str, data: &[u8]) {
        if self.failed.is_some() {
            return;
        }
        // Duplicate entry names break start_file (and strict extractors) —
        // first copy wins, duplicates are skipped silently.
        if !self.names.insert(path.to_string()) {
            return;
        }
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        if self.writer.start_file(path, opts).is_err() {
            self.failed = Some(format!("start_file: {}", path));
            return;
        }
        if self.writer.write_all(data).is_err() {
            self.failed = Some(format!("write_all: {}", path));
        }
    }

    pub fn finish(self) -> Result<Vec<u8>, String> {
        if let Some(what) = self.failed {
            return Err(format!("zip write error: {}", what));
        }
        self.writer
            .finish()
            .map(|c| c.into_inner())
            .map_err(|e| e.to_string())
    }
}
