// SPDX-License-Identifier: GPL-2.0-only
//! Build-id pool lookups shared between the decoder (which writes the
//! index) and the server (which serves the debuginfod endpoints).
//!
//! Layout: <pool>/.build-id/xx/yyyy....debug (debuginfod convention),
//! written as symlinks into the extracted symbol trees.

use std::path::{Path, PathBuf};

/// Resolve a build-id to an indexed debug file. Rejects anything but
/// hex, so it can be fed straight from a URL path segment.
pub fn resolve(pool_root: &Path, build_id: &str) -> Option<PathBuf> {
    if build_id.len() < 4 || !build_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let build_id = build_id.to_lowercase();

    let link = pool_root
        .join(".build-id")
        .join(&build_id[..2])
        .join(format!("{}.debug", &build_id[2..]));

    link.exists().then_some(link)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_hex_and_short() {
        let root = Path::new("/nonexistent");
        assert!(resolve(root, "../../etc/passwd").is_none());
        assert!(resolve(root, "xyz").is_none());
        assert!(resolve(root, "ab").is_none());
        assert!(resolve(root, "abcd/ef").is_none());
    }

    #[test]
    fn resolves_indexed_id() {
        let tmp = std::env::temp_dir().join(format!("ucrs-buildid-test-{}", std::process::id()));
        let dir = tmp.join(".build-id/8d");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("74ef44.debug");
        std::fs::write(&file, b"elf").unwrap();

        assert_eq!(resolve(&tmp, "8d74ef44"), Some(file.clone()));
        assert_eq!(resolve(&tmp, "8D74EF44"), Some(file));
        assert!(resolve(&tmp, "8d74ef45").is_none());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
