// SPDX-License-Identifier: GPL-2.0-only
//! Report metadata as defined in docs/protocol.md section 1.

use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u32 = 1;
pub const MAX_METADATA_SIZE: usize = 4 * 1024;
pub const MAX_PAYLOAD_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    KernelOops,
    Pstore,
}

impl ReportKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReportKind::KernelOops => "kernel_oops",
            ReportKind::Pstore => "pstore",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEncoding {
    None,
    Gzip,
    Zstd,
    Zlib,
}

impl PayloadEncoding {
    pub fn as_str(&self) -> &'static str {
        match self {
            PayloadEncoding::None => "none",
            PayloadEncoding::Gzip => "gzip",
            PayloadEncoding::Zstd => "zstd",
            PayloadEncoding::Zlib => "zlib",
        }
    }
}

impl std::str::FromStr for PayloadEncoding {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(PayloadEncoding::None),
            "gzip" => Ok(PayloadEncoding::Gzip),
            "zstd" => Ok(PayloadEncoding::Zstd),
            "zlib" => Ok(PayloadEncoding::Zlib),
            _ => Err(format!("unknown payload encoding {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenwrtInfo {
    pub version: String,
    pub revision: String,
    /// target/subtarget, e.g. "mediatek/filogic"
    pub target: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub format: u32,
    pub kind: ReportKind,
    pub uuid: String,
    pub captured_at: i64,
    pub openwrt: OpenwrtInfo,
    pub board: String,
    /// Kernel package version incl. ~buildhash, or plain `uname -r`
    /// output on self-built images.
    pub kernel: String,
    /// GNU build-id of the running kernel (lowercase hex), from the
    /// NT_GNU_BUILD_ID note in /sys/kernel/notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_buildid: Option<String>,
    pub payload_sha256: String,
    pub payload_encoding: PayloadEncoding,
}

impl ReportMetadata {
    /// The kernel build hash from the `~hash` part of the package
    /// version, used to cross-check fetched debug symbols. None for
    /// self-built images that fell back to `uname -r`.
    pub fn kernel_buildhash(&self) -> Option<&str> {
        let (_, rest) = self.kernel.split_once('~')?;
        let hash = rest.split('-').next()?;
        (!hash.is_empty()).then_some(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_metadata() {
        let m: ReportMetadata = serde_json::from_str(
            r#"{
                "format": 1,
                "kind": "kernel_oops",
                "uuid": "f81d4fae-7dec-4b58-a94b-2c0dd4f1fc6f",
                "captured_at": 1751712000,
                "openwrt": {
                    "version": "25.12.5",
                    "revision": "r33051-f5dae5ece4",
                    "target": "mediatek/filogic",
                    "arch": "aarch64_cortex-a53"
                },
                "board": "glinet,gl-mt6000",
                "kernel": "6.12.94~0c91ecae4d3d95c948b453b592db96fe-r1",
                "payload_sha256": "abc123",
                "payload_encoding": "gzip"
            }"#,
        )
        .unwrap();

        assert_eq!(m.kind, ReportKind::KernelOops);
        assert_eq!(
            m.kernel_buildhash(),
            Some("0c91ecae4d3d95c948b453b592db96fe")
        );
    }

    #[test]
    fn buildhash_absent_for_uname() {
        let mut m: ReportMetadata = serde_json::from_str(
            r#"{
                "format": 1, "kind": "pstore", "uuid": "x",
                "captured_at": 0,
                "openwrt": {"version": "SNAPSHOT", "revision": "r1",
                            "target": "armsr/armv8", "arch": "aarch64_generic"},
                "board": "b", "kernel": "6.12.94",
                "payload_sha256": "s", "payload_encoding": "none"
            }"#,
        )
        .unwrap();

        assert_eq!(m.kernel_buildhash(), None);
        m.kernel = "6.12.94~".into();
        assert_eq!(m.kernel_buildhash(), None);
    }
}
