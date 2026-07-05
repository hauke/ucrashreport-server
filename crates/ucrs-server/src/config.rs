// SPDX-License-Identifier: GPL-2.0-only
//! Server configuration. Designed for self-hosting: everything
//! instance-specific (URLs, artifact sources) lives here.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Name shown in the UI, e.g. "OpenWrt crash reports".
    #[serde(default = "default_instance_name")]
    pub instance_name: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Public base URL of this instance, used in view/publish links.
    pub base_url: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// sqlite://... (default) or postgres://...
    #[serde(default = "default_database_url")]
    pub database_url: String,
    #[serde(default)]
    pub symbols: Symbols,
}

/// Where to fetch debug symbols from — points at downloads.openwrt.org
/// by default; a variant vendor replaces these with their own mirror.
#[derive(Debug, Clone, Deserialize)]
pub struct Symbols {
    #[serde(default = "default_kernel_release_url")]
    pub kernel_release: String,
    #[serde(default = "default_kernel_snapshot_url")]
    pub kernel_snapshot: String,
    /// GC symbols unused for this many weeks (releases are pinned).
    #[serde(default = "default_retention_weeks")]
    pub retention_weeks: u32,
}

impl Default for Symbols {
    fn default() -> Self {
        Self {
            kernel_release: default_kernel_release_url(),
            kernel_snapshot: default_kernel_snapshot_url(),
            retention_weeks: default_retention_weeks(),
        }
    }
}

fn default_instance_name() -> String {
    "ucrashreport".into()
}

fn default_listen() -> String {
    "127.0.0.1:8087".into()
}

fn default_data_dir() -> PathBuf {
    "data".into()
}

fn default_database_url() -> String {
    "sqlite://data/ucrashreport.db".into()
}

fn default_kernel_release_url() -> String {
    "https://downloads.openwrt.org/releases/{version}/targets/{target}/kernel-debug.tar.zst".into()
}

fn default_kernel_snapshot_url() -> String {
    "https://downloads.openwrt.org/snapshots/targets/{target}/kernel-debug.tar.zst".into()
}

fn default_retention_weeks() -> u32 {
    4
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw).context("parsing config")?;

        Ok(cfg)
    }

    pub fn raw_dir(&self) -> PathBuf {
        self.data_dir.join("raw")
    }

    pub fn decoded_dir(&self) -> PathBuf {
        self.data_dir.join("decoded")
    }

    pub fn symbols_dir(&self) -> PathBuf {
        self.data_dir.join("symbols")
    }
}
