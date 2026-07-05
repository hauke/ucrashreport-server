// SPDX-License-Identifier: GPL-2.0-only
//! Kernel symbol pool and symbolizer.
//!
//! Pool: fetches kernel-debug.tar.zst for a (version, target) from the
//! configured artifact source, verifies it against the published
//! sha256sums, and extracts it to
//! data/symbols/kernel/<version>/<target>/debug/{vmlinux,modules/}.
//! The tarball members are `--only-keep-debug` processed, i.e. .symtab
//! and DWARF are present. A last_used stamp prepares for retention GC.
//!
//! Symbolizer: kernel traces already carry kallsyms symbol names; what
//! we add is source file:line resolution — symbol name -> address via
//! .symtab (object crate), address -> file:line via DWARF (addr2line).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use object::{Object, ObjectSymbol};
use sha2::{Digest, Sha256};
use ucrs_common::config::Config;

const MAX_TARBALL_SIZE: u64 = 2 * 1024 * 1024 * 1024;

pub struct SymbolPool {
    dir: PathBuf,
    release_url: String,
    snapshot_url: String,
}

impl SymbolPool {
    pub fn new(cfg: &Config) -> Self {
        Self {
            dir: cfg.symbols_dir(),
            release_url: cfg.symbols.kernel_release.clone(),
            snapshot_url: cfg.symbols.kernel_snapshot.clone(),
        }
    }

    /// Directory containing debug/vmlinux + debug/modules for this
    /// (version, target), fetching it on first use.
    pub async fn ensure_kernel(&self, version: &str, target: &str) -> anyhow::Result<PathBuf> {
        if version.contains("..") || target.contains("..") {
            bail!("invalid version/target");
        }

        let dest = self.dir.join("kernel").join(version).join(target);
        let stamp = dest.join("last_used");

        if dest.join("debug/vmlinux").exists() {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let _ = std::fs::write(&stamp, now.as_secs().to_string());
            return Ok(dest);
        }

        let template = if version == "SNAPSHOT" {
            &self.snapshot_url
        } else {
            &self.release_url
        };
        let url = template
            .replace("{version}", version)
            .replace("{target}", target);

        tracing::info!("fetching kernel symbols from {url}");

        let tarball = download(&url).await?;

        match fetch_expected_sha256(&url).await {
            Ok(expected) => {
                let got = hex::encode(Sha256::digest(&tarball));
                if got != expected {
                    bail!("kernel-debug.tar.zst checksum mismatch (got {got}, expected {expected})");
                }
            }
            Err(e) => {
                // self-hosted mirrors may not publish sha256sums;
                // transport security still comes from https
                tracing::warn!("no sha256sums verification for {url}: {e:#}");
            }
        }

        extract_tarball(&tarball, &dest)?;

        if !dest.join("debug/vmlinux").exists() {
            bail!("tarball did not contain debug/vmlinux");
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let _ = std::fs::write(&stamp, now.as_secs().to_string());

        Ok(dest)
    }
}

async fn download(url: &str) -> anyhow::Result<Vec<u8>> {
    let resp = reqwest::get(url).await?.error_for_status()?;

    if resp.content_length().unwrap_or(0) > MAX_TARBALL_SIZE {
        bail!("tarball too large");
    }

    let mut data = Vec::new();
    let mut resp = resp;
    while let Some(chunk) = resp.chunk().await? {
        data.extend_from_slice(&chunk);
        if data.len() as u64 > MAX_TARBALL_SIZE {
            bail!("tarball too large");
        }
    }

    Ok(data)
}

/// Fetch the sha256sums file next to the artifact and extract the entry
/// for its file name.
async fn fetch_expected_sha256(url: &str) -> anyhow::Result<String> {
    let (base, file) = url.rsplit_once('/').context("invalid url")?;
    let sums = reqwest::get(format!("{base}/sha256sums"))
        .await?
        .error_for_status()?
        .text()
        .await?;

    for line in sums.lines() {
        // "<sha256> *<filename>"
        if let Some((sha, name)) = line.split_once(' ') {
            if name.trim_start_matches('*') == file {
                return Ok(sha.trim().to_lowercase());
            }
        }
    }

    bail!("no sha256sums entry for {file}");
}

fn extract_tarball(data: &[u8], dest: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest)?;

    let zst = zstd::stream::read::Decoder::new(data)?;
    let mut archive = tar::Archive::new(zst);

    // tar-rs refuses path traversal in unpack(); additionally only
    // accept the expected debug/ prefix
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if !path.starts_with("debug") {
            continue;
        }
        entry.unpack_in(dest)?;
    }

    Ok(())
}

struct Binary {
    /// defined symbol name -> address (section-relative for .ko)
    syms: HashMap<String, u64>,
    loader: addr2line::Loader,
}

impl Binary {
    fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        let obj = object::File::parse(&*data)?;

        let mut syms = HashMap::new();
        for sym in obj.symbols() {
            if !sym.is_definition() {
                continue;
            }
            if let Ok(name) = sym.name() {
                syms.insert(name.to_string(), sym.address());
            }
        }

        let loader = addr2line::Loader::new(path)
            .map_err(|e| anyhow::anyhow!("loading {}: {e}", path.display()))?;

        Ok(Binary { syms, loader })
    }

    fn find_location(&self, symbol: &str, offset: u64) -> Option<String> {
        let addr = self.syms.get(symbol)?.checked_add(offset)?;
        let loc = self.loader.find_location(addr).ok()??;

        let file = loc.file?;
        // strip the build-host prefix; OpenWrt builds under .../build_dir/
        let file = file
            .rsplit_once("/linux-")
            .and_then(|(_, rest)| rest.split_once('/').map(|(_, p)| p))
            .unwrap_or(file);

        match loc.line {
            Some(line) => Some(format!("{file}:{line}")),
            None => Some(file.to_string()),
        }
    }
}

/// Per-job symbol resolver: vmlinux plus lazily loaded modules. Not
/// kept across jobs — reports for different builds need different
/// symbols and memory is bounded per job this way.
pub struct Symbolizer {
    vmlinux: Option<Binary>,
    modules_dir: PathBuf,
    modules: HashMap<String, Option<Binary>>,
}

impl Symbolizer {
    pub fn new(symbol_dir: Option<&Path>) -> Self {
        let (vmlinux, modules_dir) = match symbol_dir {
            Some(dir) => (
                Binary::load(&dir.join("debug/vmlinux"))
                    .map_err(|e| tracing::warn!("vmlinux unusable: {e:#}"))
                    .ok(),
                dir.join("debug/modules"),
            ),
            None => (None, PathBuf::new()),
        };

        Symbolizer {
            vmlinux,
            modules_dir,
            modules: HashMap::new(),
        }
    }

    pub fn have_symbols(&self) -> bool {
        self.vmlinux.is_some()
    }

    fn module(&mut self, name: &str) -> Option<&Binary> {
        if !self.modules.contains_key(name) {
            let path = self.modules_dir.join(format!("{name}.ko"));
            let bin = path.exists().then(|| Binary::load(&path).ok()).flatten();
            self.modules.insert(name.to_string(), bin);
        }
        self.modules.get(name).and_then(|b| b.as_ref())
    }

    /// Resolve "symbol+0xoff" (optionally scoped to a module) to
    /// "file:line".
    pub fn resolve(&mut self, symbol: &str, offset: u64, module: Option<&str>) -> Option<String> {
        match module {
            Some(m) => self.module(m)?.find_location(symbol, offset),
            None => self.vmlinux.as_ref()?.find_location(symbol, offset),
        }
    }
}

/// Annotate trace lines containing "symbol+0xoff/0xsize [module]" with
/// resolved source locations.
pub fn annotate(text: &str, sym: &mut Symbolizer) -> String {
    let re = regex::Regex::new(
        r"([A-Za-z0-9_.]+)\+(0x[0-9a-fA-F]+)/0x[0-9a-fA-F]+(?:\s+\[([A-Za-z0-9_-]+)\])?",
    )
    .unwrap();

    let mut out = String::with_capacity(text.len());

    for line in text.lines() {
        out.push_str(line);

        if let Some(c) = re.captures(line) {
            let symbol = &c[1];
            let offset = u64::from_str_radix(c[2].trim_start_matches("0x"), 16).unwrap_or(0);
            let module = c.get(3).map(|m| m.as_str());

            if let Some(loc) = sym.resolve(symbol, offset, module) {
                out.push_str(&format!(" ({loc})"));
            }
        }

        out.push('\n');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annotate_without_symbols_is_identity() {
        let mut sym = Symbolizer::new(None);
        let text = "[ 1.0] Call trace:\n[ 1.1]  foo+0x10/0x20 [bar]\n";

        assert_eq!(annotate(text, &mut sym), text);
        assert!(!sym.have_symbols());
    }

    // Exercise the object + addr2line integration against a real ELF
    // with .symtab and DWARF: this test binary itself.
    #[test]
    fn resolve_against_own_binary() {
        let exe = std::env::current_exe().unwrap();

        let data = std::fs::read(&exe).unwrap();
        let obj = object::File::parse(&*data).unwrap();
        use object::Object;
        if obj.section_by_name(".debug_info").is_none() {
            // release profile without debug info — nothing to test
            return;
        }

        let bin = Binary::load(&exe).unwrap();
        assert!(!bin.syms.is_empty(), "no symbols in test binary");

        let resolved = bin
            .syms
            .keys()
            .filter(|s| s.contains("resolve_against_own_binary"))
            .chain(bin.syms.keys())
            .find_map(|s| bin.find_location(s, 0).map(|loc| (s.clone(), loc)));

        let (sym, loc) = resolved.expect("no symbol resolved to a source location");
        assert!(loc.contains(':'), "location {loc} for {sym} has no line");
    }
}
