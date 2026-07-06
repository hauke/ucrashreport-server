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
    ///
    /// `expected_buildid`: the reporting kernel's build-id, if known.
    /// A cached tree whose vmlinux does not match is stale (snapshots
    /// and local builds change under the same version string) — it is
    /// dropped and fetched again once.
    pub async fn ensure_kernel(
        &self,
        version: &str,
        target: &str,
        expected_buildid: Option<&str>,
    ) -> anyhow::Result<PathBuf> {
        if version.contains("..") || target.contains("..") {
            bail!("invalid version/target");
        }

        let dest = self.dir.join("kernel").join(version).join(target);
        let stamp = dest.join("last_used");
        let vmlinux = dest.join("debug/vmlinux");

        if vmlinux.exists() {
            let stale = match (expected_buildid, file_build_id(&vmlinux)) {
                (Some(expected), Some(got)) => !got.eq_ignore_ascii_case(expected),
                _ => false,
            };

            if !stale {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let _ = std::fs::write(&stamp, now.as_secs().to_string());
                return Ok(dest);
            }

            tracing::info!(
                "cached symbols for {version}/{target} do not match reporting \
                 kernel, refetching"
            );
            let _ = std::fs::remove_dir_all(&dest);
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

        if url.starts_with("file://") {
            // local trusted disk, no transport to verify
            extract_tarball(&tarball, &dest)?;
            return self.finish_extract(&dest, &stamp);
        }

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
        self.finish_extract(&dest, &stamp)
    }

    fn finish_extract(&self, dest: &Path, stamp: &Path) -> anyhow::Result<PathBuf> {
        if !dest.join("debug/vmlinux").exists() {
            bail!("tarball did not contain debug/vmlinux");
        }

        if let Err(e) = index_build_ids(dest, &self.dir) {
            tracing::warn!("build-id indexing failed: {e:#}");
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let _ = std::fs::write(stamp, now.as_secs().to_string());

        Ok(dest.to_path_buf())
    }

    /// Remove snapshot symbol trees not used for retention_weeks and
    /// clean up dangling build-id symlinks. Release symbols are pinned
    /// (they never change and stay in the field for years).
    pub fn gc(&self, retention_weeks: u32) {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - (retention_weeks as i64) * 7 * 86400;

        let snapshot_dir = self.dir.join("kernel").join("SNAPSHOT");
        for target_dir in walk_two_levels(&snapshot_dir) {
            let last_used = std::fs::read_to_string(target_dir.join("last_used"))
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok())
                .unwrap_or(0);

            if last_used < cutoff {
                tracing::info!("GC: removing stale symbols {}", target_dir.display());
                let _ = std::fs::remove_dir_all(&target_dir);
            }
        }

        // drop build-id links whose target vanished
        let buildid_dir = self.dir.join(".build-id");
        for link in walk_two_levels(&buildid_dir) {
            if link.is_symlink() && !link.exists() {
                let _ = std::fs::remove_file(&link);
            }
        }
    }
}

/// Entries two directory levels below `root` (e.g. <target>/<subtarget>
/// under kernel/SNAPSHOT, or xx/yyyy.debug under .build-id).
fn walk_two_levels(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(level1) = std::fs::read_dir(root) else {
        return out;
    };
    for l1 in level1.flatten() {
        if let Ok(level2) = std::fs::read_dir(l1.path()) {
            out.extend(level2.flatten().map(|e| e.path()));
        }
    }
    out
}

fn file_build_id(path: &Path) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let obj = object::File::parse(&*data).ok()?;
    obj.build_id().ok()?.map(hex::encode)
}

/// Index extracted debug files by GNU build-id in debuginfod layout:
/// <pool>/.build-id/xx/yyyy....debug -> ../../kernel/<ver>/<tgt>/debug/...
fn index_build_ids(dest: &Path, pool_root: &Path) -> anyhow::Result<()> {
    let mut files = vec![dest.join("debug/vmlinux")];
    if let Ok(modules) = std::fs::read_dir(dest.join("debug/modules")) {
        files.extend(modules.flatten().map(|e| e.path()));
    }

    for file in files {
        let Some(id) = file_build_id(&file) else {
            continue;
        };
        if id.len() < 4 {
            continue;
        }

        let link_dir = pool_root.join(".build-id").join(&id[..2]);
        std::fs::create_dir_all(&link_dir)?;
        let link = link_dir.join(format!("{}.debug", &id[2..]));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(file.canonicalize()?, &link)?;
    }

    Ok(())
}


async fn download(url: &str) -> anyhow::Result<Vec<u8>> {
    // file:// support for development and self-hosted setups where the
    // artifacts live on the same machine (e.g. a buildroot bin/targets
    // directory)
    if let Some(path) = url.strip_prefix("file://") {
        let meta = tokio::fs::metadata(path)
            .await
            .with_context(|| format!("reading {path}"))?;
        if meta.len() > MAX_TARBALL_SIZE {
            bail!("tarball too large");
        }
        return tokio::fs::read(path)
            .await
            .with_context(|| format!("reading {path}"));
    }

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
    build_id: Option<String>,
    loader: addr2line::Loader,
}

impl Binary {
    fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        let obj = object::File::parse(&*data)?;

        let build_id = obj.build_id().ok().flatten().map(hex::encode);

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

        Ok(Binary {
            syms,
            build_id,
            loader,
        })
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
    /// `expected_buildid`: the reporting kernel's GNU build-id, if the
    /// device provided one. When it does not match the extracted
    /// vmlinux, the symbols belong to a different build (stale
    /// snapshot artifacts) and are discarded — wrong source locations
    /// are worse than none.
    pub fn new(symbol_dir: Option<&Path>, expected_buildid: Option<&str>) -> Self {
        let (mut vmlinux, modules_dir) = match symbol_dir {
            Some(dir) => (
                Binary::load(&dir.join("debug/vmlinux"))
                    .map_err(|e| tracing::warn!("vmlinux unusable: {e:#}"))
                    .ok(),
                dir.join("debug/modules"),
            ),
            None => (None, PathBuf::new()),
        };

        if let (Some(bin), Some(expected)) = (&vmlinux, expected_buildid) {
            match &bin.build_id {
                Some(got) if got.eq_ignore_ascii_case(expected) => {}
                got => {
                    tracing::warn!(
                        "vmlinux build-id {:?} does not match reporting kernel {expected}, \
                         skipping symbolization",
                        got
                    );
                    vmlinux = None;
                }
            }
        }

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
        let mut sym = Symbolizer::new(None, None);
        let text = "[ 1.0] Call trace:\n[ 1.1]  foo+0x10/0x20 [bar]\n";

        assert_eq!(annotate(text, &mut sym), text);
        assert!(!sym.have_symbols());
    }

    #[test]
    fn gc_removes_stale_snapshot_keeps_release() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SymbolPool {
            dir: tmp.path().to_path_buf(),
            release_url: String::new(),
            snapshot_url: String::new(),
        };

        let stale = tmp.path().join("kernel/SNAPSHOT/ath79/generic");
        let fresh = tmp.path().join("kernel/SNAPSHOT/x86/64");
        let release = tmp.path().join("kernel/25.12.5/ath79/generic");
        for d in [&stale, &fresh, &release] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(stale.join("last_used"), "0").unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::write(fresh.join("last_used"), now.to_string()).unwrap();
        std::fs::write(release.join("last_used"), "0").unwrap();

        // dangling build-id link into the stale tree
        let link_dir = tmp.path().join(".build-id/ab");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::os::unix::fs::symlink(stale.join("debug/vmlinux"), link_dir.join("cd.debug"))
            .unwrap();

        pool.gc(4);

        assert!(!stale.exists(), "stale snapshot tree not removed");
        assert!(fresh.exists(), "fresh snapshot tree removed");
        assert!(release.exists(), "pinned release tree removed");
        assert!(!link_dir.join("cd.debug").is_symlink(), "dangling link kept");
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
