# ucrashreport roadmap

Status and remaining work, as of 2026-07-06. Complements
[phase1-plan.md](phase1-plan.md) (the original task breakdown) and
[protocol.md](protocol.md) (the wire protocol).

## Where we are

Working end-to-end, verified with a real device (OpenWrt One,
mediatek/filogic) and a self-built image:

- device agent (`ucrashreport`, pure ucode): pstore/ramoops collection
  after a panic, kmsg watcher (host-validated incl. WARNING capture),
  spool with review-ready state machine, dedup, daily quota, usign
  device identity, async uploads via the ucode uclient binding with
  4xx-drop/5xx-retry semantics, persistent upload history, syslog
  logging of every attempt
- server: ingest with usign verification and TOFU device registration,
  sandbox-lite decoder (memory-safe Rust, size caps), kernel
  symbolization via .symtab + DWARF with file:line annotation,
  kernel build-id validation incl. stale-cache refetch, MAC/IP
  scrubbing, crash-signature grouping (last crash section wins,
  pstore printk prefixes handled), dashboard with top-crashers /
  group detail / report view, publish links, device /my page,
  debuginfod endpoints, retention GC, docker-compose deployment
- openwrt.git: `package/utils/ucrashreport` on the `ucrashreport`
  branch

## Remaining phase-1 work

Device:
- [ ] on-target test of the live kmsg path (`warnings='1'` +
      lkdtm WARNING; the fatal path always goes through pstore on
      filogic because the kernel panics on oops)
- [ ] on-target test of `ucrashreport login-url` and the /my page
- [ ] investigate the `pstore: backend (ramoops) writing error (-28)`
      seen on the OpenWrt One (record_size vs. dump size; check
      /sys/module/ramoops/parameters); pstore worked on later crashes
- [ ] enable ramoops on more targets where a safe RAM region exists
      (openwrt.git, per-board device tree work)

Server:
- [ ] per-IP and per-pubkey rate limiting on ingest (TODO in api.rs)
- [ ] group management UI: edit issue_url, set state
      (new/known/fixed-in-version) — fields exist in the schema
- [ ] PostgreSQL profile (schema and queries are already portable;
      needs sqlx Any/feature wiring and CI coverage)
- [ ] repeat decode with fresh symbols: reports currently keep the
      unannotated decode if symbols arrive later; consider a
      re-symbolize action for developers

Project:
- [ ] LICENSE files in both repos (SPDX headers exist, license text
      missing)
- [ ] CI: cargo test/fmt/clippy for the server; host-ucode test run
      for the client (tests/run.sh; needs a ucode build in CI)
- [ ] tag a release and set PKG_MIRROR_HASH properly in the package
- [ ] RFC to openwrt-devel: governance, who operates
      crash.openwrt.org, retention/privacy statement (draft material
      in README privacy sections and the retention rules)
- [ ] production deployment (docker-compose exists; needs a host,
      TLS, backups)

## Phase 2 — userspace crash reporting (segfaults/coredumps)

openwrt.git build system (must land at least one release before the
server can decode release binaries):
- [ ] `COLLECT_PACKAGE_DEBUG` config option (mirroring
      COLLECT_KERNEL_DEBUG, default BUILDBOT): selects CONFIG_DEBUG,
      adds `-Wl,--build-id=sha1` to TARGET_LDFLAGS
- [ ] hook RSTRIP: `objcopy --only-keep-debug` before stripping,
      collect debug files in debuginfod layout
      (.build-id/xx/yyyy.debug)
- [ ] verify sstrip keeps the build-id PT_NOTE readable; fall back to
      plain strip when the option is enabled if not
- [ ] emit a per-package companion artifact
      (<pkg>_<version>_<arch>.debug.tar.zst) next to the .apk — per
      package, not per target, because rolling-release rebuilds change
      binaries without version bumps and devices run mixed versions
- [ ] buildbot: publish the debug artifacts (openwrt/buildbot repo)

Device (`ucrashreport`):
- [ ] core_pattern pipe helper (small C: streams the core from stdin
      under kernel control): size cap, compress, capture
      /proc/<pid>/exe build-id and package owner before the process is
      reaped, write spool entry kind=coredump
- [ ] switch kernel.core_pattern when the feature is enabled; global
      procd option to raise the core rlimit for services
- [ ] privacy: coredumps can contain secrets (hostapd PSKs!) — gate
      behind a separate consent flag; review-before-upload strongly
      recommended for this kind; document plainly

Server:
- [ ] extend the symbol pool to per-package debug artifacts keyed by
      GNU build-id, content-addressed, `last_seen` refreshed on feed
      scans, GC after retention_weeks unless referenced by a release
      (the kernel pool's ensure/GC design generalizes; see
      phase1-plan.md T2.4 note)
- [ ] coredump decode in a real sandbox: podman container
      (--network none, memory/pids/time limits, ro mounts), gdb-multiarch
      against the stripped binary (fetched from the published apk) +
      .debug file by build-id; `thread apply all bt full`
- [ ] delete raw cores immediately after decode (same rule as today);
      decide retention for undecodable cores
- [ ] protocol: kind=coredump, fields for binary path/package/
      signal/build-ids (format bump per protocol.md section 7)
- [ ] debuginfod serves package debug files (endpoint exists, pool
      feed is the new part)

## Phase 3 — comfort and reach

- [ ] udebug ring-buffer snapshots attached to reports (hostapd/netifd
      flight recorder): separate opt-in, never public, needs
      review-before-upload; enriches live oops + segfaults only
      (shared memory does not survive a panic)
- [ ] review-before-upload UI (spool state machine and ubus
      approve/discard exist; needs `review='1'` default handling
      polish + LuCI surface)
- [ ] LuCI app: opt-in toggle with privacy text, report list,
      login-url button
- [ ] regression view ("first seen in version X") and notifications
      (new group on snapshot -> mailing list/Matrix)
- [ ] report-count vs device-count refinement in the dashboard
      (distinct pubkeys are already counted; decide how to present
      anonymous reports)

## Lessons learned (keep in mind when touching this code)

- ucode uloop: `timer.cancel()` frees the callback — the timer is dead
  for good, `.set()` will not revive it. Create timers once, only ever
  re-arm with `.set()`.
- ucode resolves identifiers at declaration time: referencing a
  function declared later in the file compiles into a global lookup
  that fails at runtime.
- uclient-fetch accepts only HTTP 200/204/206 (that is why the ingest
  returns 200, not 201) and `-q` silences even its error output.
- pstore dmesg records contain the whole kmsg ring: old WARNINGs
  precede the fatal crash (last section wins), lines carry
  `<level>[timestamp]` prefixes, arm64 marks the faulting frame `(P)`,
  and records may be zlib-compressed (`.enc.z`, decompressed
  server-side).
- dev trees rebuild constantly: symbol artifacts and flashed images
  diverge quickly. The kernel build-id guard plus refetch-on-mismatch
  handles it; on production infra artifacts and images come from the
  same build by construction.
- filogic (and any panic_on_oops kernel) never produces a live oops:
  the kmsg watcher only ever sees WARNINGs there; everything fatal
  arrives via pstore after reboot.
