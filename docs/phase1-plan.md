# ucrashreport — Phase 1 task breakdown

Goal of phase 1: **kernel crash reporting end-to-end**. A device captures kernel
oopses (live via kmsg, post-panic via pstore), uploads them signed to the
server, the server symbolizes them in a sandbox, groups them by signature, and
shows developers a dashboard of top crashers. Traces are private by default
with a publish-link. Kernel symbols come from the already-published
`kernel-debug.tar.zst`, so no openwrt.git build changes are required for this
phase.

Two new repos: `ucrashreport` (device, ucode) and `ucrashreport-server` (Rust).

---

## M0 — Shared: wire protocol and formats (do this first)

Small spec document, lives in the server repo under `docs/protocol.md`.
Everything else depends on it.

### T0.1 Report metadata format (S)

JSON, versioned with `"format": 1`:

```json
{
  "format": 1,
  "kind": "kernel_oops",            // kernel_oops | pstore   (later: coredump)
  "uuid": "f81d4fae-...",           // random per report, generated on device
  "captured_at": 1751712000,        // device clock, may be wrong — server records received_at too
  "openwrt": {
    "version": "25.12.5",           // VERSION from /etc/os-release ("SNAPSHOT" allowed)
    "revision": "r33051-f5dae5ece4",
    "target": "mediatek/filogic",   // OPENWRT_BOARD
    "arch": "aarch64_cortex-a53"    // OPENWRT_ARCH
  },
  "board": "glinet,gl-mt6000",      // /tmp/sysinfo/board_name
  "kernel": "6.12.94~0c91ecae4d3d95c948b453b592db96fe-r1",
                                    // apk version of the kernel package, NOT uname -r:
                                    // the ~hash identifies the exact kernel build
  "payload_sha256": "..."
}
```

Payload = raw oops/pstore text, zstd- or gzip-compressed. Hard caps: payload
256 KiB compressed, metadata 4 KiB.

### T0.2 Upload + device auth protocol (M)

- `POST /api/v1/reports` — multipart: `metadata` (JSON) + `payload` (blob).
  - Signed mode: headers `X-UCR-Pubkey` (usign public key, base64) and
    `X-UCR-Signature` (ed25519 signature over the payload_sha256 + metadata
    hash). First-seen pubkeys are registered (TOFU).
  - Anonymous mode: no key headers; report has no owner, cannot be viewed later.
  - Response: `{"report_id": "...", "view_url": "..."}`.
- Device login (to browse own reports):
  - `POST /api/v1/device/challenge {"pubkey": ...}` → `{"nonce": ...}` (expires 60 s)
  - `POST /api/v1/device/login {"pubkey", "signature(nonce)"}` → `{"token", "expires"}`
  - Device prints `https://<server>/my#token=<token>`.
- Decide/verify: usign signature blob format so the server can verify with a
  plain ed25519 library (usign is ed25519 with a small custom envelope —
  reimplement the envelope parsing in Rust, ~100 lines; test vectors generated
  with usign in CI).

### T0.3 Signature (grouping) algorithm spec (S)

Deterministic function from a *decoded* trace to a group signature:
`kind | exception type | top ≤5 frames as symbol names` — after dropping
unwinder/panic helper frames (`dump_stack`, `show_stack`, `die`,
`panic`, `__warn`, ...) and normalizing symbols (strip `+0x.../0x...` offsets,
`.constprop.*`, `.isra.*`, `.cold` suffixes, module annotations `[act_mirred]`
kept as separate field). SHA256, hex. Spec includes a test corpus of real oops
texts (start with the one from openwrt#24029) with expected signatures.

---

## M1 — Device: `ucrashreport` repo

Flat source repo like procd/netifd — the OpenWrt package Makefile lives in
openwrt.git (`package/utils/ucrashreport`) and pulls this repo via
PKG_SOURCE_URL:

```
ucrashreportd.uc                daemon entry point
kmsg.uc  spool.uc  pstore.uc    modules at repo root
upload.uc  keys.uc  meta.uc
ucrashreport.uc                 CLI
initd/ucrashreport              procd init script
config/ucrashreport             uci defaults (enabled=0)
tests/                          ucode unit tests (run on host ucode)
Makefile                        install rules (DESTDIR-style)
README.md
```

Only runtime deps: ucode (+fs/uloop/ubus modules), uclient-fetch, usign,
zlib/zstd binary for compression. No C code needed in phase 1.

### T1.1 Repo skeleton + service + uci schema (S)

uci `ucrashreport.settings`: `enabled` (0), `oops` (1), `pstore` (1),
`server` (URL), `review` (0, parsed but unused in phase 1 — state machine
supports it), `max_reports_per_day` (5), `anonymous` (0),
`keep_files` (0, debugging only — see T1.2/T1.4).
procd service, respawn, jail-friendly. `reload_config` support.
Companion task in openwrt.git: `package/utils/ucrashreport/Makefile`
(procd/netifd-style source-repo package).

### T1.2 Spool state machine (M)

`/tmp/ucrashreport/spool/<uuid>/` containing `meta.json`, `payload.bin`,
`state`. States: `captured → pending-review → queued → uploading → uploaded`
(+ `failed`). Phase 1 auto-transitions `captured → queued` unless
`review=1` (state machine complete now; only the approval UI is later).
Size cap on the spool dir, oldest-dropped. Survives daemon restart; note that
/tmp does not survive reboot — acceptable, panics go through pstore.
Dedup: rolling file of recent payload hashes; per-day rate limit.
`keep_files=1` (debugging only): uploaded/discarded spool entries are kept
on disk instead of being removed, so the exact submitted payload can be
inspected. Never enable in normal operation — the spool cap still applies.

### T1.3 kmsg watcher (M)

uloop fd handler on `/dev/kmsg` (non-blocking, seek to end at start).
Maintain small ring of recent lines for context. Trigger patterns:
`Oops`, `BUG:`, `kernel BUG at`, `Internal error:`, `Unhandled fault`,
`WARNING:`, `Call trace:`/`Call Trace:`. Capture until `---[ end trace`
marker or 2 s of kmsg silence. Prepend ~20 context lines. One capture at a
time; overlapping traces folded into one report. WARNINGs behind separate
uci flag (`warnings=0` default — they can be noisy).

### T1.4 pstore collector (M)

On daemon start: if `/sys/fs/pstore` empty, try mounting pstore. Read
`dmesg-*` records (all parts, sort by part number, newest crash first —
handle `.enc.z` zlib-compressed records), also `console-*` if present.
Spool as `kind=pstore`, then **delete** records to free the slots
(`keep_files=1` skips the deletion for debugging; hash dedup then prevents
re-reporting the same records on every boot). Guard against re-reporting
the same crash (hash dedup as in T1.2).

### T1.5 Metadata collector (S)

Parse `/etc/os-release` (VERSION, OPENWRT_RELEASE, OPENWRT_BOARD,
OPENWRT_ARCH, BUILD_ID/revision) and `/tmp/sysinfo/board_name`.
Kernel version from the package manager, not `uname -r`:
`apk list --installed kernel` → `kernel-6.12.94~0c91ecae4d…-r1 aarch64_generic`;
store the full version string incl. the `~hash` (identifies the exact kernel
build) and revision. Fall back to `uname -r` only if the apk query fails
(self-built images without package metadata). Unit-testable pure function:
inputs → metadata JSON.

### T1.6 Device keys (S)

`keys.uc`: on first enable generate usign keypair into
`/etc/ucrashreport/` (persists across reboot/sysupgrade via sysupgrade.conf
entry). `ucrashreport rotate-key` regenerates. `anonymous=1` skips signing.

### T1.7 Uploader (M)

Triggered by: spool non-empty at start, new capture, ubus
`network.interface` up events, retry timer (exponential backoff 1 min → 6 h).
Uses uclient-fetch with system CA bundle; multipart POST per T0.2; on 2xx
mark uploaded and store returned `report_id`/`view_url` in the spool entry
(kept for `ucrashreport list`); on 4xx mark failed (no retry), on 5xx/network
retry.

### T1.8 CLI + ubus (S)

ubus object `ucrashreport`: `status`, `list`, `show {uuid}`, `approve {uuid}`,
`discard {uuid}`, `upload_now`, `login_url`. CLI wraps ubus. `login_url` runs
the challenge-response flow (T0.2) and prints the browser URL.

### T1.9 Device test plan (S)

Doc + scripts: qemu armsr/armv8 image; trigger live oops safely with
`lkdtm` (`echo EXCEPTION > /sys/kernel/debug/provoke-crash/DIRECT`, needs
CONFIG_LKDTM=m in a test build) and panic+pstore with
`echo c > /proc/sysrq-trigger` on a ramoops-enabled target. Verify spool,
upload against a local server instance.

---

## M2 — Server: `ucrashreport-server` repo

Rust workspace:

```
crates/ucrs-server/     axum: ingest API + web UI + auth (one binary)
crates/ucrs-decoder/    worker binary: job loop, container orchestration
crates/ucrs-common/     types, signature algorithm, usign verify, config
crates/ucrs-symbols/    symbol pool: feeder, GC, debuginfod endpoints
migrations/             sqlx migrations (sqlite + postgres compatible)
containers/decoder/     Containerfile: gdb-multiarch, elfutils, kernel
                        decode_stacktrace.sh, zstd
deploy/docker-compose.yml
docs/protocol.md  docs/self-hosting.md
```

### T2.1 Skeleton, config, storage (M)

Config file (TOML): instance name, base URL, data dir, DB URL
(`sqlite://...` default, `postgres://...` supported), artifact source
templates:

```toml
[symbols.kernel]
release = "https://downloads.openwrt.org/releases/{version}/targets/{target}/kernel-debug.tar.zst"
snapshot = "https://downloads.openwrt.org/snapshots/targets/{target}/kernel-debug.tar.zst"
retention_weeks = 4        # non-release; releases pinned until EOL
```

sqlx setup with the portability rules (integer epoch timestamps, text UUIDs,
no backend-specific SQL); CI runs tests against sqlite *and* postgres.
Blob spool on filesystem: `data/raw/<report_id>`, `data/decoded/<report_id>`.

Schema (initial migration):

```
device(id, pubkey UNIQUE, first_seen, last_seen)
report(id, device_id NULL, kind, received_at, captured_at,
       version, revision, target, arch, board_name,
       kernel,           -- apk version string incl. ~buildhash

       state,            -- received|decoding|decoded|failed
       visibility,       -- private|public
       group_id NULL, publish_slug NULL, raw_deleted_at NULL)
crash_group(id, signature UNIQUE, kind, title, module NULL,
            first_seen, last_seen, first_seen_version, issue_url NULL, state)
dev_user(id, login UNIQUE, pw_hash, role)   -- local accounts first
device_token(token_hash, device_id, expires)
decode_job(id, report_id, state, attempts, last_error)
```

### T2.2 Ingest endpoint (M)

`POST /api/v1/reports` per T0.2: size caps, JSON schema validation, usign
ed25519 verification, TOFU device upsert, per-IP + per-pubkey rate limits
(in-DB counters, fine for sqlite), blob to `data/raw/`, report + decode_job
rows. **Client IP is used for rate limiting only and never stored on the
report.** Return report_id + view_url.

### T2.3 usign verification in Rust (S)

Parse usign pubkey/signature envelope, verify with ed25519-dalek. Test
vectors generated by real usign in CI (usign is trivial to build).

### T2.4 Kernel symbol pool + feeder (M)

`ucrs-symbols`: on-demand fetch of `kernel-debug.tar.zst` for
(version, target) with download lock, verify against sha256sums file, and
cross-check the report's kernel `~buildhash` (from the apk version string)
against the fetched kernel so a mismatched tarball is rejected instead of
producing silently wrong symbolization (snapshot devices lag the snapshot
feed). Extract vmlinux + modules into `data/symbols/<version>/<target>/`, record
`last_seen`/`last_used`. GC task: delete non-release entries unused for
`retention_weeks`; releases pinned. (This pool object model is the same one
per-package symbols will use in phase 2 — keyed lookup + last_seen + GC —
so build it generic: entries keyed by either (version,target) or build-id.)

### T2.5 Decoder worker + sandbox (L)

Job loop polling `decode_job`. Per job:

1. Ensure symbols present (T2.4).
2. Run podman container (`--network none`, `--memory 512m`, `--pids-limit`,
   timeout 120 s, read-only mounts: raw payload + symbol dir; tmpfs work dir).
3. Inside: decompress payload, run symbolization —
   `decode_stacktrace.sh vmlinux < oops.txt` (ships in the kernel scripts;
   vendored into the container image) producing the symbolized text; a small
   extractor produces structured JSON: exception type, PC symbol, frame list,
   involved modules, taint flags.
4. Outside: store decoded text + structured JSON, compute group signature
   (T0.3, implemented in ucrs-common with the shared test corpus), upsert
   crash_group, link report, **delete raw blob**, mark decoded.
5. Failures: retry ×3, then state failed with error; raw blob kept
   `failed_retention_days` (default 14) to allow re-decode after a fix, then
   GC'd.

Scrubbing pass on decoded text before storing: MAC addresses (keep OUI,
mask NIC part), IPv4/IPv6 literals outside well-known ranges.

### T2.6 Auth + report visibility (M)

- Developer accounts: local username/password + role (admin/dev), session
  cookies. (OAuth/GitHub later.)
- Device tokens: challenge-response endpoints per T0.2, short-lived tokens,
  `GET /my` lists the device's reports.
- Report page access: owner token, dev session, or `visibility=public` via
  `GET /r/<publish_slug>`. Publish/unpublish button for owner and devs;
  publishing generates the random slug.

### T2.7 Dashboard UI (L)

Server-rendered (askama templates + htmx or vanilla JS, no SPA):

1. **Top crashers**: window selector (24 h/7 d/30 d), filters
   (version, target, kind, release-vs-snapshot), columns: title, count,
   distinct-device count (by pubkey), trend vs previous window, versions,
   first-seen version.
2. **Group detail**: signature, count-over-time chart, breakdown tables
   (version / target / board), sample decoded traces (latest 5), issue-URL
   field, state (new/known/fixed-in).
3. **Report view**: metadata header + decoded trace, publish control.
4. **Device "my reports"** view.
5. JSON API mirroring 1–2 (`/api/v1/groups`, `/api/v1/groups/<id>`).

### T2.8 debuginfod endpoints (S)

Serve `GET /buildid/<id>/debuginfo` (+ `/executable`) from the symbol pool
for kernel vmlinux/modules (they carry build-ids). Sufficient for
`DEBUGINFOD_URLS` consumers in phase 1; grows to packages in phase 2.
Alternative fallback: stock elfutils debuginfod container over the pool dir —
decide after T2.4 by whichever is less code.

### T2.9 Deployment + docs (M)

docker-compose: server, decoder, (debuginfod), volumes, healthchecks.
`docs/self-hosting.md`: config walkthrough for a variant vendor (own
downloads URL templates, own branding string). Retention/ops doc: what is
stored, what is deleted when — this doubles as the privacy statement draft
for the later RFC/announcement.

---

## M3 — Integration milestone ("something works" → publishable)

- E2E script: local docker-compose up → qemu armsr device with ucrashreport →
  lkdtm oops → report uploaded → decoded → appears in dashboard → publish
  link opens without login.
- Same for pstore path (sysrq-c panic on ramoops target, reboot, collect).
- Feed the openwrt#24029 oops text through ingest manually (curl) as a
  fixture — good demo that real field data decodes.
- README in both repos with the architecture picture and privacy model.

## Suggested order / parallelization

```
T0.1–T0.3 (spec)                                   ~ first
  ├─ client: T1.1 → T1.2 → T1.3/T1.4/T1.5 → T1.6 → T1.7 → T1.8/T1.9
  └─ server: T2.1 → T2.2/T2.3 → T2.4 → T2.5 → T2.6 → T2.7 → T2.8/T2.9
integration: M3 once T1.7 and T2.5 exist (dashboard can be rough)
```

Critical path: T2.5 (decoder sandbox) and T1.3 (kmsg watcher) — start those
early. T2.7 dashboard polish can trail everything.

## Deliberately out of phase 1 (tracked, not forgotten)

- Userspace cores, per-package debug artifacts, `COLLECT_PACKAGE_DEBUG`
  (openwrt.git + buildbot changes), core_pattern C helper.
- udebug snapshot attachments.
- Review-before-upload UI (state machine already in, T1.2).
- LuCI app, GitHub OAuth, notifications, regression view.
- openwrt-devel RFC — user will publish once something works.
