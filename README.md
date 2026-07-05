# ucrashreport-server

Server side of OpenWrt crash reporting: receives kernel crash reports
from devices running [ucrashreport](https://github.com/openwrt/ucrashreport),
symbolizes them against the published debug artifacts, groups them by
crash signature and gives developers a dashboard of what crashes in the
field, how often, on which versions and targets.

**Status: early development.** Implemented so far: wire protocol
([docs/protocol.md](docs/protocol.md)), report ingest with usign
(ed25519) device authentication, device challenge-response login, the
crash-signature/grouping algorithm with test corpus. Not yet
implemented: decoder worker + sandbox, symbol pool/feeder, dashboard,
debuginfod endpoints, docker-compose deployment.

## Design (see the phase-1 plan for details)

- `crates/ucrs-server` — the internet-facing binary: ingest API, device
  auth, (later) dashboard. Never parses crash payload contents.
- `crates/ucrs-common` — protocol types, usign verification, the
  normative crash-signature implementation.
- decoder worker (TODO) — decodes each report in a throwaway container
  (no network, resource limits) since payloads are untrusted input;
  deletes raw payloads after successful decode.
- Storage: SQLite by default, schema/queries kept portable so large
  instances can move to PostgreSQL; blobs live on the filesystem, never
  in the database.
- Self-hosting is a first-class goal: all instance specifics (base URL,
  symbol artifact URLs) live in `config.toml` — see
  `config.example.toml`.

## Privacy model

- Reports are private by default: visible to the submitting device
  (challenge-response login with its usign key) and registered
  developers. Owners can publish a report to get a shareable link.
- Client IPs are used for rate limiting only and never stored with
  reports.
- Raw payloads are deleted after successful decoding; only the decoded,
  scrubbed trace is retained.

## Running

```
cp config.example.toml config.toml   # edit base_url etc.
cargo run -p ucrs-server -- config.toml
```

## Development

```
cargo test          # unit tests incl. signature-algorithm corpus
cargo fmt --check
```
