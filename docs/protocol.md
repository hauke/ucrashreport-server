# ucrashreport wire protocol — version 1

This document specifies the protocol between the `ucrashreport` device agent
and `ucrashreport-server`. It is the contract both repositories implement;
changes require bumping the `format` field.

## 1. Report metadata

Every report consists of a **metadata** JSON document and a **payload** blob.

```json
{
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
  "payload_sha256": "hex...",
  "payload_encoding": "gzip"
}
```

Field rules:

- `format` (int, required): protocol version, this document describes `1`.
- `kind` (string, required): `kernel_oops` | `pstore`. Future: `coredump`.
- `uuid` (string, required): RFC 4122 random UUID generated on the device,
  one per report. The device keeps it to correlate with the server copy.
- `captured_at` (int, required): Unix epoch from the device clock. Device
  clocks are unreliable (routers boot at epoch 0 until NTP); the server
  stores `received_at` itself and treats `captured_at` as advisory.
- `openwrt.version` (string, required): `VERSION` from `/etc/os-release`;
  `SNAPSHOT` is a valid value.
- `openwrt.revision` (string, required): e.g. `r33051-f5dae5ece4`.
- `openwrt.target` (string, required): `OPENWRT_BOARD`, `target/subtarget`.
- `openwrt.arch` (string, required): `OPENWRT_ARCH`.
- `board` (string, required): `/tmp/sysinfo/board_name`. No device model
  string beyond this, no hostname, no serial numbers.
- `kernel` (string, required): version of the installed `kernel` package as
  reported by the package manager (e.g. `apk list --installed kernel`),
  **including** the `~<buildhash>` and `-r<n>` parts — the buildhash
  identifies the exact kernel build and is used server-side to validate the
  fetched debug symbols. Devices without package metadata (self-built
  images) fall back to `uname -r`; the server detects the missing `~` and
  skips the buildhash cross-check.
- `payload_sha256` (string, required): lowercase hex SHA-256 of the
  payload blob **as transmitted** (i.e. of the compressed bytes).
- `payload_encoding` (string, required): `gzip` | `zstd` | `none`.

Size limits (server MUST enforce, device SHOULD enforce before upload):

- metadata: 4 KiB
- payload: 256 KiB as transmitted

## 2. Device identity

A device MAY have an ed25519 keypair, generated with OpenWrt's `usign`.
The public key is the device's pseudonymous identity:

- Reports signed with a key belong to that key; the key owner can later
  list and view them and control their visibility.
- Anonymous submissions (no key) are accepted but cannot be viewed later.
- Key rotation is a normal, supported operation. The server treats a new
  key as a new device; no linkage is attempted.

### usign formats

usign is OpenBSD signify with OpenWrt framing. On the wire we use the raw
base64 blobs (the second line of the `.pub` / `.sig` files, without the
`untrusted comment:` line):

- public key blob (42 bytes): `pkalg[2]="Ed"` + `keynum[8]` + `pubkey[32]`
- signature blob (74 bytes): `pkalg[2]="Ed"` + `keynum[8]` + `sig[64]`

The signature is a plain Ed25519 signature over the message bytes
(signify semantics). Verifiers MUST check `pkalg == "Ed"` and that the
`keynum` in the signature matches the public key's `keynum`.

## 3. Report upload

```
POST /api/v1/reports
Content-Type: multipart/form-data; boundary=...
```

Multipart fields, in order:

1. `metadata` — the JSON document from section 1,
   `Content-Type: application/json`.
2. `payload` — the blob, `Content-Type: application/octet-stream`.

Signed mode — two additional HTTP headers:

- `X-UCR-Pubkey`: base64 public key blob (section 2)
- `X-UCR-Signature`: base64 signature blob over the **entire multipart
  request body** (exactly the bytes on the wire)

Signing the whole body keeps the device side trivial: build body file,
`usign -S -m <bodyfile>`, send. The device MUST build the body
deterministically (fixed boundary string per request is fine).

Server behaviour:

- Unknown `X-UCR-Pubkey` values are registered on first use (trust on
  first use). There is no separate registration call.
- Invalid signature → `401`.
- Schema violation / size cap exceeded / `payload_sha256` mismatch → `400`
  with a JSON `{"error": "..."}` body. The device MUST NOT retry 4xx.
- Rate limited → `429` with `Retry-After`. Device backs off.
- Success → `201`:

```json
{
  "report_id": "f81d4fae-7dec-4b58-a94b-2c0dd4f1fc6f",
  "view_url": "https://crash.example.org/reports/f81d4fae-..."
}
```

`report_id` echoes the device-supplied `uuid` unless it collides with an
existing report, in which case the server assigns a fresh one (the response
is authoritative). `view_url` is only useful for signed submissions.

The server MUST use the client IP only for rate limiting and MUST NOT
persist it with the report.

Duplicate handling: a signed re-upload of the same `uuid` by the same key
is idempotent (`201` with the existing ids, no new report row).

## 4. Device login (challenge–response)

Lets the device owner open their report list in a browser without any
account.

```
POST /api/v1/device/challenge
{"pubkey": "<base64 pubkey blob>"}
  → 200 {"nonce": "<base64 32 random bytes>", "expires_in": 60}

POST /api/v1/device/login
{"pubkey": "<base64 pubkey blob>", "signature": "<base64 sig blob over the raw nonce bytes>"}
  → 200 {"token": "<opaque>", "expires_in": 3600}
```

- Nonces are single-use and expire after 60 s.
- The token grants read access to that key's reports plus
  publish/unpublish/delete on them. It is passed as
  `Authorization: Bearer <token>` (API) or in the URL fragment for the
  browser flow: `https://<server>/my#token=...`.
- Unknown pubkey at `challenge` time → 404 (device has never uploaded).

## 5. Report visibility

- Every report starts `private`: visible to the submitting key (via device
  token) and to registered developer accounts on the server instance.
- The owner or a developer can **publish** a report: the server assigns a
  random unguessable slug; `GET /r/<slug>` then serves the decoded trace
  and metadata without authentication. Publishing never exposes raw
  (undecoded) payloads or future attachment types (udebug captures).
- Unpublish removes the slug.

## 6. Crash signature algorithm (grouping)

Two reports belong to the same crash group iff their signatures are equal.
The signature is computed **after symbolization** from the decoded trace.

Inputs: `kind`, exception line, ordered list of call-trace frames
(symbol names, optional module), from the decoder's structured output.

Algorithm:

1. Determine the **exception type**: the normalized first matching line of
   `Oops[: ]`, `kernel BUG at`, `BUG:`, `Internal error:`,
   `Unhandled fault`, `Unable to handle kernel`, `WARNING:`. Strip
   addresses (`0x[0-9a-f]+`, bare hex ≥ 4 digits) and CPU/PID/task noise.
2. Take the call trace of the crashing context. Drop leading frames that
   belong to the unwinder/report machinery: `dump_backtrace`,
   `show_stack`, `dump_stack*`, `die`, `__die`, `oops*`, `panic`,
   `__warn`, `warn_slowpath*`, `report_bug`, `bug_handler`,
   `do_trap*`, `do_page_fault`, `do_translation_fault`, `do_mem_abort`,
   `el1_*`, `el1h_*`, `__do_kernel_fault`, exception vectors
   (`ret_from_*`, `*_exception`, `handle_exception`).
3. Normalize each remaining symbol:
   - strip `+0x<off>/0x<size>` suffixes,
   - strip compiler suffixes matching `\.(constprop|isra|part|cold|lto)\.?[0-9]*`,
   - strip a trailing `[module]` annotation (recorded separately),
   - question-mark frames (`? symbol`) are dropped.
4. Take the first **5** normalized frames (fewer if the trace is shorter).
5. `signature_input = kind + "|" + exception_type + "|" + frame1 + "|" + ... `
6. `signature = lowercase hex SHA-256 of signature_input` (UTF-8).

The group **title** is `frame1` (or the exception type if no frames
survive); the involved modules (union of `[module]` annotations) are
stored as searchable group metadata.

The reference implementation and its test corpus live in
`crates/ucrs-common`; the corpus contains real oops texts and expected
signatures and is the normative tie-breaker for ambiguities in this text.

## 7. Compatibility

- Devices send `format: 1`; a server that does not support the received
  format responds `400` with `{"error": "unsupported format"}`.
- Servers MUST ignore unknown metadata fields (forward compatibility
  within a format version).
- New `kind` values require a format bump only if they change the payload
  contract; the server rejects unknown kinds with `400`.
