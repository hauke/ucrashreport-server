-- SPDX-License-Identifier: GPL-2.0-only
-- Initial schema. Portability rules: TEXT UUIDs as primary keys,
-- INTEGER unix-epoch timestamps, no backend-specific types — must work
-- on both SQLite and PostgreSQL.

CREATE TABLE device (
    id TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL UNIQUE,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);

CREATE TABLE crash_group (
    id TEXT PRIMARY KEY,
    signature TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    -- space-separated involved kernel modules
    modules TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    first_seen_version TEXT,
    issue_url TEXT,
    -- new | known | fixed
    state TEXT NOT NULL DEFAULT 'new'
);

CREATE TABLE report (
    id TEXT PRIMARY KEY,
    device_id TEXT REFERENCES device(id),
    -- kernel_oops | pstore
    kind TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    captured_at INTEGER NOT NULL,
    version TEXT NOT NULL,
    revision TEXT NOT NULL,
    target TEXT NOT NULL,
    arch TEXT NOT NULL,
    board_name TEXT NOT NULL,
    -- apk version string incl. ~buildhash (or uname -r fallback)
    kernel TEXT NOT NULL,
    -- received | decoding | decoded | failed
    state TEXT NOT NULL DEFAULT 'received',
    -- private | public
    visibility TEXT NOT NULL DEFAULT 'private',
    group_id TEXT REFERENCES crash_group(id),
    publish_slug TEXT UNIQUE,
    raw_deleted_at INTEGER
);

CREATE INDEX report_received_idx ON report(received_at);
CREATE INDEX report_group_idx ON report(group_id);
CREATE INDEX report_device_idx ON report(device_id);

CREATE TABLE dev_user (
    id TEXT PRIMARY KEY,
    login TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    -- admin | dev
    role TEXT NOT NULL DEFAULT 'dev'
);

CREATE TABLE device_token (
    token_hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES device(id),
    expires INTEGER NOT NULL
);

CREATE TABLE decode_job (
    id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES report(id),
    -- pending | running | done | failed
    state TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);

CREATE INDEX decode_job_state_idx ON decode_job(state);
