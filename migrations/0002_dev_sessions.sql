-- SPDX-License-Identifier: GPL-2.0-only
-- Browser sessions for developer accounts.

CREATE TABLE dev_session (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES dev_user(id),
    expires INTEGER NOT NULL
);
