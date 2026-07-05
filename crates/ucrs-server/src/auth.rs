// SPDX-License-Identifier: GPL-2.0-only
//! Developer accounts (argon2 passwords + session cookies) and the
//! device-token helper shared by the /my API endpoints.

use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};

use crate::api::SharedState;

pub const SESSION_COOKIE: &str = "ucrs_session";
const SESSION_TTL_SECS: i64 = 7 * 24 * 3600;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn new_secret() -> String {
    let a = uuid::Uuid::new_v4();
    let b = uuid::Uuid::new_v4();
    hex::encode([a.as_bytes().as_slice(), b.as_bytes().as_slice()].concat())
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::encode_b64(uuid::Uuid::new_v4().as_bytes())
        .map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))?
        .to_string())
    // NOTE: salt from UUIDv4 (getrandom-backed) instead of
    // password_hash's OsRng to avoid the extra rand feature wiring
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false)
}

/// Create a developer account with a random password; used by the
/// `adduser` subcommand. Returns the generated password.
pub async fn create_user(db: &SqlitePool, login: &str) -> anyhow::Result<String> {
    let password = new_secret()[..20].to_string();
    let hash = hash_password(&password)?;

    sqlx::query("INSERT INTO dev_user (id, login, pw_hash, role) VALUES (?, ?, ?, 'dev')")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(login)
        .bind(&hash)
        .execute(db)
        .await?;

    Ok(password)
}

/// Verify a login and create a session; returns the cookie value.
pub async fn login(db: &SqlitePool, login: &str, password: &str) -> anyhow::Result<Option<String>> {
    let Some(row) = sqlx::query("SELECT id, pw_hash FROM dev_user WHERE login = ?")
        .bind(login)
        .fetch_optional(db)
        .await?
    else {
        // constant-ish time: still run a verification
        let _ = verify_password(password, "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        return Ok(None);
    };

    let hash: String = row.get("pw_hash");
    if !verify_password(password, &hash) {
        return Ok(None);
    }

    let token = new_secret();
    sqlx::query("INSERT INTO dev_session (token_hash, user_id, expires) VALUES (?, ?, ?)")
        .bind(token_hash(&token))
        .bind(row.get::<String, _>("id"))
        .bind(now() + SESSION_TTL_SECS)
        .execute(db)
        .await?;

    Ok(Some(token))
}

pub async fn logout(db: &SqlitePool, token: &str) {
    let _ = sqlx::query("DELETE FROM dev_session WHERE token_hash = ?")
        .bind(token_hash(token))
        .execute(db)
        .await;
}

/// Authenticated developer, extracted from the session cookie.
/// Rejection redirects HTML requests to /login.
pub struct Dev {
    // not read yet; kept for upcoming role checks / audit trail
    #[allow(dead_code)]
    pub user_id: String,
    pub login: String,
}

impl FromRequestParts<SharedState> for Dev {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let Some(cookie) = jar.get(SESSION_COOKIE) else {
            return Err(Redirect::to("/login").into_response());
        };

        let row = sqlx::query(
            "SELECT u.id, u.login FROM dev_session s
             JOIN dev_user u ON u.id = s.user_id
             WHERE s.token_hash = ? AND s.expires > ?",
        )
        .bind(token_hash(cookie.value()))
        .bind(now())
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;

        match row {
            Some(r) => Ok(Dev {
                user_id: r.get("id"),
                login: r.get("login"),
            }),
            None => Err(Redirect::to("/login").into_response()),
        }
    }
}

/// Resolve a device from a Bearer token (from /api/v1/device/login).
pub async fn device_from_bearer(db: &SqlitePool, headers: &HeaderMap) -> Option<String> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))?;

    sqlx::query("SELECT device_id FROM device_token WHERE token_hash = ? AND expires > ?")
        .bind(token_hash(token))
        .bind(now())
        .fetch_optional(db)
        .await
        .ok()?
        .map(|r| r.get("device_id"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let hash = hash_password("secret").unwrap();
        assert!(verify_password("secret", &hash));
        assert!(!verify_password("wrong", &hash));
        assert!(!verify_password("secret", "not-a-hash"));
    }
}
