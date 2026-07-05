// SPDX-License-Identifier: GPL-2.0-only
//! HTTP API: report ingest (protocol.md section 3), device
//! challenge-response login (section 4) and the device report list.
//!
//! Deliberately small attack surface: this module never parses crash
//! payload *contents* — that happens in the sandboxed decoder.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::sync::Arc;

use ucrs_common::config::Config;
use ucrs_common::types::{ReportMetadata, FORMAT_VERSION, MAX_METADATA_SIZE, MAX_PAYLOAD_SIZE};
use ucrs_common::usign;

const NONCE_TTL: Duration = Duration::from_secs(60);
const TOKEN_TTL_SECS: i64 = 3600;

pub struct AppState {
    pub cfg: Config,
    pub db: sqlx::SqlitePool,
    /// pending login nonces by pubkey blob
    pub nonces: Mutex<HashMap<String, (Vec<u8>, Instant)>>,
}

pub type SharedState = Arc<AppState>;

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("internal error: {e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        anyhow::Error::from(e).into()
    }
}

fn bad(msg: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn new_secret() -> String {
    // 32 random bytes from two v4 UUIDs
    let a = uuid::Uuid::new_v4();
    let b = uuid::Uuid::new_v4();
    hex::encode([a.as_bytes().as_slice(), b.as_bytes().as_slice()].concat())
}

pub async fn healthz() -> &'static str {
    "ok"
}

/// Verify the request signature headers (if present) and return the
/// device id, registering unknown keys (trust on first use).
async fn authenticate_device(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Option<String>, ApiError> {
    let Some(pubkey_b64) = headers.get("x-ucr-pubkey").and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let Some(sig_b64) = headers.get("x-ucr-signature").and_then(|v| v.to_str().ok()) else {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "pubkey without signature".into(),
        ));
    };

    let key = usign::PublicKey::from_base64(pubkey_b64).map_err(|_| bad("invalid pubkey"))?;

    key.verify(sig_b64, body)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "signature verification failed".into()))?;

    let ts = now();
    let id = new_id();

    // TOFU upsert; the RETURNING clause works on sqlite >= 3.35 and postgres
    let row = sqlx::query(
        "INSERT INTO device (id, pubkey, first_seen, last_seen)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(pubkey) DO UPDATE SET last_seen = excluded.last_seen
         RETURNING id",
    )
    .bind(&id)
    .bind(pubkey_b64)
    .bind(ts)
    .bind(ts)
    .fetch_one(&state.db)
    .await?;

    Ok(Some(row.get::<String, _>("id")))
}

async fn parse_multipart(
    headers: &HeaderMap,
    body: Bytes,
) -> Result<(ReportMetadata, Bytes), ApiError> {
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| bad("missing content-type"))?;
    let boundary = multer::parse_boundary(ct).map_err(|_| bad("invalid content-type"))?;

    let stream = futures_util::stream::once(async move { Ok::<_, std::io::Error>(body) });
    let mut mp = multer::Multipart::new(stream, boundary);

    let mut metadata: Option<String> = None;
    let mut payload: Option<Bytes> = None;

    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|_| bad("invalid multipart body"))?
    {
        match field.name() {
            Some("metadata") => {
                let text = field.text().await.map_err(|_| bad("invalid metadata"))?;
                if text.len() > MAX_METADATA_SIZE {
                    return Err(bad("metadata too large"));
                }
                metadata = Some(text);
            }
            Some("payload") => {
                let data = field.bytes().await.map_err(|_| bad("invalid payload"))?;
                if data.len() > MAX_PAYLOAD_SIZE {
                    return Err(bad("payload too large"));
                }
                payload = Some(data);
            }
            _ => {}
        }
    }

    let metadata = metadata.ok_or_else(|| bad("missing metadata field"))?;
    let payload = payload.ok_or_else(|| bad("missing payload field"))?;

    let meta: ReportMetadata =
        serde_json::from_str(&metadata).map_err(|e| bad(&format!("invalid metadata: {e}")))?;

    Ok((meta, payload))
}

pub async fn post_report(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    // TODO: per-IP and per-pubkey rate limiting

    // signature covers the raw body, verify before parsing anything
    let device_id = authenticate_device(&state, &headers, &body).await?;

    let (meta, payload) = parse_multipart(&headers, body).await?;

    if meta.format != FORMAT_VERSION {
        return Err(bad("unsupported format"));
    }

    if hex::encode(Sha256::digest(&payload)) != meta.payload_sha256.to_lowercase() {
        return Err(bad("payload_sha256 mismatch"));
    }

    // idempotent re-upload by the same device
    let mut report_id = meta.uuid.clone();
    if uuid::Uuid::parse_str(&report_id).is_err() {
        return Err(bad("invalid uuid"));
    }

    if let Some(row) = sqlx::query("SELECT device_id FROM report WHERE id = ?")
        .bind(&report_id)
        .fetch_optional(&state.db)
        .await?
    {
        let existing_dev: Option<String> = row.get("device_id");
        if existing_dev.is_some() && existing_dev == device_id {
            return Ok(respond_created(&state.cfg, &report_id));
        }
        // uuid collision from another device: assign a fresh id
        report_id = new_id();
    }

    let raw_dir = state.cfg.raw_dir();
    tokio::fs::create_dir_all(&raw_dir)
        .await
        .map_err(anyhow::Error::from)?;
    tokio::fs::write(raw_dir.join(&report_id), &payload)
        .await
        .map_err(anyhow::Error::from)?;

    sqlx::query(
        "INSERT INTO report (id, device_id, kind, received_at, captured_at,
                             version, revision, target, arch, board_name, kernel,
                             payload_encoding)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&report_id)
    .bind(&device_id)
    .bind(meta.kind.as_str())
    .bind(now())
    .bind(meta.captured_at)
    .bind(&meta.openwrt.version)
    .bind(&meta.openwrt.revision)
    .bind(&meta.openwrt.target)
    .bind(&meta.openwrt.arch)
    .bind(&meta.board)
    .bind(&meta.kernel)
    .bind(meta.payload_encoding.as_str())
    .execute(&state.db)
    .await?;

    sqlx::query("INSERT INTO decode_job (id, report_id) VALUES (?, ?)")
        .bind(new_id())
        .bind(&report_id)
        .execute(&state.db)
        .await?;

    Ok(respond_created(&state.cfg, &report_id))
}

fn respond_created(cfg: &Config, report_id: &str) -> Response {
    (
        StatusCode::CREATED,
        Json(json!({
            "report_id": report_id,
            "view_url": format!("{}/reports/{}", cfg.base_url, report_id),
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct ChallengeReq {
    pubkey: String,
}

pub async fn device_challenge(
    State(state): State<SharedState>,
    Json(req): Json<ChallengeReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    usign::PublicKey::from_base64(&req.pubkey).map_err(|_| bad("invalid pubkey"))?;

    let known = sqlx::query("SELECT id FROM device WHERE pubkey = ?")
        .bind(&req.pubkey)
        .fetch_optional(&state.db)
        .await?;
    if known.is_none() {
        return Err(ApiError(StatusCode::NOT_FOUND, "unknown device".into()));
    }

    let mut nonce = uuid::Uuid::new_v4().as_bytes().to_vec();
    nonce.extend_from_slice(uuid::Uuid::new_v4().as_bytes());

    let mut nonces = state.nonces.lock().unwrap();
    nonces.retain(|_, (_, t)| t.elapsed() < NONCE_TTL);
    nonces.insert(req.pubkey.clone(), (nonce.clone(), Instant::now()));

    Ok(Json(json!({
        "nonce": B64.encode(nonce),
        "expires_in": NONCE_TTL.as_secs(),
    })))
}

#[derive(Deserialize)]
pub struct LoginReq {
    pubkey: String,
    signature: String,
}

pub async fn device_login(
    State(state): State<SharedState>,
    Json(req): Json<LoginReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let key = usign::PublicKey::from_base64(&req.pubkey).map_err(|_| bad("invalid pubkey"))?;

    let nonce = {
        let mut nonces = state.nonces.lock().unwrap();
        match nonces.remove(&req.pubkey) {
            Some((nonce, t)) if t.elapsed() < NONCE_TTL => nonce,
            _ => return Err(ApiError(StatusCode::UNAUTHORIZED, "no valid challenge".into())),
        }
    };

    key.verify(&req.signature, &nonce)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "signature verification failed".into()))?;

    let row = sqlx::query("SELECT id FROM device WHERE pubkey = ?")
        .bind(&req.pubkey)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "unknown device".into()))?;
    let device_id: String = row.get("id");

    let token = new_secret();

    sqlx::query("INSERT INTO device_token (token_hash, device_id, expires) VALUES (?, ?, ?)")
        .bind(hex::encode(Sha256::digest(token.as_bytes())))
        .bind(&device_id)
        .bind(now() + TOKEN_TTL_SECS)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({
        "token": token,
        "expires_in": TOKEN_TTL_SECS,
    })))
}

pub async fn my_reports(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "missing token".into()))?;

    let row = sqlx::query("SELECT device_id FROM device_token WHERE token_hash = ? AND expires > ?")
        .bind(hex::encode(Sha256::digest(token.as_bytes())))
        .bind(now())
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "invalid token".into()))?;
    let device_id: String = row.get("device_id");

    let rows = sqlx::query(
        "SELECT id, kind, received_at, version, target, state, visibility
         FROM report WHERE device_id = ? ORDER BY received_at DESC",
    )
    .bind(&device_id)
    .fetch_all(&state.db)
    .await?;

    let reports: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            json!({
                "report_id": r.get::<String, _>("id"),
                "kind": r.get::<String, _>("kind"),
                "received_at": r.get::<i64, _>("received_at"),
                "version": r.get::<String, _>("version"),
                "target": r.get::<String, _>("target"),
                "state": r.get::<String, _>("state"),
                "visibility": r.get::<String, _>("visibility"),
            })
        })
        .collect();

    Ok(Json(json!({ "reports": reports })))
}
