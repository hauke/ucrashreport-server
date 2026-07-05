// SPDX-License-Identifier: GPL-2.0-only
//! HTTP API: report ingest (protocol.md section 3), device
//! challenge-response login (section 4) and the device report list.
//!
//! Deliberately small attack surface: this module never parses crash
//! payload *contents* — that happens in the sandboxed decoder.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

use crate::auth::{self, new_secret, now};
use crate::web::{query_groups, GroupsQuery};

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

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
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
                             kernel_buildid, payload_encoding)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .bind(meta.kernel_buildid.as_deref().map(str::to_lowercase))
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

async fn require_device(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    auth::device_from_bearer(&state.db, headers)
        .await
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "missing or invalid token".into()))
}

pub async fn my_reports(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let device_id = require_device(&state, &headers).await?;

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

/// Set a report public (assigning a stable random slug) or private.
/// Returns None if the report does not exist; Some(slug) when public.
pub async fn set_visibility(
    db: &sqlx::SqlitePool,
    report_id: &str,
    public: bool,
) -> Result<Option<Option<String>>, sqlx::Error> {
    let Some(row) = sqlx::query("SELECT publish_slug FROM report WHERE id = ?")
        .bind(report_id)
        .fetch_optional(db)
        .await?
    else {
        return Ok(None);
    };

    if public {
        let slug = row
            .get::<Option<String>, _>("publish_slug")
            .unwrap_or_else(|| new_secret()[..16].to_string());
        sqlx::query("UPDATE report SET visibility = 'public', publish_slug = ? WHERE id = ?")
            .bind(&slug)
            .bind(report_id)
            .execute(db)
            .await?;
        Ok(Some(Some(slug)))
    } else {
        sqlx::query("UPDATE report SET visibility = 'private', publish_slug = NULL WHERE id = ?")
            .bind(report_id)
            .execute(db)
            .await?;
        Ok(Some(None))
    }
}

async fn owned_report(
    state: &AppState,
    headers: &HeaderMap,
    report_id: &str,
) -> Result<sqlx::sqlite::SqliteRow, ApiError> {
    let device_id = require_device(state, headers).await?;

    sqlx::query(
        "SELECT id, kind, received_at, version, target, kernel, state, visibility,
                publish_slug
         FROM report WHERE id = ? AND device_id = ?",
    )
    .bind(report_id)
    .bind(&device_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such report".into()))
}

pub async fn my_report_detail(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let r = owned_report(&state, &headers, &id).await?;

    let decoded = std::fs::read_to_string(state.cfg.decoded_dir().join(&id)).ok();

    Ok(Json(json!({
        "report_id": r.get::<String, _>("id"),
        "kind": r.get::<String, _>("kind"),
        "received_at": r.get::<i64, _>("received_at"),
        "version": r.get::<String, _>("version"),
        "target": r.get::<String, _>("target"),
        "kernel": r.get::<String, _>("kernel"),
        "state": r.get::<String, _>("state"),
        "visibility": r.get::<String, _>("visibility"),
        "decoded": decoded,
    })))
}

async fn my_set_visibility(
    state: &AppState,
    headers: &HeaderMap,
    id: &str,
    public: bool,
) -> Result<Json<serde_json::Value>, ApiError> {
    owned_report(state, headers, id).await?;

    let slug = set_visibility(&state.db, id, public)
        .await?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such report".into()))?;

    Ok(Json(json!({
        "visibility": if public { "public" } else { "private" },
        "public_url": slug.map(|s| format!("{}/r/{}", state.cfg.base_url, s)),
    })))
}

pub async fn my_publish(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    my_set_visibility(&state, &headers, &id, true).await
}

pub async fn my_unpublish(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    my_set_visibility(&state, &headers, &id, false).await
}

/// debuginfod: serve debug files by GNU build-id
/// (https://sourceware.org/elfutils/Debuginfod.html). With
/// DEBUGINFOD_URLS pointing here, gdb/addr2line/perf resolve OpenWrt
/// kernels transparently.
pub async fn debuginfod_debuginfo(
    State(state): State<SharedState>,
    axum::extract::Path(buildid): axum::extract::Path<String>,
) -> Response {
    let Some(path) = ucrs_common::buildid::resolve(&state.cfg.symbols_dir(), &buildid) else {
        return (StatusCode::NOT_FOUND, "unknown build-id").into_response();
    };

    match tokio::fs::File::open(&path).await {
        Ok(file) => {
            let stream = tokio_util::io::ReaderStream::new(file);
            (
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                axum::body::Body::from_stream(stream),
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!("debuginfod: cannot open {}: {e}", path.display());
            (StatusCode::NOT_FOUND, "unknown build-id").into_response()
        }
    }
}

/// The pool only holds --only-keep-debug files, not executables.
pub async fn debuginfod_executable() -> Response {
    (StatusCode::NOT_FOUND, "only debuginfo available").into_response()
}

/// Developer JSON API mirroring the top-crashers view.
pub async fn groups_json(
    State(state): State<SharedState>,
    _dev: crate::auth::Dev,
    axum::extract::Query(q): axum::extract::Query<GroupsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let groups = query_groups(
        &state.db,
        q.window.as_deref().unwrap_or("7d"),
        q.kind.as_deref().unwrap_or(""),
        q.version.as_deref().unwrap_or(""),
        q.target.as_deref().unwrap_or(""),
    )
    .await?;

    let groups: Vec<serde_json::Value> = groups
        .iter()
        .map(|g| {
            json!({
                "group_id": g.id,
                "title": g.title,
                "kind": g.kind,
                "modules": g.modules,
                "reports": g.count,
                "devices": g.devices,
                "first_seen_version": g.first_version,
                "last_report": g.last_report,
                "state": g.state,
            })
        })
        .collect();

    Ok(Json(json!({ "groups": groups })))
}
