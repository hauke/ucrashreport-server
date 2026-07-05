// SPDX-License-Identifier: GPL-2.0-only
//! ucrashreport-server — ingest API for OpenWrt crash reports.
//!
//! Currently implemented: ingest, device challenge-response login,
//! device report list. Decoder worker, grouping and the dashboard are
//! separate milestones (see README).

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use axum::routing::{get, post};
use axum::Router;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

mod api;

use api::AppState;
use ucrs_common::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| "config.toml".into());
    let cfg = Config::load(&config_path)?;

    std::fs::create_dir_all(&cfg.data_dir).context("creating data dir")?;
    std::fs::create_dir_all(cfg.raw_dir())?;
    std::fs::create_dir_all(cfg.decoded_dir())?;
    std::fs::create_dir_all(cfg.symbols_dir())?;

    // TODO: support postgres:// via sqlx::AnyPool once the queries are
    // finalized; schema and queries already avoid sqlite-specifics.
    let db_url = cfg
        .database_url
        .strip_prefix("sqlite://")
        .map(|p| format!("sqlite://{p}"))
        .unwrap_or_else(|| cfg.database_url.clone());
    let opts = SqliteConnectOptions::from_str(&db_url)
        .context("parsing database_url")?
        .create_if_missing(true);
    let db = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .context("opening database")?;

    sqlx::migrate!("../../migrations")
        .run(&db)
        .await
        .context("running migrations")?;

    let listen = cfg.listen.clone();
    let state = Arc::new(AppState {
        cfg,
        db,
        nonces: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/healthz", get(api::healthz))
        .route("/api/v1/reports", post(api::post_report))
        .route("/api/v1/device/challenge", post(api::device_challenge))
        .route("/api/v1/device/login", post(api::device_login))
        .route("/api/v1/my/reports", get(api::my_reports))
        .with_state(state);

    tracing::info!("listening on {listen}");
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    axum::serve(listener, app).await?;

    Ok(())
}
