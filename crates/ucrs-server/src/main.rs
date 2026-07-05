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
mod auth;
mod web;

use api::AppState;
use ucrs_common::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let mut config_path = PathBuf::from("config.toml");
    let mut adduser: Option<String> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == "adduser" {
            adduser = Some(
                it.next()
                    .context("usage: ucrs-server [config.toml] adduser <login>")?
                    .clone(),
            );
        } else {
            config_path = PathBuf::from(arg);
        }
    }

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

    if let Some(login) = adduser {
        let password = auth::create_user(&db, &login).await?;
        println!("created user '{login}' with password: {password}");
        return Ok(());
    }

    let listen = cfg.listen.clone();
    let state = Arc::new(AppState {
        cfg,
        db,
        nonces: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/healthz", get(api::healthz))
        // device API
        .route("/api/v1/reports", post(api::post_report))
        .route("/api/v1/device/challenge", post(api::device_challenge))
        .route("/api/v1/device/login", post(api::device_login))
        .route("/api/v1/my/reports", get(api::my_reports))
        .route("/api/v1/my/reports/{id}", get(api::my_report_detail))
        .route("/api/v1/my/reports/{id}/publish", post(api::my_publish))
        .route("/api/v1/my/reports/{id}/unpublish", post(api::my_unpublish))
        // developer API
        .route("/api/v1/groups", get(api::groups_json))
        // dashboard
        .route("/", get(web::index))
        .route("/login", get(web::login_page).post(web::login_post))
        .route("/logout", post(web::logout))
        .route("/groups", get(web::groups))
        .route("/groups/{id}", get(web::group_detail))
        .route("/reports/{id}", get(web::report_view))
        .route("/reports/{id}/publish", post(web::publish))
        .route("/reports/{id}/unpublish", post(web::unpublish))
        .route("/r/{slug}", get(web::public_report))
        .route("/my", get(web::my_page))
        .with_state(state);

    tracing::info!("listening on {listen}");
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    axum::serve(listener, app).await?;

    Ok(())
}
