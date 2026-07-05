// SPDX-License-Identifier: GPL-2.0-only
//! ucrs-decoder — worker that decodes queued crash reports.
//!
//! Runs as a separate binary from the ingest server so it can be
//! deployed under a different user/host. Crash payloads are untrusted;
//! the current kernel-oops pipeline only handles *text* in memory-safe
//! Rust with strict size caps. When core-dump decoding (gdb) arrives,
//! that step will additionally be wrapped in a podman sandbox.
//!
//! Usage: ucrs-decoder [config.toml] [--once]

use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use ucrs_common::config::Config;
use ucrs_decoder::{decode, symbols};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let mut config_path = PathBuf::from("config.toml");
    let mut once = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--once" => once = true,
            other => config_path = PathBuf::from(other),
        }
    }

    let cfg = Config::load(&config_path)?;

    let opts = SqliteConnectOptions::from_str(&cfg.database_url)
        .context("parsing database_url")?;
    let db = SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .context("opening database (does the server create it first?)")?;

    let pool = symbols::SymbolPool::new(&cfg);

    tracing::info!("decoder started ({})", if once { "one-shot" } else { "loop" });

    loop {
        match decode::claim_job(&db).await {
            Ok(Some(job)) => {
                decode::process_job(&cfg, &db, &pool, &job).await;
                continue; // drain the queue without sleeping
            }
            Ok(None) => {
                if once {
                    return Ok(());
                }
            }
            Err(e) => tracing::error!("claiming job: {e:#}"),
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
