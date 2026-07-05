// SPDX-License-Identifier: GPL-2.0-only
//! The decode pipeline for one report:
//! raw payload -> decompress -> symbolize -> scrub -> store decoded
//! text -> compute signature -> upsert crash group -> delete raw blob.

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use sqlx::{Row, SqlitePool};
use ucrs_common::config::Config;
use ucrs_common::signature;
use ucrs_common::types::PayloadEncoding;

use crate::payload;
use crate::scrub::scrub;
use crate::symbols::{annotate, SymbolPool, Symbolizer};

const MAX_ATTEMPTS: i64 = 3;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub struct Job {
    pub id: String,
    pub report_id: String,
    pub attempts: i64,
}

/// Delete raw payloads of failed reports past their retention window.
pub async fn gc_failed_raw(cfg: &Config, db: &SqlitePool) {
    let cutoff = now() - cfg.raw_failed_retention_days as i64 * 86400;

    let Ok(rows) = sqlx::query(
        "SELECT id FROM report
         WHERE state = 'failed' AND raw_deleted_at IS NULL AND received_at < ?",
    )
    .bind(cutoff)
    .fetch_all(db)
    .await
    else {
        return;
    };

    for row in rows {
        let id: String = row.get("id");
        let _ = std::fs::remove_file(cfg.raw_dir().join(&id));
        let _ = sqlx::query("UPDATE report SET raw_deleted_at = ? WHERE id = ?")
            .bind(now())
            .bind(&id)
            .execute(db)
            .await;
        tracing::info!("GC: dropped raw payload of failed report {id}");
    }
}

/// Claim the oldest pending job, if any.
pub async fn claim_job(db: &SqlitePool) -> anyhow::Result<Option<Job>> {
    let row = sqlx::query(
        "UPDATE decode_job SET state = 'running', attempts = attempts + 1
         WHERE id = (SELECT id FROM decode_job WHERE state = 'pending'
                     ORDER BY id LIMIT 1)
         RETURNING id, report_id, attempts",
    )
    .fetch_optional(db)
    .await?;

    Ok(row.map(|r| Job {
        id: r.get("id"),
        report_id: r.get("report_id"),
        attempts: r.get("attempts"),
    }))
}

pub async fn process_job(cfg: &Config, db: &SqlitePool, pool: &SymbolPool, job: &Job) {
    match decode_report(cfg, db, pool, &job.report_id).await {
        Ok(group_id) => {
            let _ = sqlx::query("UPDATE decode_job SET state = 'done' WHERE id = ?")
                .bind(&job.id)
                .execute(db)
                .await;
            tracing::info!("report {} decoded into group {group_id}", job.report_id);
        }
        Err(e) => {
            let state = if job.attempts >= MAX_ATTEMPTS {
                "failed"
            } else {
                "pending"
            };
            tracing::warn!(
                "decoding report {} failed (attempt {}): {e:#}",
                job.report_id,
                job.attempts
            );
            let _ = sqlx::query("UPDATE decode_job SET state = ?, last_error = ? WHERE id = ?")
                .bind(state)
                .bind(format!("{e:#}"))
                .bind(&job.id)
                .execute(db)
                .await;
            if state == "failed" {
                let _ = sqlx::query("UPDATE report SET state = 'failed' WHERE id = ?")
                    .bind(&job.report_id)
                    .execute(db)
                    .await;
            }
        }
    }
}

async fn decode_report(
    cfg: &Config,
    db: &SqlitePool,
    pool: &SymbolPool,
    report_id: &str,
) -> anyhow::Result<String> {
    let report = sqlx::query(
        "SELECT kind, version, target, kernel, kernel_buildid, payload_encoding
         FROM report WHERE id = ?",
    )
    .bind(report_id)
    .fetch_one(db)
    .await
    .context("loading report")?;

    let kind: String = report.get("kind");
    let version: String = report.get("version");
    let target: String = report.get("target");
    let kernel_buildid: Option<String> = report.get("kernel_buildid");
    let encoding: String = report.get("payload_encoding");

    let raw_path = cfg.raw_dir().join(report_id);
    let raw = std::fs::read(&raw_path).context("reading raw payload")?;

    let encoding =
        PayloadEncoding::from_str(&encoding).map_err(|e| anyhow::anyhow!("{e}"))?;
    let text = payload::decode(&raw, encoding)?;

    // Symbols are best-effort: kernel traces already contain symbol
    // names, so grouping works without them; file:line annotation is
    // an enrichment. The Symbolizer discards them if the device's
    // kernel build-id does not match the extracted vmlinux.
    let symbol_dir = match pool.ensure_kernel(&version, &target).await {
        Ok(dir) => Some(dir),
        Err(e) => {
            tracing::warn!("no symbols for {version}/{target}: {e:#}");
            None
        }
    };

    // synchronous section: Symbolizer (memory-mapped DWARF) is not
    // held across await points
    let (decoded, sig) = {
        let mut sym = Symbolizer::new(symbol_dir.as_deref(), kernel_buildid.as_deref());
        let annotated = if sym.have_symbols() {
            annotate(&text, &mut sym)
        } else {
            text.clone()
        };
        let decoded = scrub(&annotated);

        let sig = match signature::parse_oops(&decoded) {
            Some((exception, frames)) => signature::compute(&kind, &exception, &frames),
            // no recognizable crash: group all of these per kind so
            // they remain visible instead of silently piling up
            None => signature::compute(&kind, "unclassified", &[]),
        };

        (decoded, sig)
    };

    let decoded_dir = cfg.decoded_dir();
    std::fs::create_dir_all(&decoded_dir)?;
    std::fs::write(decoded_dir.join(report_id), &decoded).context("writing decoded text")?;

    let ts = now();
    let group_row = sqlx::query(
        "INSERT INTO crash_group (id, signature, kind, title, modules,
                                  first_seen, last_seen, first_seen_version)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(signature) DO UPDATE SET last_seen = excluded.last_seen
         RETURNING id",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&sig.signature)
    .bind(&kind)
    .bind(&sig.title)
    .bind(sig.modules.join(" "))
    .bind(ts)
    .bind(ts)
    .bind(&version)
    .fetch_one(db)
    .await
    .context("upserting crash group")?;
    let group_id: String = group_row.get("id");

    sqlx::query(
        "UPDATE report SET state = 'decoded', group_id = ?, raw_deleted_at = ? WHERE id = ?",
    )
    .bind(&group_id)
    .bind(ts)
    .bind(report_id)
    .execute(db)
    .await?;

    // the raw payload is only deleted after everything else succeeded
    std::fs::remove_file(&raw_path).context("deleting raw payload")?;

    Ok(group_id)
}
