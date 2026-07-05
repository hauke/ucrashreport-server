// SPDX-License-Identifier: GPL-2.0-only
//! Integration test: a queued gzip kernel-oops report is decoded,
//! scrubbed, grouped, and its raw payload deleted — without symbols
//! available (the degrade path, which is also what CI can exercise
//! offline).

use std::io::Write;
use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::Row;
use ucrs_common::config::{Config, Symbols};

const OOPS: &str = r#"[ 7136.514751] Internal error: Oops - BUG: 00000000f2000800 [#1] SMP
[ 7136.520932] Modules linked in: act_mirred cls_matchall
[ 7136.611944] Hardware name: GL.iNet GL-MT6000 (DT)
[ 7136.611944] eth0 mac 94:83:c4:12:34:56 peer 192.168.1.42
[ 7136.622209] Call trace:
[ 7136.624642]  kfree_skb_list_reason+0x3c/0x2d0
[ 7136.628993]  tcf_mirred_to_dev+0x1e8/0x350 [act_mirred]
[ 7136.656045] ---[ end trace 0000000000000000 ]---
"#;

#[tokio::test]
async fn decode_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();

    let cfg = Config {
        instance_name: "test".into(),
        listen: "127.0.0.1:0".into(),
        base_url: "http://test".into(),
        data_dir: tmp.path().to_path_buf(),
        database_url: format!("sqlite://{}/test.db?mode=rwc", tmp.path().display()),
        raw_failed_retention_days: 14,
        symbols: Symbols {
            // unreachable on purpose: exercises the no-symbols path
            kernel_release: "http://127.0.0.1:1/{version}/{target}/kernel-debug.tar.zst".into(),
            kernel_snapshot: "http://127.0.0.1:1/{target}/kernel-debug.tar.zst".into(),
            retention_weeks: 4,
        },
    };

    let opts = SqliteConnectOptions::from_str(&cfg.database_url)
        .unwrap()
        .create_if_missing(true);
    let db = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
    sqlx::migrate!("../../migrations").run(&db).await.unwrap();

    // spool the raw payload like the ingest API would
    let report_id = "11111111-2222-3333-4444-555555555555";
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(OOPS.as_bytes()).unwrap();
    let raw = enc.finish().unwrap();
    std::fs::create_dir_all(cfg.raw_dir()).unwrap();
    let raw_path = cfg.raw_dir().join(report_id);
    std::fs::write(&raw_path, &raw).unwrap();

    sqlx::query(
        "INSERT INTO report (id, kind, received_at, captured_at, version, revision,
                             target, arch, board_name, kernel, payload_encoding)
         VALUES (?, 'kernel_oops', 1, 1, '25.12.5', 'r33051', 'mediatek/filogic',
                 'aarch64_cortex-a53', 'glinet,gl-mt6000', '6.12.94~abc-r1', 'gzip')",
    )
    .bind(report_id)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query("INSERT INTO decode_job (id, report_id) VALUES ('job-1', ?)")
        .bind(report_id)
        .execute(&db)
        .await
        .unwrap();

    // run the worker logic once
    let pool = ucrs_decoder::symbols::SymbolPool::new(&cfg);
    let job = ucrs_decoder::decode::claim_job(&db).await.unwrap().unwrap();
    assert_eq!(job.report_id, report_id);
    ucrs_decoder::decode::process_job(&cfg, &db, &pool, &job).await;

    // report decoded and grouped
    let report = sqlx::query("SELECT state, group_id, raw_deleted_at FROM report WHERE id = ?")
        .bind(report_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(report.get::<String, _>("state"), "decoded");
    let group_id: String = report.get("group_id");
    assert!(report.get::<Option<i64>, _>("raw_deleted_at").is_some());

    let group = sqlx::query("SELECT title, modules, kind FROM crash_group WHERE id = ?")
        .bind(&group_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(group.get::<String, _>("title"), "kfree_skb_list_reason");
    assert_eq!(group.get::<String, _>("modules"), "act_mirred");

    // decoded text stored and scrubbed, raw blob gone
    let decoded = std::fs::read_to_string(cfg.decoded_dir().join(report_id)).unwrap();
    assert!(decoded.contains("94:83:c4:xx:xx:xx"), "MAC not scrubbed");
    assert!(decoded.contains("x.x.x.x"), "IP not scrubbed");
    assert!(decoded.contains("tcf_mirred_to_dev+0x1e8/0x350"));
    assert!(!raw_path.exists(), "raw payload not deleted");

    // job marked done
    let job_row = sqlx::query("SELECT state FROM decode_job WHERE id = 'job-1'")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(job_row.get::<String, _>("state"), "done");

    // a second identical report must land in the same group
    let report2 = "aaaaaaaa-2222-3333-4444-555555555555";
    std::fs::write(cfg.raw_dir().join(report2), &raw).unwrap();
    sqlx::query(
        "INSERT INTO report (id, kind, received_at, captured_at, version, revision,
                             target, arch, board_name, kernel, payload_encoding)
         VALUES (?, 'kernel_oops', 2, 2, '25.12.5', 'r33051', 'mediatek/filogic',
                 'aarch64_cortex-a53', 'glinet,gl-mt6000', '6.12.94~abc-r1', 'gzip')",
    )
    .bind(report2)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query("INSERT INTO decode_job (id, report_id) VALUES ('job-2', ?)")
        .bind(report2)
        .execute(&db)
        .await
        .unwrap();

    let job = ucrs_decoder::decode::claim_job(&db).await.unwrap().unwrap();
    ucrs_decoder::decode::process_job(&cfg, &db, &pool, &job).await;

    let n: i64 = sqlx::query("SELECT COUNT(*) AS n FROM crash_group")
        .fetch_one(&db)
        .await
        .unwrap()
        .get("n");
    assert_eq!(n, 1, "same crash created a second group");
}
