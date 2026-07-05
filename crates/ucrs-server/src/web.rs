// SPDX-License-Identifier: GPL-2.0-only
//! Server-rendered dashboard: top crashers, group detail, report view
//! with publish links, developer login and the device "my reports"
//! page.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use sqlx::Row;

use crate::api::{set_visibility, SharedState};
use crate::auth::{self, Dev, SESSION_COOKIE};

fn fmt_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| ts.to_string())
}

fn render<T: Template>(t: T) -> Response {
    match t.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("template error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn db_err(e: sqlx::Error) -> Response {
    tracing::error!("db error: {e}");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

pub async fn index() -> Redirect {
    Redirect::to("/groups")
}

// ---- login/logout ----

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    instance: String,
    error: String,
}

pub async fn login_page(State(state): State<SharedState>) -> Response {
    render(LoginTemplate {
        instance: state.cfg.instance_name.clone(),
        error: String::new(),
    })
}

#[derive(Deserialize)]
pub struct LoginForm {
    login: String,
    password: String,
}

pub async fn login_post(
    State(state): State<SharedState>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    match auth::login(&state.db, &form.login, &form.password).await {
        Ok(Some(token)) => {
            let cookie = Cookie::build((SESSION_COOKIE, token))
                .path("/")
                .http_only(true)
                .same_site(SameSite::Lax)
                .build();
            (jar.add(cookie), Redirect::to("/groups")).into_response()
        }
        Ok(None) => render(LoginTemplate {
            instance: state.cfg.instance_name.clone(),
            error: "Invalid login or password.".into(),
        }),
        Err(e) => {
            tracing::error!("login: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn logout(State(state): State<SharedState>, jar: CookieJar) -> Response {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        auth::logout(&state.db, cookie.value()).await;
    }
    (jar.remove(Cookie::from(SESSION_COOKIE)), Redirect::to("/login")).into_response()
}

// ---- groups (top crashers) ----

#[derive(Deserialize)]
pub struct GroupsQuery {
    pub window: Option<String>,
    pub kind: Option<String>,
    pub version: Option<String>,
    pub target: Option<String>,
}

pub struct GroupRow {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub modules: String,
    pub count: i64,
    pub devices: i64,
    pub first_version: String,
    pub last_report: String,
    pub state: String,
}

fn window_cutoff(window: &str) -> i64 {
    let secs = match window {
        "24h" => 24 * 3600,
        "30d" => 30 * 24 * 3600,
        "all" => return 0,
        _ => 7 * 24 * 3600,
    };
    auth::now() - secs
}

pub async fn query_groups(
    db: &sqlx::SqlitePool,
    window: &str,
    kind: &str,
    version: &str,
    target: &str,
) -> Result<Vec<GroupRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT g.id, g.title, g.kind, g.modules, g.first_seen_version, g.state,
                COUNT(r.id) AS cnt,
                COUNT(DISTINCT r.device_id) AS devices,
                MAX(r.received_at) AS last_report
         FROM crash_group g
         JOIN report r ON r.group_id = g.id
         WHERE r.received_at >= ?
           AND (? = '' OR g.kind = ?)
           AND (? = '' OR r.version = ?)
           AND (? = '' OR r.target = ?)
         GROUP BY g.id
         ORDER BY cnt DESC, last_report DESC
         LIMIT 100",
    )
    .bind(window_cutoff(window))
    .bind(kind)
    .bind(kind)
    .bind(version)
    .bind(version)
    .bind(target)
    .bind(target)
    .fetch_all(db)
    .await?;

    Ok(rows
        .iter()
        .map(|r| GroupRow {
            id: r.get("id"),
            title: r.get("title"),
            kind: r.get("kind"),
            modules: r.get::<Option<String>, _>("modules").unwrap_or_default(),
            count: r.get("cnt"),
            devices: r.get("devices"),
            first_version: r
                .get::<Option<String>, _>("first_seen_version")
                .unwrap_or_default(),
            last_report: fmt_ts(r.get("last_report")),
            state: r.get("state"),
        })
        .collect())
}

#[derive(Template)]
#[template(path = "groups.html")]
struct GroupsTemplate {
    instance: String,
    login: String,
    window: String,
    kind: String,
    version: String,
    target: String,
    groups: Vec<GroupRow>,
}

pub async fn groups(
    State(state): State<SharedState>,
    dev: Dev,
    Query(q): Query<GroupsQuery>,
) -> Response {
    let window = q.window.unwrap_or_else(|| "7d".into());
    let kind = q.kind.unwrap_or_default();
    let version = q.version.unwrap_or_default();
    let target = q.target.unwrap_or_default();

    let groups = match query_groups(&state.db, &window, &kind, &version, &target).await {
        Ok(g) => g,
        Err(e) => return db_err(e),
    };

    render(GroupsTemplate {
        instance: state.cfg.instance_name.clone(),
        login: dev.login,
        window,
        kind,
        version,
        target,
        groups,
    })
}

// ---- group detail ----

pub struct KeyCount {
    pub key: String,
    pub count: i64,
}

pub struct ReportRow {
    pub id: String,
    pub received: String,
    pub version: String,
    pub target: String,
    pub board: String,
    pub state: String,
    pub visibility: String,
}

#[derive(Template)]
#[template(path = "group.html")]
struct GroupTemplate {
    instance: String,
    login: String,
    title: String,
    kind: String,
    modules: String,
    signature: String,
    first_seen: String,
    last_seen: String,
    first_version: String,
    issue_url: String,
    report_count: i64,
    device_count: i64,
    by_version: Vec<KeyCount>,
    by_target: Vec<KeyCount>,
    by_board: Vec<KeyCount>,
    reports: Vec<ReportRow>,
}

async fn breakdown(
    db: &sqlx::SqlitePool,
    group_id: &str,
    column: &str,
) -> Result<Vec<KeyCount>, sqlx::Error> {
    // column comes from a fixed list below, never from user input
    let rows = sqlx::query(&format!(
        "SELECT {column} AS k, COUNT(*) AS n FROM report
         WHERE group_id = ? GROUP BY {column} ORDER BY n DESC LIMIT 20"
    ))
    .bind(group_id)
    .fetch_all(db)
    .await?;

    Ok(rows
        .iter()
        .map(|r| KeyCount {
            key: r.get("k"),
            count: r.get("n"),
        })
        .collect())
}

pub async fn group_detail(
    State(state): State<SharedState>,
    dev: Dev,
    Path(id): Path<String>,
) -> Response {
    let Some(g) = sqlx::query(
        "SELECT title, kind, modules, signature, first_seen, last_seen,
                first_seen_version, issue_url, state
         FROM crash_group WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)
    .transpose()
    else {
        return (StatusCode::NOT_FOUND, "no such group").into_response();
    };
    let g = match g {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    let counts = sqlx::query(
        "SELECT COUNT(*) AS n, COUNT(DISTINCT device_id) AS d FROM report WHERE group_id = ?",
    )
    .bind(&id)
    .fetch_one(&state.db)
    .await;
    let counts = match counts {
        Ok(c) => c,
        Err(e) => return db_err(e),
    };

    let (by_version, by_target, by_board) = match (
        breakdown(&state.db, &id, "version").await,
        breakdown(&state.db, &id, "target").await,
        breakdown(&state.db, &id, "board_name").await,
    ) {
        (Ok(v), Ok(t), Ok(b)) => (v, t, b),
        _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let reports = sqlx::query(
        "SELECT id, received_at, version, target, board_name, state, visibility
         FROM report WHERE group_id = ? ORDER BY received_at DESC LIMIT 20",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await;
    let reports = match reports {
        Ok(r) => r,
        Err(e) => return db_err(e),
    };

    render(GroupTemplate {
        instance: state.cfg.instance_name.clone(),
        login: dev.login,
        title: g.get("title"),
        kind: g.get("kind"),
        modules: g.get::<Option<String>, _>("modules").unwrap_or_default(),
        signature: g.get("signature"),
        first_seen: fmt_ts(g.get("first_seen")),
        last_seen: fmt_ts(g.get("last_seen")),
        first_version: g
            .get::<Option<String>, _>("first_seen_version")
            .unwrap_or_default(),
        issue_url: g.get::<Option<String>, _>("issue_url").unwrap_or_default(),
        report_count: counts.get("n"),
        device_count: counts.get("d"),
        by_version,
        by_target,
        by_board,
        reports: reports
            .iter()
            .map(|r| ReportRow {
                id: r.get("id"),
                received: fmt_ts(r.get("received_at")),
                version: r.get("version"),
                target: r.get("target"),
                board: r.get("board_name"),
                state: r.get("state"),
                visibility: r.get("visibility"),
            })
            .collect(),
    })
}

// ---- report view (developer) ----

#[derive(Template)]
#[template(path = "report.html")]
struct ReportTemplate {
    instance: String,
    login: String,
    id: String,
    group_id: String,
    group_title: String,
    kind: String,
    received: String,
    version: String,
    revision: String,
    target: String,
    arch: String,
    board: String,
    kernel: String,
    state: String,
    visibility: String,
    slug: String,
    decoded: String,
}

pub async fn report_view(
    State(state): State<SharedState>,
    dev: Dev,
    Path(id): Path<String>,
) -> Response {
    let row = sqlx::query(
        "SELECT r.*, g.title AS group_title FROM report r
         LEFT JOIN crash_group g ON g.id = r.group_id
         WHERE r.id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await;
    let Some(r) = (match row {
        Ok(r) => r,
        Err(e) => return db_err(e),
    }) else {
        return (StatusCode::NOT_FOUND, "no such report").into_response();
    };

    let decoded =
        std::fs::read_to_string(state.cfg.decoded_dir().join(&id)).unwrap_or_default();

    render(ReportTemplate {
        instance: state.cfg.instance_name.clone(),
        login: dev.login,
        id: id.clone(),
        group_id: r.get::<Option<String>, _>("group_id").unwrap_or_default(),
        group_title: r
            .get::<Option<String>, _>("group_title")
            .unwrap_or_default(),
        kind: r.get("kind"),
        received: fmt_ts(r.get("received_at")),
        version: r.get("version"),
        revision: r.get("revision"),
        target: r.get("target"),
        arch: r.get("arch"),
        board: r.get("board_name"),
        kernel: r.get("kernel"),
        state: r.get("state"),
        visibility: r.get("visibility"),
        slug: r.get::<Option<String>, _>("publish_slug").unwrap_or_default(),
        decoded,
    })
}

pub async fn publish(
    State(state): State<SharedState>,
    _dev: Dev,
    Path(id): Path<String>,
) -> Response {
    match set_visibility(&state.db, &id, true).await {
        Ok(Some(_)) => Redirect::to(&format!("/reports/{id}")).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such report").into_response(),
        Err(e) => db_err(e),
    }
}

pub async fn unpublish(
    State(state): State<SharedState>,
    _dev: Dev,
    Path(id): Path<String>,
) -> Response {
    match set_visibility(&state.db, &id, false).await {
        Ok(Some(_)) => Redirect::to(&format!("/reports/{id}")).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such report").into_response(),
        Err(e) => db_err(e),
    }
}

// ---- public report ----

#[derive(Template)]
#[template(path = "public_report.html")]
struct PublicReportTemplate {
    instance: String,
    kind: String,
    version: String,
    revision: String,
    target: String,
    arch: String,
    board: String,
    kernel: String,
    decoded: String,
}

pub async fn public_report(State(state): State<SharedState>, Path(slug): Path<String>) -> Response {
    let row = sqlx::query(
        "SELECT id, kind, version, revision, target, arch, board_name, kernel
         FROM report WHERE publish_slug = ? AND visibility = 'public'",
    )
    .bind(&slug)
    .fetch_optional(&state.db)
    .await;
    let Some(r) = (match row {
        Ok(r) => r,
        Err(e) => return db_err(e),
    }) else {
        return (StatusCode::NOT_FOUND, "no such report").into_response();
    };

    let id: String = r.get("id");
    let decoded =
        std::fs::read_to_string(state.cfg.decoded_dir().join(&id)).unwrap_or_default();

    render(PublicReportTemplate {
        instance: state.cfg.instance_name.clone(),
        kind: r.get("kind"),
        version: r.get("version"),
        revision: r.get("revision"),
        target: r.get("target"),
        arch: r.get("arch"),
        board: r.get("board_name"),
        kernel: r.get("kernel"),
        decoded,
    })
}

// ---- device "my reports" page ----

#[derive(Template)]
#[template(path = "my.html")]
struct MyTemplate {
    instance: String,
}

pub async fn my_page(State(state): State<SharedState>) -> Response {
    render(MyTemplate {
        instance: state.cfg.instance_name.clone(),
    })
}
