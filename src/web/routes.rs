use crate::fetch::account_store;
use crate::keys;
use crate::mailbox;
use crate::policy;
use crate::private_keys;
use crate::queue;
use crate::users;
use crate::web::templates::{self, DashboardStats, LogRecord};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Form,
};
use maud::{html, Markup};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::sync::Arc;
use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub pool: Arc<SqlitePool>,
    pub config: Arc<Config>,
    pub fetch_trigger: tokio::sync::mpsc::Sender<()>,
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

pub async fn dashboard(State(state): State<AppState>) -> impl IntoResponse {
    let total_keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pgp_keys")
        .fetch_one(state.pool.as_ref())
        .await
        .unwrap_or(0);

    let total_policies: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies")
        .fetch_one(state.pool.as_ref())
        .await
        .unwrap_or(0);

    let recent_logs = fetch_logs(state.pool.as_ref(), 10).await;

    let stats = DashboardStats {
        total_keys,
        total_policies,
        recent_logs,
    };

    templates::dashboard_page(&stats)
}

// ── Keys ──────────────────────────────────────────────────────────────────────

pub async fn keys_page(State(state): State<AppState>) -> impl IntoResponse {
    let keys = keys::list_keys(state.pool.as_ref()).await.unwrap_or_default();
    templates::keys_page(&keys)
}

#[derive(Deserialize)]
pub struct AddKeyForm {
    pub email: String,
    pub armor: String,
}

pub async fn add_key(
    State(state): State<AppState>,
    Form(form): Form<AddKeyForm>,
) -> impl IntoResponse {
    match keys::add_key(state.pool.as_ref(), &form.email, &form.armor).await {
        Ok(_) => {
            let keys = keys::list_keys(state.pool.as_ref()).await.unwrap_or_default();
            (StatusCode::OK, templates::keys_table(&keys)).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            err_markup(&e.to_string()),
        )
            .into_response(),
    }
}

pub async fn delete_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match keys::delete_key(state.pool.as_ref(), &id).await {
        Ok(_) => (StatusCode::OK, html! {}).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_markup(&e.to_string())).into_response(),
    }
}

// ── Policies ──────────────────────────────────────────────────────────────────

pub async fn policies_page(State(state): State<AppState>) -> impl IntoResponse {
    let policies = policy::list_policies(state.pool.as_ref())
        .await
        .unwrap_or_default();
    templates::policies_page(&policies)
}

#[derive(Deserialize)]
pub struct AddPolicyForm {
    pub priority: i64,
    pub sender_pattern: String,
    pub recipient_pattern: String,
    pub action: String,
    pub on_missing_key: String,
}

pub async fn add_policy(
    State(state): State<AppState>,
    Form(form): Form<AddPolicyForm>,
) -> impl IntoResponse {
    let valid_actions = ["encrypt", "sign", "encrypt_sign", "none"];
    let valid_missing = ["reject", "send_plain"];

    if !valid_actions.contains(&form.action.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            err_markup(&format!("Invalid action: {}", form.action)),
        )
            .into_response();
    }

    if !valid_missing.contains(&form.on_missing_key.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            err_markup(&format!("Invalid on_missing_key value: {}", form.on_missing_key)),
        )
            .into_response();
    }

    match policy::add_policy(
        state.pool.as_ref(),
        form.priority,
        &form.sender_pattern,
        &form.recipient_pattern,
        &form.action,
        &form.on_missing_key,
    )
    .await
    {
        Ok(_) => {
            let policies = policy::list_policies(state.pool.as_ref())
                .await
                .unwrap_or_default();
            (StatusCode::OK, templates::policies_table(&policies)).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_markup(&e.to_string())).into_response(),
    }
}

pub async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match policy::delete_policy(state.pool.as_ref(), &id).await {
        Ok(_) => (StatusCode::OK, html! {}).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_markup(&e.to_string())).into_response(),
    }
}

// ── Logs ──────────────────────────────────────────────────────────────────────

pub async fn logs_page(State(state): State<AppState>) -> impl IntoResponse {
    let logs = fetch_logs(state.pool.as_ref(), 100).await;
    templates::logs_page(&logs)
}

pub async fn logs_partial(State(state): State<AppState>) -> impl IntoResponse {
    let logs = fetch_logs(state.pool.as_ref(), 100).await;
    templates::logs_table(&logs)
}

// ── Config ────────────────────────────────────────────────────────────────────

pub async fn config_page(State(state): State<AppState>) -> impl IntoResponse {
    templates::config_page(&state.config)
}

// ── Users ─────────────────────────────────────────────────────────────────────

pub async fn users_page(State(state): State<AppState>) -> impl IntoResponse {
    let user_list = users::list_users(state.pool.as_ref())
        .await
        .unwrap_or_default();
    templates::users_page(&user_list)
}

#[derive(Deserialize)]
pub struct AddUserForm {
    pub email: String,
    pub password: String,
}

pub async fn add_user(
    State(state): State<AppState>,
    Form(form): Form<AddUserForm>,
) -> impl IntoResponse {
    match users::add_user(state.pool.as_ref(), &form.email, &form.password).await {
        Ok(_) => {
            let user_list = users::list_users(state.pool.as_ref())
                .await
                .unwrap_or_default();
            (StatusCode::OK, templates::users_table(&user_list)).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_markup(&e.to_string())).into_response(),
    }
}

pub async fn delete_user(
    State(state): State<AppState>,
    Path(email): Path<String>,
) -> impl IntoResponse {
    match users::delete_user(state.pool.as_ref(), &email).await {
        Ok(_) => (StatusCode::OK, html! {}).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_markup(&e.to_string())).into_response(),
    }
}

// ── Private Keys ──────────────────────────────────────────────────────────────

pub async fn private_keys_page(State(state): State<AppState>) -> impl IntoResponse {
    let pkeys = private_keys::list_private_keys(state.pool.as_ref())
        .await
        .unwrap_or_default();
    templates::private_keys_page(&pkeys)
}

#[derive(Deserialize)]
pub struct AddPrivateKeyForm {
    pub email: String,
    pub armor: String,
    pub passphrase: String,
}

pub async fn add_private_key(
    State(state): State<AppState>,
    Form(form): Form<AddPrivateKeyForm>,
) -> impl IntoResponse {
    match private_keys::add_private_key(
        state.pool.as_ref(),
        &form.email,
        &form.armor,
        &form.passphrase,
    )
    .await
    {
        Ok(_) => {
            let pkeys = private_keys::list_private_keys(state.pool.as_ref())
                .await
                .unwrap_or_default();
            (StatusCode::OK, templates::private_keys_table(&pkeys)).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_markup(&e.to_string())).into_response(),
    }
}

pub async fn delete_private_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match private_keys::delete_private_key(state.pool.as_ref(), &id).await {
        Ok(_) => (StatusCode::OK, html! {}).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_markup(&e.to_string())).into_response(),
    }
}

// ── Mailbox ───────────────────────────────────────────────────────────────────

pub async fn mailbox_page(State(state): State<AppState>) -> impl IntoResponse {
    let messages = mailbox::list_all_messages(state.pool.as_ref())
        .await
        .unwrap_or_default();
    templates::mailbox_page(&messages)
}

// ── Delivery Queue ─────────────────────────────────────────────────────────────

pub async fn queue_page(State(state): State<AppState>) -> impl IntoResponse {
    let entries = queue::list_queue(state.pool.as_ref()).await.unwrap_or_default();
    templates::queue_page(&entries)
}

pub async fn queue_partial(State(state): State<AppState>) -> impl IntoResponse {
    let entries = queue::list_queue(state.pool.as_ref()).await.unwrap_or_default();
    templates::queue_table(&entries)
}

pub async fn delete_queue_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match queue::delete_entry(state.pool.as_ref(), &id).await {
        Ok(_) => (StatusCode::OK, html! {}).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_markup(&e.to_string())).into_response(),
    }
}

// ── Fetch Accounts ────────────────────────────────────────────────────────────

pub async fn fetch_accounts_page(State(state): State<AppState>) -> impl IntoResponse {
    let accounts = account_store::list_accounts(state.pool.as_ref())
        .await
        .unwrap_or_default();
    templates::fetch_accounts_page(&accounts)
}

#[derive(Deserialize)]
pub struct AddFetchAccountForm {
    pub protocol: String,
    pub host: String,
    pub port: i64,
    pub tls: Option<String>,
    pub username: String,
    pub password: String,
    pub local_recipient: String,
    pub imap_mailbox: String,
    pub poll_interval_secs: i64,
    pub batch_size: i64,
}

pub async fn add_fetch_account(
    State(state): State<AppState>,
    Form(form): Form<AddFetchAccountForm>,
) -> impl IntoResponse {
    let valid_protocols = ["imap", "pop3"];
    if !valid_protocols.contains(&form.protocol.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            err_markup(&format!("Invalid protocol: {}", form.protocol)),
        )
            .into_response();
    }

    let tls = form.tls.as_deref() == Some("on") || form.tls.as_deref() == Some("true");

    match account_store::add_account(
        state.pool.as_ref(),
        &form.protocol,
        &form.host,
        form.port,
        tls,
        &form.username,
        &form.password,
        &form.local_recipient,
        &form.imap_mailbox,
        form.poll_interval_secs,
        form.batch_size,
    )
    .await
    {
        Ok(_) => {
            let accounts = account_store::list_accounts(state.pool.as_ref())
                .await
                .unwrap_or_default();
            (StatusCode::OK, templates::fetch_accounts_table(&accounts)).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_markup(&e.to_string())).into_response(),
    }
}

pub async fn delete_fetch_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match account_store::delete_account(state.pool.as_ref(), &id).await {
        Ok(_) => (StatusCode::OK, html! {}).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_markup(&e.to_string())).into_response(),
    }
}

pub async fn toggle_fetch_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match account_store::toggle_account(state.pool.as_ref(), &id).await {
        Ok(_) => {
            let accounts = account_store::list_accounts(state.pool.as_ref())
                .await
                .unwrap_or_default();
            (StatusCode::OK, templates::fetch_accounts_table(&accounts)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_markup(&e.to_string())).into_response(),
    }
}

pub async fn trigger_fetch_poll(State(state): State<AppState>) -> impl IntoResponse {
    state.fetch_trigger.try_send(()).ok();
    (StatusCode::OK, html! { span { "Poll triggered." } }).into_response()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn err_markup(msg: &str) -> Markup {
    html! {
        div class="error-banner" {
            span class="error-icon" { "⚠" }
            (msg)
        }
    }
}

async fn fetch_logs(pool: &SqlitePool, limit: i64) -> Vec<LogRecord> {
    let rows: Vec<(String, String, String, String, Option<String>, String, Option<String>, String)> =
        sqlx::query_as(
            r#"
            SELECT id, message_id, sender, recipients, applied_policy, status, error, created_at
            FROM smtp_logs
            ORDER BY created_at DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    rows.into_iter()
        .map(
            |(id, message_id, sender, recipients, applied_policy, status, error, created_at)| {
                LogRecord {
                    id,
                    message_id,
                    sender,
                    recipients,
                    applied_policy,
                    status,
                    error,
                    created_at,
                }
            },
        )
        .collect()
}
