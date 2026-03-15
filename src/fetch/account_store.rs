use anyhow::Context;
use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct FetchAccount {
    pub id: String,
    pub protocol: String,
    pub host: String,
    pub port: i64,
    pub tls: bool,
    pub username: String,
    pub password: String,
    pub local_recipient: String,
    pub imap_mailbox: String,
    pub poll_interval_secs: i64,
    pub batch_size: i64,
    pub enabled: bool,
    pub last_fetch_at: Option<String>,
    pub last_fetch_status: Option<String>,
    pub last_messages_fetched: i64,
    #[allow(dead_code)]
    pub created_at: String,
}

type AccountRow = (
    String, String, String, i64, i64, String, String, String,
    String, i64, i64, i64, Option<String>, Option<String>, i64, String,
);

fn row_to_account(r: AccountRow) -> FetchAccount {
    let (
        id, protocol, host, port, tls, username, password, local_recipient,
        imap_mailbox, poll_interval_secs, batch_size, enabled,
        last_fetch_at, last_fetch_status, last_messages_fetched, created_at,
    ) = r;
    FetchAccount {
        id, protocol, host, port,
        tls: tls != 0,
        username, password, local_recipient, imap_mailbox,
        poll_interval_secs, batch_size,
        enabled: enabled != 0,
        last_fetch_at, last_fetch_status, last_messages_fetched, created_at,
    }
}

const SELECT: &str = r#"
    SELECT id, protocol, host, port, tls, username, password, local_recipient,
           imap_mailbox, poll_interval_secs, batch_size, enabled,
           last_fetch_at, last_fetch_status, last_messages_fetched, created_at
    FROM fetch_accounts
"#;

pub async fn list_accounts(pool: &SqlitePool) -> anyhow::Result<Vec<FetchAccount>> {
    let rows: Vec<AccountRow> = sqlx::query_as(&format!("{SELECT} ORDER BY created_at"))
        .fetch_all(pool)
        .await
        .context("Failed to list fetch accounts")?;
    Ok(rows.into_iter().map(row_to_account).collect())
}

#[allow(dead_code)]
pub async fn get_account(pool: &SqlitePool, id: &str) -> anyhow::Result<Option<FetchAccount>> {
    let row: Option<AccountRow> =
        sqlx::query_as(&format!("{SELECT} WHERE id = ?"))
            .bind(id)
            .fetch_optional(pool)
            .await
            .context("Failed to get fetch account")?;
    Ok(row.map(row_to_account))
}

#[allow(clippy::too_many_arguments)]
pub async fn add_account(
    pool: &SqlitePool,
    protocol: &str,
    host: &str,
    port: i64,
    tls: bool,
    username: &str,
    password: &str,
    local_recipient: &str,
    imap_mailbox: &str,
    poll_interval_secs: i64,
    batch_size: i64,
) -> anyhow::Result<String> {
    let id = Uuid::new_v4().to_string();
    let created_at = Utc::now().to_rfc3339();
    sqlx::query(
        r#"INSERT INTO fetch_accounts
           (id, protocol, host, port, tls, username, password, local_recipient,
            imap_mailbox, poll_interval_secs, batch_size, enabled,
            last_messages_fetched, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?)"#,
    )
    .bind(&id)
    .bind(protocol)
    .bind(host)
    .bind(port)
    .bind(tls as i64)
    .bind(username)
    .bind(password)
    .bind(local_recipient)
    .bind(imap_mailbox)
    .bind(poll_interval_secs)
    .bind(batch_size)
    .bind(&created_at)
    .execute(pool)
    .await
    .context("Failed to add fetch account")?;
    Ok(id)
}

pub async fn delete_account(pool: &SqlitePool, id: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM fetch_accounts WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .context("Failed to delete fetch account")?;
    sqlx::query("DELETE FROM seen_messages WHERE account_id = ?")
        .bind(id)
        .execute(pool)
        .await
        .ok();
    Ok(())
}

pub async fn toggle_account(pool: &SqlitePool, id: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE fetch_accounts SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .context("Failed to toggle fetch account")?;
    Ok(())
}

pub async fn record_fetch_result(
    pool: &SqlitePool,
    account_id: &str,
    status: &str,
    messages_fetched: i64,
) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE fetch_accounts SET last_fetch_at = ?, last_fetch_status = ?, last_messages_fetched = ? WHERE id = ?",
    )
    .bind(&now)
    .bind(status)
    .bind(messages_fetched)
    .bind(account_id)
    .execute(pool)
    .await
    .context("Failed to record fetch result")?;
    Ok(())
}

pub async fn get_seen_ids(pool: &SqlitePool, account_id: &str) -> anyhow::Result<HashSet<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT remote_id FROM seen_messages WHERE account_id = ?")
            .bind(account_id)
            .fetch_all(pool)
            .await
            .context("Failed to get seen IDs")?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn mark_seen(
    pool: &SqlitePool,
    account_id: &str,
    remote_id: &str,
) -> anyhow::Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT OR IGNORE INTO seen_messages (id, account_id, remote_id, seen_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(account_id)
    .bind(remote_id)
    .bind(&now)
    .execute(pool)
    .await
    .context("Failed to mark message seen")?;
    Ok(())
}
