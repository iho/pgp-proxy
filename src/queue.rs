use crate::config::Config;
use crate::smtp::client;
use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct QueueEntry {
    pub id: String,
    #[allow(dead_code)]
    pub message_id: String,
    pub from_addr: String,
    pub to_addr: String,
    pub raw_message: String,
    pub attempts: i64,
    pub max_attempts: i64,
    pub next_retry_at: String,
    pub last_error: Option<String>,
    pub status: String,
    pub created_at: String,
}

/// Retry delay after each successive failure.
fn backoff_delay(attempts: i64) -> Duration {
    match attempts {
        1 => Duration::minutes(5),
        2 => Duration::minutes(30),
        3 => Duration::hours(2),
        4 => Duration::hours(8),
        _ => Duration::hours(24),
    }
}

pub async fn enqueue(
    pool: &SqlitePool,
    message_id: &str,
    from_addr: &str,
    to_addr: &str,
    raw_message: &str,
) -> anyhow::Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        r#"
        INSERT INTO delivery_queue
            (id, message_id, from_addr, to_addr, raw_message, attempts, max_attempts,
             next_retry_at, last_error, status, created_at)
        VALUES (?, ?, ?, ?, ?, 0, 5, ?, NULL, 'pending', ?)
        "#,
    )
    .bind(&id)
    .bind(message_id)
    .bind(from_addr)
    .bind(to_addr)
    .bind(raw_message)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await
    .context("Failed to enqueue message")?;

    Ok(id)
}

pub async fn list_queue(pool: &SqlitePool) -> anyhow::Result<Vec<QueueEntry>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            i64,
            i64,
            String,
            Option<String>,
            String,
            String,
        ),
    >(
        r#"
        SELECT id, message_id, from_addr, to_addr, raw_message,
               attempts, max_attempts, next_retry_at, last_error, status, created_at
        FROM delivery_queue
        ORDER BY created_at DESC
        LIMIT 200
        "#,
    )
    .fetch_all(pool)
    .await
    .context("Failed to list queue")?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                message_id,
                from_addr,
                to_addr,
                raw_message,
                attempts,
                max_attempts,
                next_retry_at,
                last_error,
                status,
                created_at,
            )| QueueEntry {
                id,
                message_id,
                from_addr,
                to_addr,
                raw_message,
                attempts,
                max_attempts,
                next_retry_at,
                last_error,
                status,
                created_at,
            },
        )
        .collect())
}

pub async fn delete_entry(pool: &SqlitePool, id: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM delivery_queue WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .context("Failed to delete queue entry")?;
    Ok(())
}

async fn fetch_pending(pool: &SqlitePool) -> anyhow::Result<Vec<QueueEntry>> {
    let now = Utc::now().to_rfc3339();
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            i64,
            i64,
            String,
            Option<String>,
            String,
            String,
        ),
    >(
        r#"
        SELECT id, message_id, from_addr, to_addr, raw_message,
               attempts, max_attempts, next_retry_at, last_error, status, created_at
        FROM delivery_queue
        WHERE status = 'pending' AND next_retry_at <= ?
        ORDER BY next_retry_at ASC
        LIMIT 50
        "#,
    )
    .bind(&now)
    .fetch_all(pool)
    .await
    .context("Failed to fetch pending queue entries")?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                message_id,
                from_addr,
                to_addr,
                raw_message,
                attempts,
                max_attempts,
                next_retry_at,
                last_error,
                status,
                created_at,
            )| QueueEntry {
                id,
                message_id,
                from_addr,
                to_addr,
                raw_message,
                attempts,
                max_attempts,
                next_retry_at,
                last_error,
                status,
                created_at,
            },
        )
        .collect())
}

async fn mark_delivered(pool: &SqlitePool, id: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE delivery_queue SET status = 'delivered' WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .context("Failed to mark delivered")?;
    Ok(())
}

async fn mark_failed(pool: &SqlitePool, id: &str, error: &str, attempts: i64) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE delivery_queue SET status = 'failed', attempts = ?, last_error = ? WHERE id = ?",
    )
    .bind(attempts)
    .bind(error)
    .bind(id)
    .execute(pool)
    .await
    .context("Failed to mark failed")?;
    Ok(())
}

async fn schedule_retry(
    pool: &SqlitePool,
    id: &str,
    attempts: i64,
    error: &str,
) -> anyhow::Result<()> {
    let delay = backoff_delay(attempts);
    let next_retry: DateTime<Utc> = Utc::now() + delay;
    sqlx::query(
        r#"
        UPDATE delivery_queue
        SET attempts = ?, last_error = ?, next_retry_at = ?
        WHERE id = ?
        "#,
    )
    .bind(attempts)
    .bind(error)
    .bind(next_retry.to_rfc3339())
    .bind(id)
    .execute(pool)
    .await
    .context("Failed to schedule retry")?;
    Ok(())
}

async fn process_entry(entry: &QueueEntry, config: &Config) -> anyhow::Result<()> {
    let to = vec![entry.to_addr.clone()];
    if config.delivery.mode == "direct" {
        client::deliver_direct(&entry.from_addr, &to, &entry.raw_message, &config.smtp.hostname)
            .await
    } else {
        client::relay_message(&config.relay, &entry.from_addr, &to, &entry.raw_message).await
    }
}

pub async fn run_queue_processor(
    config: Arc<Config>,
    pool: Arc<SqlitePool>,
) -> anyhow::Result<()> {
    info!("Delivery queue processor started (poll interval: 30s)");
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        let pending = match fetch_pending(pool.as_ref()).await {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to fetch pending queue entries: {e}");
                continue;
            }
        };

        if !pending.is_empty() {
            info!("Processing {} pending queue entries", pending.len());
        }

        for entry in &pending {
            let attempts = entry.attempts + 1;
            match process_entry(entry, &config).await {
                Ok(_) => {
                    info!(
                        "Delivered queue entry {} to {} (attempt {})",
                        entry.id, entry.to_addr, attempts
                    );
                    if let Err(e) = mark_delivered(pool.as_ref(), &entry.id).await {
                        warn!("Failed to mark entry {} as delivered: {e}", entry.id);
                    }
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if attempts >= entry.max_attempts {
                        warn!(
                            "Queue entry {} permanently failed after {} attempts: {err_str}",
                            entry.id, attempts
                        );
                        if let Err(le) = mark_failed(pool.as_ref(), &entry.id, &err_str, attempts).await {
                            warn!("Failed to mark entry {} as failed: {le}", entry.id);
                        }
                    } else {
                        let delay = backoff_delay(attempts);
                        warn!(
                            "Queue entry {} failed (attempt {}), retrying in {}m: {err_str}",
                            entry.id,
                            attempts,
                            delay.num_minutes()
                        );
                        if let Err(le) =
                            schedule_retry(pool.as_ref(), &entry.id, attempts, &err_str).await
                        {
                            warn!("Failed to schedule retry for entry {}: {le}", entry.id);
                        }
                    }
                }
            }
        }
    }
}
