use anyhow::Context;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct MailMessage {
    pub id: String,
    pub recipient: String,
    pub sender: String,
    pub subject: String,
    pub raw_message: String,
    pub received_at: String,
    pub is_read: bool,
    #[allow(dead_code)]
    pub is_deleted: bool,
}

pub async fn store_message(
    pool: &SqlitePool,
    recipient: &str,
    sender: &str,
    subject: &str,
    raw_message: &str,
) -> anyhow::Result<String> {
    let id = Uuid::new_v4().to_string();
    let received_at = Utc::now().to_rfc3339();
    sqlx::query(
        r#"
        INSERT INTO mailbox (id, recipient, sender, subject, raw_message, received_at, is_read, is_deleted)
        VALUES (?, ?, ?, ?, ?, ?, 0, 0)
        "#,
    )
    .bind(&id)
    .bind(recipient)
    .bind(sender)
    .bind(subject)
    .bind(raw_message)
    .bind(&received_at)
    .execute(pool)
    .await
    .context("Failed to store message")?;
    Ok(id)
}

pub async fn list_messages(
    pool: &SqlitePool,
    recipient: &str,
) -> anyhow::Result<Vec<MailMessage>> {
    let rows: Vec<(String, String, String, String, String, String, i64, i64)> =
        sqlx::query_as(
            r#"
            SELECT id, recipient, sender, subject, raw_message, received_at, is_read, is_deleted
            FROM mailbox
            WHERE recipient = ? AND is_deleted = 0
            ORDER BY received_at DESC
            "#,
        )
        .bind(recipient)
        .fetch_all(pool)
        .await
        .context("Failed to list messages")?;

    Ok(rows
        .into_iter()
        .map(
            |(id, recipient, sender, subject, raw_message, received_at, is_read, is_deleted)| {
                MailMessage {
                    id,
                    recipient,
                    sender,
                    subject,
                    raw_message,
                    received_at,
                    is_read: is_read != 0,
                    is_deleted: is_deleted != 0,
                }
            },
        )
        .collect())
}

pub async fn list_all_messages(pool: &SqlitePool) -> anyhow::Result<Vec<MailMessage>> {
    let rows: Vec<(String, String, String, String, String, String, i64, i64)> =
        sqlx::query_as(
            r#"
            SELECT id, recipient, sender, subject, raw_message, received_at, is_read, is_deleted
            FROM mailbox
            WHERE is_deleted = 0
            ORDER BY received_at DESC
            "#,
        )
        .fetch_all(pool)
        .await
        .context("Failed to list all messages")?;

    Ok(rows
        .into_iter()
        .map(
            |(id, recipient, sender, subject, raw_message, received_at, is_read, is_deleted)| {
                MailMessage {
                    id,
                    recipient,
                    sender,
                    subject,
                    raw_message,
                    received_at,
                    is_read: is_read != 0,
                    is_deleted: is_deleted != 0,
                }
            },
        )
        .collect())
}

#[allow(dead_code)]
pub async fn get_message(pool: &SqlitePool, id: &str) -> anyhow::Result<Option<MailMessage>> {
    let row: Option<(String, String, String, String, String, String, i64, i64)> =
        sqlx::query_as(
            r#"
            SELECT id, recipient, sender, subject, raw_message, received_at, is_read, is_deleted
            FROM mailbox
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .context("Failed to get message")?;

    Ok(row.map(
        |(id, recipient, sender, subject, raw_message, received_at, is_read, is_deleted)| {
            MailMessage {
                id,
                recipient,
                sender,
                subject,
                raw_message,
                received_at,
                is_read: is_read != 0,
                is_deleted: is_deleted != 0,
            }
        },
    ))
}

pub async fn mark_deleted(pool: &SqlitePool, id: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE mailbox SET is_deleted = 1 WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .context("Failed to mark message deleted")?;
    Ok(())
}

pub async fn mark_read(pool: &SqlitePool, id: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE mailbox SET is_read = 1 WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .context("Failed to mark message read")?;
    Ok(())
}

pub async fn expunge(pool: &SqlitePool, recipient: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM mailbox WHERE recipient = ? AND is_deleted = 1")
        .bind(recipient)
        .execute(pool)
        .await
        .context("Failed to expunge messages")?;
    Ok(())
}

#[allow(dead_code)]
pub async fn message_count(pool: &SqlitePool, recipient: &str) -> anyhow::Result<(i64, i64)> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mailbox WHERE recipient = ? AND is_deleted = 0")
            .bind(recipient)
            .fetch_one(pool)
            .await
            .context("Failed to count messages")?;

    let size: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(LENGTH(raw_message)), 0) FROM mailbox WHERE recipient = ? AND is_deleted = 0",
    )
    .bind(recipient)
    .fetch_one(pool)
    .await
    .context("Failed to sum message sizes")?;

    Ok((count, size))
}
