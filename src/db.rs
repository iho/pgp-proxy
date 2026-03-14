use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use std::str::FromStr;

pub async fn init_db(url: &str) -> anyhow::Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str(url)?.create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS pgp_keys (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            fingerprint TEXT NOT NULL,
            public_key_armor TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY,
            priority INTEGER NOT NULL,
            sender_pattern TEXT NOT NULL,
            recipient_pattern TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('encrypt','sign','encrypt_sign','none')),
            on_missing_key TEXT NOT NULL CHECK(on_missing_key IN ('reject','send_plain')),
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS smtp_logs (
            id TEXT PRIMARY KEY,
            message_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            recipients TEXT NOT NULL,
            applied_policy TEXT,
            status TEXT NOT NULL,
            error TEXT,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS mailbox (
            id TEXT PRIMARY KEY,
            recipient TEXT NOT NULL,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL DEFAULT '',
            raw_message TEXT NOT NULL,
            received_at TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            is_deleted INTEGER NOT NULL DEFAULT 0
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS private_keys (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            fingerprint TEXT NOT NULL,
            private_key_armor TEXT NOT NULL,
            passphrase TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS delivery_queue (
            id TEXT PRIMARY KEY,
            message_id TEXT NOT NULL,
            from_addr TEXT NOT NULL,
            to_addr TEXT NOT NULL,
            raw_message TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 5,
            next_retry_at TEXT NOT NULL,
            last_error TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}
