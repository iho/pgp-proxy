use anyhow::Context;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::Utc;
use sqlx::SqlitePool;

fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {e}"))?;
    Ok(hash.to_string())
}

fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub async fn add_user(pool: &SqlitePool, email: &str, password: &str) -> anyhow::Result<()> {
    let password_hash = hash_password(password)?;
    let now_str = Utc::now().to_rfc3339();
    sqlx::query(
        r#"
        INSERT INTO users (email, password_hash, created_at)
        VALUES (?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET
            password_hash = excluded.password_hash
        "#,
    )
    .bind(email)
    .bind(&password_hash)
    .bind(&now_str)
    .execute(pool)
    .await
    .context("Failed to insert user")?;
    Ok(())
}

pub async fn verify_user(pool: &SqlitePool, email: &str, password: &str) -> anyhow::Result<bool> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT password_hash FROM users WHERE email = ?")
            .bind(email)
            .fetch_optional(pool)
            .await
            .context("Failed to query user")?;
    match row {
        None => Ok(false),
        Some((stored_hash,)) => Ok(verify_password(password, &stored_hash)),
    }
}

pub async fn list_users(pool: &SqlitePool) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT email FROM users ORDER BY email")
            .fetch_all(pool)
            .await
            .context("Failed to list users")?;
    Ok(rows.into_iter().map(|(e,)| e).collect())
}

pub async fn delete_user(pool: &SqlitePool, email: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM users WHERE email = ?")
        .bind(email)
        .execute(pool)
        .await
        .context("Failed to delete user")?;
    Ok(())
}
