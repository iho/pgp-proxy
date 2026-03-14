use anyhow::{anyhow, Context};
use chrono::Utc;
use pgp::composed::{Deserializable, SignedSecretKey};
use pgp::types::PublicKeyTrait;
use sqlx::SqlitePool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PrivateKeyRecord {
    pub id: String,
    pub email: String,
    pub fingerprint: String,
    pub private_key_armor: String,
    pub passphrase: String,
    pub created_at: String,
}

pub async fn add_private_key(
    pool: &SqlitePool,
    email: &str,
    armor: &str,
    passphrase: &str,
) -> anyhow::Result<PrivateKeyRecord> {
    let (seckey, _) = SignedSecretKey::from_string(armor)
        .map_err(|e| anyhow!("Failed to parse PGP private key: {e}"))?;

    let fingerprint = hex::encode(seckey.fingerprint().as_bytes());

    let id = Uuid::new_v4().to_string();
    let now_str = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO private_keys (id, email, fingerprint, private_key_armor, passphrase, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET
            id = excluded.id,
            fingerprint = excluded.fingerprint,
            private_key_armor = excluded.private_key_armor,
            passphrase = excluded.passphrase,
            created_at = excluded.created_at
        "#,
    )
    .bind(&id)
    .bind(email)
    .bind(&fingerprint)
    .bind(armor)
    .bind(passphrase)
    .bind(&now_str)
    .execute(pool)
    .await
    .context("Failed to insert private key")?;

    let record = get_private_key(pool, email)
        .await?
        .ok_or_else(|| anyhow!("Private key not found after insert"))?;

    Ok(record)
}

pub async fn get_private_key(
    pool: &SqlitePool,
    email: &str,
) -> anyhow::Result<Option<PrivateKeyRecord>> {
    let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
        r#"
        SELECT id, email, fingerprint, private_key_armor, passphrase, created_at
        FROM private_keys
        WHERE email = ?
        "#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .context("Failed to query private key")?;

    Ok(row.map(
        |(id, email, fingerprint, private_key_armor, passphrase, created_at)| PrivateKeyRecord {
            id,
            email,
            fingerprint,
            private_key_armor,
            passphrase,
            created_at,
        },
    ))
}

pub async fn list_private_keys(pool: &SqlitePool) -> anyhow::Result<Vec<PrivateKeyRecord>> {
    let rows: Vec<(String, String, String, String, String, String)> = sqlx::query_as(
        r#"
        SELECT id, email, fingerprint, private_key_armor, passphrase, created_at
        FROM private_keys
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
    .context("Failed to list private keys")?;

    Ok(rows
        .into_iter()
        .map(
            |(id, email, fingerprint, private_key_armor, _passphrase, created_at)| {
                PrivateKeyRecord {
                    id,
                    email,
                    fingerprint,
                    private_key_armor,
                    passphrase: String::new(), // do not expose passphrase in listings
                    created_at,
                }
            },
        )
        .collect())
}

pub async fn delete_private_key(pool: &SqlitePool, id: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM private_keys WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .context("Failed to delete private key")?;
    Ok(())
}
