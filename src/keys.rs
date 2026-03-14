use anyhow::{anyhow, Context};
use chrono::{DateTime, Utc};
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::types::PublicKeyTrait;
use sqlx::SqlitePool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct KeyRecord {
    pub id: String,
    pub email: String,
    pub fingerprint: String,
    pub public_key_armor: String,
    pub created_at: DateTime<Utc>,
}

pub async fn add_key(pool: &SqlitePool, email: &str, armor: &str) -> anyhow::Result<KeyRecord> {
    let (pubkey, _) = SignedPublicKey::from_string(armor)
        .map_err(|e| anyhow!("Failed to parse PGP public key: {e}"))?;

    let fingerprint = hex::encode(pubkey.fingerprint().as_bytes());

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let now_str = now.to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO pgp_keys (id, email, fingerprint, public_key_armor, created_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET
            fingerprint = excluded.fingerprint,
            public_key_armor = excluded.public_key_armor,
            created_at = excluded.created_at
        "#,
    )
    .bind(&id)
    .bind(email)
    .bind(&fingerprint)
    .bind(armor)
    .bind(&now_str)
    .execute(pool)
    .await
    .context("Failed to insert key")?;

    // Fetch the actual record (in case of upsert, id might differ)
    let record = get_key(pool, email)
        .await?
        .ok_or_else(|| anyhow!("Key not found after insert"))?;

    Ok(record)
}

pub async fn get_key(pool: &SqlitePool, email: &str) -> anyhow::Result<Option<KeyRecord>> {
    let row = sqlx::query_as::<_, (String, String, String, String, String)>(
        r#"
        SELECT id, email, fingerprint, public_key_armor, created_at
        FROM pgp_keys
        WHERE email = ?
        "#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .context("Failed to query key")?;

    Ok(row.map(|(id, email, fingerprint, public_key_armor, created_at)| KeyRecord {
        id,
        email,
        fingerprint,
        public_key_armor,
        created_at: created_at
            .parse::<DateTime<Utc>>()
            .unwrap_or_else(|_| Utc::now()),
    }))
}

pub async fn list_keys(pool: &SqlitePool) -> anyhow::Result<Vec<KeyRecord>> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String)>(
        r#"
        SELECT id, email, fingerprint, public_key_armor, created_at
        FROM pgp_keys
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
    .context("Failed to list keys")?;

    Ok(rows
        .into_iter()
        .map(|(id, email, fingerprint, public_key_armor, created_at)| KeyRecord {
            id,
            email,
            fingerprint,
            public_key_armor,
            created_at: created_at
                .parse::<DateTime<Utc>>()
                .unwrap_or_else(|_| Utc::now()),
        })
        .collect())
}

pub async fn delete_key(pool: &SqlitePool, id: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM pgp_keys WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .context("Failed to delete key")?;
    Ok(())
}
