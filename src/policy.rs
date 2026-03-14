use anyhow::Context;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyAction {
    Encrypt,
    Sign,
    EncryptSign,
    None,
}

impl PolicyAction {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyAction::Encrypt => "encrypt",
            PolicyAction::Sign => "sign",
            PolicyAction::EncryptSign => "encrypt_sign",
            PolicyAction::None => "none",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "encrypt" => PolicyAction::Encrypt,
            "sign" => PolicyAction::Sign,
            "encrypt_sign" => PolicyAction::EncryptSign,
            _ => PolicyAction::None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyRecord {
    pub id: String,
    pub priority: i64,
    pub sender_pattern: String,
    pub recipient_pattern: String,
    pub action: String,
    pub on_missing_key: String,
    pub created_at: DateTime<Utc>,
}

pub async fn add_policy(
    pool: &SqlitePool,
    priority: i64,
    sender_pattern: &str,
    recipient_pattern: &str,
    action: &str,
    on_missing_key: &str,
) -> anyhow::Result<PolicyRecord> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let now_str = now.to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO policies (id, priority, sender_pattern, recipient_pattern, action, on_missing_key, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(priority)
    .bind(sender_pattern)
    .bind(recipient_pattern)
    .bind(action)
    .bind(on_missing_key)
    .bind(&now_str)
    .execute(pool)
    .await
    .context("Failed to insert policy")?;

    Ok(PolicyRecord {
        id,
        priority,
        sender_pattern: sender_pattern.to_string(),
        recipient_pattern: recipient_pattern.to_string(),
        action: action.to_string(),
        on_missing_key: on_missing_key.to_string(),
        created_at: now,
    })
}

pub async fn list_policies(pool: &SqlitePool) -> anyhow::Result<Vec<PolicyRecord>> {
    let rows = sqlx::query_as::<_, (String, i64, String, String, String, String, String)>(
        r#"
        SELECT id, priority, sender_pattern, recipient_pattern, action, on_missing_key, created_at
        FROM policies
        ORDER BY priority ASC
        "#,
    )
    .fetch_all(pool)
    .await
    .context("Failed to list policies")?;

    Ok(rows
        .into_iter()
        .map(
            |(id, priority, sender_pattern, recipient_pattern, action, on_missing_key, created_at)| {
                PolicyRecord {
                    id,
                    priority,
                    sender_pattern,
                    recipient_pattern,
                    action,
                    on_missing_key,
                    created_at: created_at
                        .parse::<DateTime<Utc>>()
                        .unwrap_or_else(|_| Utc::now()),
                }
            },
        )
        .collect())
}

pub async fn delete_policy(pool: &SqlitePool, id: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM policies WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .context("Failed to delete policy")?;
    Ok(())
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Handle wildcard domain patterns like *@example.com
    if let Some(domain_pattern) = pattern.strip_prefix("*@") {
        if let Some(value_domain) = value.split('@').nth(1) {
            return value_domain.eq_ignore_ascii_case(domain_pattern);
        }
        return false;
    }

    // Handle prefix wildcard like user@*
    if let Some(user_pattern) = pattern.strip_suffix("@*") {
        if let Some(value_user) = value.split('@').next() {
            return value_user.eq_ignore_ascii_case(user_pattern);
        }
        return false;
    }

    // Exact match (case-insensitive)
    pattern.eq_ignore_ascii_case(value)
}

pub async fn evaluate(
    pool: &SqlitePool,
    sender: &str,
    recipient: &str,
) -> anyhow::Result<Option<PolicyRecord>> {
    let policies = list_policies(pool).await?;

    for policy in policies {
        if pattern_matches(&policy.sender_pattern, sender)
            && pattern_matches(&policy.recipient_pattern, recipient)
        {
            return Ok(Some(policy));
        }
    }

    Ok(None)
}
