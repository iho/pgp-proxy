use crate::fetch::account_store::{self, FetchAccount};
use crate::fetch::{imap_client, pop3_client, FetchedMessage};
use crate::mailbox;
use crate::pgp_engine;
use crate::private_keys;
use crate::smtp::server::{extract_body, extract_header_from_raw, replace_body};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

/// Runs the background fetch poller.
///
/// Polls all enabled accounts at their configured interval. Sending `()` on
/// `trigger_rx` causes an immediate poll sweep without waiting for the next tick.
pub async fn run_fetch_poller(
    pool: Arc<SqlitePool>,
    global_poll_interval_secs: u64,
    mut trigger_rx: mpsc::Receiver<()>,
) -> anyhow::Result<()> {
    let mut ticker = interval(Duration::from_secs(global_poll_interval_secs.max(30)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!("Fetch poller started (global interval: {global_poll_interval_secs}s)");

    loop {
        tokio::select! {
            _ = ticker.tick() => {},
            msg = trigger_rx.recv() => {
                if msg.is_none() {
                    // channel closed — shut down
                    break;
                }
                info!("Fetch poller triggered manually");
            }
        }

        let accounts = match account_store::list_accounts(&pool).await {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to load fetch accounts: {e}");
                continue;
            }
        };

        for account in accounts.into_iter().filter(|a| a.enabled) {
            poll_account(&pool, &account).await;
        }
    }

    Ok(())
}

async fn poll_account(pool: &SqlitePool, account: &FetchAccount) {
    let seen_ids = match account_store::get_seen_ids(pool, &account.id).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to load seen IDs for account {}: {e}", account.id);
            return;
        }
    };

    let result = match account.protocol.as_str() {
        "imap" => imap_client::fetch_new_messages(account, &seen_ids).await,
        "pop3" => pop3_client::fetch_new_messages(account, &seen_ids).await,
        other => {
            warn!("Unknown fetch protocol '{}' for account {}", other, account.id);
            return;
        }
    };

    match result {
        Err(e) => {
            let status = format!("error: {e}");
            warn!("Fetch failed for account {} ({}): {e}", account.id, account.username);
            account_store::record_fetch_result(pool, &account.id, &status, 0)
                .await
                .ok();
        }
        Ok(messages) => {
            let count = messages.len() as i64;
            let mut injected = 0i64;

            for msg in &messages {
                match inject_message(pool, account, msg).await {
                    Ok(true) => {
                        injected += 1;
                        account_store::mark_seen(pool, &account.id, &msg.remote_id)
                            .await
                            .ok();
                    }
                    Ok(false) => {
                        // duplicate — still mark seen so we don't re-fetch
                        account_store::mark_seen(pool, &account.id, &msg.remote_id)
                            .await
                            .ok();
                    }
                    Err(e) => {
                        error!(
                            "Failed to inject message {} for account {}: {e}",
                            msg.remote_id, account.id
                        );
                    }
                }
            }

            if count > 0 {
                info!(
                    "Fetch account {} ({}): {injected}/{count} messages stored",
                    account.id, account.username
                );
            }

            account_store::record_fetch_result(pool, &account.id, "ok", injected)
                .await
                .ok();
        }
    }
}

/// Decrypt (if PGP) and store a fetched message in the local mailbox.
/// Returns `true` if the message was newly stored, `false` if it was a duplicate.
async fn inject_message(
    pool: &SqlitePool,
    account: &FetchAccount,
    msg: &FetchedMessage,
) -> anyhow::Result<bool> {
    let recipient = &account.local_recipient;
    let raw = &msg.raw_rfc822;

    let is_pgp = raw.contains("BEGIN PGP MESSAGE")
        || raw.to_lowercase().contains("content-type: multipart/encrypted");

    let final_message = if is_pgp {
        match private_keys::get_private_key(pool, recipient).await {
            Ok(Some(privkey)) => {
                let body = extract_body(raw);
                match pgp_engine::decrypt_message(
                    body,
                    &privkey.private_key_armor,
                    &privkey.passphrase,
                ) {
                    Ok(plaintext) => {
                        info!("Decrypted PGP message from fetch for {recipient}");
                        replace_body(raw, &plaintext)
                    }
                    Err(e) => {
                        warn!("PGP decryption failed for fetched message ({}): {e}", recipient);
                        raw.clone()
                    }
                }
            }
            Ok(None) => raw.clone(),
            Err(e) => {
                warn!("Private key lookup failed for {recipient}: {e}");
                raw.clone()
            }
        }
    } else {
        raw.clone()
    };

    let subject = extract_header_from_raw(&final_message, "Subject")
        .unwrap_or_else(|| msg.subject.clone());

    mailbox::store_message(pool, recipient, &msg.sender, &subject, &final_message)
        .await
        .map(|_| true)
}
