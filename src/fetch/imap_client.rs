use crate::fetch::account_store::FetchAccount;
use crate::fetch::FetchedMessage;
use anyhow::Context;
use futures::TryStreamExt;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Fetch unseen messages from an IMAP account (implicit TLS only).
pub async fn fetch_new_messages(
    account: &FetchAccount,
    seen_ids: &HashSet<String>,
) -> anyhow::Result<Vec<FetchedMessage>> {
    let tls_stream = connect_tls(&account.host, account.port as u16).await?;
    let client = async_imap::Client::new(tls_stream);

    let mut session = client
        .login(&account.username, &account.password)
        .await
        .map_err(|(e, _)| anyhow::anyhow!("IMAP login failed: {e}"))?;

    let mailbox = if account.imap_mailbox.is_empty() {
        "INBOX"
    } else {
        &account.imap_mailbox
    };
    session
        .select(mailbox)
        .await
        .context("Failed to select IMAP mailbox")?;

    let uid_set = session
        .uid_search("UNSEEN")
        .await
        .context("IMAP UID SEARCH UNSEEN failed")?;

    let new_uids: Vec<u32> = uid_set
        .into_iter()
        .filter(|uid| !seen_ids.contains(&uid.to_string()))
        .take(account.batch_size as usize)
        .collect();

    if new_uids.is_empty() {
        session.logout().await.ok();
        return Ok(vec![]);
    }

    info!(
        "IMAP fetch: {} new messages for account {} ({})",
        new_uids.len(),
        account.id,
        account.username
    );

    let uid_list = new_uids
        .iter()
        .map(|u| u.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let stream = session
        .uid_fetch(&uid_list, "RFC822 UID")
        .await
        .context("IMAP UID FETCH failed")?;

    let fetches: Vec<_> = stream.try_collect().await.context("IMAP stream error")?;

    let mut results = Vec::new();
    for msg in fetches {
        let uid = match msg.uid {
            Some(u) => u,
            None => {
                warn!("IMAP message has no UID, skipping");
                continue;
            }
        };
        match msg.body() {
            Some(body) => {
                let raw = String::from_utf8_lossy(body).into_owned();
                let sender =
                    extract_header(&raw, "From").unwrap_or_else(|| String::from("(unknown)"));
                let subject = extract_header(&raw, "Subject")
                    .unwrap_or_else(|| String::from("(no subject)"));
                results.push(FetchedMessage {
                    remote_id: uid.to_string(),
                    raw_rfc822: raw,
                    sender,
                    subject,
                });
            }
            None => {
                warn!("IMAP UID {uid}: no body returned");
            }
        }
    }

    session.logout().await.ok();
    Ok(results)
}

async fn connect_tls(
    host: &str,
    port: u16,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in
        rustls_native_certs::load_native_certs().context("Failed to load native TLS certs")?
    {
        root_store.add(cert).ok();
    }
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("TCP connect to {host}:{port} failed"))?;

    let server_name =
        rustls::pki_types::ServerName::try_from(host.to_owned()).context("Invalid server name")?;

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")
}

fn extract_header(raw: &str, name: &str) -> Option<String> {
    let name_lower = name.to_lowercase();
    let end = raw
        .find("\r\n\r\n")
        .or_else(|| raw.find("\n\n"))
        .unwrap_or(raw.len());
    for line in raw[..end].lines() {
        if let Some(colon) = line.find(':') {
            if line[..colon].trim().to_lowercase() == name_lower {
                return Some(line[colon + 1..].trim().to_string());
            }
        }
    }
    None
}
