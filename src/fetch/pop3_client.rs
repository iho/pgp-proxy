use crate::fetch::account_store::FetchAccount;
use crate::fetch::FetchedMessage;
use anyhow::Context;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Fetch new messages from a POP3 account.
pub async fn fetch_new_messages(
    account: &FetchAccount,
    seen_ids: &HashSet<String>,
) -> anyhow::Result<Vec<FetchedMessage>> {
    if account.tls {
        let stream = connect_tls(&account.host, account.port as u16).await?;
        let (r, w) = tokio::io::split(stream);
        run_pop3_session(BufReader::new(r), w, account, seen_ids).await
    } else {
        let stream = TcpStream::connect((&*account.host, account.port as u16))
            .await
            .with_context(|| format!("TCP connect to {}:{} failed", account.host, account.port))?;
        let (r, w) = tokio::io::split(stream);
        run_pop3_session(BufReader::new(r), w, account, seen_ids).await
    }
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

async fn run_pop3_session<R, W>(
    mut reader: BufReader<R>,
    mut writer: W,
    account: &FetchAccount,
    seen_ids: &HashSet<String>,
) -> anyhow::Result<Vec<FetchedMessage>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Read greeting
    let greeting = read_line(&mut reader).await?;
    if !greeting.starts_with("+OK") {
        anyhow::bail!("POP3 server refused connection: {greeting}");
    }

    // USER
    send(&mut writer, &format!("USER {}\r\n", account.username)).await?;
    expect_ok(&mut reader, "USER").await?;

    // PASS
    send(&mut writer, &format!("PASS {}\r\n", account.password)).await?;
    expect_ok(&mut reader, "PASS").await?;

    // UIDL — get server-assigned unique IDs
    send(&mut writer, "UIDL\r\n").await?;
    let uidl_status = read_line(&mut reader).await?;
    if !uidl_status.starts_with("+OK") {
        // Server doesn't support UIDL — fall back to sequence-number based
        warn!("POP3 server doesn't support UIDL; skipping dedup for account {}", account.id);
        send(&mut writer, "QUIT\r\n").await?;
        return Ok(vec![]);
    }

    let mut uidls: Vec<(u32, String)> = Vec::new();
    loop {
        let line = read_line(&mut reader).await?;
        if line == "." {
            break;
        }
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() == 2 {
            if let Ok(n) = parts[0].parse::<u32>() {
                uidls.push((n, parts[1].to_string()));
            }
        }
    }

    let new_msgs: Vec<(u32, String)> = uidls
        .into_iter()
        .filter(|(_, uidl)| !seen_ids.contains(uidl))
        .take(account.batch_size as usize)
        .collect();

    if new_msgs.is_empty() {
        send(&mut writer, "QUIT\r\n").await?;
        return Ok(vec![]);
    }

    info!(
        "POP3 fetch: {} new messages for account {} ({})",
        new_msgs.len(),
        account.id,
        account.username
    );

    let mut results = Vec::new();

    for (msg_num, uidl) in &new_msgs {
        send(&mut writer, &format!("RETR {msg_num}\r\n")).await?;
        let status = read_line(&mut reader).await?;
        if !status.starts_with("+OK") {
            warn!("POP3 RETR {msg_num} failed: {status}");
            continue;
        }

        // Read message until lone "."
        let mut raw_lines: Vec<String> = Vec::new();
        loop {
            let line = read_line(&mut reader).await?;
            if line == "." {
                break;
            }
            // Dot-unstuffing per RFC 1939
            let content = if line.starts_with("..") {
                line[1..].to_string()
            } else {
                line
            };
            raw_lines.push(content);
        }

        let raw = raw_lines.join("\n");
        let sender =
            extract_header(&raw, "From").unwrap_or_else(|| String::from("(unknown)"));
        let subject =
            extract_header(&raw, "Subject").unwrap_or_else(|| String::from("(no subject)"));

        results.push(FetchedMessage {
            remote_id: uidl.clone(),
            raw_rfc822: raw,
            sender,
            subject,
        });
    }

    send(&mut writer, "QUIT\r\n").await?;
    Ok(results)
}

async fn read_line<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> anyhow::Result<String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("POP3 read error")?;
    Ok(line.trim_end_matches(|c| c == '\r' || c == '\n').to_string())
}

async fn send<W: AsyncWrite + Unpin>(writer: &mut W, cmd: &str) -> anyhow::Result<()> {
    writer
        .write_all(cmd.as_bytes())
        .await
        .context("POP3 write error")?;
    writer.flush().await.context("POP3 flush error")?;
    Ok(())
}

async fn expect_ok<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    cmd: &str,
) -> anyhow::Result<()> {
    let line = read_line(reader).await?;
    if !line.starts_with("+OK") {
        anyhow::bail!("POP3 {cmd} failed: {line}");
    }
    Ok(())
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
