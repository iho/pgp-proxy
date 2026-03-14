use crate::config::RelayConfig;
use anyhow::{anyhow, Context};
use hickory_resolver::TokioAsyncResolver;
use lettre::{
    message::{header::ContentType, Mailbox, MessageBuilder},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

pub async fn relay_message(
    config: &RelayConfig,
    from: &str,
    to: &[String],
    raw_message: &str,
) -> anyhow::Result<()> {
    let (headers_part, body_part) = split_headers_body(raw_message);
    let subject = extract_header(&headers_part, "Subject").unwrap_or_else(|| "No Subject".into());

    let from_mailbox: Mailbox = from
        .parse()
        .with_context(|| format!("Invalid from address: {from}"))?;

    let mut builder: MessageBuilder = Message::builder().from(from_mailbox).subject(subject);

    for recipient in to {
        let mailbox: Mailbox = recipient
            .parse()
            .with_context(|| format!("Invalid recipient address: {recipient}"))?;
        builder = builder.to(mailbox);
    }

    let email = builder
        .header(ContentType::TEXT_PLAIN)
        .body(body_part.to_string())
        .context("Failed to build email message")?;

    let transport = build_transport(config)?;

    transport
        .send(email)
        .await
        .map_err(|e| anyhow!("Failed to send email via relay: {e}"))?;

    Ok(())
}

pub async fn deliver_direct(
    from: &str,
    to: &[String],
    raw_message: &str,
    hostname: &str,
) -> anyhow::Result<()> {
    // Group recipients by domain
    let mut by_domain: HashMap<String, Vec<String>> = HashMap::new();
    for addr in to {
        let domain = addr
            .split('@')
            .nth(1)
            .ok_or_else(|| anyhow!("Invalid recipient address (no @): {addr}"))?
            .to_lowercase();
        by_domain.entry(domain).or_default().push(addr.clone());
    }

    let mut errors: Vec<String> = Vec::new();
    for (domain, recipients) in by_domain {
        if let Err(e) =
            deliver_to_domain(from, &recipients, raw_message, &domain, hostname).await
        {
            errors.push(format!("Failed to deliver to {domain}: {e}"));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("{}", errors.join("; ")))
    }
}

async fn deliver_to_domain(
    from: &str,
    recipients: &[String],
    raw_message: &str,
    domain: &str,
    hostname: &str,
) -> anyhow::Result<()> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|e| anyhow!("Failed to create DNS resolver: {e}"))?;

    let mut mx_hosts: Vec<(u16, String)> = Vec::new();

    match resolver.mx_lookup(domain).await {
        Ok(mx_response) => {
            let mut records: Vec<(u16, String)> = mx_response
                .iter()
                .map(|mx| {
                    let pref = mx.preference();
                    let host = mx.exchange().to_utf8();
                    let host = host.trim_end_matches('.').to_string();
                    (pref, host)
                })
                .collect();
            records.sort_by_key(|(pref, _)| *pref);
            mx_hosts = records;
            info!("MX lookup for {domain}: {} records", mx_hosts.len());
        }
        Err(e) => {
            warn!("MX lookup failed for {domain}: {e}, falling back to A record");
        }
    }

    if mx_hosts.is_empty() {
        mx_hosts.push((0, domain.to_string()));
    }

    let to_refs: Vec<&str> = recipients.iter().map(|s| s.as_str()).collect();

    let mut last_error: Option<anyhow::Error> = None;
    for (_, host) in &mx_hosts {
        debug!("Trying MX host {host}:25 for domain {domain}");
        match smtp_send_raw(host, 25, from, &to_refs, raw_message, hostname).await {
            Ok(()) => {
                info!("Delivered to {domain} via {host}");
                return Ok(());
            }
            Err(e) => {
                warn!("Delivery to {host} failed: {e}");
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("No MX hosts available for {domain}")))
}

async fn smtp_send_raw(
    host: &str,
    port: u16,
    from: &str,
    to: &[&str],
    message: &str,
    our_hostname: &str,
) -> anyhow::Result<()> {
    let addr = format!("{host}:{port}");
    let tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("TCP connect to {addr} failed"))?;

    let (reader_half, writer_half) = tokio::io::split(tcp);
    let mut reader = BufReader::new(reader_half);
    let mut writer = writer_half;

    // Read greeting
    read_smtp_response(&mut reader, 220)
        .await
        .with_context(|| "Server greeting failed")?;

    // EHLO
    smtp_write(&mut writer, &format!("EHLO {our_hostname}\r\n")).await?;
    let ehlo_resp = read_smtp_response_raw(&mut reader).await?;
    check_smtp_code(&ehlo_resp, 250).with_context(|| "EHLO rejected")?;

    let supports_starttls = ehlo_resp
        .lines()
        .any(|l| l.to_uppercase().contains("STARTTLS"));

    if supports_starttls {
        smtp_write(&mut writer, "STARTTLS\r\n").await?;
        let resp = read_smtp_response_raw(&mut reader).await?;
        if resp.starts_with("220") {
            // Recombine halves to get the TcpStream back
            let reader_half = reader.into_inner();
            let tcp = reader_half.unsplit(writer);

            // Upgrade to TLS using system root CAs
            match tls_connect(tcp, host, our_hostname, from, to, message).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    // After 220 STARTTLS the server won't accept plain SMTP; bail out
                    return Err(e).with_context(|| format!("STARTTLS upgrade to {host} failed"));
                }
            }
        }
        // Server refused STARTTLS (4xx/5xx) — continue without TLS
    }

    smtp_send_commands(&mut reader, &mut writer, from, to, message).await
}

/// Perform a TLS handshake on an already-established TCP connection and run
/// the SMTP session on the resulting encrypted stream.
async fn tls_connect(
    tcp: TcpStream,
    host: &str,
    our_hostname: &str,
    from: &str,
    to: &[&str],
    message: &str,
) -> anyhow::Result<()> {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().unwrap_or_default() {
        let _ = root_store.add(cert);
    }

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| anyhow!("Invalid server name: {host}"))?;

    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake with {host} failed"))?;

    let (tr, tw) = tokio::io::split(tls_stream);
    let mut reader = BufReader::new(tr);
    let mut writer = tw;

    // Re-EHLO after TLS upgrade
    smtp_write(&mut writer, &format!("EHLO {our_hostname}\r\n")).await?;
    let ehlo_resp = read_smtp_response_raw(&mut reader).await?;
    check_smtp_code(&ehlo_resp, 250).with_context(|| "EHLO (post-TLS) rejected")?;

    smtp_send_commands(&mut reader, &mut writer, from, to, message).await
}

/// Send MAIL FROM / RCPT TO / DATA / QUIT on any async reader+writer.
async fn smtp_send_commands<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    from: &str,
    to: &[&str],
    message: &str,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    smtp_write(writer, &format!("MAIL FROM:<{from}>\r\n")).await?;
    read_smtp_response(reader, 250)
        .await
        .with_context(|| format!("MAIL FROM rejected for {from}"))?;

    for recipient in to {
        smtp_write(writer, &format!("RCPT TO:<{recipient}>\r\n")).await?;
        read_smtp_response(reader, 250)
            .await
            .with_context(|| format!("RCPT TO rejected for {recipient}"))?;
    }

    smtp_write(writer, "DATA\r\n").await?;
    read_smtp_response(reader, 354)
        .await
        .with_context(|| "DATA command rejected")?;

    writer.write_all(message.as_bytes()).await?;
    if !message.ends_with("\r\n") {
        writer.write_all(b"\r\n").await?;
    }
    writer.write_all(b".\r\n").await?;
    writer.flush().await?;
    read_smtp_response(reader, 250)
        .await
        .with_context(|| "Message rejected by server")?;

    smtp_write(writer, "QUIT\r\n").await?;
    let _ = read_smtp_response_raw(reader).await;

    Ok(())
}

async fn smtp_write<W: AsyncWrite + Unpin>(writer: &mut W, s: &str) -> anyhow::Result<()> {
    writer.write_all(s.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_smtp_response_raw<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
) -> anyhow::Result<String> {
    let mut full = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(anyhow!("Connection closed while reading SMTP response"));
        }
        full.push_str(&line);
        if line.len() >= 4 && &line[3..4] != "-" {
            break;
        }
    }
    Ok(full)
}

async fn read_smtp_response<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    expected: u16,
) -> anyhow::Result<()> {
    let resp = read_smtp_response_raw(reader).await?;
    check_smtp_code(&resp, expected)
}

fn check_smtp_code(resp: &str, expected: u16) -> anyhow::Result<()> {
    let code_str = resp.get(..3).unwrap_or("000");
    let code: u16 = code_str.parse().unwrap_or(0);
    if code == expected {
        Ok(())
    } else if code >= 400 {
        Err(anyhow!("SMTP error {code}: {}", resp.trim_end()))
    } else {
        Err(anyhow!(
            "Unexpected SMTP code {code} (expected {expected}): {}",
            resp.trim_end()
        ))
    }
}

fn build_transport(
    config: &RelayConfig,
) -> anyhow::Result<AsyncSmtpTransport<Tokio1Executor>> {
    let transport = if config.tls {
        let builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
            .map_err(|e| anyhow!("Failed to create TLS relay transport: {e}"))?
            .port(config.port);

        let builder = if let (Some(user), Some(pass)) = (&config.username, &config.password) {
            builder.credentials(Credentials::new(user.clone(), pass.clone()))
        } else {
            builder
        };

        builder.build()
    } else {
        let builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
            .port(config.port);

        let builder = if let (Some(user), Some(pass)) = (&config.username, &config.password) {
            builder.credentials(Credentials::new(user.clone(), pass.clone()))
        } else {
            builder
        };

        builder.build()
    };

    Ok(transport)
}

fn split_headers_body(raw: &str) -> (&str, &str) {
    if let Some(pos) = raw.find("\r\n\r\n") {
        return (&raw[..pos], &raw[pos + 4..]);
    }
    if let Some(pos) = raw.find("\n\n") {
        return (&raw[..pos], &raw[pos + 2..]);
    }
    (raw, "")
}

fn extract_header(headers: &str, name: &str) -> Option<String> {
    let name_lower = name.to_lowercase();
    for line in headers.lines() {
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_lowercase();
            if key == name_lower {
                return Some(line[colon_pos + 1..].trim().to_string());
            }
        }
    }
    None
}
