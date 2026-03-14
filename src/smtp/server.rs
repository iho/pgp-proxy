use crate::config::Config;
use crate::keys;
use crate::mailbox;
use crate::pgp_engine;
use crate::policy::{self, PolicyAction};
use crate::private_keys;
use crate::queue;
use crate::users;
use anyhow::Context;
use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct SmtpEnvelope {
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
}

#[derive(Debug, PartialEq)]
enum SmtpState {
    Init,
    Greeted,
    MailFrom,
    RcptTo,
    Data,
    Done,
}

// ── Public server entry points ────────────────────────────────────────────────

pub async fn run_smtp_server(
    config: Arc<Config>,
    pool: Arc<SqlitePool>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.smtp.listen_addr)
        .await
        .with_context(|| format!("Failed to bind SMTP on {}", config.smtp.listen_addr))?;

    info!("SMTP server listening on {}", config.smtp.listen_addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let config = Arc::clone(&config);
        let pool = Arc::clone(&pool);
        let tls = tls_acceptor.clone();

        tokio::spawn(async move {
            info!("New SMTP connection from {peer_addr}");
            if let Err(e) = handle_connection(stream, config, pool, tls).await {
                error!("SMTP connection error from {peer_addr}: {e}");
            }
        });
    }
}

pub async fn run_inbound_smtp_server(
    config: Arc<Config>,
    pool: Arc<SqlitePool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.inbound.listen_addr)
        .await
        .with_context(|| {
            format!(
                "Failed to bind inbound SMTP on {}",
                config.inbound.listen_addr
            )
        })?;

    info!(
        "Inbound SMTP server listening on {}",
        config.inbound.listen_addr
    );

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let config = Arc::clone(&config);
        let pool = Arc::clone(&pool);

        tokio::spawn(async move {
            info!("New inbound SMTP connection from {peer_addr}");
            if let Err(e) = handle_inbound_connection(stream, config, pool).await {
                error!("Inbound SMTP connection error from {peer_addr}: {e}");
            }
        });
    }
}

// ── Outbound submission handler (port 2587) ───────────────────────────────────

/// Handle a new connection on the submission port. Performs the greeting,
/// optional STARTTLS upgrade, then delegates to `smtp_submission_loop`.
async fn handle_connection(
    stream: TcpStream,
    config: Arc<Config>,
    pool: Arc<SqlitePool>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> anyhow::Result<()> {
    let has_tls = tls_acceptor.is_some();
    let (r, w) = tokio::io::split(stream);
    let mut reader = BufReader::new(r);
    let mut writer = w;

    write_smtp(
        &mut writer,
        &format!("220 {} ESMTP pgp-proxy ready\r\n", config.smtp.hostname),
    )
    .await?;

    // Wait for EHLO/HELO before advertising capabilities
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let trimmed = trim_crlf(&line);
        let upper = trimmed.to_uppercase();

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            let client = trimmed.splitn(2, ' ').nth(1).unwrap_or("unknown");
            info!("Submission EHLO from {client}");
            let resp = build_ehlo_response(&config.smtp.hostname, config.smtp.max_message_size, has_tls);
            write_smtp(&mut writer, &resp).await?;
            break;
        } else if upper == "QUIT" {
            write_smtp(&mut writer, "221 Bye\r\n").await?;
            return Ok(());
        } else {
            write_smtp(&mut writer, "503 5.5.2 Send EHLO first\r\n").await?;
        }
    }

    // If TLS is available, check whether the client wants to upgrade
    if let Some(ref acceptor) = tls_acceptor {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let trimmed = trim_crlf(&line);
        let upper = trimmed.to_uppercase();

        if upper == "STARTTLS" {
            write_smtp(&mut writer, "220 2.0.0 Ready to start TLS\r\n").await?;

            // Recombine the split halves to recover the TcpStream
            let tcp = reader.into_inner().unsplit(writer);

            let tls_stream = Arc::clone(acceptor)
                .accept(tcp)
                .await
                .context("TLS handshake on submission port failed")?;

            let (tr, tw) = tokio::io::split(tls_stream);
            let mut tls_reader = BufReader::new(tr);
            let mut tls_writer = tw;

            // Run the full session on the TLS stream; client will re-greet with EHLO
            return smtp_submission_loop(
                &mut tls_reader,
                &mut tls_writer,
                &config,
                &pool,
                None,
            )
            .await;
        } else {
            // Client skipped STARTTLS — feed the already-read line back as pending
            return smtp_submission_loop(
                &mut reader,
                &mut writer,
                &config,
                &pool,
                Some(trimmed),
            )
            .await;
        }
    }

    // No TLS configured: start session immediately (no pending command)
    smtp_submission_loop(&mut reader, &mut writer, &config, &pool, None).await
}

/// Build the EHLO multi-line response.
fn build_ehlo_response(hostname: &str, max_size: usize, offer_tls: bool) -> String {
    let mut s = format!("250-{hostname} pgp-proxy ready\r\n250-SIZE {max_size}\r\n");
    if offer_tls {
        s.push_str("250-STARTTLS\r\n");
    }
    s.push_str("250-AUTH PLAIN LOGIN\r\n250 ENHANCEDSTATUSCODES\r\n");
    s
}

/// The main SMTP session loop for the submission port. Works on any
/// `AsyncRead + AsyncWrite` pair (plain TCP or TLS).
///
/// `pending_line` is a command that was already read from the stream before
/// this function was called (e.g. when the client skipped STARTTLS).
async fn smtp_submission_loop<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    config: &Config,
    pool: &SqlitePool,
    pending_line: Option<String>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let mut state = SmtpState::Greeted;
    let mut envelope = SmtpEnvelope::default();
    let mut data_lines: Vec<String> = Vec::new();
    let mut authenticated = false;

    // Yield the pending command first (if any), then read from the stream
    let mut pending = pending_line;

    loop {
        let trimmed = if let Some(p) = pending.take() {
            p
        } else {
            let mut line = String::new();
            if reader.read_line(&mut line).await? == 0 {
                info!("Submission client disconnected");
                break;
            }
            trim_crlf(&line)
        };

        let upper = trimmed.to_uppercase();

        // ── DATA accumulation ────────────────────────────────────────────────
        if state == SmtpState::Data {
            if trimmed == "." {
                let raw_message = data_lines.join("\n");
                data_lines.clear();
                match process_message(&envelope, &raw_message, config, pool).await {
                    Ok(_) => {
                        write_smtp(writer, "250 2.0.0 OK: Message queued\r\n").await?;
                    }
                    Err(e) => {
                        error!("Failed to process message: {e}");
                        write_smtp(
                            writer,
                            &format!("554 5.3.0 Message processing failed: {e}\r\n"),
                        )
                        .await?;
                    }
                }
                envelope = SmtpEnvelope::default();
                state = SmtpState::Greeted;
                continue;
            }

            let content_line = if trimmed.starts_with("..") {
                trimmed[1..].to_string()
            } else {
                trimmed.clone()
            };
            data_lines.push(content_line);

            let total_size: usize = data_lines.iter().map(|l| l.len() + 1).sum();
            if total_size > config.smtp.max_message_size {
                write_smtp(writer, "552 5.3.4 Message too large\r\n").await?;
                state = SmtpState::Greeted;
                envelope = SmtpEnvelope::default();
                data_lines.clear();
            }
            continue;
        }

        // ── Commands ─────────────────────────────────────────────────────────
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            // Re-EHLO (common after TLS upgrade)
            let client = trimmed.splitn(2, ' ').nth(1).unwrap_or("unknown");
            // After STARTTLS, no longer advertise it
            let resp = build_ehlo_response(&config.smtp.hostname, config.smtp.max_message_size, false);
            write_smtp(writer, &resp).await?;
            info!("Re-EHLO from {client}");
            state = SmtpState::Greeted;
        } else if upper.starts_with("AUTH PLAIN") {
            let b64 = trimmed["AUTH PLAIN".len()..].trim().to_string();
            let b64 = if b64.is_empty() {
                // Two-step: send empty challenge, wait for credentials
                write_smtp(writer, "334 \r\n").await?;
                let mut cred_line = String::new();
                if reader.read_line(&mut cred_line).await? == 0 {
                    break;
                }
                trim_crlf(&cred_line)
            } else {
                b64
            };

            match verify_plain_auth(&b64, pool).await {
                Ok(true) => {
                    authenticated = true;
                    info!("AUTH PLAIN: authentication successful (auth={authenticated})");
                    write_smtp(writer, "235 2.7.0 Authentication successful\r\n").await?;
                }
                Ok(false) => {
                    write_smtp(
                        writer,
                        "535 5.7.8 Authentication credentials invalid\r\n",
                    )
                    .await?;
                }
                Err(e) => {
                    warn!("AUTH PLAIN error: {e}");
                    write_smtp(
                        writer,
                        "454 4.7.0 Temporary authentication failure\r\n",
                    )
                    .await?;
                }
            }
        } else if upper == "AUTH LOGIN" {
            // Step 1: username
            write_smtp(writer, "334 VXNlcm5hbWU6\r\n").await?; // "Username:" base64
            let mut u_line = String::new();
            if reader.read_line(&mut u_line).await? == 0 {
                break;
            }
            let username = decode_b64_str(trim_crlf(&u_line).as_str()).unwrap_or_default();

            // Step 2: password
            write_smtp(writer, "334 UGFzc3dvcmQ6\r\n").await?; // "Password:" base64
            let mut p_line = String::new();
            if reader.read_line(&mut p_line).await? == 0 {
                break;
            }
            let password = decode_b64_str(trim_crlf(&p_line).as_str()).unwrap_or_default();

            match users::verify_user(pool, &username, &password).await {
                Ok(true) => {
                    authenticated = true;
                    info!("AUTH LOGIN: {username} authenticated");
                    write_smtp(writer, "235 2.7.0 Authentication successful\r\n").await?;
                }
                Ok(false) => {
                    write_smtp(
                        writer,
                        "535 5.7.8 Authentication credentials invalid\r\n",
                    )
                    .await?;
                }
                Err(e) => {
                    warn!("AUTH LOGIN error: {e}");
                    write_smtp(
                        writer,
                        "454 4.7.0 Temporary authentication failure\r\n",
                    )
                    .await?;
                }
            }
        } else if upper.starts_with("MAIL FROM:") {
            if state != SmtpState::Greeted && state != SmtpState::Done {
                write_smtp(writer, "503 5.5.1 Bad sequence of commands\r\n").await?;
                continue;
            }
            let addr = extract_address(&trimmed[10..]);
            info!("MAIL FROM: {addr} (auth={authenticated})");
            envelope.mail_from = addr;
            envelope.rcpt_to.clear();
            state = SmtpState::MailFrom;
            write_smtp(writer, "250 2.1.0 OK\r\n").await?;
        } else if upper.starts_with("RCPT TO:") {
            if state != SmtpState::MailFrom && state != SmtpState::RcptTo {
                write_smtp(writer, "503 5.5.1 Bad sequence of commands\r\n").await?;
                continue;
            }
            let addr = extract_address(&trimmed[8..]);
            info!("RCPT TO: {addr}");
            envelope.rcpt_to.push(addr);
            state = SmtpState::RcptTo;
            write_smtp(writer, "250 2.1.5 OK\r\n").await?;
        } else if upper == "DATA" {
            if state != SmtpState::RcptTo {
                write_smtp(writer, "503 5.5.1 Bad sequence of commands\r\n").await?;
                continue;
            }
            if envelope.rcpt_to.is_empty() {
                write_smtp(writer, "503 5.5.1 No recipients\r\n").await?;
                continue;
            }
            state = SmtpState::Data;
            data_lines.clear();
            write_smtp(writer, "354 End data with <CR><LF>.<CR><LF>\r\n").await?;
        } else if upper == "RSET" {
            envelope = SmtpEnvelope::default();
            data_lines.clear();
            state = if state == SmtpState::Init {
                SmtpState::Init
            } else {
                SmtpState::Greeted
            };
            write_smtp(writer, "250 2.0.0 OK\r\n").await?;
        } else if upper == "NOOP" {
            write_smtp(writer, "250 2.0.0 OK\r\n").await?;
        } else if upper == "QUIT" {
            write_smtp(writer, "221 2.0.0 Bye\r\n").await?;
            break;
        } else if upper == "STARTTLS" {
            // Client sent STARTTLS but we're already past the upgrade point
            write_smtp(writer, "454 4.7.0 TLS not available on this connection\r\n").await?;
        } else {
            write_smtp(writer, "500 5.5.2 Unknown command\r\n").await?;
        }
    }

    let _ = authenticated; // suppress unused-variable warning if no enforcement is needed
    Ok(())
}

// ── Inbound SMTP handler (port 2525) ─────────────────────────────────────────

async fn handle_inbound_connection(
    stream: TcpStream,
    config: Arc<Config>,
    pool: Arc<SqlitePool>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    write_smtp(
        &mut writer,
        &format!("220 {} ESMTP pgp-proxy ready\r\n", config.smtp.hostname),
    )
    .await?;

    let mut state = SmtpState::Init;
    let mut envelope = SmtpEnvelope::default();
    let mut data_lines: Vec<String> = Vec::new();
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            info!("Inbound client disconnected");
            break;
        }

        let trimmed = trim_crlf(&line);
        let upper = trimmed.to_uppercase();

        if state == SmtpState::Data {
            if trimmed == "." {
                let raw_message = data_lines.join("\n");
                data_lines.clear();

                match process_inbound_message(&envelope, &raw_message, &config, &pool).await {
                    Ok(_) => {
                        write_smtp(&mut writer, "250 OK: Message accepted\r\n").await?;
                    }
                    Err(e) => {
                        error!("Failed to process inbound message: {e}");
                        write_smtp(
                            &mut writer,
                            &format!("554 Message processing failed: {e}\r\n"),
                        )
                        .await?;
                    }
                }

                envelope = SmtpEnvelope::default();
                state = SmtpState::Greeted;
                continue;
            }

            let content_line = if trimmed.starts_with("..") {
                trimmed[1..].to_string()
            } else {
                trimmed.clone()
            };
            data_lines.push(content_line);

            let total_size: usize = data_lines.iter().map(|l| l.len() + 1).sum();
            if total_size > config.smtp.max_message_size {
                write_smtp(&mut writer, "552 Message too large\r\n").await?;
                state = SmtpState::Greeted;
                envelope = SmtpEnvelope::default();
                data_lines.clear();
            }

            continue;
        }

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            let hostname = trimmed.splitn(2, ' ').nth(1).unwrap_or("unknown");
            info!("Inbound EHLO/HELO from {hostname}");
            write_smtp(
                &mut writer,
                &format!(
                    "250-{} Hello {hostname}\r\n250-SIZE {}\r\n250 ENHANCEDSTATUSCODES\r\n",
                    config.smtp.hostname, config.smtp.max_message_size
                ),
            )
            .await?;
            state = SmtpState::Greeted;
        } else if upper.starts_with("MAIL FROM:") {
            if state != SmtpState::Greeted && state != SmtpState::Done {
                write_smtp(&mut writer, "503 Bad sequence of commands\r\n").await?;
                continue;
            }
            let addr = extract_address(&trimmed[10..]);
            envelope.mail_from = addr;
            envelope.rcpt_to.clear();
            state = SmtpState::MailFrom;
            write_smtp(&mut writer, "250 OK\r\n").await?;
        } else if upper.starts_with("RCPT TO:") {
            if state != SmtpState::MailFrom && state != SmtpState::RcptTo {
                write_smtp(&mut writer, "503 Bad sequence of commands\r\n").await?;
                continue;
            }
            let addr = extract_address(&trimmed[8..]);

            let accept = if config.inbound.local_domains.is_empty() {
                true
            } else {
                let domain = addr.split('@').nth(1).unwrap_or("").to_lowercase();
                config
                    .inbound
                    .local_domains
                    .iter()
                    .any(|d| d.to_lowercase() == domain)
            };

            if !accept {
                write_smtp(&mut writer, "550 Relay not permitted\r\n").await?;
                continue;
            }

            envelope.rcpt_to.push(addr);
            state = SmtpState::RcptTo;
            write_smtp(&mut writer, "250 OK\r\n").await?;
        } else if upper == "DATA" {
            if state != SmtpState::RcptTo {
                write_smtp(&mut writer, "503 Bad sequence of commands\r\n").await?;
                continue;
            }
            if envelope.rcpt_to.is_empty() {
                write_smtp(&mut writer, "503 No recipients\r\n").await?;
                continue;
            }
            state = SmtpState::Data;
            data_lines.clear();
            write_smtp(&mut writer, "354 End data with <CR><LF>.<CR><LF>\r\n").await?;
        } else if upper == "RSET" {
            envelope = SmtpEnvelope::default();
            data_lines.clear();
            state = if state == SmtpState::Init {
                SmtpState::Init
            } else {
                SmtpState::Greeted
            };
            write_smtp(&mut writer, "250 OK\r\n").await?;
        } else if upper == "NOOP" {
            write_smtp(&mut writer, "250 OK\r\n").await?;
        } else if upper == "QUIT" {
            write_smtp(&mut writer, "221 Bye\r\n").await?;
            break;
        } else if upper.starts_with("STARTTLS") {
            write_smtp(&mut writer, "454 TLS not available\r\n").await?;
        } else {
            write_smtp(&mut writer, "500 Unknown command\r\n").await?;
        }
    }

    Ok(())
}

// ── Message processing ────────────────────────────────────────────────────────

async fn process_message(
    envelope: &SmtpEnvelope,
    raw_message: &str,
    _config: &Config,
    pool: &SqlitePool,
) -> anyhow::Result<()> {
    let message_id = Uuid::new_v4().to_string();
    let now_str = Utc::now().to_rfc3339();
    let sender = &envelope.mail_from;

    let mut relay_errors: Vec<String> = Vec::new();

    for recipient in &envelope.rcpt_to {
        let policy = policy::evaluate(pool, sender, recipient).await?;

        let (final_message, policy_desc) = match &policy {
            None => {
                info!("No policy for {sender} -> {recipient}, sending plain");
                (raw_message.to_string(), "none".to_string())
            }
            Some(p) => {
                let action = PolicyAction::from_str(&p.action);
                info!(
                    "Applying policy '{}' for {sender} -> {recipient}",
                    p.action
                );

                match action {
                    PolicyAction::None => (raw_message.to_string(), p.action.clone()),
                    PolicyAction::Encrypt | PolicyAction::EncryptSign => {
                        match keys::get_key(pool, recipient).await? {
                            None => {
                                if p.on_missing_key == "reject" {
                                    let err = format!(
                                        "No PGP key for recipient {recipient}, rejecting per policy"
                                    );
                                    warn!("{err}");
                                    relay_errors.push(err);
                                    continue;
                                } else {
                                    warn!("No PGP key for {recipient}, sending plain per policy");
                                    (
                                        raw_message.to_string(),
                                        format!("{} (no key, sent plain)", p.action),
                                    )
                                }
                            }
                            Some(key) => {
                                let body = extract_body(raw_message);
                                match pgp_engine::encrypt_message(body, &key.public_key_armor) {
                                    Ok(encrypted) => {
                                        let new_msg = replace_body(raw_message, &encrypted);
                                        (new_msg, p.action.clone())
                                    }
                                    Err(e) => {
                                        warn!("PGP encrypt failed for {recipient}: {e}");
                                        if p.on_missing_key == "reject" {
                                            relay_errors
                                                .push(format!("Encryption failed: {e}"));
                                            continue;
                                        }
                                        (
                                            raw_message.to_string(),
                                            format!("{} (encrypt failed, sent plain)", p.action),
                                        )
                                    }
                                }
                            }
                        }
                    }
                    PolicyAction::Sign => {
                        warn!("Sign action not yet supported, sending plain");
                        (
                            raw_message.to_string(),
                            "sign (unsupported, sent plain)".to_string(),
                        )
                    }
                }
            }
        };

        match queue::enqueue(pool, &message_id, sender, recipient, &final_message).await {
            Ok(queue_id) => {
                info!("Queued message {message_id} for {recipient} (queue entry {queue_id})");
                if let Err(e) = log_smtp(
                    pool,
                    &message_id,
                    sender,
                    recipient,
                    Some(&policy_desc),
                    "queued",
                    None,
                    &now_str,
                )
                .await
                {
                    warn!("Failed to write smtp log: {e}");
                }
            }
            Err(e) => {
                error!("Failed to enqueue message for {recipient}: {e}");
                let err_str = e.to_string();
                if let Err(le) = log_smtp(
                    pool,
                    &message_id,
                    sender,
                    recipient,
                    Some(&policy_desc),
                    "enqueue_failed",
                    Some(&err_str),
                    &now_str,
                )
                .await
                {
                    warn!("Failed to write smtp log: {le}");
                }
                relay_errors.push(format!("Enqueue failed for {recipient}: {e}"));
            }
        }
    }

    if !relay_errors.is_empty() {
        anyhow::bail!("Some recipients failed: {}", relay_errors.join("; "));
    }

    Ok(())
}

async fn process_inbound_message(
    envelope: &SmtpEnvelope,
    raw_message: &str,
    _config: &Config,
    pool: &SqlitePool,
) -> anyhow::Result<()> {
    let sender = &envelope.mail_from;
    let subject = extract_header_from_raw(raw_message, "Subject")
        .unwrap_or_else(|| String::from("(no subject)"));

    for recipient in &envelope.rcpt_to {
        let is_pgp = raw_message.contains("BEGIN PGP MESSAGE")
            || raw_message
                .to_lowercase()
                .contains("content-type: multipart/encrypted");

        let final_message = if is_pgp {
            match private_keys::get_private_key(pool, recipient).await {
                Ok(Some(privkey)) => {
                    let body = extract_body(raw_message);
                    match pgp_engine::decrypt_message(
                        body,
                        &privkey.private_key_armor,
                        &privkey.passphrase,
                    ) {
                        Ok(plaintext) => {
                            info!("Decrypted PGP message for {recipient}");
                            replace_body(raw_message, &plaintext)
                        }
                        Err(e) => {
                            warn!("PGP decryption failed for {recipient}: {e}, storing encrypted");
                            raw_message.to_string()
                        }
                    }
                }
                Ok(None) => {
                    warn!("No private key for {recipient}, storing encrypted message");
                    raw_message.to_string()
                }
                Err(e) => {
                    warn!("Error looking up private key for {recipient}: {e}");
                    raw_message.to_string()
                }
            }
        } else {
            raw_message.to_string()
        };

        match mailbox::store_message(pool, recipient, sender, &subject, &final_message).await {
            Ok(id) => {
                info!("Stored inbound message {id} for {recipient}");
            }
            Err(e) => {
                error!("Failed to store message for {recipient}: {e}");
                return Err(e);
            }
        }
    }

    Ok(())
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

/// Verify AUTH PLAIN credentials. The base64 payload encodes
/// `[authzid]\0username\0password`.
async fn verify_plain_auth(b64: &str, pool: &SqlitePool) -> anyhow::Result<bool> {
    let decoded = general_purpose::STANDARD
        .decode(b64.trim())
        .context("Invalid base64 in AUTH PLAIN")?;
    let parts: Vec<&[u8]> = decoded.splitn(3, |&b| b == 0).collect();
    if parts.len() < 3 {
        return Ok(false);
    }
    let username = std::str::from_utf8(parts[1]).unwrap_or("");
    let password = std::str::from_utf8(parts[2]).unwrap_or("");
    users::verify_user(pool, username, password).await
}

fn decode_b64_str(s: &str) -> Option<String> {
    let bytes = general_purpose::STANDARD.decode(s.trim()).ok()?;
    String::from_utf8(bytes).ok()
}

// ── DB helpers ────────────────────────────────────────────────────────────────

async fn log_smtp(
    pool: &SqlitePool,
    message_id: &str,
    sender: &str,
    recipients: &str,
    applied_policy: Option<&str>,
    status: &str,
    error: Option<&str>,
    created_at: &str,
) -> anyhow::Result<()> {
    let log_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO smtp_logs (id, message_id, sender, recipients, applied_policy, status, error, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&log_id)
    .bind(message_id)
    .bind(sender)
    .bind(recipients)
    .bind(applied_policy)
    .bind(status)
    .bind(error)
    .bind(created_at)
    .execute(pool)
    .await
    .context("Failed to write smtp log")?;
    Ok(())
}

// ── IO helpers ────────────────────────────────────────────────────────────────

async fn write_smtp<W: AsyncWrite + Unpin>(writer: &mut W, line: &str) -> anyhow::Result<()> {
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

fn trim_crlf(s: &str) -> String {
    s.trim_end_matches(|c| c == '\r' || c == '\n').to_string()
}

fn extract_address(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('<') && s.ends_with('>') {
        s[1..s.len() - 1].to_string()
    } else {
        s.split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(['<', '>'])
            .to_string()
    }
}

fn extract_body(raw: &str) -> &str {
    if let Some(pos) = raw.find("\r\n\r\n") {
        return &raw[pos + 4..];
    }
    if let Some(pos) = raw.find("\n\n") {
        return &raw[pos + 2..];
    }
    raw
}

fn replace_body(raw: &str, new_body: &str) -> String {
    if let Some(pos) = raw.find("\r\n\r\n") {
        return format!("{}\r\n\r\n{}", &raw[..pos], new_body);
    }
    if let Some(pos) = raw.find("\n\n") {
        return format!("{}\n\n{}", &raw[..pos], new_body);
    }
    new_body.to_string()
}

fn extract_header_from_raw(raw: &str, name: &str) -> Option<String> {
    let (headers, _) = split_headers_body(raw);
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

fn split_headers_body(raw: &str) -> (&str, &str) {
    if let Some(pos) = raw.find("\r\n\r\n") {
        return (&raw[..pos], &raw[pos + 4..]);
    }
    if let Some(pos) = raw.find("\n\n") {
        return (&raw[..pos], &raw[pos + 2..]);
    }
    (raw, "")
}
