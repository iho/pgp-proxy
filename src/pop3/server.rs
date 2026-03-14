use crate::config::Config;
use crate::mailbox::{self, MailMessage};
use crate::users;
use anyhow::Context;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

pub async fn run_pop3_server(
    config: Arc<Config>,
    pool: Arc<SqlitePool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.pop3.listen_addr)
        .await
        .with_context(|| format!("Failed to bind POP3 on {}", config.pop3.listen_addr))?;

    info!("POP3 server listening on {}", config.pop3.listen_addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let pool = Arc::clone(&pool);

        tokio::spawn(async move {
            info!("New POP3 connection from {peer_addr}");
            if let Err(e) = handle_pop3_connection(stream, pool).await {
                error!("POP3 connection error from {peer_addr}: {e}");
            }
        });
    }
}

#[derive(Debug, PartialEq)]
enum Pop3State {
    Authorization,
    Transaction,
}

struct SessionMessage {
    message: MailMessage,
    deleted: bool,
}

async fn handle_pop3_connection(
    stream: TcpStream,
    pool: Arc<SqlitePool>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    write_pop3(&mut writer, "+OK PGP-Proxy POP3 server ready\r\n").await?;

    let mut state = Pop3State::Authorization;
    let mut username: Option<String> = None;
    let mut authenticated_user: Option<String> = None;
    let mut session_messages: Vec<SessionMessage> = Vec::new();
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            info!("POP3 client disconnected");
            break;
        }

        let trimmed = line.trim_end_matches(|c| c == '\r' || c == '\n').to_string();
        let upper = trimmed.to_uppercase();
        let cmd = upper.split_whitespace().next().unwrap_or("");
        let arg = trimmed.splitn(2, ' ').nth(1).unwrap_or("").trim().to_string();

        match state {
            Pop3State::Authorization => match cmd {
                "USER" => {
                    if arg.is_empty() {
                        write_pop3(&mut writer, "-ERR Missing username\r\n").await?;
                    } else {
                        username = Some(arg.clone());
                        write_pop3(&mut writer, "+OK\r\n").await?;
                    }
                }
                "PASS" => {
                    if let Some(ref user) = username {
                        let ok = users::verify_user(pool.as_ref(), user, &arg)
                            .await
                            .unwrap_or(false);
                        if ok {
                            info!("POP3 login success for {user}");
                            // Load messages into session
                            let msgs = mailbox::list_messages(pool.as_ref(), user)
                                .await
                                .unwrap_or_default();
                            session_messages = msgs
                                .into_iter()
                                .map(|m| SessionMessage {
                                    message: m,
                                    deleted: false,
                                })
                                .collect();
                            authenticated_user = username.take();
                            state = Pop3State::Transaction;
                            write_pop3(&mut writer, "+OK Logged in\r\n").await?;
                        } else {
                            write_pop3(&mut writer, "-ERR Invalid credentials\r\n").await?;
                        }
                    } else {
                        write_pop3(&mut writer, "-ERR USER first\r\n").await?;
                    }
                }
                "QUIT" => {
                    write_pop3(&mut writer, "+OK Bye\r\n").await?;
                    break;
                }
                _ => {
                    write_pop3(&mut writer, "-ERR Unknown command\r\n").await?;
                }
            },

            Pop3State::Transaction => match cmd {
                "STAT" => {
                    let count = session_messages.iter().filter(|m| !m.deleted).count();
                    let total_size: usize = session_messages
                        .iter()
                        .filter(|m| !m.deleted)
                        .map(|m| m.message.raw_message.len())
                        .sum();
                    let resp = format!("+OK {count} {total_size}\r\n");
                    write_pop3(&mut writer, &resp).await?;
                }
                "LIST" => {
                    if arg.is_empty() {
                        let count = session_messages.iter().filter(|m| !m.deleted).count();
                        let total_size: usize = session_messages
                            .iter()
                            .filter(|m| !m.deleted)
                            .map(|m| m.message.raw_message.len())
                            .sum();
                        let header = format!("+OK {count} messages ({total_size} octets)\r\n");
                        write_pop3(&mut writer, &header).await?;
                        for (i, sm) in session_messages.iter().enumerate() {
                            if !sm.deleted {
                                let entry =
                                    format!("{} {}\r\n", i + 1, sm.message.raw_message.len());
                                write_pop3(&mut writer, &entry).await?;
                            }
                        }
                        write_pop3(&mut writer, ".\r\n").await?;
                    } else {
                        match parse_msg_num(&arg, &session_messages) {
                            Some(idx) => {
                                let size = session_messages[idx].message.raw_message.len();
                                let resp = format!("+OK {} {size}\r\n", idx + 1);
                                write_pop3(&mut writer, &resp).await?;
                            }
                            None => {
                                write_pop3(&mut writer, "-ERR No such message\r\n").await?;
                            }
                        }
                    }
                }
                "RETR" => {
                    match parse_msg_num(&arg, &session_messages) {
                        Some(idx) => {
                            let size = session_messages[idx].message.raw_message.len();
                            let header = format!("+OK {size} octets\r\n");
                            write_pop3(&mut writer, &header).await?;
                            // Dot-stuff the message body per RFC 1939
                            let msg_body = &session_messages[idx].message.raw_message;
                            for msg_line in msg_body.lines() {
                                if msg_line.starts_with('.') {
                                    write_pop3(&mut writer, ".").await?;
                                }
                                write_pop3(&mut writer, msg_line).await?;
                                write_pop3(&mut writer, "\r\n").await?;
                            }
                            write_pop3(&mut writer, ".\r\n").await?;
                            // Mark as read in DB (best-effort)
                            let msg_id = session_messages[idx].message.id.clone();
                            let _ = mailbox::mark_read(pool.as_ref(), &msg_id).await;
                        }
                        None => {
                            write_pop3(&mut writer, "-ERR No such message\r\n").await?;
                        }
                    }
                }
                "DELE" => {
                    match parse_msg_num(&arg, &session_messages) {
                        Some(idx) => {
                            session_messages[idx].deleted = true;
                            let resp = format!("+OK Message {} deleted\r\n", idx + 1);
                            write_pop3(&mut writer, &resp).await?;
                        }
                        None => {
                            write_pop3(&mut writer, "-ERR No such message\r\n").await?;
                        }
                    }
                }
                "NOOP" => {
                    write_pop3(&mut writer, "+OK\r\n").await?;
                }
                "RSET" => {
                    for sm in session_messages.iter_mut() {
                        sm.deleted = false;
                    }
                    write_pop3(&mut writer, "+OK\r\n").await?;
                }
                "UIDL" => {
                    if arg.is_empty() {
                        write_pop3(&mut writer, "+OK\r\n").await?;
                        for (i, sm) in session_messages.iter().enumerate() {
                            if !sm.deleted {
                                let entry = format!("{} {}\r\n", i + 1, sm.message.id);
                                write_pop3(&mut writer, &entry).await?;
                            }
                        }
                        write_pop3(&mut writer, ".\r\n").await?;
                    } else {
                        match parse_msg_num(&arg, &session_messages) {
                            Some(idx) => {
                                let resp =
                                    format!("+OK {} {}\r\n", idx + 1, session_messages[idx].message.id);
                                write_pop3(&mut writer, &resp).await?;
                            }
                            None => {
                                write_pop3(&mut writer, "-ERR No such message\r\n").await?;
                            }
                        }
                    }
                }
                "QUIT" => {
                    // Expunge messages marked deleted
                    if let Some(ref user) = authenticated_user {
                        // Perform DB deletions for messages marked deleted in session
                        for sm in &session_messages {
                            if sm.deleted {
                                let _ =
                                    mailbox::mark_deleted(pool.as_ref(), &sm.message.id).await;
                            }
                        }
                        let _ = mailbox::expunge(pool.as_ref(), user).await;
                    }
                    write_pop3(&mut writer, "+OK Bye\r\n").await?;
                    break;
                }
                _ => {
                    write_pop3(&mut writer, "-ERR Unknown command\r\n").await?;
                }
            },
        }
    }

    Ok(())
}

async fn write_pop3<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &str,
) -> anyhow::Result<()> {
    writer.write_all(data.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Parse a 1-based message number from the argument and return the 0-based index.
/// Returns None if the number is invalid, out of range, or the message is deleted.
fn parse_msg_num(arg: &str, messages: &[SessionMessage]) -> Option<usize> {
    let n: usize = arg.trim().parse().ok()?;
    if n == 0 || n > messages.len() {
        return None;
    }
    let idx = n - 1;
    if messages[idx].deleted {
        return None;
    }
    Some(idx)
}
