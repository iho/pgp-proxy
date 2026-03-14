use crate::config::Config;
use crate::keys::KeyRecord;
use crate::mailbox::MailMessage;
use crate::policy::PolicyRecord;
use crate::private_keys::PrivateKeyRecord;
use crate::queue::QueueEntry;
use maud::{html, Markup, PreEscaped, DOCTYPE};

// ── Shared data types ──────────────────────────────────────────────────────────

pub struct DashboardStats {
    pub total_keys: i64,
    pub total_policies: i64,
    pub recent_logs: Vec<LogRecord>,
}

#[derive(Debug, Clone)]
pub struct LogRecord {
    #[allow(dead_code)]
    pub id: String,
    pub message_id: String,
    pub sender: String,
    pub recipients: String,
    pub applied_policy: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub created_at: String,
}

// ── Design system helpers ──────────────────────────────────────────────────────

fn status_badge(status: &str) -> Markup {
    let cls = match status {
        "sent" | "delivered" => "badge badge-success",
        "queued" | "pending" => "badge badge-warning",
        "failed" | "enqueue_failed" => "badge badge-danger",
        _ => "badge badge-muted",
    };
    html! { span class=(cls) { (status) } }
}

fn action_badge(action: &str) -> Markup {
    let cls = match action {
        "encrypt" => "badge badge-info",
        "sign" => "badge badge-primary",
        "encrypt_sign" => "badge badge-success",
        _ => "badge badge-muted",
    };
    html! { span class=(cls) { (action) } }
}

fn missing_key_badge(val: &str) -> Markup {
    let cls = if val == "reject" { "badge badge-danger" } else { "badge badge-warning" };
    html! { span class=(cls) { (val) } }
}

fn delete_btn(url: &str, confirm: &str) -> Markup {
    html! {
        button class="btn btn-danger btn-sm"
            hx-delete=(url)
            hx-confirm=(confirm)
            hx-target="closest tr"
            hx-swap="outerHTML"
        { "Delete" }
    }
}

// ── Layout ─────────────────────────────────────────────────────────────────────

fn layout(title: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="UTF-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { (title) " — PGP Proxy" }
                link rel="preconnect" href="https://fonts.googleapis.com";
                link rel="preconnect" href="https://fonts.gstatic.com" crossorigin;
                link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet";
                script src="https://unpkg.com/htmx.org@1.9.10" {}
                style { (PreEscaped(CSS)) }
            }
            body {
                nav class="site-nav" {
                    div class="nav-inner" {
                        a class="nav-brand" href="/" { "PGP Proxy" }
                        div class="nav-links" {
                            a class="nav-link" href="/" { "Dashboard" }
                            a class="nav-link" href="/keys" { "Keys" }
                            a class="nav-link" href="/private-keys" { "Private Keys" }
                            a class="nav-link" href="/policies" { "Policies" }
                            a class="nav-link" href="/users" { "Users" }
                            a class="nav-link" href="/mailbox" { "Mailbox" }
                            a class="nav-link" href="/queue" { "Queue" }
                            a class="nav-link" href="/logs" { "Logs" }
                            a class="nav-link" href="/config" { "Config" }
                        }
                    }
                }
                main class="main-content" { (content) }
            }
        }
    }
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

pub fn dashboard_page(stats: &DashboardStats) -> Markup {
    let content = html! {
        div class="page-header" {
            h1 class="page-title" { "Dashboard" }
        }
        div class="stat-grid" {
            div class="card" {
                p class="card-label" { "Public Keys" }
                p class="card-value" { (stats.total_keys) }
                a class="card-link" href="/keys" { "Manage →" }
            }
            div class="card" {
                p class="card-label" { "Policies" }
                p class="card-value" { (stats.total_policies) }
                a class="card-link" href="/policies" { "Manage →" }
            }
            div class="card" {
                p class="card-label" { "Recent Events" }
                p class="card-value" { (stats.recent_logs.len()) }
                a class="card-link" href="/logs" { "View logs →" }
            }
        }
        h4 class="section-heading" { "Recent Activity" }
        div class="table-wrap" {
            (logs_table_inner(&stats.recent_logs))
        }
    };
    layout("Dashboard", content)
}

// ── Keys ──────────────────────────────────────────────────────────────────────

pub fn keys_table(keys: &[KeyRecord]) -> Markup {
    html! {
        div class="table-wrap" id="keys-table" {
            table {
                thead {
                    tr {
                        th { "Email" }
                        th { "Fingerprint" }
                        th { "Public Key" }
                        th { "Added" }
                        th { "" }
                    }
                }
                tbody {
                    @for k in keys {
                        tr {
                            td { (k.email) }
                            td { code { (k.fingerprint) } }
                            td { div class="armor-preview" { (k.public_key_armor) } }
                            td { small { (k.created_at.format("%Y-%m-%d %H:%M").to_string()) " UTC" } }
                            td { (delete_btn(&format!("/keys/{}", k.id), &format!("Delete key for {}?", k.email))) }
                        }
                    }
                    @if keys.is_empty() {
                        tr { td colspan="5" class="empty-row" { "No keys yet." } }
                    }
                }
            }
        }
    }
}

pub fn keys_page(keys: &[KeyRecord]) -> Markup {
    let content = html! {
        div class="page-header" {
            h1 class="page-title" { "Public Keys" }
        }
        div class="form-card" {
            div class="form-card-header" { "Add Recipient Key" }
            div class="form-card-body" {
                form hx-post="/keys"
                     hx-target="#keys-table"
                     hx-swap="outerHTML"
                     "hx-on::after-request"="this.reset()"
                {
                    div class="form-row" {
                        div class="form-group" {
                            label for="email" { "Email Address" }
                            input type="email" id="email" name="email"
                                  placeholder="alice@example.com" required;
                        }
                    }
                    div class="form-group full" style="margin-top:1rem" {
                        label for="armor" { "PGP Public Key (ASCII Armor)" }
                        textarea id="armor" name="armor" rows="7"
                                 placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----"
                                 required {}
                    }
                    div style="margin-top:1rem" {
                        button type="submit" class="btn btn-primary" { "Add Key" }
                    }
                }
            }
        }
        (keys_table(keys))
    };
    layout("Public Keys", content)
}

// ── Private Keys ──────────────────────────────────────────────────────────────

pub fn private_keys_table(keys: &[PrivateKeyRecord]) -> Markup {
    html! {
        div class="table-wrap" id="private-keys-table" {
            table {
                thead {
                    tr {
                        th { "Email" }
                        th { "Fingerprint" }
                        th { "Added" }
                        th { "" }
                    }
                }
                tbody {
                    @for k in keys {
                        tr {
                            td { (k.email) }
                            td { code { (k.fingerprint) } }
                            td { small { (k.created_at) } }
                            td { (delete_btn(&format!("/private-keys/{}", k.id), &format!("Delete private key for {}?", k.email))) }
                        }
                    }
                    @if keys.is_empty() {
                        tr { td colspan="4" class="empty-row" { "No private keys yet." } }
                    }
                }
            }
        }
    }
}

pub fn private_keys_page(keys: &[PrivateKeyRecord]) -> Markup {
    let content = html! {
        div class="page-header" {
            h1 class="page-title" { "Private Keys" }
        }
        div class="alert alert-warning" {
            "Private keys are used to decrypt inbound PGP-encrypted messages. "
            "Passphrases are stored in the database — use this only on a trusted, secured host."
        }
        div class="form-card" {
            div class="form-card-header" { "Upload Private Key" }
            div class="form-card-body" {
                form hx-post="/private-keys"
                     hx-target="#private-keys-table"
                     hx-swap="outerHTML"
                     "hx-on::after-request"="this.reset()"
                {
                    div class="form-row" {
                        div class="form-group" {
                            label for="email" { "Email Address" }
                            input type="email" id="email" name="email"
                                  placeholder="alice@example.com" required;
                        }
                        div class="form-group" {
                            label for="passphrase" { "Passphrase (leave blank if none)" }
                            input type="password" id="passphrase" name="passphrase";
                        }
                    }
                    div class="form-group full" style="margin-top:1rem" {
                        label for="armor" { "PGP Private Key (ASCII Armor)" }
                        textarea id="armor" name="armor" rows="7"
                                 placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----\n...\n-----END PGP PRIVATE KEY BLOCK-----"
                                 required {}
                    }
                    div style="margin-top:1rem" {
                        button type="submit" class="btn btn-primary" { "Upload Key" }
                    }
                }
            }
        }
        (private_keys_table(keys))
    };
    layout("Private Keys", content)
}

// ── Policies ──────────────────────────────────────────────────────────────────

pub fn policies_table(policies: &[PolicyRecord]) -> Markup {
    html! {
        div class="table-wrap" id="policies-table" {
            table {
                thead {
                    tr {
                        th { "Priority" }
                        th { "Sender" }
                        th { "Recipient" }
                        th { "Action" }
                        th { "On Missing Key" }
                        th { "Created" }
                        th { "" }
                    }
                }
                tbody {
                    @for p in policies {
                        tr {
                            td { (p.priority) }
                            td { code { (p.sender_pattern) } }
                            td { code { (p.recipient_pattern) } }
                            td { (action_badge(&p.action)) }
                            td { (missing_key_badge(&p.on_missing_key)) }
                            td { small { (p.created_at.format("%Y-%m-%d %H:%M").to_string()) " UTC" } }
                            td { (delete_btn(&format!("/policies/{}", p.id), "Delete this policy?")) }
                        }
                    }
                    @if policies.is_empty() {
                        tr { td colspan="7" class="empty-row" { "No policies yet. Without a policy all mail is sent plain." } }
                    }
                }
            }
        }
    }
}

pub fn policies_page(policies: &[PolicyRecord]) -> Markup {
    let content = html! {
        div class="page-header" {
            h1 class="page-title" { "Policies" }
        }
        div class="form-card" {
            div class="form-card-header" { "Add Policy" }
            div class="form-card-body" {
                form hx-post="/policies"
                     hx-target="#policies-table"
                     hx-swap="outerHTML"
                     "hx-on::after-request"="this.reset()"
                {
                    div class="form-row" {
                        div class="form-group" {
                            label for="priority" { "Priority" }
                            input type="number" id="priority" name="priority"
                                  value="100" min="0" required;
                            p class="form-hint" { "Lower = evaluated first" }
                        }
                        div class="form-group" {
                            label for="sender_pattern" { "Sender Pattern" }
                            input type="text" id="sender_pattern" name="sender_pattern"
                                  placeholder="* or user@domain.com or *@domain.com" required;
                        }
                        div class="form-group" {
                            label for="recipient_pattern" { "Recipient Pattern" }
                            input type="text" id="recipient_pattern" name="recipient_pattern"
                                  placeholder="* or user@domain.com or *@domain.com" required;
                        }
                        div class="form-group" {
                            label for="action" { "Action" }
                            select id="action" name="action" required {
                                option value="encrypt"      { "Encrypt" }
                                option value="sign"         { "Sign" }
                                option value="encrypt_sign" { "Encrypt + Sign" }
                                option value="none"         { "None (pass through)" }
                            }
                        }
                        div class="form-group" {
                            label for="on_missing_key" { "On Missing Key" }
                            select id="on_missing_key" name="on_missing_key" required {
                                option value="send_plain" { "Send plain" }
                                option value="reject"     { "Reject" }
                            }
                        }
                        div class="form-group" style="justify-content:flex-end" {
                            button type="submit" class="btn btn-primary" { "Add Policy" }
                        }
                    }
                }
            }
        }
        (policies_table(policies))
    };
    layout("Policies", content)
}

// ── Logs ──────────────────────────────────────────────────────────────────────

fn logs_table_inner(logs: &[LogRecord]) -> Markup {
    html! {
        table id="logs-table"
              hx-get="/logs/partial"
              hx-trigger="every 5s"
              hx-target="#logs-table"
              hx-swap="outerHTML"
        {
            thead {
                tr {
                    th { "Message ID" }
                    th { "Sender" }
                    th { "Recipients" }
                    th { "Policy" }
                    th { "Status" }
                    th { "Error" }
                    th { "Time" }
                }
            }
            tbody {
                @for log in logs {
                    tr {
                        td { small { code { (log.message_id.get(..8).unwrap_or(&log.message_id)) "…" } } }
                        td { (log.sender) }
                        td { small { (log.recipients) } }
                        td {
                            @if let Some(p) = &log.applied_policy {
                                code { (p) }
                            } @else {
                                span class="text-muted" { "—" }
                            }
                        }
                        td { (status_badge(&log.status)) }
                        td {
                            @if let Some(err) = &log.error {
                                small class="text-danger" { (err) }
                            }
                        }
                        td { small class="text-muted" { (log.created_at) } }
                    }
                }
                @if logs.is_empty() {
                    tr { td colspan="7" class="empty-row" { "No log entries yet." } }
                }
            }
        }
    }
}

pub fn logs_table(logs: &[LogRecord]) -> Markup {
    logs_table_inner(logs)
}

pub fn logs_page(logs: &[LogRecord]) -> Markup {
    let content = html! {
        div class="page-header" {
            h1 class="page-title" { "SMTP Logs" }
            span class="badge badge-muted" { "Auto-refreshes every 5s" }
        }
        div class="table-wrap" {
            (logs_table_inner(logs))
        }
    };
    layout("Logs", content)
}

// ── Config ────────────────────────────────────────────────────────────────────

pub fn config_page(cfg: &Config) -> Markup {
    let max_mb = cfg.smtp.max_message_size as f64 / 1_048_576.0;
    let domains = if cfg.inbound.local_domains.is_empty() {
        "(accept all)".to_string()
    } else {
        cfg.inbound.local_domains.join(", ")
    };
    let auth = if cfg.relay.username.is_some() { "configured" } else { "none" };

    let content = html! {
        div class="page-header" {
            h1 class="page-title" { "Configuration" }
        }
        div class="alert alert-info" {
            "Read-only. Set values via " code { "config.toml" } " or "
            code { "PGP_PROXY__*" } " environment variables."
        }
        div class="config-grid" {
            div class="card" {
                p class="card-label" { "Outbound SMTP" }
                dl class="config-dl" {
                    dt { "Listen" }   dd { code { (cfg.smtp.listen_addr) } }
                    dt { "Hostname" } dd { code { (cfg.smtp.hostname) } }
                    dt { "Max size" } dd { code { (format!("{:.1} MB", max_mb)) } }
                }
            }
            div class="card" {
                p class="card-label" { "Inbound SMTP (MX)" }
                dl class="config-dl" {
                    dt { "Listen" }  dd { code { (cfg.inbound.listen_addr) } }
                    dt { "Domains" } dd { code { (domains) } }
                }
            }
            div class="card" {
                p class="card-label" { "Delivery" }
                dl class="config-dl" {
                    dt { "Mode" } dd { code { (cfg.delivery.mode) } }
                }
            }
            div class="card" {
                p class="card-label" { "Relay (mode=relay only)" }
                dl class="config-dl" {
                    dt { "Host" } dd { code { (cfg.relay.host) } }
                    dt { "Port" } dd { code { (cfg.relay.port) } }
                    dt { "TLS" }  dd { code { (cfg.relay.tls) } }
                    dt { "Auth" } dd { code { (auth) } }
                }
            }
            div class="card" {
                p class="card-label" { "POP3" }
                dl class="config-dl" {
                    dt { "Listen" }  dd { code { (cfg.pop3.listen_addr) } }
                    dt { "Enabled" } dd { code { (cfg.pop3.enabled) } }
                }
            }
            div class="card" {
                p class="card-label" { "Web UI" }
                dl class="config-dl" {
                    dt { "Listen" } dd { code { (cfg.web.listen_addr) } }
                }
            }
            div class="card" {
                p class="card-label" { "Database" }
                dl class="config-dl" {
                    dt { "URL" } dd { code { (cfg.database.url) } }
                }
            }
        }
    };
    layout("Config", content)
}

// ── Users ─────────────────────────────────────────────────────────────────────

pub fn users_table(users: &[String]) -> Markup {
    html! {
        div class="table-wrap" id="users-table" {
            table {
                thead { tr { th { "Email" } th { "" } } }
                tbody {
                    @for email in users {
                        tr {
                            td { (email) }
                            td { (delete_btn(&format!("/users/{email}"), &format!("Delete user {email}?"))) }
                        }
                    }
                    @if users.is_empty() {
                        tr { td colspan="2" class="empty-row" { "No users yet." } }
                    }
                }
            }
        }
    }
}

pub fn users_page(users: &[String]) -> Markup {
    let content = html! {
        div class="page-header" {
            h1 class="page-title" { "Local Users" }
        }
        div class="alert alert-info" {
            "Local users are used for POP3 authentication. Passwords are hashed with Argon2id."
        }
        div class="form-card" {
            div class="form-card-header" { "Add User" }
            div class="form-card-body" {
                form hx-post="/users"
                     hx-target="#users-table"
                     hx-swap="outerHTML"
                     "hx-on::after-request"="this.reset()"
                {
                    div class="form-row" {
                        div class="form-group" {
                            label for="email" { "Email" }
                            input type="email" id="email" name="email"
                                  placeholder="alice@example.com" required;
                        }
                        div class="form-group" {
                            label for="password" { "Password" }
                            input type="password" id="password" name="password" required;
                        }
                        div class="form-group" style="justify-content:flex-end" {
                            button type="submit" class="btn btn-primary" { "Add User" }
                        }
                    }
                }
            }
        }
        (users_table(users))
    };
    layout("Users", content)
}

// ── Mailbox ───────────────────────────────────────────────────────────────────

pub fn mailbox_page(messages: &[MailMessage]) -> Markup {
    let content = html! {
        div class="page-header" {
            h1 class="page-title" { "Mailbox" }
            span class="badge badge-muted" { (messages.len()) " messages" }
        }
        div class="table-wrap" {
            table {
                thead {
                    tr {
                        th { "Recipient" }
                        th { "From" }
                        th { "Subject" }
                        th { "Received" }
                        th { "Status" }
                    }
                }
                tbody {
                    @for msg in messages {
                        tr {
                            td { (msg.recipient) }
                            td { small { (msg.sender) } }
                            td { (msg.subject) }
                            td { small class="text-muted" { (msg.received_at) } }
                            td {
                                @if msg.is_read {
                                    span class="badge badge-muted" { "Read" }
                                } @else {
                                    span class="badge badge-info" { "Unread" }
                                }
                            }
                        }
                    }
                    @if messages.is_empty() {
                        tr { td colspan="5" class="empty-row" { "Mailbox is empty." } }
                    }
                }
            }
        }
    };
    layout("Mailbox", content)
}

// ── Delivery Queue ─────────────────────────────────────────────────────────────

pub fn queue_table(entries: &[QueueEntry]) -> Markup {
    html! {
        div class="table-wrap" id="queue-table"
            hx-get="/queue/partial"
            hx-trigger="every 10s"
            hx-target="#queue-table"
            hx-swap="outerHTML"
        {
            table {
                thead {
                    tr {
                        th { "To" }
                        th { "From" }
                        th { "Status" }
                        th { "Attempts" }
                        th { "Next Retry" }
                        th { "Last Error" }
                        th { "Queued At" }
                        th { "" }
                    }
                }
                tbody {
                    @for e in entries {
                        tr {
                            td { (e.to_addr) }
                            td { small { (e.from_addr) } }
                            td { (status_badge(&e.status)) }
                            td { (e.attempts) " / " (e.max_attempts) }
                            td { small class="text-muted" { (e.next_retry_at) } }
                            td { small class="text-danger" { (e.last_error.as_deref().unwrap_or("")) } }
                            td { small class="text-muted" { (e.created_at) } }
                            td {
                                button class="btn btn-danger btn-sm"
                                    hx-delete=(format!("/queue/{}", e.id))
                                    hx-confirm="Remove this queue entry?"
                                    hx-target="closest tr"
                                    hx-swap="outerHTML"
                                { "Remove" }
                            }
                        }
                    }
                    @if entries.is_empty() {
                        tr { td colspan="8" class="empty-row" { "Queue is empty." } }
                    }
                }
            }
        }
    }
}

pub fn queue_page(entries: &[QueueEntry]) -> Markup {
    let pending   = entries.iter().filter(|e| e.status == "pending").count();
    let delivered = entries.iter().filter(|e| e.status == "delivered").count();
    let failed    = entries.iter().filter(|e| e.status == "failed").count();

    let content = html! {
        div class="page-header" {
            h1 class="page-title" { "Delivery Queue" }
            span class="badge badge-muted" { "Auto-refreshes every 10s" }
        }
        div class="stat-grid" {
            div class="card" {
                p class="card-label" { "Pending" }
                p class="card-value" style="color:var(--warning)" { (pending) }
            }
            div class="card" {
                p class="card-label" { "Delivered" }
                p class="card-value" style="color:var(--success)" { (delivered) }
            }
            div class="card" {
                p class="card-label" { "Failed" }
                p class="card-value" style="color:var(--danger)" { (failed) }
            }
        }
        div class="alert alert-info" {
            "Pending messages retry every 30s with exponential backoff: "
            "5 min → 30 min → 2 h → 8 h → permanent failure after 5 attempts."
        }
        (queue_table(entries))
    };
    layout("Queue", content)
}

// ── CSS ───────────────────────────────────────────────────────────────────────

const CSS: &str = "
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root{
  --bg:#0a0b0f;
  --surface:#11141a;
  --surface2:rgba(255,255,255,0.05);
  --border:rgba(255,255,255,0.09);
  --text:#f0f4f8;
  --text-muted:#6b7280;
  --accent:#00f5c4;
  --accent-glow:rgba(0,245,196,0.22);
  --danger:#ff4d6d;
  --warning:#fbbf24;
  --success:#4ade80;
  --radius:16px;
  --radius-sm:10px;
  --shadow:0 8px 32px rgba(0,0,0,0.45);
}

body{
  background:var(--bg);
  color:var(--text);
  font-family:Inter,system-ui,sans-serif;
  font-size:0.9375rem;
  line-height:1.6;
  min-height:100vh;
}

/* Nav */
.site-nav{
  background:rgba(17,20,26,0.88);
  backdrop-filter:blur(18px);
  border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:100;
}
.nav-inner{
  max-width:1320px;margin:0 auto;
  padding:0 2rem;height:56px;
  display:flex;align-items:center;gap:1.5rem;
}
.nav-brand{
  font-size:1.05rem;font-weight:700;
  color:var(--accent);text-decoration:none;
  letter-spacing:-0.02em;flex-shrink:0;
}
.nav-links{display:flex;gap:0.15rem;flex-wrap:wrap}
.nav-link{
  color:var(--text-muted);text-decoration:none;
  font-size:0.8rem;font-weight:500;
  padding:0.3rem 0.65rem;border-radius:8px;
  transition:color 0.15s,background 0.15s;
}
.nav-link:hover{color:var(--text);background:var(--surface2)}

/* Layout */
.main-content{max-width:1320px;margin:0 auto;padding:2.5rem 2rem}

/* Page header */
.page-header{
  display:flex;align-items:center;
  justify-content:space-between;
  margin-bottom:2rem;gap:1rem;
}
.page-title{
  font-size:1.5rem;font-weight:700;
  letter-spacing:-0.03em;color:var(--text);
}

/* Stat cards */
.stat-grid{
  display:grid;
  grid-template-columns:repeat(auto-fill,minmax(170px,1fr));
  gap:1rem;margin-bottom:2rem;
}
.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
  padding:1.4rem 1.6rem;
  box-shadow:var(--shadow);
}
.card-label{
  font-size:0.7rem;font-weight:600;
  text-transform:uppercase;letter-spacing:0.09em;
  color:var(--text-muted);margin-bottom:0.5rem;
}
.card-value{
  font-size:2.2rem;font-weight:700;
  letter-spacing:-0.04em;line-height:1;
  color:var(--text);
}
.card-link{
  display:inline-block;margin-top:0.7rem;
  font-size:0.78rem;color:var(--accent);
  text-decoration:none;font-weight:500;
}
.card-link:hover{text-decoration:underline}

/* Form card */
.form-card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
  margin-bottom:1.5rem;overflow:hidden;
}
.form-card-header{
  padding:0.8rem 1.5rem;
  border-bottom:1px solid var(--border);
  font-size:0.75rem;font-weight:600;
  color:var(--text-muted);
  text-transform:uppercase;letter-spacing:0.07em;
}
.form-card-body{padding:1.5rem}

/* Forms */
.form-row{
  display:grid;
  grid-template-columns:repeat(auto-fill,minmax(200px,1fr));
  gap:1rem;align-items:end;
}
.form-group{display:flex;flex-direction:column;gap:0.35rem}
.form-group.full{grid-column:1/-1}
label{
  font-size:0.72rem;font-weight:600;
  color:var(--text-muted);
  text-transform:uppercase;letter-spacing:0.07em;
}
input,select,textarea{
  background:var(--bg);
  border:1px solid var(--border);
  border-radius:var(--radius-sm);
  color:var(--text);
  font-family:inherit;font-size:0.875rem;
  padding:0.5rem 0.8rem;width:100%;
  transition:border-color 0.15s,box-shadow 0.15s;
  outline:none;
}
input:focus,select:focus,textarea:focus{
  border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(0,245,196,0.12);
}
textarea{resize:vertical;font-family:'Courier New',monospace;font-size:0.8rem}
select option{background:var(--surface)}
.form-hint{font-size:0.72rem;color:var(--text-muted);margin-top:0.2rem}

/* Buttons */
.btn{
  display:inline-flex;align-items:center;gap:0.35rem;
  padding:0.5rem 1.1rem;border-radius:var(--radius-sm);
  font-size:0.85rem;font-weight:600;
  border:none;cursor:pointer;
  transition:opacity 0.15s,transform 0.15s,box-shadow 0.15s;
  text-decoration:none;white-space:nowrap;
}
.btn:hover{opacity:0.87;transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn-primary{background:var(--accent);color:#0a0b0f}
.btn-primary:hover{box-shadow:0 4px 18px var(--accent-glow)}
.btn-danger{
  background:rgba(255,77,109,0.12);color:var(--danger);
  border:1px solid rgba(255,77,109,0.22);
}
.btn-danger:hover{background:rgba(255,77,109,0.22)}
.btn-sm{padding:0.28rem 0.65rem;font-size:0.76rem}

/* Tables */
.table-wrap{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
  overflow:hidden;
}
table{width:100%;border-collapse:collapse}
thead th{
  padding:0.7rem 1rem;text-align:left;
  font-size:0.7rem;font-weight:600;
  text-transform:uppercase;letter-spacing:0.08em;
  color:var(--text-muted);
  border-bottom:1px solid var(--border);
  background:rgba(0,0,0,0.18);
}
tbody tr{
  border-bottom:1px solid var(--border);
  transition:background 0.1s;
}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--surface2)}
td{
  padding:0.7rem 1rem;
  font-size:0.85rem;
  vertical-align:middle;
}
td small{color:var(--text-muted);font-size:0.78rem}
td code,code{
  font-family:'Courier New',monospace;font-size:0.78rem;
  color:var(--accent);
  background:rgba(0,245,196,0.08);
  padding:0.15rem 0.4rem;border-radius:5px;
}
.empty-row{
  text-align:center;color:var(--text-muted);
  padding:2rem!important;font-style:italic;
}
.text-muted{color:var(--text-muted)}
.text-danger{color:var(--danger);font-size:0.78rem}

/* Badges */
.badge{
  display:inline-flex;align-items:center;
  padding:0.18rem 0.55rem;border-radius:999px;
  font-size:0.7rem;font-weight:600;letter-spacing:0.03em;
}
.badge-success{background:rgba(74,222,128,0.13);color:var(--success)}
.badge-danger {background:rgba(255,77,109,0.13);color:var(--danger)}
.badge-warning{background:rgba(251,191,36,0.13);color:var(--warning)}
.badge-info   {background:rgba(0,245,196,0.12); color:var(--accent)}
.badge-muted  {background:var(--surface2);      color:var(--text-muted)}
.badge-primary{background:rgba(0,245,196,0.12); color:var(--accent)}

/* Alerts */
.alert{
  padding:0.85rem 1.15rem;
  border-radius:var(--radius-sm);
  font-size:0.875rem;
  margin-bottom:1.5rem;
  border:1px solid;
}
.alert-info   {background:rgba(0,245,196,0.06); border-color:rgba(0,245,196,0.18);  color:var(--accent)}
.alert-warning{background:rgba(251,191,36,0.06);border-color:rgba(251,191,36,0.18); color:var(--warning)}
.alert-danger {background:rgba(255,77,109,0.06);border-color:rgba(255,77,109,0.18); color:var(--danger)}

/* Config */
.config-grid{
  display:grid;
  grid-template-columns:repeat(auto-fill,minmax(300px,1fr));
  gap:1rem;
}
.config-grid .card{padding:1.2rem 1.4rem}
dl.config-dl{
  display:grid;
  grid-template-columns:auto 1fr;
  gap:0.35rem 1.2rem;
  margin-top:0.75rem;
}
dl.config-dl dt{font-size:0.75rem;color:var(--text-muted);font-weight:500;padding-top:0.15rem}
dl.config-dl dd code{display:inline-block}

/* Armor preview */
.armor-preview{
  font-family:'Courier New',monospace;font-size:0.7rem;
  color:var(--text-muted);max-height:4.5rem;
  overflow:auto;white-space:pre;
  background:var(--bg);border:1px solid var(--border);
  border-radius:6px;padding:0.35rem 0.55rem;
}

/* Section heading */
h4.section-heading{
  font-size:0.78rem;font-weight:600;
  color:var(--text-muted);margin-bottom:1rem;
  text-transform:uppercase;letter-spacing:0.08em;
}
";
