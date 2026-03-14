mod config;
mod db;
mod error;
mod keys;
mod mailbox;
mod pgp_engine;
mod policy;
mod pop3;
mod private_keys;
mod queue;
mod smtp;
mod users;
mod web;

use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pgp_proxy=info,tower_http=debug".parse().unwrap()),
        )
        .init();

    let cfg = config::Config::load().map_err(|e| {
        eprintln!("Failed to load config: {e}");
        e
    })?;
    info!("Configuration loaded");
    info!("SMTP (outbound) listening on {}", cfg.smtp.listen_addr);
    info!("Inbound SMTP listening on {}", cfg.inbound.listen_addr);
    info!("Web UI listening on {}", cfg.web.listen_addr);
    info!("Delivery mode: {}", cfg.delivery.mode);
    if cfg.delivery.mode == "relay" {
        info!("Relay: {}:{} (tls={})", cfg.relay.host, cfg.relay.port, cfg.relay.tls);
    }
    if cfg.pop3.enabled {
        info!("POP3 listening on {}", cfg.pop3.listen_addr);
    }

    // Load TLS config for the submission port (optional)
    let tls_acceptor = load_tls_acceptor(&cfg.smtp).map_err(|e| {
        eprintln!("Failed to load TLS config: {e}");
        e
    })?;
    if tls_acceptor.is_some() {
        info!("STARTTLS enabled on submission port");
    }

    let pool = db::init_db(&cfg.database.url).await.map_err(|e| {
        eprintln!("Failed to initialize database: {e}");
        e
    })?;
    info!("Database initialized at {}", cfg.database.url);

    let pool = Arc::new(pool);
    let config = Arc::new(cfg);

    // Spawn outbound SMTP server task
    let smtp_config = Arc::clone(&config);
    let smtp_pool = Arc::clone(&pool);
    let smtp_tls = tls_acceptor.clone();
    let smtp_handle = tokio::spawn(async move {
        if let Err(e) = smtp::server::run_smtp_server(smtp_config, smtp_pool, smtp_tls).await {
            eprintln!("SMTP server error: {e}");
        }
    });

    // Spawn inbound SMTP server task
    let inbound_config = Arc::clone(&config);
    let inbound_pool = Arc::clone(&pool);
    let inbound_handle = tokio::spawn(async move {
        if let Err(e) =
            smtp::server::run_inbound_smtp_server(inbound_config, inbound_pool).await
        {
            eprintln!("Inbound SMTP server error: {e}");
        }
    });

    // Spawn delivery queue processor
    let queue_config = Arc::clone(&config);
    let queue_pool = Arc::clone(&pool);
    tokio::spawn(async move {
        if let Err(e) = queue::run_queue_processor(queue_config, queue_pool).await {
            eprintln!("Queue processor error: {e}");
        }
    });

    // Spawn POP3 server task (if enabled)
    let pop3_handle = if config.pop3.enabled {
        let pop3_config = Arc::clone(&config);
        let pop3_pool = Arc::clone(&pool);
        Some(tokio::spawn(async move {
            if let Err(e) = pop3::server::run_pop3_server(pop3_config, pop3_pool).await {
                eprintln!("POP3 server error: {e}");
            }
        }))
    } else {
        info!("POP3 server disabled");
        None
    };

    // Spawn web server task
    let web_config = Arc::clone(&config);
    let web_pool = Arc::clone(&pool);
    let web_addr = web_config.web.listen_addr.clone();

    let web_handle = tokio::spawn(async move {
        let router = web::build_router(web_pool, web_config);
        let listener = match tokio::net::TcpListener::bind(&web_addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to bind web server on {web_addr}: {e}");
                return;
            }
        };
        info!("Web UI server listening on {web_addr}");
        if let Err(e) = axum::serve(listener, router).await {
            eprintln!("Web server error: {e}");
        }
    });

    if let Some(pop3_h) = pop3_handle {
        tokio::select! {
            result = smtp_handle => {
                match result {
                    Ok(_) => eprintln!("SMTP server task exited unexpectedly"),
                    Err(e) => eprintln!("SMTP server task panicked: {e}"),
                }
            }
            result = inbound_handle => {
                match result {
                    Ok(_) => eprintln!("Inbound SMTP server task exited unexpectedly"),
                    Err(e) => eprintln!("Inbound SMTP server task panicked: {e}"),
                }
            }
            result = pop3_h => {
                match result {
                    Ok(_) => eprintln!("POP3 server task exited unexpectedly"),
                    Err(e) => eprintln!("POP3 server task panicked: {e}"),
                }
            }
            result = web_handle => {
                match result {
                    Ok(_) => eprintln!("Web server task exited unexpectedly"),
                    Err(e) => eprintln!("Web server task panicked: {e}"),
                }
            }
        }
    } else {
        tokio::select! {
            result = smtp_handle => {
                match result {
                    Ok(_) => eprintln!("SMTP server task exited unexpectedly"),
                    Err(e) => eprintln!("SMTP server task panicked: {e}"),
                }
            }
            result = inbound_handle => {
                match result {
                    Ok(_) => eprintln!("Inbound SMTP server task exited unexpectedly"),
                    Err(e) => eprintln!("Inbound SMTP server task panicked: {e}"),
                }
            }
            result = web_handle => {
                match result {
                    Ok(_) => eprintln!("Web server task exited unexpectedly"),
                    Err(e) => eprintln!("Web server task panicked: {e}"),
                }
            }
        }
    }

    Ok(())
}

/// Load a `TlsAcceptor` from the configured PEM cert and key paths.
/// Returns `None` if no TLS cert is configured.
fn load_tls_acceptor(
    smtp_cfg: &config::SmtpConfig,
) -> anyhow::Result<Option<Arc<tokio_rustls::TlsAcceptor>>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::BufReader;

    let (Some(cert_path), Some(key_path)) = (&smtp_cfg.tls_cert, &smtp_cfg.tls_key) else {
        return Ok(None);
    };

    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("Cannot open TLS cert {cert_path}: {e}"))?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to parse TLS cert {cert_path}: {e}"))?;

    let key_file = std::fs::File::open(key_path)
        .map_err(|e| anyhow::anyhow!("Cannot open TLS key {key_path}: {e}"))?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(key_file))
            .map_err(|e| anyhow::anyhow!("Failed to parse TLS key {key_path}: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("No private key found in {key_path}"))?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("TLS server config error: {e}"))?;

    Ok(Some(Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(
        server_config,
    )))))
}
