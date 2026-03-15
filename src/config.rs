use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub smtp: SmtpConfig,
    pub inbound: InboundConfig,
    pub delivery: DeliveryConfig,
    pub relay: RelayConfig,
    pub pop3: Pop3Config,
    pub web: WebConfig,
    pub database: DatabaseConfig,
    pub fetch: FetchConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FetchConfig {
    pub enabled: bool,
    pub poll_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SmtpConfig {
    pub listen_addr: String,
    pub hostname: String,
    pub max_message_size: usize,
    /// Path to PEM certificate file for STARTTLS on the submission port (optional)
    pub tls_cert: Option<String>,
    /// Path to PEM private key file for STARTTLS on the submission port (optional)
    pub tls_key: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InboundConfig {
    pub listen_addr: String,
    pub local_domains: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DeliveryConfig {
    pub mode: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RelayConfig {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Pop3Config {
    pub listen_addr: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WebConfig {
    pub listen_addr: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name("config").required(false))
            .add_source(
            config::Environment::with_prefix("PGP_PROXY")
                .separator("__")
                .list_separator(",")
                .with_list_parse_key("inbound.local_domains")
                .try_parsing(true),
        )
            .set_default("smtp.listen_addr", "0.0.0.0:2587")?
            .set_default("smtp.hostname", "pgp-proxy.local")?
            .set_default("smtp.max_message_size", 26214400i64)?
            .set_default("inbound.listen_addr", "0.0.0.0:2525")?
            .set_default("inbound.local_domains", Vec::<String>::new())?
            .set_default("delivery.mode", "relay")?
            .set_default("relay.host", "localhost")?
            .set_default("relay.port", 25u16)?
            .set_default("relay.tls", false)?
            .set_default("pop3.listen_addr", "0.0.0.0:1100")?
            .set_default("pop3.enabled", true)?
            .set_default("web.listen_addr", "0.0.0.0:8080")?
            .set_default("database.url", "sqlite://pgp_proxy.db")?
            .set_default("fetch.enabled", true)?
            .set_default("fetch.poll_interval_secs", 300u64)?
            .build()?;
        Ok(cfg.try_deserialize()?)
    }
}
