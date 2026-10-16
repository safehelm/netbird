//! `onv-relay`: the Go relay's command line (`relay/cmd`), each flag also an
//! NB_ variable, so the play that starts one starts the other.
use clap::{ArgAction, Parser, builder::BoolishValueParser};
use onv_relay::{relay::HealthCheckTiming, server, tls};
use std::{path::Path, sync::Arc};
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "onv-relay", about = "Relay service for NetBird agents (Rust, QUIC on Quinn)")]
struct Config {
    /// listen address
    #[arg(short = 'l', long, env = "NB_LISTEN_ADDRESS", default_value = ":443")]
    listen_address: String,
    /// instance domain address (or ip) and port, it will be distributed between peers
    #[arg(short = 'e', long, env = "NB_EXPOSED_ADDRESS", default_value = "")]
    exposed_address: String,
    /// metrics endpoint http port; metrics are under host:metrics-port/metrics
    #[arg(long, env = "NB_METRICS_PORT", default_value_t = 9090)]
    metrics_port: u16,
    /// a directory to store Let's Encrypt data
    #[arg(short = 'd', long, env = "NB_LETSENCRYPT_DATA_DIR", default_value = "")]
    letsencrypt_data_dir: String,
    /// domains to issue a Let's Encrypt certificate for; enables TLS
    #[arg(short = 'a', long, env = "NB_LETSENCRYPT_DOMAINS", value_delimiter = ',')]
    letsencrypt_domains: Vec<String>,
    /// email address to use for Let's Encrypt certificate registration
    #[arg(long, env = "NB_LETSENCRYPT_EMAIL", default_value = "")]
    letsencrypt_email: String,
    /// use AWS Route 53 for Let's Encrypt DNS challenge (not in this relay)
    #[arg(long, env = "NB_LETSENCRYPT_AWS_ROUTE53", action = ArgAction::Set, num_args = 0..=1,
          default_value = "false", default_missing_value = "true", value_parser = BoolishValueParser::new())]
    letsencrypt_aws_route53: bool,
    #[arg(short = 'c', long, env = "NB_TLS_CERT_FILE", default_value = "")]
    tls_cert_file: String,
    #[arg(short = 'k', long, env = "NB_TLS_KEY_FILE", default_value = "")]
    tls_key_file: String,
    /// auth secret
    #[arg(
        short = 's',
        long,
        env = "NB_AUTH_SECRET",
        default_value = "",
        hide_env_values = true,
        hide_default_value = true
    )]
    auth_secret: String,
    /// log level: panic, fatal, error, warn, info, debug or trace
    #[arg(long, env = "NB_LOG_LEVEL", default_value = "info")]
    log_level: String,
    /// log file, or console
    #[arg(long, env = "NB_LOG_FILE", default_value = "console")]
    log_file: String,
    /// listen address of healthcheck server
    #[arg(short = 'H', long, env = "NB_HEALTH_LISTEN_ADDRESS", default_value = ":9000")]
    health_listen_address: String,
    /// upstream proxies whose X-Real-Ip/X-Real-Port are trusted (not in this relay)
    #[arg(long, env = "NB_TRUSTED_PROXIES", default_value = "")]
    trusted_proxies: String,
    /// embedded STUN server (not in this relay)
    #[arg(long, env = "NB_ENABLE_STUN", action = ArgAction::Set, num_args = 0..=1,
          default_value = "false", default_missing_value = "true", value_parser = BoolishValueParser::new())]
    enable_stun: bool,
    #[arg(long, env = "NB_STUN_PORTS", value_delimiter = ',', default_value = "3478")]
    stun_ports: Vec<u16>,
    #[arg(long, env = "NB_STUN_LOG_LEVEL", default_value = "info")]
    stun_log_level: String,
}

impl Config {
    /// What the Go relay refuses, and what this one has not got
    fn validate(&self) -> Result<(), String> {
        if self.exposed_address.is_empty() {
            return Err("exposed address is required".into());
        }
        if self.auth_secret.is_empty() {
            return Err("auth secret is required".into());
        }
        if self.letsencrypt_aws_route53 {
            return Err("--letsencrypt-aws-route53 is not supported by this relay".into());
        }
        if !self.trusted_proxies.is_empty() {
            return Err("--trusted-proxies is not supported by this relay".into());
        }
        if self.enable_stun {
            return Err("--enable-stun is not supported by this relay".into());
        }
        Ok(())
    }
}

fn level(name: &str) -> tracing::level_filters::LevelFilter {
    use tracing::level_filters::LevelFilter as L;
    match name.to_ascii_lowercase().as_str() {
        "panic" | "fatal" | "error" => L::ERROR,
        "warn" | "warning" => L::WARN,
        "debug" => L::DEBUG,
        "trace" => L::TRACE,
        _ => L::INFO,
    }
}

fn init_log(c: &Config) -> Result<(), String> {
    let builder = tracing_subscriber::fmt().with_max_level(level(&c.log_level)).with_target(false);
    if c.log_file == "console" {
        builder.init();
    } else {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&c.log_file)
            .map_err(|e| format!("failed to initialize log: {}: {e}", c.log_file))?;
        builder.with_ansi(false).with_writer(std::sync::Mutex::new(f)).init();
    }
    Ok(())
}

fn workers() -> usize {
    std::env::var("NB_RELAY_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()))
}

fn main() {
    let c = Config::parse();
    if let Err(e) = c.validate() {
        eprintln!("Error: invalid config: {e}");
        std::process::exit(1);
    }
    if let Err(e) = init_log(&c) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers())
        .thread_name("onv-relay")
        .enable_all()
        .build()
        .expect("runtime");
    if let Err(e) = rt.block_on(run(c)) {
        error!("{e}");
        std::process::exit(1);
    }
}

async fn run(c: Config) -> Result<(), String> {
    // Let's Encrypt when it has a directory and names, else the files, as the
    // Go relay chooses
    let certificate = if !c.letsencrypt_data_dir.is_empty() && !c.letsencrypt_domains.is_empty() {
        let dir = Path::new(&c.letsencrypt_data_dir).join("rustls-acme");
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let earlier = tls::autocert_cached(
            Path::new(&c.letsencrypt_data_dir),
            &c.letsencrypt_domains[0],
            &rustls::crypto::ring::default_provider(),
        );
        Some(tls::acme(&c.letsencrypt_domains, &dir, &c.letsencrypt_email, earlier))
    } else if !c.tls_cert_file.is_empty() && !c.tls_key_file.is_empty() {
        let provider = rustls::crypto::ring::default_provider();
        let key = tls::load_files(Path::new(&c.tls_cert_file), Path::new(&c.tls_key_file), &provider)
            .map_err(|e| format!("failed to setup TLS config: {e}"))?;
        Some(Arc::new(tls::Resolver::Files(key)))
    } else {
        None
    };
    let udp_buffer = std::env::var("NB_RELAY_UDP_BUFFER").ok().and_then(|v| v.parse().ok()).unwrap_or(7 << 20);
    let running = server::start(server::Options {
        listen: c.listen_address.clone(),
        exposed: c.exposed_address.clone(),
        certificate,
        secret: c.auth_secret.clone(),
        health_listen: Some(c.health_listen_address.clone()),
        metrics_listen: Some(format!(":{}", c.metrics_port)),
        health_check: HealthCheckTiming::default(),
        health_roots: None,
        udp_buffer,
    })
    .await?;

    let mut term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|e| e.to_string())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    info!("shutting down");
    running.shutdown().await;
    Ok(())
}
