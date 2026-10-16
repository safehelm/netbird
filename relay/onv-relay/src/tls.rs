//! The relay's certificate, from files or from Let's Encrypt (TLS-ALPN-01 on
//! the WebSocket port, as the Go relay's autocert answers it), and the TLS
//! settings of its two listeners.
use futures_util::StreamExt;
use rustls::{
    ServerConfig,
    crypto::CryptoProvider,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{path::Path, sync::Arc};
use tracing::{error, info};

pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";
/// The relay's QUIC ALPN (`shared/relay/tls.NBalpn`)
pub const NB_ALPN: &[u8] = b"nb-quic";

#[derive(Debug)]
pub enum Resolver {
    Files(Arc<CertifiedKey>),
    /// Let's Encrypt's, and until it has one, an earlier certificate
    Acme {
        acme: Arc<rustls_acme::ResolvesServerCertAcme>,
        earlier: Option<Arc<CertifiedKey>>,
    },
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match self {
            Resolver::Files(c) => Some(c.clone()),
            Resolver::Acme { acme, earlier } => {
                let challenge = rustls_acme::is_tls_alpn_challenge(&hello);
                acme.resolve(hello).or_else(|| if challenge { None } else { earlier.clone() })
            }
        }
    }
}

/// The certificate the Go relay's autocert kept for `domain` under its data
/// directory (`<dir>/letsencrypt/<domain>`: the key, then the chain, in PEM),
/// served until this relay's own is issued, so a first start does not wait
/// on Let's Encrypt
pub fn autocert_cached(dir: &Path, domain: &str, provider: &CryptoProvider) -> Option<Arc<CertifiedKey>> {
    let path = dir.join("letsencrypt").join(domain);
    let pem = std::fs::read(&path).ok()?;
    let found = (|| {
        let key = PrivateKeyDer::from_pem_slice(&pem).map_err(|e| e.to_string())?;
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(&pem).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
        if chain.is_empty() {
            return Err("no certificate".to_string());
        }
        let signer = provider.key_provider.load_private_key(key).map_err(|e| e.to_string())?;
        let certified = CertifiedKey::new(chain, signer);
        certified.keys_match().map_err(|e| e.to_string())?;
        Ok(Arc::new(certified))
    })();
    match found {
        Ok(c) => {
            info!("serving {} until Let's Encrypt issues this relay's own", path.display());
            Some(c)
        }
        Err(e) => {
            error!("{}: {e}", path.display());
            None
        }
    }
}

/// ring's suites, ChaCha20-Poly1305 first unless NB_RELAY_QUINN_CIPHER=aes
/// (16 October 2026: on a relay host whose CPU has no AES instructions it
/// costs a quarter of AES-GCM)
pub fn provider(chacha_first: bool) -> Arc<CryptoProvider> {
    let mut p = rustls::crypto::ring::default_provider();
    if chacha_first {
        p.cipher_suites.sort_by_key(|s| {
            !matches!(
                s.suite(),
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            )
        });
    }
    Arc::new(p)
}

pub fn chacha_first() -> bool {
    std::env::var("NB_RELAY_QUINN_CIPHER").map_or(true, |v| v != "aes")
}

pub fn load_files(cert: &Path, key: &Path, provider: &CryptoProvider) -> Result<Arc<CertifiedKey>, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("{}: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("{}: no certificate", cert.display()));
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let signer = provider.key_provider.load_private_key(key).map_err(|e| e.to_string())?;
    let certified = CertifiedKey::new(chain, signer);
    certified.keys_match().map_err(|e| e.to_string())?;
    Ok(Arc::new(certified))
}

/// Let's Encrypt's production directory, a cache under `dir`; the task
/// returned keeps the certificate issued and renewed
pub fn acme(domains: &[String], dir: &Path, email: &str, earlier: Option<Arc<CertifiedKey>>) -> Arc<Resolver> {
    let mut config =
        rustls_acme::AcmeConfig::new_with_provider(domains, Arc::new(rustls::crypto::ring::default_provider()))
            .cache(rustls_acme::caches::DirCache::new(dir.to_path_buf()))
            .directory_lets_encrypt(true);
    if !email.is_empty() {
        config = config.contact_push(format!("mailto:{email}"));
    }
    let mut state = config.state();
    let resolver = Arc::new(Resolver::Acme { acme: state.resolver(), earlier });
    info!("running with LetsEncrypt ({domains:?}). Cert will be stored in {}", dir.display());
    tokio::spawn(async move {
        while let Some(event) = state.next().await {
            match event {
                Ok(ok) => info!("certificate: {ok:?}"),
                Err(e) => error!("certificate: {e}"),
            }
        }
    });
    resolver
}

/// The WebSocket listener's: TLS 1.2 and 1.3, HTTP/1.1, and the ACME challenge
pub fn tcp_config(
    resolver: Arc<Resolver>,
    provider: Arc<CryptoProvider>,
    chacha_first: bool,
) -> Result<Arc<ServerConfig>, String> {
    let mut c = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    c.alpn_protocols = vec![b"http/1.1".to_vec(), ACME_TLS_ALPN.to_vec()];
    c.ignore_client_order = chacha_first;
    Ok(Arc::new(c))
}

/// The QUIC listener's: TLS 1.3, `nb-quic`, no resumption and no early data
/// (the Go relay's native listener's settings)
pub fn quic_config(
    resolver: Arc<Resolver>,
    provider: Arc<CryptoProvider>,
    chacha_first: bool,
) -> Result<ServerConfig, String> {
    let mut c = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    c.alpn_protocols = vec![NB_ALPN.to_vec()];
    c.ignore_client_order = chacha_first;
    c.send_tls13_tickets = 0;
    c.max_early_data_size = 0;
    Ok(c)
}

/// The health check's: the system's roots (SSL_CERT_FILE names others)
pub fn client_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let found = rustls_native_certs::load_native_certs();
    for e in &found.errors {
        error!("trust store: {e}");
    }
    let (added, _) = roots.add_parsable_certificates(found.certs);
    if added == 0 {
        error!("trust store: no certificate; the health check's own dial will fail");
    }
    client_config_with(roots)
}

pub fn client_config_with(roots: rustls::RootCertStore) -> Arc<rustls::ClientConfig> {
    let mut c = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring's protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(c)
}
