//! The relay's listeners started together, and stopped together.
use crate::{
    auth::Validator,
    http::{self, Health, Reply},
    net, quic,
    relay::{HealthCheckTiming, Relay},
    tls::{self, Resolver},
    ws,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::task::JoinHandle;
use tracing::info;

pub struct Options {
    pub listen: String,
    /// `rels://name:443`, or a bare `name:port` given its scheme here
    pub exposed: String,
    pub certificate: Option<Arc<Resolver>>,
    pub secret: String,
    pub health_listen: Option<String>,
    pub metrics_listen: Option<String>,
    pub health_check: HealthCheckTiming,
    /// The health check's trust store; the system's when none
    pub health_roots: Option<Arc<rustls::ClientConfig>>,
    pub udp_buffer: usize,
}

pub struct Running {
    pub relay: Arc<Relay>,
    pub tcp: SocketAddr,
    pub udp: Option<SocketAddr>,
    pub health: Option<SocketAddr>,
    pub metrics: Option<SocketAddr>,
    endpoint: Option<quinn::Endpoint>,
    tasks: Vec<JoinHandle<()>>,
}

/// `getInstanceURL`: a scheme is added by whether the relay has TLS, and a
/// plain scheme on a relay with TLS is refused
pub fn instance_url(exposed: &str, tls: bool) -> Result<String, String> {
    let url = match exposed.split("://").count() {
        1 => format!("{}://{exposed}", if tls { "rels" } else { "rel" }),
        2 => exposed.to_string(),
        _ => return Err(format!("invalid exposed address: {exposed}")),
    };
    let (scheme, rest) = url.split_once("://").unwrap();
    if scheme != "rel" && scheme != "rels" {
        return Err(format!("invalid scheme: {scheme}"));
    }
    if rest.is_empty() || rest.starts_with('/') {
        return Err(format!("invalid exposed address: {exposed}"));
    }
    if tls && scheme == "rel" {
        return Err("non-TLS scheme 'rel' provided but TLS is supported".into());
    }
    Ok(url)
}

pub async fn start(o: Options) -> Result<Running, String> {
    let chacha = tls::chacha_first();
    let provider = tls::provider(chacha);
    let url = instance_url(&o.exposed, o.certificate.is_some())?;
    let relay = Relay::new(Validator::new(&o.secret), url.clone(), o.health_check);
    let mut tasks = Vec::new();

    let tcp = net::tcp(&o.listen).map_err(|e| format!("ws listener: {e}"))?;
    let tcp_addr = tcp.local_addr().map_err(|e| e.to_string())?;
    let tcp_tls = match &o.certificate {
        Some(r) => Some(tls::tcp_config(r.clone(), provider.clone(), chacha)?),
        None => None,
    };
    info!("WS server listening address: {tcp_addr}");
    tasks.push(tokio::spawn(ws::serve(tcp, tcp_tls, relay.clone())));
    let mut listeners = vec!["ws"];

    // QUIC needs a certificate; without one the relay serves WebSocket alone
    let (endpoint, udp_addr) = match &o.certificate {
        Some(r) => {
            let socket = net::udp(&o.listen, o.udp_buffer).map_err(|e| format!("quic listener: {e}"))?;
            let ep = quic::endpoint(socket, tls::quic_config(r.clone(), provider.clone(), chacha)?)
                .map_err(|e| format!("quic listener: {e}"))?;
            let addr = ep.local_addr().map_err(|e| e.to_string())?;
            info!("QUIC server listening on address: {addr} (Quinn)");
            tasks.push(tokio::spawn(quic::serve(ep.clone(), relay.clone())));
            listeners.push("quic");
            (Some(ep), Some(addr))
        }
        None => {
            tracing::warn!("Not starting QUIC listener: valid TLS config is required for QUIC listener");
            (None, None)
        }
    };

    let mut health_addr = None;
    if let Some(addr) = &o.health_listen {
        let l = net::tcp(addr).map_err(|e| format!("health listener: {e}"))?;
        health_addr = Some(l.local_addr().map_err(|e| e.to_string())?);
        let roots = o.health_roots.clone().unwrap_or_else(tls::client_config);
        let health = Health::new(relay.clone(), listeners.clone(), roots);
        info!("starting healthcheck server on: http://{}/health", health_addr.unwrap());
        tasks.push(tokio::spawn(http::serve(l, move |path: String| {
            let health = health.clone();
            async move { if path == "/health" { health.reply().await } else { http::not_found() } }
        })));
    }
    let mut metrics_addr = None;
    if let Some(addr) = &o.metrics_listen {
        let l = net::tcp(addr).map_err(|e| format!("metrics listener: {e}"))?;
        metrics_addr = Some(l.local_addr().map_err(|e| e.to_string())?);
        info!("running metrics server: {}/metrics", metrics_addr.unwrap());
        let relay = relay.clone();
        tasks.push(tokio::spawn(http::serve(l, move |path: String| {
            let relay = relay.clone();
            async move {
                if path == "/metrics" {
                    Reply { status: 200, content_type: "text/plain; version=0.0.4", body: relay.metrics.render() }
                } else {
                    http::not_found()
                }
            }
        })));
    }
    info!("server will be available on: {url}");
    Ok(Running { relay, tcp: tcp_addr, udp: udp_addr, health: health_addr, metrics: metrics_addr, endpoint, tasks })
}

impl Running {
    /// No new connection is taken; each peer is told and closed; QUIC's
    /// closes are given a moment to reach the peers
    pub async fn shutdown(self) {
        if let Some(ep) = &self.endpoint {
            ep.set_server_config(None);
        }
        for t in &self.tasks {
            t.abort();
        }
        let _ = tokio::time::timeout(Duration::from_secs(30), self.relay.shutdown()).await;
        if let Some(ep) = self.endpoint {
            ep.close(0u32.into(), b"relay shutdown");
            let _ = tokio::time::timeout(Duration::from_secs(2), ep.wait_idle()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_urls_as_go_makes_them() {
        assert_eq!(instance_url("relay.example:443", true).unwrap(), "rels://relay.example:443");
        assert_eq!(instance_url("relay.example:80", false).unwrap(), "rel://relay.example:80");
        assert_eq!(instance_url("rels://relay.example:443", true).unwrap(), "rels://relay.example:443");
        assert!(instance_url("rel://relay.example:443", true).is_err());
        assert!(instance_url("http://relay.example", false).is_err());
        assert!(instance_url("a://b://c", false).is_err());
    }
}
