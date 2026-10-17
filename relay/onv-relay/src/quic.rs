//! The QUIC listener: Quinn, DATAGRAMs, and the transport settings the Go
//! relay's native listener had (16 October 2026), under the same variables.
use crate::{conn::Accepted, relay::Relay};
use quinn::{Endpoint, EndpointConfig, ServerConfig, TransportConfig, crypto::rustls::QuicServerConfig};
use std::{sync::Arc, time::Duration};
use tracing::{debug, info};

/// Bytes of DATAGRAMs a connection holds received and not yet read, and
/// queued and not yet sent; NB_RELAY_QUINN_DATAGRAM_RECV_BYTES and _SEND_BYTES
/// set them. At a relay's round trip the sender's leg runs ahead of the
/// receiver's while its window grows, and what a full receive queue cannot
/// hold Quinn drops: 115 kB lost 0.2% of a 150 Mbit/s stream.
fn datagram_bytes(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).filter(|&n| n >= 64 * 1024).unwrap_or(default)
}

pub fn transport() -> Result<TransportConfig, String> {
    let mut t = TransportConfig::default();
    t.initial_mtu(1232)
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().map_err(|e| format!("{e}"))?))
        .datagram_receive_buffer_size(Some(datagram_bytes("NB_RELAY_QUINN_DATAGRAM_RECV_BYTES", 4 << 20)))
        .datagram_send_buffer_size(datagram_bytes("NB_RELAY_QUINN_DATAGRAM_SEND_BYTES", 1 << 20))
        // The protocol is DATAGRAMs alone (RFC 9221), so no stream is offered
        // (RFC 9000 section 4.6): none can be opened, and nothing is held for
        // one. The Go relay offers quic-go's 100 of each and reads none
        .max_concurrent_bidi_streams(0u32.into())
        .max_concurrent_uni_streams(0u32.into());
    // NB_RELAY_QUINN_CC: newreno (when unset), cubic or bbr. Each relayed leg
    // is a QUIC connection of its own, its sending held by this controller
    match std::env::var("NB_RELAY_QUINN_CC").as_deref() {
        Ok("bbr") => t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
        Ok("cubic") => t.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
        Ok("newreno") | Err(_) => {
            t.congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default()))
        }
        Ok(other) => return Err(format!("NB_RELAY_QUINN_CC={other}: newreno, cubic or bbr")),
    };
    Ok(t)
}

pub fn endpoint(socket: std::net::UdpSocket, tls: rustls::ServerConfig) -> Result<Endpoint, String> {
    let crypto = QuicServerConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport()?));
    Endpoint::new(EndpointConfig::default(), Some(config), socket, Arc::new(quinn::TokioRuntime))
        .map_err(|e| e.to_string())
}

pub async fn serve(endpoint: Endpoint, relay: Arc<Relay>) {
    while let Some(incoming) = endpoint.accept().await {
        let relay = relay.clone();
        tokio::spawn(async move {
            let remote = incoming.remote_address();
            match incoming.await {
                Ok(c) => {
                    info!("QUIC client connected from: {remote}");
                    relay.accept(Accepted::quic(c)).await;
                }
                Err(e) => debug!("QUIC handshake with {remote}: {e}"),
            }
        });
    }
}
