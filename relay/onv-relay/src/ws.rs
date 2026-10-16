//! The WebSocket listener: TCP, TLS when the relay has a certificate, and an
//! upgrade on `/relay` alone. A TLS-ALPN-01 challenge ends at its handshake.
use crate::{
    conn::{Accepted, BoxIo},
    relay::Relay,
    tls::ACME_TLS_ALPN,
};
use std::{sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::{
    handshake::server::{ErrorResponse, Request, Response},
    http::StatusCode,
    protocol::WebSocketConfig,
};
use tracing::{debug, info, warn};

pub const PATH: &str = "/relay";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn config() -> WebSocketConfig {
    WebSocketConfig::default().max_message_size(Some(64 << 10)).max_frame_size(Some(64 << 10))
}

pub async fn serve(listener: tokio::net::TcpListener, tls: Option<Arc<rustls::ServerConfig>>, relay: Arc<Relay>) {
    loop {
        let (tcp, remote) = match listener.accept().await {
            Ok(a) => a,
            Err(e) => {
                warn!("WS accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let (tls, relay) = (tls.clone(), relay.clone());
        tokio::spawn(async move {
            let io: BoxIo = match tls {
                None => Box::new(tcp),
                Some(cfg) => match tokio::time::timeout(HANDSHAKE_TIMEOUT, TlsAcceptor::from(cfg).accept(tcp)).await {
                    Ok(Ok(mut s)) => {
                        if s.get_ref().1.alpn_protocol() == Some(ACME_TLS_ALPN) {
                            debug!("TLS-ALPN-01 challenge from {remote}");
                            let _ = s.shutdown().await;
                            return;
                        }
                        Box::new(s)
                    }
                    Ok(Err(e)) => return debug!("TLS handshake with {remote}: {e}"),
                    Err(_) => return debug!("TLS handshake with {remote}: timed out"),
                },
            };
            // The callback's type is tungstenite's
            #[allow(clippy::result_large_err)]
            let path_check = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
                if req.uri().path() == PATH {
                    Ok(resp)
                } else {
                    let mut r = ErrorResponse::new(Some("404 page not found".into()));
                    *r.status_mut() = StatusCode::NOT_FOUND;
                    Err(r)
                }
            };
            let ws = tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                tokio_tungstenite::accept_hdr_async_with_config(io, path_check, Some(config())),
            )
            .await;
            match ws {
                Ok(Ok(ws)) => {
                    info!("WS client connected from: {remote}");
                    relay.accept(Accepted::ws(ws, remote)).await;
                }
                Ok(Err(e)) => debug!("WS upgrade from {remote}: {e}"),
                Err(_) => debug!("WS upgrade from {remote}: timed out"),
            }
        });
    }
}
