//! The two small HTTP servers: `/health` (`relay/healthcheck`: the listeners
//! running, and the WebSocket listener answering a real dial of the relay's
//! own address) and `/metrics`. HTTP/1.1, one request a connection.
use crate::{auth, messages, relay::Relay};
use futures_util::SinkExt;
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_tungstenite::tungstenite::Message;
use tracing::error;

pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

pub async fn serve<F, Fut>(listener: TcpListener, handle: F)
where
    F: Fn(String) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Reply> + Send,
{
    loop {
        let Ok((mut s, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let handle = handle.clone();
        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(1024);
            let read = tokio::time::timeout(Duration::from_secs(5), async {
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 8192 {
                    let n = s.read(&mut chunk).await?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Ok::<_, std::io::Error>(())
            })
            .await;
            if !matches!(read, Ok(Ok(()))) {
                return;
            }
            let line = String::from_utf8_lossy(&buf);
            let mut parts = line.split_whitespace();
            let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            let path = target.split('?').next().unwrap_or("").to_string();
            let r = if method == "GET" || method == "HEAD" {
                handle(path).await
            } else {
                Reply { status: 405, content_type: "text/plain", body: "method not allowed\n".into() }
            };
            let reason = match r.status {
                200 => "OK",
                404 => "Not Found",
                405 => "Method Not Allowed",
                503 => "Service Unavailable",
                _ => "",
            };
            let head = format!(
                "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                r.status,
                r.content_type,
                r.body.len()
            );
            let _ = s.write_all(head.as_bytes()).await;
            if method != "HEAD" {
                let _ = s.write_all(r.body.as_bytes()).await;
            }
            let _ = s.shutdown().await;
        });
    }
}

pub fn not_found() -> Reply {
    Reply { status: 404, content_type: "text/plain; charset=utf-8", body: "404 page not found\n".into() }
}

/// What `/health` answers, kept 3 s
pub struct Health {
    pub relay: Arc<Relay>,
    pub listeners: Vec<&'static str>,
    pub roots: Arc<rustls::ClientConfig>,
    cache: Mutex<Option<(Instant, u16, String)>>,
}

impl Health {
    pub fn new(relay: Arc<Relay>, listeners: Vec<&'static str>, roots: Arc<rustls::ClientConfig>) -> Arc<Self> {
        Arc::new(Self { relay, listeners, roots, cache: Mutex::new(None) })
    }

    pub async fn reply(&self) -> Reply {
        if let Some((at, status, body)) = self.cache.lock().unwrap().clone()
            && at.elapsed() <= Duration::from_secs(3)
        {
            return Reply { status, content_type: "application/json", body };
        }
        let url = self.relay.instance_url().to_string();
        let mut healthy = !self.listeners.is_empty();
        let mut certificate_valid = url.starts_with("rels://");
        if let Err(e) = tokio::time::timeout(Duration::from_secs(5), self.dial(&url))
            .await
            .unwrap_or_else(|_| Err("timed out".into()))
        {
            error!("failed to dial WebSocket listener at {url}: {e}");
            healthy = false;
            certificate_valid = false;
        }
        let body = serde_json::json!({
            "status": if healthy { "healthy" } else { "unhealthy" },
            "timestamp": rfc3339(SystemTime::now()),
            "listeners": self.listeners,
            "certificate_valid": certificate_valid,
        })
        .to_string()
            + "\n";
        let status = if healthy { 200 } else { 503 };
        *self.cache.lock().unwrap() = Some((Instant::now(), status, body.clone()));
        Reply { status, content_type: "application/json", body }
    }

    /// The relay's own address, dialled as a client dials it, and an auth
    /// message the relay refuses quietly
    async fn dial(&self, url: &str) -> Result<(), String> {
        let (tls, rest) = match url.split_once("://") {
            Some(("rels", r)) => (true, r),
            Some(("rel", r)) => (false, r),
            _ => return Err(format!("invalid instance URL {url}")),
        };
        let authority = rest.split('/').next().unwrap_or(rest);
        let (host, port) = split_host_port(authority, if tls { 443 } else { 80 })?;
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.map_err(|e| e.to_string())?;
        let ws_url = format!("{}://{authority}{}", if tls { "wss" } else { "ws" }, crate::ws::PATH);
        let io: crate::conn::BoxIo = if tls {
            let name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
            let s = tokio_rustls::TlsConnector::from(self.roots.clone())
                .connect(name, tcp)
                .await
                .map_err(|e| e.to_string())?;
            Box::new(s)
        } else {
            Box::new(tcp)
        };
        let (mut ws, _) = tokio_tungstenite::client_async(ws_url, io).await.map_err(|e| e.to_string())?;
        let msg = messages::auth_message(&messages::health_check_peer(), &auth::dummy_token());
        ws.send(Message::Binary(msg.into())).await.map_err(|e| e.to_string())?;
        let _ = ws.close(None).await;
        Ok(())
    }
}

fn split_host_port(authority: &str, default: u16) -> Result<(String, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or("invalid IPv6 address")?;
        let port = after.strip_prefix(':').map_or(Ok(default), |p| p.parse().map_err(|_| "invalid port"))?;
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), p.parse().map_err(|_| format!("invalid port in {authority}"))?)),
        None => Ok((authority.to_string(), default)),
    }
}

/// UTC, to the nanosecond, as Go's time marshals
pub fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:09}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_nanos()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_and_addresses() {
        let t = UNIX_EPOCH + Duration::new(1_792_137_600, 5);
        assert_eq!(rfc3339(t), "2026-10-16T08:00:00.000000005Z");
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(split_host_port("relay01-pt.omnuv.com:443", 80).unwrap(), ("relay01-pt.omnuv.com".into(), 443));
        assert_eq!(split_host_port("example.com", 443).unwrap(), ("example.com".into(), 443));
        assert_eq!(split_host_port("[::1]:8443", 443).unwrap(), ("::1".into(), 8443));
    }
}
