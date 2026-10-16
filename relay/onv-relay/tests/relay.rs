//! The relay against clients speaking its protocol over both transports,
//! on loopback with a certificate made for the test.
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use onv_relay::{
    auth::Validator,
    messages::{self, PeerId},
    relay::HealthCheckTiming,
    server::{self, Options, Running},
    tls::Resolver,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

const SECRET: &str = "test-secret";
const WAIT: Duration = Duration::from_secs(5);

struct Fixture {
    running: Running,
    roots: rustls::RootCertStore,
    url: String,
}

fn certificate() -> (Arc<rustls::sign::CertifiedKey>, rustls::RootCertStore) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let signer = rustls::crypto::ring::default_provider().key_provider.load_private_key(key).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    (Arc::new(rustls::sign::CertifiedKey::new(vec![der], signer)), roots)
}

/// A port free now on loopback, for an exposed address known before the bind
fn free_port() -> u16 {
    let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = t.local_addr().unwrap().port();
    let _u = std::net::UdpSocket::bind(("127.0.0.1", port)).unwrap();
    port
}

async fn relay(health: HealthCheckTiming) -> Fixture {
    let (key, roots) = certificate();
    let port = free_port();
    let url = format!("rels://localhost:{port}");
    let running = server::start(Options {
        listen: format!("127.0.0.1:{port}"),
        exposed: url.clone(),
        certificate: Some(Arc::new(Resolver::Files(key))),
        secret: SECRET.into(),
        health_listen: Some("127.0.0.1:0".into()),
        metrics_listen: Some("127.0.0.1:0".into()),
        health_check: health,
        health_roots: Some(onv_relay::tls::client_config_with(roots.clone())),
        udp_buffer: 1 << 20,
    })
    .await
    .unwrap();
    Fixture { running, roots, url }
}

fn token() -> Vec<u8> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    Validator::new(SECRET).token(now + 3600)
}

/// A client of either transport, by messages
enum Client {
    Quic { conn: quinn::Connection, _ep: quinn::Endpoint },
    Ws(Box<tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>),
}

impl Client {
    async fn quic(f: &Fixture) -> Self {
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(f.roots.clone())
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"nb-quic".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let conn = ep.connect(f.running.udp.unwrap(), "localhost").unwrap().await.unwrap();
        Client::Quic { conn, _ep: ep }
    }

    async fn ws(f: &Fixture, path: &str) -> Result<Self, String> {
        let tcp = tokio::net::TcpStream::connect(f.running.tcp).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(onv_relay::tls::client_config_with(f.roots.clone()))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        let url = format!("wss://localhost:{}{path}", f.running.tcp.port());
        let (ws, _) = tokio_tungstenite::client_async(url, tls).await.map_err(|e| e.to_string())?;
        Ok(Client::Ws(Box::new(ws)))
    }

    async fn send(&mut self, msg: &[u8]) {
        match self {
            Client::Quic { conn, .. } => conn.send_datagram_wait(Bytes::copy_from_slice(msg)).await.unwrap(),
            Client::Ws(ws) => ws.send(Message::Binary(Bytes::copy_from_slice(msg))).await.unwrap(),
        }
    }

    /// The next message other than a health check, or None once closed
    async fn recv(&mut self) -> Option<Bytes> {
        loop {
            let m = match self {
                Client::Quic { conn, .. } => conn.read_datagram().await.ok()?,
                Client::Ws(ws) => match ws.next().await? {
                    Ok(Message::Binary(b)) => b,
                    Ok(Message::Close(_)) | Err(_) => return None,
                    Ok(_) => continue,
                },
            };
            if m[..] != [messages::VERSION, messages::HEALTH_CHECK] {
                return Some(m);
            }
        }
    }

    async fn recv_timeout(&mut self) -> Option<Bytes> {
        tokio::time::timeout(WAIT, self.recv()).await.expect("no message in time")
    }

    async fn login(&mut self, id: &PeerId, token: &[u8]) -> Option<Bytes> {
        self.send(&messages::auth_message(id, token)).await;
        self.recv_timeout().await
    }
}

async fn logged_in(f: &Fixture, name: &str, quic: bool) -> Client {
    let mut c = if quic { Client::quic(f).await } else { Client::ws(f, "/relay").await.unwrap() };
    let answer = c.login(&messages::hash_id(name), &token()).await.unwrap();
    assert_eq!(answer, messages::auth_response(&f.url));
    c
}

#[tokio::test]
async fn transport_between_every_pair_of_transports() {
    let f = relay(HealthCheckTiming::default()).await;
    for (qa, qb) in [(true, true), (true, false), (false, true), (false, false)] {
        let (an, bn) = (format!("a-{qa}-{qb}"), format!("b-{qa}-{qb}"));
        let (ida, idb) = (messages::hash_id(&an), messages::hash_id(&bn));
        let mut a = logged_in(&f, &an, qa).await;
        let mut b = logged_in(&f, &bn, qb).await;
        for i in 0..50u32 {
            let payload = i.to_be_bytes().repeat(250);
            a.send(&messages::transport(&idb, &payload)).await;
            let got = b.recv_timeout().await.unwrap();
            assert_eq!(got, Bytes::from(messages::transport(&ida, &payload)), "a→b {qa} {qb} #{i}");
            b.send(&messages::transport(&ida, &payload)).await;
            let got = a.recv_timeout().await.unwrap();
            assert_eq!(got, Bytes::from(messages::transport(&idb, &payload)), "b→a {qa} {qb} #{i}");
        }
    }
    let m = f.running.relay.metrics.render();
    // 4 pairs, 50 each way: 400 messages of 38 + 1,000 bytes
    assert!(m.contains("relay_transfer_sent_bytes_total 415200\n"), "{m}");
    f.running.shutdown().await;
}

#[tokio::test]
async fn refused_handshakes_close_the_connection() {
    let f = relay(HealthCheckTiming::default()).await;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    for (quic, token) in [
        (true, Validator::new("wrong").token(now + 3600)),
        (false, Validator::new("wrong").token(now + 3600)),
        (true, Validator::new(SECRET).token(now - 10)),
        (false, vec![1, 2, 3]),
    ] {
        let mut c = if quic { Client::quic(&f).await } else { Client::ws(&f, "/relay").await.unwrap() };
        assert_eq!(c.login(&messages::hash_id("x"), &token).await, None);
    }
    // A first message that is not an auth message
    let mut c = Client::quic(&f).await;
    c.send(&messages::transport(&messages::hash_id("x"), b"hi")).await;
    assert_eq!(c.recv_timeout().await, None);
    assert_eq!(f.running.relay.peer_count(), 0);
    assert!(f.running.relay.metrics.render().contains("relay_handshakes_rejected_total 5"));
    f.running.shutdown().await;
}

#[tokio::test]
async fn websocket_upgrades_on_relay_alone() {
    let f = relay(HealthCheckTiming::default()).await;
    let e = Client::ws(&f, "/other").await.err().unwrap();
    assert!(e.contains("404"), "{e}");
    f.running.shutdown().await;
}

#[tokio::test]
async fn peer_state_subscription() {
    let f = relay(HealthCheckTiming::default()).await;
    let (b, c) = (messages::hash_id("b"), messages::hash_id("c"));
    let mut pa = logged_in(&f, "a", true).await;
    let _pb = logged_in(&f, "b", false).await;
    for m in messages::peer_id_messages(messages::SUBSCRIBE_PEER_STATE, &[b, c]) {
        pa.send(&m).await;
    }
    // b is online: said at once; c is not
    assert_eq!(pa.recv_timeout().await.unwrap(), messages::peer_id_messages(messages::PEERS_ONLINE, &[b])[0]);
    let mut pc = logged_in(&f, "c", true).await;
    assert_eq!(pa.recv_timeout().await.unwrap(), messages::peer_id_messages(messages::PEERS_ONLINE, &[c])[0]);
    pc.send(&[messages::VERSION, messages::CLOSE]).await;
    assert_eq!(pc.recv_timeout().await, None);
    assert_eq!(pa.recv_timeout().await.unwrap(), messages::peer_id_messages(messages::PEERS_WENT_OFFLINE, &[c])[0]);
    // Unsubscribed, b's leaving is not said
    for m in messages::peer_id_messages(messages::UNSUBSCRIBE_PEER_STATE, &[b]) {
        pa.send(&m).await;
    }
    // A message to itself, read after the unsubscription: once it is back,
    // the relay has the unsubscription
    let a = messages::hash_id("a");
    pa.send(&messages::transport(&a, b"barrier")).await;
    assert_eq!(&pa.recv_timeout().await.unwrap()[38..], b"barrier");
    drop(_pb);
    let late = tokio::time::timeout(Duration::from_millis(500), pa.recv()).await;
    assert!(late.is_err(), "{late:?}");
    f.running.shutdown().await;
}

#[tokio::test]
async fn reconnection_closes_the_earlier_connection() {
    let f = relay(HealthCheckTiming::default()).await;
    let mut first = logged_in(&f, "same", true).await;
    let mut second = logged_in(&f, "same", false).await;
    assert_eq!(first.recv_timeout().await, None);
    let mut other = logged_in(&f, "other", true).await;
    other.send(&messages::transport(&messages::hash_id("same"), b"to the second")).await;
    assert_eq!(&second.recv_timeout().await.unwrap()[38..], b"to the second");
    assert_eq!(f.running.relay.peer_count(), 2);
    assert!(f.running.relay.metrics.render().contains("relay_peer_reconnections_total 1"));
    f.running.shutdown().await;
}

#[tokio::test]
async fn health_check_closes_a_silent_peer() {
    let timing =
        HealthCheckTiming { interval: Duration::from_millis(200), timeout: Duration::from_millis(200), threshold: 1 };
    let f = relay(timing).await;
    let mut silent = logged_in(&f, "silent", true).await;
    let mut answering = logged_in(&f, "answering", false).await;
    let started = std::time::Instant::now();
    // The silent one never answers: closed after its first unanswered window
    let closed = tokio::time::timeout(WAIT, silent.recv()).await.unwrap();
    assert_eq!(closed, None);
    assert!(started.elapsed() >= Duration::from_millis(350), "{:?}", started.elapsed());
    // The answering one is still there two seconds on
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let Client::Ws(ws) = &mut answering else { unreachable!() };
        match tokio::time::timeout(Duration::from_millis(100), ws.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) if b[..] == [1, 5] => {
                ws.send(Message::Binary(Bytes::from_static(&[1, 5]))).await.unwrap();
            }
            Ok(other) => panic!("unexpected {other:?}"),
            Err(_) => {}
        }
    }
    assert_eq!(f.running.relay.peer_count(), 1);
    f.running.shutdown().await;
}

#[tokio::test]
async fn unknown_message_types_close_the_peer() {
    let f = relay(HealthCheckTiming::default()).await;
    let mut a = logged_in(&f, "a", true).await;
    a.send(&[messages::VERSION, messages::AUTH]).await; // known, unexpected: kept
    a.send(&[messages::VERSION, messages::HELLO]).await; // not a client type: closed
    assert_eq!(a.recv_timeout().await, None);
    f.running.shutdown().await;
}

#[tokio::test]
async fn shutdown_tells_every_peer() {
    let f = relay(HealthCheckTiming::default()).await;
    let mut a = logged_in(&f, "a", true).await;
    let mut b = logged_in(&f, "b", false).await;
    f.running.shutdown().await;
    assert_eq!(a.recv_timeout().await.unwrap(), messages::close());
    assert_eq!(b.recv_timeout().await.unwrap(), messages::close());
}

async fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let status = out[9..12].parse().unwrap();
    (status, out.split_once("\r\n\r\n").unwrap().1.to_string())
}

#[tokio::test]
async fn health_and_metrics_endpoints() {
    let f = relay(HealthCheckTiming::default()).await;
    let (status, body) = get(f.running.health.unwrap(), "/health").await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "healthy");
    assert_eq!(v["listeners"], serde_json::json!(["ws", "quic"]));
    assert_eq!(v["certificate_valid"], true);
    // The health check's own dial is refused quietly, not counted
    assert!(f.running.relay.metrics.render().contains("relay_handshakes_rejected_total 0"));
    assert_eq!(get(f.running.health.unwrap(), "/other").await.0, 404);
    let (status, body) = get(f.running.metrics.unwrap(), "/metrics").await;
    assert_eq!(status, 200);
    assert!(body.contains("# TYPE relay_peers gauge"), "{body}");
    f.running.shutdown().await;
}

#[tokio::test]
async fn health_is_unhealthy_when_its_dial_fails() {
    // Trusting nothing, the relay's own dial fails its certificate
    let (key, _) = certificate();
    let port = free_port();
    let running = server::start(Options {
        listen: format!("127.0.0.1:{port}"),
        exposed: format!("localhost:{port}"),
        certificate: Some(Arc::new(Resolver::Files(key))),
        secret: SECRET.into(),
        health_listen: Some("127.0.0.1:0".into()),
        metrics_listen: None,
        health_check: HealthCheckTiming::default(),
        health_roots: Some(onv_relay::tls::client_config_with(rustls::RootCertStore::empty())),
        udp_buffer: 1 << 20,
    })
    .await
    .unwrap();
    let (status, body) = get(running.health.unwrap(), "/health").await;
    assert_eq!(status, 503, "{body}");
    assert!(body.contains("\"certificate_valid\":false"), "{body}");
    running.shutdown().await;
}

#[test]
fn autocert_cache_is_read_as_go_writes_it() {
    // autocert's DirCache file: the key as "EC PRIVATE KEY" (SEC 1), then the
    // chain. The fixture's key was made for this test and guards nothing
    let dir = std::env::temp_dir().join(format!("onv-relay-autocert-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("letsencrypt")).unwrap();
    std::fs::write(dir.join("letsencrypt").join("relay.example"), include_str!("autocert-cache.pem")).unwrap();
    std::fs::write(dir.join("letsencrypt").join("broken.example"), "not pem").unwrap();
    let provider = rustls::crypto::ring::default_provider();
    let got = onv_relay::tls::autocert_cached(&dir, "relay.example", &provider).expect("read");
    let want: Vec<_> =
        CertificateDer::pem_slice_iter(include_bytes!("autocert-cache.pem")).collect::<Result<_, _>>().unwrap();
    assert_eq!(got.cert, want);
    assert!(onv_relay::tls::autocert_cached(&dir, "other.example", &provider).is_none());
    assert!(onv_relay::tls::autocert_cached(&dir, "broken.example", &provider).is_none());
    std::fs::remove_dir_all(&dir).unwrap();
}
