//! The relay itself (`relay/server`): the handshake, the peers by id, each
//! peer's read loop that forwards its transport messages, its health check,
//! and the peer-state notifications a peer subscribes to.
use crate::{
    auth::Validator,
    conn::{self, Accepted, ReadEnd, WriteError, Writer},
    messages::{self, PeerId},
    metrics::Metrics,
};
use bytes::Bytes;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, sync::watch, task::JoinSet};
use tracing::{debug, error, info, warn};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The relay's health check of a peer (`shared/relay/healthcheck`'s sender):
/// a check every `interval`, and the peer closed when `threshold` windows of
/// `interval + timeout` pass with no answer
#[derive(Clone, Copy, Debug)]
pub struct HealthCheckTiming {
    pub interval: Duration,
    pub timeout: Duration,
    pub threshold: u32,
}

impl Default for HealthCheckTiming {
    fn default() -> Self {
        let threshold = std::env::var("NB_RELAY_HC_ATTEMPT_THRESHOLD")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&n: &u32| n > 0)
            .unwrap_or(1);
        Self { interval: Duration::from_secs(25), timeout: Duration::from_secs(20), threshold }
    }
}

/// The peers one peer asked about. One that comes online is said once, and
/// then forgotten for coming online; going offline is said each time
#[derive(Default)]
struct Interest {
    online: HashSet<PeerId>,
    offline: HashSet<PeerId>,
}

struct Listener {
    interest: Mutex<Interest>,
    events: mpsc::UnboundedSender<(PeerId, bool)>,
}

pub struct Peer {
    uid: u64,
    id: PeerId,
    name: String,
    writer: Writer,
    protocol: &'static str,
    closed: Arc<watch::Sender<bool>>,
    quic: Option<quinn::Connection>,
    listener: Arc<Listener>,
    acked: AtomicBool,
    /// Messages read from this peer
    read: AtomicU64,
}

impl Peer {
    fn close(&self) {
        conn::close(&self.closed, self.quic.as_ref());
    }
}

pub struct Relay {
    peers: RwLock<HashMap<PeerId, Arc<Peer>>>,
    listeners: RwLock<HashMap<u64, Arc<Listener>>>,
    validator: Validator,
    auth_response: Bytes,
    instance_url: String,
    pub metrics: Metrics,
    next_uid: AtomicU64,
    closing: AtomicBool,
    health: HealthCheckTiming,
}

impl Relay {
    pub fn new(validator: Validator, instance_url: String, health: HealthCheckTiming) -> Arc<Self> {
        Arc::new(Self {
            peers: RwLock::default(),
            listeners: RwLock::default(),
            validator,
            auth_response: messages::auth_response(&instance_url),
            instance_url,
            metrics: Metrics::default(),
            next_uid: AtomicU64::new(1),
            closing: AtomicBool::new(false),
            health,
        })
    }

    pub fn instance_url(&self) -> &str {
        &self.instance_url
    }

    pub fn peer_count(&self) -> usize {
        self.peers.read().unwrap().len()
    }

    /// The counters, and each QUIC peer's connection as Quinn counts it. A
    /// DATAGRAM Quinn received but the relay never read was dropped from a
    /// full receive queue: `received` less `read`, which nothing else counts
    pub fn render_metrics(&self) -> String {
        use std::fmt::Write;
        let mut s = self.metrics.render();
        let peers: Vec<_> = self.peers.read().unwrap().values().filter(|p| p.quic.is_some()).cloned().collect();
        let rows: Vec<(String, quinn::ConnectionStats, u64)> = peers
            .iter()
            .map(|p| (p.name.clone(), p.quic.as_ref().unwrap().stats(), p.read.load(Ordering::Relaxed)))
            .collect();
        type Series = (&'static str, &'static str, fn(&quinn::ConnectionStats, u64) -> f64);
        let series: [Series; 8] = [
            ("relay_quic_datagrams_received", "DATAGRAM frames Quinn received from the peer", |st, _| {
                st.frame_rx.datagram as f64
            }),
            ("relay_quic_datagrams_read", "Messages the relay read from the peer", |_, r| r as f64),
            ("relay_quic_datagrams_sent", "DATAGRAM frames sent to the peer", |st, _| st.frame_tx.datagram as f64),
            ("relay_quic_packets_sent", "QUIC packets sent to the peer", |st, _| st.path.sent_packets as f64),
            ("relay_quic_packets_lost", "QUIC packets to the peer declared lost", |st, _| st.path.lost_packets as f64),
            ("relay_quic_congestion_events", "Congestion events on the path to the peer", |st, _| {
                st.path.congestion_events as f64
            }),
            ("relay_quic_cwnd_bytes", "Congestion window to the peer", |st, _| st.path.cwnd as f64),
            ("relay_quic_rtt_seconds", "Round trip to the peer", |st, _| st.path.rtt.as_secs_f64()),
        ];
        for (name, help, get) in series {
            let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} gauge");
            for (peer, st, read) in &rows {
                let _ = writeln!(s, "{name}{{peer=\"{peer}\"}} {}", get(st, *read));
            }
        }
        s
    }

    /// Runs one connection from its first message to its close
    pub async fn accept(self: Arc<Self>, mut a: Accepted) {
        let started = Instant::now();
        if self.closing.load(Ordering::Acquire) {
            a.close();
            return;
        }
        let first = match tokio::time::timeout(HANDSHAKE_TIMEOUT, a.reader.read()).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                error!("failed to handshake: read from {}: {e:?}", a.remote);
                self.metrics.handshakes_rejected.fetch_add(1, Ordering::Relaxed);
                a.close();
                return;
            }
            Err(_) => {
                error!("failed to handshake: read from {}: no message in {HANDSHAKE_TIMEOUT:?}", a.remote);
                self.metrics.handshakes_rejected.fetch_add(1, Ordering::Relaxed);
                a.close();
                return;
            }
        };
        let first = &first[..first.len().min(messages::MAX_HANDSHAKE_SIZE)];
        let id = match self.handshake(first) {
            Ok(id) => id,
            Err((id, e)) => {
                if id == Some(messages::health_check_peer()) {
                    debug!("health check connection from {}", a.remote);
                } else {
                    error!("failed to handshake: {e} ({})", a.remote);
                    self.metrics.handshakes_rejected.fetch_add(1, Ordering::Relaxed);
                }
                a.close();
                return;
            }
        };
        // The answer goes before anything another peer sends this one: the
        // client reads its first message as the answer
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, a.writer.write(self.auth_response.clone())).await {
            Ok(Ok(())) => {}
            e => {
                error!("failed to send handshake response to {}: {e:?}", a.remote);
                a.close();
                return;
            }
        }
        let (events, events_rx) = mpsc::unbounded_channel();
        let listener = Arc::new(Listener { interest: Mutex::default(), events });
        let peer = Arc::new(Peer {
            uid: self.next_uid.fetch_add(1, Ordering::Relaxed),
            id,
            name: messages::peer_id_string(&id),
            writer: a.writer.clone(),
            protocol: a.protocol,
            closed: a.closed.clone(),
            quic: a.quic.clone(),
            listener: listener.clone(),
            acked: AtomicBool::new(false),
            // its auth message, which Quinn counted as received too
            read: AtomicU64::new(1),
        });
        info!(peer_id = %peer.name, "peer connected from: {}", a.remote);
        self.listeners.write().unwrap().insert(peer.uid, listener);
        let old = self.peers.write().unwrap().insert(id, peer.clone());
        if let Some(old) = old {
            old.close();
            self.metrics.reconnections.fetch_add(1, Ordering::Relaxed);
        }
        self.peer_came_online(&id);
        self.metrics.peer_connected(peer.protocol);
        self.metrics.record_auth_time(started.elapsed());

        tokio::spawn(self.clone().health_check(peer.clone()));
        tokio::spawn(notify(peer.clone(), events_rx));
        self.read_loop(&peer, a.reader).await;

        self.listeners.write().unwrap().remove(&peer.uid);
        let deleted = {
            let mut peers = self.peers.write().unwrap();
            if peers.get(&peer.id).is_some_and(|p| p.uid == peer.uid) {
                peers.remove(&peer.id);
                true
            } else {
                false
            }
        };
        if deleted {
            self.peer_went_offline(&peer.id);
        }
        peer.close();
        self.metrics.peer_disconnected(peer.protocol);
        debug!(peer_id = %peer.name, "relay connection closed");
    }

    fn handshake(&self, msg: &[u8]) -> Result<PeerId, (Option<PeerId>, String)> {
        match messages::client_type(msg) {
            Ok(messages::AUTH) => {}
            Ok(t) => return Err((None, format!("invalid message type {t}"))),
            Err(e) => return Err((None, e)),
        }
        let (id, token) = messages::parse_auth(msg).map_err(|e| (None, format!("unmarshal auth message: {e}")))?;
        self.validator
            .validate(token)
            .map_err(|e| (Some(id), format!("validate {}: {e}", messages::peer_id_string(&id))))?;
        Ok(id)
    }

    async fn read_loop(&self, peer: &Arc<Peer>, mut reader: conn::Reader) {
        let mut closed = peer.closed.subscribe();
        loop {
            let msg = tokio::select! {
                biased;
                _ = conn::until_closed(&mut closed) => return,
                m = reader.read() => m,
            };
            let msg = match msg {
                Ok(m) => {
                    peer.read.fetch_add(1, Ordering::Relaxed);
                    m
                }
                Err(ReadEnd::Closed) => return,
                Err(ReadEnd::Error(e)) => {
                    error!(peer_id = %peer.name, "failed to read message: {e}");
                    return;
                }
            };
            if msg.is_empty() {
                error!(peer_id = %peer.name, "received empty message");
                return;
            }
            match messages::client_type(&msg) {
                Ok(messages::TRANSPORT) => self.forward(peer, &msg).await,
                Ok(messages::HEALTH_CHECK) => peer.acked.store(true, Ordering::Relaxed),
                Ok(messages::CLOSE) => {
                    info!(peer_id = %peer.name, "peer exited gracefully");
                    return;
                }
                Ok(messages::SUBSCRIBE_PEER_STATE) => self.subscribe(peer, &msg).await,
                Ok(messages::UNSUBSCRIBE_PEER_STATE) => match messages::parse_peer_ids(&msg) {
                    Ok(ids) => {
                        let mut i = peer.listener.interest.lock().unwrap();
                        for id in &ids {
                            i.online.remove(id);
                            i.offline.remove(id);
                        }
                    }
                    Err(e) => error!(peer_id = %peer.name, "failed to unmarshal unsubscribe message: {e}"),
                },
                Ok(t) => warn!(peer_id = %peer.name, "received unexpected message type: {t}"),
                Err(e) => {
                    warn!(peer_id = %peer.name, "failed to determine message type: {e}");
                    return;
                }
            }
        }
    }

    async fn forward(&self, peer: &Peer, msg: &[u8]) {
        self.metrics.received.fetch_add(msg.len() as u64, Ordering::Relaxed);
        let Some(dest) = messages::transport_destination(msg) else {
            error!(peer_id = %peer.name, "failed to unmarshal transport message: invalid message length");
            return;
        };
        let Some(dp) = self.peers.read().unwrap().get(&dest).cloned() else {
            self.metrics.dropped_no_peer.fetch_add(1, Ordering::Relaxed);
            debug!(peer_id = %peer.name, "peer not found: {}", messages::peer_id_string(&dest));
            return;
        };
        let out = messages::relabel_transport(msg, &peer.id);
        let n = out.len() as u64;
        match dp.writer.write(out).await {
            Ok(()) => {
                self.metrics.sent.fetch_add(n, Ordering::Relaxed);
            }
            Err(WriteError::TooLarge) => {
                self.metrics.dropped_too_large.fetch_add(1, Ordering::Relaxed);
                debug!(peer_id = %peer.name, "transport message of {n} bytes too large for {}", dp.name);
            }
            Err(e) => {
                self.metrics.dropped_write_failed.fetch_add(1, Ordering::Relaxed);
                debug!(peer_id = %peer.name, "failed to write transport message to {}: {e:?}", dp.name);
            }
        }
    }

    async fn subscribe(&self, peer: &Peer, msg: &[u8]) {
        let ids = match messages::parse_peer_ids(msg) {
            Ok(ids) => ids,
            Err(e) => {
                error!(peer_id = %peer.name, "failed to unmarshal subscribe message: {e}");
                return;
            }
        };
        debug!(peer_id = %peer.name, "received subscription message for {} peers", ids.len());
        // Under the peers' lock, so a peer coming online now is either listed
        // here or said by the notification
        let online: Vec<PeerId> = {
            let peers = self.peers.read().unwrap();
            let mut i = peer.listener.interest.lock().unwrap();
            for id in &ids {
                i.online.insert(*id);
                i.offline.insert(*id);
            }
            ids.iter().filter(|id| peers.contains_key(*id)).copied().collect()
        };
        for m in messages::peer_id_messages(messages::PEERS_ONLINE, &online) {
            if let Err(e) = peer.writer.write(m).await {
                error!(peer_id = %peer.name, "failed to write peers online message: {e:?}");
            }
        }
    }

    fn peer_came_online(&self, id: &PeerId) {
        for l in self.listeners.read().unwrap().values() {
            if l.interest.lock().unwrap().online.remove(id) {
                let _ = l.events.send((*id, true));
            }
        }
    }

    fn peer_went_offline(&self, id: &PeerId) {
        for l in self.listeners.read().unwrap().values() {
            if l.interest.lock().unwrap().offline.contains(id) {
                let _ = l.events.send((*id, false));
            }
        }
    }

    async fn health_check(self: Arc<Self>, peer: Arc<Peer>) {
        let t = self.health;
        let mut closed = peer.closed.subscribe();
        let start = tokio::time::Instant::now();
        let mut ping = tokio::time::interval_at(start + t.interval, t.interval);
        let window = t.interval + t.timeout;
        let mut check = tokio::time::interval_at(start + window, window);
        let mut failures = 0;
        loop {
            tokio::select! {
                biased;
                _ = conn::until_closed(&mut closed) => return,
                _ = ping.tick() => {
                    if let Err(e) = peer.writer.write(messages::health_check()).await {
                        error!(peer_id = %peer.name, "failed to send healthcheck message: {e:?}");
                        return;
                    }
                }
                _ = check.tick() => {
                    if peer.acked.swap(false, Ordering::Relaxed) {
                        failures = 0;
                        continue;
                    }
                    failures += 1;
                    if failures < t.threshold {
                        warn!(peer_id = %peer.name, "Health check failed attempt {failures}.");
                        continue;
                    }
                    error!(peer_id = %peer.name, "peer healthcheck timeout");
                    peer.close();
                    info!(peer_id = %peer.name, "peer connection closed due healthcheck timeout");
                    return;
                }
            }
        }
    }

    /// Tells every peer the relay is closing, then closes them
    pub async fn shutdown(&self) {
        info!("close connection with all peers");
        self.closing.store(true, Ordering::Release);
        let peers: Vec<_> = self.peers.read().unwrap().values().cloned().collect();
        let mut all = JoinSet::new();
        for p in peers {
            all.spawn(async move {
                let sent = tokio::time::timeout(Duration::from_secs(3), p.writer.write(messages::close())).await;
                if !matches!(sent, Ok(Ok(()))) {
                    error!(peer_id = %p.name, "failed to send close message to peer");
                }
                // A DATAGRAM still queued is lost by the close: wait for the
                // queue to empty, briefly
                if let Some(c) = &p.quic {
                    let full = c.datagram_send_buffer_space();
                    for _ in 0..100 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        if c.datagram_send_buffer_space() >= full {
                            break;
                        }
                    }
                }
                p.close();
            });
        }
        while all.join_next().await.is_some() {}
    }
}

/// Sends a peer what changed among the peers it asked about, as it changes;
/// changes that arrive together go in one message
async fn notify(peer: Arc<Peer>, mut rx: mpsc::UnboundedReceiver<(PeerId, bool)>) {
    let mut closed = peer.closed.subscribe();
    loop {
        let first = tokio::select! {
            biased;
            _ = conn::until_closed(&mut closed) => return,
            e = rx.recv() => match e { Some(e) => e, None => return },
        };
        let (mut online, mut offline) = (Vec::new(), Vec::new());
        let mut next = Some(first);
        while let Some((id, up)) = next {
            if up {
                online.push(id)
            } else {
                offline.push(id)
            }
            next = rx.try_recv().ok();
        }
        for (kind, ids) in [(messages::PEERS_ONLINE, online), (messages::PEERS_WENT_OFFLINE, offline)] {
            for m in messages::peer_id_messages(kind, &ids) {
                match peer.writer.write(m).await {
                    Ok(()) => {}
                    // the peer is leaving
                    Err(WriteError::Closed) => return,
                    Err(e) => error!(peer_id = %peer.name, "failed to write peer state message: {e:?}"),
                }
            }
        }
    }
}
