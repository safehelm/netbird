//! Experimental Quinn transport for the Go relay. No Go pointer survives an FFI call.
use bytes::Bytes;
use quinn::{
    Connection, Endpoint, ServerConfig, TransportConfig, VarInt, crypto::rustls::QuicServerConfig,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    collections::{HashMap, VecDeque},
    future::{Future, poll_fn},
    panic::{AssertUnwindSafe, catch_unwind},
    pin::pin,
    slice,
    sync::{
        Arc, LazyLock, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
    time::{Duration, Instant},
};
use tokio::{
    runtime::Runtime,
    sync::{Mutex as AsyncMutex, mpsc, watch},
    task::JoinSet,
};

struct CountingAllocator;
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
// SAFETY: Allocation and deallocation use System with the original layouts.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            LIVE_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.dealloc(p, layout) };
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(p, layout, size) };
        if !next.is_null() {
            ALLOC_BYTES.fetch_add(size as u64, Ordering::Relaxed);
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            LIVE_BYTES.fetch_add(size as u64, Ordering::Relaxed);
            LIVE_BYTES.fetch_sub(layout.size() as u64, Ordering::Relaxed);
        }
        next
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    let workers = std::env::var("NB_RELAY_QUINN_WORKERS")
        .ok()
        .map(|v| v.parse::<usize>().expect("invalid NB_RELAY_QUINN_WORKERS"))
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .thread_name("onv-quinn")
        .build()
        .expect("Quinn runtime")
});
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static SERVERS: LazyLock<Mutex<HashMap<u64, Arc<Server>>>> = LazyLock::new(Mutex::default);
static CONNECTIONS: LazyLock<Mutex<HashMap<u64, Arc<Session>>>> = LazyLock::new(Mutex::default);
#[derive(Default)]
struct Handshakes {
    rejected: AtomicU64,
    last_error: Mutex<String>,
}
/// The certificate a listener presents. It starts empty when the caller has none
/// yet, and is replaced while the listener runs (a renewal).
#[derive(Debug, Default)]
struct Certificate(RwLock<Option<Arc<CertifiedKey>>>);
impl ResolvesServerCert for Certificate {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.read().unwrap().clone()
    }
}
/// A chain and its PKCS #8 key, or nothing when both are empty.
fn certified(b: &mut &[u8]) -> Result<Option<Arc<CertifiedKey>>, String> {
    let mut certs = Vec::new();
    loop {
        let cert = blob(b)?;
        if cert.is_empty() {
            break;
        };
        certs.push(CertificateDer::from(cert.to_vec()));
    }
    let key = blob(b)?;
    if certs.is_empty() {
        return if key.is_empty() {
            Ok(None)
        } else {
            Err("a key with no certificate".into())
        };
    }
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.to_vec()));
    let signer = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| e.to_string())?;
    let certified = CertifiedKey::new(certs, signer);
    certified.keys_match().map_err(|e| e.to_string())?;
    Ok(Some(Arc::new(certified)))
}
struct Server {
    certificate: Arc<Certificate>,
    handshakes: Arc<Handshakes>,
    endpoint: Endpoint,
    accepted: AsyncMutex<mpsc::Receiver<Connection>>,
    stop: watch::Sender<bool>,
    task: AsyncMutex<Option<tokio::task::JoinHandle<()>>>,
}
static ASYNC_SEND: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("NB_RELAY_QUINN_ASYNC_SEND")
        .map(|v| v.parse::<bool>().expect("invalid NB_RELAY_QUINN_ASYNC_SEND"))
        .unwrap_or(true)
});
static BATCH_READ: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("NB_RELAY_QUINN_BATCH_READ")
        .map(|v| v.parse::<bool>().expect("invalid NB_RELAY_QUINN_BATCH_READ"))
        .unwrap_or(true)
});
/// Bytes of datagrams a connection holds received and not yet read, and
/// queued and not yet sent; NB_RELAY_QUINN_DATAGRAM_RECV_BYTES and _SEND_BYTES
/// set them. At a relay's round trip (12 ms to the providers' site) the
/// sender's leg runs ahead of the receiver's while its window grows, and what
/// a full receive queue cannot hold Quinn drops: 115 kB lost 0.2% of a 150
/// Mbit/s stream, which the TCP inside reads as congestion.
fn datagram_bytes(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n >= 64 * 1024)
        .unwrap_or(default)
}
static DATAGRAM_RECV_BYTES: LazyLock<usize> =
    LazyLock::new(|| datagram_bytes("NB_RELAY_QUINN_DATAGRAM_RECV_BYTES", 4 << 20));
static DATAGRAM_SEND_BYTES: LazyLock<usize> =
    LazyLock::new(|| datagram_bytes("NB_RELAY_QUINN_DATAGRAM_SEND_BYTES", 1 << 20));
static CALL_TIMING: LazyLock<bool> =
    LazyLock::new(|| std::env::var("NB_RELAY_QUINN_TIMING").is_ok_and(|v| v == "1"));
#[derive(Default)]
struct PumpStats {
    batches: AtomicU64,
    max_batch: AtomicU64,
    errors: AtomicU64,
}
struct Session {
    closed: AtomicBool,
    tx: mpsc::Sender<Bytes>,
    tx_stop: watch::Sender<bool>,
    tx_task: AsyncMutex<Option<tokio::task::JoinHandle<()>>>,
    pump: Arc<PumpStats>,
    conn: Connection,
    peer: std::net::SocketAddr,
    owner: Arc<Server>,
    read: AtomicU64,
    written: AtomicU64,
    write_timeouts: AtomicU64,
    read_waiters: AtomicU64,
    read_ns: AtomicU64,
    cache: AsyncMutex<VecDeque<Bytes>>,
    read_batches: AtomicU64,
    write_ns: AtomicU64,
}
struct CallTimer<'a>(Option<(Instant, &'a AtomicU64)>);
impl<'a> CallTimer<'a> {
    fn new(counter: &'a AtomicU64) -> Self {
        Self(if *CALL_TIMING {
            Some((Instant::now(), counter))
        } else {
            None
        })
    }
}
impl Drop for CallTimer<'_> {
    fn drop(&mut self) {
        if let Some((started, counter)) = self.0 {
            counter.fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
    }
}
struct CounterGuard<'a>(&'a AtomicU64);
impl<'a> CounterGuard<'a> {
    fn new(counter: &'a AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}
impl Drop for CounterGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
async fn pump_datagrams(
    conn: Connection,
    mut rx: mpsc::Receiver<Bytes>,
    mut stop: watch::Receiver<bool>,
    stats: Arc<PumpStats>,
) {
    let mut batch = Vec::with_capacity(8);
    loop {
        let first = tokio::select! {biased;_=stop.changed()=>return,data=rx.recv()=>{let Some(data)=data else{return};data}};
        batch.push(first);
        while batch.len() < 8 {
            match rx.try_recv() {
                Ok(data) => batch.push(data),
                Err(_) => break,
            }
        }
        while !batch.is_empty() {
            if *stop.borrow() {
                return;
            }
            let space = conn.datagram_send_buffer_space();
            let mut bytes = 0;
            let mut ready = 0;
            for data in &batch {
                if bytes + data.len() > space {
                    break;
                }
                bytes += data.len();
                ready += 1;
            }
            let result = if ready == 0 {
                let data = batch.remove(0);
                tokio::select! {biased;_=stop.changed()=>return,result=conn.send_datagram_wait(data)=>result.map(|()|1)}
            } else {
                // This task is the sole DATAGRAM producer on this connection.
                // Only packetization can change send-buffer space between the
                // check and the sends, and that can only increase free space,
                // so send_datagram never drops an older queued message here.
                let mut result = Ok(0);
                for data in batch.drain(..ready) {
                    if let Err(e) = conn.send_datagram(data) {
                        result = Err(e);
                        break;
                    }
                    result = result.map(|n| n + 1);
                }
                result
            };
            match result {
                Ok(n) => {
                    stats.batches.fetch_add(1, Ordering::Relaxed);
                    stats.max_batch.fetch_max(n as u64, Ordering::Relaxed);
                }
                Err(_) => {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    conn.close(1u32.into(), b"native datagram sender failed");
                    return;
                }
            }
        }
    }
}
fn server(id: u64) -> Option<Arc<Server>> {
    SERVERS.lock().unwrap().get(&id).cloned()
}
fn session(id: u64) -> Option<Arc<Session>> {
    CONNECTIONS.lock().unwrap().get(&id).cloned()
}
fn boundary<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}
fn input<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(p, n) }
    }
}
fn output(p: *mut u8, cap: usize, data: &[u8]) -> i64 {
    let n = cap.min(data.len());
    if n > 0 {
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), p, n) };
    }
    n as i64
}
fn blob<'a>(b: &mut &'a [u8]) -> Result<&'a [u8], String> {
    if b.len() < 4 {
        return Err("short configuration".into());
    }
    let n = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
    *b = &b[4..];
    if n > b.len() {
        return Err("short configuration field".into());
    }
    let (v, rest) = b.split_at(n);
    *b = rest;
    Ok(v)
}
fn listen(data: &[u8]) -> Result<Arc<Server>, String> {
    let mut b = data;
    let address = std::str::from_utf8(blob(&mut b)?)
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let certificate = Arc::new(Certificate(RwLock::new(certified(&mut b)?)));
    let mut alpn = Vec::new();
    loop {
        let p = blob(&mut b)?;
        if p.is_empty() {
            break;
        };
        alpn.push(p.to_vec());
    }
    if !b.is_empty() || alpn.is_empty() {
        return Err("invalid TLS configuration".into());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(certificate.clone());
    tls.alpn_protocols = alpn;
    tls.send_tls13_tickets = 0;
    tls.max_early_data_size = 0;
    let crypto = QuicServerConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut transport = TransportConfig::default();
    transport.initial_mtu(1232).max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .map_err(|e| format!("{e}"))?,
    ));
    transport
        .datagram_receive_buffer_size(Some(*DATAGRAM_RECV_BYTES))
        .datagram_send_buffer_size(*DATAGRAM_SEND_BYTES);
    transport.congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default()));
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    let _entered = RUNTIME.enter();
    let endpoint = Endpoint::server(config, address).map_err(|e| e.to_string())?;
    let (tx, rx) = mpsc::channel(128);
    let (stop, mut stopped) = watch::channel(false);
    let ep = endpoint.clone();
    let handshakes = Arc::new(Handshakes::default());
    let handshake_stats = handshakes.clone();
    let task=RUNTIME.spawn(async move {
        let mut pending=JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _=stopped.changed()=>break,
                Some(_)=pending.join_next(), if !pending.is_empty()=>{},
                incoming=ep.accept()=> {
                    let Some(incoming)=incoming else {break};
                    if pending.len()>=256 {incoming.refuse();continue;}
                    let tx=tx.clone();let mut stopped=stopped.clone();let failures=handshake_stats.clone();
                    pending.spawn(async move {
                        tokio::select! {
                            biased;
                            _=stopped.changed()=>{},
                            c=incoming=>{match c {Ok(c)=>{tokio::select!{biased;_=stopped.changed()=>c.close(0u32.into(),b"listener stopped"),result=tx.send(c.clone())=>{if result.is_err(){c.close(0u32.into(),b"listener stopped")}}}},Err(e)=>{failures.rejected.fetch_add(1,Ordering::Relaxed);*failures.last_error.lock().unwrap()=e.to_string();}}}
                        }
                    });
                }
            }
        }
        pending.abort_all();while pending.join_next().await.is_some(){}
    });
    Ok(Arc::new(Server {
        certificate,
        handshakes,
        endpoint,
        accepted: AsyncMutex::new(rx),
        stop,
        task: AsyncMutex::new(Some(task)),
    }))
}

/// Returns the C ABI version implemented by this library.
#[unsafe(no_mangle)]
pub extern "C" fn onv_quinn_abi_version() -> u64 {
    2
}
/// Replaces the certificate a listener presents to handshakes from now on.
/// Returns 0, -1 for an unknown listener, or -3 with details in the error buffer.
/// # Safety
/// Input and output pointers must refer to valid buffers for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onv_quinn_set_certificate(
    id: u64,
    p: *const u8,
    n: usize,
    err: *mut u8,
    cap: usize,
) -> i64 {
    boundary(-6, || {
        let Some(s) = server(id) else {
            return -1;
        };
        let mut b = input(p, n);
        match certified(&mut b) {
            Ok(Some(c)) if b.is_empty() => {
                *s.certificate.0.write().unwrap() = Some(c);
                0
            }
            Ok(_) => {
                output(err, cap, b"no certificate, or bytes after it");
                -3
            }
            Err(e) => {
                output(err, cap, e.as_bytes());
                -3
            }
        }
    })
}
/// Binds a server; error details are copied to the caller's error buffer.
/// # Safety
/// Input and output pointers must refer to valid buffers for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onv_quinn_listen(p: *const u8, n: usize, err: *mut u8, cap: usize) -> u64 {
    boundary(0, || match listen(input(p, n)) {
        Ok(s) => {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            SERVERS.lock().unwrap().insert(id, s);
            id
        }
        Err(e) => {
            output(err, cap, e.as_bytes());
            0
        }
    })
}
/// Copies the bound server address to a caller-owned buffer.
/// # Safety
/// The output buffer must be valid for cap bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onv_quinn_address(id: u64, p: *mut u8, cap: usize) -> i64 {
    boundary(-6, || {
        server(id)
            .and_then(|s| s.endpoint.local_addr().ok())
            .map(|a| output(p, cap, a.to_string().as_bytes()))
            .unwrap_or(-1)
    })
}
/// Accepts an established connection, returning zero on timeout and -1 after close.
#[unsafe(no_mangle)]
pub extern "C" fn onv_quinn_accept(id: u64, millis: u64) -> i64 {
    boundary(-6, || {
        let Some(s) = server(id) else { return -1 };
        if *s.stop.borrow() {
            return -1;
        }
        RUNTIME.block_on(async {
            let mut accepted = s.accepted.lock().await;
            match tokio::time::timeout(Duration::from_millis(millis), accepted.recv()).await {
                Err(_) => 0,
                Ok(None) => -1,
                Ok(Some(c)) => {
                    if *s.stop.borrow() {
                        c.close(0u32.into(), b"listener stopped");
                        return -1;
                    }
                    let peer = c.remote_address();
                    let (tx, rx) = mpsc::channel(8);
                    let (tx_stop, stopped) = watch::channel(false);
                    let pump = Arc::new(PumpStats::default());
                    let tx_task = if *ASYNC_SEND {
                        Some(RUNTIME.spawn(pump_datagrams(c.clone(), rx, stopped, pump.clone())))
                    } else {
                        drop(rx);
                        None
                    };
                    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                    CONNECTIONS.lock().unwrap().insert(
                        id,
                        Arc::new(Session {
                            closed: AtomicBool::new(false),
                            tx,
                            tx_stop,
                            tx_task: AsyncMutex::new(tx_task),
                            pump,
                            conn: c,
                            peer,
                            owner: s.clone(),
                            read: AtomicU64::new(0),
                            written: AtomicU64::new(0),
                            write_timeouts: AtomicU64::new(0),
                            read_waiters: AtomicU64::new(0),
                            read_ns: AtomicU64::new(0),
                            cache: AsyncMutex::new(VecDeque::with_capacity(32)),
                            read_batches: AtomicU64::new(0),
                            write_ns: AtomicU64::new(0),
                        }),
                    );
                    id as i64
                }
            }
        })
    })
}
/// Copies the peer address to a caller-owned buffer.
/// # Safety
/// The output buffer must be valid for cap bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onv_quinn_remote(id: u64, p: *mut u8, cap: usize) -> i64 {
    boundary(-6, || {
        session(id)
            .map(|s| output(p, cap, s.peer.to_string().as_bytes()))
            .unwrap_or(-1)
    })
}
/// Receives one DATAGRAM; -2 means the cancellable wait timed out.
/// # Safety
/// The output buffer must be valid for cap bytes and exclusive during this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onv_quinn_read(id: u64, p: *mut u8, cap: usize, millis: u64) -> i64 {
    boundary(-6, || {
        let Some(s) = session(id) else { return -1 };
        let _timer = CallTimer::new(&s.read_ns);
        let _waiter = CounterGuard::new(&s.read_waiters);
        RUNTIME.block_on(async {
            match tokio::time::timeout(Duration::from_millis(millis), async {
                if !*BATCH_READ {
                    return s.conn.read_datagram().await;
                }
                let mut cache = s.cache.lock().await;
                if cache.is_empty() {
                    // Wait for one, then take up to 31 more that are already
                    // queued, each polled once: Quinn has no batch read, and a
                    // read polled once and dropped takes nothing off the queue.
                    cache.push_back(s.conn.read_datagram().await?);
                    while cache.len() < 32 {
                        let mut next = pin!(s.conn.read_datagram());
                        match poll_fn(|cx| Poll::Ready(next.as_mut().poll(cx))).await {
                            Poll::Ready(Ok(data)) => cache.push_back(data),
                            _ => break,
                        }
                    }
                    s.read_batches.fetch_add(1, Ordering::Relaxed);
                }
                Ok(cache.pop_front().expect("nonempty datagram batch"))
            })
            .await
            {
                Err(_) => -2,
                Ok(Err(_)) => -1,
                Ok(Ok(data)) => {
                    s.read.fetch_add(1, Ordering::Relaxed);
                    output(p, cap, &data)
                }
            }
        })
    })
}
/// Sends one DATAGRAM with backpressure; -2 means no packet was queued before timeout.
/// # Safety
/// Input must remain valid and immutable until this call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onv_quinn_write(id: u64, p: *const u8, n: usize, millis: u64) -> i64 {
    boundary(-6, || {
        let Some(s) = session(id) else { return -1 };
        let _timer = CallTimer::new(&s.write_ns);
        if *ASYNC_SEND {
            if s.closed.load(Ordering::Acquire) {
                return -1;
            }
            // Asked each time: path MTU discovery raises it after the
            // handshake, above the 1,195 bytes a connection starts with
            let Some(max) = s.conn.max_datagram_size() else {
                return -4;
            };
            if n > max {
                return -3;
            }
            let data = Bytes::copy_from_slice(input(p, n));
            return RUNTIME.block_on(async {
                match tokio::time::timeout(Duration::from_millis(millis), s.tx.reserve()).await {
                    Err(_) => {
                        s.write_timeouts.fetch_add(1, Ordering::Relaxed);
                        -2
                    }
                    Ok(Err(_)) => -1,
                    Ok(Ok(permit)) => {
                        if s.closed.load(Ordering::Acquire) {
                            return -1;
                        }
                        permit.send(data);
                        s.written.fetch_add(1, Ordering::Relaxed);
                        n as i64
                    }
                }
            });
        }
        let data = Bytes::copy_from_slice(input(p, n));
        RUNTIME.block_on(async {
            match tokio::time::timeout(
                Duration::from_millis(millis),
                s.conn.send_datagram_wait(data),
            )
            .await
            {
                Err(_) => {
                    s.write_timeouts.fetch_add(1, Ordering::Relaxed);
                    -2
                }
                Ok(Err(quinn::SendDatagramError::TooLarge)) => -3,
                Ok(Err(
                    quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled,
                )) => -4,
                Ok(Err(_)) => -1,
                Ok(Ok(())) => {
                    s.written.fetch_add(1, Ordering::Relaxed);
                    n as i64
                }
            }
        })
    })
}
/// Closes a connection; other in-flight calls retain safe Arc references.
#[unsafe(no_mangle)]
pub extern "C" fn onv_quinn_close(id: u64) -> i64 {
    boundary(-6, || {
        if let Some(s) = CONNECTIONS.lock().unwrap().remove(&id) {
            s.closed.store(true, Ordering::Release);
            s.tx_stop.send_replace(true);
            s.conn.close(VarInt::from_u32(0), b"normal closure");
            RUNTIME.block_on(async {
                if let Some(task) = s.tx_task.lock().await.take() {
                    let _ = task.await;
                }
            });
        }
        0
    })
}
/// Stops accepting while leaving already accepted sessions alive.
#[unsafe(no_mangle)]
pub extern "C" fn onv_quinn_stop(id: u64) -> i64 {
    boundary(-6, || {
        let Some(s) = SERVERS.lock().unwrap().remove(&id) else {
            return 0;
        };
        s.stop.send_replace(true);
        s.endpoint.set_server_config(None);
        RUNTIME.block_on(async {
            {
                let mut rx = s.accepted.lock().await;
                rx.close();
                while let Ok(c) = rx.try_recv() {
                    c.close(0u32.into(), b"listener stopped");
                }
            }
            if let Some(task) = s.task.lock().await.take() {
                let _ = task.await;
            }
        });
        0
    })
}
/// Copies JSON counters; returns -5 if the caller's buffer is too small.
/// # Safety
/// The output buffer must be valid for cap bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onv_quinn_stats(p: *mut u8, cap: usize) -> i64 {
    boundary(-6, || {
        let sessions: Vec<_> = CONNECTIONS
            .lock()
            .unwrap()
            .iter()
            .map(|(id, s)| (*id, s.clone()))
            .collect();
        let conns:Vec<_>=sessions.iter().map(|(id,s)|{let stats=s.conn.stats();serde_json::json!({"id":id,"local":s.owner.endpoint.local_addr().ok().map(|a|a.to_string()),"remote":s.peer.to_string(),"async_send":*ASYNC_SEND,"tx_batches":s.pump.batches.load(Ordering::Relaxed),"tx_max_batch":s.pump.max_batch.load(Ordering::Relaxed),"tx_errors":s.pump.errors.load(Ordering::Relaxed),"read_batches":s.read_batches.load(Ordering::Relaxed),"batch_read":*BATCH_READ,"read_ns":s.read_ns.load(Ordering::Relaxed),"write_ns":s.write_ns.load(Ordering::Relaxed),"path":serde_json::json!({"rtt_us":stats.path.rtt.as_micros() as u64,"cwnd":stats.path.cwnd,"lost_packets":stats.path.lost_packets,"congestion_events":stats.path.congestion_events,"mtu":stats.path.current_mtu}),"read_waiters":s.read_waiters.load(Ordering::Relaxed),"read":s.read.load(Ordering::Relaxed),"written":s.written.load(Ordering::Relaxed),"write_timeouts":s.write_timeouts.load(Ordering::Relaxed),"frame_rx":stats.frame_rx.datagram,"frame_tx":stats.frame_tx.datagram,"udp_rx":stats.udp_rx.datagrams,"udp_tx":stats.udp_tx.datagrams})}).collect();
        let listeners:Vec<_>=SERVERS.lock().unwrap().values().map(|s|serde_json::json!({"local":s.endpoint.local_addr().ok().map(|a|a.to_string()),"rejected_handshakes":s.handshakes.rejected.load(Ordering::Relaxed),"last_handshake_error":s.handshakes.last_error.lock().unwrap().clone()})).collect();
        let data=serde_json::json!({"connections":conns,"listeners":listeners,"servers":SERVERS.lock().unwrap().len(),"rust_allocated_bytes":ALLOC_BYTES.load(Ordering::Relaxed),"rust_allocations":ALLOC_COUNT.load(Ordering::Relaxed),"rust_live_bytes":LIVE_BYTES.load(Ordering::Relaxed)}).to_string();
        if data.len() > cap {
            return -5;
        }
        output(p, cap, data.as_bytes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_configuration_does_not_bind() {
        for bytes in [&[][..], &[0, 0, 0][..], &[0xff, 0xff, 0xff, 0xff][..]] {
            let mut error = [0u8; 128];
            let id = unsafe {
                onv_quinn_listen(bytes.as_ptr(), bytes.len(), error.as_mut_ptr(), error.len())
            };
            assert_eq!(id, 0);
            assert!(error.iter().any(|b| *b != 0));
        }
        assert!(SERVERS.lock().unwrap().is_empty());
    }
    #[test]
    fn invalid_handles_and_repeated_close_are_safe() {
        assert_eq!(onv_quinn_close(u64::MAX), 0);
        assert_eq!(onv_quinn_close(u64::MAX), 0);
        assert_eq!(onv_quinn_stop(u64::MAX), 0);
        assert_eq!(onv_quinn_accept(u64::MAX, 1), -1);
        let mut error = [0u8; 16];
        assert_eq!(
            unsafe { onv_quinn_set_certificate(u64::MAX, [].as_ptr(), 0, error.as_mut_ptr(), error.len()) },
            -1
        );
        let mut b = [0u8; 1];
        assert_eq!(
            unsafe { onv_quinn_read(u64::MAX, b.as_mut_ptr(), b.len(), 1) },
            -1
        );
    }
}
