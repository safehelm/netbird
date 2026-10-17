//! One accepted connection, QUIC or WebSocket: its reading half, its writing
//! half, and the signal that closes it. A message is one QUIC DATAGRAM or one
//! WebSocket binary message.
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt, stream::SplitStream};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Error as WsError, Message, error::ProtocolError},
};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}
pub type BoxIo = Box<dyn Io>;
pub type Ws = WebSocketStream<BoxIo>;

/// A WebSocket write, or a batch of them, that has not finished in this long
/// closes the connection (the Go listener's writeTimeout)
const WS_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Messages queued for one WebSocket peer before its senders wait
const WS_QUEUE: usize = 1024;

#[derive(Debug, PartialEq)]
pub enum ReadEnd {
    /// Closed by either side, normally
    Closed,
    Error(String),
}

#[derive(Debug, PartialEq)]
pub enum WriteError {
    Closed,
    /// Larger than the connection's DATAGRAM budget
    TooLarge,
    Unsupported,
}

pub enum Reader {
    Quic(quinn::Connection),
    Ws(SplitStream<Ws>),
}

impl Reader {
    pub async fn read(&mut self) -> Result<Bytes, ReadEnd> {
        match self {
            Reader::Quic(c) => c.read_datagram().await.map_err(|e| match e {
                quinn::ConnectionError::ApplicationClosed(ref a) if a.error_code == quinn::VarInt::from_u32(0) => {
                    ReadEnd::Closed
                }
                quinn::ConnectionError::LocallyClosed => ReadEnd::Closed,
                e => ReadEnd::Error(e.to_string()),
            }),
            Reader::Ws(s) => loop {
                match s.next().await {
                    Some(Ok(Message::Binary(b))) => return Ok(b),
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                    Some(Ok(Message::Text(_))) => return Err(ReadEnd::Error("unexpected message type".into())),
                    Some(Ok(Message::Close(_))) | None => return Err(ReadEnd::Closed),
                    Some(Err(WsError::ConnectionClosed | WsError::AlreadyClosed)) => return Err(ReadEnd::Closed),
                    // A client gone without a closing handshake, or without
                    // TLS's close_notify: gone all the same
                    Some(Err(WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake))) => {
                        return Err(ReadEnd::Closed);
                    }
                    Some(Err(WsError::Io(e))) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Err(ReadEnd::Closed);
                    }
                    Some(Err(e)) => return Err(ReadEnd::Error(e.to_string())),
                }
            },
        }
    }
}

#[derive(Clone)]
pub enum Writer {
    Quic(quinn::Connection),
    Ws(mpsc::Sender<Bytes>),
}

impl Writer {
    /// Waits while the connection's queue is full: a slow receiver slows its
    /// senders, as in the Go relay, rather than losing what they send
    pub async fn write(&self, msg: Bytes) -> Result<(), WriteError> {
        match self {
            Writer::Quic(c) => c.send_datagram_wait(msg).await.map_err(quic_error),
            Writer::Ws(tx) => tx.send(msg).await.map_err(|_| WriteError::Closed),
        }
    }

    /// `head` then `data` as one message: over QUIC neither is copied until
    /// the packet is built (the fork's `send_datagram_parts_wait`); over
    /// WebSocket they are joined here
    pub async fn write_parts(&self, head: Bytes, data: Bytes) -> Result<(), WriteError> {
        match self {
            Writer::Quic(c) => c.send_datagram_parts_wait(head, data).await.map_err(quic_error),
            Writer::Ws(tx) => {
                let mut msg = BytesMut::with_capacity(head.len() + data.len());
                msg.put_slice(&head);
                msg.put_slice(&data);
                tx.send(msg.freeze()).await.map_err(|_| WriteError::Closed)
            }
        }
    }
}

fn quic_error(e: quinn::SendDatagramError) -> WriteError {
    match e {
        quinn::SendDatagramError::TooLarge => WriteError::TooLarge,
        quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled => WriteError::Unsupported,
        quinn::SendDatagramError::ConnectionLost(_) => WriteError::Closed,
    }
}

pub struct Accepted {
    pub reader: Reader,
    pub writer: Writer,
    pub remote: SocketAddr,
    pub protocol: &'static str,
    pub closed: Arc<watch::Sender<bool>>,
    pub quic: Option<quinn::Connection>,
}

impl Accepted {
    pub fn quic(conn: quinn::Connection) -> Self {
        Self {
            reader: Reader::Quic(conn.clone()),
            writer: Writer::Quic(conn.clone()),
            remote: conn.remote_address(),
            protocol: "quic",
            closed: Arc::new(watch::channel(false).0),
            quic: Some(conn),
        }
    }

    /// The writing half goes to a task of its own, which batches what is
    /// queued into one flush
    pub fn ws(ws: Ws, remote: SocketAddr) -> Self {
        let (sink, stream) = ws.split();
        let (tx, rx) = mpsc::channel(WS_QUEUE);
        let closed = Arc::new(watch::channel(false).0);
        tokio::spawn(ws_writer(sink, rx, closed.clone()));
        Self { reader: Reader::Ws(stream), writer: Writer::Ws(tx), remote, protocol: "ws", closed, quic: None }
    }

    pub fn close(&self) {
        close(&self.closed, self.quic.as_ref());
    }
}

/// Resolves once the connection is closed. Holding no borrow of the
/// channel, a select over it may await in its other branches
pub async fn until_closed(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|c| *c).await;
}

pub fn close(closed: &watch::Sender<bool>, quic: Option<&quinn::Connection>) {
    closed.send_replace(true);
    if let Some(c) = quic {
        c.close(0u32.into(), b"normal closure");
    }
}

async fn ws_writer(
    mut sink: futures_util::stream::SplitSink<Ws, Message>,
    mut rx: mpsc::Receiver<Bytes>,
    closed: Arc<watch::Sender<bool>>,
) {
    let mut stop = closed.subscribe();
    loop {
        let first = tokio::select! {
            biased;
            _ = until_closed(&mut stop) => break,
            m = rx.recv() => match m { Some(m) => m, None => break },
        };
        let sent = tokio::time::timeout(WS_WRITE_TIMEOUT, async {
            sink.feed(Message::Binary(first)).await?;
            for _ in 0..63 {
                match rx.try_recv() {
                    Ok(m) => sink.feed(Message::Binary(m)).await?,
                    Err(_) => break,
                }
            }
            sink.flush().await
        })
        .await;
        if !matches!(sent, Ok(Ok(()))) {
            closed.send_replace(true);
            return;
        }
    }
    // What was queued before the close (a close message) still goes, briefly
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        while let Ok(m) = rx.try_recv() {
            sink.feed(Message::Binary(m)).await?;
        }
        sink.flush().await?;
        sink.close().await
    })
    .await;
}
