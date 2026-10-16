//! The relay protocol on the wire, as `shared/relay/messages` defines it:
//! a version byte, a type byte, and a body. Every message is one WebSocket
//! binary message or one QUIC DATAGRAM.
use base64::Engine;
use bytes::{BufMut, Bytes, BytesMut};

pub const VERSION: u8 = 1;
/// The most of a first message the relay reads (`MaxHandshakeSize`)
pub const MAX_HANDSHAKE_SIZE: usize = 212;
pub const MAX_MESSAGE_SIZE: usize = 8820;
pub const PEER_ID_SIZE: usize = 36;
const HEADER: usize = 2;
const MAGIC: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
const AUTH_HEADER: usize = HEADER + MAGIC.len() + PEER_ID_SIZE;
const TRANSPORT_HEADER: usize = HEADER + PEER_ID_SIZE;
/// Peer ids in one PeersOnline or PeersWentOffline message: 244
pub const PEERS_PER_MESSAGE: usize = (MAX_MESSAGE_SIZE - HEADER) / PEER_ID_SIZE;

pub const HELLO: u8 = 1;
pub const TRANSPORT: u8 = 3;
pub const CLOSE: u8 = 4;
pub const HEALTH_CHECK: u8 = 5;
pub const AUTH: u8 = 6;
pub const AUTH_RESPONSE: u8 = 7;
pub const SUBSCRIBE_PEER_STATE: u8 = 8;
pub const UNSUBSCRIBE_PEER_STATE: u8 = 9;
pub const PEERS_ONLINE: u8 = 10;
pub const PEERS_WENT_OFFLINE: u8 = 11;

/// `sha-` and the SHA-256 of the peer's public key
pub type PeerId = [u8; PEER_ID_SIZE];

pub fn hash_id(peer: &str) -> PeerId {
    let digest = ring::digest::digest(&ring::digest::SHA256, peer.as_bytes());
    let mut id = [0u8; PEER_ID_SIZE];
    id[..4].copy_from_slice(b"sha-");
    id[4..].copy_from_slice(digest.as_ref());
    id
}

/// What the Go relay logs: the prefix, then the hash in standard base64
pub fn peer_id_string(id: &PeerId) -> String {
    format!("{}{}", String::from_utf8_lossy(&id[..4]), base64::engine::general_purpose::STANDARD.encode(&id[4..]))
}

/// The health checker's own peer id: its rejection is logged quietly
pub fn health_check_peer() -> PeerId {
    hash_id("healthcheck-agent")
}

/// A client message's type, or why the message is refused
/// (`ValidateVersion`, then `DetermineClientMessageType`)
pub fn client_type(msg: &[u8]) -> Result<u8, String> {
    if msg.len() < HEADER {
        return Err("invalid message length".into());
    }
    if msg[0] != VERSION {
        return Err(format!("{}: unsupported version", msg[0]));
    }
    match msg[1] {
        AUTH | TRANSPORT | CLOSE | HEALTH_CHECK | SUBSCRIBE_PEER_STATE | UNSUBSCRIBE_PEER_STATE => Ok(msg[1]),
        t => Err(format!("invalid msg type {t}")),
    }
}

pub fn auth_message(peer: &PeerId, token: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(AUTH_HEADER + token.len());
    msg.extend_from_slice(&[VERSION, AUTH]);
    msg.extend_from_slice(&MAGIC);
    msg.extend_from_slice(peer);
    msg.extend_from_slice(token);
    msg
}

/// The peer id and the token of an auth message whose header was checked
pub fn parse_auth(msg: &[u8]) -> Result<(PeerId, &[u8]), String> {
    if msg.len() < AUTH_HEADER {
        return Err("invalid message length".into());
    }
    if msg[HEADER..HEADER + MAGIC.len()] != MAGIC {
        return Err("invalid magic header".into());
    }
    let id: PeerId = msg[HEADER + MAGIC.len()..AUTH_HEADER].try_into().unwrap();
    Ok((id, &msg[AUTH_HEADER..]))
}

pub fn auth_response(instance_url: &str) -> Bytes {
    let mut msg = BytesMut::with_capacity(HEADER + instance_url.len());
    msg.put_slice(&[VERSION, AUTH_RESPONSE]);
    msg.put_slice(instance_url.as_bytes());
    msg.freeze()
}

pub fn close() -> Bytes {
    Bytes::from_static(&[VERSION, CLOSE])
}

pub fn health_check() -> Bytes {
    Bytes::from_static(&[VERSION, HEALTH_CHECK])
}

pub fn transport(dest: &PeerId, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(TRANSPORT_HEADER + payload.len());
    msg.extend_from_slice(&[VERSION, TRANSPORT]);
    msg.extend_from_slice(dest);
    msg.extend_from_slice(payload);
    msg
}

/// The peer a transport message is addressed to
pub fn transport_destination(msg: &[u8]) -> Option<PeerId> {
    msg.get(HEADER..TRANSPORT_HEADER).map(|id| id.try_into().unwrap())
}

/// The message as its receiver gets it: the sender's id in the address's place
pub fn relabel_transport(msg: &[u8], source: &PeerId) -> Bytes {
    let mut out = BytesMut::with_capacity(msg.len());
    out.put_slice(&msg[..HEADER]);
    out.put_slice(source);
    out.put_slice(&msg[TRANSPORT_HEADER..]);
    out.freeze()
}

pub fn parse_peer_ids(msg: &[u8]) -> Result<Vec<PeerId>, String> {
    if msg.len() < HEADER {
        return Err("invalid message format".into());
    }
    let body = &msg[HEADER..];
    if !body.len().is_multiple_of(PEER_ID_SIZE) {
        return Err(format!("invalid peer list size: {}", body.len()));
    }
    Ok(body.as_chunks::<PEER_ID_SIZE>().0.to_vec())
}

/// One message for each 244 ids or fewer
pub fn peer_id_messages(kind: u8, ids: &[PeerId]) -> Vec<Bytes> {
    ids.chunks(PEERS_PER_MESSAGE)
        .map(|chunk| {
            let mut msg = BytesMut::with_capacity(HEADER + chunk.len() * PEER_ID_SIZE);
            msg.put_slice(&[VERSION, kind]);
            for id in chunk {
                msg.put_slice(id);
            }
            msg.freeze()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_round_trip() {
        let id = hash_id("abdFAaBcawquEiCMzAabYosuUaGLtSNhKxz+");
        let msg = auth_message(&id, b"token");
        assert_eq!(client_type(&msg), Ok(AUTH));
        let (got, token) = parse_auth(&msg).unwrap();
        assert_eq!(got, id);
        assert_eq!(token, b"token");
        let mut bad = msg.clone();
        bad[2] ^= 1;
        assert!(parse_auth(&bad).is_err());
        assert!(parse_auth(&msg[..41]).is_err());
    }

    #[test]
    fn peer_id_reads_as_go_prints_it() {
        // sha256("") is e3b0c442…, standard base64 with padding
        assert_eq!(peer_id_string(&hash_id("")), "sha-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    }

    #[test]
    fn types_the_client_may_send() {
        for t in [AUTH, TRANSPORT, CLOSE, HEALTH_CHECK, SUBSCRIBE_PEER_STATE, UNSUBSCRIBE_PEER_STATE] {
            assert_eq!(client_type(&[VERSION, t]), Ok(t));
        }
        for t in [0, HELLO, 2, AUTH_RESPONSE, PEERS_ONLINE, PEERS_WENT_OFFLINE, 12, 255] {
            assert!(client_type(&[VERSION, t]).is_err(), "type {t}");
        }
        assert!(client_type(&[2, TRANSPORT]).is_err());
        assert!(client_type(&[VERSION]).is_err());
    }

    #[test]
    fn transport_is_relabelled_with_its_sender() {
        let (a, b) = (hash_id("a"), hash_id("b"));
        let msg = transport(&b, b"payload");
        assert_eq!(transport_destination(&msg), Some(b));
        let out = relabel_transport(&msg, &a);
        assert_eq!(&out[..2], &[VERSION, TRANSPORT]);
        assert_eq!(transport_destination(&out), Some(a));
        assert_eq!(&out[38..], b"payload");
        assert_eq!(transport_destination(&msg[..37]), None);
    }

    #[test]
    fn peer_lists_split_at_244() {
        let ids: Vec<PeerId> = (0..500).map(|i| hash_id(&i.to_string())).collect();
        let msgs = peer_id_messages(PEERS_ONLINE, &ids);
        assert_eq!(msgs.iter().map(|m| (m.len() - 2) / 36).collect::<Vec<_>>(), [244, 244, 12]);
        assert!(msgs.iter().all(|m| m.len() <= MAX_MESSAGE_SIZE));
        let back: Vec<PeerId> = msgs.iter().flat_map(|m| parse_peer_ids(m).unwrap()).collect();
        assert_eq!(back, ids);
        assert!(parse_peer_ids(&[VERSION, SUBSCRIBE_PEER_STATE, 0]).is_err());
        assert!(parse_peer_ids(&[VERSION]).is_err());
    }
}
