//! The relay's token check, `shared/relay/auth/hmac/v2`: an algorithm byte,
//! its signature, and a payload that is the expiry in Unix seconds, signed
//! with HMAC-SHA256 under the SHA-256 of the relay's secret.
use ring::hmac;
use std::time::{SystemTime, UNIX_EPOCH};

const ALGO_HMAC_SHA256: u8 = 1;
const SIGNATURE_SIZE: usize = 32;
const MIN_PAYLOAD: usize = 10;

pub struct Validator {
    key: hmac::Key,
}

impl Validator {
    pub fn new(secret: &str) -> Self {
        let hashed = ring::digest::digest(&ring::digest::SHA256, secret.as_bytes());
        Self { key: hmac::Key::new(hmac::HMAC_SHA256, hashed.as_ref()) }
    }

    pub fn validate(&self, token: &[u8]) -> Result<(), String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        self.validate_at(token, now)
    }

    /// The Go validator's checks, in its order
    pub fn validate_at(&self, token: &[u8], now: i64) -> Result<(), String> {
        let Some((&algo, rest)) = token.split_first() else {
            return Err("unmarshal token: invalid token data".into());
        };
        let size = if algo == ALGO_HMAC_SHA256 { SIGNATURE_SIZE } else { 0 };
        if rest.len() < size {
            return Err("unmarshal token: invalid token data: insufficient length".into());
        }
        let (signature, payload) = rest.split_at(size);
        if payload.len() < MIN_PAYLOAD {
            return Err("invalid payload: insufficient length".into());
        }
        if algo != ALGO_HMAC_SHA256 {
            return Err("unsupported auth algorithm: Unknown".into());
        }
        hmac::verify(&self.key, payload, signature).map_err(|_| "invalid signature".to_string())?;
        let expires: i64 = std::str::from_utf8(payload)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| "invalid payload".to_string())?;
        if now > expires {
            return Err("expired token".into());
        }
        Ok(())
    }

    /// A token this validator accepts until `expires` (tests and tools)
    pub fn token(&self, expires: i64) -> Vec<u8> {
        let payload = expires.to_string();
        let tag = hmac::sign(&self.key, payload.as_bytes());
        let mut t = vec![ALGO_HMAC_SHA256];
        t.extend_from_slice(tag.as_ref());
        t.extend_from_slice(payload.as_bytes());
        t
    }
}

/// What the health check sends: a well-formed token no secret signed
pub fn dummy_token() -> Vec<u8> {
    let mut t = vec![ALGO_HMAC_SHA256];
    t.extend_from_slice(&[0u8; SIGNATURE_SIZE]);
    t.extend_from_slice(b"healthcheck");
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_its_own_and_refuses_the_rest() {
        let v = Validator::new("supersecret");
        let now = 1_800_000_000;
        assert_eq!(v.validate_at(&v.token(now + 3600), now), Ok(()));
        assert_eq!(v.validate_at(&v.token(now - 1), now), Err("expired token".into()));
        assert_eq!(Validator::new("other").validate_at(&v.token(now + 3600), now), Err("invalid signature".into()));

        let mut bad = v.token(now + 3600);
        bad[5] ^= 1;
        assert_eq!(v.validate_at(&bad, now), Err("invalid signature".into()));
        let mut algo = v.token(now + 3600);
        algo[0] = 2;
        assert!(v.validate_at(&algo, now).is_err());
        assert!(v.validate_at(&[], now).is_err());
        assert!(v.validate_at(&[1; 20], now).is_err());
        assert_eq!(v.validate_at(&dummy_token(), now), Err("invalid signature".into()));
    }

    #[test]
    fn signature_is_over_the_hashed_secret() {
        // The Go generator signs with sha256(secret) as the key: a token signed
        // with the bare secret is refused
        let now = 1_800_000_000;
        let payload = (now + 60).to_string();
        let bare = hmac::Key::new(hmac::HMAC_SHA256, b"supersecret");
        let mut t = vec![1];
        t.extend_from_slice(hmac::sign(&bare, payload.as_bytes()).as_ref());
        t.extend_from_slice(payload.as_bytes());
        assert!(Validator::new("supersecret").validate_at(&t, now).is_err());
    }
}
