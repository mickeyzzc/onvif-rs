use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha1::Digest;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::types::UsernameToken;

/// Verify a WS-UsernameToken against expected credentials.
///
/// Supports two modes:
/// - **plaintext**: direct comparison when `nonce` is empty.
/// - **digest**: `base64(SHA1(base64_decode(Nonce) + Created + Password))`
///   when `nonce` is non-empty.
pub fn verify_username_token(
    token: &UsernameToken,
    expected_user: &str,
    expected_pass: &str,
) -> bool {
    if token.username != expected_user {
        return false;
    }

    if token.nonce.is_empty() {
        // Plaintext mode
        constant_time_eq(token.password.as_bytes(), expected_pass.as_bytes())
    } else {
        // Digest mode
        let computed = compute_password_digest(&token.nonce, &token.created, expected_pass);
        constant_time_eq(token.password.as_bytes(), computed.as_bytes())
    }
}

/// Compute the ONVIF password digest:
/// `BASE64(SHA1(base64_decode(Nonce) + Created + Password))`
pub fn compute_password_digest(nonce: &str, created: &str, password: &str) -> String {
    let nonce_bytes = BASE64
        .decode(nonce)
        .unwrap_or_else(|_| nonce.as_bytes().to_vec());

    let mut hasher = sha1::Sha1::new();
    hasher.update(&nonce_bytes);
    hasher.update(created.as_bytes());
    hasher.update(password.as_bytes());
    let result = hasher.finalize();

    BASE64.encode(result)
}

/// Constant-time byte comparison to prevent timing side-channels on
/// password validation.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b) {
        result |= x ^ y;
    }
    result == 0
}

// ---------------------------------------------------------------------------
// Replay guard (issue #16): a captured digest UsernameToken must not be
// replayable — nonces are remembered and Created must be fresh.
// ---------------------------------------------------------------------------

/// Remembers seen nonces (bounded map) and enforces a Created freshness
/// window. `window_secs == 0` disables both checks (tests only).
pub struct ReplayGuard {
    window_secs: u64,
    seen: Mutex<HashMap<String, Instant>>,
}

const MAX_REMEMBERED_NONCES: usize = 1024;

impl ReplayGuard {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Accepts a (nonce, created) pair exactly once: the Created timestamp
    /// must sit inside the freshness window and the nonce must not have
    /// been seen before.
    pub fn check_and_remember(&self, nonce: &str, created: &str) -> bool {
        if self.window_secs == 0 {
            return true;
        }
        if !created_is_fresh(created, self.window_secs) {
            return false;
        }
        let mut seen = match self.seen.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if seen.len() >= MAX_REMEMBERED_NONCES {
            prune_stale(&mut seen);
        }
        // The nonce (not its decoded bytes) is the identity — the wire
        // value is what an attacker replays byte-for-byte.
        seen.insert(nonce.to_string(), Instant::now()).is_none()
    }
}

fn prune_stale(seen: &mut HashMap<String, Instant>) {
    // One full window back covers every accepted token.
    seen.retain(|_, at| at.elapsed() < Duration::from_secs(600));
    if seen.len() >= MAX_REMEMBERED_NONCES {
        // Still full (degenerate all-at-once replay): drop the oldest
        // quarter instead of growing without bound.
        let mut times: Vec<(String, Instant)> = seen.iter().map(|(k, v)| (k.clone(), *v)).collect();
        times.sort_by_key(|(_, at)| *at);
        for (k, _) in times.into_iter().take(MAX_REMEMBERED_NONCES / 4) {
            seen.remove(&k);
        }
    }
}

/// Parses an RFC3339-ish `YYYY-MM-DDTHH:MM:SS[.fff]Z` Created value and
/// checks it lies within ±window of now. Unparseable timestamps are stale
/// (fail closed).
fn created_is_fresh(created: &str, window_secs: u64) -> bool {
    let Some(unix) = parse_created_unix(created) else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (unix - now).abs() <= window_secs as i64
}

/// Minimal civil-time parser for the ONVIF Created format (no chrono dep):
/// Howard Hinnant's days-from-civil over the date part.
pub fn parse_created_unix(created: &str) -> Option<i64> {
    let bytes = created.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let num = |a: usize, b: usize| -> Option<i64> { created.get(a..b)?.parse::<i64>().ok() };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, s) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy.rem_euclid(400);
    let mp = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + s)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector for digest computation.
    // Nonce (base64): "dGhpcyBpcyBhIG5vbmNl" → bytes: "this is a nonce"
    const TEST_NONCE: &str = "dGhpcyBpcyBhIG5vbmNl";
    const TEST_CREATED: &str = "2025-01-01T00:00:00Z";
    const TEST_PASSWORD: &str = "test123";

    fn expected_digest() -> String {
        compute_password_digest(TEST_NONCE, TEST_CREATED, TEST_PASSWORD)
    }

    // ------------------------------------------------------------------
    // Plaintext
    // ------------------------------------------------------------------

    #[test]
    fn test_auth_plaintext_valid() {
        let token = UsernameToken {
            username: "admin".into(),
            password: "secret".into(),
            nonce: String::new(),
            created: String::new(),
        };
        assert!(verify_username_token(&token, "admin", "secret"));
    }

    #[test]
    fn test_auth_plaintext_valid_empty_password() {
        let token = UsernameToken {
            username: "admin".into(),
            password: String::new(),
            nonce: String::new(),
            created: String::new(),
        };
        assert!(verify_username_token(&token, "admin", ""));
    }

    #[test]
    fn test_auth_plaintext_invalid() {
        let token = UsernameToken {
            username: "admin".into(),
            password: "wrong".into(),
            nonce: String::new(),
            created: String::new(),
        };
        assert!(!verify_username_token(&token, "admin", "secret"));
    }

    #[test]
    fn test_auth_plaintext_username_mismatch() {
        let token = UsernameToken {
            username: "nobody".into(),
            password: "secret".into(),
            nonce: String::new(),
            created: String::new(),
        };
        assert!(!verify_username_token(&token, "admin", "secret"));
    }

    // ------------------------------------------------------------------
    // Digest
    // ------------------------------------------------------------------

    #[test]
    fn test_auth_digest_valid() {
        let token = UsernameToken {
            username: "admin".into(),
            password: expected_digest(),
            nonce: TEST_NONCE.into(),
            created: TEST_CREATED.into(),
        };
        assert!(verify_username_token(&token, "admin", TEST_PASSWORD));
    }

    #[test]
    fn test_auth_digest_invalid() {
        let token = UsernameToken {
            username: "admin".into(),
            password: "AAAAAAAA".into(),
            nonce: TEST_NONCE.into(),
            created: TEST_CREATED.into(),
        };
        assert!(!verify_username_token(&token, "admin", TEST_PASSWORD));
    }

    #[test]
    fn test_auth_digest_username_mismatch() {
        let token = UsernameToken {
            username: "nobody".into(),
            password: expected_digest(),
            nonce: TEST_NONCE.into(),
            created: TEST_CREATED.into(),
        };
        assert!(!verify_username_token(&token, "admin", TEST_PASSWORD));
    }

    #[test]
    fn test_auth_digest_wrong_password() {
        let token = UsernameToken {
            username: "admin".into(),
            password: expected_digest(),
            nonce: TEST_NONCE.into(),
            created: TEST_CREATED.into(),
        };
        assert!(!verify_username_token(&token, "admin", "wrong_password"));
    }

    // ------------------------------------------------------------------
    // Digest computation
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_digest_deterministic() {
        let a = compute_password_digest(TEST_NONCE, TEST_CREATED, TEST_PASSWORD);
        let b = compute_password_digest(TEST_NONCE, TEST_CREATED, TEST_PASSWORD);
        assert_eq!(a, b);
    }

    #[test]
    fn test_compute_digest_different_inputs() {
        let a = compute_password_digest(TEST_NONCE, TEST_CREATED, TEST_PASSWORD);
        let b = compute_password_digest(TEST_NONCE, TEST_CREATED, "other");
        assert_ne!(a, b);
    }

    #[test]
    fn test_compute_digest_correct_format() {
        let digest = compute_password_digest(TEST_NONCE, TEST_CREATED, TEST_PASSWORD);
        // Digest must be valid base64
        assert!(
            BASE64.decode(&digest).is_ok(),
            "digest must be valid base64"
        );
        // Decoded must be 20 bytes (SHA-1 output)
        assert_eq!(
            BASE64.decode(&digest).unwrap().len(),
            20,
            "SHA-1 digest must be 20 bytes"
        );
    }

    // ------------------------------------------------------------------
    // Constant-time helper
    // ------------------------------------------------------------------

    #[test]
    fn test_constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_diff() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_eq_diff_len() {
        assert!(!constant_time_eq(b"hello", b"helloo"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"", b"a"));
    }
}
