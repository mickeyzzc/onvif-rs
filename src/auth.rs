use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha1::Digest;

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
