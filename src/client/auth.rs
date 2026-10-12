//! Authentication modes, the sticky fallback ladder, clock-skew
//! auto-correction and auth triage — the twin of the Go client's
//! `WithAuthMode` / `WithAuthFallback` / `WithAutoClockSkew` /
//! `DiagnoseAuth` quartet.
//!
//! The default is UsernameToken PasswordDigest (the ONVIF default). With
//! [`SoapClient::with_auth_fallback`] the client walks the ladder on
//! auth-class failures (HTTP 401/403 or a NotAuthorized fault) and
//! remembers the first mode the device accepts — the sticky behavior
//! real firmware forces (devices disagree on which mode they honor per
//! service). With [`SoapClient::with_auto_clock_skew`] an auth failure
//! first measures the device clock over the unauthenticated
//! GetSystemDateAndTime and retries once with the corrected `Created`
//! stamp — the drifted-clock trap where the very call that would fix the
//! clock is the one digest rejects.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::SoapClient;

/// The authentication modes of the client half.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthMode {
    /// WS-Security UsernameToken with PasswordDigest (the ONVIF default).
    #[default]
    PasswordDigest,
    /// WS-Security UsernameToken with cleartext PasswordText (some
    /// firmwares reject digest on specific services).
    PasswordText,
    /// HTTP Basic authorization header, no SOAP header.
    HttpBasic,
    /// HTTP Digest transport auth (RFC 7616 subset the twin server
    /// offers: MD5, qop="auth"): the call rides a 401 challenge →
    /// `Authorization: Digest` response exchange, no SOAP header.
    HttpDigest,
    /// No credentials on the wire (anonymous calls only).
    None,
}

impl AuthMode {
    /// The ladder used by the fallback: the configured mode first, then
    /// the remaining ones in the Go twin's order.
    #[must_use]
    pub fn ladder(configured: AuthMode) -> [AuthMode; 5] {
        let all = [
            AuthMode::PasswordDigest,
            AuthMode::PasswordText,
            AuthMode::HttpBasic,
            AuthMode::HttpDigest,
            AuthMode::None,
        ];
        let mut ladder = [configured; 5];
        let mut idx = 1;
        for mode in all {
            if mode != configured {
                ladder[idx] = mode;
                idx += 1;
            }
        }
        ladder
    }
}

/// Outcome classification of [`SoapClient::diagnose_auth`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    /// The current credentials authenticate as-is.
    Ok,
    /// Digest failed with the local clock but the device clock reads far
    /// off — the root cause is clock divergence (fix the camera's NTP;
    /// meanwhile `with_clock_skew`/`with_auto_clock_skew` keeps the
    /// client working).
    ClockSkew,
    /// Authentication fails regardless of clock skew — wrong
    /// username/password (or the device rejects ONVIF auth entirely; try
    /// `with_auth_fallback`).
    BadCredentials,
}

/// The triage result of [`SoapClient::diagnose_auth`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDiagnosis {
    /// The classification.
    pub status: AuthStatus,
    /// The measured device-minus-local clock offset (valid when the
    /// clock could be read, zero otherwise).
    pub clock_skew: Duration,
    /// Human-readable explanation with remediation hints.
    pub detail: String,
}

/// Beyond this measured device-clock divergence the digest timestamp is
/// considered at risk (ONVIF replay windows are commonly ±5 minutes;
/// 2 minutes leaves little margin) — the Go twin's threshold.
const AUTH_SKEW_THRESHOLD_SECS: i64 = 120;

/// Mutable-per-ladder, shared-per-clone auth state.
#[derive(Debug, Default)]
pub(crate) struct AuthState {
    pub(crate) configured_mode: Option<AuthMode>,
    /// Sticky first-accepted mode (the fallback's memory).
    pub(crate) sticky: Mutex<Option<AuthMode>>,
    pub(crate) fallback: bool,
    pub(crate) auto_skew: bool,
    /// Set once the auto-skew measurement has been attempted.
    pub(crate) skew_attempted: Mutex<bool>,
    /// HTTP Digest nonce-count bookkeeping (the Go twin's shared-counter
    /// semantics: a server reusing nonces requires the count to advance).
    pub(crate) digest_nc: Mutex<std::collections::HashMap<String, u32>>,
}

impl AuthState {
    /// The mode a call starts from: the sticky one when the ladder has
    /// settled, the configured one otherwise.
    pub(crate) fn initial_mode(&self) -> AuthMode {
        if let Some(sticky) = *self.sticky.lock().unwrap_or_else(|g| g.into_inner()) {
            return sticky;
        }
        self.configured_mode.unwrap_or_default()
    }
}

impl SoapClient {
    /// Select the authentication mode (default
    /// [`AuthMode::PasswordDigest`]).
    #[must_use]
    pub fn with_auth_mode(mut self, mode: AuthMode) -> Self {
        if let Some(state) = Arc::get_mut(&mut self.auth_state) {
            state.configured_mode = Some(mode);
        }
        self
    }

    /// Walk the auth-mode ladder on auth-class failures and remember the
    /// first mode the device accepts (sticky for the client's lifetime).
    #[must_use]
    pub fn with_auth_fallback(mut self) -> Self {
        if let Some(state) = Arc::get_mut(&mut self.auth_state) {
            state.fallback = true;
        }
        self
    }

    /// On an auth-class failure, measure the device clock over the
    /// unauthenticated GetSystemDateAndTime and retry once with the
    /// corrected `Created` stamp (the drifted-clock trap).
    #[must_use]
    pub fn with_auto_clock_skew(mut self) -> Self {
        if let Some(state) = Arc::get_mut(&mut self.auth_state) {
            state.auto_skew = true;
        }
        self
    }

    /// The mode the ladder settled on, if any (diagnostics).
    #[must_use]
    pub fn effective_auth_mode(&self) -> Option<AuthMode> {
        *self
            .auth_state
            .sticky
            .lock()
            .unwrap_or_else(|g| g.into_inner())
    }

    /// Triage authentication: does the current credential set work, is
    /// the failure clock-skew shaped, or are the credentials wrong?
    /// Mirrors the Go client's `DiagnoseAuth`.
    pub async fn diagnose_auth(&self) -> AuthDiagnosis {
        // The protected probe: GetDeviceInformation (the Go twin's probe
        // action — cheap to answer, write-protected on most firmwares).
        let probe = "<tds:GetDeviceInformation xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"></tds:GetDeviceInformation>";

        match self.device_call(probe).await {
            Ok(_) => AuthDiagnosis {
                status: AuthStatus::Ok,
                clock_skew: Duration::ZERO,
                detail: "credentials accepted".into(),
            },
            Err(e) if e.is_unauthorized() => {
                // Measure the device clock while anonymous.
                let skew_secs = match self.get_device_time().await {
                    Ok(t) => device_clock_skew_secs(t.utc.unix),
                    Err(_) => 0,
                };

                if skew_secs.abs() >= AUTH_SKEW_THRESHOLD_SECS && skew_secs > 0 {
                    let probe_client = self
                        .clone()
                        .with_clock_skew(Duration::from_secs(skew_secs as u64));
                    if probe_client.device_call(probe).await.is_ok() {
                        return AuthDiagnosis {
                            status: AuthStatus::ClockSkew,
                            clock_skew: Duration::from_secs(skew_secs.unsigned_abs()),
                            detail: format!(
                                "digest failed with the local clock but succeeds using the device \
                                 time (device is {skew_secs}s ahead); fix the camera's NTP or apply \
                                 with_clock_skew/with_auto_clock_skew"
                            ),
                        };
                    }
                }

                AuthDiagnosis {
                    status: AuthStatus::BadCredentials,
                    clock_skew: Duration::from_secs(skew_secs.unsigned_abs()),
                    detail: format!(
                        "authentication fails regardless of clock skew (device clock {skew_secs}s \
                         off); wrong username/password, or the device rejects this auth mode — try \
                         with_auth_fallback ({e})"
                    ),
                }
            }
            Err(e) => AuthDiagnosis {
                status: AuthStatus::BadCredentials,
                clock_skew: Duration::ZERO,
                detail: format!("probe failed before authentication could be triaged: {e}"),
            },
        }
    }
}

/// Device-minus-local clock offset in whole seconds.
fn device_clock_skew_secs(device_unix: i64) -> i64 {
    let local = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    device_unix - local
}

/// Whether a SOAP fault code/subcode is the NotAuthorized family.
pub(crate) fn is_notauthorized_fault(code: &str, subcode: &str) -> bool {
    let joined = format!("{code}|{subcode}").to_lowercase();
    joined.contains("notauthorized")
        || joined.contains("not authorized")
        || joined.contains("unauthorized")
}

// ---------------------------------------------------------------------------
// HTTP Digest challenge/response (RFC 7616 subset the twin server offers:
// MD5, qop="auth" — the Go twin's transport default, mirrored as a ladder
// mode).
// ---------------------------------------------------------------------------

/// Parameters of a server `WWW-Authenticate: Digest` challenge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DigestChallengeParams {
    pub(crate) realm: String,
    pub(crate) nonce: String,
    /// `auth` or empty (the challenge did not offer qop).
    pub(crate) qop: String,
    pub(crate) opaque: String,
}

/// Parse a `WWW-Authenticate` header value; None when it is not a Digest
/// challenge (scheme is case-insensitive; values may be quoted or bare).
pub(crate) fn parse_digest_challenge(header: &str) -> Option<DigestChallengeParams> {
    let trimmed = header.trim();
    let (scheme, params) = trimmed.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Digest") {
        return None;
    }

    Some(DigestChallengeParams {
        realm: quoted_param(params, "realm")?,
        nonce: quoted_param(params, "nonce")?,
        qop: quoted_param(params, "qop").unwrap_or_default(),
        opaque: quoted_param(params, "opaque").unwrap_or_default(),
    })
}

/// Extract one `key=value` parameter of a challenge list. Keys match
/// case-insensitively at a segment boundary (so `nonce=` never matches
/// inside `cnonce=`); values are quoted or bare tokens.
fn quoted_param(params: &str, key: &str) -> Option<String> {
    let lower = params.to_ascii_lowercase();
    let needle = format!("{key}=");
    let mut search_from = 0;
    loop {
        let idx = lower[search_from..].find(&needle)? + search_from;
        let boundary_ok = idx == 0
            || lower[..idx]
                .chars()
                .next_back()
                .is_some_and(|c| c == ',' || c.is_whitespace());
        if boundary_ok {
            let value = &params[idx + needle.len()..];
            if let Some(rest) = value.strip_prefix('"') {
                let end = rest.find('"')?;
                return Some(rest[..end].to_string());
            }
            let end = value.find(',').unwrap_or(value.len());
            return Some(value[..end].trim().to_string());
        }
        search_from = idx + needle.len();
    }
}

fn md5_hex(s: &str) -> String {
    use md5::{Digest as Md5Digest, Md5};
    let mut h = Md5::new();
    h.update(s.as_bytes());
    let out = h.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// The MD5 `response` of the digest auth exchange (qop="auth" when the
/// challenge offered it, the legacy RFC 2069 form otherwise).
pub(crate) fn digest_response_md5(
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    challenge: &DigestChallengeParams,
    nc_hex: &str,
    cnonce: &str,
) -> String {
    let ha1 = md5_hex(&format!("{username}:{}:{password}", challenge.realm));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    if challenge.qop.eq_ignore_ascii_case("auth") {
        md5_hex(&format!(
            "{ha1}:{}:{nc_hex}:{cnonce}:auth:{ha2}",
            challenge.nonce
        ))
    } else {
        md5_hex(&format!("{ha1}:{}:{ha2}", challenge.nonce))
    }
}

/// The `Authorization: Digest ...` header value (the Go twin's field
/// order; the opaque/qop/nc/cnonce tail rides only when qop was offered).
pub(crate) fn build_digest_authorization(
    username: &str,
    challenge: &DigestChallengeParams,
    uri: &str,
    response: &str,
    nc_hex: &str,
    cnonce: &str,
) -> String {
    let mut header = format!(
        "Digest username=\"{username}\", realm=\"{}\", nonce=\"{}\", uri=\"{uri}\", response=\"{response}\"",
        challenge.realm, challenge.nonce
    );
    if challenge.qop.eq_ignore_ascii_case("auth") {
        header.push_str(&format!(
            ", opaque=\"{}\", qop=auth, nc={nc_hex}, cnonce=\"{cnonce}\"",
            challenge.opaque
        ));
    }
    header
}

/// A fresh random cnonce (hex, 8 bytes of entropy).
pub(crate) fn random_digest_cnonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn ladder_order() {
        let ladder = AuthMode::ladder(AuthMode::PasswordDigest);
        assert_eq!(
            ladder,
            [
                AuthMode::PasswordDigest,
                AuthMode::PasswordText,
                AuthMode::HttpBasic,
                AuthMode::HttpDigest,
                AuthMode::None
            ]
        );

        // The configured mode leads even when it is None.
        let ladder = AuthMode::ladder(AuthMode::None);
        assert_eq!(ladder[0], AuthMode::None);
        assert_eq!(ladder[1], AuthMode::PasswordDigest);
        // Every mode appears exactly once.
        for mode in [
            AuthMode::PasswordDigest,
            AuthMode::PasswordText,
            AuthMode::HttpBasic,
            AuthMode::HttpDigest,
            AuthMode::None,
        ] {
            assert_eq!(ladder.iter().filter(|m| **m == mode).count(), 1);
        }
    }

    #[test]
    fn digest_challenge_parsing() {
        // The server twin's exact challenge format.
        let challenge =
            parse_digest_challenge("Digest realm=\"onvif\", nonce=\"n-1\", qop=\"auth\", algorithm=MD5, stale=FALSE, opaque=\"op-1\"")
                .expect("digest challenge");
        assert_eq!(challenge.realm, "onvif");
        assert_eq!(challenge.nonce, "n-1");
        assert_eq!(challenge.qop, "auth");
        assert_eq!(challenge.opaque, "op-1");

        // Case-insensitive scheme, unquoted params, no qop.
        let legacy =
            parse_digest_challenge("digest realm=cam, nonce=abc").expect("legacy challenge");
        assert_eq!(
            (legacy.realm.as_str(), legacy.nonce.as_str()),
            ("cam", "abc")
        );
        assert_eq!(legacy.qop, "");

        assert!(parse_digest_challenge("Basic realm=\"onvif\"").is_none());
        // nonce= must not match inside cnonce=.
        let cnonce_case =
            parse_digest_challenge("Digest realm=\"r\", nonce=\"real\", cnonce=\"x\"")
                .expect("boundary match");
        assert_eq!(cnonce_case.nonce, "real");
    }

    #[test]
    fn digest_response_rfc2617_vector() {
        // The canonical RFC 2617 §3.5 example (MD5, qop=auth).
        let rfc_challenge = DigestChallengeParams {
            realm: "testrealm@host.com".into(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".into(),
            qop: "auth".into(),
            opaque: String::new(),
        };
        let response = digest_response_md5(
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            &rfc_challenge,
            "00000001",
            "0a4f113b",
        );
        assert_eq!(response, "6629fae49393a05397450978507c4ef1");

        // Legacy (no qop) form: response = MD5(HA1:nonce:HA2).
        let legacy = digest_response_md5(
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            &DigestChallengeParams {
                qop: String::new(),
                ..rfc_challenge.clone()
            },
            "00000001",
            "0a4f113b",
        );
        assert_eq!(legacy, "670fd8c2df070c60b045671b8b24ff02");
    }

    #[test]
    fn digest_authorization_shape() {
        let challenge = DigestChallengeParams {
            realm: "onvif".into(),
            nonce: "n-1".into(),
            qop: "auth".into(),
            opaque: "op-1".into(),
        };
        let header = build_digest_authorization(
            "admin",
            &challenge,
            "/onvif/device_service",
            "deadbeef",
            "00000001",
            "c0ffee",
        );
        assert_eq!(
            header,
            "Digest username=\"admin\", realm=\"onvif\", nonce=\"n-1\", uri=\"/onvif/device_service\", response=\"deadbeef\", opaque=\"op-1\", qop=auth, nc=00000001, cnonce=\"c0ffee\""
        );

        let legacy_header = build_digest_authorization(
            "admin",
            &DigestChallengeParams {
                realm: "onvif".into(),
                nonce: "n-1".into(),
                ..Default::default()
            },
            "/onvif/device_service",
            "deadbeef",
            "00000001",
            "c0ffee",
        );
        assert!(!legacy_header.contains("qop="));
    }

    #[test]
    fn notauthorized_classification() {
        assert!(is_notauthorized_fault("ter:NotAuthorized", ""));
        assert!(is_notauthorized_fault("s:Sender", "ter:NotAuthorized"));
        assert!(is_notauthorized_fault("soap:Sender", "SenderNotAuthorized"));
        assert!(!is_notauthorized_fault(
            "s:Sender",
            "ter:ActionNotSupported"
        ));
        assert!(!is_notauthorized_fault("s:Receiver", ""));
    }

    /// Read one HTTP request by headers + Content-Length (the client
    /// keeps its write side open while awaiting the response).
    async fn read_request(sock: &mut tokio::net::TcpStream) -> String {
        use tokio::io::AsyncReadExt;

        let mut raw = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match sock.read(&mut byte).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    raw.push(byte[0]);
                    if raw.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
        let head = String::from_utf8_lossy(&raw).to_string();
        let len: usize = head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; len];
        if len > 0 {
            let _ = sock.read_exact(&mut body).await;
        }
        format!("{head}{}", String::from_utf8_lossy(&body))
    }

    #[tokio::test]
    async fn fallback_ladder_settles_sticky() {
        use tokio::io::AsyncWriteExt;

        // A device that answers 401 to the first exchange and 200 to any
        // request carrying HTTP Basic.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut calls = 0u32;
            while let Ok((mut sock, _)) = listener.accept().await {
                calls += 1;
                let text = read_request(&mut sock).await;
                let authorized = text.contains("Authorization: Basic ");
                let (status, body) = if authorized || calls > 4 {
                    ("200 OK", "<GetDeviceInformationResponse/>")
                } else {
                    ("401 Unauthorized", "")
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });

        let client = SoapClient::new(&format!("http://127.0.0.1:{port}/onvif/device_service"))
            .unwrap()
            .with_credentials("admin", "secret")
            .with_auth_fallback();

        let body = "<x xmlns=\"y\"/>";
        client
            .soap_call(
                &format!("http://127.0.0.1:{port}/onvif/device_service"),
                body,
            )
            .await
            .unwrap();
        assert_eq!(client.effective_auth_mode(), Some(AuthMode::HttpBasic));

        // The sticky mode survives a clone (shared state).
        assert_eq!(
            client.clone().effective_auth_mode(),
            Some(AuthMode::HttpBasic)
        );
    }

    #[tokio::test]
    async fn diagnose_bad_credentials() {
        // A device that always answers NotAuthorized faults with 200.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let text = read_request(&mut sock).await;
                let body = if text.contains("GetSystemDateAndTime") {
                    // A sane current clock, so skew is NOT the answer.
                    "<GetSystemDateAndTimeResponse xmlns=\"http://www.onvif.org/ver10/device/wsdl\">\
                     <SystemDateAndTime><DateTimeType>NTP</DateTimeType><DaylightSavings>false</DaylightSavings>\
                     <UTCDateTime><Time><Hour>12</Hour><Minute>0</Minute><Second>0</Second></Time>\
                     <Date><Year>2026</Year><Month>10</Month><Day>12</Day></Date></UTCDateTime>\
                     </SystemDateAndTime></GetSystemDateAndTimeResponse>"
                } else {
                    "<Envelope xmlns=\"http://www.w3.org/2003/05/soap-envelope\"><Body>\
                     <Fault><Code><Value>s:Sender</Value><Subcode><Value>ter:NotAuthorized</Value></Subcode></Code>\
                     <Reason><Text>bad creds</Text></Reason></Fault></Body></Envelope>"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });

        let client = SoapClient::new(&format!("http://127.0.0.1:{port}/onvif/device_service"))
            .unwrap()
            .with_credentials("admin", "wrong");
        let diagnosis = client.diagnose_auth().await;
        assert_eq!(diagnosis.status, AuthStatus::BadCredentials);
    }
}
