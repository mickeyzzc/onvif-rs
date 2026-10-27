//! ONVIF client (consumer role): a minimal SOAP-over-HTTP caller plus the
//! capability package mirrored from the Go twin's v2.4.0 (issues
//! #126–#129 there): typed device time sync, WS-BaseNotification push
//! receiving, standard motion-topic parsing, and — in
//! [`crate::discovery_listener`] — the passive discovery listener.
//!
//! The library's first half is the Device (server) role; this module is
//! the consumer half for hosts that talk TO cameras (NVR-style recorders,
//! management tools, hybrid gateways). It is deliberately dependency-free
//! beyond what the server already uses: HTTP/1.1 is spoken over a plain
//! `tokio` TCP stream (`Connection: close` exchanges; `Content-Length`
//! and chunked responses both read; TLS is out of scope — `https://`
//! endpoints are rejected up front).
//!
//! Authentication is WS-Security UsernameToken PasswordDigest — the same
//! formula the server half verifies ([`crate::auth::compute_password_digest`]),
//! so a client built from this crate interops with this crate's own server
//! out of the box. Devices with drifted clocks are handled by stamping
//! `Created` with [`SoapClient::with_clock_skew`] (measure with
//! [`SoapClient::get_device_time`], which needs no credentials).
//!
//! ```
//! use onvif_device_rs::client::{motion, notify, SoapClient};
//!
//! # async fn demo() -> Result<(), onvif_device_rs::client::ClientError> {
//! let client = SoapClient::new("http://192.168.63.118:8080/onvif/device_service")?
//!     .with_credentials("admin", "secret");
//!
//! // Typed clock read (pre-auth): also the data source for clock skew.
//! let t = client.get_device_time().await?;
//! println!("camera clock: {}", t.utc.to_rfc3339());
//!
//! // Push events: probe, fall back to pull-point when unsupported.
//! use std::time::Duration;
//! match client.push_subscribe("http://nvr:8080/onvif/notify", Duration::from_secs(3600)).await {
//!     Ok(sub) => println!("push subscription: {}", sub.subscription_reference),
//!     Err(e) if e.is_push_not_supported() => { /* fall back to polling */ }
//!     Err(e) => return Err(e),
//! }
//!
//! // Notify POST parsing + standard motion recognition.
//! let msgs = notify::parse_notify_events("<s:Envelope/>")?;
//! let _ = msgs.first().and_then(motion::parse_motion_alarm);
//! # Ok(())
//! # }
//! ```

pub mod analytics;
pub mod auth;
pub mod device;
pub mod deviceio;
pub mod discovery;
pub mod events_pull;
pub mod imaging;
pub mod media;
pub mod media2;
pub mod metadata;
pub mod motion;
pub mod notify;
pub mod ptz;
pub mod push;
pub mod security;
pub mod time;

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use auth::{AuthDiagnosis, AuthMode, AuthStatus};

/// Errors of the client half. SOAP faults arrive as [`ClientError::Fault`]
/// regardless of the HTTP status (ONVIF devices frequently fault with
/// HTTP 200 — the same rule the server half enforces for its responses);
/// sender-side faults of a push Subscribe probe are normalized to
/// [`ClientError::PushNotSupported`] (see [`ClientError::is_push_not_supported`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The endpoint URL is not a plain `http://` address (TLS is out of
    /// scope for the client half) or is malformed.
    UnsupportedEndpoint(String),
    /// Socket-level failure (connect/write/read/timeout).
    Transport(String),
    /// The response was not usable SOAP (unparseable, or no body).
    Parse(String),
    /// A SOAP fault. `code`/`subcode` are SOAP 1.2 Code/Subcode values
    /// (or the SOAP 1.1 faultcode), `reason` the human-readable text.
    Fault {
        code: String,
        subcode: String,
        reason: String,
    },
    /// An invalid argument (rejected before the wire).
    InvalidArgument(String),
    /// A write operation was attempted without credentials — the twin of
    /// the Go library's `ErrNoCredentials`: an explicit state, not a
    /// generic device rejection.
    NoCredentials(String),
    /// The device answered the push Subscribe probe with a sender-side
    /// fault: it does not accept push subscriptions. Fall back to
    /// pull-point.
    PushNotSupported { code: String, reason: String },
    /// The device answered HTTP 200 with an empty body — the twin of the
    /// Go client's `ErrEmptyResponseBody`. Old firmwares (2016-era
    /// devices that cannot process a WS-Security digest) do this instead
    /// of answering 401 or a NotAuthorized fault. Not an auth failure by
    /// classification, but the fallback ladder treats it as retryable:
    /// the next auth mode often succeeds where the digest died.
    EmptyBody,
    /// An authentication-shaped failure: HTTP 401/403 or a NotAuthorized
    /// SOAP fault (the twin of the Go client's `ErrUnauthorized`). The
    /// fallback ladder and auth triage key off this class.
    Unauthorized(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedEndpoint(m) => write!(f, "unsupported endpoint: {m}"),
            Self::Transport(m) => write!(f, "transport: {m}"),
            Self::Parse(m) => write!(f, "parse: {m}"),
            Self::Fault {
                code,
                subcode,
                reason,
            } => {
                if subcode.is_empty() {
                    write!(f, "SOAP fault [{code}]: {reason}")
                } else {
                    write!(f, "SOAP fault [{code}/{subcode}]: {reason}")
                }
            }
            Self::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Self::NoCredentials(m) => write!(f, "credentials required: {m}"),
            Self::PushNotSupported { code, reason } => {
                write!(f, "push not supported [{code}]: {reason}")
            }
            Self::EmptyBody => write!(f, "received empty response body"),
            Self::Unauthorized(m) => write!(f, "unauthorized: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl ClientError {
    /// Whether this is a SOAP fault whose code/subcode is sender-side
    /// (`s:Sender`, `SOAP-ENV:Client`, …) — the class the push probe maps
    /// to [`ClientError::PushNotSupported`].
    #[must_use]
    pub fn is_sender_fault(&self) -> bool {
        let ClientError::Fault { code, subcode, .. } = self else {
            return false;
        };
        let joined = format!("{code}|{subcode}").to_lowercase();
        joined.contains("sender") || joined.contains("client")
    }

    /// Whether the device refused push subscriptions (fall back to
    /// pull-point).
    #[must_use]
    pub fn is_push_not_supported(&self) -> bool {
        matches!(self, Self::PushNotSupported { .. })
    }

    /// Whether this is an authentication-shaped failure (HTTP 401/403 or
    /// a NotAuthorized fault).
    #[must_use]
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Unauthorized(_))
    }

    /// Whether the auth fallback ladder should advance past this error:
    /// an auth-class failure, or an empty 200 response body (old
    /// firmwares answer a rejected digest with an empty body — no 401,
    /// no fault; the next auth mode often succeeds where the digest
    /// died). Empty bodies stay non-auth for classification — only the
    /// ladder decision treats them as retryable (the Go twin's
    /// `IsAuthLadderRetryable`, onvif-go #140).
    #[must_use]
    pub fn is_auth_ladder_retryable(&self) -> bool {
        self.is_unauthorized() || matches!(self, Self::EmptyBody)
    }
}

/// SOAP envelope namespace used by the client half.
pub(crate) const SOAP_ENVELOPE: &str = "http://www.w3.org/2003/05/soap-envelope";
const WSSE_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const PASSWORD_DIGEST_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";

/// One parsed `http://host:port/path` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEndpoint {
    /// Host name or IP literal (no scheme, no port).
    pub host: String,
    /// Port (defaults to 80 when the URL carries none).
    pub port: u16,
    /// Request path with leading `/`.
    pub path: String,
}

/// Parse a plain `http://` URL (the client half speaks no TLS).
pub(crate) fn parse_http_endpoint(url: &str) -> Result<HttpEndpoint, ClientError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        ClientError::UnsupportedEndpoint(format!(
            "{url}: the client half speaks plain http only (TLS is out of scope)"
        ))
    })?;

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| ClientError::UnsupportedEndpoint(format!("{url}: bad port")))?,
        ),
        None => (authority.to_string(), 80),
    };

    if host.is_empty() {
        return Err(ClientError::UnsupportedEndpoint(format!("{url}: no host")));
    }

    Ok(HttpEndpoint {
        host,
        port,
        path: path.to_string(),
    })
}

/// A wall-clock instant in UTC (unix seconds) with the crate's
/// dependency-free RFC 3339 rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct UtcStamp {
    /// Seconds since the unix epoch.
    pub unix: i64,
}

impl UtcStamp {
    /// From UTC calendar components.
    #[must_use]
    pub fn from_components(
        year: i64,
        month: i64,
        day: i64,
        hour: i64,
        minute: i64,
        second: i64,
    ) -> Self {
        // Days-from-civil (Howard Hinnant) — the same math the server half
        // uses in reverse in auth::parse_created_unix.
        let yy = if month <= 2 { year - 1 } else { year };
        let era = yy.div_euclid(400);
        let yoe = yy.rem_euclid(400);
        let mp = if month > 2 { month - 3 } else { month + 9 };
        let doy = (153 * mp + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe - 719468;
        Self {
            unix: days * 86400 + hour * 3600 + minute * 60 + second,
        }
    }

    /// RFC 3339 rendering (`2026-10-12T08:57:05Z`).
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        let (y, mo, d, h, mi, s) = crate::device::secs_to_utc(self.unix.max(0) as u64);
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    }
}

/// xs:dateTime shapes devices actually emit: RFC 3339 with/without
/// fraction and zone, bare local time, fractional-no-zone. Zone-less
/// forms are taken as UTC (the ONVIF time fields this parses are UTC).
pub(crate) fn parse_xsd_datetime(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }
    let base = crate::auth::parse_created_unix(s.get(0..19)?)?;

    let rest = s[19..].trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    let offset_secs = match rest {
        "" | "Z" | "z" => 0,
        zone => {
            let digits = zone.strip_prefix(['+', '-']).unwrap_or(zone);
            let (h, m) = if digits.len() >= 5 && digits.as_bytes()[2] == b':' {
                (
                    digits.get(0..2)?.parse::<i64>().ok()?,
                    digits.get(3..5)?.parse::<i64>().ok()?,
                )
            } else if digits.len() >= 4 {
                (
                    digits.get(0..2)?.parse::<i64>().ok()?,
                    digits.get(2..4)?.parse::<i64>().ok()?,
                )
            } else {
                (digits.parse::<i64>().ok()?, 0)
            };
            let magnitude = h * 3600 + m * 60;
            if zone.starts_with('-') {
                -magnitude
            } else {
                magnitude
            }
        }
    };

    Some(base - offset_secs)
}

/// ISO 8601 duration formatting, byte-identical with the Go twin's
/// `formatDuration` (`PT30S`, `PT1M`, `PT1M30S`, `PT60M` for an hour).
pub(crate) fn format_xs_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let minutes = secs / 60;
    let rem = secs % 60;
    if minutes == 0 {
        format!("PT{rem}S")
    } else if rem == 0 {
        format!("PT{minutes}M")
    } else {
        format!("PT{minutes}M{rem}S")
    }
}

/// Cap on one SOAP response: real ONVIF payloads are far smaller; the cap
/// keeps a hostile or broken device from pinning memory.
const MAX_RESPONSE_BYTES: usize = 4 << 20;

/// A minimal ONVIF SOAP caller: POST one action body to one endpoint,
/// with optional UsernameToken PasswordDigest security and a clock-skew
/// correction for the `Created` stamp.
///
/// The client is `Clone` (cheap — configuration only); each call opens a
/// fresh `Connection: close` exchange, so no connection state is shared
/// and calls may run concurrently.
#[derive(Debug, Clone)]
pub struct SoapClient {
    endpoint: HttpEndpoint,
    username: Option<String>,
    password: Option<String>,
    clock_skew: Duration,
    timeout: Duration,
    /// Auth-mode ladder / sticky / auto-skew state, shared across clones.
    pub(crate) auth_state: Arc<auth::AuthState>,
}

impl SoapClient {
    /// Build a client for `endpoint` (`http://host:port/path`).
    pub fn new(endpoint: &str) -> Result<Self, ClientError> {
        Ok(Self {
            endpoint: parse_http_endpoint(endpoint)?,
            username: None,
            password: None,
            clock_skew: Duration::ZERO,
            timeout: Duration::from_secs(30),
            auth_state: Arc::new(auth::AuthState::default()),
        })
    }

    /// Attach WS-Security UsernameToken PasswordDigest credentials.
    #[must_use]
    pub fn with_credentials(mut self, username: &str, password: &str) -> Self {
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self
    }

    /// Stamp `Created` `d` into the future (device clock ahead) — pair
    /// with [`SoapClient::get_device_time`] to keep digest auth working
    /// against drifted devices.
    #[must_use]
    pub fn with_clock_skew(mut self, d: Duration) -> Self {
        self.clock_skew = d;
        self
    }

    /// Per-exchange timeout (default 30 s).
    #[must_use]
    pub fn with_timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    /// The configured device endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &HttpEndpoint {
        &self.endpoint
    }

    /// POST `body_xml` (the SOAP action element) wrapped in an envelope to
    /// `target` — a full URL; pass the subscription manager address for
    /// wsnt:Renew/Unsubscribe, the device endpoint otherwise. Returns the
    /// response envelope; SOAP faults become [`ClientError::Fault`],
    /// auth-shaped failures become [`ClientError::Unauthorized`] (after
    /// the fallback ladder and the auto-skew retry, when enabled).
    pub async fn soap_call(&self, target: &str, body_xml: &str) -> Result<String, ClientError> {
        let fallback = self.auth_state.fallback;
        let initial = self.auth_state.initial_mode();
        let ladder = auth::AuthMode::ladder(initial);

        let mut last_retryable_err: Option<ClientError> = None;
        for (step, mode) in ladder.iter().enumerate() {
            match self.soap_call_once(target, body_xml, *mode).await {
                Ok(body) => {
                    if fallback && step > 0 {
                        *self
                            .auth_state
                            .sticky
                            .lock()
                            .unwrap_or_else(|g| g.into_inner()) = Some(*mode);
                    }
                    return Ok(body);
                }
                Err(e) if e.is_auth_ladder_retryable() => {
                    // Auto-skew: measure the device clock once and retry the
                    // SAME mode with a corrected Created stamp. Only an
                    // auth-class failure can be a clock-skew trap; an empty
                    // body means the device could not process the request.
                    if e.is_unauthorized()
                        && self.auth_state.auto_skew
                        && !*self
                            .auth_state
                            .skew_attempted
                            .lock()
                            .unwrap_or_else(|g| g.into_inner())
                    {
                        *self
                            .auth_state
                            .skew_attempted
                            .lock()
                            .unwrap_or_else(|g| g.into_inner()) = true;
                        // Inline anonymous clock read (single
                        // non-laddered exchange): going through
                        // get_device_time would recurse through soap_call.
                        if let Some(skew) = self.measure_clock_skew_secs().await {
                            if skew > 0 {
                                let skewed = SoapClient {
                                    clock_skew: Duration::from_secs(skew as u64),
                                    ..self.clone()
                                };
                                if let Ok(body) =
                                    skewed.soap_call_once(target, body_xml, *mode).await
                                {
                                    if fallback {
                                        *self
                                            .auth_state
                                            .sticky
                                            .lock()
                                            .unwrap_or_else(|g| g.into_inner()) = Some(*mode);
                                    }
                                    return Ok(body);
                                }
                            }
                        }
                    }
                    last_retryable_err = Some(e);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        // Ladder exhausted: the last retryable error surfaces as-is —
        // an auth-class failure stays `Unauthorized`, an empty-body
        // failure stays `EmptyBody` (never misreported as a credentials
        // problem; the Go twin's exhaustion rule, onvif-go #140).
        Err(last_retryable_err
            .unwrap_or_else(|| ClientError::Transport("no auth attempt made".into())))
    }

    /// One exchange under one explicit auth mode (a ladder step).
    async fn soap_call_once(
        &self,
        target: &str,
        body_xml: &str,
        mode: auth::AuthMode,
    ) -> Result<String, ClientError> {
        let target = parse_http_endpoint(target)?;
        let envelope = self.build_envelope_for_mode(body_xml, mode);

        let build_request = |authz: Option<String>| {
            let mut request = format!(
                "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/soap+xml; charset=utf-8\r\n",
                target.path, target.host, target.port,
            );
            match mode {
                auth::AuthMode::HttpBasic => {
                    if let Some((username, password)) = self.credentials() {
                        let token = BASE64.encode(format!("{username}:{password}"));
                        request.push_str(&format!("Authorization: Basic {token}\r\n"));
                    }
                }
                auth::AuthMode::HttpDigest => {
                    // The challenge-driven Authorization header rides only
                    // on the retry (see below).
                    if let Some(header) = authz {
                        request.push_str(&format!("Authorization: {header}\r\n"));
                    }
                }
                _ => {}
            }
            request.push_str(&format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n{envelope}",
                envelope.len()
            ));
            request
        };

        let mut raw = self.http_exchange(&target, &build_request(None)).await?;

        if raw.len() > MAX_RESPONSE_BYTES {
            return Err(ClientError::Parse(format!(
                "response too large ({} bytes)",
                raw.len()
            )));
        }

        if mode == auth::AuthMode::HttpDigest {
            // Answer a Digest challenge (RFC 7616 MD5 subset) with one
            // authenticated retry — no SOAP header on this leg.
            let (status, headers) = split_http_status_headers(&raw)?;
            if status == 401 {
                if let Some(challenge) = header_value(&headers, "www-authenticate")
                    .and_then(auth::parse_digest_challenge)
                {
                    if let Some((username, password)) = self.credentials() {
                        let nc = self.next_digest_nc(&challenge.nonce);
                        let nc_hex = format!("{nc:08x}");
                        let cnonce = auth::random_digest_cnonce();
                        let response = auth::digest_response_md5(
                            &username,
                            &password,
                            "POST",
                            &target.path,
                            &challenge,
                            &nc_hex,
                            &cnonce,
                        );
                        let authz = auth::build_digest_authorization(
                            &username,
                            &challenge,
                            &target.path,
                            &response,
                            &nc_hex,
                            &cnonce,
                        );
                        raw = self
                            .http_exchange(&target, &build_request(Some(authz)))
                            .await?;

                        if raw.len() > MAX_RESPONSE_BYTES {
                            return Err(ClientError::Parse(format!(
                                "response too large ({} bytes)",
                                raw.len()
                            )));
                        }
                    }
                }
            }
        }

        let (status, body) = split_http_status_body(&raw)?;

        if status == 401 || status == 403 {
            return Err(ClientError::Unauthorized(format!("HTTP {status}")));
        }

        if body.trim().is_empty() {
            return Err(ClientError::EmptyBody);
        }

        if let Some(fault) = find_soap_fault(&body) {
            if let ClientError::Fault {
                code,
                subcode,
                reason,
            } = &fault
            {
                if auth::is_notauthorized_fault(code, subcode) {
                    return Err(ClientError::Unauthorized(reason.clone()));
                }
            }
            return Err(fault);
        }

        Ok(body)
    }

    /// One HTTP/1.1 request/response exchange over a fresh connection
    /// (`Connection: close` — the client's transport contract).
    async fn http_exchange(
        &self,
        target: &HttpEndpoint,
        request: &str,
    ) -> Result<Vec<u8>, ClientError> {
        tokio::time::timeout(self.timeout, async {
            let mut sock = tokio::net::TcpStream::connect((target.host.as_str(), target.port))
                .await
                .map_err(|e| ClientError::Transport(format!("connect {}: {e}", target.host)))?;
            sock.write_all(request.as_bytes())
                .await
                .map_err(|e| ClientError::Transport(format!("write: {e}")))?;
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf)
                .await
                .map_err(|e| ClientError::Transport(format!("read: {e}")))?;
            Ok::<_, ClientError>(buf)
        })
        .await
        .map_err(|_| ClientError::Transport("exchange timed out".into()))?
    }

    /// Advance and return the nonce-count for an HTTP Digest nonce (the
    /// Go twin's shared-counter semantics: a server reusing nonces
    /// requires the count to advance). Bounded at 64 nonces — beyond that
    /// the bookkeeping resets, which at worst costs one stale-nc retry.
    fn next_digest_nc(&self, nonce: &str) -> u32 {
        let mut map = self
            .auth_state
            .digest_nc
            .lock()
            .unwrap_or_else(|g| g.into_inner());
        if map.len() >= 64 {
            map.clear();
        }
        let entry = map.entry(nonce.to_string()).or_insert(0);
        *entry += 1;
        *entry
    }

    /// One anonymous GetSystemDateAndTime exchange against the configured
    /// device endpoint, returning the device-minus-local offset in whole
    /// seconds (None when the clock cannot be read). Single-shot and
    /// ladder-free so the auto-skew retry cannot recurse.
    async fn measure_clock_skew_secs(&self) -> Option<i64> {
        let url = format!(
            "http://{}:{}{}",
            self.endpoint.host, self.endpoint.port, self.endpoint.path
        );
        let body = "<tds:GetSystemDateAndTime xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"></tds:GetSystemDateAndTime>";
        let resp = self
            .soap_call_once(&url, body, auth::AuthMode::None)
            .await
            .ok()?;
        let t = crate::client::time::parse_device_time(&resp).ok()?;
        let local = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Some(t.utc.unix - local)
    }

    pub(crate) fn credentials(&self) -> Option<(String, String)> {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) if !u.is_empty() => Some((u.clone(), p.clone())),
            _ => None,
        }
    }

    /// POST to the configured device endpoint.
    pub async fn device_call(&self, body_xml: &str) -> Result<String, ClientError> {
        let url = format!(
            "http://{}:{}{}",
            self.endpoint.host, self.endpoint.port, self.endpoint.path
        );
        self.soap_call(&url, body_xml).await
    }

    /// The envelope for one auth mode: UsernameToken (digest or cleartext)
    /// in the SOAP header; nothing for HTTP Basic (the transport header
    /// carries it) and None.
    ///
    /// Canonical compact wire form: `s:`-prefixed Envelope/Header/Body and
    /// the operation element's namespace declarations hoisted onto
    /// `s:Body`. The default-namespace form is semantically equivalent but
    /// strict parsers in old camera firmware answer HTTP 200 with an empty
    /// body (onvif-go #150 / MiBeeNvr#1074 has the packet-capture matrix:
    /// compact + prefix + hoisting must all hold).
    fn build_envelope_for_mode(&self, body_xml: &str, mode: auth::AuthMode) -> String {
        let header = match (mode, self.credentials()) {
            (auth::AuthMode::PasswordDigest, Some((u, p))) => {
                username_token_digest_xml(&u, &p, self.clock_skew)
            }
            (auth::AuthMode::PasswordText, Some((u, p))) => username_token_text_xml(&u, &p),
            _ => String::new(),
        };
        let (inner, decls) = hoist_namespace_decls(body_xml);
        let body_attrs = if decls.is_empty() {
            String::new()
        } else {
            format!(" {}", decls.join(" "))
        };
        format!(
            "<s:Envelope xmlns:s=\"{SOAP_ENVELOPE}\">{header}\
             <s:Body{body_attrs}>{inner}</s:Body></s:Envelope>"
        )
    }

    pub(crate) fn has_credentials(&self) -> bool {
        matches!(&self.username, Some(u) if !u.is_empty())
    }
}

/// Strip the root element's `xmlns="…"` and `xmlns:p="…"` declarations from
/// a body fragment and return them as complete attribute strings for
/// re-declaration on an ancestor (`s:Body` — a prefixed element whose
/// default namespace stays free, so un-prefixed children inherit it).
/// Attribute values in these fragments are namespace URLs (never
/// containing an unescaped quote), which makes scanning to the closing
/// quote unambiguous; a non-namespace attribute or unexpected shape falls
/// through and leaves the fragment untouched (still well-formed XML, just
/// not hoisted).
fn hoist_namespace_decls(fragment: &str) -> (String, Vec<String>) {
    let end = fragment.find('>').unwrap_or(fragment.len());
    let mut tag = fragment[..end].to_string();
    let rest = &fragment[end..];
    let mut decls = Vec::new();
    let mut i = 0;
    while i < tag.len() {
        let Some(rel) = tag[i..].find(" xmlns") else {
            break;
        };
        let start = i + rel + 1; // attribute name starts after the space
        let Some(eq_rel) = tag[start..].find('=') else {
            break;
        };
        let eq = start + eq_rel;
        let name = &tag[start..eq];
        if name == "xmlns" || name.starts_with("xmlns:") {
            let open = eq + 1; // fragments are assembled as xmlns="…", no space
            if tag.as_bytes().get(open) != Some(&b'"') {
                break;
            }
            let Some(cl_rel) = tag[open + 1..].find('"') else {
                break;
            };
            let close = open + 1 + cl_rel;
            decls.push(tag[start..=close].to_string());
            // Drop the declaration together with its preceding space.
            tag.replace_range(start - 1..=close, "");
            i = start - 1;
        } else {
            i = eq; // a different attribute; keep scanning after its name
        }
    }
    (format!("{tag}{rest}"), decls)
}

/// Split an HTTP/1.1 response into (status, body), de-chunking when the
/// server used `Transfer-Encoding: chunked`.
pub(crate) fn split_http_status_body(raw: &[u8]) -> Result<(u16, String), ClientError> {
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| ClientError::Parse("no HTTP body".into()))?;
    let head = String::from_utf8_lossy(&raw[..head_end]);

    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| ClientError::Parse("no HTTP status line".into()))?;

    let body = split_http_body(raw)?;
    Ok((status, body))
}

/// Split an HTTP/1.1 response into (status, header list) — the header
/// names lower-cased for case-insensitive lookup. Used by the
/// HTTP-Digest leg to read the `WWW-Authenticate` challenge.
pub(crate) fn split_http_status_headers(
    raw: &[u8],
) -> Result<(u16, Vec<(String, String)>), ClientError> {
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| ClientError::Parse("no HTTP body".into()))?;
    let head = String::from_utf8_lossy(&raw[..head_end]);

    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| ClientError::Parse("no HTTP status line".into()))?;

    let headers = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    Ok((status, headers))
}

/// Case-insensitive header lookup over [`split_http_status_headers`]
/// output.
fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let name = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.as_str())
}

/// Split an HTTP/1.1 response into its body bytes, de-chunking when the
/// server used `Transfer-Encoding: chunked`.
pub(crate) fn split_http_body(raw: &[u8]) -> Result<String, ClientError> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| ClientError::Parse("no HTTP body".into()))?;
    let (head, body) = raw.split_at(split + 4);

    let chunked = head.split(|&b| b == b'\n').any(|l| {
        let l = String::from_utf8_lossy(l).to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });

    let bytes = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    String::from_utf8(bytes).map_err(|e| ClientError::Parse(format!("response not UTF-8: {e}")))
}

/// Decode chunked transfer framing (per-chunk extensions and trailing
/// headers are ignored).
pub(crate) fn dechunk(body: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| ClientError::Parse("truncated chunk".into()))?;
        let size_str = String::from_utf8_lossy(&rest[..line_end]);
        let size_str = size_str.split(';').next().unwrap_or("").trim().to_string();
        let size = usize::from_str_radix(&size_str, 16)
            .map_err(|_| ClientError::Parse(format!("bad chunk size {size_str:?}")))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size {
            return Err(ClientError::Parse("truncated chunk payload".into()));
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        rest = rest
            .strip_prefix(b"\r\n")
            .ok_or_else(|| ClientError::Parse("missing chunk CRLF".into()))?;
    }
}

/// Local name of a start/end element (`dp0:NetworkVideoTransmitter` →
/// `NetworkVideoTransmitter`).
pub(crate) fn local_name(e: &quick_xml::events::BytesStart<'_>) -> String {
    let full = String::from_utf8_lossy(e.name().as_ref()).to_string();
    match full.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => full,
    }
}

/// Text content of the current element, entity-unescaped.
pub(crate) fn text_content(t: &quick_xml::events::BytesText<'_>) -> String {
    let raw = String::from_utf8_lossy(t.as_ref());
    match quick_xml::escape::unescape(raw.as_ref()) {
        Ok(s) => s.into_owned(),
        Err(_) => raw.into_owned(),
    }
}

/// Locate a SOAP Fault (local-name tolerant) and lift its
/// Code/Subcode/Reason fields.
pub(crate) fn find_soap_fault(body: &str) -> Option<ClientError> {
    let mut reader = quick_xml::Reader::from_str(body);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    let mut code = String::new();
    let mut subcode = String::new();
    let mut reason = String::new();

    let mut in_fault = false;
    let mut capture: Option<u8> = None; // 1=code 2=subcode 3=reason

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                if name == "Fault" {
                    in_fault = true;
                } else if in_fault {
                    let parent = stack.last().map(String::as_str).unwrap_or("");
                    capture = match (parent, name.as_str()) {
                        ("Code", "Value") => Some(1),
                        ("Subcode", "Value") => Some(2),
                        ("Reason", "Text") => Some(3),
                        _ => capture.take(),
                    };
                }
                stack.push(name);
            }
            Ok(XmlEvent::Text(t)) => {
                if in_fault {
                    let text = text_content(&t);
                    match (
                        capture,
                        code.is_empty(),
                        subcode.is_empty(),
                        reason.is_empty(),
                    ) {
                        (Some(1), true, _, _) => code = text,
                        (Some(2), _, true, _) => subcode = text,
                        (Some(3), _, _, true) => reason = text,
                        _ => {}
                    }
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
                if in_fault && stack.is_empty() {
                    break;
                }
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => return Some(ClientError::Parse(format!("scan fault: {e}"))),
        }
        buf.clear();
    }

    if !in_fault {
        return None;
    }

    Some(ClientError::Fault {
        code,
        subcode,
        reason,
    })
}

/// UsernameToken PasswordDigest header (the client side of the formula
/// [`crate::auth::compute_password_digest`] verifies).
pub(crate) fn username_token_digest_xml(
    username: &str,
    password: &str,
    clock_skew: Duration,
) -> String {
    use rand::RngCore;

    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_b64 = BASE64.encode(nonce);

    let created_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        + clock_skew.as_secs() as i64;
    let created = format!("{}.000Z", UtcStamp { unix: created_unix }.to_rfc3339());

    let digest = crate::auth::compute_password_digest(&nonce_b64, &created, password);

    format!(
        "<s:Header><wsse:Security xmlns:wsse=\"{WSSE_NS}\" xmlns:wsu=\"{WSU_NS}\">\
         <wsse:UsernameToken>\
         <wsse:Username>{username}</wsse:Username>\
         <wsse:Password Type=\"{PASSWORD_DIGEST_TYPE}\">{digest}</wsse:Password>\
         <wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">{nonce_b64}</wsse:Nonce>\
         <wsu:Created>{created}</wsu:Created>\
         </wsse:UsernameToken></wsse:Security></s:Header>"
    )
}

/// UsernameToken cleartext PasswordText header — the digest-rejecting
/// firmware fallback.
pub(crate) fn username_token_text_xml(username: &str, password: &str) -> String {
    format!(
        "<s:Header><wsse:Security xmlns:wsse=\"{WSSE_NS}\" xmlns:wsu=\"{WSU_NS}\">\
         <wsse:UsernameToken>\
         <wsse:Username>{username}</wsse:Username>\
         <wsse:Password Type=\"{PASSWORD_TEXT_TYPE}\">{password}</wsse:Password>\
         </wsse:UsernameToken></wsse:Security></s:Header>"
    )
}

const PASSWORD_TEXT_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical compact wire form (onvif-go #150 twin): s:-prefixed
    /// envelope, wsse:/wsu: header, operation namespace hoisted onto s:Body,
    /// no inter-element whitespace.
    #[test]
    fn envelope_wire_form_canonical() {
        let c = SoapClient::new("http://192.168.62.1:80/onvif/device_service")
            .expect("client")
            .with_credentials("admin", "secret");
        let body =
            "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><token/></GetProfiles>";
        let env = c.build_envelope_for_mode(body, auth::AuthMode::PasswordText);
        assert!(
            env.starts_with(
                "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Header>"
            ),
            "{env}"
        );
        assert!(env.contains("<wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu="), "{env}");
        assert!(
            env.contains("<wsse:Username>admin</wsse:Username>"),
            "{env}"
        );
        // Namespace hoisted off the operation element onto s:Body.
        assert!(
            env.contains("<s:Body xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><GetProfiles><token/></GetProfiles></s:Body>"),
            "{env}"
        );
        assert!(env.ends_with("</s:Body></s:Envelope>"), "{env}");
        assert!(!env.contains("\n"), "compact, no whitespace: {env}");
    }

    #[test]
    fn hoist_namespace_decls_variants() {
        // default ns hoisted
        let (inner, d) = hoist_namespace_decls(
            "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><x/></GetProfiles>",
        );
        assert_eq!(
            d,
            vec!["xmlns=\"http://www.onvif.org/ver10/media/wsdl\"".to_string()]
        );
        assert_eq!(inner, "<GetProfiles><x/></GetProfiles>");
        // prefixed ns hoisted, other attribute kept
        let (inner, d) = hoist_namespace_decls(
            "<tr2:GetProfiles xmlns:tr2=\"http://www.onvif.org/ver20/media/wsdl\" Token=\"1\"/>",
        );
        assert_eq!(
            d,
            vec!["xmlns:tr2=\"http://www.onvif.org/ver20/media/wsdl\"".to_string()]
        );
        assert_eq!(inner, "<tr2:GetProfiles Token=\"1\"/>");
        // both forms together
        let (inner, d) = hoist_namespace_decls("<a xmlns=\"urn:x\" xmlns:p=\"urn:p\"/>");
        assert_eq!(d.len(), 2);
        assert_eq!(inner, "<a/>");
        // nothing to hoist stays verbatim
        let (inner, d) = hoist_namespace_decls("<Plain/>");
        assert_eq!(inner, "<Plain/>");
        assert!(d.is_empty());
    }

    #[test]
    fn xs_duration_matches_go_twin() {
        assert_eq!(format_xs_duration(Duration::from_secs(30)), "PT30S");
        assert_eq!(format_xs_duration(Duration::from_secs(60)), "PT1M");
        assert_eq!(format_xs_duration(Duration::from_secs(90)), "PT1M30S");
        assert_eq!(format_xs_duration(Duration::from_secs(300)), "PT5M");
        assert_eq!(format_xs_duration(Duration::from_secs(65)), "PT1M5S");
        assert_eq!(format_xs_duration(Duration::from_secs(3600)), "PT60M");
    }

    fn render(unix: i64) -> String {
        UtcStamp { unix }.to_rfc3339()
    }

    #[test]
    fn xs_datetime_layouts() {
        assert_eq!(
            parse_xsd_datetime("2026-10-12T09:00:00Z")
                .map(render)
                .as_deref(),
            Some("2026-10-12T09:00:00Z")
        );
        assert_eq!(
            parse_xsd_datetime("2026-10-12T09:00:00.5Z")
                .map(render)
                .as_deref(),
            Some("2026-10-12T09:00:00Z")
        );
        assert_eq!(
            parse_xsd_datetime("2026-10-12T09:00:00")
                .map(render)
                .as_deref(),
            Some("2026-10-12T09:00:00Z")
        );
        assert_eq!(
            parse_xsd_datetime("2026-10-12T09:00:00.25")
                .map(render)
                .as_deref(),
            Some("2026-10-12T09:00:00Z")
        );
        // 17:00 at +08:00 is 09:00 UTC
        assert_eq!(
            parse_xsd_datetime("2026-10-12T17:00:00+08:00")
                .map(render)
                .as_deref(),
            Some("2026-10-12T09:00:00Z")
        );
        assert_eq!(
            parse_xsd_datetime("2026-10-12T05:00:00-04:00")
                .map(render)
                .as_deref(),
            Some("2026-10-12T09:00:00Z")
        );
        assert!(parse_xsd_datetime("garbage").is_none());
        assert!(parse_xsd_datetime("").is_none());
    }

    #[test]
    fn http_body_split_and_dechunk() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        assert_eq!(split_http_body(raw).unwrap(), "ok");

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n";
        assert_eq!(split_http_body(chunked).unwrap(), "abcdefg");
    }

    #[test]
    fn soap12_fault_extraction() {
        let body = r#"<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body>
            <Fault><Code><Value>s:Sender</Value><Subcode><Value>ter:FilteringRequestedNotSupported</Value></Subcode></Code>
            <Reason><Text xml:lang="en">Not supported</Text></Reason></Fault>
            </Body></Envelope>"#;
        let err = find_soap_fault(body).unwrap();
        assert!(err.is_sender_fault());
        match err {
            ClientError::Fault {
                code,
                subcode,
                reason,
            } => {
                assert_eq!(code, "s:Sender");
                assert_eq!(subcode, "ter:FilteringRequestedNotSupported");
                assert_eq!(reason, "Not supported");
            }
            other => panic!("expected fault, got {other:?}"),
        }
    }

    #[test]
    fn receiver_fault_is_not_sender() {
        let body = r#"<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body>
            <Fault><Code><Value>s:Receiver</Value></Code><Reason><Text>internal</Text></Reason></Fault>
            </Body></Envelope>"#;
        let err = find_soap_fault(body).unwrap();
        assert!(!err.is_sender_fault());
    }

    #[test]
    fn no_fault_in_regular_response() {
        let body = r#"<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body><GetDeviceInformationResponse/></Body></Envelope>"#;
        assert!(find_soap_fault(body).is_none());
    }

    #[test]
    fn endpoint_parsing() {
        let e = parse_http_endpoint("http://192.168.1.64:80/onvif/device_service").unwrap();
        assert_eq!(
            (e.host.as_str(), e.port, e.path.as_str()),
            ("192.168.1.64", 80, "/onvif/device_service")
        );
        let e = parse_http_endpoint("http://cam/onvif").unwrap();
        assert_eq!(e.port, 80);
        assert!(parse_http_endpoint("https://cam/onvif").is_err());
        assert!(parse_http_endpoint("not a url").is_err());
    }

    #[test]
    fn utc_stamp_roundtrip() {
        let s = UtcStamp::from_components(2026, 10, 12, 8, 57, 5);
        assert_eq!(s.to_rfc3339(), "2026-10-12T08:57:05Z");
        let epoch = UtcStamp::from_components(1970, 1, 1, 0, 0, 0);
        assert_eq!(epoch.unix, 0);
        let leap = UtcStamp::from_components(2000, 2, 29, 12, 34, 56);
        assert_eq!(leap.to_rfc3339(), "2000-02-29T12:34:56Z");
    }
}
