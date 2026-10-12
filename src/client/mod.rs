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

pub mod motion;
pub mod notify;
pub mod push;
pub mod time;

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    /// response envelope; SOAP faults become [`ClientError::Fault`].
    pub async fn soap_call(&self, target: &str, body_xml: &str) -> Result<String, ClientError> {
        let target = parse_http_endpoint(target)?;
        let envelope = self.build_envelope(body_xml);

        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            target.path,
            target.host,
            target.port,
            envelope.len(),
            envelope
        );

        let raw = tokio::time::timeout(self.timeout, async {
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
        .map_err(|_| ClientError::Transport("exchange timed out".into()))??;

        if raw.len() > MAX_RESPONSE_BYTES {
            return Err(ClientError::Parse(format!(
                "response too large ({} bytes)",
                raw.len()
            )));
        }

        let body = split_http_body(&raw)?;
        if body.trim().is_empty() {
            return Err(ClientError::Parse("empty response body".into()));
        }

        if let Some(fault) = find_soap_fault(&body) {
            return Err(fault);
        }

        Ok(body)
    }

    /// POST to the configured device endpoint.
    pub async fn device_call(&self, body_xml: &str) -> Result<String, ClientError> {
        let url = format!(
            "http://{}:{}{}",
            self.endpoint.host, self.endpoint.port, self.endpoint.path
        );
        self.soap_call(&url, body_xml).await
    }

    fn build_envelope(&self, body_xml: &str) -> String {
        let header = match (&self.username, &self.password) {
            (Some(u), Some(p)) if !u.is_empty() => username_token_xml(u, p, self.clock_skew),
            _ => String::new(),
        };
        format!("<Envelope xmlns=\"{SOAP_ENVELOPE}\">{header}<Body>{body_xml}</Body></Envelope>")
    }

    pub(crate) fn has_credentials(&self) -> bool {
        matches!(&self.username, Some(u) if !u.is_empty())
    }
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
fn username_token_xml(username: &str, password: &str, clock_skew: Duration) -> String {
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
        "<Header><Security xmlns=\"{WSSE_NS}\"><UsernameToken xmlns:wsu=\"{WSU_NS}\">\
         <Username>{username}</Username>\
         <Password Type=\"{PASSWORD_DIGEST_TYPE}\">{digest}</Password>\
         <Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">{nonce_b64}</Nonce>\
         <Created xmlns=\"{WSU_NS}\">{created}</Created>\
         </UsernameToken></Security></Header>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
