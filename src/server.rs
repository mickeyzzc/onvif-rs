use std::collections::{HashMap, HashSet};
use std::str;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use quick_xml::events::Event;
use quick_xml::Reader;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::auth::verify_username_token;
use crate::types::{serialize_soap_fault, AuthResult, OnvifError, RequestInfo, UsernameToken};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default cap on a request body (SOAP envelopes are a few KiB).
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
/// Default per-connection read timeout.
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard cap on the HTTP header section.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Configuration for the ONVIF SOAP server.
///
/// Auth is **fail-closed**: starting the server with an empty password and
/// `allow_no_auth = false` (the default) is a configuration error. Hosts
/// that deliberately want an open server must set `allow_no_auth = true`.
#[derive(Debug, Clone)]
pub struct OnvifConfig {
    /// Port to bind (`OnvifServer::start`). Ignored by [`OnvifServer::start_on`].
    pub port: u16,
    /// WS-UsernameToken username expected from clients.
    pub username: String,
    /// WS-UsernameToken password expected from clients.
    pub password: String,
    /// Explicitly permit running without authentication when the password is
    /// empty (every action becomes open). Default `false` — fail closed.
    pub allow_no_auth: bool,
    /// Maximum accepted HTTP request body in bytes. Larger bodies are
    /// rejected with 413. Default 1 MiB.
    pub max_body_bytes: usize,
    /// Per-connection read timeout (header + body). Default 30 s.
    pub read_timeout: Duration,
}

impl Default for OnvifConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            username: String::new(),
            password: String::new(),
            allow_no_auth: false,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            read_timeout: DEFAULT_READ_TIMEOUT,
        }
    }
}

// ---------------------------------------------------------------------------
// Server handle
// ---------------------------------------------------------------------------

/// Handle to a running ONVIF SOAP server.
///
/// Await it (`handle.await`) to wait for the accept loop to finish, or call
/// [`OnvifServerHandle::shutdown`] for a graceful stop.
#[derive(Debug)]
pub struct OnvifServerHandle {
    task: Option<tokio::task::JoinHandle<()>>,
    shutdown: watch::Sender<bool>,
}

impl OnvifServerHandle {
    /// Request a graceful shutdown and wait for the accept loop to finish.
    /// In-flight connections finish their current request first.
    pub async fn shutdown(&mut self) -> Result<(), OnvifError> {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|e| OnvifError::Internal(format!("server task join failed: {e}")))?;
        }
        Ok(())
    }
}

impl std::future::Future for OnvifServerHandle {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.task.as_mut() {
            Some(task) => std::pin::Pin::new(task).poll(cx).map(|_| ()),
            None => std::task::Poll::Ready(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Action handler trait
// ---------------------------------------------------------------------------

/// Handler for a single ONVIF SOAP action.
///
/// `body` is the raw XML content of the SOAP Body's child (the action
/// element).  `request_info` provides caller context and the authentication
/// outcome.
#[async_trait]
pub trait OnvifActionHandler: Send + Sync {
    async fn handle(&self, body: &str, request_info: &RequestInfo) -> Result<String, OnvifError>;
}

// ---------------------------------------------------------------------------
// Parsed SOAP
// ---------------------------------------------------------------------------

/// Result of parsing an incoming SOAP 1.2 request.
pub(crate) struct ParsedSoap {
    pub action: String,
    pub body_xml: String,
    pub username_token: Option<UsernameToken>,
}

// ---------------------------------------------------------------------------
// OnvifServer
// ---------------------------------------------------------------------------

/// SOAP / ONVIF server that listens on a configured port and dispatches
/// SOAP actions to registered handlers.
pub struct OnvifServer {
    config: OnvifConfig,
    handlers: HashMap<String, Box<dyn OnvifActionHandler>>,
    /// SOAP actions exempt from authentication (pre-auth per ONVIF spec).
    anonymous_actions: HashSet<String>,
}

impl OnvifServer {
    /// Create a new server with the given configuration.
    pub fn new(config: &OnvifConfig) -> Self {
        Self {
            config: config.clone(),
            handlers: HashMap::new(),
            anonymous_actions: HashSet::new(),
        }
    }

    /// Register a handler for a SOAP action (local element name of the
    /// first child of the SOAP Body).
    pub fn register_handler(&mut self, action: &str, handler: Box<dyn OnvifActionHandler>) {
        self.handlers.insert(action.to_string(), handler);
    }

    /// Mark a SOAP action as accessible without authentication.
    ///
    /// Per the ONVIF spec, `GetSystemDateAndTime` must be reachable before a
    /// client can compute the WS-Security digest, so it is exempt from auth.
    pub fn register_anonymous_action(&mut self, action: &str) {
        self.anonymous_actions.insert(action.to_string());
    }

    /// Validate the configuration. Fail-closed: an empty password without an
    /// explicit `allow_no_auth` is a configuration error, not an open server.
    fn validate_config(config: &OnvifConfig) -> Result<(), OnvifError> {
        if config.password.is_empty() && !config.allow_no_auth {
            return Err(OnvifError::NotAuthorized(
                "OnvifConfig.password is empty — set credentials, or set \
                 allow_no_auth = true to deliberately run an open server"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Start listening on `0.0.0.0:{config.port}` and serve.
    ///
    /// Consumes `self` — all handlers must be registered before calling
    /// this. Returns an [`OnvifServerHandle`] for graceful shutdown.
    pub async fn start(self) -> Result<OnvifServerHandle, OnvifError> {
        Self::validate_config(&self.config)?;
        let addr = format!("0.0.0.0:{}", self.config.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| OnvifError::Internal(format!("bind {addr}: {e}")))?;
        self.start_on(listener).await
    }

    /// Serve on an already-bound listener (injection point for tests, custom
    /// bind addresses, or sharing a port with host infrastructure).
    ///
    /// `OnvifConfig::port` is ignored; the listener's own address is used.
    pub async fn start_on(self, listener: TcpListener) -> Result<OnvifServerHandle, OnvifError> {
        Self::validate_config(&self.config)?;
        let local_addr = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        log::info!("onvif: serving SOAP on {local_addr}");

        let handlers = Arc::new(self.handlers);
        let cfg = Arc::new(self.config);
        let anonymous = Arc::new(self.anonymous_actions);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(async move {
            loop {
                let (mut stream, peer_addr) = tokio::select! {
                    accepted = listener.accept() => match accepted {
                        Ok(conn) => conn,
                        Err(e) => {
                            // Accept errors are usually transient
                            log::warn!("onvif: accept error: {e}");
                            continue;
                        }
                    },
                    _ = shutdown_rx.changed() => {
                        log::info!("onvif: shutdown requested — accept loop stopping");
                        break;
                    }
                };

                let handlers = Arc::clone(&handlers);
                let cfg = Arc::clone(&cfg);
                let anonymous = Arc::clone(&anonymous);

                tokio::spawn(async move {
                    let client_ip = peer_addr.ip().to_string();
                    let server_ip = stream
                        .local_addr()
                        .map(|a| a.ip().to_string())
                        .unwrap_or_default();
                    if let Err(e) = handle_connection(
                        &mut stream,
                        &client_ip,
                        &server_ip,
                        &handlers,
                        &cfg,
                        &anonymous,
                    )
                    .await
                    {
                        log::error!("onvif: connection error from {client_ip}: {e}");
                    }
                });
            }
        });

        Ok(OnvifServerHandle {
            task: Some(task),
            shutdown: shutdown_tx,
        })
    }
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

/// Internal server state shared across connections.
type HandlerMap = Arc<HashMap<String, Box<dyn OnvifActionHandler>>>;
type SharedConfig = Arc<OnvifConfig>;
type SharedAnonymous = Arc<HashSet<String>>;

async fn handle_connection(
    stream: &mut tokio::net::TcpStream,
    client_ip: &str,
    server_ip: &str,
    handlers: &HandlerMap,
    cfg: &SharedConfig,
    anonymous: &SharedAnonymous,
) -> Result<(), OnvifError> {
    // --- Read HTTP request (bounded header, bounded body, read timeout) ---
    let read = read_http_request(stream, cfg);
    let (method, body) = match tokio::time::timeout(cfg.read_timeout, read).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(OnvifError::InvalidXml(m))) if m.starts_with("body too large") => {
            let fault = serialize_soap_fault("soap:Sender", &m);
            write_http_response(stream, 413, &fault).await?;
            // Drain the in-flight body before closing so the client sees the
            // 413 instead of a connection reset (RFC 7230 §6.6 politeness).
            drain_before_close(stream).await;
            return Ok(());
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            log::warn!("onvif: read timeout from {client_ip}");
            return Ok(());
        }
    };

    if method != "POST" {
        let fault = serialize_soap_fault("soap:Sender", "only POST method is supported");
        write_http_response(stream, 405, &fault).await?;
        return Ok(());
    }

    // --- Parse SOAP ---
    let parsed = match parse_soap_request(&body) {
        Ok(p) => p,
        Err(e) => {
            let fault = serialize_soap_fault("soap:Client", &e.to_string());
            write_http_response(stream, 400, &fault).await?;
            return Ok(());
        }
    };

    // --- Auth ---
    // `auth_disabled` requires BOTH an explicit opt-in flag and an empty
    // password — an empty password alone never silently disables auth.
    let auth_disabled = cfg.allow_no_auth && cfg.password.is_empty();
    let auth_result = if let Some(ref token) = parsed.username_token {
        let ok = verify_username_token(token, &cfg.username, &cfg.password);
        AuthResult {
            username: token.username.clone(),
            authenticated: ok,
        }
    } else {
        AuthResult::default()
    };

    // --- Action check ---
    if parsed.action.is_empty() {
        let fault = serialize_soap_fault("soap:Client", "no action found in SOAP body");
        write_http_response(stream, 400, &fault).await?;
        return Ok(());
    }

    // --- Dispatch ---
    let handler = match handlers.get(&parsed.action) {
        Some(h) => h,
        None => {
            let fault = serialize_soap_fault(
                "soap:Sender",
                &format!("unsupported action: {}", parsed.action),
            );
            write_http_response(stream, 400, &fault).await?;
            return Ok(());
        }
    };

    let is_anonymous = anonymous.contains(&parsed.action);
    if !is_anonymous && !auth_disabled && !auth_result.authenticated {
        let fault = serialize_soap_fault(
            "soap:Sender",
            &format!("authentication required for action: {}", parsed.action),
        );
        write_http_response(stream, 401, &fault).await?;
        return Ok(());
    }

    let request_info = RequestInfo {
        client_ip: client_ip.to_string(),
        server_ip: server_ip.to_string(),
        auth_result,
    };

    match handler.handle(&parsed.body_xml, &request_info).await {
        Ok(response_xml) => {
            write_http_response(stream, 200, &response_xml).await?;
        }
        Err(e) => {
            let fault = serialize_soap_fault("soap:Receiver", &e.to_string());
            write_http_response(stream, 500, &fault).await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Minimal HTTP request reader
// ---------------------------------------------------------------------------

/// Read one HTTP request: header section (capped at [`MAX_HEADER_BYTES`],
/// may span multiple reads), then exactly `Content-Length` body bytes
/// (capped at `cfg.max_body_bytes`).
async fn read_http_request(
    stream: &mut tokio::net::TcpStream,
    cfg: &OnvifConfig,
) -> Result<(String, String), OnvifError> {
    let mut data: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];

    // Read until the end of the header section (or the cap).
    let header_end = loop {
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if data.len() > MAX_HEADER_BYTES {
            return Err(OnvifError::InvalidXml("malformed HTTP headers".into()));
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| OnvifError::Internal(format!("read request: {e}")))?;
        if n == 0 {
            return Err(OnvifError::InvalidXml("empty request".into()));
        }
        data.extend_from_slice(&chunk[..n]);
    };

    let header_str = str::from_utf8(&data[..header_end])
        .map_err(|_| OnvifError::InvalidXml("invalid HTTP header encoding".into()))?;

    // Extract method (first token of the first line)
    let first_line = header_str.lines().next().unwrap_or("");
    let method = first_line
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();

    // Extract Content-Length
    let content_length = header_str
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-length:") {
                lower
                    .trim_start_matches("content-length:")
                    .trim()
                    .parse::<usize>()
                    .ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    if content_length > cfg.max_body_bytes {
        return Err(OnvifError::InvalidXml(format!(
            "body too large: {content_length} bytes exceeds limit {}",
            cfg.max_body_bytes
        )));
    }

    // Body starts after headers; keep whatever arrived with them (bounded
    // by the declared Content-Length — the connection closes after each
    // response, so pipelined bytes beyond it are ignored).
    let body_start = header_end + 4;
    let mut body: Vec<u8> = data[body_start..].to_vec();
    body.truncate(content_length);

    // Read the remainder of the declared body.
    while body.len() < content_length {
        let m = stream
            .read(&mut chunk)
            .await
            .map_err(|e| OnvifError::Internal(format!("read body: {e}")))?;
        if m == 0 {
            break; // EOF before Content-Length — truncated
        }
        body.extend_from_slice(&chunk[..m]);
    }

    let body_str = String::from_utf8(body)
        .map_err(|_| OnvifError::InvalidXml("request body is not valid UTF-8".into()))?;

    Ok((method, body_str))
}

/// Read and discard pending inbound bytes (bounded) so closing the socket
/// sends FIN instead of RST while the peer is still writing.
async fn drain_before_close(stream: &mut tokio::net::TcpStream) {
    let mut scratch = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let mut drained: usize = 0;
    loop {
        let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remain.is_zero() || drained > 4 * 1024 * 1024 {
            break;
        }
        match tokio::time::timeout(remain, stream.read(&mut scratch)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => drained += n,
        }
    }
}

/// Write an HTTP 1.1 response with `Content-Type: application/soap+xml`.
async fn write_http_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &str,
) -> Result<(), OnvifError> {
    let status_line = match status {
        200 => "200 OK",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        405 => "405 Method Not Allowed",
        413 => "413 Content Too Large",
        500 => "500 Internal Server Error",
        _ => "500 Internal Server Error",
    };

    let header = format!(
        "HTTP/1.1 {status_line}\r\n\
         Content-Type: application/soap+xml; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );

    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|e| OnvifError::Internal(format!("write response header: {e}")))?;
    stream
        .write_all(body.as_bytes())
        .await
        .map_err(|e| OnvifError::Internal(format!("write response body: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// SOAP XML parsing
// ---------------------------------------------------------------------------

/// Parse a SOAP 1.2 envelope and extract the action name, body XML, and
/// optional WS-UsernameToken.
///
/// Uses `quick_xml::Reader` as a streaming XML state machine.
pub(crate) fn parse_soap_request(xml: &str) -> Result<ParsedSoap, OnvifError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();

    // State machine
    #[derive(Default)]
    struct ParseState {
        in_header: bool,
        in_security: bool,
        in_ut: bool,
        in_body: bool,
        // UsernameToken fields being accumulated
        ut_username: String,
        ut_password: String,
        ut_nonce: String,
        ut_created: String,
        current_field: String,
        // Action and body
        action: String,
        body_xml: String,
        body_writer: Option<quick_xml::Writer<Vec<u8>>>,
    }

    let mut st = ParseState::default();

    loop {
        let event = reader.read_event_into(&mut buf);
        match event {
            Ok(Event::Start(e)) => {
                let name_bytes = e.name().as_ref().to_owned();
                let qname = str::from_utf8(&name_bytes).unwrap_or("");
                let local = qname.rsplit(':').next().unwrap_or(qname);

                match local {
                    "Header" => st.in_header = true,
                    "Security" if st.in_header => st.in_security = true,
                    "UsernameToken" if st.in_security => st.in_ut = true,
                    "Body" => {
                        st.in_body = true;
                        st.body_writer = Some(quick_xml::Writer::new(Vec::new()));
                    }
                    _ => {
                        if st.in_ut && st.current_field.is_empty() {
                            st.current_field = local.to_string();
                        }
                        if st.in_body && st.action.is_empty() {
                            st.action = local.to_string();
                            // Write the action element to the body writer
                            if let Some(ref mut w) = st.body_writer {
                                let _ = w.write_event(Event::Start(e.clone()));
                            }
                        } else if st.in_body {
                            if let Some(ref mut w) = st.body_writer {
                                let _ = w.write_event(Event::Start(e.clone()));
                            }
                        }
                    }
                }
            }

            Ok(Event::Empty(e)) => {
                let name_bytes = e.name().as_ref().to_owned();
                let qname = str::from_utf8(&name_bytes).unwrap_or("");
                let local = qname.rsplit(':').next().unwrap_or(qname);

                // Self-closing structural elements do not change parse state.
                // They are handled in the _ branch (writing to body_writer if inside Body).
                match local {
                    "Header" | "Security" | "UsernameToken" | "Body" => {}
                    _ => {
                        if st.in_ut && st.current_field.is_empty() {
                            st.current_field = local.to_string();
                        }
                        if st.in_body && st.action.is_empty() {
                            st.action = local.to_string();
                            if let Some(ref mut w) = st.body_writer {
                                let _ = w.write_event(Event::Empty(e.clone()));
                            }
                        } else if st.in_body {
                            if let Some(ref mut w) = st.body_writer {
                                let _ = w.write_event(Event::Empty(e.clone()));
                            }
                        }
                    }
                }
            }

            Ok(Event::End(e)) => {
                let name_bytes = e.name().as_ref().to_owned();
                let qname = str::from_utf8(&name_bytes).unwrap_or("");
                let local = qname.rsplit(':').next().unwrap_or(qname);

                // The Body's own close tag terminates body_xml — do not copy
                // it in (its opening twin was never written, so appending it
                // would leave a dangling close tag for strict downstream
                // parsers like imaging's SetImagingSettings).
                if local == "Body" && st.in_body {
                    st.in_body = false;
                    st.body_xml = st
                        .body_writer
                        .take()
                        .map(|w| String::from_utf8(w.into_inner()).unwrap_or_default())
                        .unwrap_or_default();
                } else if st.in_body {
                    if let Some(ref mut w) = st.body_writer {
                        let _ = w.write_event(Event::End(e.clone()));
                    }
                }

                match local {
                    "Header" => st.in_header = false,
                    "Security" => st.in_security = false,
                    "UsernameToken" => {
                        st.in_ut = false;
                        st.current_field.clear();
                    }
                    _ => {
                        if st.in_ut {
                            st.current_field.clear();
                        }
                    }
                }
            }

            Ok(Event::Text(e)) => {
                if let Ok(text) = e.unescape() {
                    let text = text.as_ref().to_string();
                    if st.in_ut {
                        match st.current_field.as_str() {
                            "Username" => st.ut_username = text,
                            "Password" => st.ut_password = text,
                            "Nonce" => st.ut_nonce = text,
                            "Created" => st.ut_created = text,
                            _ => {}
                        }
                    }
                    if st.in_body {
                        if let Some(ref mut w) = st.body_writer {
                            let _ = w.write_event(Event::Text(e.clone()));
                        }
                    }
                }
            }

            Ok(Event::CData(e)) => {
                if st.in_body {
                    if let Some(ref mut w) = st.body_writer {
                        let _ = w.write_event(Event::CData(e.clone()));
                    }
                }
            }

            Ok(Event::Eof) => break,

            Err(e) => {
                return Err(OnvifError::InvalidXml(format!("XML parse error: {e}")));
            }

            _ => {}
        }
        buf.clear();
    }

    // quick-xml does not validate balanced tags; check our state machine
    // to reject incomplete XML where an element was opened but never closed.
    if st.in_body || st.in_security || st.in_ut {
        return Err(OnvifError::InvalidXml(
            "XML parse error: unexpected end of input, unclosed element".to_string(),
        ));
    }

    let username_token = if !st.ut_username.is_empty() {
        Some(UsernameToken {
            username: st.ut_username,
            password: st.ut_password,
            nonce: st.ut_nonce,
            created: st.ut_created,
        })
    } else {
        None
    };

    Ok(ParsedSoap {
        action: st.action,
        body_xml: st.body_xml,
        username_token,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespaces::SOAP_ENVELOPE;
    use crate::types::serialize_soap_response;

    // ------------------------------------------------------------------
    // SOAP parsing
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_simple_envelope() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
          <soap:Header/>
          <soap:Body>
            <GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>
          </soap:Body>
        </soap:Envelope>"#;

        let parsed = parse_soap_request(xml).unwrap();
        assert_eq!(parsed.action, "GetDeviceInformation");
        assert!(parsed.body_xml.contains("GetDeviceInformation"));
        assert!(parsed.username_token.is_none());
    }

    #[test]
    fn test_parse_body_xml_is_balanced() {
        // Regression: the writer used to emit the closing `</soap:Body>` (and
        // could not emit its opening twin) into body_xml, leaving a dangling
        // close tag. Substring-searching handlers tolerated it, but strict
        // downstream parsers (imaging's SetImagingSettings) failed end-to-end
        // even though their unit tests — fed balanced fragments — passed.
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
          <soap:Body>
            <SetImagingSettings xmlns="http://www.onvif.org/ver20/imaging/wsdl/">
              <Settings><Brightness Value="0.8"/></Settings>
            </SetImagingSettings>
          </soap:Body>
        </soap:Envelope>"#;

        let parsed = parse_soap_request(xml).unwrap();
        let body = &parsed.body_xml;
        assert!(
            !body.contains("</soap:Body>") && !body.contains("</s:Body>"),
            "body_xml must not leak the Body close tag: {body}"
        );
        assert!(
            body.trim_end().ends_with("</SetImagingSettings>"),
            "body_xml must end at the action element: {body}"
        );

        // The strict reader used by imaging's parse_settings must accept it.
        let mut reader = quick_xml::Reader::from_str(body);
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Eof) | Err(_) => break,
                Ok(_) => {}
            }
            buf.clear();
        }
    }

    #[test]
    fn test_parse_with_security_header() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                       xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                       xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
          <soap:Header>
            <wsse:Security>
              <wsse:UsernameToken>
                <wsse:Username>admin</wsse:Username>
                <wsse:Password>secret</wsse:Password>
                <wsse:Nonce>dGhpcyBpcyBhIG5vbmNl</wsse:Nonce>
                <wsu:Created>2025-01-01T00:00:00Z</wsu:Created>
              </wsse:UsernameToken>
            </wsse:Security>
          </soap:Header>
          <soap:Body>
            <GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>
          </soap:Body>
        </soap:Envelope>"#;

        let parsed = parse_soap_request(xml).unwrap();
        assert_eq!(parsed.action, "GetProfiles");
        let token = parsed.username_token.expect("should have UsernameToken");
        assert_eq!(token.username, "admin");
        assert_eq!(token.password, "secret");
        assert_eq!(token.nonce, "dGhpcyBpcyBhIG5vbmNl");
        assert_eq!(token.created, "2025-01-01T00:00:00Z");
    }

    #[test]
    fn test_parse_empty_body() {
        let xml = r#"<?xml version="1.0"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
          <soap:Header/>
          <soap:Body/>
        </soap:Envelope>"#;

        let parsed = parse_soap_request(xml).unwrap();
        assert!(parsed.action.is_empty());
        assert!(parsed.body_xml.is_empty());
        assert!(parsed.username_token.is_none());
    }

    #[test]
    fn test_parse_malformed_xml() {
        // quick_xml is lenient: non-XML input produces no events but no error
        let result = parse_soap_request("not xml at all");
        if let Ok(parsed) = result {
            assert!(parsed.action.is_empty());
            assert!(parsed.body_xml.is_empty());
            assert!(parsed.username_token.is_none());
        }
        // Actual XML parse errors (e.g. unclosed tags) should still error
        let broken = parse_soap_request("<Envelope><Body><unclosed>");
        assert!(broken.is_err());
    }

    #[test]
    fn test_parse_with_default_namespace() {
        // Some ONVIF clients use default namespace instead of prefixed
        let xml = r#"<?xml version="1.0"?>
        <Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
          <Header/>
          <Body>
            <GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>
          </Body>
        </Envelope>"#;

        let parsed = parse_soap_request(xml).unwrap();
        assert_eq!(parsed.action, "GetSystemDateAndTime");
    }

    // ------------------------------------------------------------------
    // Auth integration
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_and_auth_plaintext() {
        let xml = r#"<?xml version="1.0"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                       xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
          <soap:Header>
            <wsse:Security>
              <wsse:UsernameToken>
                <wsse:Username>admin</wsse:Username>
                <wsse:Password>correct</wsse:Password>
              </wsse:UsernameToken>
            </wsse:Security>
          </soap:Header>
          <soap:Body>
            <GetDeviceInformation/>
          </soap:Body>
        </soap:Envelope>"#;

        let parsed = parse_soap_request(xml).unwrap();
        let token = parsed.username_token.unwrap();

        // Verify correct password
        assert!(verify_username_token(&token, "admin", "correct"));
        // Verify wrong password
        assert!(!verify_username_token(&token, "admin", "wrong"));
    }

    // ------------------------------------------------------------------
    // Fault generation
    // ------------------------------------------------------------------

    #[test]
    fn test_fault_action_not_supported() {
        let fault = serialize_soap_fault("soap:Sender", "unsupported action: GetFoo");
        assert!(fault.contains("soap:Fault"));
        assert!(fault.contains("unsupported action: GetFoo"));
        assert!(fault.contains(SOAP_ENVELOPE));
    }

    #[test]
    fn test_fault_not_authorized() {
        let fault = serialize_soap_fault(
            "soap:Sender",
            "authentication required for action: SetConfiguration",
        );
        assert!(fault.contains("soap:Fault"));
        assert!(fault.contains("authentication required"));
    }

    // ------------------------------------------------------------------
    // Action router
    // ------------------------------------------------------------------

    struct TestHandler {
        response: String,
    }

    #[async_trait]
    impl OnvifActionHandler for TestHandler {
        async fn handle(&self, _body: &str, _info: &RequestInfo) -> Result<String, OnvifError> {
            Ok(self.response.clone())
        }
    }

    #[test]
    fn test_action_router_dispatch() {
        let mut server = OnvifServer::new(&OnvifConfig {
            port: 0, // won't actually listen
            username: "admin".into(),
            password: "pass".into(),
            ..Default::default()
        });

        server.register_handler(
            "GetStatus",
            Box::new(TestHandler {
                response: "<GetStatusResponse/>".into(),
            }),
        );

        // Verify handler was registered
        assert!(server.handlers.contains_key("GetStatus"));
        assert_eq!(server.handlers.len(), 1);
    }

    #[test]
    fn test_action_router_unknown_action() {
        let server = OnvifServer::new(&OnvifConfig {
            port: 0,
            username: "admin".into(),
            password: "pass".into(),
            ..Default::default()
        });

        assert!(!server.handlers.contains_key("GetFoo"));
    }

    #[test]
    fn test_anonymous_action_registration() {
        let mut server = OnvifServer::new(&OnvifConfig {
            port: 0,
            username: "admin".into(),
            password: "pass".into(),
            ..Default::default()
        });

        assert!(!server.anonymous_actions.contains("GetSystemDateAndTime"));
        server.register_anonymous_action("GetSystemDateAndTime");
        assert!(server.anonymous_actions.contains("GetSystemDateAndTime"));
        assert!(!server.anonymous_actions.contains("GetCapabilities"));
    }
    // ------------------------------------------------------------------
    // HTTP request parsing
    // ------------------------------------------------------------------

    #[test]
    fn test_read_http_request_parses_method() {
        // We test the method extraction logic directly
        let raw = b"POST /onvif/device_service HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let header_str = str::from_utf8(&raw[..header_end]).unwrap();
        let first_line = header_str.lines().next().unwrap();
        let method = first_line.split_whitespace().next().unwrap();
        assert_eq!(method, "POST");
    }

    #[test]
    fn test_read_http_request_content_length() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 11\r\n\r\nHello World";
        let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let header_str = str::from_utf8(&raw[..header_end]).unwrap();
        let cl = header_str
            .lines()
            .find_map(|l| {
                let lower = l.to_ascii_lowercase();
                if lower.starts_with("content-length:") {
                    lower
                        .trim_start_matches("content-length:")
                        .trim()
                        .parse::<usize>()
                        .ok()
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(cl, 11);
    }

    // ------------------------------------------------------------------
    // Response serialization round-trip
    // ------------------------------------------------------------------

    #[test]
    fn test_response_round_trip() {
        let response = serialize_soap_response("<TestResponse>ok</TestResponse>");
        let parsed = parse_soap_request(&response).unwrap();
        assert_eq!(parsed.action, "TestResponse");
    }

    // ------------------------------------------------------------------
    // body_xml reconstruction
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_body_xml_content() {
        let xml = r#"<?xml version="1.0"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
          <soap:Body>
            <GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl">
              <SomeParam>value</SomeParam>
            </GetDeviceInformation>
          </soap:Body>
        </soap:Envelope>"#;

        let parsed = parse_soap_request(xml).unwrap();
        assert_eq!(parsed.action, "GetDeviceInformation");
        assert!(parsed.body_xml.contains("GetDeviceInformation"));
        assert!(parsed.body_xml.contains("SomeParam"));
        assert!(parsed.body_xml.contains("value"));
    }
}
