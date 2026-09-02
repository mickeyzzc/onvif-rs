// ---------------------------------------------------------------------------
// WS-Discovery (WS-Discovery) UDP multicast responder for ONVIF device
// discovery.
//
// Listens on `239.255.255.250:3702` for Probe messages and responds with
// ProbeMatches containing device XAddrs, Scopes, and Types.
//
// Also provides an HTTP handler for `POST /onvif/discovery`.
// ---------------------------------------------------------------------------

use std::net::{Ipv4Addr, UdpSocket as StdUdpSocket};
use std::sync::Arc;

use quick_xml::events::Event;
use quick_xml::Reader;
use rand::RngCore;
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// WS-Discovery UDP multicast address.
pub const DISCOVERY_ADDR: &str = "239.255.255.250:3702";

/// WS-Discovery namespace.
pub const DISCOVERY_NS: &str = "http://schemas.xmlsoap.org/ws/2004/09/discovery";

/// WS-Discovery Probe action URI.
pub const PROBE_ACTION: &str = "http://schemas.xmlsoap.org/ws/2004/09/discovery/Probe";

/// WS-Discovery ProbeMatches action URI.
pub const PROBE_MATCHES_ACTION: &str =
    "http://schemas.xmlsoap.org/ws/2004/09/discovery/ProbeMatches";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur in WS-Discovery operations.
#[derive(Debug)]
pub enum DiscoveryError {
    /// I/O error (UDP socket, network).
    Io(std::io::Error),
    /// Invalid or unparseable Probe message.
    InvalidXml(String),
    /// Server/configuration error.
    Server(String),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryError::Io(e) => write!(f, "Discovery I/O error: {e}"),
            DiscoveryError::InvalidXml(s) => write!(f, "Invalid Probe XML: {s}"),
            DiscoveryError::Server(s) => write!(f, "Discovery server error: {s}"),
        }
    }
}

impl std::error::Error for DiscoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DiscoveryError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DiscoveryError {
    fn from(e: std::io::Error) -> Self {
        DiscoveryError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a version 4 (random) UUID string with `uuid:` prefix.
fn generate_uuid() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    // Set UUID version 4 (random)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set UUID variant (RFC 4122)
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex_str = hex::encode(bytes);
    format!(
        "uuid:{}-{}-{}-{}-{}",
        &hex_str[0..8],
        &hex_str[8..12],
        &hex_str[12..16],
        &hex_str[16..20],
        &hex_str[20..32]
    )
}

/// Detect the local non-loopback IPv4 address for XAddr generation.
///
/// Uses the "connect to a known address" technique which finds the IP
/// associated with the default route without actually sending any data.
/// On an isolated network with no default route the fallback is loopback —
/// XAddrs built from it are unreachable for remote clients, so a warning is
/// logged. Pass an explicit `device_ip` to [`DiscoveryServer::new`] to avoid
/// the fallback entirely.
pub fn detect_local_ip() -> String {
    if let Ok(socket) = StdUdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = socket.local_addr() {
                let ip = local.ip();
                if !ip.is_loopback() && ip.is_ipv4() {
                    return ip.to_string();
                }
            }
        }
    }
    // Last resort
    log::warn!(
        "onvif: could not detect a routable local IP — discovery XAddrs fall back to 127.0.0.1 \
         (unreachable for remote clients); pass an explicit device_ip"
    );
    "127.0.0.1".to_string()
}

/// Check whether the SOAP action is a WS-Discovery Probe.
///
/// Matches both the full URI and suffix form (used by some NVR clients).
fn is_probe_action(action: &str) -> bool {
    action == PROBE_ACTION || action.ends_with("/discovery/Probe")
}

/// Build an `onvif://www.onvif.org/<category>/<value>` scope URI.
///
/// The value is percent-encoded: the `<d:Scopes>` element is a
/// space-separated list, so a literal space in a name would split one scope
/// into two broken fragments on the wire.
fn scope_uri(category: &str, value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    format!("onvif://www.onvif.org/{category}/{encoded}")
}

/// Escape a string for interpolation as XML text (client-supplied
/// MessageIDs and host-configured URIs both reach ProbeMatches).
fn xml_escape(text: &str) -> std::borrow::Cow<'_, str> {
    quick_xml::escape::escape(text)
}

// ---------------------------------------------------------------------------
// Probe XML parsing
// ---------------------------------------------------------------------------

/// Extract the `MessageID` from a WS-Discovery Probe Envelope.
///
/// Returns `None` if the message is not a valid Probe or cannot be parsed.
fn parse_probe(msg: &[u8]) -> Option<String> {
    let xml = std::str::from_utf8(msg).ok()?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut in_header = false;
    let mut action = String::new();
    let mut message_id = String::new();
    let mut current_field = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name_bytes = e.name();
                let name = std::str::from_utf8(name_bytes.as_ref()).ok()?;
                let local = name.rsplit(':').next().unwrap_or(name);
                match local {
                    "Header" => in_header = true,
                    "Action" if in_header => current_field = "Action".to_string(),
                    "MessageID" if in_header => current_field = "MessageID".to_string(),
                    "Body" => in_header = false,
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                let name_bytes = e.name();
                let name = std::str::from_utf8(name_bytes.as_ref()).ok()?;
                let local = name.rsplit(':').next().unwrap_or(name);
                if local == "Body" {
                    in_header = false;
                }
            }
            Ok(Event::Text(e)) => {
                if let Ok(text) = e.unescape() {
                    if in_header {
                        match current_field.as_str() {
                            "Action" => action = text.to_string(),
                            "MessageID" => message_id = text.to_string(),
                            _ => {}
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name_bytes = e.name();
                let name = std::str::from_utf8(name_bytes.as_ref()).ok()?;
                let local = name.rsplit(':').next().unwrap_or(name);
                match local {
                    "Header" => in_header = false,
                    "Action" | "MessageID" => current_field.clear(),
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }

    if !is_probe_action(&action) {
        return None;
    }

    Some(if message_id.is_empty() {
        "uuid:unknown".to_string()
    } else {
        message_id
    })
}

// ---------------------------------------------------------------------------
// DiscoveryServer
// ---------------------------------------------------------------------------

/// WS-Discovery responder that listens for UDP multicast Probe messages
/// and responds with ProbeMatches.
///
/// # Example
///
/// ```rust,no_run
/// use onvif_device_rs::discovery::DiscoveryServer;
///
/// let server = DiscoveryServer::with_identity(
///     "192.0.2.10",
///     8080,
///     "Front Gate Camera",
///     "IMX219",
/// );
/// // let handle = server.start().await.unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct DiscoveryServer {
    /// The device's own IP address used in XAddr URLs.
    device_ip: String,
    /// The ONVIF HTTP server port.
    onvif_port: u16,
    /// Unique device identifier (UUID with `uuid:` prefix).
    uuid: String,
    /// ONVIF scope URIs.
    scopes: Vec<String>,
}

impl DiscoveryServer {
    /// Create a new `DiscoveryServer` with neutral scopes.
    ///
    /// `device_ip` is the IP address to use in XAddr URLs. If empty, the
    /// server attempts to auto-detect the local non-loopback IPv4 address
    /// (and logs a warning when detection falls back to loopback).
    ///
    /// The default scope set is only `onvif://www.onvif.org/Profile/Streaming`
    /// — use [`DiscoveryServer::with_identity`] or
    /// [`DiscoveryServer::with_scopes`] to advertise a name/hardware scope.
    /// A fresh random UUID is generated; persist one across restarts with
    /// [`DiscoveryServer::with_uuid`] so NVRs keying on EndpointReference
    /// do not see a new device after every reboot.
    #[must_use]
    pub fn new(device_ip: &str, onvif_port: u16) -> Self {
        let ip = if device_ip.is_empty() {
            detect_local_ip()
        } else {
            device_ip.to_string()
        };

        Self {
            device_ip: ip,
            onvif_port,
            uuid: generate_uuid(),
            scopes: vec!["onvif://www.onvif.org/Profile/Streaming".to_string()],
        }
    }

    /// Create a `DiscoveryServer` that advertises the device's name and
    /// hardware in its scopes:
    /// `onvif://www.onvif.org/name/<name>` and
    /// `onvif://www.onvif.org/hardware/<hardware_id>`.
    #[must_use]
    pub fn with_identity(device_ip: &str, onvif_port: u16, name: &str, hardware_id: &str) -> Self {
        let mut server = Self::new(device_ip, onvif_port);
        server.scopes.push(scope_uri("name", name));
        server.scopes.push(scope_uri("hardware", hardware_id));
        server
    }

    /// Override the scope set entirely (caller controls the full URIs).
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Set a stable device UUID (with `uuid:` prefix) so the discovery
    /// identity survives process restarts.
    #[must_use]
    pub fn with_uuid(mut self, uuid: &str) -> Self {
        self.uuid = uuid.to_string();
        self
    }

    /// Returns the device UUID (with `uuid:` prefix).
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    /// Returns the ONVIF scope URIs.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Build XAddr URLs for the given host IP.
    ///
    /// When `host_ip` is empty the device's own IP is used (for UDP probes).
    /// For HTTP probes `host_ip` should be the server's local address from
    /// the connection context.
    pub fn xaddrs(&self, host_ip: &str) -> Vec<String> {
        let ip = if host_ip.is_empty() {
            &self.device_ip
        } else {
            host_ip
        };
        vec![format!(
            "http://{ip}:{}/onvif/device_service",
            self.onvif_port
        )]
    }

    /// Build the ProbeMatches XML response for a given `message_id`.
    ///
    /// `host_ip` controls the IP in XAddr URLs (empty = use device's own IP).
    /// Client-controlled values (the echoed `message_id`) and host-configured
    /// scopes are XML-escaped.
    pub fn build_probe_matches(&self, message_id: &str, host_ip: &str) -> Vec<u8> {
        let scopes_str = self.scopes.join(" ");
        let xaddrs_str = self.xaddrs(host_ip).join(" ");

        let mut xml = String::new();
        xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        xml.push_str(r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" "#);
        xml.push_str(r#"xmlns:a="http://www.w3.org/2005/08/addressing">"#);
        xml.push_str("<s:Header>");
        xml.push_str(&format!(
            r#"<a:Action s:mustUnderstand="1">{}</a:Action>"#,
            PROBE_MATCHES_ACTION
        ));
        xml.push_str(&format!(
            "<a:RelatesTo>{}</a:RelatesTo>",
            xml_escape(message_id)
        ));
        xml.push_str(
            r#"<a:To s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>"#,
        );
        xml.push_str("</s:Header>");
        xml.push_str("<s:Body>");
        xml.push_str(&format!(r#"<d:ProbeMatches xmlns:d="{}">"#, DISCOVERY_NS));
        xml.push_str("<d:ProbeMatch>");
        xml.push_str(&format!(
            r#"<a:EndpointReference xmlns:a="http://www.w3.org/2005/08/addressing"><a:Address>{}</a:Address></a:EndpointReference>"#,
            xml_escape(&self.uuid)
        ));
        xml.push_str(&format!("<d:Scopes>{}</d:Scopes>", xml_escape(&scopes_str)));
        xml.push_str(&format!("<d:XAddrs>{}</d:XAddrs>", xml_escape(&xaddrs_str)));
        xml.push_str("<d:Types>tdn:NetworkVideoTransmitter tdn:Device</d:Types>");
        xml.push_str("<d:MetadataVersion>1</d:MetadataVersion>");
        xml.push_str("</d:ProbeMatch>");
        xml.push_str("</d:ProbeMatches>");
        xml.push_str("</s:Body>");
        xml.push_str("</s:Envelope>");

        xml.into_bytes()
    }

    /// Handle a raw Probe message and return the ProbeMatches response.
    ///
    /// Returns `None` if the message is not a valid Probe.
    ///
    /// `host_ip` controls the IP in XAddr URLs. Pass `""` for UDP probes
    /// (uses the device's own IP). For HTTP probes, pass the server's local
    /// connection IP.
    pub fn handle_probe(&self, msg: &[u8], host_ip: &str) -> Option<Vec<u8>> {
        let message_id = parse_probe(msg)?;
        Some(self.build_probe_matches(&message_id, host_ip))
    }

    /// Start the UDP multicast listener.
    ///
    /// Binds to `0.0.0.0:3702`, joins the `239.255.255.250` multicast group,
    /// and spawns a background task that reads Probe messages and sends
    /// ProbeMatches responses.
    ///
    /// Returns a [`DiscoveryHandle`] — await it for the listener task's exit
    /// or call [`DiscoveryHandle::shutdown`] to stop it. (Binding and
    /// joining happen before the handle is returned, so `Ok` really means
    /// the responder is up.)
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError::Io` if the UDP socket cannot be bound or
    /// the multicast group cannot be joined.
    pub async fn start(&self) -> Result<DiscoveryHandle, DiscoveryError> {
        // Create UDP socket with SO_REUSEADDR (required for multicast + restarts).
        use socket2::{Domain, Protocol, Socket, Type};
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        sock.set_nonblocking(true)?;
        sock.bind(&(std::net::SocketAddr::from((Ipv4Addr::UNSPECIFIED, 3702))).into())?;
        let std_socket: StdUdpSocket = sock.into();
        // Join multicast on the specific interface.
        let iface: Ipv4Addr = self.device_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        std_socket.join_multicast_v4(&Ipv4Addr::new(239, 255, 255, 250), &iface)?;
        std_socket.set_multicast_ttl_v4(1)?;
        std_socket.set_multicast_loop_v4(true)?;

        let socket = UdpSocket::from_std(std_socket)?;
        let server = Arc::new(self.clone());
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = run_udp_listener_once(&socket, &server) => {
                        if let Err(e) = result {
                            log::error!("discovery: UDP listener error: {e}");
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        log::info!("discovery: shutdown requested — UDP listener stopping");
                        break;
                    }
                }
            }
        });

        Ok(DiscoveryHandle {
            task: Some(task),
            shutdown: shutdown_tx,
        })
    }
}

/// Handle to a running WS-Discovery responder.
///
/// `#[must_use]`: dropping the handle stops the responder (same Drop
/// semantics as the SOAP server handle).
#[derive(Debug)]
#[must_use = "dropping the handle stops the responder; await it or store it for shutdown()"]
pub struct DiscoveryHandle {
    task: Option<tokio::task::JoinHandle<()>>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl DiscoveryHandle {
    /// Stop the discovery listener and wait for its task to finish.
    pub async fn shutdown(&mut self) -> Result<(), DiscoveryError> {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|e| DiscoveryError::Server(format!("listener task join failed: {e}")))?;
        }
        Ok(())
    }
}

impl std::future::Future for DiscoveryHandle {
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
// Background UDP listener task
// ---------------------------------------------------------------------------

/// Serve one UDP datagram (probe response). Errors are returned so the
/// caller's select loop can log and keep running.
async fn run_udp_listener_once(
    socket: &UdpSocket,
    server: &DiscoveryServer,
) -> Result<(), DiscoveryError> {
    let mut buf = vec![0u8; 8192];
    let (n, src) = socket.recv_from(&mut buf).await?;
    let msg = &buf[..n];
    // For UDP probes, always use the device's own IP for XAddr —
    // never the requester's source IP.
    if let Some(resp) = server.handle_probe(msg, "") {
        if let Err(e) = socket.send_to(&resp, src).await {
            log::error!("discovery: failed to send ProbeMatches to {src}: {e}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP Probe handler
// ---------------------------------------------------------------------------

/// Handle an HTTP POST Probe request to `/onvif/discovery`.
///
/// Reads the SOAP XML body, extracts the Probe MessageID, and returns a
/// ProbeMatches response with the given `server_ip` in XAddr URLs.
///
/// Returns `(status_code, response_body)` where status is 200 on success
/// and `body` contains the SOAP XML. Non-Probe requests return 200 with an
/// empty body.
pub fn handle_http_probe(server: &DiscoveryServer, body: &str, server_ip: &str) -> (u16, String) {
    let resp = server.handle_probe(body.as_bytes(), server_ip);
    match resp {
        Some(xml) => (200, String::from_utf8(xml).unwrap_or_default()),
        None => (200, String::new()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // probe parsing
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_probe_valid() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                     xmlns:a="http://www.w3.org/2005/08/addressing">
          <s:Header>
            <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/discovery/Probe</a:Action>
            <a:MessageID>uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890</a:MessageID>
          </s:Header>
          <s:Body>
            <d:Probe xmlns:d="http://schemas.xmlsoap.org/ws/2004/09/discovery"/>
          </s:Body>
        </s:Envelope>"#;

        let msg_id = parse_probe(xml.as_bytes()).expect("should parse Probe");
        assert_eq!(msg_id, "uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890");
    }

    #[test]
    fn test_parse_probe_with_default_namespace() {
        // Some ONVIF clients use default (unprefixed) namespace.
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
        <Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
          <Header>
            <Action>http://schemas.xmlsoap.org/ws/2004/09/discovery/Probe</Action>
            <MessageID>uuid:simple-id</MessageID>
          </Header>
          <Body>
            <Probe xmlns="http://schemas.xmlsoap.org/ws/2004/09/discovery"/>
          </Body>
        </Envelope>"#;

        let msg_id = parse_probe(xml.as_bytes()).expect("should parse default-ns Probe");
        assert_eq!(msg_id, "uuid:simple-id");
    }

    #[test]
    fn test_parse_probe_suffix_action() {
        // Some NVR clients use the suffix form of the action.
        let xml = r#"<?xml version="1.0"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Header>
            <a:Action xmlns:a="http://www.w3.org/2005/08/addressing">/discovery/Probe</a:Action>
            <a:MessageID xmlns:a="http://www.w3.org/2005/08/addressing">uuid:suffix-test</a:MessageID>
          </s:Header>
          <s:Body>
            <d:Probe xmlns:d="http://schemas.xmlsoap.org/ws/2004/09/discovery"/>
          </s:Body>
        </s:Envelope>"#;

        let msg_id = parse_probe(xml.as_bytes()).expect("should parse suffix-action Probe");
        assert_eq!(msg_id, "uuid:suffix-test");
    }

    #[test]
    fn test_parse_probe_missing_message_id() {
        let xml = r#"<?xml version="1.0"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Header>
            <a:Action xmlns:a="http://www.w3.org/2005/08/addressing">http://schemas.xmlsoap.org/ws/2004/09/discovery/Probe</a:Action>
          </s:Header>
          <s:Body>
            <d:Probe xmlns:d="http://schemas.xmlsoap.org/ws/2004/09/discovery"/>
          </s:Body>
        </s:Envelope>"#;

        let msg_id = parse_probe(xml.as_bytes()).expect("should handle missing MessageID");
        assert_eq!(msg_id, "uuid:unknown");
    }

    #[test]
    fn test_parse_probe_wrong_action() {
        // A non-Probe message should return None.
        let xml = r#"<?xml version="1.0"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Header>
            <a:Action xmlns:a="http://www.w3.org/2005/08/addressing">http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation</a:Action>
          </s:Header>
          <s:Body>
            <GetDeviceInformation/>
          </s:Body>
        </s:Envelope>"#;

        assert!(
            parse_probe(xml.as_bytes()).is_none(),
            "non-Probe action should return None"
        );
    }

    #[test]
    fn test_parse_probe_invalid_xml() {
        assert!(parse_probe(b"not xml").is_none());
        assert!(parse_probe(b"").is_none());
    }

    // ------------------------------------------------------------------
    // probematches generation
    // ------------------------------------------------------------------

    #[test]
    fn test_build_probe_matches_contains_required_elements() {
        let server = DiscoveryServer::new("192.168.1.100", 8080);
        let resp = server.build_probe_matches("uuid:test-id", "");
        let xml = String::from_utf8(resp).expect("valid UTF-8");

        // XML declaration
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        // Envelope
        assert!(xml.contains("<s:Envelope"));
        assert!(xml.contains("</s:Envelope>"));
        // Header with action
        assert!(xml.contains(PROBE_MATCHES_ACTION));
        assert!(xml.contains("<a:RelatesTo>uuid:test-id</a:RelatesTo>"));
        // Body / ProbeMatches
        assert!(xml.contains("<d:ProbeMatches"));
        assert!(xml.contains("<d:ProbeMatch>"));
        // Scopes
        assert!(xml.contains("<d:Scopes>"));
        assert!(xml.contains("onvif://www.onvif.org/Profile/Streaming"));
        // XAddrs
        assert!(xml.contains("<d:XAddrs>"));
        assert!(xml.contains("192.168.1.100:8080/onvif/device_service"));
        // Types
        assert!(xml.contains("<d:Types>"));
        assert!(xml.contains("tdn:NetworkVideoTransmitter"));
        // MetadataVersion
        assert!(xml.contains("<d:MetadataVersion>1</d:MetadataVersion>"));
        // EndpointReference with UUID
        assert!(xml.contains(&server.uuid));
    }

    #[test]
    fn test_build_probe_matches_with_host_ip() {
        let server = DiscoveryServer::new("10.0.0.1", 8080);
        let resp = server.build_probe_matches("uuid:test", "10.0.0.2");
        let xml = String::from_utf8(resp).expect("valid UTF-8");

        // XAddr should use the provided host_ip, not the device_ip
        assert!(xml.contains("10.0.0.2:8080/onvif/device_service"));
        assert!(!xml.contains("10.0.0.1:8080/onvif/device_service"));
    }

    #[test]
    fn test_build_probe_matches_is_valid_xml() {
        let server = DiscoveryServer::new("192.168.1.1", 8080);
        let resp = server.build_probe_matches("uuid:validate", "");
        let xml = String::from_utf8(resp).expect("valid UTF-8");

        // Verify it's well-formed XML (quick-xml can parse it)
        let mut reader = Reader::from_str(&xml);
        let mut buf = Vec::new();
        let mut events = 0usize;
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(_) => events += 1,
                Err(e) => panic!("ProbeMatches is not well-formed XML: {e}"),
            }
            buf.clear();
        }
        assert!(events > 10, "should have many XML events, got {events}");
    }

    // ------------------------------------------------------------------
    // xaddr construction
    // ------------------------------------------------------------------

    #[test]
    fn test_xaddrs_with_explicit_host() {
        let server = DiscoveryServer::new("10.0.0.1", 8080);
        let addrs = server.xaddrs("10.0.0.2");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "http://10.0.0.2:8080/onvif/device_service");
    }

    #[test]
    fn test_xaddrs_with_empty_host_uses_device_ip() {
        let server = DiscoveryServer::new("10.0.0.1", 8080);
        let addrs = server.xaddrs("");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "http://10.0.0.1:8080/onvif/device_service");
    }

    #[test]
    fn test_xaddrs_custom_port() {
        let server = DiscoveryServer::new("10.0.0.1", 2020);
        let addrs = server.xaddrs("");
        assert_eq!(addrs[0], "http://10.0.0.1:2020/onvif/device_service");
    }

    // ------------------------------------------------------------------
    // scopes format
    // ------------------------------------------------------------------

    #[test]
    fn test_scopes_contains_required_categories() {
        let server = DiscoveryServer::with_identity("10.0.0.1", 8080, "Gate Cam", "IMX219");
        let scopes = server.scopes();
        // Must have a Streaming profile scope
        assert!(scopes.iter().any(|s| s.contains("Profile/Streaming")));
        // Must have a name scope (percent-encoded — scope lists are
        // space-separated, so spaces must not appear literally)
        assert!(scopes.iter().any(|s| s.contains("/name/Gate%20Cam")));
        // Must have a hardware scope
        assert!(scopes.iter().any(|s| s.contains("/hardware/IMX219")));
    }

    /// Regression: plain `new()` must NOT advertise origin-hardware
    /// branding (PiCameraV1/OV5647) — the neutral default carries only the
    /// spec profile scope.
    #[test]
    fn test_scopes_default_is_neutral() {
        let server = DiscoveryServer::new("10.0.0.1", 8080);
        let scopes = server.scopes();
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0], "onvif://www.onvif.org/Profile/Streaming");
        assert!(!scopes.iter().any(|s| s.contains("PiCameraV1")));
        assert!(!scopes.iter().any(|s| s.contains("OV5647")));
    }

    /// Regression: the discovery UUID must be persistable across restarts.
    #[test]
    fn test_uuid_can_be_pinned() {
        let pinned = "uuid:12345678-1234-4123-8123-123456789abc";
        let server = DiscoveryServer::new("10.0.0.1", 8080).with_uuid(pinned);
        assert_eq!(server.uuid(), pinned);
    }

    /// Regression: a client-controlled MessageID must be XML-escaped in
    /// RelatesTo (injection guard).
    #[test]
    fn test_probe_matches_escapes_message_id() {
        let server = DiscoveryServer::new("10.0.0.1", 8080);
        let evil = "uuid:abc--<inject/>&amp;";
        let resp = server.build_probe_matches(evil, "");
        let xml = String::from_utf8(resp).expect("utf8");
        assert!(xml.contains("&lt;inject/&gt;"), "escaped: {xml}");
        assert!(!xml.contains("<inject/>"), "no raw injection: {xml}");
    }

    #[test]
    fn test_scopes_are_onvif_urls() {
        let server = DiscoveryServer::new("10.0.0.1", 8080);
        for scope in server.scopes() {
            assert!(
                scope.starts_with("onvif://www.onvif.org/"),
                "scope '{scope}' should start with onvif://www.onvif.org/"
            );
        }
    }

    #[test]
    fn test_scopes_joined_format() {
        let server = DiscoveryServer::with_identity("10.0.0.1", 8080, "Gate Cam", "IMX219");
        let joined = server.scopes.join(" ");
        // Must be space-separated
        assert!(joined.contains(' '));
        // Each scope must be a valid URI
        for scope in joined.split(' ') {
            assert!(
                scope.starts_with("onvif://"),
                "scope '{scope}' is not a URI"
            );
        }
    }

    // ------------------------------------------------------------------
    // probe matches round-trip through handle_probe
    // ------------------------------------------------------------------

    #[test]
    fn test_handle_probe_round_trip() {
        let server = DiscoveryServer::new("10.0.0.1", 8080);

        let probe = r#"<?xml version="1.0"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Header>
            <a:Action xmlns:a="http://www.w3.org/2005/08/addressing">http://schemas.xmlsoap.org/ws/2004/09/discovery/Probe</a:Action>
            <a:MessageID xmlns:a="http://www.w3.org/2005/08/addressing">uuid:round-trip</a:MessageID>
          </s:Header>
          <s:Body>
            <d:Probe xmlns:d="http://schemas.xmlsoap.org/ws/2004/09/discovery"/>
          </s:Body>
        </s:Envelope>"#;

        let resp = server.handle_probe(probe.as_bytes(), "10.0.0.2");
        let xml = resp.expect("should respond to Probe");
        let xml_str = String::from_utf8(xml).expect("valid UTF-8");

        // Response must contain the original message ID as RelatesTo
        assert!(xml_str.contains("<a:RelatesTo>uuid:round-trip</a:RelatesTo>"));
        // XAddr must use the HTTP server IP
        assert!(xml_str.contains("10.0.0.2:8080/onvif/device_service"));
    }

    #[test]
    fn test_handle_probe_non_probe_returns_none() {
        let server = DiscoveryServer::new("10.0.0.1", 8080);
        let non_probe = b"GET / HTTP/1.1\r\n\r\n";
        assert!(server.handle_probe(non_probe, "").is_none());
    }

    // ------------------------------------------------------------------
    // HTTP handler
    // ------------------------------------------------------------------

    #[test]
    fn test_handle_http_probe_returns_probe_matches() {
        let server = DiscoveryServer::new("10.0.0.1", 8080);
        let body = r#"<?xml version="1.0"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Header>
            <a:Action xmlns:a="http://www.w3.org/2005/08/addressing">http://schemas.xmlsoap.org/ws/2004/09/discovery/Probe</a:Action>
            <a:MessageID xmlns:a="http://www.w3.org/2005/08/addressing">uuid:http-test</a:MessageID>
          </s:Header>
          <s:Body>
            <d:Probe xmlns:d="http://schemas.xmlsoap.org/ws/2004/09/discovery"/>
          </s:Body>
        </s:Envelope>"#;

        let (status, resp_body) = handle_http_probe(&server, body, "10.0.0.99");
        assert_eq!(status, 200);
        assert!(resp_body.contains("<d:ProbeMatches"));
        assert!(resp_body.contains("10.0.0.99:8080/onvif/device_service"));
    }

    #[test]
    fn test_handle_http_probe_non_probe_returns_200_empty() {
        let server = DiscoveryServer::new("10.0.0.1", 8080);
        let (status, body) = handle_http_probe(&server, "not a probe", "");
        assert_eq!(status, 200);
        assert!(body.is_empty());
    }

    // ------------------------------------------------------------------
    // UUID generation
    // ------------------------------------------------------------------

    #[test]
    fn test_uuid_format() {
        let uuid = generate_uuid();
        assert!(uuid.starts_with("uuid:"));
        // Remove prefix and verify hex format
        let hex_part = &uuid[5..];
        // uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        assert_eq!(
            hex_part.len(),
            36,
            "UUID hex part should be 36 chars: {uuid}"
        );
        assert_eq!(hex_part.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn test_uuid_uniqueness() {
        let a = generate_uuid();
        let b = generate_uuid();
        assert_ne!(a, b, "consecutive UUIDs must differ");
    }

    // ------------------------------------------------------------------
    // detect_local_ip
    // ------------------------------------------------------------------

    #[test]
    fn test_detect_local_ip_returns_non_empty() {
        let ip = detect_local_ip();
        assert!(!ip.is_empty(), "should return some IP address");
        // The test environment might not have network, so 127.0.0.1 is also valid.
        if ip != "127.0.0.1" {
            assert!(
                ip.parse::<std::net::Ipv4Addr>().is_ok(),
                "should be valid IPv4: {ip}"
            );
        }
    }

    // ------------------------------------------------------------------
    // DiscoveryServer defaults
    // ------------------------------------------------------------------

    #[test]
    fn test_discovery_server_new_sets_device_ip() {
        let server = DiscoveryServer::new("10.0.0.1", 8080);
        assert_eq!(server.device_ip, "10.0.0.1");
        assert_eq!(server.onvif_port, 8080);
    }

    #[test]
    fn test_discovery_server_empty_ip_auto_detects() {
        let server = DiscoveryServer::new("", 8080);
        assert!(!server.device_ip.is_empty(), "IP should be auto-detected");
    }

    // ------------------------------------------------------------------
    // DiscoveryError display and source
    // ------------------------------------------------------------------

    #[test]
    fn test_discovery_error_display() {
        let e = DiscoveryError::InvalidXml("bad msg".into());
        assert!(e.to_string().contains("bad msg"));

        let e = DiscoveryError::Server("oops".into());
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn test_discovery_error_from_io() {
        let io_err = std::io::Error::other("test");
        let disc_err: DiscoveryError = io_err.into();
        assert!(matches!(disc_err, DiscoveryError::Io(_)));
    }

    // ------------------------------------------------------------------
    // is_probe_action
    // ------------------------------------------------------------------

    #[test]
    fn test_is_probe_action_full_uri() {
        assert!(is_probe_action(PROBE_ACTION));
    }

    #[test]
    fn test_is_probe_action_suffix() {
        assert!(is_probe_action("/discovery/Probe"));
    }

    #[test]
    fn test_is_probe_action_rejects_other() {
        assert!(!is_probe_action(
            "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"
        ));
        assert!(!is_probe_action(""));
    }
}
