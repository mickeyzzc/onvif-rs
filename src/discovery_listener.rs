//! Passive WS-Discovery listener (the twin of the Go library's
//! `discovery.Listener` with its #128 filtering batch): a resident UDP
//! :3702 socket that receives the Hello messages cameras broadcast the
//! moment they power on — the "plug in and it appears instantly"
//! experience — plus the ProbeMatches other devices send in answer to
//! someone else's probe (a free second discovery source). Bye messages
//! and anything unparseable are ignored.
//!
//! Announcements carrying no ONVIF signal are dropped **by default**
//! before the handler sees them (the zombie-device lesson: Windows/WSD
//! hosts on a LAN announce generic Hellos that surface as
//! forever-pending ghost devices in downstream inventories); see
//! [`ListenerConfig::without_onvif_filter`] and the Types/Scopes
//! constraints for narrowing further.
//!
//! Coexistence: the socket binds the multicast group with `SO_REUSEADDR`
//! (the same posture as [`crate::discovery::DiscoveryHandle`]), so a
//! passive listener and this crate's own responder coexist in one
//! process without stealing each other's traffic.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::client::{local_name, text_content};

/// WS-Discovery multicast endpoint.
const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const WS_DISCOVERY_PORT: u16 = 3702;

/// Receive buffer: absorbs power-on bursts when a camera rack boots at
/// once; Hello messages are small but arrive in volleys.
const BUFFER_SIZE: usize = 256 * 1024;

/// One announcement record: the shared shape of a Hello element and a
/// ProbeMatch element (the twin of the Go `wsdiscovery::Match`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryMatch {
    /// `EndpointReference/Address` (usually `urn:uuid:…`).
    pub endpoint_ref: String,
    /// Whitespace-separated `Types` split into qnames.
    pub types: Vec<String>,
    /// Whitespace-separated `Scopes` split into entries.
    pub scopes: Vec<String>,
    /// Whitespace-separated `XAddrs` split into endpoints.
    pub xaddrs: Vec<String>,
    /// The `MetadataVersion` counter.
    pub metadata_version: u32,
}

impl DiscoveryMatch {
    /// Whether this announcement carries an ONVIF signal: a
    /// `NetworkVideoTransmitter` type (compared by local part, so
    /// `dp0:`/`tns:` prefixes do not matter) or any scope under
    /// `onvif://www.onvif.org/` — the lenient OR the Go twin's
    /// `IsONVIFResponder` applies (marginal implementations are not
    /// culled).
    #[must_use]
    pub fn is_onvif(&self) -> bool {
        if self
            .types
            .iter()
            .any(|t| local_qname(t) == "NetworkVideoTransmitter")
        {
            return true;
        }
        self.scopes
            .iter()
            .any(|s| s.starts_with("onvif://www.onvif.org/"))
    }
}

/// Local part of a qname (`dp0:NetworkVideoTransmitter` →
/// `NetworkVideoTransmitter`).
fn local_qname(qname: &str) -> &str {
    match qname.rsplit_once(':') {
        Some((_, local)) => local,
        None => qname,
    }
}

/// Acceptance gates for the listener.
#[derive(Debug, Clone, Default)]
pub struct ListenerConfig {
    /// Drop announcements with no ONVIF signal (default ON).
    onvif_filter: Option<bool>,
    /// When non-empty: the announcement must advertise at least one of
    /// these types (exact local-name match, any-of).
    require_types: Vec<String>,
    /// When set: at least one scope must carry this prefix.
    scope_prefix: Option<String>,
    /// Multicast interface address; `None` = kernel default.
    interface: Option<Ipv4Addr>,
}

impl ListenerConfig {
    /// The default configuration: ONVIF gate on, no extra constraints.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable the built-in ONVIF signal gate — only for handlers that
    /// filter their own announcements.
    #[must_use]
    pub fn without_onvif_filter(mut self) -> Self {
        self.onvif_filter = Some(false);
        self
    }

    /// Require at least one of `types` (exact local-name match, any-of;
    /// namespace prefix dialects do not matter).
    #[must_use]
    pub fn with_types(mut self, types: &[&str]) -> Self {
        self.require_types = types.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// Require at least one scope carrying `prefix` (e.g.
    /// `onvif://www.onvif.org/location/Building1` to hear only one
    /// site's cameras).
    #[must_use]
    pub fn with_scope_prefix(mut self, prefix: &str) -> Self {
        self.scope_prefix = Some(prefix.to_string());
        self
    }

    /// Pin the multicast interface (multi-NIC hosts).
    #[must_use]
    pub fn with_interface(mut self, interface: Ipv4Addr) -> Self {
        self.interface = Some(interface);
        self
    }

    /// Whether `m` passes every configured gate.
    #[must_use]
    pub fn accepts(&self, m: &DiscoveryMatch) -> bool {
        if self.onvif_filter != Some(false) && !m.is_onvif() {
            return false;
        }
        if !self.require_types.is_empty()
            && !self.require_types.iter().any(|want| {
                m.types
                    .iter()
                    .any(|have| local_qname(have) == want.as_str())
            })
        {
            return false;
        }
        if let Some(prefix) = &self.scope_prefix {
            if !m.scopes.iter().any(|s| s.starts_with(prefix.as_str())) {
                return false;
            }
        }
        true
    }
}

/// A passive discovery listener over the standard multicast group.
pub struct DiscoveryListener {
    config: ListenerConfig,
}

impl DiscoveryListener {
    /// Build a listener with `config`.
    #[must_use]
    pub fn new(config: ListenerConfig) -> Self {
        Self { config }
    }

    /// Bind the standard group and listen until `stop` fires, invoking
    /// `handler` for every accepted announcement. The handler runs on the
    /// listener task: return quickly and run slow work on your own task —
    /// a panicking handler is contained and does not stop the listener.
    ///
    /// Returns when `stop` resolves or the socket fails terminally.
    pub async fn run<F>(&self, stop: stop_token::StopToken, handler: F) -> std::io::Result<()>
    where
        F: Fn(DiscoveryMatch) + Send + Sync + 'static,
    {
        let socket = bind_multicast(self.config.interface)?;
        self.serve(&socket, stop, handler).await
    }

    /// The parsing/dispatch loop over an already-bound socket — the
    /// deterministic test seam (a plain loopback UDP socket drives it).
    pub async fn serve<F>(
        &self,
        socket: &UdpSocket,
        stop: stop_token::StopToken,
        handler: F,
    ) -> std::io::Result<()>
    where
        F: Fn(DiscoveryMatch) + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        let mut buf = vec![0u8; BUFFER_SIZE];

        loop {
            let read = tokio::select! {
                _ = stop.stopped() => return Ok(()),
                r = socket.recv_from(&mut buf) => r?,
            };

            let (n, _from) = read;
            if let Some(m) = parse_announcement(&buf[..n]) {
                if self.config.accepts(&m) {
                    // A panicking handler must not stop the listener.
                    let handler = Arc::clone(&handler);
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || handler(m)));
                    if result.is_err() {
                        log::warn!("discovery listener: handler panicked; continuing");
                    }
                }
            }
        }
    }
}

/// Bind UDP :3702 on the multicast group with `SO_REUSEADDR` (listeners
/// and responders coexist; Linux and macOS deliver a copy of each
/// multicast datagram to every bound socket).
fn bind_multicast(interface: Option<Ipv4Addr>) -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, WS_DISCOVERY_PORT).into())?;
    let iface = interface.unwrap_or(Ipv4Addr::UNSPECIFIED);
    sock.join_multicast_v4(&MULTICAST_GROUP, &iface)?;
    UdpSocket::from_std(sock.into())
}

/// Parse a WS-Discovery datagram into the announcement it carries: a
/// Hello (device announcing itself on power-on) or the FIRST ProbeMatch
/// of a ProbeMatches (a device answering someone else's probe). Bye
/// messages, unmatched shapes and unparseable bytes return `None` — the
/// listener must survive garbage on the wire.
#[must_use]
pub fn parse_announcement(data: &[u8]) -> Option<DiscoveryMatch> {
    let text = std::str::from_utf8(data).ok()?;
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    // The single match being decoded, plus which shape filled it.
    let mut m = DiscoveryMatch::default();
    let mut have_match = false;
    let mut in_hello = false;
    let mut in_first_probe_match = false;

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                match name.as_str() {
                    "Hello" => in_hello = true,
                    "ProbeMatch" if !have_match => in_first_probe_match = true,
                    _ => {}
                }
                stack.push(name);
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                let capturing = in_hello || in_first_probe_match;
                if capturing {
                    match stack.last().map(String::as_str) {
                        Some("Address") if stack.iter().any(|s| s == "EndpointReference") => {
                            m.endpoint_ref = text.trim().to_string();
                            have_match = true;
                        }
                        Some("Types") => {
                            m.types = text.split_whitespace().map(String::from).collect();
                            have_match = true;
                        }
                        Some("Scopes") => {
                            m.scopes = text.split_whitespace().map(String::from).collect();
                            have_match = true;
                        }
                        Some("XAddrs") => {
                            m.xaddrs = text.split_whitespace().map(String::from).collect();
                            have_match = true;
                        }
                        Some("MetadataVersion") => {
                            m.metadata_version = text.trim().parse().unwrap_or(0);
                            have_match = true;
                        }
                        _ => {}
                    }
                }
            }
            Ok(XmlEvent::End(_)) => match stack.pop().unwrap_or_default().as_str() {
                "Hello" => in_hello = false,
                "ProbeMatch" => in_first_probe_match = false,
                _ => {}
            },
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(_) => return None,
        }
        buf.clear();
    }

    have_match.then_some(m)
}

/// Minimal stop token for listener shutdown: resolves when cancelled.
///
/// The crate deliberately avoids a `tokio_util` dependency; this is the
/// one-shot cancellation shape the listener needs.
pub mod stop_token {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// A cancellation token: `stop()` fires [`StopToken::stopped`].
    #[derive(Clone, Default)]
    pub struct StopSource {
        inner: Arc<Inner>,
    }

    #[derive(Default)]
    struct Inner {
        fired: AtomicBool,
        notify: tokio::sync::Notify,
    }

    impl StopSource {
        /// A new, un-fired source.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// The watchable side.
        #[must_use]
        pub fn token(&self) -> StopToken {
            StopToken {
                inner: Arc::clone(&self.inner),
            }
        }

        /// Fire the token (idempotent).
        pub fn stop(&self) {
            self.inner.fired.store(true, Ordering::SeqCst);
            self.inner.notify.notify_waiters();
        }
    }

    /// The watchable side of a [`StopSource`].
    #[derive(Clone)]
    pub struct StopToken {
        inner: Arc<Inner>,
    }

    impl StopToken {
        /// Resolves once the source fires.
        pub async fn stopped(&self) {
            loop {
                if self.inner.fired.load(Ordering::SeqCst) {
                    return;
                }
                self.inner.notify.notified().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Body>
<Hello xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
<EndpointReference><Address>urn:uuid:hello-1111</Address></EndpointReference>
<Types>dp0:NetworkVideoTransmitter</Types>
<Scopes>onvif://www.onvif.org/name/HelloCam</Scopes>
<XAddrs>http://192.168.1.77:80/onvif/device_service</XAddrs>
<MetadataVersion>3</MetadataVersion>
</Hello>
</s:Body>
</s:Envelope>"#;

    const WSD_ZOMBIE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Body>
<Hello xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
<EndpointReference><Address>urn:uuid:wsd-host-4444</Address></EndpointReference>
<Types>wsdiscovery:Device</Types>
<Scopes>http://192.168.1.50:5000/wsd/</Scopes>
<XAddrs>http://192.168.1.50:5000/wsd/</XAddrs>
<MetadataVersion>1</MetadataVersion>
</Hello>
</s:Body>
</s:Envelope>"#;

    const PROBE_MATCHES: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Body>
<ProbeMatches xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
<ProbeMatch>
<EndpointReference><Address>urn:uuid:match-2222</Address></EndpointReference>
<Types>dp0:NetworkVideoTransmitter</Types>
<XAddrs>http://192.168.1.88:8000/onvif/device_service</XAddrs>
</ProbeMatch>
</ProbeMatches>
</s:Body>
</s:Envelope>"#;

    const BYE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Body>
<Bye xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
<EndpointReference><Address>urn:uuid:bye-3333</Address></EndpointReference>
</Bye>
</s:Body>
</s:Envelope>"#;

    fn parse(s: &str) -> Option<DiscoveryMatch> {
        parse_announcement(s.as_bytes())
    }

    #[test]
    fn parses_hello() {
        let m = parse(HELLO).unwrap();
        assert_eq!(m.endpoint_ref, "urn:uuid:hello-1111");
        assert_eq!(m.types, vec!["dp0:NetworkVideoTransmitter"]);
        assert_eq!(m.scopes, vec!["onvif://www.onvif.org/name/HelloCam"]);
        assert_eq!(
            m.xaddrs,
            vec!["http://192.168.1.77:80/onvif/device_service"]
        );
        assert_eq!(m.metadata_version, 3);
    }

    #[test]
    fn parses_first_probe_match() {
        let m = parse(PROBE_MATCHES).unwrap();
        assert_eq!(m.endpoint_ref, "urn:uuid:match-2222");
    }

    #[test]
    fn ignores_bye_and_garbage() {
        assert!(parse(BYE).is_none());
        assert!(parse_announcement(b"<not xml").is_none());
        assert!(parse_announcement(b"").is_none());
    }

    #[test]
    fn onvif_signal_detection() {
        assert!(parse(HELLO).unwrap().is_onvif());
        assert!(!parse(WSD_ZOMBIE).unwrap().is_onvif());
        // Scope-only signal (no NVT type).
        let scope_only = parse(
            &HELLO
                .replace("dp0:NetworkVideoTransmitter", "tdn:NetworkVideoDisplay")
                .replace(
                    "onvif://www.onvif.org/name/HelloCam",
                    "onvif://www.onvif.org/name/X onvif://www.onvif.org/location/Building1",
                ),
        )
        .unwrap();
        assert!(scope_only.is_onvif());
    }

    #[test]
    fn acceptance_gates_table() {
        let nvt = parse(HELLO).unwrap();
        let zombie = parse(WSD_ZOMBIE).unwrap();

        let default_cfg = ListenerConfig::new();
        assert!(default_cfg.accepts(&nvt));
        assert!(!default_cfg.accepts(&zombie));

        let open = ListenerConfig::new().without_onvif_filter();
        assert!(open.accepts(&zombie));

        let types = ListenerConfig::new().with_types(&["NetworkVideoTransmitter"]);
        assert!(types.accepts(&nvt));
        let wrong_type = ListenerConfig::new().with_types(&["NetworkVideoRecorder"]);
        assert!(!wrong_type.accepts(&nvt));

        let scope = ListenerConfig::new().with_scope_prefix("onvif://www.onvif.org/name/");
        assert!(scope.accepts(&nvt));
        let wrong_scope =
            ListenerConfig::new().with_scope_prefix("onvif://www.onvif.org/hardware/");
        assert!(!wrong_scope.accepts(&nvt));

        // The ONVIF gate fires before the configured constraints.
        let zombie_types = ListenerConfig::new().with_types(&["Device"]);
        assert!(!zombie_types.accepts(&zombie));
    }
}
