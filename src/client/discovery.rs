//! Active discovery client family — the port of the onvif-go `discovery`
//! package's probing half (the passive listener lives in
//! [`crate::discovery_listener`]): multicast Probe sweep, directed
//! HTTP probing for known addresses (cross-subnet), the serial-anchored
//! identity probe, scope parsing, the ONVIF-responder filter, and
//! bounded-concurrency identity enrichment.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use super::device::{tail_is, walk_local, Step};
use super::{ClientError, SoapClient};

use crate::discovery_listener::DiscoveryMatch;

/// WS-Discovery multicast endpoint.
const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const WS_DISCOVERY_PORT: u16 = 3702;

/// The short single-shot budget a rediscovery engine needs (NVRs use
/// ~1.2 s per attempt) — the Go twin's default.
const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(1200);

/// The ports ProbeSerial scans when none are given.
#[must_use]
pub fn default_probe_ports() -> Vec<u16> {
    vec![80, 8000, 8080, 8081, 8899]
}

/// Build a WS-Discovery Probe envelope (byte-mirrors the Go twin's
/// `wsdiscovery.BuildProbe`, which the crate's own responder also parses).
#[must_use]
pub fn build_probe(message_id: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
<Header>
<Action xmlns="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</Action>
<MessageID xmlns="http://schemas.xmlsoap.org/ws/2004/08/addressing">urn:uuid:{}</MessageID>
<To xmlns="http://schemas.xmlsoap.org/ws/2004/08/addressing">urn:schemas-xmlsoap-org:ws:2005:04:discovery</To>
</Header>
<Body>
<Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
<Types>dn:NetworkVideoTransmitter</Types>
</Probe>
</Body>
</Envelope>"#,
        crate::types::xml_escape(message_id)
    )
    .into_bytes()
}

/// Parse a ProbeMatches (or Hello) datagram into its FIRST match —
/// sharing the listener's announcement decode.
#[must_use]
pub fn parse_probe_match(data: &[u8]) -> Option<DiscoveryMatch> {
    crate::discovery_listener::parse_announcement(data)
}

/// Multicast Probe sweep: broadcast a WS-Discovery Probe and collect the
/// distinct answers until `timeout` elapses. `interface` picks the
/// multicast interface (`None` = kernel default).
pub async fn discover(
    timeout: Duration,
    interface: Option<Ipv4Addr>,
) -> Result<Vec<DiscoveryMatch>, ClientError> {
    let socket = bind_multicast(interface)?;
    let addr = SocketAddrV4::new(MULTICAST_GROUP, WS_DISCOVERY_PORT);
    let probe: Vec<u8> = build_probe(&random_message_id());
    let target: std::net::SocketAddr = addr.into();
    socket
        .send_to(&probe, target)
        .await
        .map_err(|e| ClientError::Transport(format!("send probe: {e}")))?;

    collect_answers(&socket, timeout).await
}

/// The collection loop over an already-bound socket — the deterministic
/// test seam (a plain loopback socket can drive it).
pub async fn collect_answers(
    socket: &UdpSocket,
    timeout: Duration,
) -> Result<Vec<DiscoveryMatch>, ClientError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut seen: Vec<String> = Vec::new();
    let mut out: Vec<DiscoveryMatch> = Vec::new();
    let mut buf = vec![0u8; 8192];

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(out);
        }

        let read = tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await;
        let Ok(read) = read else {
            return Ok(out); // deadline
        };
        let (n, _) = read.map_err(|e| ClientError::Transport(format!("read probe answer: {e}")))?;

        if let Some(m) = parse_probe_match(&buf[..n]) {
            if !m.endpoint_ref.is_empty() && !seen.contains(&m.endpoint_ref) {
                seen.push(m.endpoint_ref.clone());
                out.push(m);
            }
        }
    }
}

/// Directed probe of a known host:port — WS-Discovery Probe over HTTP
/// first, unauthenticated GetDeviceInformation second (the Go twin's
/// two strategies; cross-subnet reach where multicast cannot go).
#[must_use]
pub async fn probe_endpoint(host: &str, port: u16, timeout: Duration) -> Option<DiscoveryMatch> {
    if host.is_empty() || port == 0 {
        return None;
    }

    let url = format!("http://{host}:{port}/onvif/device_service");

    // Strategy 1: WS-Discovery Probe over HTTP.
    let probe_body = String::from_utf8_lossy(&build_probe(&random_message_id())).to_string();
    let probe_client = SoapClient::new(&url).ok()?.with_timeout(timeout);
    if let Ok(resp) = probe_client.soap_call(&url, &probe_body).await {
        if let Some(m) = parse_probe_match(resp.as_bytes()) {
            let mut m = m;
            if m.xaddrs.is_empty() {
                m.xaddrs.push(url.clone());
            }
            return Some(m);
        }
    }

    // Strategy 2: unauthenticated GetDeviceInformation.
    if let Ok(resp) = probe_client
        .soap_call(
            &url,
            "<tds:GetDeviceInformation xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"></tds:GetDeviceInformation>",
        )
        .await
    {
        if let Some(serial) = extract_serial_number(&resp) {
            return Some(DiscoveryMatch {
                xaddrs: vec![url],
                endpoint_ref: serial,
                ..DiscoveryMatch::default()
            });
        }
    }

    None
}

/// Scan `ports` (the defaults when empty) for an ONVIF device and return
/// its serial number — the identity anchor for correlating the same
/// physical camera across protocols.
#[must_use]
pub async fn probe_serial(host: &str, ports: &[u16]) -> Option<String> {
    let ports: Vec<u16> = if ports.is_empty() {
        default_probe_ports()
    } else {
        ports.to_vec()
    };
    if host.is_empty() {
        return None;
    }

    for port in ports {
        let url = format!("http://{host}:{port}/onvif/device_service");
        let Ok(probe_client) = SoapClient::new(&url) else {
            continue;
        };
        let probe_client = probe_client.with_timeout(DEFAULT_PROBE_TIMEOUT);
        if let Ok(resp) = probe_client
            .soap_call(
                &url,
                "<tds:GetDeviceInformation xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"></tds:GetDeviceInformation>",
            )
            .await
        {
            if let Some(serial) = extract_serial_number(&resp) {
                return Some(serial);
            }
        }
    }

    None
}

/// The serial number out of a GetDeviceInformation response (namespace-
/// free local-name walk — no assumptions about the response shape).
#[must_use]
pub fn extract_serial_number(resp: &str) -> Option<String> {
    let mut serial = String::new();
    walk_local(resp, "GetDeviceInformationResponse", |step| {
        if let Step::Text { path, text } = step {
            if tail_is(path, &["GetDeviceInformationResponse", "SerialNumber"]) {
                serial = text.to_string();
            }
        }
        Ok(())
    })
    .ok()?;
    (!serial.is_empty()).then_some(serial)
}

/// The structured form of the well-known ONVIF scope entries
/// (`onvif://www.onvif.org/name/XXX`, …`/hardware/YYY`, …`/location/ZZZ`);
/// percent-decoded where possible, later entries win.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeInfo {
    pub name: String,
    pub hardware: String,
    pub location: String,
}

/// Extract the well-known scope entries (the Go twin's `ParseScopes`).
#[must_use]
pub fn parse_scopes(scopes: &[String]) -> ScopeInfo {
    const PREFIX: &str = "onvif://www.onvif.org/";
    let mut info = ScopeInfo::default();

    for scope in scopes {
        let Some(rest) = scope.strip_prefix(PREFIX) else {
            continue;
        };
        let Some((key, value)) = rest.split_once('/') else {
            continue;
        };
        let decoded = percent_decode(value);
        match key {
            "name" => info.name = decoded,
            "hardware" => info.hardware = decoded,
            "location" => info.location = decoded,
            _ => {}
        }
    }

    info
}

/// Percent-decode a scope value (lenient: malformed escapes pass through).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() + 1 && i + 2 < bytes.len() + 1 {
            let hex = |b: u8| (b as char).is_ascii_hexdigit();
            if i + 2 < bytes.len() && hex(bytes[i + 1]) && hex(bytes[i + 2]) {
                let hi = (bytes[i + 1] as char).to_digit(16).unwrap_or(0) as u8;
                let lo = (bytes[i + 2] as char).to_digit(16).unwrap_or(0) as u8;
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The matches that are actual ONVIF responders (the Go twin's
/// `FilterONVIFDevices` — same lenient OR as [`DiscoveryMatch::is_onvif`]).
#[must_use]
pub fn filter_onvif(matches: Vec<DiscoveryMatch>) -> Vec<DiscoveryMatch> {
    matches.into_iter().filter(|m| m.is_onvif()).collect()
}

/// Identity enrichment fan-out: unauthenticated GetDeviceInformation per
/// device with bounded concurrency, anchoring each device by its serial
/// number. Best-effort by design — devices without XAddrs or unreachable
/// devices are skipped, never fatal.
pub async fn enrich_devices(
    client: &SoapClient,
    devices: &mut [DiscoveryMatch],
    concurrency: usize,
) {
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles: Vec<(usize, tokio::task::JoinHandle<Option<String>>)> = Vec::new();

    for (idx, device) in devices.iter().enumerate() {
        let Some(endpoint) = device.xaddrs.first().cloned() else {
            continue;
        };
        if super::parse_http_endpoint(&endpoint).is_err() {
            continue;
        }
        let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
            continue;
        };
        let probe_client = client.clone().with_timeout(DEFAULT_PROBE_TIMEOUT);
        handles.push((idx, tokio::spawn(async move {
            let _permit = permit;
            probe_client
                .soap_call(
                    &endpoint,
                    "<tds:GetDeviceInformation xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"></tds:GetDeviceInformation>",
                )
                .await
                .ok()
                .and_then(|resp| extract_serial_number(&resp))
        })));
    }

    for (idx, handle) in handles {
        if let Ok(Some(serial)) = handle.await {
            if let Some(device) = devices.get_mut(idx) {
                device.endpoint_ref = serial;
            }
        }
    }
}

fn random_message_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn bind_multicast(interface: Option<Ipv4Addr>) -> Result<UdpSocket, ClientError> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| ClientError::Transport(format!("probe socket: {e}")))?;
    sock.set_reuse_address(true)
        .map_err(|e| ClientError::Transport(format!("probe reuse: {e}")))?;
    sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())
        .map_err(|e| ClientError::Transport(format!("probe bind: {e}")))?;
    let iface = interface.unwrap_or(Ipv4Addr::UNSPECIFIED);
    sock.join_multicast_v4(&MULTICAST_GROUP, &iface)
        .map_err(|e| ClientError::Transport(format!("probe join: {e}")))?;
    UdpSocket::from_std(sock.into())
        .map_err(|e| ClientError::Transport(format!("probe async: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_envelope_golden() {
        let probe = String::from_utf8_lossy(&build_probe("abc-123")).to_string();
        assert!(probe.contains("urn:uuid:abc-123"));
        assert!(probe.contains("http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"));
        assert!(probe.contains("<Types>dn:NetworkVideoTransmitter</Types>"));
    }

    #[test]
    fn parse_scopes_table() {
        let scopes = vec![
            "onvif://www.onvif.org/name/Hello%20Cam".to_string(),
            "onvif://www.onvif.org/hardware/HW-1".to_string(),
            "onvif://www.onvif.org/location/Building1/Floor2".to_string(),
            "http://unrelated.example/".to_string(),
        ];
        let info = parse_scopes(&scopes);
        assert_eq!(info.name, "Hello Cam");
        assert_eq!(info.hardware, "HW-1");
        assert_eq!(info.location, "Building1/Floor2");

        // Later entries win.
        let later = vec![
            "onvif://www.onvif.org/name/first".to_string(),
            "onvif://www.onvif.org/name/second".to_string(),
        ];
        assert_eq!(parse_scopes(&later).name, "second");
    }

    #[test]
    fn percent_decode_lenient() {
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("bad%2"), "bad%2");
    }

    #[test]
    fn filters_onvif_responders() {
        let onvif = DiscoveryMatch {
            types: vec!["dp0:NetworkVideoTransmitter".into()],
            ..Default::default()
        };
        let zombie = DiscoveryMatch {
            types: vec!["wsdiscovery:Device".into()],
            ..Default::default()
        };
        let filtered = filter_onvif(vec![zombie.clone(), onvif.clone()]);
        assert_eq!(filtered, vec![onvif]);
    }

    #[test]
    fn extracts_serial() {
        let resp = r#"<GetDeviceInformationResponse>
            <Manufacturer>Acme</Manufacturer><SerialNumber>SN-42</SerialNumber>
            </GetDeviceInformationResponse>"#;
        assert_eq!(extract_serial_number(resp).as_deref(), Some("SN-42"));
        assert!(extract_serial_number("<other/>").is_none());
    }

    #[tokio::test]
    async fn collects_answers_over_loopback() {
        // Deterministic seam: drive the collection loop with a plain
        // loopback socket and canned ProbeMatches datagrams.
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for uuid in ["urn:uuid:cam-1", "urn:uuid:cam-2", "urn:uuid:cam-1"] {
            let body = format!(
                r#"<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body>
                <ProbeMatches xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
                <ProbeMatch><EndpointReference><Address>{uuid}</Address></EndpointReference>
                <Types>dp0:NetworkVideoTransmitter</Types>
                <XAddrs>http://192.0.2.10/onvif/device_service</XAddrs></ProbeMatch>
                </ProbeMatches></Body></Envelope>"#
            );
            responder.send_to(body.as_bytes(), addr).await.unwrap();
        }

        let found = collect_answers(&listener, Duration::from_millis(300))
            .await
            .unwrap();
        assert_eq!(found.len(), 2, "deduplicated by endpoint_ref: {found:?}");
        assert!(found.iter().any(|m| m.endpoint_ref == "urn:uuid:cam-1"));
    }
}
