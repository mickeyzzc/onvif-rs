//! Device-service (tds) client family — the Rust twin of the Go library's
//! `device` package: identity, capabilities, scopes, hostname/DNS/NTP and
//! network configuration, system maintenance (logs/backup/firmware), the
//! geo-location and device-provisioning addresses, storage configurations,
//! zero-conf/dynamic-DNS, and the 802.11/802.1X wireless family.
//!
//! Request envelopes are byte-compatible with what the Go package marshals
//! (element prefixes and `xmlns:` placement exactly as the Go struct tags
//! build them — including the Go quirks such as unprefixed children where
//! the Go types carry no tags); response decoding is local-name tolerant
//! through the shared [`walk_local`] walk, which this module also exports
//! for the security family.
//!
//! The time family (Get/SetSystemDateAndTime, SetNTP) lives in
//! [`super::time`]; only the read side [`SoapClient::get_ntp`] is here.

use super::{local_name, text_content, ClientError, SoapClient};

/// tds (device service) namespace.
const TDS_NS: &str = "http://www.onvif.org/ver10/device/wsdl";
/// tt (schema) namespace.
const TT_NS: &str = "http://www.onvif.org/ver10/schema";

// ---------------------------------------------------------------------------
// Shared local-name walk engine (also used by the security family)
// ---------------------------------------------------------------------------

/// One step of a local-name XML walk. `path` is the stack of local element
/// names from the document root through the current element.
pub(crate) enum Step<'a> {
    /// An element opened; `attrs` are its attributes keyed by local name
    /// (namespace prefixes stripped), entity-unescaped.
    Start {
        path: &'a [String],
        attrs: &'a [(String, String)],
    },
    /// Text content under the element at `path`.
    Text { path: &'a [String], text: &'a str },
    /// The element at `path` closed (the path still includes it).
    End { path: &'a [String] },
}

/// Walk `resp` by local names, reporting start/text/end steps. Self-closing
/// elements surface as an immediate Start + End pair, so attribute-only
/// shapes (`<Capabilities IPFilter="true"/>`) are visible to the visitor.
/// `visit` may abort the walk with an error (propagated as-is); reader
/// failures map to [`ClientError::Parse`] labeled with `op`.
pub(crate) fn walk_local<F>(resp: &str, op: &str, mut visit: F) -> Result<(), ClientError>
where
    F: FnMut(Step<'_>) -> Result<(), ClientError>,
{
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let attrs = collect_attrs(&e);
                stack.push(local_name(&e));
                visit(Step::Start {
                    path: &stack,
                    attrs: &attrs,
                })?;
            }
            Ok(XmlEvent::Empty(e)) => {
                let attrs = collect_attrs(&e);
                stack.push(local_name(&e));
                let started = visit(Step::Start {
                    path: &stack,
                    attrs: &attrs,
                });
                let ended = started.and_then(|()| visit(Step::End { path: &stack }));
                stack.pop();
                ended?;
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                if !text.is_empty() {
                    visit(Step::Text {
                        path: &stack,
                        text: &text,
                    })?;
                }
            }
            Ok(XmlEvent::End(_)) => {
                visit(Step::End { path: &stack })?;
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!("parse {op}: {e}")));
            }
        }
        buf.clear();
    }
    Ok(())
}

/// Collect an element's attributes as (local-name, unescaped value) pairs.
pub(crate) fn collect_attrs(e: &quick_xml::events::BytesStart<'_>) -> Vec<(String, String)> {
    e.attributes()
        .flatten()
        .filter_map(|a| {
            let key = String::from_utf8_lossy(a.key.as_ref()).to_string();
            let key = match key.rsplit_once(':') {
                Some((_, local)) => local.to_string(),
                None => key,
            };
            let value = a
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .ok()?
                .into_owned();
            Some((key, value))
        })
        .collect()
}

/// Whether `path` ends with exactly the `names` sequence.
pub(crate) fn tail_is(path: &[String], names: &[&str]) -> bool {
    if path.len() < names.len() {
        return false;
    }
    path.iter()
        .rev()
        .zip(names.iter().rev())
        .all(|(p, n)| p == n)
}

/// Look up a local-named attribute.
pub(crate) fn attr_get<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Bool decode with `strconv.ParseBool`'s accepted truthy spellings;
/// anything else is false (lenient by design — see the module tests).
pub(crate) fn xml_bool(s: &str) -> bool {
    matches!(s.trim(), "1" | "t" | "T" | "true" | "TRUE" | "True")
}

/// Integer decode; unparseable text decodes as 0 (lenient).
pub(crate) fn xml_int(s: &str) -> i32 {
    s.trim().parse().unwrap_or(0)
}

/// Float decode; unparseable text decodes as 0.0 (lenient).
pub(crate) fn xml_f64(s: &str) -> f64 {
    s.trim().parse().unwrap_or(0.0)
}

/// Base64 decode of a `xs:base64Binary` payload (Go's `[]byte` decode
/// errors on bad input; so does this).
pub(crate) fn b64_bytes(s: &str) -> Result<Vec<u8>, ClientError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| ClientError::Parse(format!("bad base64 payload: {e}")))
}

/// First text value under any element with local name `leaf` ("" if none).
fn text_of(resp: &str, op: &str, leaf: &str) -> Result<String, ClientError> {
    let mut out = String::new();
    walk_local(resp, op, |step| {
        if let Step::Text { path, text } = step {
            if path.last().map(String::as_str) == Some(leaf) && out.is_empty() {
                out = text.to_string();
            }
        }
        Ok(())
    })?;
    Ok(out)
}

/// All text values under elements with local name `leaf`.
fn texts_of(resp: &str, op: &str, leaf: &str) -> Result<Vec<String>, ClientError> {
    let mut out = Vec::new();
    walk_local(resp, op, |step| {
        if let Step::Text { path, text } = step {
            if path.last().map(String::as_str) == Some(leaf) {
                out.push(text.to_string());
            }
        }
        Ok(())
    })?;
    Ok(out)
}

/// RebootNeeded flag shared by SetHostnameFromDHCP / SetNetworkInterfaces.
fn parse_reboot_needed(resp: &str) -> Result<bool, ClientError> {
    Ok(xml_bool(&text_of(resp, "RebootNeeded", "RebootNeeded")?))
}

// ---------------------------------------------------------------------------
// Types (mirroring the Go device package's response types)
// ---------------------------------------------------------------------------

/// Basic device identity (Go `DeviceInformation`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceInformation {
    /// Manufacturer name.
    pub manufacturer: String,
    /// Device model.
    pub model: String,
    /// Firmware version.
    pub firmware_version: String,
    /// Device serial number.
    pub serial_number: String,
    /// Hardware identifier (Go `HardwareId`).
    pub hardware_id: String,
}

/// The service capability tree (Go `Capabilities`); absent sections are
/// `None` — "not reported".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// Analytics service section.
    pub analytics: Option<AnalyticsCapabilities>,
    /// Device service section.
    pub device: Option<DeviceCapabilities>,
    /// Events service section.
    pub events: Option<EventCapabilities>,
    /// Imaging service section.
    pub imaging: Option<ImagingCapabilities>,
    /// Media service section.
    pub media: Option<MediaCapabilities>,
    /// PTZ service section.
    pub ptz: Option<PtzCapabilities>,
}

/// Analytics service capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyticsCapabilities {
    /// Service endpoint address.
    pub x_addr: String,
    /// Rule support flag.
    pub rule_support: bool,
    /// Analytics module support flag.
    pub analytics_module_support: bool,
}

/// Device service capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceCapabilities {
    /// Service endpoint address.
    pub x_addr: String,
    /// Network sub-capabilities.
    pub network: Option<NetworkCapabilities>,
    /// System sub-capabilities.
    pub system: Option<SystemCapabilities>,
    /// I/O sub-capabilities.
    pub io: Option<IoCapabilities>,
    /// Security sub-capabilities.
    pub security: Option<SecurityCapabilities>,
}

/// Event service capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventCapabilities {
    /// Service endpoint address.
    pub x_addr: String,
    /// WS-Subscription policy support flag.
    pub ws_subscription_policy_support: bool,
    /// WS pull-point support flag.
    pub ws_pull_point_support: bool,
    /// WS pausable subscription support flag (the wire element is
    /// `WSPausableSubscriptionManagerInterfaceSupport`).
    pub ws_pausable_subscription_support: bool,
}

/// Imaging service capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImagingCapabilities {
    /// Service endpoint address.
    pub x_addr: String,
}

/// Media service capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaCapabilities {
    /// Service endpoint address.
    pub x_addr: String,
    /// Streaming sub-capabilities.
    pub streaming_capabilities: Option<StreamingCapabilities>,
}

/// PTZ service capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PtzCapabilities {
    /// Service endpoint address.
    pub x_addr: String,
}

/// Network capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkCapabilities {
    /// IP filtering support.
    pub ip_filter: bool,
    /// Zero-configuration support.
    pub zero_configuration: bool,
    /// IPv6 support.
    pub ip_version6: bool,
    /// Dynamic DNS support.
    pub dyn_dns: bool,
}

/// System capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemCapabilities {
    /// Discovery resolve support.
    pub discovery_resolve: bool,
    /// Discovery BYE support.
    pub discovery_bye: bool,
    /// Remote discovery support.
    pub remote_discovery: bool,
    /// System backup support.
    pub system_backup: bool,
    /// System logging support.
    pub system_logging: bool,
    /// Firmware upgrade support.
    pub firmware_upgrade: bool,
    /// Supported ONVIF major versions (Go collects the `Major` entries).
    pub supported_versions: Vec<String>,
}

/// I/O capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IoCapabilities {
    /// Number of input connectors.
    pub input_connectors: i32,
    /// Number of relay outputs.
    pub relay_outputs: i32,
}

/// Security capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityCapabilities {
    /// TLS 1.1 support.
    pub tls11: bool,
    /// TLS 1.2 support.
    pub tls12: bool,
    /// Onboard key generation support.
    pub onboard_key_generation: bool,
    /// Access policy configuration support.
    pub access_policy_config: bool,
    /// X.509 token support (wire element `X.509Token`).
    pub x509_token: bool,
    /// SAML token support.
    pub saml_token: bool,
    /// Kerberos token support.
    pub kerberos_token: bool,
    /// REL token support.
    pub rel_token: bool,
}

/// Streaming capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamingCapabilities {
    /// RTP multicast support.
    pub rtp_multicast: bool,
    /// RTP/TCP support (wire element `RTP_TCP`).
    pub rtp_tcp: bool,
    /// RTP/RTSP/TCP support (wire element `RTP_RTSP_TCP`).
    pub rtp_rtsp_tcp: bool,
}

/// Hostname configuration (Go `HostnameInformation`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostnameInformation {
    /// Whether the hostname comes from DHCP.
    pub from_dhcp: bool,
    /// The configured hostname ("" when DHCP-set and unreported).
    pub name: String,
}

/// One DNS server entry (Go `types.IPAddress` — only the fields the device
/// family puts on the wire: Type / IPv4Address / IPv6Address).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpAddress {
    /// `IPv4`, `IPv6` or `DNS`.
    pub kind: String,
    /// The IPv4 address (when `kind` is `IPv4`).
    pub ipv4_address: String,
    /// The IPv6 address (when `kind` is `IPv6`).
    pub ipv6_address: String,
}

/// DNS configuration (Go `DNSInformation`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsInformation {
    /// Whether DNS servers come from DHCP.
    pub from_dhcp: bool,
    /// Search domains.
    pub search_domain: Vec<String>,
    /// DHCP-provided DNS servers (Go decode fills Type/IPv4Address only).
    pub dns_from_dhcp: Vec<IpAddress>,
    /// Manually configured DNS servers.
    pub dns_manual: Vec<IpAddress>,
}

/// A network host entry (Go `NetworkHost`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkHost {
    /// `IPv4`, `IPv6` or `DNS`.
    pub kind: String,
    /// The IPv4 address.
    pub ipv4_address: String,
    /// The IPv6 address.
    pub ipv6_address: String,
    /// The DNS name (wire element `DNSname`).
    pub dns_name: String,
}

/// NTP configuration (Go `NTPInformation`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NtpInformation {
    /// Whether NTP servers come from DHCP.
    pub from_dhcp: bool,
    /// DHCP-provided NTP servers.
    pub ntp_from_dhcp: Vec<NetworkHost>,
    /// Manually configured NTP servers.
    pub ntp_manual: Vec<NetworkHost>,
}

/// Interface hardware info.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkInterfaceInfo {
    /// Interface name.
    pub name: String,
    /// MAC address.
    pub hw_address: String,
    /// MTU.
    pub mtu: i32,
}

/// An IPv4 address with prefix; `netmask` is derived from the prefix length
/// (Go does the same via `NetmaskFromPrefixLength`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrefixedIpv4Address {
    /// The IPv4 address.
    pub address: String,
    /// Prefix length (0-32).
    pub prefix_length: i32,
    /// Dotted netmask derived from the prefix length ("" if out of range).
    pub netmask: String,
}

/// IPv4 configuration of one interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ipv4Configuration {
    /// Static addresses.
    pub manual: Vec<PrefixedIpv4Address>,
    /// DHCP enabled.
    pub dhcp: bool,
}

/// The IPv4 block of one interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ipv4NetworkInterface {
    /// IPv4 stack enabled.
    pub enabled: bool,
    /// Address configuration.
    pub config: Ipv4Configuration,
}

/// One network interface (Go `NetworkInterface`; the Go decode never
/// populates the IPv6 arm, so neither does this port).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkInterface {
    /// Interface token (attribute).
    pub token: String,
    /// Interface enabled.
    pub enabled: bool,
    /// Hardware info.
    pub info: NetworkInterfaceInfo,
    /// IPv4 block — attached only when the device reports IPv4 enabled
    /// (mirroring the Go decode).
    pub ipv4: Option<Ipv4NetworkInterface>,
}

/// Desired configuration for one interface in
/// [`SoapClient::set_network_interfaces`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkInterfaceConfig {
    /// Toggles the interface itself.
    pub enabled: bool,
    /// Toggles the interface's IPv4 stack.
    pub ipv4_enabled: bool,
    /// Enables DHCP address acquisition. When false, `manual_address` and
    /// `manual_prefix_length` define the static address.
    pub dhcp: bool,
    /// Static IPv4 address (ignored when `dhcp` is true).
    pub manual_address: String,
    /// Static prefix length, e.g. 24 for a /24 (ignored when `dhcp` is
    /// true).
    pub manual_prefix_length: i32,
}

/// One configured scope (Go `Scope`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    /// `Fixed` or `Configurable`.
    pub scope_def: String,
    /// The scope item URI.
    pub scope_item: String,
}

/// ONVIF version pair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OnvifVersion {
    /// Major version.
    pub major: i32,
    /// Minor version.
    pub minor: i32,
}

/// One service entry from GetServices (Go `ServiceEntry`). Go types the
/// capabilities as an opaque `interface{}`; this port keeps an equally
/// opaque re-serialized inner XML of the `Capabilities` element
/// (local-name normalized), when the device included one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceEntry {
    /// Service namespace URI.
    pub namespace: String,
    /// Service endpoint address.
    pub x_addr: String,
    /// Opaque capabilities payload (inner XML of the `Capabilities`
    /// element), when present.
    pub capabilities: Option<String>,
    /// Service version.
    pub version: OnvifVersion,
}

/// Device-service capabilities (the attribute-shaped
/// GetServiceCapabilities response).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceServiceCapabilities {
    /// Network capabilities.
    pub network: NetworkCapabilities,
    /// Security capabilities.
    pub security: SecurityCapabilities,
    /// System capabilities.
    pub system: SystemCapabilities,
}

/// One network protocol entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkProtocol {
    /// Protocol name (`HTTP`, `HTTPS`, `RTSP`).
    pub name: String,
    /// Enabled.
    pub enabled: bool,
    /// Configured ports.
    pub port: Vec<i32>,
}

/// Default gateway configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkGateway {
    /// IPv4 gateway addresses.
    pub ipv4_address: Vec<String>,
    /// IPv6 gateway addresses.
    pub ipv6_address: Vec<String>,
}

/// Attachment metadata. Go's `AttachmentData` also declares an XOP
/// `Include` arm, but neither direction of this family ever decodes or
/// marshals it — only the `contentType` attribute travels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttachmentData {
    /// The `contentType` attribute.
    pub content_type: String,
}

/// System log / support-info payload: Go's decode only captures the
/// string arm plus the binary part's content type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemLog {
    /// Binary attachment metadata, when the device answered binary.
    pub binary: Option<AttachmentData>,
    /// The textual log/diagnostics payload.
    pub string: String,
}

/// Alias for [`SystemLog`] (Go's separate `SupportInformation` type has the
/// identical shape here).
pub type SupportInformation = SystemLog;

/// One downloadable system log URI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemLogUri {
    /// Log type (`System`, `Access`).
    pub kind: String,
    /// Download URI (wire element `Uri`).
    pub uri: String,
}

/// GetSystemUris result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemUris {
    /// Log URIs — `None` when the device reported no `SystemLogUris`
    /// block at all.
    pub log_uris: Option<Vec<SystemLogUri>>,
    /// Support info download URI.
    pub support_info_uri: String,
    /// System backup download URI.
    pub system_backup_uri: String,
}

/// One backup file. Go's transport shape carries only the name and the
/// data part's content type — the payload bytes never ride this struct.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupFile {
    /// File name.
    pub name: String,
    /// Attachment metadata.
    pub data: AttachmentData,
}

/// StartFirmwareUpgrade result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirmwareUpgrade {
    /// Upload URI.
    pub upload_uri: String,
    /// Upload delay.
    pub upload_delay: String,
    /// Expected downtime.
    pub expected_downtime: String,
}

/// StartSystemRestore result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemRestore {
    /// Upload URI.
    pub upload_uri: String,
    /// Expected downtime.
    pub expected_downtime: String,
}

/// Zero-configuration state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkZeroConfiguration {
    /// The interface token zero-conf runs on.
    pub interface_token: String,
    /// Enabled.
    pub enabled: bool,
    /// Zero-conf (link-local) addresses.
    pub addresses: Vec<String>,
}

/// Dynamic DNS state. Go leaves its `TTL` arm unpopulated ("would need
/// duration parsing"); this port drops it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DynamicDnsInformation {
    /// `NoUpdate`, `ClientUpdates` or `ServerUpdates`.
    pub kind: String,
    /// The dynamic DNS name.
    pub name: String,
}

/// Storage credentials (tds `UserCredential`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserCredential {
    /// User name (wire `UserName`).
    pub user_name: String,
    /// Password (omitted from requests when empty).
    pub password: String,
}

/// tds `StorageConfigurationData`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StorageConfigurationData {
    /// Local storage path (omitted when empty).
    pub local_path: String,
    /// Network storage URI (wire `StorageUri`; omitted when empty).
    pub storage_uri: String,
    /// Access credentials (omitted when `None`).
    pub user: Option<UserCredential>,
    /// Certificate path validation policy id (omitted when empty).
    pub cert_path_validation_policy_id: String,
}

/// tds `StorageConfiguration`: token plus data payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StorageConfiguration {
    /// Configuration token (attribute).
    pub token: String,
    /// Payload.
    pub data: StorageConfigurationData,
}

/// One geo-location entity (Go `LocationEntity`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LocationEntity {
    /// Entity type.
    pub entity: String,
    /// Entity token.
    pub token: String,
    /// Fixed flag.
    pub fixed: bool,
    /// Longitude in degrees (attribute `Lon`).
    pub lon: f64,
    /// Latitude in degrees (attribute `Lat`).
    pub lat: f64,
    /// Elevation in meters (attribute `Elevation`).
    pub elevation: f64,
}

/// 802.11 capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dot11Capabilities {
    /// TKIP support.
    pub tkip: bool,
    /// Scan-available-networks support.
    pub scan_available_networks: bool,
    /// Multiple-configuration support.
    pub multiple_configuration: bool,
    /// Ad-hoc station mode support.
    pub ad_hoc_station_mode: bool,
    /// WEP support.
    pub wep: bool,
}

/// 802.11 station status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dot11Status {
    /// SSID.
    pub ssid: String,
    /// BSSID.
    pub bssid: String,
    /// Pairwise cipher.
    pub pair_cipher: String,
    /// Group cipher.
    pub group_cipher: String,
    /// Signal strength.
    pub signal_strength: String,
    /// Alias of the active configuration.
    pub active_config_alias: String,
}

/// TLS EAP configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsConfiguration {
    /// Referenced certificate id.
    pub certificate_id: String,
}

/// EAP method configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EapMethodConfiguration {
    /// TLS arm.
    pub tls_configuration: Option<TlsConfiguration>,
    /// Password (EAP-GPSK style arm on the wire).
    pub password: String,
}

/// One 802.1X configuration (the Go type carries no XML tags — its request
/// serialization emits unprefixed children, mirrored here).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dot1XConfiguration {
    /// Configuration token.
    pub dot1x_configuration_token: String,
    /// EAP identity.
    pub identity: String,
    /// Anonymous identity.
    pub anonymous_id: String,
    /// EAP method number.
    pub eap_method: i32,
    /// CA certificate ids.
    pub ca_certificate_id: Vec<String>,
    /// EAP method configuration.
    pub eap_method_configuration: Option<EapMethodConfiguration>,
}

/// One scanned 802.11 network (Go `Dot11AvailableNetworks` — the
/// auth-suite field name preserves the Go wire spelling
/// `AuthAndMangementSuite`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dot11AvailableNetworks {
    /// SSID.
    pub ssid: String,
    /// BSSID.
    pub bssid: String,
    /// Authentication/management suites.
    pub auth_and_mangement_suite: Vec<String>,
    /// Pairwise ciphers.
    pub pair_cipher: Vec<String>,
    /// Group ciphers.
    pub group_cipher: Vec<String>,
    /// Signal strength.
    pub signal_strength: String,
}

// Enum-ish string constants (Go's typed-string constants).

/// Discovery mode: discoverable.
pub const DISCOVERY_MODE_DISCOVERABLE: &str = "Discoverable";
/// Discovery mode: non-discoverable.
pub const DISCOVERY_MODE_NON_DISCOVERABLE: &str = "NonDiscoverable";
/// System log type: system log.
pub const SYSTEM_LOG_TYPE_SYSTEM: &str = "System";
/// System log type: access log.
pub const SYSTEM_LOG_TYPE_ACCESS: &str = "Access";
/// Factory default: hard (wipe all parameters incl. network).
pub const FACTORY_DEFAULT_HARD: &str = "Hard";
/// Factory default: soft (keep network parameters).
pub const FACTORY_DEFAULT_SOFT: &str = "Soft";
/// Network protocol name: HTTP.
pub const NETWORK_PROTOCOL_HTTP: &str = "HTTP";
/// Network protocol name: HTTPS.
pub const NETWORK_PROTOCOL_HTTPS: &str = "HTTPS";
/// Network protocol name: RTSP.
pub const NETWORK_PROTOCOL_RTSP: &str = "RTSP";
/// Dynamic DNS type: no updates.
pub const DYNAMIC_DNS_NO_UPDATE: &str = "NoUpdate";
/// Dynamic DNS type: client updates.
pub const DYNAMIC_DNS_CLIENT_UPDATES: &str = "ClientUpdates";
/// Dynamic DNS type: server updates.
pub const DYNAMIC_DNS_SERVER_UPDATES: &str = "ServerUpdates";

// ---------------------------------------------------------------------------
// Request building (Go envelope mirroring)
// ---------------------------------------------------------------------------

/// XML-escape for interpolation into text/attribute positions.
pub(crate) fn esc(s: &str) -> String {
    crate::types::xml_escape(s).into_owned()
}

/// The no-argument action envelope: `<tds:Action xmlns:tds="…"></tds:Action>`
/// (Go renders struct payloads with a full closing tag, never self-closed).
pub(crate) fn tds_action(action: &str) -> String {
    format!("<tds:{action} xmlns:tds=\"{TDS_NS}\"></tds:{action}>")
}

/// An action envelope wrapping `children`.
fn tds_body(action: &str, children: &str) -> String {
    format!("<tds:{action} xmlns:tds=\"{TDS_NS}\">{children}</tds:{action}>")
}

/// One `tds:Name`-style repeated string child.
fn string_children(tag: &str, values: &[String]) -> String {
    values
        .iter()
        .map(|v| format!("<tds:{tag}>{}</tds:{tag}>", esc(v)))
        .collect()
}

/// The SetDNS/SetNetworkInterfaces-style double-namespace open tag.
fn tds_tt_open(action: &str) -> String {
    format!("<tds:{action} xmlns:tds=\"{TDS_NS}\" xmlns:tt=\"{TT_NS}\">")
}

/// Build a SetDNS body (Go field order: FromDHCP, SearchDomain*, DNSManual*;
/// SearchDomain/DNSManual omitempty; manual entry children are tt:-prefixed
/// with IPv4/IPv6Address omitempty).
fn build_set_dns_request(
    from_dhcp: bool,
    search_domain: &[String],
    dns_manual: &[IpAddress],
) -> String {
    let mut children = format!("<tds:FromDHCP>{from_dhcp}</tds:FromDHCP>");
    children.push_str(&string_children("SearchDomain", search_domain));
    for host in dns_manual {
        let mut entry = format!("<tds:DNSManual><tt:Type>{}</tt:Type>", esc(&host.kind));
        if !host.ipv4_address.is_empty() {
            entry.push_str(&format!(
                "<tt:IPv4Address>{}</tt:IPv4Address>",
                esc(&host.ipv4_address)
            ));
        }
        if !host.ipv6_address.is_empty() {
            entry.push_str(&format!(
                "<tt:IPv6Address>{}</tt:IPv6Address>",
                esc(&host.ipv6_address)
            ));
        }
        entry.push_str("</tds:DNSManual>");
        children.push_str(&entry);
    }
    format!("{}{children}</tds:SetDNS>", tds_tt_open("SetDNS"))
}

/// Build a SetNetworkInterfaces body (manual entry present only when the
/// config is static — mirroring the Go conditional pointer).
fn build_set_network_interfaces_request(token: &str, cfg: &NetworkInterfaceConfig) -> String {
    let manual = if cfg.dhcp {
        String::new()
    } else {
        format!(
            "<tt:Manual><tt:Address>{}</tt:Address><tt:PrefixLength>{}</tt:PrefixLength></tt:Manual>",
            esc(&cfg.manual_address),
            cfg.manual_prefix_length
        )
    };
    format!(
        "<tds:SetNetworkInterfaces xmlns:tds=\"{TDS_NS}\" xmlns:tt=\"{TT_NS}\">\
         <tds:InterfaceToken>{}</tds:InterfaceToken>\
         <tds:NetworkInterface><tt:Enabled>{}</tt:Enabled>\
         <tt:IPv4><tt:Enabled>{}</tt:Enabled><tt:Config>{manual}<tt:DHCP>{}</tt:DHCP></tt:Config></tt:IPv4>\
         </tds:NetworkInterface></tds:SetNetworkInterfaces>",
        esc(token),
        cfg.enabled,
        cfg.ipv4_enabled,
        cfg.dhcp
    )
}

/// Build a SetGeoLocation/DeleteGeoLocation body (attributes first, then
/// Entity/Token/Fixed children — Go marshals attributes before elements).
fn build_geo_location_request(action: &str, locations: &[LocationEntity]) -> String {
    let items: String = locations
        .iter()
        .map(|loc| {
            format!(
                "<tds:Location Lon=\"{}\" Lat=\"{}\" Elevation=\"{}\">\
                 <Entity>{}</Entity><Token>{}</Token><Fixed>{}</Fixed></tds:Location>",
                loc.lon,
                loc.lat,
                loc.elevation,
                esc(&loc.entity),
                esc(&loc.token),
                loc.fixed
            )
        })
        .collect();
    tds_body(action, &items)
}

/// Build a SetDPAddresses body — the Go `NetworkHost` type carries no XML
/// tags, so its children marshal unprefixed and all four fields always
/// appear (no omitempty). Quirk preserved deliberately.
fn build_set_dp_addresses_request(addresses: &[NetworkHost]) -> String {
    let items: String = addresses
        .iter()
        .map(|h| {
            format!(
                "<tds:DPAddress><Type>{}</Type><IPv4Address>{}</IPv4Address>\
                 <IPv6Address>{}</IPv6Address><DNSname>{}</DNSname></tds:DPAddress>",
                esc(&h.kind),
                esc(&h.ipv4_address),
                esc(&h.ipv6_address),
                esc(&h.dns_name)
            )
        })
        .collect();
    tds_body("SetDPAddresses", &items)
}

/// Build a SetNetworkProtocols body.
fn build_set_network_protocols_request(protocols: &[NetworkProtocol]) -> String {
    let items: String = protocols
        .iter()
        .map(|p| {
            let ports: String = p
                .port
                .iter()
                .map(|port| format!("<tds:Port>{port}</tds:Port>"))
                .collect();
            format!(
                "<tds:NetworkProtocols><tds:Name>{}</tds:Name><tds:Enabled>{}</tds:Enabled>{ports}</tds:NetworkProtocols>",
                esc(&p.name),
                p.enabled
            )
        })
        .collect();
    tds_body("SetNetworkProtocols", &items)
}

/// Build a RestoreSystem body — the Go wire shape carries only each file's
/// name plus its data part's `contentType` attribute.
fn build_restore_system_request(files: &[BackupFile]) -> String {
    let items: String = files
        .iter()
        .map(|f| {
            format!(
                "<tds:BackupFiles><tds:Name>{}</tds:Name>\
                 <tds:Data contentType=\"{}\"></tds:Data></tds:BackupFiles>",
                esc(&f.name),
                esc(&f.data.content_type)
            )
        })
        .collect();
    tds_body("RestoreSystem", &items)
}

/// Serialize the tds `StorageConfigurationData` children (all omitempty,
/// tds-prefixed — the WSDL declares them in the device service).
fn build_storage_data_children(data: &StorageConfigurationData) -> String {
    let mut out = String::new();
    if !data.local_path.is_empty() {
        out.push_str(&format!(
            "<tds:LocalPath>{}</tds:LocalPath>",
            esc(&data.local_path)
        ));
    }
    if !data.storage_uri.is_empty() {
        out.push_str(&format!(
            "<tds:StorageUri>{}</tds:StorageUri>",
            esc(&data.storage_uri)
        ));
    }
    if let Some(user) = &data.user {
        let password = if user.password.is_empty() {
            String::new()
        } else {
            format!("<tds:Password>{}</tds:Password>", esc(&user.password))
        };
        out.push_str(&format!(
            "<tds:User><tds:UserName>{}</tds:UserName>{password}</tds:User>",
            esc(&user.user_name)
        ));
    }
    if !data.cert_path_validation_policy_id.is_empty() {
        out.push_str(&format!(
            "<tds:CertPathValidationPolicyID>{}</tds:CertPathValidationPolicyID>",
            esc(&data.cert_path_validation_policy_id)
        ));
    }
    out
}

/// Build a CreateStorageConfiguration body — the StorageConfiguration
/// element is typed `tds:StorageConfigurationData`: the data children live
/// directly under it (no token attribute, no Data wrapper).
fn build_create_storage_configuration_request(config: &StorageConfiguration) -> String {
    tds_body(
        "CreateStorageConfiguration",
        &format!(
            "<tds:StorageConfiguration>{}</tds:StorageConfiguration>",
            build_storage_data_children(&config.data)
        ),
    )
}

/// Build a SetStorageConfiguration body — the full `tds:StorageConfiguration`
/// (token attribute plus the Data wrapper).
fn build_set_storage_configuration_request(config: &StorageConfiguration) -> String {
    tds_body(
        "SetStorageConfiguration",
        &format!(
            "<tds:StorageConfiguration token=\"{}\"><tds:Data>{}</tds:Data></tds:StorageConfiguration>",
            esc(&config.token),
            build_storage_data_children(&config.data)
        ),
    )
}

/// Serialize the Go `Dot1XConfiguration` inner payload — the Go type has no
/// XML tags, so every field marshals as an unprefixed element (empty
/// strings included; nil slices / absent pointers omitted).
fn build_dot1x_configuration_inner(config: &Dot1XConfiguration) -> String {
    let mut out = format!(
        "<Dot1XConfigurationToken>{}</Dot1XConfigurationToken>\
         <Identity>{}</Identity><AnonymousID>{}</AnonymousID><EAPMethod>{}</EAPMethod>",
        esc(&config.dot1x_configuration_token),
        esc(&config.identity),
        esc(&config.anonymous_id),
        config.eap_method
    );
    for ca in &config.ca_certificate_id {
        out.push_str(&format!("<CACertificateID>{}</CACertificateID>", esc(ca)));
    }
    if let Some(eap) = &config.eap_method_configuration {
        let tls = eap.tls_configuration.as_ref().map(|tls| {
            format!(
                "<TLSConfiguration><CertificateID>{}</CertificateID></TLSConfiguration>",
                esc(&tls.certificate_id)
            )
        });
        out.push_str(&format!(
            "<EAPMethodConfiguration>{}<Password>{}</Password></EAPMethodConfiguration>",
            tls.unwrap_or_default(),
            esc(&eap.password)
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

impl SoapClient {
    /// GetDeviceInformation — basic identity fields.
    pub async fn get_device_information(&self) -> Result<DeviceInformation, ClientError> {
        let resp = self
            .device_call(&tds_action("GetDeviceInformation"))
            .await?;
        parse_device_information(&resp)
    }

    /// GetCapabilities (category `All`) — the full service capability tree.
    /// The Go twin's cached/single-flight variant is a caller-side concern
    /// here: `SoapClient` is cheap to clone and this call is a plain fetch.
    pub async fn get_capabilities(&self) -> Result<Capabilities, ClientError> {
        let body = tds_body("GetCapabilities", "<tds:Category>All</tds:Category>");
        let resp = self.device_call(&body).await?;
        parse_capabilities(&resp)
    }

    /// SystemReboot — returns the device's reboot message.
    pub async fn system_reboot(&self) -> Result<String, ClientError> {
        let resp = self.device_call(&tds_action("SystemReboot")).await?;
        text_of(&resp, "SystemRebootResponse", "Message")
    }

    /// GetHostname.
    pub async fn get_hostname(&self) -> Result<HostnameInformation, ClientError> {
        let resp = self.device_call(&tds_action("GetHostname")).await?;
        parse_hostname(&resp)
    }

    /// SetHostname.
    pub async fn set_hostname(&self, name: &str) -> Result<(), ClientError> {
        let body = tds_body(
            "SetHostname",
            &format!("<tds:Name>{}</tds:Name>", esc(name)),
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// SetHostnameFromDHCP — returns whether a reboot is needed for the
    /// change to take effect.
    pub async fn set_hostname_from_dhcp(&self, from_dhcp: bool) -> Result<bool, ClientError> {
        let body = tds_body(
            "SetHostnameFromDHCP",
            &format!("<tds:FromDHCP>{from_dhcp}</tds:FromDHCP>"),
        );
        let resp = self.device_call(&body).await?;
        parse_reboot_needed(&resp)
    }

    /// GetDNS.
    pub async fn get_dns(&self) -> Result<DnsInformation, ClientError> {
        let resp = self.device_call(&tds_action("GetDNS")).await?;
        parse_dns(&resp)
    }

    /// SetDNS.
    pub async fn set_dns(
        &self,
        from_dhcp: bool,
        search_domain: &[String],
        dns_manual: &[IpAddress],
    ) -> Result<(), ClientError> {
        let body = build_set_dns_request(from_dhcp, search_domain, dns_manual);
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetNTP — the read side of the NTP family (the write side lives in
    /// [`super::time`] as `set_ntp_server`).
    pub async fn get_ntp(&self) -> Result<NtpInformation, ClientError> {
        let resp = self.device_call(&tds_action("GetNTP")).await?;
        parse_ntp(&resp)
    }

    /// GetNetworkInterfaces.
    pub async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>, ClientError> {
        let resp = self
            .device_call(&tds_action("GetNetworkInterfaces"))
            .await?;
        parse_network_interfaces(&resp)
    }

    /// SetNetworkInterfaces — applies configuration for ONE interface token
    /// (the ONVIF operation is per-interface despite its plural name).
    /// Validation mirrors the Go twin: an empty token or a static config
    /// without a manual address is rejected before the wire; most devices
    /// apply the change only after a reboot — check the returned flag and
    /// call [`SoapClient::system_reboot`] accordingly.
    pub async fn set_network_interfaces(
        &self,
        token: &str,
        cfg: &NetworkInterfaceConfig,
    ) -> Result<bool, ClientError> {
        if token.is_empty() {
            return Err(ClientError::InvalidArgument(
                "SetNetworkInterfaces: invalid parameter: interface token is empty".into(),
            ));
        }
        if !cfg.dhcp && cfg.manual_address.is_empty() {
            return Err(ClientError::InvalidArgument(
                "SetNetworkInterfaces: invalid parameter: static configuration needs a manual address"
                    .into(),
            ));
        }
        let body = build_set_network_interfaces_request(token, cfg);
        let resp = self.device_call(&body).await?;
        parse_reboot_needed(&resp)
    }

    /// GetScopes.
    pub async fn get_scopes(&self) -> Result<Vec<Scope>, ClientError> {
        let resp = self.device_call(&tds_action("GetScopes")).await?;
        parse_scopes(&resp)
    }

    /// AddScopes.
    pub async fn add_scopes(&self, scope_items: &[String]) -> Result<(), ClientError> {
        let body = tds_body("AddScopes", &string_children("ScopeItem", scope_items));
        self.device_call(&body).await?;
        Ok(())
    }

    /// RemoveScopes — returns the scopes the device reports as removed.
    pub async fn remove_scopes(&self, scope_items: &[String]) -> Result<Vec<String>, ClientError> {
        let body = tds_body("RemoveScopes", &string_children("ScopeItem", scope_items));
        let resp = self.device_call(&body).await?;
        texts_of(&resp, "RemoveScopesResponse", "ScopeItem")
    }

    /// SetScopes — replaces the configurable scope set.
    pub async fn set_scopes(&self, scopes: &[String]) -> Result<(), ClientError> {
        let body = tds_body("SetScopes", &string_children("Scopes", scopes));
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetServices.
    pub async fn get_services(
        &self,
        include_capability: bool,
    ) -> Result<Vec<ServiceEntry>, ClientError> {
        let body = tds_body(
            "GetServices",
            &format!("<tds:IncludeCapability>{include_capability}</tds:IncludeCapability>"),
        );
        let resp = self.device_call(&body).await?;
        parse_services(&resp)
    }

    /// GetServiceCapabilities (device service) — the attribute-shaped
    /// capability triple (Go method name: GetDeviceServiceCapabilities).
    pub async fn get_device_service_capabilities(
        &self,
    ) -> Result<DeviceServiceCapabilities, ClientError> {
        let resp = self
            .device_call(&tds_action("GetServiceCapabilities"))
            .await?;
        parse_device_service_capabilities(&resp)
    }

    /// GetDiscoveryMode.
    pub async fn get_discovery_mode(&self) -> Result<String, ClientError> {
        let resp = self.device_call(&tds_action("GetDiscoveryMode")).await?;
        text_of(&resp, "GetDiscoveryModeResponse", "DiscoveryMode")
    }

    /// SetDiscoveryMode.
    pub async fn set_discovery_mode(&self, mode: &str) -> Result<(), ClientError> {
        let body = tds_body(
            "SetDiscoveryMode",
            &format!("<tds:DiscoveryMode>{}</tds:DiscoveryMode>", esc(mode)),
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetRemoteDiscoveryMode.
    pub async fn get_remote_discovery_mode(&self) -> Result<String, ClientError> {
        let resp = self
            .device_call(&tds_action("GetRemoteDiscoveryMode"))
            .await?;
        text_of(
            &resp,
            "GetRemoteDiscoveryModeResponse",
            "RemoteDiscoveryMode",
        )
    }

    /// SetRemoteDiscoveryMode.
    pub async fn set_remote_discovery_mode(&self, mode: &str) -> Result<(), ClientError> {
        let body = tds_body(
            "SetRemoteDiscoveryMode",
            &format!(
                "<tds:RemoteDiscoveryMode>{}</tds:RemoteDiscoveryMode>",
                esc(mode)
            ),
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetEndpointReference — the device GUID.
    pub async fn get_endpoint_reference(&self) -> Result<String, ClientError> {
        let resp = self
            .device_call(&tds_action("GetEndpointReference"))
            .await?;
        text_of(&resp, "GetEndpointReferenceResponse", "GUID")
    }

    /// GetNetworkProtocols.
    pub async fn get_network_protocols(&self) -> Result<Vec<NetworkProtocol>, ClientError> {
        let resp = self.device_call(&tds_action("GetNetworkProtocols")).await?;
        parse_network_protocols(&resp)
    }

    /// SetNetworkProtocols.
    pub async fn set_network_protocols(
        &self,
        protocols: &[NetworkProtocol],
    ) -> Result<(), ClientError> {
        let body = build_set_network_protocols_request(protocols);
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetNetworkDefaultGateway.
    pub async fn get_network_default_gateway(&self) -> Result<NetworkGateway, ClientError> {
        let resp = self
            .device_call(&tds_action("GetNetworkDefaultGateway"))
            .await?;
        parse_network_gateway(&resp)
    }

    /// SetNetworkDefaultGateway.
    pub async fn set_network_default_gateway(
        &self,
        gateway: &NetworkGateway,
    ) -> Result<(), ClientError> {
        let children = format!(
            "{}{}",
            string_children("IPv4Address", &gateway.ipv4_address),
            string_children("IPv6Address", &gateway.ipv6_address)
        );
        let body = tds_body("SetNetworkDefaultGateway", &children);
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetGeoLocation.
    pub async fn get_geo_location(&self) -> Result<Vec<LocationEntity>, ClientError> {
        let resp = self.device_call(&tds_action("GetGeoLocation")).await?;
        parse_geo_location(&resp)
    }

    /// SetGeoLocation.
    pub async fn set_geo_location(&self, locations: &[LocationEntity]) -> Result<(), ClientError> {
        let body = build_geo_location_request("SetGeoLocation", locations);
        self.device_call(&body).await?;
        Ok(())
    }

    /// DeleteGeoLocation.
    pub async fn delete_geo_location(
        &self,
        locations: &[LocationEntity],
    ) -> Result<(), ClientError> {
        let body = build_geo_location_request("DeleteGeoLocation", locations);
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetDPAddresses — device provisioning addresses.
    pub async fn get_dp_addresses(&self) -> Result<Vec<NetworkHost>, ClientError> {
        let resp = self.device_call(&tds_action("GetDPAddresses")).await?;
        parse_dp_addresses(&resp)
    }

    /// SetDPAddresses.
    pub async fn set_dp_addresses(&self, addresses: &[NetworkHost]) -> Result<(), ClientError> {
        let body = build_set_dp_addresses_request(addresses);
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetWsdlURL (the wire action is `GetWsdlUrl`).
    pub async fn get_wsdl_url(&self) -> Result<String, ClientError> {
        let resp = self.device_call(&tds_action("GetWsdlUrl")).await?;
        text_of(&resp, "GetWsdlUrlResponse", "WsdlUrl")
    }

    /// SendAuxiliaryCommand — round-trips one auxiliary command (the Go
    /// twin's `ptz.AuxiliaryData` string type).
    pub async fn send_auxiliary_command(&self, command: &str) -> Result<String, ClientError> {
        let body = tds_body(
            "SendAuxiliaryCommand",
            &format!(
                "<tds:AuxiliaryCommand>{}</tds:AuxiliaryCommand>",
                esc(command)
            ),
        );
        let resp = self.device_call(&body).await?;
        text_of(
            &resp,
            "SendAuxiliaryCommandResponse",
            "AuxiliaryCommandResponse",
        )
    }

    /// GetSystemLog (`System` or `Access` — see [`SYSTEM_LOG_TYPE_SYSTEM`]).
    pub async fn get_system_log(&self, log_type: &str) -> Result<SystemLog, ClientError> {
        let body = tds_body(
            "GetSystemLog",
            &format!("<tds:LogType>{}</tds:LogType>", esc(log_type)),
        );
        let resp = self.device_call(&body).await?;
        parse_system_log(&resp)
    }

    /// GetSystemBackup — file list with attachment metadata (the Go wire
    /// shape carries no payload bytes).
    pub async fn get_system_backup(&self) -> Result<Vec<BackupFile>, ClientError> {
        let resp = self.device_call(&tds_action("GetSystemBackup")).await?;
        parse_system_backup(&resp)
    }

    /// RestoreSystem.
    pub async fn restore_system(&self, files: &[BackupFile]) -> Result<(), ClientError> {
        let body = build_restore_system_request(files);
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetSystemUris.
    pub async fn get_system_uris(&self) -> Result<SystemUris, ClientError> {
        let resp = self.device_call(&tds_action("GetSystemUris")).await?;
        parse_system_uris(&resp)
    }

    /// GetSystemSupportInformation — arbitrary device diagnostics.
    pub async fn get_system_support_information(&self) -> Result<SupportInformation, ClientError> {
        let resp = self
            .device_call(&tds_action("GetSystemSupportInformation"))
            .await?;
        parse_system_log(&resp)
    }

    /// SetSystemFactoryDefault (`Hard` / `Soft`).
    pub async fn set_system_factory_default(
        &self,
        factory_default: &str,
    ) -> Result<(), ClientError> {
        let body = tds_body(
            "SetSystemFactoryDefault",
            &format!(
                "<tds:FactoryDefault>{}</tds:FactoryDefault>",
                esc(factory_default)
            ),
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// StartFirmwareUpgrade — the HTTP POST upload handshake.
    pub async fn start_firmware_upgrade(&self) -> Result<FirmwareUpgrade, ClientError> {
        let resp = self
            .device_call(&tds_action("StartFirmwareUpgrade"))
            .await?;
        Ok(FirmwareUpgrade {
            upload_uri: text_of(&resp, "StartFirmwareUpgradeResponse", "UploadUri")?,
            upload_delay: text_of(&resp, "StartFirmwareUpgradeResponse", "UploadDelay")?,
            expected_downtime: text_of(&resp, "StartFirmwareUpgradeResponse", "ExpectedDownTime")?,
        })
    }

    /// StartSystemRestore.
    pub async fn start_system_restore(&self) -> Result<SystemRestore, ClientError> {
        let resp = self.device_call(&tds_action("StartSystemRestore")).await?;
        Ok(SystemRestore {
            upload_uri: text_of(&resp, "StartSystemRestoreResponse", "UploadUri")?,
            expected_downtime: text_of(&resp, "StartSystemRestoreResponse", "ExpectedDownTime")?,
        })
    }

    /// GetZeroConfiguration.
    pub async fn get_zero_configuration(&self) -> Result<NetworkZeroConfiguration, ClientError> {
        let resp = self
            .device_call(&tds_action("GetZeroConfiguration"))
            .await?;
        parse_zero_configuration(&resp)
    }

    /// SetZeroConfiguration.
    pub async fn set_zero_configuration(
        &self,
        interface_token: &str,
        enabled: bool,
    ) -> Result<(), ClientError> {
        let body = tds_body(
            "SetZeroConfiguration",
            &format!(
                "<tds:InterfaceToken>{}</tds:InterfaceToken><tds:Enabled>{enabled}</tds:Enabled>",
                esc(interface_token)
            ),
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetDynamicDNS (the Go decode leaves the TTL arm unpopulated).
    pub async fn get_dynamic_dns(&self) -> Result<DynamicDnsInformation, ClientError> {
        let resp = self.device_call(&tds_action("GetDynamicDNS")).await?;
        parse_dynamic_dns(&resp)
    }

    /// SetDynamicDNS.
    pub async fn set_dynamic_dns(&self, dns_type: &str, name: &str) -> Result<(), ClientError> {
        let name_elem = if name.is_empty() {
            String::new()
        } else {
            format!("<tds:Name>{}</tds:Name>", esc(name))
        };
        let body = tds_body(
            "SetDynamicDNS",
            &format!("<tds:Type>{}</tds:Type>{name_elem}", esc(dns_type)),
        );
        self.device_call(&body).await?;
        Ok(())
    }

    // -- storage -----------------------------------------------------------

    /// GetStorageConfigurations. The Go decode collects elements named
    /// `StorageConfigurations`; real devices send `StorageConfiguration` —
    /// this port accepts both local names.
    pub async fn get_storage_configurations(
        &self,
    ) -> Result<Vec<StorageConfiguration>, ClientError> {
        let resp = self
            .device_call(&tds_action("GetStorageConfigurations"))
            .await?;
        parse_storage_configurations(&resp)
    }

    /// GetStorageConfiguration — `None` when the device reports no such
    /// configuration.
    pub async fn get_storage_configuration(
        &self,
        token: &str,
    ) -> Result<Option<StorageConfiguration>, ClientError> {
        let body = tds_body(
            "GetStorageConfiguration",
            &format!("<tds:Token>{}</tds:Token>", esc(token)),
        );
        let resp = self.device_call(&body).await?;
        Ok(parse_storage_configurations(&resp)?.into_iter().next())
    }

    /// CreateStorageConfiguration — returns the new configuration's token.
    pub async fn create_storage_configuration(
        &self,
        config: &StorageConfiguration,
    ) -> Result<String, ClientError> {
        let body = build_create_storage_configuration_request(config);
        let resp = self.device_call(&body).await?;
        text_of(&resp, "CreateStorageConfigurationResponse", "Token")
    }

    /// SetStorageConfiguration.
    pub async fn set_storage_configuration(
        &self,
        config: &StorageConfiguration,
    ) -> Result<(), ClientError> {
        let body = build_set_storage_configuration_request(config);
        self.device_call(&body).await?;
        Ok(())
    }

    /// DeleteStorageConfiguration.
    pub async fn delete_storage_configuration(&self, token: &str) -> Result<(), ClientError> {
        let body = tds_body(
            "DeleteStorageConfiguration",
            &format!("<tds:Token>{}</tds:Token>", esc(token)),
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// SetHashingAlgorithm.
    pub async fn set_hashing_algorithm(&self, algorithm: &str) -> Result<(), ClientError> {
        let body = tds_body(
            "SetHashingAlgorithm",
            &format!("<tds:Algorithm>{}</tds:Algorithm>", esc(algorithm)),
        );
        self.device_call(&body).await?;
        Ok(())
    }

    // -- 802.11 / 802.1X ----------------------------------------------------

    /// GetDot11Capabilities — `None` when the device reports none.
    pub async fn get_dot11_capabilities(&self) -> Result<Option<Dot11Capabilities>, ClientError> {
        let resp = self
            .device_call(&tds_action("GetDot11Capabilities"))
            .await?;
        parse_dot11_capabilities(&resp)
    }

    /// GetDot11Status — `None` when the device reports none.
    pub async fn get_dot11_status(
        &self,
        interface_token: &str,
    ) -> Result<Option<Dot11Status>, ClientError> {
        let body = tds_body(
            "GetDot11Status",
            &format!(
                "<tds:InterfaceToken>{}</tds:InterfaceToken>",
                esc(interface_token)
            ),
        );
        let resp = self.device_call(&body).await?;
        parse_dot11_status(&resp)
    }

    /// GetDot1XConfiguration — `None` when the device reports none.
    pub async fn get_dot1x_configuration(
        &self,
        config_token: &str,
    ) -> Result<Option<Dot1XConfiguration>, ClientError> {
        let body = tds_body(
            "GetDot1XConfiguration",
            &format!(
                "<tds:Dot1XConfigurationToken>{}</tds:Dot1XConfigurationToken>",
                esc(config_token)
            ),
        );
        let resp = self.device_call(&body).await?;
        Ok(parse_dot1x_configurations(&resp)?.into_iter().next())
    }

    /// GetDot1XConfigurations.
    pub async fn get_dot1x_configurations(&self) -> Result<Vec<Dot1XConfiguration>, ClientError> {
        let resp = self
            .device_call(&tds_action("GetDot1XConfigurations"))
            .await?;
        parse_dot1x_configurations(&resp)
    }

    /// SetDot1XConfiguration.
    pub async fn set_dot1x_configuration(
        &self,
        config: &Dot1XConfiguration,
    ) -> Result<(), ClientError> {
        let body = tds_body(
            "SetDot1XConfiguration",
            &format!(
                "<tds:Dot1XConfiguration>{}</tds:Dot1XConfiguration>",
                build_dot1x_configuration_inner(config)
            ),
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// CreateDot1XConfiguration.
    pub async fn create_dot1x_configuration(
        &self,
        config: &Dot1XConfiguration,
    ) -> Result<(), ClientError> {
        let body = tds_body(
            "CreateDot1XConfiguration",
            &format!(
                "<tds:Dot1XConfiguration>{}</tds:Dot1XConfiguration>",
                build_dot1x_configuration_inner(config)
            ),
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// DeleteDot1XConfiguration.
    pub async fn delete_dot1x_configuration(&self, config_token: &str) -> Result<(), ClientError> {
        let body = tds_body(
            "DeleteDot1XConfiguration",
            &format!(
                "<tds:Dot1XConfigurationToken>{}</tds:Dot1XConfigurationToken>",
                esc(config_token)
            ),
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// ScanAvailableDot11Networks.
    pub async fn scan_available_dot11_networks(
        &self,
        interface_token: &str,
    ) -> Result<Vec<Dot11AvailableNetworks>, ClientError> {
        let body = tds_body(
            "ScanAvailableDot11Networks",
            &format!(
                "<tds:InterfaceToken>{}</tds:InterfaceToken>",
                esc(interface_token)
            ),
        );
        let resp = self.device_call(&body).await?;
        parse_dot11_networks(&resp)
    }
}

/// Convert a prefix length (0-32) to a dotted netmask ("255.255.255.0" for
/// 24). Returns "" for out-of-range prefixes — the Go twin's exported
/// convenience, reused by the security family's IP-filter decode.
#[must_use]
pub fn netmask_from_prefix_length(prefix_length: i32) -> String {
    if !(0..=32).contains(&prefix_length) {
        return String::new();
    }
    if prefix_length == 0 {
        return "0.0.0.0".into();
    }
    let mask: u32 = 0xFFFF_FFFFu32 << (32 - prefix_length);
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) as u8,
        (mask >> 16) as u8,
        (mask >> 8) as u8,
        mask as u8
    )
}

// ---------------------------------------------------------------------------
// Response decoders
// ---------------------------------------------------------------------------

fn parse_device_information(resp: &str) -> Result<DeviceInformation, ClientError> {
    let mut info = DeviceInformation::default();
    walk_local(resp, "GetDeviceInformationResponse", |step| {
        if let Step::Text { path, text } = step {
            match path.last().map(String::as_str) {
                Some("Manufacturer") => info.manufacturer = text.to_string(),
                Some("Model") => info.model = text.to_string(),
                Some("FirmwareVersion") => info.firmware_version = text.to_string(),
                Some("SerialNumber") => info.serial_number = text.to_string(),
                Some("HardwareId") => info.hardware_id = text.to_string(),
                _ => {}
            }
        }
        Ok(())
    })?;
    Ok(info)
}

fn parse_hostname(resp: &str) -> Result<HostnameInformation, ClientError> {
    let mut info = HostnameInformation::default();
    walk_local(resp, "GetHostnameResponse", |step| {
        if let Step::Text { path, text } = step {
            if tail_is(path, &["HostnameInformation", "FromDHCP"]) {
                info.from_dhcp = xml_bool(text);
            } else if tail_is(path, &["HostnameInformation", "Name"]) {
                info.name = text.to_string();
            }
        }
        Ok(())
    })?;
    Ok(info)
}

fn parse_dns(resp: &str) -> Result<DnsInformation, ClientError> {
    let mut out = DnsInformation::default();
    walk_local(resp, "GetDNSResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["DNSInformation", "DNSFromDHCP"]) {
                out.dns_from_dhcp.push(IpAddress::default());
            } else if tail_is(path, &["DNSInformation", "DNSManual"]) {
                out.dns_manual.push(IpAddress::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if tail_is(path, &["DNSInformation", "FromDHCP"]) {
                out.from_dhcp = xml_bool(text);
            } else if tail_is(path, &["DNSInformation", "SearchDomain"]) {
                out.search_domain.push(text.to_string());
            } else if let Some(field) = host_field(path, "DNSFromDHCP") {
                fill_ip_address(out.dns_from_dhcp.last_mut(), field, text);
            } else if let Some(field) = host_field(path, "DNSManual") {
                fill_ip_address(out.dns_manual.last_mut(), field, text);
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

/// Host-entry field selector: for a path ending `[host, field]` inside a
/// GetDNS/GetNTP/GetDPAddresses item, returns the field name.
fn host_field<'p>(path: &'p [String], host: &str) -> Option<&'p str> {
    if path.len() >= 2 && path[path.len() - 2] == host {
        path.last().map(String::as_str)
    } else {
        None
    }
}

fn fill_ip_address(target: Option<&mut IpAddress>, field: &str, text: &str) {
    if let Some(host) = target {
        match field {
            "Type" => host.kind = text.to_string(),
            "IPv4Address" => host.ipv4_address = text.to_string(),
            "IPv6Address" => host.ipv6_address = text.to_string(),
            _ => {}
        }
    }
}

fn parse_ntp(resp: &str) -> Result<NtpInformation, ClientError> {
    let mut out = NtpInformation::default();
    walk_local(resp, "GetNTPResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["NTPInformation", "NTPFromDHCP"]) {
                out.ntp_from_dhcp.push(NetworkHost::default());
            } else if tail_is(path, &["NTPInformation", "NTPManual"]) {
                out.ntp_manual.push(NetworkHost::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if tail_is(path, &["NTPInformation", "FromDHCP"]) {
                out.from_dhcp = xml_bool(text);
            } else if let Some(field) = host_field(path, "NTPFromDHCP") {
                fill_network_host(out.ntp_from_dhcp.last_mut(), field, text);
            } else if let Some(field) = host_field(path, "NTPManual") {
                fill_network_host(out.ntp_manual.last_mut(), field, text);
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn fill_network_host(target: Option<&mut NetworkHost>, field: &str, text: &str) {
    if let Some(host) = target {
        match field {
            "Type" => host.kind = text.to_string(),
            "IPv4Address" => host.ipv4_address = text.to_string(),
            "IPv6Address" => host.ipv6_address = text.to_string(),
            "DNSname" => host.dns_name = text.to_string(),
            _ => {}
        }
    }
}

fn parse_network_interfaces(resp: &str) -> Result<Vec<NetworkInterface>, ClientError> {
    let mut out: Vec<NetworkInterface> = Vec::new();
    // Per-item IPv4 scratch, attached only when IPv4/Enabled is true —
    // mirroring the Go decode.
    let mut ipv4_enabled = false;
    let mut ipv4_dhcp = false;
    let mut ipv4_manual: Vec<PrefixedIpv4Address> = Vec::new();

    walk_local(resp, "GetNetworkInterfacesResponse", |step| match step {
        Step::Start { path, attrs } => {
            if tail_is(path, &["NetworkInterfaces"]) {
                // Reset the per-item IPv4 scratch: an interface without an
                // IPv4 block reports None, not the previous item's state.
                ipv4_enabled = false;
                ipv4_dhcp = false;
                ipv4_manual.clear();
                out.push(NetworkInterface {
                    token: attr_get(attrs, "token").unwrap_or("").to_string(),
                    ..NetworkInterface::default()
                });
            } else if tail_is(path, &["NetworkInterfaces", "IPv4", "Config", "Manual"]) {
                ipv4_manual.push(PrefixedIpv4Address::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if let Some(last) = out.last_mut() {
                if tail_is(path, &["NetworkInterfaces", "Enabled"]) {
                    last.enabled = xml_bool(text);
                } else if tail_is(path, &["NetworkInterfaces", "Info", "Name"]) {
                    last.info.name = text.to_string();
                } else if tail_is(path, &["NetworkInterfaces", "Info", "HwAddress"]) {
                    last.info.hw_address = text.to_string();
                } else if tail_is(path, &["NetworkInterfaces", "Info", "MTU"]) {
                    last.info.mtu = xml_int(text);
                }
            }
            if tail_is(path, &["NetworkInterfaces", "IPv4", "Enabled"]) {
                ipv4_enabled = xml_bool(text);
            } else if tail_is(path, &["NetworkInterfaces", "IPv4", "Config", "DHCP"]) {
                ipv4_dhcp = xml_bool(text);
            } else if tail_is(
                path,
                &["NetworkInterfaces", "IPv4", "Config", "Manual", "Address"],
            ) {
                if let Some(entry) = ipv4_manual.last_mut() {
                    entry.address = text.to_string();
                }
            } else if tail_is(
                path,
                &[
                    "NetworkInterfaces",
                    "IPv4",
                    "Config",
                    "Manual",
                    "PrefixLength",
                ],
            ) {
                if let Some(entry) = ipv4_manual.last_mut() {
                    entry.prefix_length = xml_int(text);
                    entry.netmask = netmask_from_prefix_length(entry.prefix_length);
                }
            }
            Ok(())
        }
        Step::End { path } => {
            if tail_is(path, &["NetworkInterfaces"]) && ipv4_enabled {
                if let Some(last) = out.last_mut() {
                    last.ipv4 = Some(Ipv4NetworkInterface {
                        enabled: true,
                        config: Ipv4Configuration {
                            manual: std::mem::take(&mut ipv4_manual),
                            dhcp: ipv4_dhcp,
                        },
                    });
                }
            }
            Ok(())
        }
    })?;
    Ok(out)
}

fn parse_scopes(resp: &str) -> Result<Vec<Scope>, ClientError> {
    let mut out: Vec<Scope> = Vec::new();
    walk_local(resp, "GetScopesResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["Scopes"]) {
                out.push(Scope::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if tail_is(path, &["Scopes", "ScopeDef"]) {
                if let Some(last) = out.last_mut() {
                    last.scope_def = text.to_string();
                }
            } else if tail_is(path, &["Scopes", "ScopeItem"]) {
                if let Some(last) = out.last_mut() {
                    last.scope_item = text.to_string();
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_services(resp: &str) -> Result<Vec<ServiceEntry>, ClientError> {
    let mut out: Vec<ServiceEntry> = Vec::new();
    // (depth of the Capabilities element, accumulated inner XML)
    let mut capture: Option<(usize, String)> = None;
    walk_local(resp, "GetServicesResponse", |step| match step {
        Step::Start { path, .. } => {
            if let Some((_, buf)) = capture.as_mut() {
                if let Some(name) = path.last() {
                    buf.push('<');
                    buf.push_str(name);
                    buf.push('>');
                }
                return Ok(());
            }
            if tail_is(path, &["Service"]) {
                out.push(ServiceEntry::default());
            } else if tail_is(path, &["Service", "Capabilities"]) {
                capture = Some((path.len(), String::new()));
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if let Some((_, buf)) = capture.as_mut() {
                buf.push_str(&crate::types::xml_escape(text));
                return Ok(());
            }
            if let Some(last) = out.last_mut() {
                if tail_is(path, &["Service", "Namespace"]) {
                    last.namespace = text.to_string();
                } else if tail_is(path, &["Service", "XAddr"]) {
                    last.x_addr = text.to_string();
                } else if tail_is(path, &["Service", "Version", "Major"]) {
                    last.version.major = xml_int(text);
                } else if tail_is(path, &["Service", "Version", "Minor"]) {
                    last.version.minor = xml_int(text);
                }
            }
            Ok(())
        }
        Step::End { path } => {
            let at_capture_root = matches!(capture.as_ref(), Some((d, _)) if *d == path.len());
            if at_capture_root {
                if let Some((_, buf)) = capture.take() {
                    if let Some(last) = out.last_mut() {
                        last.capabilities = Some(buf);
                    }
                }
                return Ok(());
            }
            if let Some((_, buf)) = capture.as_mut() {
                if let Some(name) = path.last() {
                    buf.push_str("</");
                    buf.push_str(name);
                    buf.push('>');
                }
            }
            Ok(())
        }
    })?;
    Ok(out)
}

fn parse_capabilities(resp: &str) -> Result<Capabilities, ClientError> {
    let mut caps = Capabilities::default();
    walk_local(resp, "GetCapabilitiesResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["Capabilities", "Analytics"]) {
                caps.analytics = Some(AnalyticsCapabilities::default());
            } else if tail_is(path, &["Capabilities", "Device"]) {
                caps.device = Some(DeviceCapabilities::default());
            } else if tail_is(path, &["Capabilities", "Device", "Network"]) {
                if let Some(d) = caps.device.as_mut() {
                    d.network = Some(NetworkCapabilities::default());
                }
            } else if tail_is(path, &["Capabilities", "Device", "System"]) {
                if let Some(d) = caps.device.as_mut() {
                    d.system = Some(SystemCapabilities::default());
                }
            } else if tail_is(path, &["Capabilities", "Device", "IO"]) {
                if let Some(d) = caps.device.as_mut() {
                    d.io = Some(IoCapabilities::default());
                }
            } else if tail_is(path, &["Capabilities", "Device", "Security"]) {
                if let Some(d) = caps.device.as_mut() {
                    d.security = Some(SecurityCapabilities::default());
                }
            } else if tail_is(path, &["Capabilities", "Events"]) {
                caps.events = Some(EventCapabilities::default());
            } else if tail_is(path, &["Capabilities", "Imaging"]) {
                caps.imaging = Some(ImagingCapabilities::default());
            } else if tail_is(path, &["Capabilities", "Media"]) {
                caps.media = Some(MediaCapabilities::default());
            } else if tail_is(path, &["Capabilities", "Media", "StreamingCapabilities"]) {
                if let Some(m) = caps.media.as_mut() {
                    m.streaming_capabilities = Some(StreamingCapabilities::default());
                }
            } else if tail_is(path, &["Capabilities", "PTZ"]) {
                caps.ptz = Some(PtzCapabilities::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if tail_is(path, &["Analytics", "XAddr"]) {
                set_field(caps.analytics.as_mut(), |a| a.x_addr = text.to_string());
            } else if tail_is(path, &["Analytics", "RuleSupport"]) {
                set_field(caps.analytics.as_mut(), |a| a.rule_support = xml_bool(text));
            } else if tail_is(path, &["Analytics", "AnalyticsModuleSupport"]) {
                set_field(caps.analytics.as_mut(), |a| {
                    a.analytics_module_support = xml_bool(text)
                });
            } else if tail_is(path, &["Device", "XAddr"]) {
                set_field(caps.device.as_mut(), |d| d.x_addr = text.to_string());
            } else if tail_is(path, &["Device", "Network", "IPFilter"]) {
                with_net(&mut caps, |n| n.ip_filter = xml_bool(text));
            } else if tail_is(path, &["Device", "Network", "ZeroConfiguration"]) {
                with_net(&mut caps, |n| n.zero_configuration = xml_bool(text));
            } else if tail_is(path, &["Device", "Network", "IPVersion6"]) {
                with_net(&mut caps, |n| n.ip_version6 = xml_bool(text));
            } else if tail_is(path, &["Device", "Network", "DynDNS"]) {
                with_net(&mut caps, |n| n.dyn_dns = xml_bool(text));
            } else if tail_is(path, &["Device", "System", "DiscoveryResolve"]) {
                with_sys(&mut caps, |s| s.discovery_resolve = xml_bool(text));
            } else if tail_is(path, &["Device", "System", "DiscoveryBye"]) {
                with_sys(&mut caps, |s| s.discovery_bye = xml_bool(text));
            } else if tail_is(path, &["Device", "System", "RemoteDiscovery"]) {
                with_sys(&mut caps, |s| s.remote_discovery = xml_bool(text));
            } else if tail_is(path, &["Device", "System", "SystemBackup"]) {
                with_sys(&mut caps, |s| s.system_backup = xml_bool(text));
            } else if tail_is(path, &["Device", "System", "SystemLogging"]) {
                with_sys(&mut caps, |s| s.system_logging = xml_bool(text));
            } else if tail_is(path, &["Device", "System", "FirmwareUpgrade"]) {
                with_sys(&mut caps, |s| s.firmware_upgrade = xml_bool(text));
            } else if tail_is(path, &["Device", "System", "SupportedVersions", "Major"]) {
                if let Some(d) = caps.device.as_mut() {
                    if let Some(s) = d.system.as_mut() {
                        s.supported_versions.push(text.to_string());
                    }
                }
            } else if tail_is(path, &["Device", "IO", "InputConnectors"]) {
                with_io(&mut caps, |io| io.input_connectors = xml_int(text));
            } else if tail_is(path, &["Device", "IO", "RelayOutputs"]) {
                with_io(&mut caps, |io| io.relay_outputs = xml_int(text));
            } else if tail_is(path, &["Device", "Security", "TLS1.1"]) {
                with_sec(&mut caps, |sec| sec.tls11 = xml_bool(text));
            } else if tail_is(path, &["Device", "Security", "TLS1.2"]) {
                with_sec(&mut caps, |sec| sec.tls12 = xml_bool(text));
            } else if tail_is(path, &["Device", "Security", "OnboardKeyGeneration"]) {
                with_sec(&mut caps, |sec| sec.onboard_key_generation = xml_bool(text));
            } else if tail_is(path, &["Device", "Security", "AccessPolicyConfig"]) {
                with_sec(&mut caps, |sec| sec.access_policy_config = xml_bool(text));
            } else if tail_is(path, &["Device", "Security", "X.509Token"]) {
                with_sec(&mut caps, |sec| sec.x509_token = xml_bool(text));
            } else if tail_is(path, &["Device", "Security", "SAMLToken"]) {
                with_sec(&mut caps, |sec| sec.saml_token = xml_bool(text));
            } else if tail_is(path, &["Device", "Security", "KerberosToken"]) {
                with_sec(&mut caps, |sec| sec.kerberos_token = xml_bool(text));
            } else if tail_is(path, &["Device", "Security", "RELToken"]) {
                with_sec(&mut caps, |sec| sec.rel_token = xml_bool(text));
            } else if tail_is(path, &["Events", "XAddr"]) {
                set_field(caps.events.as_mut(), |e| e.x_addr = text.to_string());
            } else if tail_is(path, &["Events", "WSSubscriptionPolicySupport"]) {
                set_field(caps.events.as_mut(), |e| {
                    e.ws_subscription_policy_support = xml_bool(text)
                });
            } else if tail_is(path, &["Events", "WSPullPointSupport"]) {
                set_field(caps.events.as_mut(), |e| {
                    e.ws_pull_point_support = xml_bool(text)
                });
            } else if tail_is(
                path,
                &["Events", "WSPausableSubscriptionManagerInterfaceSupport"],
            ) {
                set_field(caps.events.as_mut(), |e| {
                    e.ws_pausable_subscription_support = xml_bool(text)
                });
            } else if tail_is(path, &["Imaging", "XAddr"]) {
                set_field(caps.imaging.as_mut(), |i| i.x_addr = text.to_string());
            } else if tail_is(path, &["Media", "XAddr"]) {
                set_field(caps.media.as_mut(), |m| m.x_addr = text.to_string());
            } else if tail_is(path, &["Media", "StreamingCapabilities", "RTPMulticast"]) {
                with_streaming(&mut caps, |s| s.rtp_multicast = xml_bool(text));
            } else if tail_is(path, &["Media", "StreamingCapabilities", "RTP_TCP"]) {
                with_streaming(&mut caps, |s| s.rtp_tcp = xml_bool(text));
            } else if tail_is(path, &["Media", "StreamingCapabilities", "RTP_RTSP_TCP"]) {
                with_streaming(&mut caps, |s| s.rtp_rtsp_tcp = xml_bool(text));
            } else if tail_is(path, &["PTZ", "XAddr"]) {
                set_field(caps.ptz.as_mut(), |p| p.x_addr = text.to_string());
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(caps)
}

fn set_field<T>(slot: Option<&mut T>, f: impl FnOnce(&mut T)) {
    if let Some(value) = slot {
        f(value);
    }
}

/// Run `f` on the device section's Network sub-capabilities (only when the
/// section was reported — mirroring Go's nil-arm semantics).
fn with_net(caps: &mut Capabilities, f: impl FnOnce(&mut NetworkCapabilities)) {
    if let Some(d) = caps.device.as_mut() {
        if let Some(n) = d.network.as_mut() {
            f(n);
        }
    }
}

/// Run `f` on the device section's System sub-capabilities.
fn with_sys(caps: &mut Capabilities, f: impl FnOnce(&mut SystemCapabilities)) {
    if let Some(d) = caps.device.as_mut() {
        if let Some(s) = d.system.as_mut() {
            f(s);
        }
    }
}

/// Run `f` on the device section's I/O sub-capabilities.
fn with_io(caps: &mut Capabilities, f: impl FnOnce(&mut IoCapabilities)) {
    if let Some(d) = caps.device.as_mut() {
        if let Some(io) = d.io.as_mut() {
            f(io);
        }
    }
}

/// Run `f` on the device section's Security sub-capabilities.
fn with_sec(caps: &mut Capabilities, f: impl FnOnce(&mut SecurityCapabilities)) {
    if let Some(d) = caps.device.as_mut() {
        if let Some(sec) = d.security.as_mut() {
            f(sec);
        }
    }
}

/// Run `f` on the media section's streaming sub-capabilities.
fn with_streaming(caps: &mut Capabilities, f: impl FnOnce(&mut StreamingCapabilities)) {
    if let Some(m) = caps.media.as_mut() {
        if let Some(s) = m.streaming_capabilities.as_mut() {
            f(s);
        }
    }
}

fn parse_device_service_capabilities(resp: &str) -> Result<DeviceServiceCapabilities, ClientError> {
    let mut out = DeviceServiceCapabilities::default();
    walk_local(resp, "GetServiceCapabilitiesResponse", |step| {
        if let Step::Start { path, attrs } = step {
            if tail_is(path, &["Capabilities", "Network"]) {
                out.network = NetworkCapabilities {
                    ip_filter: xml_bool(attr_get(attrs, "IPFilter").unwrap_or("")),
                    zero_configuration: xml_bool(
                        attr_get(attrs, "ZeroConfiguration").unwrap_or(""),
                    ),
                    ip_version6: xml_bool(attr_get(attrs, "IPVersion6").unwrap_or("")),
                    dyn_dns: xml_bool(attr_get(attrs, "DynDNS").unwrap_or("")),
                };
            } else if tail_is(path, &["Capabilities", "Security"]) {
                out.security = SecurityCapabilities {
                    tls11: xml_bool(attr_get(attrs, "TLS1.1").unwrap_or("")),
                    tls12: xml_bool(attr_get(attrs, "TLS1.2").unwrap_or("")),
                    onboard_key_generation: xml_bool(
                        attr_get(attrs, "OnboardKeyGeneration").unwrap_or(""),
                    ),
                    access_policy_config: xml_bool(
                        attr_get(attrs, "AccessPolicyConfig").unwrap_or(""),
                    ),
                    ..SecurityCapabilities::default()
                };
            } else if tail_is(path, &["Capabilities", "System"]) {
                out.system = SystemCapabilities {
                    discovery_resolve: xml_bool(attr_get(attrs, "DiscoveryResolve").unwrap_or("")),
                    discovery_bye: xml_bool(attr_get(attrs, "DiscoveryBye").unwrap_or("")),
                    remote_discovery: xml_bool(attr_get(attrs, "RemoteDiscovery").unwrap_or("")),
                    system_backup: xml_bool(attr_get(attrs, "SystemBackup").unwrap_or("")),
                    system_logging: xml_bool(attr_get(attrs, "SystemLogging").unwrap_or("")),
                    firmware_upgrade: xml_bool(attr_get(attrs, "FirmwareUpgrade").unwrap_or("")),
                    ..SystemCapabilities::default()
                };
            }
        }
        Ok(())
    })?;
    Ok(out)
}

fn parse_network_protocols(resp: &str) -> Result<Vec<NetworkProtocol>, ClientError> {
    let mut out: Vec<NetworkProtocol> = Vec::new();
    walk_local(resp, "GetNetworkProtocolsResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["NetworkProtocols"]) {
                out.push(NetworkProtocol::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if let Some(last) = out.last_mut() {
                if tail_is(path, &["NetworkProtocols", "Name"]) {
                    last.name = text.to_string();
                } else if tail_is(path, &["NetworkProtocols", "Enabled"]) {
                    last.enabled = xml_bool(text);
                } else if tail_is(path, &["NetworkProtocols", "Port"]) {
                    last.port.push(xml_int(text));
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_network_gateway(resp: &str) -> Result<NetworkGateway, ClientError> {
    let mut out = NetworkGateway::default();
    walk_local(resp, "GetNetworkDefaultGatewayResponse", |step| {
        if let Step::Text { path, text } = step {
            if tail_is(path, &["NetworkGateway", "IPv4Address"]) {
                out.ipv4_address.push(text.to_string());
            } else if tail_is(path, &["NetworkGateway", "IPv6Address"]) {
                out.ipv6_address.push(text.to_string());
            }
        }
        Ok(())
    })?;
    Ok(out)
}

fn parse_geo_location(resp: &str) -> Result<Vec<LocationEntity>, ClientError> {
    let mut out: Vec<LocationEntity> = Vec::new();
    walk_local(resp, "GetGeoLocationResponse", |step| match step {
        Step::Start { path, attrs } => {
            if tail_is(path, &["Location"]) {
                out.push(LocationEntity {
                    lon: attr_get(attrs, "Lon").map(xml_f64).unwrap_or(0.0),
                    lat: attr_get(attrs, "Lat").map(xml_f64).unwrap_or(0.0),
                    elevation: attr_get(attrs, "Elevation").map(xml_f64).unwrap_or(0.0),
                    ..LocationEntity::default()
                });
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if let Some(last) = out.last_mut() {
                if tail_is(path, &["Location", "Entity"]) {
                    last.entity = text.to_string();
                } else if tail_is(path, &["Location", "Token"]) {
                    last.token = text.to_string();
                } else if tail_is(path, &["Location", "Fixed"]) {
                    last.fixed = xml_bool(text);
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_dp_addresses(resp: &str) -> Result<Vec<NetworkHost>, ClientError> {
    let mut out: Vec<NetworkHost> = Vec::new();
    walk_local(resp, "GetDPAddressesResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["DPAddress"]) {
                out.push(NetworkHost::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if let Some(last) = out.last_mut() {
                if tail_is(path, &["DPAddress", "Type"]) {
                    last.kind = text.to_string();
                } else if tail_is(path, &["DPAddress", "IPv4Address"]) {
                    last.ipv4_address = text.to_string();
                } else if tail_is(path, &["DPAddress", "IPv6Address"]) {
                    last.ipv6_address = text.to_string();
                } else if tail_is(path, &["DPAddress", "DNSname"]) {
                    last.dns_name = text.to_string();
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_zero_configuration(resp: &str) -> Result<NetworkZeroConfiguration, ClientError> {
    let mut out = NetworkZeroConfiguration::default();
    walk_local(resp, "GetZeroConfigurationResponse", |step| {
        if let Step::Text { path, text } = step {
            if tail_is(path, &["ZeroConfiguration", "InterfaceToken"]) {
                out.interface_token = text.to_string();
            } else if tail_is(path, &["ZeroConfiguration", "Enabled"]) {
                out.enabled = xml_bool(text);
            } else if tail_is(path, &["ZeroConfiguration", "Addresses"]) {
                out.addresses.push(text.to_string());
            }
        }
        Ok(())
    })?;
    Ok(out)
}

fn parse_dynamic_dns(resp: &str) -> Result<DynamicDnsInformation, ClientError> {
    let mut out = DynamicDnsInformation::default();
    walk_local(resp, "GetDynamicDNSResponse", |step| {
        if let Step::Text { path, text } = step {
            if tail_is(path, &["DynamicDNSInformation", "Type"]) {
                out.kind = text.to_string();
            } else if tail_is(path, &["DynamicDNSInformation", "Name"]) {
                out.name = text.to_string();
            }
        }
        Ok(())
    })?;
    Ok(out)
}

fn parse_system_log(resp: &str) -> Result<SystemLog, ClientError> {
    let mut out = SystemLog::default();
    walk_local(resp, "SystemLogResponse", |step| match step {
        Step::Start { path, attrs } => {
            if tail_is(path, &["SystemLog", "Binary"])
                || tail_is(path, &["SupportInformation", "Binary"])
            {
                out.binary = Some(AttachmentData {
                    content_type: attr_get(attrs, "contentType").unwrap_or("").to_string(),
                });
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if tail_is(path, &["SystemLog", "String"])
                || tail_is(path, &["SupportInformation", "String"])
            {
                out.string = text.to_string();
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_system_backup(resp: &str) -> Result<Vec<BackupFile>, ClientError> {
    let mut out: Vec<BackupFile> = Vec::new();
    walk_local(resp, "GetSystemBackupResponse", |step| match step {
        Step::Start { path, attrs } => {
            if tail_is(path, &["BackupFiles"]) {
                out.push(BackupFile::default());
            } else if tail_is(path, &["BackupFiles", "Data"]) {
                if let Some(last) = out.last_mut() {
                    last.data.content_type =
                        attr_get(attrs, "contentType").unwrap_or("").to_string();
                }
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if tail_is(path, &["BackupFiles", "Name"]) {
                if let Some(last) = out.last_mut() {
                    last.name = text.to_string();
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_system_uris(resp: &str) -> Result<SystemUris, ClientError> {
    let mut log_present = false;
    let mut log_uris: Vec<SystemLogUri> = Vec::new();
    let mut out = SystemUris::default();
    walk_local(resp, "GetSystemUrisResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["SystemLogUris"]) {
                log_present = true;
            } else if tail_is(path, &["SystemLogUris", "SystemLog"]) {
                log_uris.push(SystemLogUri::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if tail_is(path, &["SystemLogUris", "SystemLog", "Type"]) {
                if let Some(last) = log_uris.last_mut() {
                    last.kind = text.to_string();
                }
            } else if tail_is(path, &["SystemLogUris", "SystemLog", "Uri"]) {
                if let Some(last) = log_uris.last_mut() {
                    last.uri = text.to_string();
                }
            } else if tail_is(path, &["SupportInfoUri"]) {
                out.support_info_uri = text.to_string();
            } else if tail_is(path, &["SystemBackupUri"]) {
                out.system_backup_uri = text.to_string();
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    out.log_uris = log_present.then_some(log_uris);
    Ok(out)
}

/// Storage-config item walk accepting BOTH the Go-decoded
/// `StorageConfigurations` wrapper name and the on-wire
/// `StorageConfiguration` (see [`SoapClient::get_storage_configurations`]).
fn parse_storage_configurations(resp: &str) -> Result<Vec<StorageConfiguration>, ClientError> {
    const WRAPPERS: [&str; 2] = ["StorageConfiguration", "StorageConfigurations"];
    let item_start = |path: &[String]| {
        path.last()
            .is_some_and(|leaf| WRAPPERS.contains(&leaf.as_str()))
    };
    // Path helper: does `path` end with [wrapper, rest...]?
    let in_item = |path: &[String], rest: &[&str]| {
        WRAPPERS.iter().any(|w| {
            let mut full: Vec<&str> = rest.to_vec();
            full.insert(0, w);
            tail_is(path, &full)
        })
    };

    let mut out: Vec<StorageConfiguration> = Vec::new();
    walk_local(resp, "StorageConfigurationResponse", |step| match step {
        Step::Start { path, attrs } => {
            if item_start(path) && !in_item(path, &["Data"]) {
                out.push(StorageConfiguration {
                    token: attr_get(attrs, "token").unwrap_or("").to_string(),
                    ..StorageConfiguration::default()
                });
            } else if in_item(path, &["Data", "User"]) {
                if let Some(last) = out.last_mut() {
                    last.data.user = Some(UserCredential::default());
                }
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if let Some(last) = out.last_mut() {
                if in_item(path, &["Data", "LocalPath"]) {
                    last.data.local_path = text.to_string();
                } else if in_item(path, &["Data", "StorageUri"]) {
                    last.data.storage_uri = text.to_string();
                } else if in_item(path, &["Data", "CertPathValidationPolicyID"]) {
                    last.data.cert_path_validation_policy_id = text.to_string();
                } else if in_item(path, &["Data", "User", "UserName"]) {
                    if let Some(user) = last.data.user.as_mut() {
                        user.user_name = text.to_string();
                    }
                } else if in_item(path, &["Data", "User", "Password"]) {
                    if let Some(user) = last.data.user.as_mut() {
                        user.password = text.to_string();
                    }
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_dot11_capabilities(resp: &str) -> Result<Option<Dot11Capabilities>, ClientError> {
    let mut out: Option<Dot11Capabilities> = None;
    walk_local(resp, "GetDot11CapabilitiesResponse", |step| {
        match step {
            Step::Start { path, attrs } => {
                if tail_is(path, &["Capabilities"]) {
                    let caps = Dot11Capabilities {
                        tkip: xml_bool(attr_get(attrs, "TKIP").unwrap_or("")),
                        scan_available_networks: xml_bool(
                            attr_get(attrs, "ScanAvailableNetworks").unwrap_or(""),
                        ),
                        multiple_configuration: xml_bool(
                            attr_get(attrs, "MultipleConfiguration").unwrap_or(""),
                        ),
                        ad_hoc_station_mode: xml_bool(
                            attr_get(attrs, "AdHocStationMode").unwrap_or(""),
                        ),
                        wep: xml_bool(attr_get(attrs, "WEP").unwrap_or("")),
                    };
                    out = Some(caps);
                }
                Ok(())
            }
            Step::Text { path, text } => {
                // Element-shaped spellings too (the Go decode only reads
                // elements; the schema shape is attributes — accept both).
                if let Some(caps) = out.as_mut() {
                    if tail_is(path, &["Capabilities", "TKIP"]) {
                        caps.tkip = xml_bool(text);
                    } else if tail_is(path, &["Capabilities", "ScanAvailableNetworks"]) {
                        caps.scan_available_networks = xml_bool(text);
                    } else if tail_is(path, &["Capabilities", "MultipleConfiguration"]) {
                        caps.multiple_configuration = xml_bool(text);
                    } else if tail_is(path, &["Capabilities", "AdHocStationMode"]) {
                        caps.ad_hoc_station_mode = xml_bool(text);
                    } else if tail_is(path, &["Capabilities", "WEP"]) {
                        caps.wep = xml_bool(text);
                    }
                }
                Ok(())
            }
            Step::End { .. } => Ok(()),
        }
    })?;
    Ok(out)
}

fn parse_dot11_status(resp: &str) -> Result<Option<Dot11Status>, ClientError> {
    let mut out: Option<Dot11Status> = None;
    walk_local(resp, "GetDot11StatusResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["Status"]) {
                out = Some(Dot11Status::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if let Some(status) = out.as_mut() {
                if tail_is(path, &["Status", "SSID"]) {
                    status.ssid = text.to_string();
                } else if tail_is(path, &["Status", "BSSID"]) {
                    status.bssid = text.to_string();
                } else if tail_is(path, &["Status", "PairCipher"]) {
                    status.pair_cipher = text.to_string();
                } else if tail_is(path, &["Status", "GroupCipher"]) {
                    status.group_cipher = text.to_string();
                } else if tail_is(path, &["Status", "SignalStrength"]) {
                    status.signal_strength = text.to_string();
                } else if tail_is(path, &["Status", "ActiveConfigAlias"]) {
                    status.active_config_alias = text.to_string();
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_dot1x_configurations(resp: &str) -> Result<Vec<Dot1XConfiguration>, ClientError> {
    let mut out: Vec<Dot1XConfiguration> = Vec::new();
    walk_local(resp, "Dot1XConfigurationResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["Dot1XConfiguration"]) {
                out.push(Dot1XConfiguration::default());
            } else if tail_is(path, &["Dot1XConfiguration", "EAPMethodConfiguration"]) {
                if let Some(last) = out.last_mut() {
                    last.eap_method_configuration = Some(EapMethodConfiguration::default());
                }
            } else if tail_is(
                path,
                &[
                    "Dot1XConfiguration",
                    "EAPMethodConfiguration",
                    "TLSConfiguration",
                ],
            ) {
                if let Some(last) = out.last_mut() {
                    if let Some(eap) = last.eap_method_configuration.as_mut() {
                        eap.tls_configuration = Some(TlsConfiguration::default());
                    }
                }
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if let Some(last) = out.last_mut() {
                if tail_is(path, &["Dot1XConfiguration", "Dot1XConfigurationToken"]) {
                    last.dot1x_configuration_token = text.to_string();
                } else if tail_is(path, &["Dot1XConfiguration", "Identity"]) {
                    last.identity = text.to_string();
                } else if tail_is(path, &["Dot1XConfiguration", "AnonymousID"]) {
                    last.anonymous_id = text.to_string();
                } else if tail_is(path, &["Dot1XConfiguration", "EAPMethod"]) {
                    last.eap_method = xml_int(text);
                } else if tail_is(path, &["Dot1XConfiguration", "CACertificateID"]) {
                    last.ca_certificate_id.push(text.to_string());
                } else if tail_is(
                    path,
                    &["Dot1XConfiguration", "EAPMethodConfiguration", "Password"],
                ) {
                    if let Some(eap) = last.eap_method_configuration.as_mut() {
                        eap.password = text.to_string();
                    }
                } else if tail_is(
                    path,
                    &[
                        "Dot1XConfiguration",
                        "EAPMethodConfiguration",
                        "TLSConfiguration",
                        "CertificateID",
                    ],
                ) {
                    if let Some(eap) = last.eap_method_configuration.as_mut() {
                        if let Some(tls) = eap.tls_configuration.as_mut() {
                            tls.certificate_id = text.to_string();
                        }
                    }
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_dot11_networks(resp: &str) -> Result<Vec<Dot11AvailableNetworks>, ClientError> {
    let mut out: Vec<Dot11AvailableNetworks> = Vec::new();
    walk_local(
        resp,
        "ScanAvailableDot11NetworksResponse",
        |step| match step {
            Step::Start { path, .. } => {
                if tail_is(path, &["Networks"]) {
                    out.push(Dot11AvailableNetworks::default());
                }
                Ok(())
            }
            Step::Text { path, text } => {
                if let Some(last) = out.last_mut() {
                    if tail_is(path, &["Networks", "SSID"]) {
                        last.ssid = text.to_string();
                    } else if tail_is(path, &["Networks", "BSSID"]) {
                        last.bssid = text.to_string();
                    } else if tail_is(path, &["Networks", "AuthAndMangementSuite"]) {
                        last.auth_and_mangement_suite.push(text.to_string());
                    } else if tail_is(path, &["Networks", "PairCipher"]) {
                        last.pair_cipher.push(text.to_string());
                    } else if tail_is(path, &["Networks", "GroupCipher"]) {
                        last.group_cipher.push(text.to_string());
                    } else if tail_is(path, &["Networks", "SignalStrength"]) {
                        last.signal_strength = text.to_string();
                    }
                }
                Ok(())
            }
            Step::End { .. } => Ok(()),
        },
    )?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Decode fixtures (lifted from the Go twin's *_test.go)
    // -----------------------------------------------------------------

    const DEVINFO_RESP: &str = r#"<GetDeviceInformationResponse><Manufacturer>Acme</Manufacturer><Model>CamX</Model><FirmwareVersion>1.2.3</FirmwareVersion><SerialNumber>SN-1</SerialNumber><HardwareId>HW-1</HardwareId></GetDeviceInformationResponse>"#;

    const CAPS_RESP: &str = r#"<GetCapabilitiesResponse><Capabilities>
        <Analytics><XAddr>http://192.0.2.1/onvif/analytics</XAddr><RuleSupport>true</RuleSupport><AnalyticsModuleSupport>false</AnalyticsModuleSupport></Analytics>
        <Device><XAddr>http://192.0.2.1/onvif/device_service</XAddr>
        <Network><IPFilter>true</IPFilter><ZeroConfiguration>false</ZeroConfiguration><IPVersion6>true</IPVersion6><DynDNS>false</DynDNS></Network>
        <System><DiscoveryResolve>true</DiscoveryResolve><DiscoveryBye>true</DiscoveryBye><RemoteDiscovery>false</RemoteDiscovery><SystemBackup>true</SystemBackup><SystemLogging>false</SystemLogging><FirmwareUpgrade>true</FirmwareUpgrade><SupportedVersions><Major>16</Major><Major>20</Major></SupportedVersions></System>
        <IO><InputConnectors>2</InputConnectors><RelayOutputs>1</RelayOutputs></IO>
        <Security><TLS1.1>false</TLS1.1><TLS1.2>true</TLS1.2><OnboardKeyGeneration>true</OnboardKeyGeneration><AccessPolicyConfig>false</AccessPolicyConfig><X.509Token>true</X.509Token><SAMLToken>false</SAMLToken><KerberosToken>false</KerberosToken><RELToken>false</RELToken></Security>
        </Device>
        <Events><XAddr>http://192.0.2.1/onvif/events</XAddr><WSSubscriptionPolicySupport>true</WSSubscriptionPolicySupport><WSPullPointSupport>true</WSPullPointSupport><WSPausableSubscriptionManagerInterfaceSupport>false</WSPausableSubscriptionManagerInterfaceSupport></Events>
        <Imaging><XAddr>http://192.0.2.1/onvif/imaging</XAddr></Imaging>
        <Media><XAddr>http://192.0.2.1/onvif/media</XAddr><StreamingCapabilities><RTPMulticast>false</RTPMulticast><RTP_TCP>true</RTP_TCP><RTP_RTSP_TCP>true</RTP_RTSP_TCP></StreamingCapabilities></Media>
        <PTZ><XAddr>http://192.0.2.1/onvif/ptz</XAddr></PTZ>
        </Capabilities></GetCapabilitiesResponse>"#;

    const NETIF_RESP: &str = r#"<GetNetworkInterfacesResponse>
        <NetworkInterfaces token="eth0">
            <Enabled>true</Enabled>
            <Info><Name>eth0</Name><HwAddress>00:11:22:33:44:55</HwAddress><MTU>1500</MTU></Info>
            <IPv4><Enabled>true</Enabled><Config>
                <Manual><Address>192.168.1.42</Address><PrefixLength>24</PrefixLength></Manual>
                <DHCP>false</DHCP>
            </Config></IPv4>
        </NetworkInterfaces>
        <NetworkInterfaces token="eth1"><Enabled>false</Enabled></NetworkInterfaces>
        </GetNetworkInterfacesResponse>"#;

    const NTP_RESP: &str = r#"<GetNTPResponse>
        <NTPInformation><FromDHCP>false</FromDHCP>
            <NTPManual><Type>IPv4</Type><IPv4Address>10.0.0.9</IPv4Address></NTPManual>
        </NTPInformation>
    </GetNTPResponse>"#;

    const SERVICES_RESP: &str = r#"<GetServicesResponse>
        <Service><Namespace>http://www.onvif.org/ver10/device/wsdl</Namespace><XAddr>http://192.0.2.1/onvif/device_service</XAddr><Capabilities><Categories>device</Categories></Capabilities><Version><Major>2</Major><Minor>0</Minor></Version></Service>
        <Service><Namespace>http://www.onvif.org/ver10/media/wsdl</Namespace><XAddr>http://192.0.2.1/onvif/media</XAddr><Version><Major>2</Major><Minor>0</Minor></Version></Service>
        </GetServicesResponse>"#;

    #[test]
    fn decodes_device_information() {
        let info = parse_device_information(DEVINFO_RESP).unwrap();
        assert_eq!(info.manufacturer, "Acme");
        assert_eq!(info.serial_number, "SN-1");
        assert_eq!(info.hardware_id, "HW-1");
    }

    #[test]
    fn decodes_capabilities_full_mapping() {
        let caps = parse_capabilities(CAPS_RESP).unwrap();
        let ana = caps.analytics.as_ref().unwrap();
        assert!(ana.rule_support && !ana.analytics_module_support);
        assert_eq!(ana.x_addr, "http://192.0.2.1/onvif/analytics");

        let dev = caps.device.as_ref().unwrap();
        let net = dev.network.as_ref().unwrap();
        assert!(net.ip_filter && net.ip_version6 && !net.zero_configuration);
        let sys = dev.system.as_ref().unwrap();
        assert!(sys.firmware_upgrade && sys.system_backup && !sys.system_logging);
        assert_eq!(sys.supported_versions, vec!["16", "20"]);
        let io = dev.io.as_ref().unwrap();
        assert_eq!((io.input_connectors, io.relay_outputs), (2, 1));
        let sec = dev.security.as_ref().unwrap();
        assert!(sec.tls12 && sec.onboard_key_generation && sec.x509_token);
        assert!(!sec.tls11 && !sec.saml_token && !sec.kerberos_token && !sec.rel_token);

        let ev = caps.events.as_ref().unwrap();
        assert!(ev.ws_pull_point_support && ev.ws_subscription_policy_support);
        assert!(!ev.ws_pausable_subscription_support);

        let media = caps.media.as_ref().unwrap();
        let stream = media.streaming_capabilities.as_ref().unwrap();
        assert!(stream.rtp_tcp && stream.rtp_rtsp_tcp && !stream.rtp_multicast);

        assert!(caps.imaging.is_some() && caps.ptz.is_some());
    }

    #[test]
    fn decodes_capabilities_absent_sections_stay_none() {
        let caps = parse_capabilities("<GetCapabilitiesResponse><Capabilities><Device><XAddr>x</XAddr></Device></Capabilities></GetCapabilitiesResponse>").unwrap();
        assert!(caps.analytics.is_none());
        assert!(caps.device.as_ref().unwrap().network.is_none());
    }

    #[test]
    fn decodes_network_interfaces_with_netmask() {
        let ifaces = parse_network_interfaces(NETIF_RESP).unwrap();
        assert_eq!(ifaces.len(), 2);
        let eth0 = &ifaces[0];
        assert_eq!(eth0.token, "eth0");
        assert!(eth0.enabled);
        assert_eq!(eth0.info.mtu, 1500);
        assert_eq!(eth0.info.hw_address, "00:11:22:33:44:55");
        let ipv4 = eth0.ipv4.as_ref().unwrap();
        assert!(!ipv4.config.dhcp);
        let manual = &ipv4.config.manual[0];
        assert_eq!(manual.address, "192.168.1.42");
        assert_eq!(manual.prefix_length, 24);
        assert_eq!(manual.netmask, "255.255.255.0");
        // Disabled interface reports no IPv4 config (Go behavior).
        assert!(ifaces[1].ipv4.is_none());
    }

    #[test]
    fn decodes_ntp() {
        let ntp = parse_ntp(NTP_RESP).unwrap();
        assert!(!ntp.from_dhcp);
        assert!(ntp.ntp_from_dhcp.is_empty());
        let manual = &ntp.ntp_manual;
        assert_eq!(manual.len(), 1);
        assert_eq!(manual[0].kind, "IPv4");
        assert_eq!(manual[0].ipv4_address, "10.0.0.9");
    }

    #[test]
    fn decodes_services_with_capabilities_capture() {
        let services = parse_services(SERVICES_RESP).unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(
            services[0].namespace,
            "http://www.onvif.org/ver10/device/wsdl"
        );
        assert_eq!(
            services[0].capabilities.as_deref(),
            Some("<Categories>device</Categories>")
        );
        assert!(services[1].capabilities.is_none());
        assert_eq!(services[1].version.major, 2);
        assert_eq!(services[1].version.minor, 0);
    }

    #[test]
    fn decodes_service_capabilities_attributes() {
        let resp = r#"<GetServiceCapabilitiesResponse><Capabilities>
            <Network IPFilter="true" ZeroConfiguration="false" IPVersion6="true" DynDNS="false"></Network>
            <Security TLS1.1="false" TLS1.2="true" OnboardKeyGeneration="true" AccessPolicyConfig="false"></Security>
            <System DiscoveryResolve="true" DiscoveryBye="true" RemoteDiscovery="false" SystemBackup="true" SystemLogging="false" FirmwareUpgrade="true"></System>
            </Capabilities></GetServiceCapabilitiesResponse>"#;
        let caps = parse_device_service_capabilities(resp).unwrap();
        assert!(caps.network.ip_filter && caps.network.ip_version6);
        assert!(caps.security.tls12 && !caps.security.tls11);
        assert!(caps.system.firmware_upgrade && caps.system.system_backup);

        // Self-closing attribute-only element (Empty event path).
        let empty_elem = r#"<GetServiceCapabilitiesResponse><Capabilities><Network IPFilter="true"/></Capabilities></GetServiceCapabilitiesResponse>"#;
        let caps = parse_device_service_capabilities(empty_elem).unwrap();
        assert!(caps.network.ip_filter && !caps.network.dyn_dns);
    }

    #[test]
    fn decodes_small_config_families() {
        let hostname = parse_hostname(
            r#"<GetHostnameResponse><HostnameInformation><FromDHCP>true</FromDHCP><Name>cam1</Name></HostnameInformation></GetHostnameResponse>"#,
        )
        .unwrap();
        assert!(hostname.from_dhcp);
        assert_eq!(hostname.name, "cam1");

        let dns = parse_dns(
            r#"<GetDNSResponse><DNSInformation><FromDHCP>false</FromDHCP><SearchDomain>corp.example</SearchDomain>
            <DNSFromDHCP><Type>IPv4</Type><IPv4Address>10.0.0.1</IPv4Address></DNSFromDHCP>
            <DNSManual><Type>IPv4</Type><IPv4Address>10.1.1.53</IPv4Address></DNSManual>
            </DNSInformation></GetDNSResponse>"#,
        )
        .unwrap();
        assert!(!dns.from_dhcp);
        assert_eq!(dns.search_domain, vec!["corp.example"]);
        assert_eq!(dns.dns_from_dhcp[0].ipv4_address, "10.0.0.1");
        assert_eq!(dns.dns_manual[0].kind, "IPv4");

        let scopes = parse_scopes(
            r#"<GetScopesResponse><Scopes><ScopeDef>Fixed</ScopeDef><ScopeItem>onvif://www.onvif.org/name/cam</ScopeItem></Scopes><Scopes><ScopeDef>Configurable</ScopeDef><ScopeItem>onvif://www.onvif.org/type/video_encoder</ScopeItem></Scopes></GetScopesResponse>"#,
        )
        .unwrap();
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0].scope_def, "Fixed");
        assert_eq!(
            scopes[1].scope_item,
            "onvif://www.onvif.org/type/video_encoder"
        );

        let protocols = parse_network_protocols(
            r#"<GetNetworkProtocolsResponse><NetworkProtocols><Name>HTTP</Name><Enabled>true</Enabled><Port>80</Port><Port>8080</Port></NetworkProtocols><NetworkProtocols><Name>RTSP</Name><Enabled>false</Enabled><Port>554</Port></NetworkProtocols></GetNetworkProtocolsResponse>"#,
        )
        .unwrap();
        assert_eq!(protocols.len(), 2);
        assert_eq!(protocols[0].name, "HTTP");
        assert!(protocols[0].enabled);
        assert_eq!(protocols[0].port, vec![80, 8080]);
        assert_eq!(protocols[1].name, "RTSP");
        assert!(!protocols[1].enabled);

        let gw = parse_network_gateway(
            r#"<GetNetworkDefaultGatewayResponse><NetworkGateway><IPv4Address>192.168.1.1</IPv4Address><IPv4Address>10.0.0.1</IPv4Address></NetworkGateway></GetNetworkDefaultGatewayResponse>"#,
        )
        .unwrap();
        assert_eq!(gw.ipv4_address.len(), 2);

        let geo = parse_geo_location(
            r#"<GetGeoLocationResponse><Location Lon="113.25" Lat="23.13" Elevation="11.5"><Entity>Camera</Entity><Token>t1</Token><Fixed>true</Fixed></Location></GetGeoLocationResponse>"#,
        )
        .unwrap();
        assert_eq!(geo.len(), 1);
        assert_eq!(
            (geo[0].lon, geo[0].lat, geo[0].elevation),
            (113.25, 23.13, 11.5)
        );
        assert!(geo[0].fixed);

        let dp = parse_dp_addresses(
            r#"<GetDPAddressesResponse><DPAddress><Type>DNS</Type><DNSname>prov.example.org</DNSname></DPAddress></GetDPAddressesResponse>"#,
        )
        .unwrap();
        assert_eq!(dp[0].dns_name, "prov.example.org");

        let zero = parse_zero_configuration(
            r#"<GetZeroConfigurationResponse><ZeroConfiguration><InterfaceToken>eth0</InterfaceToken><Enabled>true</Enabled><Addresses>169.254.1.2</Addresses></ZeroConfiguration></GetZeroConfigurationResponse>"#,
        )
        .unwrap();
        assert!(zero.enabled);
        assert_eq!(zero.addresses, vec!["169.254.1.2"]);

        let ddns = parse_dynamic_dns(
            r#"<GetDynamicDNSResponse><DynamicDNSInformation><Type>ClientUpdates</Type><Name>cam.example</Name></DynamicDNSInformation></GetDynamicDNSResponse>"#,
        )
        .unwrap();
        assert_eq!(ddns.kind, "ClientUpdates");
        assert_eq!(ddns.name, "cam.example");
    }

    #[test]
    fn decodes_system_maintenance_families() {
        let log = parse_system_log(
            r#"<GetSystemLogResponse><SystemLog><Binary contentType="text/plain"></Binary><String>boot ok</String></SystemLog></GetSystemLogResponse>"#,
        )
        .unwrap();
        assert_eq!(log.string, "boot ok");
        assert_eq!(log.binary.as_ref().unwrap().content_type, "text/plain");

        let backup = parse_system_backup(
            r#"<GetSystemBackupResponse><BackupFiles><Name>config.tar.gz</Name><Data contentType="application/gzip">aGVsbG8=</Data></BackupFiles></GetSystemBackupResponse>"#,
        )
        .unwrap();
        assert_eq!(backup.len(), 1);
        assert_eq!(backup[0].name, "config.tar.gz");
        assert_eq!(backup[0].data.content_type, "application/gzip");

        let uris = parse_system_uris(
            r#"<GetSystemUrisResponse>
            <SystemLogUris><SystemLog><Type>System</Type><Uri>http://fake/log</Uri></SystemLog></SystemLogUris>
            <SupportInfoUri>http://fake/support</SupportInfoUri>
            <SystemBackupUri>http://fake/backup</SystemBackupUri>
            </GetSystemUrisResponse>"#,
        )
        .unwrap();
        assert_eq!(uris.support_info_uri, "http://fake/support");
        assert_eq!(uris.system_backup_uri, "http://fake/backup");
        let logs = uris.log_uris.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].kind, "System");
        assert_eq!(logs[0].uri, "http://fake/log");

        let support = parse_system_log(
            r#"<GetSystemSupportInformationResponse><SupportInformation><String>blob</String></SupportInformation></GetSystemSupportInformationResponse>"#,
        )
        .unwrap();
        assert_eq!(support.string, "blob");
        assert!(support.binary.is_none());

        assert!(parse_reboot_needed(
            r#"<SetHostnameFromDHCPResponse><RebootNeeded>true</RebootNeeded></SetHostnameFromDHCPResponse>"#
        )
        .unwrap());
    }

    #[test]
    fn decodes_wifi_families() {
        // Attribute shape (schema form; the Go decode misses it, this port
        // accepts both).
        let caps = parse_dot11_capabilities(
            r#"<GetDot11CapabilitiesResponse><Capabilities TKIP="true" ScanAvailableNetworks="true" MultipleConfiguration="false" AdHocStationMode="false" WEP="true"/></GetDot11CapabilitiesResponse>"#,
        )
        .unwrap()
        .unwrap();
        assert!(caps.tkip && caps.scan_available_networks && caps.wep);
        assert!(!caps.multiple_configuration && !caps.ad_hoc_station_mode);

        // Element shape (what the Go twin decodes).
        let caps = parse_dot11_capabilities(
            r#"<GetDot11CapabilitiesResponse><Capabilities><TKIP>false</TKIP><WEP>true</WEP></Capabilities></GetDot11CapabilitiesResponse>"#,
        )
        .unwrap()
        .unwrap();
        assert!(!caps.tkip && caps.wep);
        assert!(parse_dot11_capabilities("<GetDot11CapabilitiesResponse/>")
            .unwrap()
            .is_none());

        let status = parse_dot11_status(
            r#"<GetDot11StatusResponse><Status><SSID>net</SSID><BSSID>aa:bb:cc:dd:ee:ff</BSSID><PairCipher>CCMP</PairCipher><GroupCipher>TKIP</GroupCipher><SignalStrength>Good</SignalStrength><ActiveConfigAlias>conf1</ActiveConfigAlias></Status></GetDot11StatusResponse>"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(status.ssid, "net");
        assert_eq!(status.signal_strength, "Good");

        let dot1x = parse_dot1x_configurations(
            r#"<GetDot1XConfigurationResponse><Dot1XConfiguration><Dot1XConfigurationToken>dot1x-1</Dot1XConfigurationToken><Identity>id</Identity><AnonymousID>anon</AnonymousID><EAPMethod>13</EAPMethod><CACertificateID>ca1</CACertificateID><CACertificateID>ca2</CACertificateID><EAPMethodConfiguration><TLSConfiguration><CertificateID>cert-1</CertificateID></TLSConfiguration><Password>pw</Password></EAPMethodConfiguration></Dot1XConfiguration></GetDot1XConfigurationResponse>"#,
        )
        .unwrap();
        assert_eq!(dot1x.len(), 1);
        assert_eq!(dot1x[0].eap_method, 13);
        assert_eq!(dot1x[0].ca_certificate_id, vec!["ca1", "ca2"]);
        let eap = dot1x[0].eap_method_configuration.as_ref().unwrap();
        assert_eq!(
            eap.tls_configuration.as_ref().unwrap().certificate_id,
            "cert-1"
        );
        assert_eq!(eap.password, "pw");

        let networks = parse_dot11_networks(
            r#"<ScanAvailableDot11NetworksResponse><Networks><SSID>net</SSID><BSSID>aa:bb</BSSID><AuthAndMangementSuite>PSK</AuthAndMangementSuite><PairCipher>CCMP</PairCipher><SignalStrength>Very Bad</SignalStrength></Networks></ScanAvailableDot11NetworksResponse>"#,
        )
        .unwrap();
        assert_eq!(networks[0].auth_and_mangement_suite, vec!["PSK"]);
        assert_eq!(networks[0].signal_strength, "Very Bad");
    }

    #[test]
    fn decodes_storage_configurations_both_names() {
        // Real-device name (StorageConfiguration)…
        let resp = r#"<GetStorageConfigurationsResponse><StorageConfiguration token="storage-001"><Data><LocalPath>/var/media</LocalPath><StorageUri>file:///var/media</StorageUri><User><UserName>recorder</UserName><Password>pw</Password></User></Data></StorageConfiguration></GetStorageConfigurationsResponse>"#;
        let configs = parse_storage_configurations(resp).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].token, "storage-001");
        assert_eq!(configs[0].data.local_path, "/var/media");
        assert_eq!(configs[0].data.storage_uri, "file:///var/media");
        assert_eq!(configs[0].data.user.as_ref().unwrap().user_name, "recorder");
        // …and the Go-decoded wrapper name (StorageConfigurations).
        let go_name = resp
            .replace("<StorageConfiguration ", "<StorageConfigurations ")
            .replace("</StorageConfiguration>", "</StorageConfigurations>");
        assert_eq!(parse_storage_configurations(&go_name).unwrap().len(), 1);
    }

    #[test]
    fn envelope_wrapped_responses_decode() {
        // The live transport hands back the full envelope; the walk must
        // be prefix/wrapper tolerant.
        let wrapped = format!(
            r#"<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body>{DEVINFO_RESP}</Body></Envelope>"#
        );
        let info = parse_device_information(&wrapped).unwrap();
        assert_eq!(info.manufacturer, "Acme");
    }

    // -----------------------------------------------------------------
    // Request goldens
    // -----------------------------------------------------------------

    #[test]
    fn simple_action_envelope() {
        assert_eq!(
            tds_action("GetDeviceInformation"),
            r#"<tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"></tds:GetDeviceInformation>"#
        );
    }

    #[test]
    fn get_capabilities_request() {
        assert_eq!(
            tds_body("GetCapabilities", "<tds:Category>All</tds:Category>"),
            r#"<tds:GetCapabilities xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Category>All</tds:Category></tds:GetCapabilities>"#
        );
    }

    #[test]
    fn get_services_request() {
        assert_eq!(
            tds_body(
                "GetServices",
                &format!("<tds:IncludeCapability>{}</tds:IncludeCapability>", true)
            ),
            r#"<tds:GetServices xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:IncludeCapability>true</tds:IncludeCapability></tds:GetServices>"#
        );
    }

    #[test]
    fn set_dns_request() {
        assert_eq!(
            build_set_dns_request(
                false,
                &["corp.example".to_string()],
                &[IpAddress {
                    kind: "IPv4".into(),
                    ipv4_address: "10.1.1.53".into(),
                    ipv6_address: String::new(),
                }],
            ),
            r#"<tds:SetDNS xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tds:FromDHCP>false</tds:FromDHCP><tds:SearchDomain>corp.example</tds:SearchDomain><tds:DNSManual><tt:Type>IPv4</tt:Type><tt:IPv4Address>10.1.1.53</tt:IPv4Address></tds:DNSManual></tds:SetDNS>"#
        );
        // omitempty: empty search list and empty manual fields drop out.
        assert_eq!(
            build_set_dns_request(true, &[], &[IpAddress::default()]),
            r#"<tds:SetDNS xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tds:FromDHCP>true</tds:FromDHCP><tds:DNSManual><tt:Type></tt:Type></tds:DNSManual></tds:SetDNS>"#
        );
    }

    #[test]
    fn set_network_interfaces_request() {
        let static_cfg = NetworkInterfaceConfig {
            enabled: true,
            ipv4_enabled: true,
            dhcp: false,
            manual_address: "192.168.1.42".into(),
            manual_prefix_length: 24,
        };
        assert_eq!(
            build_set_network_interfaces_request("eth0", &static_cfg),
            r#"<tds:SetNetworkInterfaces xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tds:InterfaceToken>eth0</tds:InterfaceToken><tds:NetworkInterface><tt:Enabled>true</tt:Enabled><tt:IPv4><tt:Enabled>true</tt:Enabled><tt:Config><tt:Manual><tt:Address>192.168.1.42</tt:Address><tt:PrefixLength>24</tt:PrefixLength></tt:Manual><tt:DHCP>false</tt:DHCP></tt:Config></tt:IPv4></tds:NetworkInterface></tds:SetNetworkInterfaces>"#
        );
        let dhcp_cfg = NetworkInterfaceConfig {
            enabled: true,
            ipv4_enabled: true,
            dhcp: true,
            ..NetworkInterfaceConfig::default()
        };
        let body = build_set_network_interfaces_request("eth0", &dhcp_cfg);
        assert!(!body.contains("tt:Manual"));
        assert!(body.contains("<tt:DHCP>true</tt:DHCP>"));
    }

    #[test]
    fn geo_location_request_float_attributes() {
        let loc = LocationEntity {
            entity: "Camera".into(),
            token: "t1".into(),
            fixed: true,
            lon: 113.25,
            lat: 23.13,
            elevation: 11.5,
        };
        assert_eq!(
            build_geo_location_request("SetGeoLocation", &[loc]),
            r#"<tds:SetGeoLocation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Location Lon="113.25" Lat="23.13" Elevation="11.5"><Entity>Camera</Entity><Token>t1</Token><Fixed>true</Fixed></tds:Location></tds:SetGeoLocation>"#
        );
    }

    #[test]
    fn set_dp_addresses_request_untagged_children() {
        let host = NetworkHost {
            kind: "IPv4".into(),
            ipv4_address: "10.0.0.9".into(),
            ..NetworkHost::default()
        };
        assert_eq!(
            build_set_dp_addresses_request(&[host]),
            r#"<tds:SetDPAddresses xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:DPAddress><Type>IPv4</Type><IPv4Address>10.0.0.9</IPv4Address><IPv6Address></IPv6Address><DNSname></DNSname></tds:DPAddress></tds:SetDPAddresses>"#
        );
    }

    #[test]
    fn set_network_protocols_request() {
        let proto = NetworkProtocol {
            name: "HTTP".into(),
            enabled: true,
            port: vec![80, 8080],
        };
        assert_eq!(
            build_set_network_protocols_request(&[proto]),
            r#"<tds:SetNetworkProtocols xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:NetworkProtocols><tds:Name>HTTP</tds:Name><tds:Enabled>true</tds:Enabled><tds:Port>80</tds:Port><tds:Port>8080</tds:Port></tds:NetworkProtocols></tds:SetNetworkProtocols>"#
        );
    }

    #[test]
    fn restore_system_request_content_type_only() {
        let file = BackupFile {
            name: "config.tar.gz".into(),
            data: AttachmentData {
                content_type: "application/gzip".into(),
            },
        };
        assert_eq!(
            build_restore_system_request(&[file]),
            r#"<tds:RestoreSystem xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:BackupFiles><tds:Name>config.tar.gz</tds:Name><tds:Data contentType="application/gzip"></tds:Data></tds:BackupFiles></tds:RestoreSystem>"#
        );
    }

    #[test]
    fn storage_configuration_requests() {
        let config = StorageConfiguration {
            token: "storage-001".into(),
            data: StorageConfigurationData {
                local_path: "/var/media".into(),
                storage_uri: "file:///var/media".into(),
                user: Some(UserCredential {
                    user_name: "recorder".into(),
                    password: "pw".into(),
                }),
                cert_path_validation_policy_id: String::new(),
            },
        };
        assert_eq!(
            build_create_storage_configuration_request(&config),
            r#"<tds:CreateStorageConfiguration xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:StorageConfiguration><tds:LocalPath>/var/media</tds:LocalPath><tds:StorageUri>file:///var/media</tds:StorageUri><tds:User><tds:UserName>recorder</tds:UserName><tds:Password>pw</tds:Password></tds:User></tds:StorageConfiguration></tds:CreateStorageConfiguration>"#
        );
        assert_eq!(
            build_set_storage_configuration_request(&config),
            r#"<tds:SetStorageConfiguration xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:StorageConfiguration token="storage-001"><tds:Data><tds:LocalPath>/var/media</tds:LocalPath><tds:StorageUri>file:///var/media</tds:StorageUri><tds:User><tds:UserName>recorder</tds:UserName><tds:Password>pw</tds:Password></tds:User></tds:Data></tds:StorageConfiguration></tds:SetStorageConfiguration>"#
        );
        // omitempty: empty data children drop out entirely.
        let empty = StorageConfiguration::default();
        assert_eq!(
            build_create_storage_configuration_request(&empty),
            r#"<tds:CreateStorageConfiguration xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:StorageConfiguration></tds:StorageConfiguration></tds:CreateStorageConfiguration>"#
        );
    }

    #[test]
    fn dot1x_configuration_request_untagged_children() {
        let config = Dot1XConfiguration {
            dot1x_configuration_token: "dot1x-1".into(),
            identity: "id".into(),
            anonymous_id: "anon".into(),
            eap_method: 13,
            ca_certificate_id: vec!["ca1".into()],
            eap_method_configuration: Some(EapMethodConfiguration {
                tls_configuration: Some(TlsConfiguration {
                    certificate_id: "cert-1".into(),
                }),
                password: "pw".into(),
            }),
        };
        assert_eq!(
            build_dot1x_configuration_inner(&config),
            r#"<Dot1XConfigurationToken>dot1x-1</Dot1XConfigurationToken><Identity>id</Identity><AnonymousID>anon</AnonymousID><EAPMethod>13</EAPMethod><CACertificateID>ca1</CACertificateID><EAPMethodConfiguration><TLSConfiguration><CertificateID>cert-1</CertificateID></TLSConfiguration><Password>pw</Password></EAPMethodConfiguration>"#
        );
        // Zero-value config still emits the four scalar fields.
        assert_eq!(
            build_dot1x_configuration_inner(&Dot1XConfiguration::default()),
            r#"<Dot1XConfigurationToken></Dot1XConfigurationToken><Identity></Identity><AnonymousID></AnonymousID><EAPMethod>0</EAPMethod>"#
        );
    }

    #[test]
    fn netmask_conversion_table() {
        assert_eq!(netmask_from_prefix_length(0), "0.0.0.0");
        assert_eq!(netmask_from_prefix_length(8), "255.0.0.0");
        assert_eq!(netmask_from_prefix_length(24), "255.255.255.0");
        assert_eq!(netmask_from_prefix_length(32), "255.255.255.255");
        assert_eq!(netmask_from_prefix_length(-1), "");
        assert_eq!(netmask_from_prefix_length(33), "");
    }

    #[test]
    fn scalar_decode_helpers() {
        assert!(xml_bool("true") && xml_bool("1") && xml_bool("T") && xml_bool("TRUE"));
        assert!(!xml_bool("false") && !xml_bool("") && !xml_bool("yes"));
        assert_eq!(xml_int("42"), 42);
        assert_eq!(xml_int("nope"), 0);
        assert_eq!(b64_bytes("QUJD").unwrap(), b"ABC");
        assert!(b64_bytes("!!").is_err());
    }
}
