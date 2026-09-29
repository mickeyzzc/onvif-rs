// ---------------------------------------------------------------------------
// ONVIF Device Service Handlers
// ---------------------------------------------------------------------------
//
// Implements GetSystemDateAndTime, GetDeviceInformation, GetCapabilities,
// GetServices, and GetScopes as OnvifActionHandler trait objects.

use std::sync::Arc;

use async_trait::async_trait;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;

use crate::config::DeviceConfig;
use crate::namespaces::{
    DEVICE_SERVICE, EVENTS_SERVICE, IMAGING_SERVICE, MEDIA_SERVICE, PTZ_SERVICE, SCHEMAS,
};
use crate::server::OnvifActionHandler;
use crate::types::{resolve_server_ip, serialize_soap_response, OnvifError, RequestInfo};

// ---------------------------------------------------------------------------
// DeviceServiceHandlers — config holder with XML body builders
// ---------------------------------------------------------------------------

/// Holds device-level configuration needed by all device service handlers.
pub struct DeviceServiceHandlers {
    device_config: DeviceConfig,
    onvif_port: u16,
    device_ip: String,
    /// Advertise the Media service in GetCapabilities/GetServices. Default
    /// `true` (the historical advertisement); hosts that do not register the
    /// media handlers turn it off so the advertisement matches the routes
    /// actually served (issue #47).
    support_media: bool,
    /// Advertise the PTZ service (see [`Self::with_media_support`]).
    support_ptz: bool,
    /// Advertise the Imaging service (see [`Self::with_media_support`]).
    support_imaging: bool,
    /// Advertise the Events service in GetCapabilities/GetServices (the
    /// host must also serve the routes — `OnvifServer::enable_events` on the
    /// SOAP side; parity with onvif-go's SupportEvents flagging both).
    support_events: bool,
    /// IP address filter seam (issue #54): the shared store behind the
    /// Get/Set/Add/RemoveIPAddressFilter ops. `None` (default) — Get
    /// answers a disabled filter, mutations are refused. Wire the same
    /// state into [`crate::server::OnvifServer::with_ip_filter`] for
    /// per-connection enforcement.
    ip_filter: Option<IpFilterState>,
    /// AccessPolicy seam (issue #54): opaque Base64-backed policy blob
    /// (Get/SetAccessPolicy). `None` (default) — Get answers an empty
    /// policy, Set is refused.
    access_policy: Option<AccessPolicyState>,
}

impl DeviceServiceHandlers {
    /// Fail-fast on an unvalidated identity (issue #20): a config left at
    /// the neutral placeholders is a configuration error, not a silent
    /// "unknown" device on the network.
    pub fn new(
        device_config: DeviceConfig,
        onvif_port: u16,
        device_ip: String,
    ) -> Result<Self, OnvifError> {
        device_config
            .validate()
            .map_err(OnvifError::InvalidConfig)?;
        Ok(Self {
            device_config,
            onvif_port,
            device_ip,
            support_media: true,
            support_ptz: true,
            support_imaging: true,
            support_events: false,
            ip_filter: None,
            access_policy: None,
        })
    }

    /// Advertise (or omit) the Media service in GetCapabilities /
    /// GetServices. Set to `false` when the host does not register the
    /// media action handlers, so clients discover only what is really
    /// served. Default `true` — the historical advertisement.
    #[must_use]
    pub fn with_media_support(mut self, support: bool) -> Self {
        self.support_media = support;
        self
    }

    /// Advertise (or omit) the PTZ service — see
    /// [`Self::with_media_support`]. Default `true`.
    #[must_use]
    pub fn with_ptz_support(mut self, support: bool) -> Self {
        self.support_ptz = support;
        self
    }

    /// Advertise (or omit) the Imaging service — see
    /// [`Self::with_media_support`]. Default `true`.
    #[must_use]
    pub fn with_imaging_support(mut self, support: bool) -> Self {
        self.support_imaging = support;
        self
    }

    /// Advertise (or omit) the Events service in GetCapabilities /
    /// GetServices. Set together with `OnvifServer::enable_events` so the
    /// advertisement and the served routes agree — with
    /// `WSPullPointSupport = true`, because the pull-point service really
    /// serves Create/Pull/Renew/Unsubscribe on the advertised XAddr.
    #[must_use]
    pub fn with_events_support(mut self, support: bool) -> Self {
        self.support_events = support;
        self
    }

    fn base_url(&self, server_ip: &str) -> String {
        let ip = resolve_server_ip(server_ip, &self.device_ip);
        format!("http://{ip}:{}/onvif", self.onvif_port)
    }
}

// ---------------------------------------------------------------------------
// DeviceHandler — dispatches to the right body builder and wraps in SOAP
// ---------------------------------------------------------------------------

/// Wraps `Arc<DeviceServiceHandlers>` and dispatches `handle()` to the
/// appropriate response builder based on the action element in `body`.
pub struct DeviceHandler(pub Arc<DeviceServiceHandlers>);

#[async_trait]
impl OnvifActionHandler for DeviceHandler {
    async fn handle(&self, body: &str, info: &RequestInfo) -> Result<String, OnvifError> {
        let svc = &self.0;
        let fragment = if body.contains("GetSystemDateAndTime") {
            svc.build_system_date_time()
        } else if body.contains("GetDeviceInformation") {
            svc.build_device_information()
        } else if body.contains("GetCapabilities") {
            svc.build_capabilities(&info.server_ip)
        } else if body.contains("GetServices") {
            svc.build_services(&info.server_ip)
        } else if body.contains("GetScopes") {
            svc.build_scopes()
        } else if body.contains("SystemReboot") {
            svc.build_system_reboot()
        } else if body.contains("GetIPAddressFilter") {
            svc.sec_build_get_ip_address_filter()
        } else if body.contains("SetIPAddressFilter") {
            svc.sec_apply_set_ip_address_filter(body)?
        } else if body.contains("AddIPAddressFilter") {
            svc.sec_apply_add_ip_address_filter(body)?
        } else if body.contains("RemoveIPAddressFilter") {
            svc.sec_apply_remove_ip_address_filter(body)?
        } else if body.contains("GetAccessPolicy") {
            svc.sec_build_get_access_policy()
        } else if body.contains("SetAccessPolicy") {
            svc.sec_apply_set_access_policy(body)?
        } else {
            return Err(OnvifError::ActionNotSupported(
                "unknown device action".into(),
            ));
        };
        Ok(serialize_soap_response(&fragment))
    }
}

// ---------------------------------------------------------------------------
// XML response body builders (return just the <tds:GetXxxResponse> fragment)
// ---------------------------------------------------------------------------

impl DeviceServiceHandlers {
    /// Build `<tds:GetSystemDateAndTimeResponse>` body.
    fn build_system_date_time(&self) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs();
        let (year, month, day, hour, minute, second) = secs_to_utc(secs);

        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

        let mut root = BytesStart::new("tds:GetSystemDateAndTimeResponse");
        root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
        root.push_attribute(("xmlns:tt", SCHEMAS));
        w.write_event(Event::Start(root)).unwrap_or_default();

        w.write_event(Event::Start(BytesStart::new("tds:SystemDateAndTime")))
            .unwrap_or_default();
        write_text(&mut w, "tt:DateTimeType", "Manual");
        write_text(&mut w, "tt:DaylightSavings", "false");
        open_close(&mut w, "tt:TimeZone", |w| {
            write_text(w, "tt:TZ", "UTC");
        });
        open_close(&mut w, "tt:UTCDateTime", |w| {
            open_close(w, "tt:Time", |w| {
                write_int(w, "tt:Hour", hour);
                write_int(w, "tt:Minute", minute);
                write_int(w, "tt:Second", second);
            });
            open_close(w, "tt:Date", |w| {
                write_int(w, "tt:Year", year);
                write_int(w, "tt:Month", month);
                write_int(w, "tt:Day", day);
            });
        });
        w.write_event(Event::End(BytesEnd::new("tds:SystemDateAndTime")))
            .unwrap_or_default();
        w.write_event(Event::End(BytesEnd::new(
            "tds:GetSystemDateAndTimeResponse",
        )))
        .unwrap_or_default();

        String::from_utf8(w.into_inner()).unwrap_or_default()
    }

    /// Build `<tds:GetDeviceInformationResponse>` body.
    fn build_device_information(&self) -> String {
        let cfg = &self.device_config;
        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

        let mut root = BytesStart::new("tds:GetDeviceInformationResponse");
        root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
        w.write_event(Event::Start(root)).unwrap_or_default();

        write_text(&mut w, "tds:Manufacturer", &cfg.manufacturer);
        write_text(&mut w, "tds:Model", &cfg.model);
        write_text(&mut w, "tds:FirmwareVersion", &cfg.firmware);
        write_text(&mut w, "tds:SerialNumber", &cfg.serial_number);
        write_text(&mut w, "tds:HardwareId", &cfg.hardware_id);

        w.write_event(Event::End(BytesEnd::new(
            "tds:GetDeviceInformationResponse",
        )))
        .unwrap_or_default();

        String::from_utf8(w.into_inner()).unwrap_or_default()
    }

    /// Build `<tds:GetCapabilitiesResponse>` body.
    fn build_capabilities(&self, server_ip: &str) -> String {
        let base = self.base_url(server_ip);
        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

        let mut root = BytesStart::new("tds:GetCapabilitiesResponse");
        root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
        root.push_attribute(("xmlns:tt", SCHEMAS));
        w.write_event(Event::Start(root)).unwrap_or_default();

        w.write_event(Event::Start(BytesStart::new("tds:Capabilities")))
            .unwrap_or_default();
        capability_xaddr(&mut w, "tt:Device", &base, "/device_service");
        if self.support_media {
            capability_xaddr(&mut w, "tt:Media", &base, "/media_service");
        }
        if self.support_ptz {
            capability_xaddr(&mut w, "tt:PTZ", &base, "/ptz_service");
        }
        if self.support_imaging {
            capability_xaddr(&mut w, "tt:Imaging", &base, "/device_service");
        }
        if self.support_events {
            // WSPullPointSupport=true: the events service really serves
            // CreatePullPointSubscription/PullMessages/Renew/Unsubscribe on
            // the advertised XAddr (parity with onvif-go, including its
            // spec-divergent WSPausableSubscriptionManagerInterfaceSupport
            // attribute name — twin wire parity wins over the spec text).
            let mut events = BytesStart::new("tt:Events");
            events.push_attribute(("WSSubscriptionPolicySupport", "false"));
            events.push_attribute(("WSPullPointSupport", "true"));
            events.push_attribute(("WSPausableSubscriptionManagerInterfaceSupport", "false"));
            w.write_event(Event::Start(events)).unwrap_or_default();
            write_text(&mut w, "tt:XAddr", &format!("{base}/events_service"));
            w.write_event(Event::End(BytesEnd::new("tt:Events")))
                .unwrap_or_default();
        }
        w.write_event(Event::End(BytesEnd::new("tds:Capabilities")))
            .unwrap_or_default();

        w.write_event(Event::End(BytesEnd::new("tds:GetCapabilitiesResponse")))
            .unwrap_or_default();
        String::from_utf8(w.into_inner()).unwrap_or_default()
    }

    /// Build `<tds:GetServicesResponse>` body.
    ///
    /// Enumerates the services this host actually serves (issue #47):
    /// Device always; Media/PTZ/Imaging per their support flags; Events
    /// only after [`Self::with_events_support`]. XAddr paths match the
    /// GetCapabilities advertisement.
    fn build_services(&self, server_ip: &str) -> String {
        let base = self.base_url(server_ip);
        let mut services: Vec<(&str, &str)> = vec![(DEVICE_SERVICE, "/device_service")];
        if self.support_media {
            services.push((MEDIA_SERVICE, "/media_service"));
        }
        if self.support_ptz {
            services.push((PTZ_SERVICE, "/ptz_service"));
        }
        if self.support_imaging {
            services.push((IMAGING_SERVICE, "/device_service"));
        }
        if self.support_events {
            services.push((EVENTS_SERVICE, "/events_service"));
        }

        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

        let mut root = BytesStart::new("tds:GetServicesResponse");
        root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
        root.push_attribute(("xmlns:tt", SCHEMAS));
        w.write_event(Event::Start(root)).unwrap_or_default();

        w.write_event(Event::Start(BytesStart::new("tds:Services")))
            .unwrap_or_default();

        for (ns, path) in services {
            w.write_event(Event::Start(BytesStart::new("tds:Service")))
                .unwrap_or_default();
            write_text(&mut w, "tds:Namespace", ns);
            write_text(&mut w, "tds:XAddr", &format!("{}{}", base, path));
            open_close(&mut w, "tds:Version", |w| {
                write_int(w, "tt:Major", 1);
                write_int(w, "tt:Minor", 0);
            });
            w.write_event(Event::End(BytesEnd::new("tds:Service")))
                .unwrap_or_default();
        }

        w.write_event(Event::End(BytesEnd::new("tds:Services")))
            .unwrap_or_default();
        w.write_event(Event::End(BytesEnd::new("tds:GetServicesResponse")))
            .unwrap_or_default();
        String::from_utf8(w.into_inner()).unwrap_or_default()
    }

    /// Build `<tds:GetScopesResponse>` body.
    fn build_scopes(&self) -> String {
        let cfg = &self.device_config;
        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

        let mut root = BytesStart::new("tds:GetScopesResponse");
        root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
        root.push_attribute(("xmlns:tt", SCHEMAS));
        w.write_event(Event::Start(root)).unwrap_or_default();

        write_text(
            &mut w,
            "tt:ScopeItem",
            "onvif://www.onvif.org/type/video_encoder",
        );
        write_text(
            &mut w,
            "tt:ScopeItem",
            &format!("onvif://www.onvif.org/name/{}", cfg.name),
        );
        write_text(
            &mut w,
            "tt:ScopeItem",
            &format!("onvif://www.onvif.org/hardware/{}", cfg.hardware_id),
        );

        w.write_event(Event::End(BytesEnd::new("tds:GetScopesResponse")))
            .unwrap_or_default();
        String::from_utf8(w.into_inner()).unwrap_or_default()
    }

    /// Build `<tds:SystemRebootResponse>` body.
    ///
    /// **Protocol answer only** — this library never performs the reboot
    /// side effect. The ONVIF Device service defines SystemReboot as
    /// "reboot the device"; here it is a byte-stable wire answer (WSDL
    /// `SystemRebootResponse/Message`, parity with onvif-go's
    /// `HandleSystemReboot` returning "Device rebooting"). Hosts that want
    /// a real reboot observe the action in their handler wrapping layer;
    /// keep this action authenticated (it is not in the anonymous set by
    /// default), matching onvif-go which treats SystemReboot as a
    /// write-style credential-protected action.
    fn build_system_reboot(&self) -> String {
        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

        let mut root = BytesStart::new("tds:SystemRebootResponse");
        root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
        w.write_event(Event::Start(root)).unwrap_or_default();

        write_text(&mut w, "tds:Message", "Device rebooting");

        w.write_event(Event::End(BytesEnd::new("tds:SystemRebootResponse")))
            .unwrap_or_default();

        String::from_utf8(w.into_inner()).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn write_text(w: &mut Writer<Vec<u8>>, name: &str, text: &str) {
    w.write_event(Event::Start(BytesStart::new(name)))
        .unwrap_or_default();
    w.write_event(Event::Text(BytesText::new(text)))
        .unwrap_or_default();
    w.write_event(Event::End(BytesEnd::new(name)))
        .unwrap_or_default();
}

fn write_int(w: &mut Writer<Vec<u8>>, name: &str, value: i32) {
    write_text(w, name, &value.to_string());
}

/// Open an element, call `f` to write children, close it.
fn open_close<F>(w: &mut Writer<Vec<u8>>, name: &str, f: F)
where
    F: FnOnce(&mut Writer<Vec<u8>>),
{
    w.write_event(Event::Start(BytesStart::new(name)))
        .unwrap_or_default();
    f(w);
    w.write_event(Event::End(BytesEnd::new(name)))
        .unwrap_or_default();
}

/// Write `<tt:XXX><tt:XAddr>base/path</tt:XAddr></tt:XXX>`.
fn capability_xaddr(w: &mut Writer<Vec<u8>>, tag: &str, base: &str, path: &str) {
    open_close(w, tag, |w| {
        write_text(w, "tt:XAddr", &format!("{}{}", base, path));
    });
}

/// Convert seconds since UNIX_EPOCH to UTC date/time fields.
/// Valid for years 1970–2100. Crate-visible: the events service reuses it
/// for RFC3339 timestamps.
pub(crate) fn secs_to_utc(secs: u64) -> (i32, i32, i32, i32, i32, i32) {
    let days = secs / 86400;
    let rem = secs % 86400;
    let hour = (rem / 3600) as i32;
    let minute = ((rem % 3600) / 60) as i32;
    let second = (rem % 60) as i32;

    let mut y: i64 = 1970;
    let mut d = days as i64;
    loop {
        let diy = if is_leap(y) { 366 } else { 365 };
        if d < diy {
            break;
        }
        d -= diy;
        y += 1;
    }

    let mdays = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1i32;
    for &md in &mdays {
        if d < md as i64 {
            break;
        }
        d -= md as i64;
        month += 1;
    }
    (y as i32, month, (d + 1) as i32, hour, minute, second)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ---------------------------------------------------------------------------
// Security ops (issue #54): IP address filter + AccessPolicy
//
// Self-contained section — `sec_`-prefixed helpers only, nothing shared
// with the response builders above, so the section stays merge-friendly
// against independent changes to the rest of this file.
//
// 802.1X (GetDot1XConfiguration/SetDot1XConfiguration &c.) is
// deliberately NOT implemented: an EAP supplicant is host
// infrastructure, not SOAP device protocol — those actions stay
// unregistered and answer the generic unsupported-action fault.
// ---------------------------------------------------------------------------

/// Mode of the ONVIF IP address filter (`tt:IPAddressFilter/Type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFilterMode {
    Allow,
    Deny,
}

impl IpFilterMode {
    fn as_wire(&self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::Deny => "Deny",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        match s.trim() {
            "Allow" => Some(Self::Allow),
            "Deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

/// One IPv4 filter entry: dotted-quad network address + prefix length
/// 0–32 (`tt:PrefixedIPv4Address` on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpEntry {
    pub ipv4: String,
    pub prefix_len: u8,
}

/// The ONVIF IP address filter state — host-mutable config seam shared
/// between the SOAP ops and [`crate::server::OnvifServer::with_ip_filter`].
/// `enabled = false` filters nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFilter {
    pub enabled: bool,
    pub mode: IpFilterMode,
    pub entries: Vec<IpEntry>,
}

impl Default for IpFilter {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: IpFilterMode::Allow,
            entries: Vec::new(),
        }
    }
}

impl IpFilter {
    /// A filter that admits everyone (`enabled = false`).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Whether a client IP passes the filter.
    ///
    /// Unparseable or IPv6 client addresses fail OPEN (allowed): a
    /// malformed peer address must not brick the SOAP listener — the
    /// caller logs a warning. Entries whose address does not parse
    /// never match. Enforcement notes: prefix 0 matches everything,
    /// 32 matches one host; Allow mode admits only matching peers,
    /// Deny mode refuses only matching peers.
    pub fn allows_client_ip(&self, client_ip: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let Some(ip) = client_ip.trim().parse::<std::net::Ipv4Addr>().ok() else {
            // IPv6 peer or unparseable address: fail open (documented) —
            // a malformed peer address must not brick the listener.
            log::warn!("onvif: IP filter cannot parse client address {client_ip:?} — allowing");
            return true;
        };
        let client = u32::from(ip);
        let matched = self
            .entries
            .iter()
            .any(|e| match e.ipv4.parse::<std::net::Ipv4Addr>() {
                Ok(net) => sec_ipv4_prefix_matches(client, u32::from(net), e.prefix_len),
                Err(_) => false, // malformed stored entry never matches
            });
        match self.mode {
            IpFilterMode::Allow => matched,
            IpFilterMode::Deny => !matched,
        }
    }
}

/// Shared IP filter state (install via
/// [`DeviceServiceHandlers::with_ip_filter`]).
pub type IpFilterState = Arc<std::sync::RwLock<IpFilter>>;
/// Shared AccessPolicy blob state (install via
/// [`DeviceServiceHandlers::with_access_policy`]). The library stores
/// and returns the bytes verbatim — interpreting (enforcing) the policy
/// is host-side.
pub type AccessPolicyState = Arc<std::sync::RwLock<Vec<u8>>>;

/// Poison-tolerant read guard (the established crate pattern, kept
/// local to this section under a `sec_` name).
fn sec_read<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Poison-tolerant write guard.
fn sec_write<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Whether two IPv4 addresses (as `u32`) share the first `prefix` bits.
fn sec_ipv4_prefix_matches(a: u32, b: u32, prefix: u8) -> bool {
    if prefix > 32 {
        return false;
    }
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    (a & mask) == (b & mask)
}

impl DeviceServiceHandlers {
    /// Install the IP filter config seam (issue #54). Wire the SAME
    /// state into [`crate::server::OnvifServer::with_ip_filter`] so the
    /// SOAP Get/Set/Add/RemoveIPAddressFilter ops and the
    /// per-connection gate share one store.
    #[must_use]
    pub fn with_ip_filter(mut self, state: IpFilterState) -> Self {
        self.ip_filter = Some(state);
        self
    }

    /// The installed IP filter state, when present (hand this to
    /// [`crate::server::OnvifServer::with_ip_filter`]).
    #[must_use]
    pub fn ip_filter_state(&self) -> Option<IpFilterState> {
        self.ip_filter.clone()
    }

    /// Install the AccessPolicy config seam (issue #54): Get/Set carry
    /// an opaque Base64 blob; this library does not interpret it.
    #[must_use]
    pub fn with_access_policy(mut self, state: AccessPolicyState) -> Self {
        self.access_policy = Some(state);
        self
    }

    /// The installed AccessPolicy state, when present.
    #[must_use]
    pub fn access_policy_state(&self) -> Option<AccessPolicyState> {
        self.access_policy.clone()
    }

    /// `<tds:GetIPAddressFilterResponse>` — the current filter; without
    /// an installed state, a disabled (allow-all) filter.
    fn sec_build_get_ip_address_filter(&self) -> String {
        let filter = match &self.ip_filter {
            Some(state) => sec_read(state).clone(),
            None => IpFilter::disabled(),
        };
        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);
        let mut root = BytesStart::new("tds:GetIPAddressFilterResponse");
        root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
        root.push_attribute(("xmlns:tt", SCHEMAS));
        w.write_event(Event::Start(root)).unwrap_or_default();
        w.write_event(Event::Start(BytesStart::new("tds:IPAddressFilter")))
            .unwrap_or_default();
        sec_write_text(&mut w, "tt:Type", filter.mode.as_wire());
        for e in &filter.entries {
            sec_write_entry(&mut w, e);
        }
        w.write_event(Event::End(BytesEnd::new("tds:IPAddressFilter")))
            .unwrap_or_default();
        w.write_event(Event::End(BytesEnd::new("tds:GetIPAddressFilterResponse")))
            .unwrap_or_default();
        String::from_utf8(w.into_inner()).unwrap_or_default()
    }

    /// `SetIPAddressFilter` — replace mode + entries wholesale.
    fn sec_apply_set_ip_address_filter(&self, body: &str) -> Result<String, OnvifError> {
        let Some(state) = &self.ip_filter else {
            return Err(OnvifError::SenderFault(
                "IP address filter is not configured on this device".into(),
            ));
        };
        let parsed = sec_parse_ip_filter(body)?;
        let mut f = sec_write(state);
        f.enabled = true;
        f.mode = parsed.mode;
        f.entries = parsed.entries;
        Ok(sec_empty_ack("tds:SetIPAddressFilterResponse"))
    }

    /// `AddIPAddressFilter` — set the mode and append entries not
    /// already present.
    fn sec_apply_add_ip_address_filter(&self, body: &str) -> Result<String, OnvifError> {
        let Some(state) = &self.ip_filter else {
            return Err(OnvifError::SenderFault(
                "IP address filter is not configured on this device".into(),
            ));
        };
        let parsed = sec_parse_ip_filter(body)?;
        let mut f = sec_write(state);
        f.enabled = true;
        f.mode = parsed.mode;
        for e in parsed.entries {
            if !f.entries.contains(&e) {
                f.entries.push(e);
            }
        }
        Ok(sec_empty_ack("tds:AddIPAddressFilterResponse"))
    }

    /// `RemoveIPAddressFilter` — remove entries matching the request
    /// (address + prefix); the mode is kept. Idempotent: removing an
    /// absent entry still acks.
    fn sec_apply_remove_ip_address_filter(&self, body: &str) -> Result<String, OnvifError> {
        let Some(state) = &self.ip_filter else {
            return Err(OnvifError::SenderFault(
                "IP address filter is not configured on this device".into(),
            ));
        };
        let parsed = sec_parse_ip_filter(body)?;
        let mut f = sec_write(state);
        f.entries.retain(|e| !parsed.entries.contains(e));
        Ok(sec_empty_ack("tds:RemoveIPAddressFilterResponse"))
    }

    /// `<tds:GetAccessPolicyResponse>` — the stored policy blob
    /// (Base64), empty when none installed.
    fn sec_build_get_access_policy(&self) -> String {
        use base64::Engine as _;

        let blob = match &self.access_policy {
            Some(state) => sec_read(state).clone(),
            None => Vec::new(),
        };
        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);
        let mut root = BytesStart::new("tds:GetAccessPolicyResponse");
        root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
        root.push_attribute(("xmlns:tt", SCHEMAS));
        w.write_event(Event::Start(root)).unwrap_or_default();
        w.write_event(Event::Start(BytesStart::new("tds:PolicyFile")))
            .unwrap_or_default();
        sec_write_text(&mut w, "tt:Data", &b64);
        w.write_event(Event::End(BytesEnd::new("tds:PolicyFile")))
            .unwrap_or_default();
        w.write_event(Event::End(BytesEnd::new("tds:GetAccessPolicyResponse")))
            .unwrap_or_default();
        String::from_utf8(w.into_inner()).unwrap_or_default()
    }

    /// `SetAccessPolicy` — decode the Base64 PolicyFile/Data into the
    /// store.
    fn sec_apply_set_access_policy(&self, body: &str) -> Result<String, OnvifError> {
        use base64::Engine as _;

        let Some(state) = &self.access_policy else {
            return Err(OnvifError::SenderFault(
                "access policy is not configured on this device".into(),
            ));
        };
        let b64 = sec_extract_policy_data(body).ok_or_else(|| {
            OnvifError::SenderFault("SetAccessPolicy requires a PolicyFile/Data payload".into())
        })?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|_| OnvifError::SenderFault("PolicyFile Data is not valid base64".into()))?;
        *sec_write(state) = bytes;
        Ok(sec_empty_ack("tds:SetAccessPolicyResponse"))
    }
}

/// Serialize one `<tt:Address>`/`<tt:PrefixLength>` pair inside an open
/// `tt:IPv4Address` element.
fn sec_write_entry(w: &mut Writer<Vec<u8>>, entry: &IpEntry) {
    w.write_event(Event::Start(BytesStart::new("tt:IPv4Address")))
        .unwrap_or_default();
    sec_write_text(w, "tt:Address", &entry.ipv4);
    sec_write_text(w, "tt:PrefixLength", &entry.prefix_len.to_string());
    w.write_event(Event::End(BytesEnd::new("tt:IPv4Address")))
        .unwrap_or_default();
}

/// Text-element writer for this section (independent of `write_text`).
fn sec_write_text(w: &mut Writer<Vec<u8>>, name: &str, text: &str) {
    w.write_event(Event::Start(BytesStart::new(name)))
        .unwrap_or_default();
    w.write_event(Event::Text(BytesText::new(text)))
        .unwrap_or_default();
    w.write_event(Event::End(BytesEnd::new(name)))
        .unwrap_or_default();
}

/// An empty (ack-only) `<tds:XxxResponse>` fragment.
fn sec_empty_ack(response_local_name: &str) -> String {
    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);
    let mut root = BytesStart::new(response_local_name);
    root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
    w.write_event(Event::Start(root)).unwrap_or_default();
    w.write_event(Event::End(BytesEnd::new(response_local_name)))
        .unwrap_or_default();
    String::from_utf8(w.into_inner()).unwrap_or_default()
}

/// Local name of a QName (`tt:Address` → `Address`).
fn sec_local_name(name: quick_xml::name::QName<'_>) -> String {
    let qname = std::str::from_utf8(name.as_ref()).unwrap_or("");
    qname.rsplit(':').next().unwrap_or(qname).to_string()
}

/// Parse the `IPAddressFilter` payload of Set/Add/Remove (tolerant of
/// `tt:`-prefixed or default-namespace forms). Requires a valid Type
/// and complete IPv4 entries; IPv6 entries are refused (IPv4-only
/// state, honestly reported rather than silently dropped).
fn sec_parse_ip_filter(body: &str) -> Result<IpFilter, OnvifError> {
    let mut reader = quick_xml::Reader::from_str(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut mode: Option<IpFilterMode> = None;
    let mut entries: Vec<IpEntry> = Vec::new();
    let mut saw_ipv6 = false;
    // State inside one <IPv4Address> element.
    let mut in_v4 = false;
    let mut addr: Option<String> = None;
    let mut plen: Option<u8> = None;
    let mut field = String::new();
    let mut text_acc = crate::types::TextAccumulator::new();

    loop {
        let event = reader.read_event_into(&mut buf);
        match event {
            Ok(Event::Text(e)) => {
                let _ = text_acc.push_text(&e);
            }
            Ok(Event::GeneralRef(e)) => {
                let _ = text_acc.push_ref(&e);
            }
            other => {
                if let Some(text) = text_acc.flush() {
                    if !text.is_empty() {
                        match field.as_str() {
                            "Type" => {
                                if mode.is_none() {
                                    mode = IpFilterMode::from_wire(&text);
                                }
                            }
                            "Address" if in_v4 => addr = Some(text),
                            "PrefixLength" if in_v4 => {
                                plen = text.parse::<u8>().ok().filter(|p| *p <= 32)
                            }
                            _ => {}
                        }
                    }
                }
                match other {
                    Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                        match sec_local_name(e.name()).as_str() {
                            "Type" => field = "Type".into(),
                            "IPv4Address" => {
                                in_v4 = true;
                                addr = None;
                                plen = None;
                                field.clear();
                            }
                            "IPv6Address" => saw_ipv6 = true,
                            "Address" if in_v4 => field = "Address".into(),
                            "PrefixLength" if in_v4 => field = "PrefixLength".into(),
                            _ => field.clear(),
                        }
                    }
                    Ok(Event::End(e)) => {
                        let local = sec_local_name(e.name());
                        if local == "IPv4Address" && in_v4 {
                            let a = addr
                                .as_deref()
                                .and_then(|a| a.parse::<std::net::Ipv4Addr>().ok())
                                .map(|ip| ip.to_string());
                            match (a, plen) {
                                (Some(address), Some(prefix_len)) => {
                                    entries.push(IpEntry {
                                        ipv4: address,
                                        prefix_len,
                                    });
                                }
                                (None, _) => {
                                    return Err(OnvifError::SenderFault(
                                        "IPv4 filter entry requires a valid dotted-quad Address"
                                            .into(),
                                    ));
                                }
                                (_, None) => {
                                    return Err(OnvifError::SenderFault(
                                        "IPv4 filter entry requires a PrefixLength (0-32)".into(),
                                    ));
                                }
                            }
                            in_v4 = false;
                        }
                        if local == "Type" || local == "Address" || local == "PrefixLength" {
                            field.clear();
                        }
                    }
                    Ok(Event::Eof) => break,
                    Err(e) => {
                        return Err(OnvifError::InvalidXml(format!("XML parse error: {e}")));
                    }
                    _ => {}
                }
            }
        }
        buf.clear();
    }

    if saw_ipv6 {
        return Err(OnvifError::SenderFault(
            "IPv6 filter entries are not supported (IPv4 only)".into(),
        ));
    }
    let Some(mode) = mode else {
        return Err(OnvifError::SenderFault(
            "IPAddressFilter requires a Type of Allow or Deny".into(),
        ));
    };
    Ok(IpFilter {
        enabled: true,
        mode,
        entries,
    })
}

/// Extract the Base64 text of `PolicyFile/Data` from a SetAccessPolicy
/// body (tolerant of prefixes). `None` when no Data element is found.
fn sec_extract_policy_data(body: &str) -> Option<String> {
    let mut reader = quick_xml::Reader::from_str(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut in_data = false;
    let mut out: Option<String> = None;
    let mut text_acc = crate::types::TextAccumulator::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Text(e)) => {
                let _ = text_acc.push_text(&e);
            }
            Ok(Event::GeneralRef(e)) => {
                let _ = text_acc.push_ref(&e);
            }
            Ok(Event::Start(e)) => {
                let _ = text_acc.flush();
                if sec_local_name(e.name()) == "Data" {
                    in_data = true;
                }
            }
            Ok(Event::Empty(_)) => {
                let _ = text_acc.flush();
            }
            Ok(Event::End(e)) => {
                let flushed = text_acc.flush();
                let local = sec_local_name(e.name());
                if in_data && local == "Data" {
                    in_data = false;
                    out = flushed; // schema has exactly one Data
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuthResult;

    fn test_handlers() -> DeviceServiceHandlers {
        DeviceServiceHandlers::new(test_device_config(), 8080, "192.168.1.100".to_string()).unwrap()
    }

    /// Explicit, valid identity — the neutral defaults would fail the
    /// constructor's fail-fast validation (issue #20).
    fn test_device_config() -> DeviceConfig {
        DeviceConfig {
            name: "Test Cam".into(),
            manufacturer: "MiBee".into(),
            model: "IMX219".into(),
            firmware: "1.0.0".into(),
            hardware_id: "HW-1".into(),
            serial_number: "SN-1".into(),
        }
    }

    fn test_info(server_ip: &str) -> RequestInfo {
        RequestInfo {
            client_ip: "10.0.0.1".to_string(),
            server_ip: server_ip.to_string(),
            auth_result: AuthResult {
                username: "admin".into(),
                authenticated: true,
            },
        }
    }

    // --------------------------------------------------------------
    // XML body fragment tests (no SOAP envelope)
    // --------------------------------------------------------------

    #[test]
    fn test_get_system_date_time_contains_expected_fields() {
        let h = test_handlers();
        let xml = h.build_system_date_time();

        assert!(xml.contains("GetSystemDateAndTimeResponse"));
        assert!(xml.contains("DateTimeType"));
        assert!(xml.contains("Manual"));
        assert!(xml.contains("DaylightSavings"));
        assert!(xml.contains("TimeZone"));
        assert!(xml.contains("<tt:TZ>UTC</tt:TZ>"));
        assert!(xml.contains("UTCDateTime"));
        assert!(xml.contains("tt:Hour"));
        assert!(xml.contains("tt:Minute"));
        assert!(xml.contains("tt:Second"));
        assert!(xml.contains("tt:Year"));
        assert!(xml.contains("tt:Month"));
        assert!(xml.contains("tt:Day"));

        // Verify well-formed XML
        let mut reader = quick_xml::Reader::from_str(&xml);
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Err(e) => panic!("XML parse error in system_date_time: {e}"),
                _ => {}
            }
            buf.clear();
        }
    }

    #[test]
    fn test_get_device_information_contains_expected_fields() {
        let h = DeviceServiceHandlers::new(
            DeviceConfig {
                manufacturer: "Raspberry Pi".into(),
                model: "OV5647".into(),
                firmware: "1.0.0".into(),
                serial_number: "SN-001".into(),
                hardware_id: "OV5647".into(),
                name: "Pi Camera V1".into(),
            },
            8080,
            "192.168.1.100".to_string(),
        )
        .unwrap();
        let xml = h.build_device_information();

        assert!(xml.contains("GetDeviceInformationResponse"));
        assert!(xml.contains("Raspberry Pi"));
        assert!(xml.contains("OV5647"));
        assert!(xml.contains("1.0.0"));
        assert!(xml.contains("SN-001"));
        assert!(xml.contains("tds:Manufacturer"));
        assert!(xml.contains("tds:Model"));
        assert!(xml.contains("tds:FirmwareVersion"));
        assert!(xml.contains("tds:SerialNumber"));
        assert!(xml.contains("tds:HardwareId"));
    }

    #[test]
    fn test_get_capabilities_contains_service_endpoints() {
        let h = test_handlers();
        let xml = h.build_capabilities("10.0.0.5");

        assert!(xml.contains("GetCapabilitiesResponse"));
        assert!(xml.contains("http://10.0.0.5:8080/onvif/device_service"));
        assert!(xml.contains("http://10.0.0.5:8080/onvif/media_service"));
        assert!(xml.contains("http://10.0.0.5:8080/onvif/ptz_service"));
        assert!(xml.contains("tt:Device"));
        assert!(xml.contains("tt:Media"));
        assert!(xml.contains("tt:PTZ"));
        assert!(xml.contains("tt:Imaging"));
    }

    #[test]
    fn test_get_services_contains_service_entries() {
        let h = test_handlers();
        let xml = h.build_services("10.0.0.5");

        assert!(xml.contains("GetServicesResponse"));
        assert!(xml.contains("tds:Service"));
        assert!(xml.contains("tds:Namespace"));
        assert!(xml.contains("tds:XAddr"));
        assert!(xml.contains("tds:Version"));
        assert!(xml.contains("<tt:Major>1</tt:Major>"));
        assert!(xml.contains("<tt:Minor>0</tt:Minor>"));
        assert!(xml.contains("http://10.0.0.5:8080/onvif/device_service"));
        assert!(xml.contains("http://10.0.0.5:8080/onvif/media_service"));
        assert!(xml.contains("http://10.0.0.5:8080/onvif/ptz_service"));
        assert!(xml.contains(DEVICE_SERVICE));
        assert!(xml.contains(MEDIA_SERVICE));
        assert!(xml.contains(PTZ_SERVICE));
        assert!(xml.contains(IMAGING_SERVICE));
    }

    #[test]
    fn test_get_scopes_contains_scope_items() {
        let h = DeviceServiceHandlers::new(
            DeviceConfig {
                name: "Pi Camera V1".into(),
                hardware_id: "OV5647".into(),
                manufacturer: "TestVendor".into(),
                model: "TestModel".into(),
                ..DeviceConfig::default()
            },
            8080,
            "192.168.1.100".to_string(),
        )
        .unwrap();
        let xml = h.build_scopes();

        assert!(xml.contains("GetScopesResponse"));
        assert!(xml.contains("tt:ScopeItem"));
        assert!(xml.contains("onvif://www.onvif.org/type/video_encoder"));
        assert!(xml.contains("onvif://www.onvif.org/name/Pi Camera V1"));
        assert!(xml.contains("onvif://www.onvif.org/hardware/OV5647"));
    }

    // --------------------------------------------------------------
    // SystemReboot (parity with onvif-go HandleSystemReboot)
    // --------------------------------------------------------------

    #[test]
    fn test_build_system_reboot_contains_message() {
        let h = test_handlers();
        let xml = h.build_system_reboot();

        assert!(xml.contains("tds:SystemRebootResponse"));
        assert!(xml.contains("tds:Message"));
        assert!(xml.contains("Device rebooting"));
        // WSDL namespace declaration on the response root.
        assert!(xml.contains("xmlns:tds"));
        assert!(xml.contains(DEVICE_SERVICE));

        // Verify well-formed XML
        let mut reader = quick_xml::Reader::from_str(&xml);
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Err(e) => panic!("XML parse error in system_reboot: {e}"),
                _ => {}
            }
            buf.clear();
        }
    }

    #[tokio::test]
    async fn test_handler_dispatches_system_reboot() {
        let svc = Arc::new(test_handlers());
        let handler = DeviceHandler(svc);
        let ri = test_info("10.0.0.1");

        let body = r#"<SystemReboot xmlns="http://www.onvif.org/ver10/device/wsdl"/>"#;
        let resp = handler.handle(body, &ri).await.unwrap();

        assert!(resp.contains("soap:Envelope"));
        assert!(resp.contains("SystemRebootResponse"));
        assert!(resp.contains("Device rebooting"));
    }

    /// A SOAP body mentioning SystemReboot inside a *different* action
    /// element must not be misrouted by the substring dispatch chain.
    #[tokio::test]
    async fn test_handler_routes_get_actions_over_system_reboot_substring() {
        let svc = Arc::new(test_handlers());
        let handler = DeviceHandler(svc);
        let ri = test_info("10.0.0.1");

        // GetServices contains "Service", GetSystemDateAndTime contains
        // "System"… but none of the existing actions contains the exact
        // "SystemReboot" token; this pins the reverse direction — a body
        // that IS SystemReboot never matches the earlier arms.
        let body = r#"<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>"#;
        let resp = handler.handle(body, &ri).await.unwrap();
        assert!(resp.contains("GetDeviceInformationResponse"));
        assert!(!resp.contains("SystemRebootResponse"));
    }

    // --------------------------------------------------------------
    // Per-request client IP tests
    // --------------------------------------------------------------

    #[test]
    fn test_get_capabilities_uses_per_request_client_ip() {
        let h = test_handlers();
        let a = h.build_capabilities("192.168.1.99");
        let b = h.build_capabilities("10.0.0.42");
        assert!(a.contains("192.168.1.99"));
        assert!(b.contains("10.0.0.42"));
        assert!(!a.contains("10.0.0.42"));
        assert!(!b.contains("192.168.1.99"));
    }

    #[test]
    fn test_get_services_uses_per_request_client_ip() {
        let h = test_handlers();
        let xml = h.build_services("172.16.0.8");
        assert!(xml.contains("172.16.0.8"));
    }

    // --------------------------------------------------------------
    // Per-service advertisement flags (issue #47) — GetServices and
    // GetCapabilities must agree with what the host actually serves.
    // --------------------------------------------------------------

    #[test]
    fn test_get_services_omits_disabled_services() {
        let h = test_handlers()
            .with_media_support(false)
            .with_ptz_support(false)
            .with_imaging_support(false)
            .with_events_support(false);
        let xml = h.build_services("10.0.0.5");

        assert!(
            xml.contains(DEVICE_SERVICE),
            "Device is always advertised, got: {xml}"
        );
        assert!(!xml.contains(MEDIA_SERVICE), "media disabled: {xml}");
        assert!(!xml.contains(PTZ_SERVICE), "ptz disabled: {xml}");
        assert!(!xml.contains(IMAGING_SERVICE), "imaging disabled: {xml}");
        assert!(!xml.contains(EVENTS_SERVICE), "events disabled: {xml}");
        // Exactly one tds:Service entry.
        assert_eq!(xml.matches("<tds:Service>").count(), 1, "{xml}");
    }

    #[test]
    fn test_get_services_selectively_disables_services() {
        let h = test_handlers().with_ptz_support(false);
        let xml = h.build_services("10.0.0.5");
        assert!(xml.contains(DEVICE_SERVICE));
        assert!(xml.contains(MEDIA_SERVICE));
        assert!(!xml.contains(PTZ_SERVICE));
        assert!(xml.contains(IMAGING_SERVICE));
        assert_eq!(xml.matches("<tds:Service>").count(), 3, "{xml}");
    }

    #[test]
    fn test_get_capabilities_omits_disabled_services() {
        let h = test_handlers()
            .with_media_support(false)
            .with_ptz_support(false)
            .with_imaging_support(false);
        let xml = h.build_capabilities("10.0.0.5");

        assert!(xml.contains("tt:Device"), "device caps always present");
        assert!(!xml.contains("tt:Media"), "media disabled: {xml}");
        assert!(!xml.contains("tt:PTZ"), "ptz disabled: {xml}");
        assert!(!xml.contains("tt:Imaging"), "imaging disabled: {xml}");
        assert!(
            !xml.contains("/media_service"),
            "no media XAddr when disabled: {xml}"
        );
    }

    #[test]
    fn test_service_flags_default_advertises_everything() {
        // Defaults keep the historical (pre-flag) advertisement: every
        // service listed — existing hosts' wire bytes must not change.
        let h = test_handlers();
        let services = h.build_services("10.0.0.5");
        for ns in [DEVICE_SERVICE, MEDIA_SERVICE, PTZ_SERVICE, IMAGING_SERVICE] {
            assert!(services.contains(ns), "default must advertise {ns}");
        }
        assert_eq!(services.matches("<tds:Service>").count(), 4);
    }

    // --------------------------------------------------------------
    // DeviceHandler dispatch integration
    // --------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_dispatches_get_device_information() {
        let svc = Arc::new(test_handlers());
        let handler = DeviceHandler(svc);
        let ri = test_info("10.0.0.1");

        let body = r#"<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>"#;
        let resp = handler.handle(body, &ri).await.unwrap();

        assert!(resp.contains("soap:Envelope"));
        assert!(resp.contains("GetDeviceInformationResponse"));
        assert!(resp.contains("MiBee"));
    }

    #[tokio::test]
    async fn test_handler_dispatches_get_capabilities_with_client_ip() {
        let svc = Arc::new(test_handlers());
        let handler = DeviceHandler(svc);
        let ri = test_info("192.168.1.50");

        let body = r#"<GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl"/>"#;
        let resp = handler.handle(body, &ri).await.unwrap();

        assert!(resp.contains("soap:Envelope"));
        assert!(resp.contains("192.168.1.50"));
        assert!(resp.contains("/onvif/device_service"));
    }

    #[tokio::test]
    async fn test_handler_returns_error_for_unknown_action() {
        let svc = Arc::new(test_handlers());
        let handler = DeviceHandler(svc);
        let ri = test_info("10.0.0.1");

        let body = r#"<GetFoo xmlns="http://www.onvif.org/ver10/device/wsdl"/>"#;
        let result = handler.handle(body, &ri).await;
        assert!(result.is_err());
        match result {
            Err(OnvifError::ActionNotSupported(msg)) => {
                assert!(msg.contains("unknown device action"));
            }
            _ => panic!("expected ActionNotSupported"),
        }
    }

    #[test]
    fn test_soap_response_well_formed() {
        let svc = test_handlers();
        let xml = svc.build_device_information();
        let wrapped = serialize_soap_response(&xml);

        let mut reader = quick_xml::Reader::from_str(&wrapped);
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Err(e) => panic!("SOAP response XML parse error: {e}"),
                _ => {}
            }
            buf.clear();
        }
    }
}

// ---------------------------------------------------------------------------
// Security ops tests (issue #54)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod security_ops_tests {
    use super::*;
    use crate::types::AuthResult;

    fn handlers() -> DeviceServiceHandlers {
        DeviceServiceHandlers::new(
            DeviceConfig {
                name: "Sec Cam".into(),
                manufacturer: "Vendor".into(),
                model: "Model".into(),
                firmware: "1.0.0".into(),
                hardware_id: "HW".into(),
                serial_number: "SN".into(),
            },
            8080,
            "10.1.1.1".to_string(),
        )
        .unwrap()
    }

    fn info() -> RequestInfo {
        RequestInfo {
            client_ip: "10.0.0.1".to_string(),
            server_ip: "10.0.0.5".to_string(),
            auth_result: AuthResult {
                username: "admin".into(),
                authenticated: true,
            },
        }
    }

    fn filter_state(f: IpFilter) -> IpFilterState {
        Arc::new(std::sync::RwLock::new(f))
    }

    fn entry(ip: &str, plen: u8) -> IpEntry {
        IpEntry {
            ipv4: ip.to_string(),
            prefix_len: plen,
        }
    }

    fn assert_well_formed(xml: &str) {
        let mut reader = quick_xml::Reader::from_str(xml);
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Err(e) => panic!("XML parse error: {e} in\n{xml}"),
                _ => {}
            }
            buf.clear();
        }
    }

    // ------------------------------------------------------------------
    // Filter matching
    // ------------------------------------------------------------------

    #[test]
    fn ip_filter_disabled_allows_everything() {
        assert!(IpFilter::disabled().allows_client_ip("10.0.0.1"));
        // Entries present but disabled: still no enforcement.
        let f = IpFilter {
            enabled: false,
            mode: IpFilterMode::Deny,
            entries: vec![entry("10.0.0.1", 32)],
        };
        assert!(f.allows_client_ip("10.0.0.1"));
    }

    #[test]
    fn ip_filter_allow_mode_admits_only_matches() {
        let f = IpFilter {
            enabled: true,
            mode: IpFilterMode::Allow,
            entries: vec![entry("192.168.1.0", 24)],
        };
        assert!(f.allows_client_ip("192.168.1.77"));
        assert!(!f.allows_client_ip("192.168.2.1"));
        assert!(!f.allows_client_ip("10.0.0.1"));
    }

    #[test]
    fn ip_filter_deny_mode_refuses_only_matches() {
        let f = IpFilter {
            enabled: true,
            mode: IpFilterMode::Deny,
            entries: vec![entry("10.9.9.5", 32)],
        };
        assert!(!f.allows_client_ip("10.9.9.5"));
        assert!(f.allows_client_ip("10.9.9.6"));
    }

    #[test]
    fn ip_filter_prefix_bounds() {
        let all = IpFilter {
            enabled: true,
            mode: IpFilterMode::Allow,
            entries: vec![entry("0.0.0.0", 0)],
        };
        assert!(all.allows_client_ip("203.0.113.9"));

        let host = IpFilter {
            enabled: true,
            mode: IpFilterMode::Allow,
            entries: vec![entry("198.51.100.7", 32)],
        };
        assert!(host.allows_client_ip("198.51.100.7"));
        assert!(!host.allows_client_ip("198.51.100.8"));
    }

    /// IPv6 / unparseable peer addresses fail OPEN (documented): a
    /// malformed address must not brick the listener.
    #[test]
    fn ip_filter_ipv6_and_garbage_fail_open() {
        let deny_all_v4 = IpFilter {
            enabled: true,
            mode: IpFilterMode::Deny,
            entries: vec![entry("0.0.0.0", 0)],
        };
        assert!(!deny_all_v4.allows_client_ip("10.0.0.1"), "IPv4 is denied");
        assert!(deny_all_v4.allows_client_ip("::1"));
        assert!(deny_all_v4.allows_client_ip("not-an-ip"));
    }

    #[test]
    fn ip_filter_invalid_entries_never_match() {
        let f = IpFilter {
            enabled: true,
            mode: IpFilterMode::Allow,
            entries: vec![entry("garbage", 24), entry("10.0.0.0", 40)],
        };
        assert!(!f.allows_client_ip("192.168.0.1"));
        assert!(!f.allows_client_ip("10.0.0.1"));
    }

    // ------------------------------------------------------------------
    // GetIPAddressFilter wire shape
    // ------------------------------------------------------------------

    #[test]
    fn get_ip_filter_without_state_reports_disabled() {
        let xml = handlers().sec_build_get_ip_address_filter();
        assert!(xml.contains("tds:GetIPAddressFilterResponse"), "{xml}");
        assert!(xml.contains("<tds:IPAddressFilter>"), "{xml}");
        assert!(xml.contains("<tt:Type>Allow</tt:Type>"), "{xml}");
        assert!(!xml.contains("tt:IPv4Address"), "{xml}");
        assert_well_formed(&xml);
    }

    #[test]
    fn get_ip_filter_serializes_entries() {
        let state = filter_state(IpFilter {
            enabled: true,
            mode: IpFilterMode::Deny,
            entries: vec![entry("192.168.0.0", 16), entry("10.1.2.3", 32)],
        });
        let xml = handlers()
            .with_ip_filter(state)
            .sec_build_get_ip_address_filter();
        assert!(xml.contains("<tt:Type>Deny</tt:Type>"), "{xml}");
        assert!(
            xml.contains("<tt:Address>192.168.0.0</tt:Address>"),
            "{xml}"
        );
        assert!(
            xml.contains("<tt:PrefixLength>16</tt:PrefixLength>"),
            "{xml}"
        );
        assert!(xml.contains("<tt:Address>10.1.2.3</tt:Address>"), "{xml}");
        assert!(
            xml.contains("<tt:PrefixLength>32</tt:PrefixLength>"),
            "{xml}"
        );
        assert_eq!(xml.matches("tt:IPv4Address").count(), 4, "{xml}"); // open+close per entry
        assert_well_formed(&xml);
    }

    // ------------------------------------------------------------------
    // Request parsing
    // ------------------------------------------------------------------

    fn set_filter_body(mode: &str, entries: &[(&str, &str)], prefixed: bool) -> String {
        let (pt, pv, pe, pp) = if prefixed {
            ("tt:Type", "tt:IPv4Address", "tt:Address", "tt:PrefixLength")
        } else {
            ("Type", "IPv4Address", "Address", "PrefixLength")
        };
        let mut x = format!(
            "<SetIPAddressFilter xmlns=\"http://www.onvif.org/ver10/device/wsdl\">\
             <IPAddressFilter><{pt}>{mode}</{pt}>"
        );
        for (addr, plen) in entries {
            x.push_str(&format!(
                "<{pv}><{pe}>{addr}</{pe}><{pp}>{plen}</{pp}></{pv}>"
            ));
        }
        x.push_str("</IPAddressFilter></SetIPAddressFilter>");
        x
    }

    #[test]
    fn parse_ip_filter_tolerates_tt_prefixes() {
        let f = sec_parse_ip_filter(&set_filter_body("Deny", &[("192.168.0.0", "16")], true))
            .expect("prefixed body must parse");
        assert_eq!(f.mode, IpFilterMode::Deny);
        assert_eq!(f.entries, vec![entry("192.168.0.0", 16)]);
    }

    #[test]
    fn parse_ip_filter_tolerates_default_namespace() {
        let f = sec_parse_ip_filter(&set_filter_body("Allow", &[("10.0.0.0", "8")], false))
            .expect("unprefixed body must parse");
        assert_eq!(f.mode, IpFilterMode::Allow);
        assert_eq!(f.entries, vec![entry("10.0.0.0", 8)]);
    }

    #[test]
    fn parse_ip_filter_rejects_bad_type() {
        let err = sec_parse_ip_filter(&set_filter_body("Maybe", &[], false)).unwrap_err();
        assert!(err.to_string().contains("Type"), "{err}");
    }

    #[test]
    fn parse_ip_filter_rejects_ipv6_entries() {
        let body = "<SetIPAddressFilter><IPAddressFilter><Type>Allow</Type>\
                    <IPv6Address><Address>fe80::1</Address><PrefixLength>10</PrefixLength></IPv6Address>\
                    </IPAddressFilter></SetIPAddressFilter>";
        let err = sec_parse_ip_filter(body).unwrap_err();
        assert!(err.to_string().contains("IPv6"), "{err}");
    }

    #[test]
    fn parse_ip_filter_rejects_incomplete_entry() {
        let body = "<SetIPAddressFilter><IPAddressFilter><Type>Allow</Type>\
                    <IPv4Address><Address>10.0.0.0</Address></IPv4Address>\
                    </IPAddressFilter></SetIPAddressFilter>";
        let err = sec_parse_ip_filter(body).unwrap_err();
        assert!(err.to_string().contains("PrefixLength"), "{err}");
    }

    #[test]
    fn parse_ip_filter_rejects_bad_address() {
        let err = sec_parse_ip_filter(&set_filter_body("Allow", &[("300.1.2.3", "24")], false))
            .unwrap_err();
        assert!(err.to_string().contains("Address"), "{err}");
    }

    #[test]
    fn parse_ip_filter_rejects_prefix_over_32() {
        let err = sec_parse_ip_filter(&set_filter_body("Allow", &[("10.0.0.0", "33")], false))
            .unwrap_err();
        assert!(err.to_string().contains("PrefixLength"), "{err}");
    }

    // ------------------------------------------------------------------
    // Handler dispatch round-trips (Set/Add/Remove/Get over the store)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn set_then_get_ip_filter_roundtrip() {
        let state = filter_state(IpFilter::disabled());
        let svc = Arc::new(handlers().with_ip_filter(state.clone()));
        let handler = DeviceHandler(svc);
        let ri = info();

        let resp = handler
            .handle(
                &set_filter_body("Allow", &[("172.16.0.0", "12")], false),
                &ri,
            )
            .await
            .unwrap();
        assert!(resp.contains("tds:SetIPAddressFilterResponse"), "{resp}");

        // Mutations mark the filter enabled in the shared state.
        assert!(state.read().unwrap().enabled);

        let get = handler
            .handle(
                "<GetIPAddressFilter xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>",
                &ri,
            )
            .await
            .unwrap();
        assert!(get.contains("<tt:Type>Allow</tt:Type>"), "{get}");
        assert!(get.contains("<tt:Address>172.16.0.0</tt:Address>"), "{get}");
        assert!(
            get.contains("<tt:PrefixLength>12</tt:PrefixLength>"),
            "{get}"
        );
    }

    #[tokio::test]
    async fn add_appends_then_set_replaces() {
        let state = filter_state(IpFilter::disabled());
        let svc = Arc::new(handlers().with_ip_filter(state));
        let handler = DeviceHandler(svc);
        let ri = info();

        handler
            .handle(&set_filter_body("Allow", &[("10.0.0.0", "8")], false), &ri)
            .await
            .unwrap();
        let resp = handler
            .handle(
                "<AddIPAddressFilter xmlns=\"http://www.onvif.org/ver10/device/wsdl\">\
                 <IPAddressFilter><Type>Allow</Type>\
                 <IPv4Address><Address>192.168.0.0</Address><PrefixLength>16</PrefixLength></IPv4Address>\
                 </IPAddressFilter></AddIPAddressFilter>",
                &ri,
            )
            .await
            .unwrap();
        assert!(resp.contains("tds:AddIPAddressFilterResponse"), "{resp}");

        let get = handler.handle("<GetIPAddressFilter/>", &ri).await.unwrap();
        assert!(
            get.contains("10.0.0.0") && get.contains("192.168.0.0"),
            "{get}"
        );

        // Set replaces wholesale.
        handler
            .handle(&set_filter_body("Deny", &[("10.9.0.0", "16")], false), &ri)
            .await
            .unwrap();
        let get = handler.handle("<GetIPAddressFilter/>", &ri).await.unwrap();
        assert!(get.contains("<tt:Type>Deny</tt:Type>"), "{get}");
        assert!(get.contains("10.9.0.0"), "{get}");
        assert!(!get.contains("192.168.0.0"), "{get}");
    }

    #[tokio::test]
    async fn remove_removes_matching_entry() {
        let state = filter_state(IpFilter::disabled());
        let svc = Arc::new(handlers().with_ip_filter(state));
        let handler = DeviceHandler(svc);
        let ri = info();

        handler
            .handle(
                &set_filter_body("Deny", &[("10.1.0.0", "16"), ("10.2.0.0", "16")], false),
                &ri,
            )
            .await
            .unwrap();
        let resp = handler
            .handle(
                "<RemoveIPAddressFilter xmlns=\"http://www.onvif.org/ver10/device/wsdl\">\
                 <IPAddressFilter><Type>Deny</Type>\
                 <IPv4Address><Address>10.1.0.0</Address><PrefixLength>16</PrefixLength></IPv4Address>\
                 </IPAddressFilter></RemoveIPAddressFilter>",
                &ri,
            )
            .await
            .unwrap();
        assert!(resp.contains("tds:RemoveIPAddressFilterResponse"), "{resp}");

        let get = handler.handle("<GetIPAddressFilter/>", &ri).await.unwrap();
        assert!(get.contains("10.2.0.0"), "{get}");
        assert!(!get.contains("10.1.0.0"), "{get}");
        // Mode is kept on remove.
        assert!(get.contains("<tt:Type>Deny</tt:Type>"), "{get}");
    }

    #[tokio::test]
    async fn set_ip_filter_without_state_refused() {
        let handler = DeviceHandler(Arc::new(handlers()));
        let result = handler
            .handle(
                &set_filter_body("Allow", &[("10.0.0.0", "8")], false),
                &info(),
            )
            .await;
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not configured"), "{err}");
    }

    // ------------------------------------------------------------------
    // AccessPolicy
    // ------------------------------------------------------------------

    #[test]
    fn get_access_policy_default_empty() {
        let xml = handlers().sec_build_get_access_policy();
        assert!(xml.contains("tds:GetAccessPolicyResponse"), "{xml}");
        assert!(xml.contains("tds:PolicyFile"), "{xml}");
        assert!(xml.contains("tt:Data"), "{xml}");
        assert_well_formed(&xml);
    }

    #[tokio::test]
    async fn access_policy_roundtrip() {
        use base64::Engine as _;

        let state: AccessPolicyState = Arc::new(std::sync::RwLock::new(Vec::new()));
        let svc = Arc::new(handlers().with_access_policy(state));
        let handler = DeviceHandler(svc);
        let ri = info();

        let blob = b"<policy>allow admin</policy>".as_slice();
        let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
        let set_body = format!(
            "<SetAccessPolicy xmlns=\"http://www.onvif.org/ver10/device/wsdl\">\
             <PolicyFile><Data>{b64}</Data></PolicyFile></SetAccessPolicy>"
        );
        let resp = handler.handle(&set_body, &ri).await.unwrap();
        assert!(resp.contains("tds:SetAccessPolicyResponse"), "{resp}");

        let get = handler
            .handle(
                "<GetAccessPolicy xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>",
                &ri,
            )
            .await
            .unwrap();
        assert!(get.contains(&format!("<tt:Data>{b64}</tt:Data>")), "{get}");
    }

    #[tokio::test]
    async fn set_access_policy_invalid_base64_refused() {
        let state: AccessPolicyState = Arc::new(std::sync::RwLock::new(Vec::new()));
        let handler = DeviceHandler(Arc::new(handlers().with_access_policy(state)));
        let body = "<SetAccessPolicy><PolicyFile><Data>!!not-base64!!</Data></PolicyFile></SetAccessPolicy>";
        let err = handler.handle(body, &info()).await.unwrap_err();
        assert!(err.to_string().contains("base64"), "{err}");
    }

    #[tokio::test]
    async fn set_access_policy_without_state_refused() {
        let handler = DeviceHandler(Arc::new(handlers()));
        let body = "<SetAccessPolicy><PolicyFile><Data>AAAA</Data></PolicyFile></SetAccessPolicy>";
        let err = handler.handle(body, &info()).await.unwrap_err();
        assert!(err.to_string().contains("not configured"), "{err}");
    }

    // ------------------------------------------------------------------
    // Builder seam
    // ------------------------------------------------------------------

    #[test]
    fn with_ip_filter_exposes_the_same_state() {
        let state = filter_state(IpFilter::disabled());
        let h = handlers().with_ip_filter(state.clone());
        let exposed = h.ip_filter_state().expect("state must be exposed");
        assert!(Arc::ptr_eq(&exposed, &state));
        assert!(handlers().ip_filter_state().is_none());
    }

    #[test]
    fn with_access_policy_exposes_the_same_state() {
        let state: AccessPolicyState = Arc::new(std::sync::RwLock::new(Vec::new()));
        let h = handlers().with_access_policy(state.clone());
        let exposed = h.access_policy_state().expect("state must be exposed");
        assert!(Arc::ptr_eq(&exposed, &state));
        assert!(handlers().access_policy_state().is_none());
    }
}
