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
use crate::namespaces::{DEVICE_SERVICE, IMAGING_SERVICE, MEDIA_SERVICE, PTZ_SERVICE, SCHEMAS};
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
}

impl DeviceServiceHandlers {
    pub fn new(device_config: DeviceConfig, onvif_port: u16, device_ip: String) -> Self {
        Self {
            device_config,
            onvif_port,
            device_ip,
        }
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
        w.write_event(Event::Start(root)).expect("write root");

        w.write_event(Event::Start(BytesStart::new("tds:SystemDateAndTime")))
            .expect("write SystemDateAndTime");
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
            .expect("close SystemDateAndTime");
        w.write_event(Event::End(BytesEnd::new(
            "tds:GetSystemDateAndTimeResponse",
        )))
        .expect("close root");

        String::from_utf8(w.into_inner()).expect("UTF-8 body")
    }

    /// Build `<tds:GetDeviceInformationResponse>` body.
    fn build_device_information(&self) -> String {
        let cfg = &self.device_config;
        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

        let mut root = BytesStart::new("tds:GetDeviceInformationResponse");
        root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
        w.write_event(Event::Start(root)).expect("write root");

        write_text(&mut w, "tds:Manufacturer", &cfg.manufacturer);
        write_text(&mut w, "tds:Model", &cfg.model);
        write_text(&mut w, "tds:FirmwareVersion", &cfg.firmware);
        write_text(&mut w, "tds:SerialNumber", &cfg.serial_number);
        write_text(&mut w, "tds:HardwareId", &cfg.hardware_id);

        w.write_event(Event::End(BytesEnd::new(
            "tds:GetDeviceInformationResponse",
        )))
        .expect("close root");

        String::from_utf8(w.into_inner()).expect("UTF-8 body")
    }

    /// Build `<tds:GetCapabilitiesResponse>` body.
    fn build_capabilities(&self, server_ip: &str) -> String {
        let base = self.base_url(server_ip);
        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

        let mut root = BytesStart::new("tds:GetCapabilitiesResponse");
        root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
        root.push_attribute(("xmlns:tt", SCHEMAS));
        w.write_event(Event::Start(root)).expect("write root");

        w.write_event(Event::Start(BytesStart::new("tds:Capabilities")))
            .expect("write Capabilities");
        capability_xaddr(&mut w, "tt:Device", &base, "/device_service");
        capability_xaddr(&mut w, "tt:Media", &base, "/media_service");
        capability_xaddr(&mut w, "tt:PTZ", &base, "/ptz_service");
        capability_xaddr(&mut w, "tt:Imaging", &base, "/device_service");
        w.write_event(Event::End(BytesEnd::new("tds:Capabilities")))
            .expect("close Capabilities");

        w.write_event(Event::End(BytesEnd::new("tds:GetCapabilitiesResponse")))
            .expect("close root");
        String::from_utf8(w.into_inner()).expect("UTF-8 body")
    }

    /// Build `<tds:GetServicesResponse>` body.
    fn build_services(&self, server_ip: &str) -> String {
        let base = self.base_url(server_ip);
        let services: &[(&str, &str)] = &[
            (DEVICE_SERVICE, "/device_service"),
            (MEDIA_SERVICE, "/media_service"),
            (PTZ_SERVICE, "/ptz_service"),
            (IMAGING_SERVICE, "/device_service"),
        ];

        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

        let mut root = BytesStart::new("tds:GetServicesResponse");
        root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
        root.push_attribute(("xmlns:tt", SCHEMAS));
        w.write_event(Event::Start(root)).expect("write root");

        w.write_event(Event::Start(BytesStart::new("tds:Services")))
            .expect("write Services");

        for (ns, path) in services {
            w.write_event(Event::Start(BytesStart::new("tds:Service")))
                .expect("write Service");
            write_text(&mut w, "tds:Namespace", ns);
            write_text(&mut w, "tds:XAddr", &format!("{}{}", base, path));
            open_close(&mut w, "tds:Version", |w| {
                write_int(w, "tt:Major", 1);
                write_int(w, "tt:Minor", 0);
            });
            w.write_event(Event::End(BytesEnd::new("tds:Service")))
                .expect("close Service");
        }

        w.write_event(Event::End(BytesEnd::new("tds:Services")))
            .expect("close Services");
        w.write_event(Event::End(BytesEnd::new("tds:GetServicesResponse")))
            .expect("close root");
        String::from_utf8(w.into_inner()).expect("UTF-8 body")
    }

    /// Build `<tds:GetScopesResponse>` body.
    fn build_scopes(&self) -> String {
        let cfg = &self.device_config;
        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

        let mut root = BytesStart::new("tds:GetScopesResponse");
        root.push_attribute(("xmlns:tds", DEVICE_SERVICE));
        root.push_attribute(("xmlns:tt", SCHEMAS));
        w.write_event(Event::Start(root)).expect("write root");

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
            .expect("close root");
        String::from_utf8(w.into_inner()).expect("UTF-8 body")
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn write_text(w: &mut Writer<Vec<u8>>, name: &str, text: &str) {
    w.write_event(Event::Start(BytesStart::new(name)))
        .expect("write start");
    w.write_event(Event::Text(BytesText::new(text)))
        .expect("write text");
    w.write_event(Event::End(BytesEnd::new(name)))
        .expect("write end");
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
        .expect("write open");
    f(w);
    w.write_event(Event::End(BytesEnd::new(name)))
        .expect("write close");
}

/// Write `<tt:XXX><tt:XAddr>base/path</tt:XAddr></tt:XXX>`.
fn capability_xaddr(w: &mut Writer<Vec<u8>>, tag: &str, base: &str, path: &str) {
    open_close(w, tag, |w| {
        write_text(w, "tt:XAddr", &format!("{}{}", base, path));
    });
}

/// Convert seconds since UNIX_EPOCH to UTC date/time fields.
/// Valid for years 1970–2100.
fn secs_to_utc(secs: u64) -> (i32, i32, i32, i32, i32, i32) {
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuthResult;

    fn test_handlers() -> DeviceServiceHandlers {
        DeviceServiceHandlers::new(DeviceConfig::default(), 8080, "192.168.1.100".to_string())
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
                ..DeviceConfig::default()
            },
            8080,
            "192.168.1.100".to_string(),
        );
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
                ..DeviceConfig::default()
            },
            8080,
            "192.168.1.100".to_string(),
        );
        let xml = h.build_scopes();

        assert!(xml.contains("GetScopesResponse"));
        assert!(xml.contains("tt:ScopeItem"));
        assert!(xml.contains("onvif://www.onvif.org/type/video_encoder"));
        assert!(xml.contains("onvif://www.onvif.org/name/Pi Camera V1"));
        assert!(xml.contains("onvif://www.onvif.org/hardware/OV5647"));
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
        assert!(resp.contains("Raspberry Pi"));
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
