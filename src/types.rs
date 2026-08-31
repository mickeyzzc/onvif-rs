use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;

use crate::namespaces::SOAP_ENVELOPE;

/// Escape a string for interpolation as XML text content.
///
/// Client-controlled data (SOAP action names, preset names, host identity
/// strings) reaches response text through this helper — without escaping, a
/// `<` or `&` in any of them produces malformed XML that strict NVR parsers
/// reject.
pub(crate) fn xml_escape(text: &str) -> std::borrow::Cow<'_, str> {
    quick_xml::escape::escape(text)
}

// ---------------------------------------------------------------------------
// SOAP data types
// ---------------------------------------------------------------------------

/// WS-UsernameToken credentials carried in the SOAP Security header.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UsernameToken {
    pub username: String,
    pub password: String,
    pub nonce: String,
    pub created: String,
}

/// Outcome of WS-UsernameToken authentication.
#[derive(Debug, Clone, Default)]
pub struct AuthResult {
    /// The username that was authenticated (empty if none).
    pub username: String,
    /// Whether authentication succeeded.
    pub authenticated: bool,
}

/// Top-level errors that can occur during ONVIF request processing.
#[derive(Debug, Clone)]
pub enum OnvifError {
    /// The requested SOAP action is not supported by this server.
    ActionNotSupported(String),
    /// Authentication failed.
    NotAuthorized(String),
    /// The incoming XML could not be parsed.
    InvalidXml(String),
    /// Internal server error.
    Internal(String),
}

impl std::fmt::Display for OnvifError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OnvifError::ActionNotSupported(a) => write!(f, "Action not supported: {a}"),
            OnvifError::NotAuthorized(m) => write!(f, "Not authorized: {m}"),
            OnvifError::InvalidXml(m) => write!(f, "Invalid XML: {m}"),
            OnvifError::Internal(m) => write!(f, "Internal error: {m}"),
        }
    }
}

impl std::error::Error for OnvifError {}

/// SOAP 1.2 Fault representation used for serialising error responses.
#[derive(Debug, Clone)]
pub struct SoapFault {
    pub code: String,
    pub reason: String,
}

/// Contextual information about an incoming ONVIF request.
#[derive(Debug, Clone)]
pub struct RequestInfo {
    /// The remote (peer) IP of the ONVIF client — used for logging.
    pub client_ip: String,
    /// The local IP that received the connection — used to build URIs
    /// (RTSP stream URI, ONVIF service endpoints) so they are reachable
    /// from the caller. Falls back to the startup-detected `device_ip`
    /// when empty (e.g. UDP discovery has no TCP local address).
    pub server_ip: String,
    pub auth_result: AuthResult,
}

/// Resolve the server IP to use in ONVIF URI responses.
///
/// Uses the per-request `server_ip` (the local interface that received the
/// TCP connection) when it is a real routable address. Falls back to the
/// startup-detected `device_ip` when `server_ip` is empty or a loopback
/// address — this covers requests arriving through a host-side localhost
/// reverse proxy (e.g. a web UI on :8088 proxying to the ONVIF port).
///
/// NOTE for multi-homed hosts: this rewrites loopback-sourced requests to
/// the startup `device_ip`. Hosts that genuinely serve ONVIF on loopback to
/// external callers should pass the loopback address as `device_ip`.
pub fn resolve_server_ip<'a>(server_ip: &'a str, device_ip: &'a str) -> &'a str {
    if server_ip.is_empty() || server_ip.starts_with("127.") || server_ip == "::1" {
        device_ip
    } else {
        server_ip
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Build a complete SOAP 1.2 Envelope containing the given `body_xml`
/// (typically a service response).
pub fn serialize_soap_response(body_xml: &str) -> String {
    let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);

    write_declaration(&mut writer);
    let mut envelope = BytesStart::new("soap:Envelope");
    envelope.push_attribute(("xmlns:soap", SOAP_ENVELOPE));
    writer
        .write_event(Event::Start(envelope))
        .expect("write soap:Envelope start");

    // Empty header
    write_empty_tag(&mut writer, "soap:Header");
    // Body with user content
    write_tag_with_raw(&mut writer, "soap:Body", body_xml);

    writer
        .write_event(Event::End(BytesEnd::new("soap:Envelope")))
        .expect("write soap:Envelope end");

    String::from_utf8(writer.into_inner()).expect("SOAP envelope UTF-8")
}

/// Build a SOAP 1.2 Fault Envelope.
///
/// `fault_code` should be something like `"soap:Sender"` and `reason` a
/// human-readable description.
pub fn serialize_soap_fault(fault_code: &str, reason: &str) -> String {
    let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);

    write_declaration(&mut writer);
    let mut envelope = BytesStart::new("soap:Envelope");
    envelope.push_attribute(("xmlns:soap", SOAP_ENVELOPE));
    writer
        .write_event(Event::Start(envelope))
        .expect("write soap:Envelope start");

    write_empty_tag(&mut writer, "soap:Header");

    // ---- Body / Fault ----
    writer
        .write_event(Event::Start(BytesStart::new("soap:Body")))
        .expect("write soap:Body start");

    writer
        .write_event(Event::Start(BytesStart::new("soap:Fault")))
        .expect("write soap:Fault start");

    // Code
    writer
        .write_event(Event::Start(BytesStart::new("soap:Code")))
        .expect("write soap:Code start");
    write_text_tag(&mut writer, "soap:Value", fault_code);
    writer
        .write_event(Event::End(BytesEnd::new("soap:Code")))
        .expect("write soap:Code end");

    // Reason
    writer
        .write_event(Event::Start(BytesStart::new("soap:Reason")))
        .expect("write soap:Reason start");
    write_text_tag(&mut writer, "soap:Text", reason);
    writer
        .write_event(Event::End(BytesEnd::new("soap:Reason")))
        .expect("write soap:Reason end");

    writer
        .write_event(Event::End(BytesEnd::new("soap:Fault")))
        .expect("write soap:Fault end");
    writer
        .write_event(Event::End(BytesEnd::new("soap:Body")))
        .expect("write soap:Body end");

    writer
        .write_event(Event::End(BytesEnd::new("soap:Envelope")))
        .expect("write soap:Envelope end");

    String::from_utf8(writer.into_inner()).expect("SOAP fault UTF-8")
}

// ---------------------------------------------------------------------------
// Internal writer helpers
// ---------------------------------------------------------------------------

fn write_declaration(writer: &mut Writer<Vec<u8>>) {
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))
        .expect("write XML declaration");
}

fn write_empty_tag(writer: &mut Writer<Vec<u8>>, name: &str) {
    writer
        .write_event(Event::Start(BytesStart::new(name)))
        .expect("write empty tag start");
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .expect("write empty tag end");
}

fn write_text_tag(writer: &mut Writer<Vec<u8>>, name: &str, text: &str) {
    writer
        .write_event(Event::Start(BytesStart::new(name)))
        .expect("write text tag start");
    writer
        .write_event(Event::Text(BytesText::from_escaped(xml_escape(text))))
        .expect("write text");
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .expect("write text tag end");
}

fn write_tag_with_raw(writer: &mut Writer<Vec<u8>>, name: &str, raw: &str) {
    use std::io::Write;
    writer
        .write_event(Event::Start(BytesStart::new(name)))
        .expect("write raw tag start");
    // Write raw content WITHOUT XML escaping
    writer
        .get_mut()
        .write_all(raw.as_bytes())
        .expect("write raw content");
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .expect("write raw tag end");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_soap_response_includes_envelope() {
        let xml = serialize_soap_response("<test>hello</test>");
        assert!(xml.contains("soap:Envelope"), "should have Envelope");
        assert!(xml.contains("soap:Body"), "should have Body");
        assert!(xml.contains("<test>hello</test>"), "should embed body XML");
        assert!(xml.contains(SOAP_ENVELOPE), "should declare SOAP namespace");
    }

    #[test]
    fn test_serialize_soap_fault_includes_code_reason() {
        let xml = serialize_soap_fault("soap:Sender", "test fault");
        assert!(xml.contains("soap:Envelope"));
        assert!(xml.contains("soap:Fault"));
        assert!(xml.contains("soap:Value"));
        assert!(xml.contains("soap:Text"));
        assert!(xml.contains("soap:Sender"));
        assert!(xml.contains("test fault"));
    }

    #[test]
    fn test_onvif_error_display() {
        let e = OnvifError::ActionNotSupported("GetFoo".into());
        assert!(e.to_string().contains("GetFoo"));

        let e = OnvifError::NotAuthorized("bad pass".into());
        assert!(e.to_string().contains("bad pass"));

        let e = OnvifError::InvalidXml("malformed".into());
        assert!(e.to_string().contains("malformed"));

        let e = OnvifError::Internal("oops".into());
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn test_serialize_fault_with_body_fragment() {
        // Verify that a fault can be parsed back by quick_xml to catch
        // well-formedness issues.
        let xml = serialize_soap_fault("soap:Receiver", "something broke");
        let mut reader = quick_xml::Reader::from_str(&xml);
        let mut count = 0;
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Eof) => break,
                Err(e) => panic!("fault XML parse error: {e}"),
                _ => count += 1,
            }
            buf.clear();
        }
        assert!(count > 5, "fault should have multiple XML events");
    }

    #[test]
    fn test_serialize_response_well_formed() {
        let xml = serialize_soap_response("<GetDeviceInformationResponse/>");
        let mut reader = quick_xml::Reader::from_str(&xml);
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Eof) => break,
                Err(e) => panic!("response XML parse error: {e}"),
                _ => {}
            }
            buf.clear();
        }
    }
}
