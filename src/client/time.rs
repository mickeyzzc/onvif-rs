//! Typed device time sync (the twin of the Go library's #129 batch):
//! read the camera clock over the unauthenticated GetSystemDateAndTime,
//! write a Manual clock, and switch the camera to NTP in one call.
//!
//! The read path needs no credentials — one of the few ONVIF operations
//! devices must serve pre-auth — so camera time stays observable exactly
//! when a drifted clock has broken digest auth; pair the reading with
//! [`crate::client::SoapClient::with_clock_skew`] so the writes go
//! through.

use super::{ClientError, SoapClient, UtcStamp};

/// tds (device service) and tt (schema) namespaces.
const TDS_NS: &str = "http://www.onvif.org/ver10/device/wsdl";
const TT_NS: &str = "http://www.onvif.org/ver10/schema";

/// Clocks before this year are firmware noise (never set / dead RTC
/// battery), not a clock.
const MINIMUM_USABLE_YEAR: i64 = 2000;

/// The camera wall clock in usable types (the twin of the Go
/// `device.DeviceTime`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceTime {
    /// The camera's clock as a UTC instant (second resolution).
    pub utc: UtcStamp,
    /// The camera's wall clock in its own configured zone — a component
    /// view for display (`Some` only when the device reports a usable
    /// local time).
    pub local: Option<UtcStamp>,
    /// POSIX TZ string (e.g. `CST-8`); empty when the device reports none.
    pub time_zone: String,
    /// How the camera sets its clock: `Manual` or `NTP`.
    pub date_time_type: String,
    /// The camera's daylight-savings flag.
    pub daylight_savings: bool,
}

/// One manual NTP server entry: an IPv4/IPv6 address or a DNS name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpHost {
    /// `IPv4`, `IPv6` or `DNS`.
    pub kind: String,
    /// The address or name.
    pub value: String,
}

impl NtpHost {
    /// An IPv4 address entry.
    #[must_use]
    pub fn ipv4(addr: &str) -> Self {
        Self {
            kind: "IPv4".into(),
            value: addr.into(),
        }
    }

    /// An IPv6 address entry.
    #[must_use]
    pub fn ipv6(addr: &str) -> Self {
        Self {
            kind: "IPv6".into(),
            value: addr.into(),
        }
    }

    /// A DNS name entry.
    #[must_use]
    pub fn dns(name: &str) -> Self {
        Self {
            kind: "DNS".into(),
            value: name.into(),
        }
    }

    fn xml(&self) -> String {
        let host_elem = match self.kind.as_str() {
            "IPv4" => format!("<tt:IPv4Address>{}</tt:IPv4Address>", self.value),
            "IPv6" => format!("<tt:IPv6Address>{}</tt:IPv6Address>", self.value),
            _ => format!("<tt:DNSname>{}</tt:DNSname>", self.value),
        };
        format!(
            "<tds:NTPManual><tt:Type>{}</tt:Type>{host_elem}</tds:NTPManual>",
            self.kind
        )
    }
}

/// Date/time components lifted from a GetSystemDateAndTime response.
#[derive(Default)]
struct TimeComponents {
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
}

impl TimeComponents {
    fn stamp(&self) -> UtcStamp {
        UtcStamp::from_components(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )
    }
}

impl SoapClient {
    /// Read the camera clock via the unauthenticated GetSystemDateAndTime.
    /// Rejects unusable clocks (absent UTC block, pre-2000 year) instead
    /// of silently decoding firmware noise.
    pub async fn get_device_time(&self) -> Result<DeviceTime, ClientError> {
        let body =
            format!("<tds:GetSystemDateAndTime xmlns:tds=\"{TDS_NS}\"></tds:GetSystemDateAndTime>");
        let resp = self.device_call(&body).await?;
        parse_device_time(&resp)
    }

    /// Write a Manual clock. `utc` is sent verbatim (UTC components);
    /// `time_zone` (POSIX TZ, e.g. `CST-8`) is omitted when empty so the
    /// camera keeps its zone. Requires credentials — a camera in NTP mode
    /// may refuse with a Sender fault, surfaced as-is.
    pub async fn set_device_time(&self, utc: UtcStamp, time_zone: &str) -> Result<(), ClientError> {
        self.require_credentials("SetDeviceTime")?;

        let (y, mo, d, h, mi, s) = crate::device::secs_to_utc(utc.unix.max(0) as u64);
        let tz_elem = if time_zone.is_empty() {
            String::new()
        } else {
            format!(
                "<tds:TimeZone><tt:TZ>{}</tt:TZ></tds:TimeZone>",
                crate::types::xml_escape(time_zone)
            )
        };

        let body = format!(
            "<tds:SetSystemDateAndTime xmlns:tds=\"{TDS_NS}\" xmlns:tt=\"{TT_NS}\">\
             <tds:DateTimeType>Manual</tds:DateTimeType>\
             <tds:DaylightSavings>false</tds:DaylightSavings>{tz_elem}\
             <tds:UTCDateTime><tt:Time><tt:Hour>{h}</tt:Hour><tt:Minute>{mi}</tt:Minute><tt:Second>{s}</tt:Second></tt:Time>\
             <tt:Date><tt:Year>{y}</tt:Year><tt:Month>{mo}</tt:Month><tt:Day>{d}</tt:Day></tt:Date>\
             </tds:UTCDateTime></tds:SetSystemDateAndTime>"
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// Point the camera at manual NTP servers AND flip its DateTimeType
    /// to NTP so it actually uses them — the field-proven two-step from
    /// the MiBeeNvr production implementation (firmwares that accept
    /// SetNTP without switching modes included). When the flip fails the
    /// error says so while the server list is already configured.
    pub async fn set_ntp_server(&self, hosts: &[NtpHost]) -> Result<(), ClientError> {
        if hosts.is_empty() {
            return Err(ClientError::InvalidArgument(
                "SetNTPServer: at least one NTP server host is required".into(),
            ));
        }
        self.require_credentials("SetNTPServer")?;

        let manual = hosts.iter().map(NtpHost::xml).collect::<String>();
        let set_ntp = format!(
            "<tds:SetNTP xmlns:tds=\"{TDS_NS}\" xmlns:tt=\"{TT_NS}\">\
             <tds:FromDHCP>false</tds:FromDHCP>{manual}</tds:SetNTP>"
        );
        self.device_call(&set_ntp).await?;

        let flip = format!(
            "<tds:SetSystemDateAndTime xmlns:tds=\"{TDS_NS}\">\
             <tds:DateTimeType>NTP</tds:DateTimeType>\
             <tds:DaylightSavings>false</tds:DaylightSavings></tds:SetSystemDateAndTime>"
        );
        if let Err(e) = self.device_call(&flip).await {
            return Err(ClientError::Transport(format!(
                "NTP server configured, but switching DateTimeType to NTP failed: {e}"
            )));
        }
        Ok(())
    }

    pub(crate) fn require_credentials(&self, op: &str) -> Result<(), ClientError> {
        if self.has_credentials() {
            Ok(())
        } else {
            Err(ClientError::NoCredentials(format!(
                "{op}: admin-level write needs credentials"
            )))
        }
    }
}

/// Lift the SystemDateAndTime out of a GetSystemDateAndTime response
/// (local-name walk — prefix dialects differ between firmwares).
pub(crate) fn parse_device_time(resp: &str) -> Result<DeviceTime, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    let mut utc = TimeComponents::default();
    let mut local = TimeComponents::default();
    let mut in_utc = false;
    let mut in_local = false;

    let mut date_time_type = String::new();
    let mut daylight = false;
    let mut tz = String::new();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                match super::local_name(&e).as_str() {
                    "UTCDateTime" => in_utc = true,
                    "LocalDateTime" => in_local = true,
                    _ => {}
                }
                stack.push(super::local_name(&e));
            }
            Ok(XmlEvent::Text(t)) => {
                let text = super::text_content(&t);
                let target = if in_utc && !in_local {
                    Some(&mut utc)
                } else if in_local && !in_utc {
                    Some(&mut local)
                } else {
                    None
                };
                if let Some(comp) = target {
                    match stack.last().map(String::as_str) {
                        Some("Year") => comp.year = text.parse().unwrap_or(0),
                        Some("Month") => comp.month = text.parse().unwrap_or(0),
                        Some("Day") => comp.day = text.parse().unwrap_or(0),
                        Some("Hour") => comp.hour = text.parse().unwrap_or(0),
                        Some("Minute") => comp.minute = text.parse().unwrap_or(0),
                        Some("Second") => comp.second = text.parse().unwrap_or(0),
                        _ => {}
                    }
                } else {
                    match stack.last().map(String::as_str) {
                        Some("DateTimeType") => date_time_type = text,
                        Some("DaylightSavings") => daylight = text == "true",
                        Some("TZ") => tz = text,
                        _ => {}
                    }
                }
            }
            Ok(XmlEvent::End(_)) => match stack.pop().unwrap_or_default().as_str() {
                "UTCDateTime" => in_utc = false,
                "LocalDateTime" => in_local = false,
                _ => {}
            },
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse GetSystemDateAndTime: {e}"
                )))
            }
        }
        buf.clear();
    }

    if utc.year < MINIMUM_USABLE_YEAR {
        return Err(ClientError::Parse(format!(
            "device returned no usable clock (year={})",
            utc.year
        )));
    }

    Ok(DeviceTime {
        utc: utc.stamp(),
        local: (local.year >= MINIMUM_USABLE_YEAR).then(|| local.stamp()),
        time_zone: tz,
        date_time_type,
        daylight_savings: daylight,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Field-shaped Hikvision-style answer: dual clocks, POSIX TZ, NTP
    /// mode (prefix dialects on purpose).
    const RESP: &str = r#"<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body>
        <GetSystemDateAndTimeResponse xmlns="http://www.onvif.org/ver10/device/wsdl">
        <SystemDateAndTime>
        <DateTimeType>NTP</DateTimeType>
        <DaylightSavings>false</DaylightSavings>
        <TimeZone><TZ>CST-8</TZ></TimeZone>
        <UTCDateTime><Time><Hour>7</Hour><Minute>42</Minute><Second>13</Second></Time>
        <Date><Year>2026</Year><Month>10</Month><Day>12</Day></Date></UTCDateTime>
        <LocalDateTime><Time><Hour>15</Hour><Minute>42</Minute><Second>13</Second></Time>
        <Date><Year>2026</Year><Month>10</Month><Day>12</Day></Date></LocalDateTime>
        </SystemDateAndTime></GetSystemDateAndTimeResponse>
        </Body></Envelope>"#;

    #[test]
    fn decodes_field_response() {
        let t = parse_device_time(RESP).unwrap();
        assert_eq!(t.utc.to_rfc3339(), "2026-10-12T07:42:13Z");
        assert_eq!(
            t.local.map(|l| l.to_rfc3339()).as_deref(),
            Some("2026-10-12T15:42:13Z")
        );
        assert_eq!(t.time_zone, "CST-8");
        assert_eq!(t.date_time_type, "NTP");
        assert!(!t.daylight_savings);
    }

    #[test]
    fn rejects_unusable_clock() {
        let bad = RESP.replace("<Year>2026</Year>", "<Year>1970</Year>");
        assert!(parse_device_time(&bad).is_err());

        let empty = "<Envelope><Body><GetSystemDateAndTimeResponse/></Body></Envelope>";
        assert!(parse_device_time(empty).is_err());
    }

    #[test]
    fn local_absent_is_none() {
        let no_local = RESP
            .split("<LocalDateTime>")
            .next()
            .unwrap()
            .trim_end_matches("</SystemDateAndTime></GetSystemDateAndTimeResponse>");
        let doc = format!(
            "{no_local}</SystemDateAndTime></GetSystemDateAndTimeResponse></Body></Envelope>"
        );
        let t = parse_device_time(&doc).unwrap();
        assert!(t.local.is_none());
        assert_eq!(t.utc.to_rfc3339(), "2026-10-12T07:42:13Z");
    }

    #[test]
    fn ntp_host_wire_shape() {
        assert_eq!(
            NtpHost::ipv4("10.1.1.53").xml(),
            "<tds:NTPManual><tt:Type>IPv4</tt:Type><tt:IPv4Address>10.1.1.53</tt:IPv4Address></tds:NTPManual>"
        );
        assert_eq!(
            NtpHost::dns("ntp.example.org").xml(),
            "<tds:NTPManual><tt:Type>DNS</tt:Type><tt:DNSname>ntp.example.org</tt:DNSname></tds:NTPManual>"
        );
    }
}
