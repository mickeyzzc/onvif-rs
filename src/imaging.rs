//! ONVIF Imaging Service handlers (GetImagingSettings, SetImagingSettings,
//! GetOptions).
//!
//! Each handler implements [`OnvifActionHandler`] and bridges ONVIF imaging
//! parameter names to the host's normalized `[0.0, 1.0]` values via the
//! [`ImagingParams`] seam.

use std::sync::Arc;

use async_trait::async_trait;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Reader;
use quick_xml::Writer;

use crate::namespaces::{IMAGING_SERVICE, SCHEMAS};
use crate::server::OnvifActionHandler;
use crate::server::OnvifServer;
use crate::types::{serialize_soap_response, OnvifError, RequestInfo};

// ---------------------------------------------------------------------------
// Host seam
// ---------------------------------------------------------------------------

/// Errors surfaced by an [`ImagingParams`] implementation.
#[derive(Debug, Clone)]
pub enum ImagingParamError {
    /// The parameter name is not recognised.
    InvalidName(String),
    /// The requested value falls outside the valid range.
    OutOfRange {
        /// The value that was attempted.
        value: f64,
        /// Minimum allowed value.
        min: f64,
        /// Maximum allowed value.
        max: f64,
    },
    /// Backing store / device I/O failure.
    Io(String),
}

impl std::fmt::Display for ImagingParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImagingParamError::InvalidName(name) => write!(f, "invalid parameter name: {name}"),
            ImagingParamError::OutOfRange { value, min, max } => {
                write!(f, "value {value} out of range [{min}, {max}]")
            }
            ImagingParamError::Io(msg) => write!(f, "parameter I/O error: {msg}"),
        }
    }
}

/// Source of imaging parameters for the Imaging service — implemented by the
/// host over its camera parameter manager (e.g. V4L2 controls normalized to
/// `[0.0, 1.0]`).
pub trait ImagingParams: Send + Sync {
    /// Current value of a parameter by ONVIF name (e.g. "Brightness").
    fn get_param(&self, name: &str) -> Result<f64, ImagingParamError>;
    /// Set a parameter by ONVIF name to a normalized `[0.0, 1.0]` value.
    fn set_param(&self, name: &str, value: f64) -> Result<(), ImagingParamError>;
    /// Exposure mode reported by GetImagingSettings (`"AUTO"` or
    /// `"MANUAL"`). Default: `"AUTO"` (not backed by host state).
    fn exposure_mode(&self) -> String {
        "AUTO".to_string()
    }
    /// White-balance mode reported by GetImagingSettings. Default: `"AUTO"`
    /// (the historical wire value; not backed by host state).
    fn white_balance_mode(&self) -> String {
        "AUTO".to_string()
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Register the three Imaging service action handlers on the given server.
///
/// Each handler shares the same parameter source via an [`Arc`].
pub fn register_imaging_actions(server: &mut OnvifServer, pm: Arc<dyn ImagingParams>) {
    let pm2 = pm.clone();
    let pm3 = pm.clone();

    server.register_handler(
        "GetImagingSettings",
        Box::new(GetImagingSettingsHandler { pm }),
    );
    server.register_handler(
        "SetImagingSettings",
        Box::new(SetImagingSettingsHandler { pm: pm2 }),
    );
    server.register_handler("GetOptions", Box::new(GetOptionsHandler { pm: pm3 }));
}

// ---------------------------------------------------------------------------
// Handler structs
// ---------------------------------------------------------------------------

struct GetImagingSettingsHandler {
    pm: Arc<dyn ImagingParams>,
}

struct SetImagingSettingsHandler {
    pm: Arc<dyn ImagingParams>,
}

#[allow(dead_code)]
struct GetOptionsHandler {
    pm: Arc<dyn ImagingParams>,
}

#[allow(dead_code)]
impl GetImagingSettingsHandler {
    fn new(pm: Arc<dyn ImagingParams>) -> Self {
        Self { pm }
    }
}

#[allow(dead_code)]
impl SetImagingSettingsHandler {
    fn new(pm: Arc<dyn ImagingParams>) -> Self {
        Self { pm }
    }
}

#[allow(dead_code)]
impl GetOptionsHandler {
    fn new(pm: Arc<dyn ImagingParams>) -> Self {
        Self { pm }
    }
}

// ---------------------------------------------------------------------------
// GetImagingSettings
// ---------------------------------------------------------------------------

#[async_trait]
impl OnvifActionHandler for GetImagingSettingsHandler {
    async fn handle(&self, _body: &str, _info: &RequestInfo) -> Result<String, OnvifError> {
        let brightness = self
            .pm
            .get_param("Brightness")
            .map_err(|e| OnvifError::Internal(format!("get brightness: {e}")))?;
        let contrast = self
            .pm
            .get_param("Contrast")
            .map_err(|e| OnvifError::Internal(format!("get contrast: {e}")))?;
        let saturation = self
            .pm
            .get_param("Saturation")
            .map_err(|e| OnvifError::Internal(format!("get saturation: {e}")))?;
        let sharpness = self
            .pm
            .get_param("Sharpness")
            .map_err(|e| OnvifError::Internal(format!("get sharpness: {e}")))?;

        let body_xml = build_get_imaging_settings_xml(
            brightness,
            contrast,
            saturation,
            sharpness,
            &self.pm.exposure_mode(),
            &self.pm.white_balance_mode(),
        );
        Ok(serialize_soap_response(&body_xml))
    }
}

fn build_get_imaging_settings_xml(
    brightness: f64,
    contrast: f64,
    saturation: f64,
    sharpness: f64,
    exposure_mode: &str,
    white_balance_mode: &str,
) -> String {
    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

    let mut root = BytesStart::new("timg:GetImagingSettingsResponse");
    root.push_attribute(("xmlns:timg", IMAGING_SERVICE));
    root.push_attribute(("xmlns:tt", SCHEMAS));
    w.write_event(Event::Start(root)).unwrap_or_default();

    w.write_event(Event::Start(BytesStart::new("timg:Settings")))
        .unwrap_or_default();

    write_value_attr(&mut w, "tt:Brightness", brightness);
    write_value_attr(&mut w, "tt:Contrast", contrast);
    write_value_attr(&mut w, "tt:ColorSaturation", saturation);
    write_value_attr(&mut w, "tt:Sharpness", sharpness);

    // Exposure / WhiteBalance modes come from the host seam (AUTO defaults).
    w.write_event(Event::Start(BytesStart::new("tt:Exposure")))
        .unwrap_or_default();
    write_text(&mut w, "tt:Mode", exposure_mode);
    w.write_event(Event::End(BytesEnd::new("tt:Exposure")))
        .unwrap_or_default();

    w.write_event(Event::Start(BytesStart::new("tt:WhiteBalance")))
        .unwrap_or_default();
    write_text(&mut w, "tt:Mode", white_balance_mode);
    w.write_event(Event::End(BytesEnd::new("tt:WhiteBalance")))
        .unwrap_or_default();

    w.write_event(Event::End(BytesEnd::new("timg:Settings")))
        .unwrap_or_default();
    w.write_event(Event::End(BytesEnd::new("timg:GetImagingSettingsResponse")))
        .unwrap_or_default();

    String::from_utf8(w.into_inner()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// SetImagingSettings
// ---------------------------------------------------------------------------

#[async_trait]
impl OnvifActionHandler for SetImagingSettingsHandler {
    async fn handle(&self, body: &str, _info: &RequestInfo) -> Result<String, OnvifError> {
        let parsed = parse_settings(body)
            .map_err(|e| OnvifError::InvalidXml(format!("parsing SetImagingSettings: {e}")))?;

        if let Some(val) = parsed.brightness {
            self.pm
                .set_param("Brightness", val)
                .map_err(|e| OnvifError::Internal(format!("set brightness: {e}")))?;
        }
        if let Some(val) = parsed.contrast {
            self.pm
                .set_param("Contrast", val)
                .map_err(|e| OnvifError::Internal(format!("set contrast: {e}")))?;
        }
        if let Some(val) = parsed.saturation {
            self.pm
                .set_param("Saturation", val)
                .map_err(|e| OnvifError::Internal(format!("set saturation: {e}")))?;
        }
        if let Some(val) = parsed.sharpness {
            self.pm
                .set_param("Sharpness", val)
                .map_err(|e| OnvifError::Internal(format!("set sharpness: {e}")))?;
        }

        // ExposureTime is not yet exposed as a separate ParamManager parameter.
        // If the client sends Exposure with Mode=MANUAL and ExposureTime, we
        // ignore the time value for now.
        if parsed.exposure_mode.as_deref() == Some("MANUAL") {
            if let Some(_time) = parsed.exposure_time {
                // ExposureTime param not available in current ParamManager;
                // silently skipped.
            }
        }

        let body_xml = build_set_imaging_settings_response_xml();
        Ok(serialize_soap_response(&body_xml))
    }
}

fn build_set_imaging_settings_response_xml() -> String {
    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

    let mut root = BytesStart::new("timg:SetImagingSettingsResponse");
    root.push_attribute(("xmlns:timg", IMAGING_SERVICE));
    w.write_event(Event::Empty(root)).unwrap_or_default();

    String::from_utf8(w.into_inner()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// GetOptions
// ---------------------------------------------------------------------------

#[async_trait]
impl OnvifActionHandler for GetOptionsHandler {
    async fn handle(&self, _body: &str, _info: &RequestInfo) -> Result<String, OnvifError> {
        let body_xml = build_get_options_xml();
        Ok(serialize_soap_response(&body_xml))
    }
}

fn build_get_options_xml() -> String {
    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

    let mut root = BytesStart::new("timg:GetOptionsResponse");
    root.push_attribute(("xmlns:timg", IMAGING_SERVICE));
    root.push_attribute(("xmlns:tt", SCHEMAS));
    w.write_event(Event::Start(root)).unwrap_or_default();

    w.write_event(Event::Start(BytesStart::new("timg:ImagingOptions")))
        .unwrap_or_default();

    // Brightness, Contrast, ColorSaturation, Sharpness — all [0, 1]
    for param in &[
        "tt:Brightness",
        "tt:Contrast",
        "tt:ColorSaturation",
        "tt:Sharpness",
    ] {
        write_range(&mut w, param, 0.0, 1.0);
    }

    // Exposure options
    w.write_event(Event::Start(BytesStart::new("tt:Exposure")))
        .unwrap_or_default();
    write_text(&mut w, "tt:MinExposureTime", "0");
    write_text(&mut w, "tt:MaxExposureTime", "1");
    write_text(&mut w, "tt:MinGain", "0");
    write_text(&mut w, "tt:MaxGain", "1");
    w.write_event(Event::End(BytesEnd::new("tt:Exposure")))
        .unwrap_or_default();

    // WhiteBalance options
    w.write_event(Event::Start(BytesStart::new("tt:WhiteBalance")))
        .unwrap_or_default();

    // Mode with Auto/Manual boolean attributes
    let mut mode = BytesStart::new("tt:Mode");
    mode.push_attribute(("Auto", "true"));
    mode.push_attribute(("Manual", "true"));
    w.write_event(Event::Empty(mode)).unwrap_or_default();

    write_range(&mut w, "tt:CrGain", 0.0, 1.0);
    write_range(&mut w, "tt:CbGain", 0.0, 1.0);

    w.write_event(Event::End(BytesEnd::new("tt:WhiteBalance")))
        .unwrap_or_default();

    w.write_event(Event::End(BytesEnd::new("timg:ImagingOptions")))
        .unwrap_or_default();
    w.write_event(Event::End(BytesEnd::new("timg:GetOptionsResponse")))
        .unwrap_or_default();

    String::from_utf8(w.into_inner()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// XML helpers
// ---------------------------------------------------------------------------

/// Write `<name>text</name>`.
fn write_text(w: &mut Writer<Vec<u8>>, name: &str, text: &str) {
    w.write_event(Event::Start(BytesStart::new(name)))
        .unwrap_or_default();
    w.write_event(Event::Text(BytesText::new(text)))
        .unwrap_or_default();
    w.write_event(Event::End(BytesEnd::new(name)))
        .unwrap_or_default();
}

/// Write `<name Value="val"/>`.
fn write_value_attr(w: &mut Writer<Vec<u8>>, name: &str, val: f64) {
    let mut elem = BytesStart::new(name);
    let val_str = format!("{val}");
    elem.push_attribute(("Value", val_str.as_str()));
    w.write_event(Event::Empty(elem)).unwrap_or_default();
}

/// Write `<name><Min>x</Min><Max>y</Max></name>`.
fn write_range(w: &mut Writer<Vec<u8>>, name: &str, min: f64, max: f64) {
    w.write_event(Event::Start(BytesStart::new(name)))
        .unwrap_or_default();
    write_text(w, "tt:Min", &format!("{min}"));
    write_text(w, "tt:Max", &format!("{max}"));
    w.write_event(Event::End(BytesEnd::new(name)))
        .unwrap_or_default();
}

// ---------------------------------------------------------------------------
// SetImagingSettings XML parsing (namespace-agnostic)
// ---------------------------------------------------------------------------

/// Values parsed from a `SetImagingSettings` request body.
#[derive(Debug, Default, PartialEq)]
struct ParsedSettings {
    brightness: Option<f64>,
    contrast: Option<f64>,
    saturation: Option<f64>,
    sharpness: Option<f64>,
    exposure_mode: Option<String>,
    exposure_time: Option<f64>,
}

/// Parse a `SetImagingSettings` SOAP body, matching element names by local
/// name only (namespace-agnostic).
fn parse_settings(body: &str) -> Result<ParsedSettings, String> {
    let mut reader = Reader::from_str(body);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut result = ParsedSettings::default();

    // State: what element we are currently inside
    #[derive(Default)]
    struct State {
        in_settings: bool,  // inside <Settings>
        in_exposure: bool,  // inside <Exposure>
        text_field: String, // "Mode" or "ExposureTime" when inside one
    }

    let mut st = State::default();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let elem_name = e.name();
                let local = local_name(elem_name.as_ref());
                if local == "Settings" {
                    st.in_settings = true;
                } else if st.in_settings && local == "Exposure" {
                    st.in_exposure = true;
                } else if st.in_exposure {
                    st.text_field = local.to_string();
                }

                // Some clients may use non-self-closing tags with Value attr
                if st.in_settings && !st.in_exposure {
                    if let Some(val) = attr_value_f64(&e, "Value") {
                        set_float_param(&mut result, local, val);
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                let elem_name = e.name();
                let local = local_name(elem_name.as_ref());
                // Self-closing param inside <Settings>
                if st.in_settings {
                    if let Some(val) = attr_value_f64(&e, "Value") {
                        set_float_param(&mut result, local, val);
                    }
                }
            }
            Ok(Event::Text(e)) => match e.unescape() {
                Ok(text) => {
                    if st.in_exposure && !st.text_field.is_empty() {
                        match st.text_field.as_str() {
                            "Mode" => {
                                result.exposure_mode = Some(text.as_ref().to_string());
                            }
                            "ExposureTime" => {
                                if let Ok(v) = text.as_ref().parse::<f64>() {
                                    result.exposure_time = Some(v);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => return Err(format!("XML unescape error: {e}")),
            },
            Ok(Event::End(e)) => {
                let elem_name = e.name();
                let local = local_name(elem_name.as_ref());
                match local {
                    "Settings" => st.in_settings = false,
                    "Exposure" => {
                        st.in_exposure = false;
                        st.text_field.clear();
                    }
                    _ => {
                        if st.in_exposure {
                            st.text_field.clear();
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    Ok(result)
}

/// Extract the local name from a qualified XML name (e.g. `timg:Settings` ->
/// `Settings`, `Brightness` -> `Brightness`).
fn local_name(name: &[u8]) -> &str {
    let qname = std::str::from_utf8(name).unwrap_or("");
    qname.rsplit(':').next().unwrap_or(qname)
}

fn attr_value_f64(e: &BytesStart, attr: &str) -> Option<f64> {
    for a in e.attributes().flatten() {
        let key = std::str::from_utf8(a.key.as_ref()).unwrap_or("");
        let local = key.rsplit(':').next().unwrap_or(key);
        if local == attr {
            let val_str = std::str::from_utf8(&a.value).unwrap_or("");
            return val_str.parse::<f64>().ok();
        }
    }
    None
}

/// Dispatch a float parameter value into the parsed result by local element
/// name.
fn set_float_param(result: &mut ParsedSettings, name: &str, val: f64) {
    match name {
        "Brightness" => result.brightness = Some(val),
        "Contrast" => result.contrast = Some(val),
        "ColorSaturation" => result.saturation = Some(val),
        "Sharpness" => result.sharpness = Some(val),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory parameter source standing in for the host ParamManager:
    /// values live in `[0.0, 1.0]`, out-of-range writes are rejected, and
    /// unset parameters read back the 0.5 mid-scale default.
    struct MockParams {
        values: Mutex<HashMap<String, f64>>,
    }

    impl MockParams {
        fn new() -> Self {
            MockParams {
                values: Mutex::new(HashMap::new()),
            }
        }
    }

    impl ImagingParams for MockParams {
        fn get_param(&self, name: &str) -> Result<f64, ImagingParamError> {
            Ok(self
                .values
                .lock()
                .unwrap()
                .get(name)
                .copied()
                .unwrap_or(0.5))
        }
        fn set_param(&self, name: &str, value: f64) -> Result<(), ImagingParamError> {
            if !(0.0..=1.0).contains(&value) {
                return Err(ImagingParamError::OutOfRange {
                    value,
                    min: 0.0,
                    max: 1.0,
                });
            }
            self.values.lock().unwrap().insert(name.to_string(), value);
            Ok(())
        }
    }

    fn make_pm() -> Arc<dyn ImagingParams> {
        Arc::new(MockParams::new())
    }

    fn dummy_info() -> RequestInfo {
        RequestInfo {
            client_ip: "127.0.0.1".into(),
            server_ip: "127.0.0.1".into(),
            auth_result: crate::types::AuthResult::default(),
        }
    }

    // ── GetImagingSettings ──

    #[tokio::test]
    async fn test_get_imaging_settings_response() {
        let pm = make_pm();
        let handler = GetImagingSettingsHandler::new(pm.clone());

        // Set known values first
        pm.set_param("Brightness", 0.25).unwrap();
        pm.set_param("Contrast", 0.75).unwrap();
        pm.set_param("Saturation", 0.5).unwrap();
        pm.set_param("Sharpness", 0.9).unwrap();

        let result = handler
            .handle("<GetImagingSettings/>", &dummy_info())
            .await
            .unwrap();

        // Is a valid SOAP envelope
        assert!(result.contains("soap:Envelope"));
        assert!(result.contains("soap:Body"));

        // Contains ONVIF namespaces
        assert!(result.contains(IMAGING_SERVICE));
        assert!(result.contains(SCHEMAS));

        // Contains the response root and settings
        assert!(result.contains("GetImagingSettingsResponse"));
        assert!(result.contains("timg:Settings"));

        // Each parameter appears with its value (the in-memory mock source
        // round-trips values exactly; a real device source quantizes)
        assert!(result.contains("tt:Brightness"));
        assert!(result.contains(r#"Value="0.25""#));
        assert!(result.contains("tt:Contrast"));
        assert!(result.contains(r#"Value="0.75""#));
        assert!(result.contains("tt:ColorSaturation"));
        assert!(result.contains(r#"Value="0.5""#));
        assert!(result.contains("tt:Sharpness"));
        assert!(result.contains(r#"Value="0.9""#));

        // Exposure and WhiteBalance modes
        assert!(result.contains("tt:Exposure"));
        assert!(result.contains("<tt:Mode>AUTO</tt:Mode>"));
        assert!(result.contains("tt:WhiteBalance"));
    }

    // ── SetImagingSettings — validation ──

    #[tokio::test]
    async fn test_set_imaging_settings_brightness() {
        let pm = make_pm();
        let handler = SetImagingSettingsHandler::new(pm.clone());

        let body = r#"<SetImagingSettings xmlns="http://www.onvif.org/ver20/imaging/wsdl">
            <Settings>
                <Brightness Value="0.75"/>
            </Settings>
        </SetImagingSettings>"#;

        let result = handler.handle(body, &dummy_info()).await.unwrap();
        assert!(result.contains("SetImagingSettingsResponse"));
        assert!(result.contains(IMAGING_SERVICE));

        // Verify the value was actually set
        let val = pm.get_param("Brightness").unwrap();
        assert!((val - 0.75).abs() < 0.01, "expected 0.75, got {val}");
    }

    #[tokio::test]
    async fn test_set_imaging_settings_validation() {
        let pm = make_pm();
        let handler = SetImagingSettingsHandler::new(pm.clone());

        // Out-of-range value should be rejected
        let body = r#"<SetImagingSettings>
            <Settings>
                <Brightness Value="2.5"/>
            </Settings>
        </SetImagingSettings>"#;

        let result = handler.handle(body, &dummy_info()).await;
        assert!(result.is_err(), "out-of-range should fail");

        // Value unchanged
        let val = pm.get_param("Brightness").unwrap();
        assert!((val - 0.5).abs() < 0.01, "expected default ~0.5, got {val}");
    }

    #[tokio::test]
    async fn test_set_imaging_settings_multiple_params() {
        let pm = make_pm();
        let handler = SetImagingSettingsHandler::new(pm.clone());

        let body = r#"<SetImagingSettings>
            <Settings>
                <Brightness Value="0.2"/>
                <Contrast Value="0.8"/>
                <ColorSaturation Value="0.3"/>
                <Sharpness Value="0.6"/>
            </Settings>
        </SetImagingSettings>"#;

        handler.handle(body, &dummy_info()).await.unwrap();

        assert!((pm.get_param("Brightness").unwrap() - 0.2).abs() < 0.01);
        assert!((pm.get_param("Contrast").unwrap() - 0.8).abs() < 0.01);
        assert!((pm.get_param("Saturation").unwrap() - 0.3).abs() < 0.01);
        assert!((pm.get_param("Sharpness").unwrap() - 0.6).abs() < 0.01);
    }

    // ── SetImagingSettings — malformed XML ──

    #[tokio::test]
    async fn test_set_imaging_settings_malformed() {
        let pm = make_pm();
        let handler = SetImagingSettingsHandler::new(pm.clone());

        // Truly invalid XML (bad entity reference)
        let body = "<SetImagingSettings>&some;</SetImagingSettings>";
        let result = handler.handle(body, &dummy_info()).await;
        assert!(result.is_err(), "malformed XML should fail");
    }

    // ── GetOptions ──

    #[tokio::test]
    async fn test_get_options_ranges() {
        let pm = make_pm();
        let handler = GetOptionsHandler::new(pm);

        let result = handler
            .handle("<GetOptions/>", &dummy_info())
            .await
            .unwrap();

        assert!(result.contains("GetOptionsResponse"));
        assert!(result.contains("timg:ImagingOptions"));

        // Each basic param has [0, 1] range
        for name in &[
            "tt:Brightness",
            "tt:Contrast",
            "tt:ColorSaturation",
            "tt:Sharpness",
        ] {
            assert!(result.contains(name), "{name} should appear in GetOptions");
        }

        // Verify min/max values
        assert!(result.contains("<tt:Min>0</tt:Min>"), "should have Min=0");
        assert!(result.contains("<tt:Max>1</tt:Max>"), "should have Max=1");

        // Exposure options
        assert!(result.contains("tt:MinExposureTime"));
        assert!(result.contains("tt:MaxExposureTime"));
        assert!(result.contains("tt:MinGain"));
        assert!(result.contains("tt:MaxGain"));

        // WhiteBalance with Auto/Manual attributes
        assert!(result.contains("tt:WhiteBalance"));
        assert!(result.contains(r#"Auto="true""#));
        assert!(result.contains(r#"Manual="true""#));
        assert!(result.contains("tt:CrGain"));
        assert!(result.contains("tt:CbGain"));
    }

    // ── ParseSettings unit tests ──

    #[test]
    fn test_parse_settings_all_params() {
        let xml = r#"<SetImagingSettings xmlns="http://www.onvif.org/ver20/imaging/wsdl">
            <Settings>
                <Brightness Value="0.1"/>
                <Contrast Value="0.2"/>
                <ColorSaturation Value="0.3"/>
                <Sharpness Value="0.4"/>
                <Exposure>
                    <Mode>AUTO</Mode>
                </Exposure>
            </Settings>
        </SetImagingSettings>"#;

        let parsed = parse_settings(xml).unwrap();
        assert_eq!(parsed.brightness, Some(0.1));
        assert_eq!(parsed.contrast, Some(0.2));
        assert_eq!(parsed.saturation, Some(0.3));
        assert_eq!(parsed.sharpness, Some(0.4));
        assert_eq!(parsed.exposure_mode.as_deref(), Some("AUTO"));
    }

    #[test]
    fn test_parse_settings_partial() {
        let xml = r#"<SetImagingSettings>
            <Settings>
                <Brightness Value="0.9"/>
            </Settings>
        </SetImagingSettings>"#;

        let parsed = parse_settings(xml).unwrap();
        assert_eq!(parsed.brightness, Some(0.9));
        assert_eq!(parsed.contrast, None);
        assert_eq!(parsed.saturation, None);
        assert_eq!(parsed.sharpness, None);
        assert_eq!(parsed.exposure_mode, None);
    }

    #[test]
    fn test_parse_settings_empty() {
        let xml = "<SetImagingSettings><Settings></Settings></SetImagingSettings>";
        let parsed = parse_settings(xml).unwrap();
        assert_eq!(parsed, ParsedSettings::default());
    }

    #[test]
    fn test_parse_settings_no_settings_element() {
        let xml = "<SomeOtherElement/>";
        let parsed = parse_settings(xml).unwrap();
        assert_eq!(parsed, ParsedSettings::default());
    }

    #[test]
    fn test_parse_settings_with_namespace_prefix() {
        let xml = r#"<timg:SetImagingSettings xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl">
            <timg:Settings>
                <tt:Brightness xmlns:tt="http://www.onvif.org/ver10/schema" Value="0.5"/>
                <tt:Contrast Value="0.6"/>
            </timg:Settings>
        </timg:SetImagingSettings>"#;

        let parsed = parse_settings(xml).unwrap();
        assert_eq!(parsed.brightness, Some(0.5));
        assert_eq!(parsed.contrast, Some(0.6));
    }

    // ── XML builder round-trips ──

    #[test]
    fn test_build_get_imaging_settings_xml_well_formed() {
        let xml = build_get_imaging_settings_xml(0.1, 0.2, 0.3, 0.4, "AUTO", "AUTO");
        let mut reader = Reader::from_str(&xml);
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Err(e) => panic!("XML parse error: {e}"),
                _ => {}
            }
            buf.clear();
        }
        assert!(xml.contains("GetImagingSettingsResponse"));
        assert!(xml.contains("tt:Brightness"));
    }

    #[test]
    fn test_build_get_options_xml_well_formed() {
        let xml = build_get_options_xml();
        let mut reader = Reader::from_str(&xml);
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Err(e) => panic!("XML parse error: {e}"),
                _ => {}
            }
            buf.clear();
        }
        assert!(xml.contains("GetOptionsResponse"));
    }
}
