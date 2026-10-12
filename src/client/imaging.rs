//! Imaging client family — the port of the onvif-go `imaging` package
//! (settings read/write, focus moves, move options, status, service
//! capabilities, imaging presets 18.12).

use super::device::{attr_get, esc, tail_is, walk_local, xml_bool, Step};
use super::{ClientError, SoapClient};

/// timg (imaging service; ver10 media/imaging lives in the media ns) and
/// tt (schema) namespaces.
const TIMG_NS: &str = "http://www.onvif.org/ver20/imaging/wsdl";
const TT_NS: &str = "http://www.onvif.org/ver10/schema";

fn xml_float(s: &str) -> f64 {
    s.trim().parse().unwrap_or(0.0)
}

/// Backlight compensation state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BacklightCompensation {
    pub mode: String,
    pub level: f64,
}

/// Exposure configuration.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Exposure {
    pub mode: String,
    pub priority: String,
    pub min_exposure_time: f64,
    pub max_exposure_time: f64,
    pub min_gain: f64,
    pub max_gain: f64,
    pub min_iris: f64,
    pub max_iris: f64,
    pub exposure_time: f64,
    pub gain: f64,
    pub iris: f64,
}

/// Focus configuration.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FocusConfiguration {
    pub auto_focus_mode: String,
    pub default_speed: f64,
    pub near_limit: f64,
    pub far_limit: f64,
}

/// Wide dynamic range state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WideDynamicRange {
    pub mode: String,
    pub level: f64,
}

/// White balance state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WhiteBalance {
    pub mode: String,
    pub cr_gain: f64,
    pub cb_gain: f64,
}

/// One imaging-settings snapshot (the fields devices actually vary).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImagingSettings {
    pub backlight_compensation: Option<BacklightCompensation>,
    pub brightness: Option<f64>,
    pub color_saturation: Option<f64>,
    pub contrast: Option<f64>,
    pub exposure: Option<Exposure>,
    pub focus: Option<FocusConfiguration>,
    pub sharpness: Option<f64>,
    pub wide_dynamic_range: Option<WideDynamicRange>,
    pub white_balance: Option<WhiteBalance>,
}

/// One focus move: exactly one arm.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FocusMove {
    pub absolute: Option<AbsoluteFocus>,
    pub relative: Option<RelativeFocus>,
    pub continuous: Option<ContinuousFocus>,
}

/// Absolute focus move.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AbsoluteFocus {
    pub position: f64,
    pub speed: Option<f64>,
}

/// Relative focus move.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RelativeFocus {
    pub distance: f64,
    pub speed: Option<f64>,
}

/// Continuous focus move.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContinuousFocus {
    pub speed: f64,
}

/// Focus move status (`IDLE`/`MOVING`/`UNKNOWN`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImagingStatus {
    pub focus_status: String,
    pub error: String,
}

/// One imaging preset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImagingPreset {
    pub token: String,
    pub name: String,
    pub type_: String,
}

fn timg_action(action: &str, inner: &str) -> String {
    if inner.is_empty() {
        return format!(
            "<timg:{action} xmlns:timg=\"{TIMG_NS}\" xmlns:tt=\"{TT_NS}\"></timg:{action}>"
        );
    }
    format!("<timg:{action} xmlns:timg=\"{TIMG_NS}\" xmlns:tt=\"{TT_NS}\">{inner}</timg:{action}>")
}

fn opt_float_xml(tag: &str, value: Option<f64>) -> String {
    // Go marshals *float64 pointers with omitempty: absent when nil.
    match value {
        Some(v) => format!("<tt:{tag}>{v}</tt:{tag}>"),
        None => String::new(),
    }
}

fn settings_group_xml(s: &ImagingSettings) -> String {
    // Only the set fields ride (Go's pointer/omitempty semantics).
    let mut inner = String::new();
    if let Some(blc) = &s.backlight_compensation {
        inner.push_str(&format!(
            "<tt:BacklightCompensation><tt:Mode>{}</tt:Mode><tt:Level>{}</tt:Level></tt:BacklightCompensation>",
            esc(&blc.mode), blc.level
        ));
    }
    inner.push_str(&opt_float_xml("Brightness", s.brightness));
    inner.push_str(&opt_float_xml("ColorSaturation", s.color_saturation));
    inner.push_str(&opt_float_xml("Contrast", s.contrast));
    if let Some(exp) = &s.exposure {
        inner.push_str(&format!(
            "<tt:Exposure><tt:Mode>{}</tt:Mode><tt:Priority>{}</tt:Priority>\
             <tt:MinExposureTime>{}</tt:MinExposureTime><tt:MaxExposureTime>{}</tt:MaxExposureTime>\
             <tt:MinGain>{}</tt:MinGain><tt:MaxGain>{}</tt:MaxGain>\
             <tt:MinIris>{}</tt:MinIris><tt:MaxIris>{}</tt:MaxIris>\
             <tt:ExposureTime>{}</tt:ExposureTime><tt:Gain>{}</tt:Gain><tt:Iris>{}</tt:Iris></tt:Exposure>",
            esc(&exp.mode), esc(&exp.priority), exp.min_exposure_time, exp.max_exposure_time,
            exp.min_gain, exp.max_gain, exp.min_iris, exp.max_iris,
            exp.exposure_time, exp.gain, exp.iris
        ));
    }
    if let Some(focus) = &s.focus {
        inner.push_str(&format!(
            "<tt:Focus><tt:AutoFocusMode>{}</tt:AutoFocusMode><tt:DefaultSpeed>{}</tt:DefaultSpeed>\
             <tt:NearLimit>{}</tt:NearLimit><tt:FarLimit>{}</tt:FarLimit></tt:Focus>",
            esc(&focus.auto_focus_mode), focus.default_speed, focus.near_limit, focus.far_limit
        ));
    }
    inner.push_str(&opt_float_xml("Sharpness", s.sharpness));
    if let Some(wdr) = &s.wide_dynamic_range {
        inner.push_str(&format!(
            "<tt:WideDynamicRange><tt:Mode>{}</tt:Mode><tt:Level>{}</tt:Level></tt:WideDynamicRange>",
            esc(&wdr.mode), wdr.level
        ));
    }
    if let Some(wb) = &s.white_balance {
        inner.push_str(&format!(
            "<tt:WhiteBalance><tt:Mode>{}</tt:Mode><tt:CrGain>{}</tt:CrGain><tt:CbGain>{}</tt:CbGain></tt:WhiteBalance>",
            esc(&wb.mode), wb.cr_gain, wb.cb_gain
        ));
    }
    format!("<timg:ImagingSettings>{inner}</timg:ImagingSettings>")
}

fn focus_move_xml(focus: &FocusMove) -> String {
    let mut inner = String::new();
    if let Some(abs) = &focus.absolute {
        let mut speed = String::new();
        if let Some(s) = abs.speed {
            speed = format!("<tt:Speed>{s}</tt:Speed>");
        }
        inner.push_str(&format!(
            "<tt:Absolute><tt:Position>{}</tt:Position>{speed}</tt:Absolute>",
            abs.position
        ));
    }
    if let Some(rel) = &focus.relative {
        let mut speed = String::new();
        if let Some(s) = rel.speed {
            speed = format!("<tt:Speed>{s}</tt:Speed>");
        }
        inner.push_str(&format!(
            "<tt:Relative><tt:Distance>{}</tt:Distance>{speed}</tt:Relative>",
            rel.distance
        ));
    }
    if let Some(cont) = &focus.continuous {
        inner.push_str(&format!(
            "<tt:Continuous><tt:Speed>{}</tt:Speed></tt:Continuous>",
            cont.speed
        ));
    }
    format!("<timg:Focus>{inner}</timg:Focus>")
}

impl SoapClient {
    /// Read the video source's imaging settings.
    pub async fn imaging_get_settings(
        &self,
        video_source_token: &str,
    ) -> Result<ImagingSettings, ClientError> {
        let inner = format!(
            "<timg:VideoSourceToken>{}</timg:VideoSourceToken>",
            esc(video_source_token)
        );
        let resp = self
            .device_call(&timg_action("GetImagingSettings", &inner))
            .await?;
        parse_imaging_settings(&resp)
    }

    /// Write imaging settings (`force_persistence` mirrors Go's flag).
    pub async fn imaging_set_settings(
        &self,
        video_source_token: &str,
        settings: &ImagingSettings,
        force_persistence: bool,
    ) -> Result<(), ClientError> {
        let mut inner = format!(
            "<timg:VideoSourceToken>{}</timg:VideoSourceToken>",
            esc(video_source_token)
        );
        inner.push_str(&settings_group_xml(settings));
        if force_persistence {
            inner.push_str("<timg:ForcePersistence>true</timg:ForcePersistence>");
        }
        self.device_call(&timg_action("SetImagingSettings", &inner))
            .await?;
        Ok(())
    }

    /// One focus move.
    pub async fn imaging_move(
        &self,
        video_source_token: &str,
        focus: &FocusMove,
    ) -> Result<(), ClientError> {
        let inner = format!(
            "<timg:VideoSourceToken>{}</timg:VideoSourceToken>{}",
            esc(video_source_token),
            focus_move_xml(focus)
        );
        self.device_call(&timg_action("Move", &inner)).await?;
        Ok(())
    }

    /// Stop the focus movement.
    pub async fn imaging_stop_focus(&self, video_source_token: &str) -> Result<(), ClientError> {
        let inner = format!(
            "<timg:VideoSourceToken>{}</timg:VideoSourceToken>",
            esc(video_source_token)
        );
        self.device_call(&timg_action("Stop", &inner)).await?;
        Ok(())
    }

    /// The focus movement status.
    pub async fn imaging_get_status(
        &self,
        video_source_token: &str,
    ) -> Result<ImagingStatus, ClientError> {
        let inner = format!(
            "<timg:VideoSourceToken>{}</timg:VideoSourceToken>",
            esc(video_source_token)
        );
        let resp = self.device_call(&timg_action("GetStatus", &inner)).await?;
        parse_imaging_status(&resp)
    }

    /// The imaging service capabilities (ImageStabilization only in the
    /// Go twin's decode; the flag answer is the common surface).
    pub async fn imaging_get_service_capabilities(&self) -> Result<bool, ClientError> {
        let resp = self
            .device_call(&timg_action("GetServiceCapabilities", ""))
            .await?;
        let mut stabilized = false;
        walk_local(&resp, "GetServiceCapabilitiesResponse", |step| {
            if let Step::Start { path, attrs } = step {
                if tail_is(path, &["GetServiceCapabilitiesResponse", "Capabilities"]) {
                    stabilized = attr_get(attrs, "ImageStabilization")
                        .map(xml_bool)
                        .unwrap_or(false);
                }
            }
            Ok(())
        })?;
        Ok(stabilized)
    }

    /// The video source's imaging presets (18.12).
    pub async fn imaging_get_presets(
        &self,
        video_source_token: &str,
    ) -> Result<Vec<ImagingPreset>, ClientError> {
        let inner = format!(
            "<timg:VideoSourceToken>{}</timg:VideoSourceToken>",
            esc(video_source_token)
        );
        let resp = self.device_call(&timg_action("GetPresets", &inner)).await?;
        parse_imaging_presets(&resp)
    }

    /// Activate an imaging preset (18.12).
    pub async fn imaging_set_current_preset(
        &self,
        video_source_token: &str,
        preset_token: &str,
    ) -> Result<(), ClientError> {
        let inner = format!(
            "<timg:VideoSourceToken>{}</timg:VideoSourceToken><timg:PresetToken>{}</timg:PresetToken>",
            esc(video_source_token), esc(preset_token)
        );
        self.device_call(&timg_action("SetCurrentPreset", &inner))
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Response decode
// ---------------------------------------------------------------------------

fn parse_imaging_settings(resp: &str) -> Result<ImagingSettings, ClientError> {
    let mut s = ImagingSettings::default();
    let mut in_blc = false;
    let mut in_exp = false;
    let mut in_focus = false;
    let mut in_wdr = false;
    let mut in_wb = false;

    walk_local(resp, "GetImagingSettingsResponse", |step| match step {
        Step::Start { path, .. } => {
            match path.last().map(String::as_str).unwrap_or("") {
                "BacklightCompensation" => in_blc = true,
                "Exposure" => in_exp = true,
                "Focus" => in_focus = true,
                "WideDynamicRange" => in_wdr = true,
                "WhiteBalance" => in_wb = true,
                _ => {}
            }
            Ok(())
        }
        Step::Text { path, text } => {
            let last = path.last().map(String::as_str).unwrap_or("");
            match last {
                "Mode" if in_blc => {
                    s.backlight_compensation
                        .get_or_insert_with(Default::default)
                        .mode = text.to_string()
                }
                "Level" if in_blc => {
                    s.backlight_compensation
                        .get_or_insert_with(Default::default)
                        .level = xml_float(text)
                }
                "Mode" if in_wdr => {
                    s.wide_dynamic_range
                        .get_or_insert_with(Default::default)
                        .mode = text.to_string()
                }
                "Level" if in_wdr => {
                    s.wide_dynamic_range
                        .get_or_insert_with(Default::default)
                        .level = xml_float(text)
                }
                "Mode" if in_wb => {
                    s.white_balance.get_or_insert_with(Default::default).mode = text.to_string()
                }
                "CrGain" if in_wb => {
                    s.white_balance.get_or_insert_with(Default::default).cr_gain = xml_float(text)
                }
                "CbGain" if in_wb => {
                    s.white_balance.get_or_insert_with(Default::default).cb_gain = xml_float(text)
                }
                _ if in_exp => {
                    let exp = s.exposure.get_or_insert_with(Default::default);
                    match last {
                        "Mode" => exp.mode = text.to_string(),
                        "Priority" => exp.priority = text.to_string(),
                        "MinExposureTime" => exp.min_exposure_time = xml_float(text),
                        "MaxExposureTime" => exp.max_exposure_time = xml_float(text),
                        "MinGain" => exp.min_gain = xml_float(text),
                        "MaxGain" => exp.max_gain = xml_float(text),
                        "MinIris" => exp.min_iris = xml_float(text),
                        "MaxIris" => exp.max_iris = xml_float(text),
                        "ExposureTime" => exp.exposure_time = xml_float(text),
                        "Gain" => exp.gain = xml_float(text),
                        "Iris" => exp.iris = xml_float(text),
                        _ => {}
                    }
                }
                _ if in_focus => {
                    let focus = s.focus.get_or_insert_with(Default::default);
                    match last {
                        "AutoFocusMode" => focus.auto_focus_mode = text.to_string(),
                        "DefaultSpeed" => focus.default_speed = xml_float(text),
                        "NearLimit" => focus.near_limit = xml_float(text),
                        "FarLimit" => focus.far_limit = xml_float(text),
                        _ => {}
                    }
                }
                _ => match last {
                    "Brightness" => s.brightness = Some(xml_float(text)),
                    "ColorSaturation" => s.color_saturation = Some(xml_float(text)),
                    "Contrast" => s.contrast = Some(xml_float(text)),
                    "Sharpness" => s.sharpness = Some(xml_float(text)),
                    _ => {}
                },
            }
            Ok(())
        }
        Step::End { path } => {
            match path.last().map(String::as_str).unwrap_or("") {
                "BacklightCompensation" => in_blc = false,
                "Exposure" => in_exp = false,
                "Focus" => in_focus = false,
                "WideDynamicRange" => in_wdr = false,
                "WhiteBalance" => in_wb = false,
                _ => {}
            }
            Ok(())
        }
    })?;
    Ok(s)
}

fn parse_imaging_status(resp: &str) -> Result<ImagingStatus, ClientError> {
    let mut st = ImagingStatus::default();
    walk_local(resp, "GetStatusResponse", |step| {
        if let Step::Text { path, text } = step {
            match path.last().map(String::as_str).unwrap_or("") {
                "Status" if tail_is(path, &["GetStatusResponse", "Status"]) => {
                    st.focus_status = text.to_string()
                }
                "Error" => st.error = text.to_string(),
                _ => {}
            }
        }
        Ok(())
    })?;
    Ok(st)
}

fn parse_imaging_presets(resp: &str) -> Result<Vec<ImagingPreset>, ClientError> {
    let mut out: Vec<ImagingPreset> = Vec::new();
    walk_local(resp, "GetPresetsResponse", |step| {
        match step {
            Step::Start { path, attrs } if tail_is(path, &["GetPresetsResponse", "Preset"]) => {
                out.push(ImagingPreset {
                    token: attr_get(attrs, "token").unwrap_or("").to_string(),
                    name: String::new(),
                    type_: String::new(),
                });
            }
            Step::Text { path, text }
                if tail_is(path, &["GetPresetsResponse", "Preset", "Name"]) =>
            {
                if let Some(last) = out.last_mut() {
                    last.name = text.to_string();
                }
            }
            Step::Text { path, text }
                if tail_is(path, &["GetPresetsResponse", "Preset", "Type"]) =>
            {
                if let Some(last) = out.last_mut() {
                    last.type_ = text.to_string();
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_goldens() {
        assert_eq!(
            timg_action("GetImagingSettings", "<timg:VideoSourceToken>src-1</timg:VideoSourceToken>"),
            "<timg:GetImagingSettings xmlns:timg=\"http://www.onvif.org/ver20/imaging/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><timg:VideoSourceToken>src-1</timg:VideoSourceToken></timg:GetImagingSettings>"
        );

        let focus = FocusMove {
            absolute: Some(AbsoluteFocus {
                position: 0.5,
                speed: Some(0.9),
            }),
            ..Default::default()
        };
        assert_eq!(
            focus_move_xml(&focus),
            "<timg:Focus><tt:Absolute><tt:Position>0.5</tt:Position><tt:Speed>0.9</tt:Speed></tt:Absolute></timg:Focus>"
        );

        let settings = ImagingSettings {
            brightness: Some(64.0),
            ..Default::default()
        };
        assert_eq!(
            settings_group_xml(&settings),
            "<timg:ImagingSettings><tt:Brightness>64</tt:Brightness></timg:ImagingSettings>"
        );
    }

    #[test]
    fn decodes_settings() {
        let resp = r#"<GetImagingSettingsResponse><ImagingSettings>
            <Brightness>64</Brightness><Contrast>32</Contrast><Sharpness>8</Sharpness>
            <BacklightCompensation><Mode>OFF</Mode><Level>0</Level></BacklightCompensation>
            <Focus><AutoFocusMode>AUTO</AutoFocusMode><DefaultSpeed>0.5</DefaultSpeed></Focus>
            <WhiteBalance><Mode>AUTO</Mode><CrGain>1</CrGain><CbGain>1</CbGain></WhiteBalance>
            </ImagingSettings></GetImagingSettingsResponse>"#;
        let s = parse_imaging_settings(resp).unwrap();
        assert_eq!(s.brightness, Some(64.0));
        assert_eq!(s.contrast, Some(32.0));
        assert_eq!(s.backlight_compensation.as_ref().unwrap().mode, "OFF");
        assert_eq!(s.focus.as_ref().unwrap().auto_focus_mode, "AUTO");
        assert_eq!(s.white_balance.as_ref().unwrap().mode, "AUTO");
    }

    #[test]
    fn decodes_presets_and_status() {
        let presets = parse_imaging_presets(
            r#"<GetPresetsResponse><Preset token="ip1"><Name>Default</Name><Type>None</Type></Preset></GetPresetsResponse>"#,
        )
        .unwrap();
        assert_eq!(presets.len(), 1);
        assert_eq!(
            (presets[0].token.as_str(), presets[0].name.as_str()),
            ("ip1", "Default")
        );

        let st =
            parse_imaging_status(r#"<GetStatusResponse><Status>IDLE</Status></GetStatusResponse>"#)
                .unwrap();
        assert_eq!(st.focus_status, "IDLE");
    }
}
