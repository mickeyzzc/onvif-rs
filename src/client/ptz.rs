//! PTZ client family — the port of the onvif-go `ptz` package (movement,
//! status, presets, home position, configurations, nodes, auxiliary
//! commands, service capabilities).

use super::device::{attr_get, esc, tail_is, walk_local, xml_bool, xml_int, Step};
use super::{ClientError, SoapClient};

/// tptz (PTZ service) and tt (schema) namespaces.
const PTZ_NS: &str = "http://www.onvif.org/ver20/ptz/wsdl";
const TT_NS: &str = "http://www.onvif.org/ver10/schema";

fn xml_float(s: &str) -> f64 {
    s.trim().parse().unwrap_or(0.0)
}

/// A 2D pan/tilt vector (`x`/`y` attributes, space-qualified).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Vector2D {
    pub x: f64,
    pub y: f64,
    pub space: String,
}

/// A 1D zoom vector (`x` attribute).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Vector1D {
    pub x: f64,
    pub space: String,
}

/// A PTZ position/translation.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PtzVector {
    pub pan_tilt: Option<Vector2D>,
    pub zoom: Option<Vector1D>,
}

/// A PTZ speed.
pub type PtzSpeed = PtzVector;

/// Movement status strings (`IDLE`, `MOVING`, `UNKNOWN`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MoveStatus {
    pub pan_tilt: String,
    pub zoom: String,
}

/// One PTZ status snapshot.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PtzStatus {
    pub position: PtzVector,
    pub move_status: Option<MoveStatus>,
    pub error: String,
    pub utc_time: String,
}

/// One named preset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PtzPreset {
    pub token: String,
    pub name: String,
}

/// One PTZ configuration.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PtzConfiguration {
    pub token: String,
    pub name: String,
    pub use_count: i32,
    pub node_token: String,
    pub default_absolute_pantilt_position_space: String,
    pub default_absolute_zoom_position_space: String,
    pub default_relative_pantilt_translation_space: String,
    pub default_relative_zoom_translation_space: String,
    pub default_continuous_pantilt_velocity_space: String,
    pub default_continuous_zoom_velocity_space: String,
    pub default_ptz_speed: PtzSpeed,
    pub default_ptz_timeout: String,
    pub pan_tilt_limits_x_range: Option<(f64, f64)>,
    pub pan_tilt_limits_y_range: Option<(f64, f64)>,
    pub zoom_limits_x_range: Option<(f64, f64)>,
}

/// One PTZ node (the movement unit a configuration binds to).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PtzNode {
    pub token: String,
    pub name: String,
    pub pan_tilt_limits: Option<(f64, f64, f64, f64)>,
    pub zoom_limits: Option<(f64, f64)>,
    pub maximum_number_of_presets: i32,
    pub home_supported: bool,
    pub auxiliary: bool,
    pub supported_pantilt_spaces: Vec<String>,
    pub supported_zoom_spaces: Vec<String>,
}

/// PTZ service capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PtzServiceCapabilities {
    pub e_flip: bool,
    pub reverse: bool,
    pub get_configuration: bool,
    pub set_configuration: bool,
    pub status_position: bool,
    pub move_status: bool,
    pub preset_status: bool,
}

// ---------------------------------------------------------------------------
// Request builders (pure — golden test targets)
// ---------------------------------------------------------------------------

fn vector2d_xml(name: &str, v: &Vector2D) -> String {
    let space = if v.space.is_empty() {
        String::new()
    } else {
        format!(" space=\"{}\"", esc(&v.space))
    };
    format!("<tt:{name} x=\"{}\" y=\"{}\"{space}></tt:{name}>", v.x, v.y)
}

fn vector1d_xml(name: &str, v: &Vector1D) -> String {
    let space = if v.space.is_empty() {
        String::new()
    } else {
        format!(" space=\"{}\"", esc(&v.space))
    };
    format!("<tt:{name} x=\"{}\"{space}></tt:{name}>", v.x)
}

fn speed_xml(v: &PtzSpeed) -> String {
    let mut inner = String::new();
    if let Some(pt) = &v.pan_tilt {
        inner.push_str(&vector2d_xml("PanTilt", pt));
    }
    if let Some(z) = &v.zoom {
        inner.push_str(&vector1d_xml("Zoom", z));
    }
    format!("<tptz:Velocity>{inner}</tptz:Velocity>")
}

fn vector_group_xml(tag: &str, v: &PtzVector) -> String {
    let mut inner = String::new();
    if let Some(pt) = &v.pan_tilt {
        inner.push_str(&vector2d_xml("PanTilt", pt));
    }
    if let Some(z) = &v.zoom {
        inner.push_str(&vector1d_xml("Zoom", z));
    }
    format!("<tptz:{tag}>{inner}</tptz:{tag}>")
}

fn tptz_action(action: &str) -> String {
    format!("<tptz:{action} xmlns:tptz=\"{PTZ_NS}\" xmlns:tt=\"{TT_NS}\"></tptz:{action}>")
}

fn tptz_action_with(action: &str, inner: &str) -> String {
    format!("<tptz:{action} xmlns:tptz=\"{PTZ_NS}\" xmlns:tt=\"{TT_NS}\">{inner}</tptz:{action}>")
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

impl SoapClient {
    /// ContinuousMove: move at `velocity` until stopped or `timeout`
    /// (an ISO 8601 duration) elapses.
    pub async fn ptz_continuous_move(
        &self,
        profile_token: &str,
        velocity: &PtzSpeed,
        timeout: &str,
    ) -> Result<(), ClientError> {
        let mut inner = format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken>",
            esc(profile_token)
        );
        inner.push_str(&speed_xml(velocity));
        if !timeout.is_empty() {
            inner.push_str(&format!("<tptz:Timeout>{}</tptz:Timeout>", esc(timeout)));
        }
        self.device_call(&tptz_action_with("ContinuousMove", &inner))
            .await?;
        Ok(())
    }

    /// AbsoluteMove: move to `position` (optionally at `speed`).
    pub async fn ptz_absolute_move(
        &self,
        profile_token: &str,
        position: &PtzVector,
        speed: Option<&PtzSpeed>,
    ) -> Result<(), ClientError> {
        let mut inner = format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken>",
            esc(profile_token)
        );
        inner.push_str(&vector_group_xml("Position", position));
        if let Some(speed) = speed {
            inner.push_str(&speed_xml(speed));
        }
        self.device_call(&tptz_action_with("AbsoluteMove", &inner))
            .await?;
        Ok(())
    }

    /// RelativeMove: move by `translation` (optionally at `speed`).
    pub async fn ptz_relative_move(
        &self,
        profile_token: &str,
        translation: &PtzVector,
        speed: Option<&PtzSpeed>,
    ) -> Result<(), ClientError> {
        let mut inner = format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken>",
            esc(profile_token)
        );
        inner.push_str(&vector_group_xml("Translation", translation));
        if let Some(speed) = speed {
            inner.push_str(&speed_xml(speed));
        }
        self.device_call(&tptz_action_with("RelativeMove", &inner))
            .await?;
        Ok(())
    }

    /// Stop the movement axes (pass false to keep an axis moving).
    pub async fn ptz_stop(
        &self,
        profile_token: &str,
        pan_tilt: bool,
        zoom: bool,
    ) -> Result<(), ClientError> {
        let inner = format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken><tptz:PanTilt>{}</tptz:PanTilt><tptz:Zoom>{}</tptz:Zoom>",
            esc(profile_token), pan_tilt, zoom
        );
        self.device_call(&tptz_action_with("Stop", &inner)).await?;
        Ok(())
    }

    /// One PTZ status snapshot.
    pub async fn ptz_get_status(&self, profile_token: &str) -> Result<PtzStatus, ClientError> {
        let inner = format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken>",
            esc(profile_token)
        );
        let resp = self
            .device_call(&tptz_action_with("GetStatus", &inner))
            .await?;
        parse_ptz_status(&resp)
    }

    /// The profile's named presets.
    pub async fn ptz_get_presets(
        &self,
        profile_token: &str,
    ) -> Result<Vec<PtzPreset>, ClientError> {
        let inner = format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken>",
            esc(profile_token)
        );
        let resp = self
            .device_call(&tptz_action_with("GetPresets", &inner))
            .await?;
        parse_ptz_presets(&resp)
    }

    /// Goto a preset.
    pub async fn ptz_goto_preset(
        &self,
        profile_token: &str,
        preset_token: &str,
        speed: Option<&PtzSpeed>,
    ) -> Result<(), ClientError> {
        let mut inner = format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken><tptz:PresetToken>{}</tptz:PresetToken>",
            esc(profile_token),
            esc(preset_token)
        );
        if let Some(speed) = speed {
            inner.push_str(&speed_xml(speed));
        }
        self.device_call(&tptz_action_with("GotoPreset", &inner))
            .await?;
        Ok(())
    }

    /// Create (empty preset_token) or update a preset; returns the preset
    /// token the device assigned.
    pub async fn ptz_set_preset(
        &self,
        profile_token: &str,
        preset_name: &str,
        preset_token: &str,
    ) -> Result<String, ClientError> {
        let mut inner = format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken>",
            esc(profile_token)
        );
        if !preset_name.is_empty() {
            inner.push_str(&format!(
                "<tptz:PresetName>{}</tptz:PresetName>",
                esc(preset_name)
            ));
        }
        if !preset_token.is_empty() {
            inner.push_str(&format!(
                "<tptz:PresetToken>{}</tptz:PresetToken>",
                esc(preset_token)
            ));
        }
        let resp = self
            .device_call(&tptz_action_with("SetPreset", &inner))
            .await?;
        let mut token = String::new();
        walk_local(&resp, "SetPresetResponse", |step| {
            if let Step::Text { path, text } = step {
                if tail_is(path, &["SetPresetResponse", "PresetToken"]) {
                    token = text.to_string();
                }
            }
            Ok(())
        })?;
        Ok(token)
    }

    /// Remove a preset.
    pub async fn ptz_remove_preset(
        &self,
        profile_token: &str,
        preset_token: &str,
    ) -> Result<(), ClientError> {
        let inner = format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken><tptz:PresetToken>{}</tptz:PresetToken>",
            esc(profile_token),
            esc(preset_token)
        );
        self.device_call(&tptz_action_with("RemovePreset", &inner))
            .await?;
        Ok(())
    }

    /// Goto the profile's home position.
    pub async fn ptz_goto_home_position(
        &self,
        profile_token: &str,
        speed: Option<&PtzSpeed>,
    ) -> Result<(), ClientError> {
        let mut inner = format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken>",
            esc(profile_token)
        );
        if let Some(speed) = speed {
            inner.push_str(&speed_xml(speed));
        }
        self.device_call(&tptz_action_with("GotoHomePosition", &inner))
            .await?;
        Ok(())
    }

    /// Set the current position as the home position.
    pub async fn ptz_set_home_position(&self, profile_token: &str) -> Result<(), ClientError> {
        let inner = format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken>",
            esc(profile_token)
        );
        self.device_call(&tptz_action_with("SetHomePosition", &inner))
            .await?;
        Ok(())
    }

    /// One configuration by token.
    pub async fn ptz_get_configuration(
        &self,
        configuration_token: &str,
    ) -> Result<PtzConfiguration, ClientError> {
        let inner = format!(
            "<tptz:PTZConfigurationToken>{}</tptz:PTZConfigurationToken>",
            esc(configuration_token)
        );
        let resp = self
            .device_call(&tptz_action_with("GetConfiguration", &inner))
            .await?;
        let mut configs = parse_ptz_configurations_body(&resp, "GetConfigurationResponse")?;
        configs
            .pop()
            .ok_or_else(|| ClientError::Parse("no PTZConfiguration in response".into()))
    }

    /// Every configuration.
    pub async fn ptz_get_configurations(&self) -> Result<Vec<PtzConfiguration>, ClientError> {
        let resp = self.device_call(&tptz_action("GetConfigurations")).await?;
        parse_ptz_configurations_body(&resp, "GetConfigurationsResponse")
    }

    /// The movement node list.
    pub async fn ptz_get_nodes(&self) -> Result<Vec<PtzNode>, ClientError> {
        let resp = self.device_call(&tptz_action("GetNodes")).await?;
        parse_ptz_nodes(&resp)
    }

    /// Fire an auxiliary command (wipers, heaters, …); returns the
    /// device's answer payload.
    pub async fn ptz_send_auxiliary_command(
        &self,
        profile_token: &str,
        aux_data: &str,
    ) -> Result<String, ClientError> {
        let inner = format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken><tptz:AuxiliaryData>{}</tptz:AuxiliaryData>",
            esc(profile_token),
            esc(aux_data)
        );
        let resp = self
            .device_call(&tptz_action_with("SendAuxiliaryCommand", &inner))
            .await?;
        let mut out = String::new();
        walk_local(&resp, "SendAuxiliaryCommandResponse", |step| {
            if let Step::Text { path, text } = step {
                if tail_is(path, &["SendAuxiliaryCommandResponse", "AuxiliaryData"]) {
                    out = text.to_string();
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// PTZ service capabilities.
    pub async fn ptz_get_service_capabilities(
        &self,
    ) -> Result<PtzServiceCapabilities, ClientError> {
        let resp = self
            .device_call(&tptz_action("GetServiceCapabilities"))
            .await?;
        let mut caps = PtzServiceCapabilities::default();
        walk_local(&resp, "GetServiceCapabilitiesResponse", |step| {
            match step {
                Step::Start { path, attrs }
                    if tail_is(path, &["GetServiceCapabilitiesResponse", "Capabilities"]) =>
                {
                    caps.e_flip = attr_get(attrs, "EFlip").map(xml_bool).unwrap_or(false);
                    caps.reverse = attr_get(attrs, "Reverse").map(xml_bool).unwrap_or(false);
                    caps.get_configuration = attr_get(attrs, "GetConfiguration")
                        .map(xml_bool)
                        .unwrap_or(false);
                    caps.set_configuration = attr_get(attrs, "SetConfiguration")
                        .map(xml_bool)
                        .unwrap_or(false);
                }
                Step::Start { path, attrs }
                    if tail_is(
                        path,
                        &["GetServiceCapabilitiesResponse", "Capabilities", "Status"],
                    ) =>
                {
                    caps.status_position = attr_get(attrs, "PositionStatus")
                        .map(xml_bool)
                        .unwrap_or(false);
                    caps.move_status = attr_get(attrs, "MoveStatus").map(xml_bool).unwrap_or(false);
                }
                Step::Start { path, attrs }
                    if tail_is(
                        path,
                        &[
                            "GetServiceCapabilitiesResponse",
                            "Capabilities",
                            "Presets",
                            "Status",
                        ],
                    ) =>
                {
                    caps.preset_status =
                        attr_get(attrs, "GetStatus").map(xml_bool).unwrap_or(false);
                }
                _ => {}
            }
            Ok(())
        })?;
        Ok(caps)
    }
}

// ---------------------------------------------------------------------------
// Response decode
// ---------------------------------------------------------------------------

fn parse_ptz_status(resp: &str) -> Result<PtzStatus, ClientError> {
    let mut status = PtzStatus::default();

    walk_local(resp, "GetStatusResponse", |step| match step {
        Step::Start { path, attrs } => {
            match path.last().map(String::as_str).unwrap_or("") {
                "PanTilt" if tail_is(path, &["PTZStatus", "Position", "PanTilt"]) => {
                    status.position.pan_tilt = Some(Vector2D {
                        x: attr_get(attrs, "x")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0.0),
                        y: attr_get(attrs, "y")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0.0),
                        space: attr_get(attrs, "space").unwrap_or("").to_string(),
                    });
                }
                "Zoom" if tail_is(path, &["PTZStatus", "Position", "Zoom"]) => {
                    status.position.zoom = Some(Vector1D {
                        x: attr_get(attrs, "x")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0.0),
                        space: attr_get(attrs, "space").unwrap_or("").to_string(),
                    });
                }
                _ => {}
            }
            Ok(())
        }
        Step::Text { path, text } => {
            match path.last().map(String::as_str).unwrap_or("") {
                "PanTilt" if tail_is(path, &["PTZStatus", "MoveStatus", "PanTilt"]) => {
                    status
                        .move_status
                        .get_or_insert_with(MoveStatus::default)
                        .pan_tilt = text.to_string();
                }
                "Zoom" if tail_is(path, &["PTZStatus", "MoveStatus", "Zoom"]) => {
                    status
                        .move_status
                        .get_or_insert_with(MoveStatus::default)
                        .zoom = text.to_string();
                }
                "Error" => status.error = text.to_string(),
                "UtcTime" | "UTCTime" => status.utc_time = text.to_string(),
                _ => {}
            }
            Ok(())
        }
        _ => Ok(()),
    })?;
    Ok(status)
}

fn parse_ptz_presets(resp: &str) -> Result<Vec<PtzPreset>, ClientError> {
    let mut out: Vec<PtzPreset> = Vec::new();
    walk_local(resp, "GetPresetsResponse", |step| {
        match step {
            Step::Start { path, attrs } if tail_is(path, &["GetPresetsResponse", "Preset"]) => {
                out.push(PtzPreset {
                    token: attr_get(attrs, "token").unwrap_or("").to_string(),
                    name: String::new(),
                });
            }
            Step::Text { path, text }
                if tail_is(path, &["GetPresetsResponse", "Preset", "Name"]) =>
            {
                if let Some(last) = out.last_mut() {
                    last.name = text.to_string();
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(out)
}

fn parse_ptz_configurations_body(
    resp: &str,
    root: &str,
) -> Result<Vec<PtzConfiguration>, ClientError> {
    let mut out: Vec<PtzConfiguration> = Vec::new();
    let mut x_range: Vec<f64> = Vec::new();
    let mut y_range: Vec<f64> = Vec::new();
    let mut in_pan_tilt_limits = false;

    walk_local(resp, root, |step| match step {
        Step::Start { path, attrs } => {
            match path.last().map(String::as_str).unwrap_or("") {
                "PTZConfiguration" => {
                    out.push(PtzConfiguration {
                        token: attr_get(attrs, "token").unwrap_or("").to_string(),
                        ..PtzConfiguration::default()
                    });
                }
                "PanTiltLimits" => {
                    in_pan_tilt_limits = true;
                    x_range.clear();
                    y_range.clear();
                }
                "DefaultPTZSpeed" | "Range" | "XRange" | "YRange" | "Extension" => {}
                _ => {}
            }
            if tail_is(path, &["PTZConfiguration", "DefaultPTZSpeed", "PanTilt"]) {
                if let Some(cfg) = out.last_mut() {
                    cfg.default_ptz_speed.pan_tilt = Some(Vector2D {
                        x: attr_get(attrs, "x")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0.0),
                        y: attr_get(attrs, "y")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0.0),
                        space: attr_get(attrs, "space").unwrap_or("").to_string(),
                    });
                }
            } else if tail_is(path, &["PTZConfiguration", "DefaultPTZSpeed", "Zoom"]) {
                if let Some(cfg) = out.last_mut() {
                    cfg.default_ptz_speed.zoom = Some(Vector1D {
                        x: attr_get(attrs, "x")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0.0),
                        space: attr_get(attrs, "space").unwrap_or("").to_string(),
                    });
                }
            }
            Ok(())
        }
        Step::Text { path, text } => {
            let last = path.last().map(String::as_str).unwrap_or("");
            let parent = path.iter().rev().nth(1).map(String::as_str).unwrap_or("");
            if parent == "PTZConfiguration" {
                if let Some(cfg) = out.last_mut() {
                    match last {
                        "Name" => cfg.name = text.to_string(),
                        "UseCount" => cfg.use_count = xml_int(text),
                        "NodeToken" => cfg.node_token = text.to_string(),
                        "DefaultAbsolutePantiltPositionSpace" => {
                            cfg.default_absolute_pantilt_position_space = text.to_string()
                        }
                        "DefaultAbsoluteZoomPositionSpace" => {
                            cfg.default_absolute_zoom_position_space = text.to_string()
                        }
                        "DefaultRelativePanTiltTranslationSpace" => {
                            cfg.default_relative_pantilt_translation_space = text.to_string()
                        }
                        "DefaultRelativeZoomTranslationSpace" => {
                            cfg.default_relative_zoom_translation_space = text.to_string()
                        }
                        "DefaultContinuousPanTiltVelocitySpace" => {
                            cfg.default_continuous_pantilt_velocity_space = text.to_string()
                        }
                        "DefaultContinuousZoomVelocitySpace" => {
                            cfg.default_continuous_zoom_velocity_space = text.to_string()
                        }
                        "DefaultPTZTimeout" => cfg.default_ptz_timeout = text.to_string(),
                        _ => {}
                    }
                }
            } else if parent == "XRange" {
                x_range.push(xml_float(text));
                if x_range.len() == 2 {
                    if let Some(cfg) = out.last_mut() {
                        if in_pan_tilt_limits {
                            cfg.pan_tilt_limits_x_range = Some((x_range[0], x_range[1]));
                        } else {
                            cfg.zoom_limits_x_range = Some((x_range[0], x_range[1]));
                        }
                    }
                    x_range.clear();
                }
            } else if parent == "YRange" && in_pan_tilt_limits {
                y_range.push(xml_float(text));
                if y_range.len() == 2 {
                    if let Some(cfg) = out.last_mut() {
                        cfg.pan_tilt_limits_y_range = Some((y_range[0], y_range[1]));
                    }
                    y_range.clear();
                }
            }
            Ok(())
        }
        Step::End { path } => {
            if path.last().map(String::as_str) == Some("PanTiltLimits") {
                in_pan_tilt_limits = false;
            }
            Ok(())
        }
    })?;
    Ok(out)
}

fn parse_ptz_nodes(resp: &str) -> Result<Vec<PtzNode>, ClientError> {
    let mut out: Vec<PtzNode> = Vec::new();
    let mut x_range: Vec<f64> = Vec::new();
    let mut y_range: Vec<f64> = Vec::new();
    let mut in_pan_tilt_limits = false;
    let mut in_zoom_limits = false;

    walk_local(resp, "GetNodesResponse", |step| match step {
        Step::Start { path, attrs } => {
            match path.last().map(String::as_str).unwrap_or("") {
                "PTZNode" => {
                    out.push(PtzNode {
                        token: attr_get(attrs, "token").unwrap_or("").to_string(),
                        ..PtzNode::default()
                    });
                }
                "PanTiltLimits" => {
                    in_pan_tilt_limits = true;
                    x_range.clear();
                    y_range.clear();
                }
                "ZoomLimits" => {
                    in_zoom_limits = true;
                    x_range.clear();
                }
                _ => {}
            }
            Ok(())
        }
        Step::Text { path, text } => {
            let last = path.last().map(String::as_str).unwrap_or("");
            let parent = path.iter().rev().nth(1).map(String::as_str).unwrap_or("");
            let Some(node) = out.last_mut() else {
                return Ok(());
            };
            match (parent, last) {
                ("PTZNode", "Name") => node.name = text.to_string(),
                ("PTZNode", "MaximumNumberOfPresets") => {
                    node.maximum_number_of_presets = xml_int(text)
                }
                ("PTZNode", "HomeSupported") => node.home_supported = xml_bool(text),
                ("PTZNode", "Auxiliary") => node.auxiliary = xml_bool(text),
                (_, "URI") if path.iter().any(|p| p == "PanTiltSpaces") => {
                    node.supported_pantilt_spaces.push(text.to_string())
                }
                (_, "URI") if path.iter().any(|p| p == "ZoomSpaces") => {
                    node.supported_zoom_spaces.push(text.to_string())
                }
                ("XRange", "Min") | ("XRange", "Max") => {
                    x_range.push(xml_float(text));
                    if x_range.len() == 2 {
                        if in_pan_tilt_limits {
                            node.pan_tilt_limits = Some((
                                x_range[0],
                                y_range.first().copied().unwrap_or(0.0),
                                x_range[1],
                                y_range.get(1).copied().unwrap_or(0.0),
                            ));
                        } else if in_zoom_limits {
                            node.zoom_limits = Some((x_range[0], x_range[1]));
                        }
                        if !in_pan_tilt_limits || y_range.len() == 2 {
                            x_range.clear();
                        }
                    }
                }
                ("YRange", "Min") | ("YRange", "Max") if in_pan_tilt_limits => {
                    y_range.push(xml_float(text));
                    if y_range.len() == 2 && x_range.len() == 2 {
                        node.pan_tilt_limits =
                            Some((x_range[0], y_range[0], x_range[1], y_range[1]));
                        x_range.clear();
                        y_range.clear();
                    }
                }
                _ => {}
            }
            Ok(())
        }
        Step::End { path } => {
            match path.last().map(String::as_str).unwrap_or("") {
                "PanTiltLimits" => in_pan_tilt_limits = false,
                "ZoomLimits" => in_zoom_limits = false,
                _ => {}
            }
            Ok(())
        }
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_goldens() {
        assert_eq!(
            tptz_action("GetConfigurations"),
            "<tptz:GetConfigurations xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"></tptz:GetConfigurations>"
        );

        let velocity = PtzSpeed {
            pan_tilt: Some(Vector2D {
                x: 0.5,
                y: -0.5,
                space: String::new(),
            }),
            zoom: Some(Vector1D {
                x: 0.1,
                space: String::new(),
            }),
        };
        assert_eq!(
            speed_xml(&velocity),
            "<tptz:Velocity><tt:PanTilt x=\"0.5\" y=\"-0.5\"></tt:PanTilt><tt:Zoom x=\"0.1\"></tt:Zoom></tptz:Velocity>"
        );
    }

    #[test]
    fn decodes_status() {
        let resp = r#"<GetStatusResponse><PTZStatus>
            <Position><PanTilt x="10.5" y="-3" space="ptspace"></PanTilt><Zoom x="0.5" space="zspace"></Zoom></Position>
            <MoveStatus><PanTilt>MOVING</PanTilt><Zoom>IDLE</Zoom></MoveStatus>
            <Error></Error><UtcTime>2026-10-12T09:00:00Z</UtcTime>
            </PTZStatus></GetStatusResponse>"#;
        let st = parse_ptz_status(resp).unwrap();
        assert_eq!(st.position.pan_tilt.as_ref().unwrap().x, 10.5);
        assert_eq!(st.position.pan_tilt.as_ref().unwrap().space, "ptspace");
        assert_eq!(st.position.zoom.as_ref().unwrap().x, 0.5);
        assert_eq!(st.move_status.as_ref().unwrap().pan_tilt, "MOVING");
        assert_eq!(st.utc_time, "2026-10-12T09:00:00Z");
    }

    #[test]
    fn decodes_presets() {
        let resp = r#"<GetPresetsResponse>
            <Preset token="p1"><Name>Door</Name></Preset>
            <Preset token="p2"><Name>Gate</Name></Preset>
            </GetPresetsResponse>"#;
        let presets = parse_ptz_presets(resp).unwrap();
        assert_eq!(presets.len(), 2);
        assert_eq!(
            (presets[0].token.as_str(), presets[0].name.as_str()),
            ("p1", "Door")
        );
    }

    #[test]
    fn decodes_configurations() {
        let resp = r#"<GetConfigurationsResponse>
            <PTZConfiguration token="ptz-1"><Name>Main</Name><UseCount>3</UseCount><NodeToken>node-1</NodeToken>
            <DefaultAbsolutePantiltPositionSpace>abs-space</DefaultAbsolutePantiltPositionSpace>
            <DefaultPTZTimeout>PT10S</DefaultPTZTimeout>
            <DefaultPTZSpeed><tt:PanTilt x="1" y="1" space="s"></tt:PanTilt></DefaultPTZSpeed>
            <PanTiltLimits><Range><URI>space</URI><XRange><Min>-1</Min><Max>1</Max></XRange><YRange><Min>-0.5</Min><Max>0.5</Max></YRange></Range></PanTiltLimits>
            </PTZConfiguration></GetConfigurationsResponse>"#;
        let configs = parse_ptz_configurations_body(resp, "GetConfigurationsResponse").unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(
            (configs[0].token.as_str(), configs[0].name.as_str()),
            ("ptz-1", "Main")
        );
        assert_eq!(configs[0].node_token, "node-1");
        assert_eq!(configs[0].pan_tilt_limits_x_range, Some((-1.0, 1.0)));
        assert_eq!(configs[0].pan_tilt_limits_y_range, Some((-0.5, 0.5)));
        assert_eq!(
            configs[0].default_ptz_speed.pan_tilt.as_ref().unwrap().x,
            1.0
        );
    }

    #[test]
    fn decodes_nodes() {
        let resp = r#"<GetNodesResponse><PTZNode token="node-1">
            <Name>PT</Name><HomeSupported>true</HomeSupported><MaximumNumberOfPresets>16</MaximumNumberOfPresets>
            <PanTiltSpaces><AbsolutePanTiltPositionSpace><URI>abs</URI></AbsolutePanTiltPositionSpace></PanTiltSpaces>
            <PanTiltLimits><Range><XRange><Min>-1</Min><Max>1</Max></XRange><YRange><Min>-0.5</Min><Max>0.5</Max></YRange></Range></PanTiltLimits>
            <ZoomLimits><Range><XRange><Min>0</Min><Max>1</Max></XRange></Range></ZoomLimits>
            </PTZNode></GetNodesResponse>"#;
        let nodes = parse_ptz_nodes(resp).unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(nodes[0].home_supported);
        assert_eq!(nodes[0].maximum_number_of_presets, 16);
        assert_eq!(nodes[0].supported_pantilt_spaces, vec!["abs"]);
        assert_eq!(nodes[0].pan_tilt_limits, Some((-1.0, -0.5, 1.0, 0.5)));
        assert_eq!(nodes[0].zoom_limits, Some((0.0, 1.0)));
    }
}
