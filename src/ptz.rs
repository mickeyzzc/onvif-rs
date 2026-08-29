// ---------------------------------------------------------------------------
// ONVIF PTZ Service Handlers
// ---------------------------------------------------------------------------
//
// Implements ContinuousMove, AbsoluteMove, RelativeMove, Stop, GetStatus,
// GetPresets, SetPreset, GotoPreset, RemovePreset, GetNodes, and
// GetConfigurations as OnvifActionHandler trait objects.
//
// Uses PtzState for state management (thread-safe via RwLock).

use std::sync::Arc;

use async_trait::async_trait;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;

use crate::namespaces::{PTZ_SERVICE, SCHEMAS};
use crate::ptz_state::{Position, PtzState, Velocity};
use crate::server::OnvifActionHandler;
use crate::types::{serialize_soap_response, OnvifError, RequestInfo};

// ---------------------------------------------------------------------------
// Coordinate space URIs (ONVIF standard)
// ---------------------------------------------------------------------------

const PAN_TILT_POSITION_SPACE: &str = "http://www.onvif.org/ver10/schema/PanTiltPositionSpace";
const ZOOM_POSITION_SPACE: &str = "http://www.onvif.org/ver10/schema/ZoomPositionSpace";
const PAN_TILT_SPEED_SPACE: &str = "http://www.onvif.org/ver10/schema/PanTiltSpeedSpace";
const ZOOM_SPEED_SPACE: &str = "http://www.onvif.org/ver10/schema/ZoomSpeedSpace";
const PAN_TILT_TRANSLATION_SPACE: &str =
    "http://www.onvif.org/ver10/schema/PanTiltTranslationSpace";
const ZOOM_TRANSLATION_SPACE: &str = "http://www.onvif.org/ver10/schema/ZoomTranslationSpace";

// ---------------------------------------------------------------------------
// PtzHandler — dispatches based on action element name in the body
// ---------------------------------------------------------------------------

/// Wraps `Arc<PtzState>` and dispatches `handle()` to the appropriate
/// response builder based on the SOAP action element found in `body`.
pub struct PtzHandler(pub Arc<PtzState>);

#[async_trait]
impl OnvifActionHandler for PtzHandler {
    async fn handle(&self, body: &str, _info: &RequestInfo) -> Result<String, OnvifError> {
        let state = &self.0;
        let fragment = if body.contains("ContinuousMove") {
            build_continuous_move(body, state)?
        } else if body.contains("AbsoluteMove") {
            build_absolute_move(body, state)?
        } else if body.contains("RelativeMove") {
            build_relative_move(body, state)?
        } else if body.contains("Stop") {
            build_stop(state)
        } else if body.contains("GetStatus") {
            build_get_status(state)
        } else if body.contains("GetPresets") {
            build_get_presets(state)
        } else if body.contains("SetPreset") {
            build_set_preset(body, state)?
        } else if body.contains("GotoPreset") {
            build_goto_preset(body, state)?
        } else if body.contains("RemovePreset") {
            build_remove_preset(body, state)?
        } else if body.contains("GetNodes") {
            build_get_nodes()
        } else if body.contains("GetConfigurations") {
            build_get_configurations()
        } else {
            return Err(OnvifError::ActionNotSupported("unknown ptz action".into()));
        };
        Ok(serialize_soap_response(&fragment))
    }
}

// ---------------------------------------------------------------------------
// Response builders — each returns a `<tptz:XxxResponse>` XML fragment
// ---------------------------------------------------------------------------

/// Build `<tptz:ContinuousMoveResponse>` (empty success).
fn build_continuous_move(body: &str, state: &PtzState) -> Result<String, OnvifError> {
    let vel = parse_velocity(body);
    state.continuous_move(vel);
    Ok(empty_response("ContinuousMove"))
}

/// Build `<tptz:AbsoluteMoveResponse>` (empty success).
fn build_absolute_move(body: &str, state: &PtzState) -> Result<String, OnvifError> {
    let pos = parse_position(body);
    state.absolute_move(pos);
    Ok(empty_response("AbsoluteMove"))
}

/// Build `<tptz:RelativeMoveResponse>` (empty success).
fn build_relative_move(body: &str, state: &PtzState) -> Result<String, OnvifError> {
    let vel = parse_velocity(body);
    state.relative_move(vel);
    Ok(empty_response("RelativeMove"))
}

/// Build `<tptz:StopResponse>` (empty success).
fn build_stop(state: &PtzState) -> String {
    state.stop();
    empty_response("Stop")
}

/// Build `<tptz:GetStatusResponse>` with position and move status.
fn build_get_status(state: &PtzState) -> String {
    let pos = state.get_position();
    let status = state.get_status();

    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

    let mut root = BytesStart::new("tptz:GetStatusResponse");
    root.push_attribute(("xmlns:tptz", PTZ_SERVICE));
    root.push_attribute(("xmlns:tt", SCHEMAS));
    w.write_event(Event::Start(root)).expect("write root");

    // PTZStatus
    w.write_event(Event::Start(BytesStart::new("tptz:PTZStatus")))
        .expect("write PTZStatus");

    // Position
    w.write_event(Event::Start(BytesStart::new("tptz:Position")))
        .expect("write Position");
    write_pan_tilt(&mut w, pos.x, pos.y, PAN_TILT_POSITION_SPACE);
    write_zoom(&mut w, pos.zoom, ZOOM_POSITION_SPACE);
    w.write_event(Event::End(BytesEnd::new("tptz:Position")))
        .expect("close Position");

    // MoveStatus
    w.write_event(Event::Start(BytesStart::new("tptz:MoveStatus")))
        .expect("write MoveStatus");
    write_text(&mut w, "tt:PanTilt", status);
    write_text(&mut w, "tt:Zoom", status);
    w.write_event(Event::End(BytesEnd::new("tptz:MoveStatus")))
        .expect("close MoveStatus");

    w.write_event(Event::End(BytesEnd::new("tptz:PTZStatus")))
        .expect("close PTZStatus");
    w.write_event(Event::End(BytesEnd::new("tptz:GetStatusResponse")))
        .expect("close root");

    String::from_utf8(w.into_inner()).expect("UTF-8 body")
}

/// Build `<tptz:GetPresetsResponse>` with preset list.
fn build_get_presets(state: &PtzState) -> String {
    let presets = state.list_presets();

    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

    let mut root = BytesStart::new("tptz:GetPresetsResponse");
    root.push_attribute(("xmlns:tptz", PTZ_SERVICE));
    root.push_attribute(("xmlns:tt", SCHEMAS));
    w.write_event(Event::Start(root)).expect("write root");

    for preset in &presets {
        let mut elem = BytesStart::new("tptz:Preset");
        elem.push_attribute(("token", preset.token.as_str()));
        w.write_event(Event::Start(elem)).expect("write Preset");
        write_text(&mut w, "tt:Name", &preset.name);
        write_pan_tilt(
            &mut w,
            preset.position.x,
            preset.position.y,
            PAN_TILT_POSITION_SPACE,
        );
        write_zoom(&mut w, preset.position.zoom, ZOOM_POSITION_SPACE);
        w.write_event(Event::End(BytesEnd::new("tptz:Preset")))
            .expect("close Preset");
    }

    w.write_event(Event::End(BytesEnd::new("tptz:GetPresetsResponse")))
        .expect("close root");

    String::from_utf8(w.into_inner()).expect("UTF-8 body")
}

/// Build `<tptz:SetPresetResponse>` containing the preset token.
fn build_set_preset(body: &str, state: &PtzState) -> Result<String, OnvifError> {
    let token = parse_preset_token(body);
    let token = match token {
        Some(t) => {
            // Use the client-provided token
            let name = if t.is_empty() { "Preset" } else { &t };
            state.save_preset_with_token(&t, name);
            t
        }
        None => {
            // Auto-generate a token; honor the WSDL PresetName when provided.
            let name =
                parse_text_content(body, "PresetName").unwrap_or_else(|| "Preset".to_string());
            state.save_preset(&name)
        }
    };

    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

    let mut root = BytesStart::new("tptz:SetPresetResponse");
    root.push_attribute(("xmlns:tptz", PTZ_SERVICE));
    w.write_event(Event::Start(root)).expect("write root");
    write_text(&mut w, "tptz:PresetToken", &token);
    w.write_event(Event::End(BytesEnd::new("tptz:SetPresetResponse")))
        .expect("close root");

    Ok(String::from_utf8(w.into_inner()).expect("UTF-8 body"))
}

/// Build `<tptz:GotoPresetResponse>` (empty success).
fn build_goto_preset(body: &str, state: &PtzState) -> Result<String, OnvifError> {
    let token = parse_preset_token(body)
        .ok_or_else(|| OnvifError::Internal("missing PresetToken in request".into()))?;
    state.goto_preset(&token).map_err(OnvifError::Internal)?;
    Ok(empty_response("GotoPreset"))
}

/// Build `<tptz:RemovePresetResponse>` (empty success).
fn build_remove_preset(body: &str, state: &PtzState) -> Result<String, OnvifError> {
    let token = parse_preset_token(body)
        .ok_or_else(|| OnvifError::Internal("missing PresetToken in request".into()))?;
    state.remove_preset(&token).map_err(OnvifError::Internal)?;
    Ok(empty_response("RemovePreset"))
}

/// Build `<tptz:GetNodesResponse>` — returns a single digital PTZ node.
fn build_get_nodes() -> String {
    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

    let mut root = BytesStart::new("tptz:GetNodesResponse");
    root.push_attribute(("xmlns:tptz", PTZ_SERVICE));
    root.push_attribute(("xmlns:tt", SCHEMAS));
    w.write_event(Event::Start(root)).expect("write root");

    let mut node = BytesStart::new("tptz:PTZNode");
    node.push_attribute(("NodeToken", "PTZNode_01"));
    w.write_event(Event::Start(node)).expect("write PTZNode");
    write_text(&mut w, "tt:Name", "Main PTZ Node");
    write_text(&mut w, "tt:FixedHomePosition", "false");

    // SupportedPTZSpaces
    w.write_event(Event::Start(BytesStart::new("tt:SupportedPTZSpaces")))
        .expect("write SupportedPTZSpaces");

    write_pan_tilt_space(
        &mut w,
        "tt:AbsolutePanTiltPositionSpace",
        PAN_TILT_POSITION_SPACE,
        -1.0,
        1.0,
        -1.0,
        1.0,
    );
    write_zoom_space(
        &mut w,
        "tt:AbsoluteZoomPositionSpace",
        ZOOM_POSITION_SPACE,
        0.0,
        1.0,
    );
    write_pan_tilt_space(
        &mut w,
        "tt:RelativePanTiltTranslationSpace",
        PAN_TILT_TRANSLATION_SPACE,
        -1.0,
        1.0,
        -1.0,
        1.0,
    );
    write_zoom_space(
        &mut w,
        "tt:RelativeZoomTranslationSpace",
        ZOOM_TRANSLATION_SPACE,
        -1.0,
        1.0,
    );
    write_pan_tilt_space(
        &mut w,
        "tt:ContinuousPanTiltVelocitySpace",
        PAN_TILT_SPEED_SPACE,
        -1.0,
        1.0,
        -1.0,
        1.0,
    );
    write_zoom_space(
        &mut w,
        "tt:ContinuousZoomVelocitySpace",
        ZOOM_SPEED_SPACE,
        0.0,
        1.0,
    );

    w.write_event(Event::End(BytesEnd::new("tt:SupportedPTZSpaces")))
        .expect("close SupportedPTZSpaces");
    w.write_event(Event::End(BytesEnd::new("tptz:PTZNode")))
        .expect("close PTZNode");
    w.write_event(Event::End(BytesEnd::new("tptz:GetNodesResponse")))
        .expect("close root");

    String::from_utf8(w.into_inner()).expect("UTF-8 body")
}

/// Build `<tptz:GetConfigurationsResponse>` — returns a single default config.
fn build_get_configurations() -> String {
    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);

    let mut root = BytesStart::new("tptz:GetConfigurationsResponse");
    root.push_attribute(("xmlns:tptz", PTZ_SERVICE));
    root.push_attribute(("xmlns:tt", SCHEMAS));
    w.write_event(Event::Start(root)).expect("write root");

    w.write_event(Event::Start(BytesStart::new("tptz:PTZConfiguration")))
        .expect("write PTZConfiguration");
    write_text(&mut w, "tt:Name", "Default PTZ Configuration");
    write_text(&mut w, "tt:UseCount", "1");
    write_text(&mut w, "tt:NodeToken", "PTZNode_01");
    // DefaultPTZSpeed
    w.write_event(Event::Start(BytesStart::new("tt:DefaultPTZSpeed")))
        .expect("write DefaultPTZSpeed");
    write_pan_tilt(&mut w, 1.0, 1.0, PAN_TILT_SPEED_SPACE);
    write_zoom(&mut w, 1.0, ZOOM_SPEED_SPACE);
    w.write_event(Event::End(BytesEnd::new("tt:DefaultPTZSpeed")))
        .expect("close DefaultPTZSpeed");
    w.write_event(Event::End(BytesEnd::new("tptz:PTZConfiguration")))
        .expect("close PTZConfiguration");
    w.write_event(Event::End(BytesEnd::new("tptz:GetConfigurationsResponse")))
        .expect("close root");

    String::from_utf8(w.into_inner()).expect("UTF-8 body")
}

// ---------------------------------------------------------------------------
// XML writer helpers
// ---------------------------------------------------------------------------

/// Write a simple text element: `<name>text</name>`.
fn write_text(w: &mut Writer<Vec<u8>>, name: &str, text: &str) {
    w.write_event(Event::Start(BytesStart::new(name)))
        .expect("write start");
    w.write_event(Event::Text(BytesText::new(text)))
        .expect("write text");
    w.write_event(Event::End(BytesEnd::new(name)))
        .expect("write end");
}

/// Write a `<tt:PanTilt x=".." y=".." space=".."/>` empty element.
fn write_pan_tilt(w: &mut Writer<Vec<u8>>, x: f64, y: f64, space: &str) {
    let mut elem = BytesStart::new("tt:PanTilt");
    let xs = format_float(x);
    let ys = format_float(y);
    elem.push_attribute(("x", xs.as_str()));
    elem.push_attribute(("y", ys.as_str()));
    elem.push_attribute(("space", space));
    w.write_event(Event::Empty(elem)).expect("write PanTilt");
}

/// Write a `<tt:Zoom x=".." space=".."/>` empty element.
fn write_zoom(w: &mut Writer<Vec<u8>>, x: f64, space: &str) {
    let mut elem = BytesStart::new("tt:Zoom");
    let xs = format_float(x);
    elem.push_attribute(("x", xs.as_str()));
    elem.push_attribute(("space", space));
    w.write_event(Event::Empty(elem)).expect("write Zoom");
}

/// Write a 2D coordinate space definition.
fn write_pan_tilt_space(
    w: &mut Writer<Vec<u8>>,
    elem_name: &str,
    uri: &str,
    x_min: f64,
    x_max: f64,
    y_min: f64,
    y_max: f64,
) {
    w.write_event(Event::Start(BytesStart::new(elem_name)))
        .expect("write space start");
    write_text(w, "tt:URI", uri);
    // XRange
    w.write_event(Event::Start(BytesStart::new("tt:XRange")))
        .expect("write XRange");
    write_text(w, "tt:Min", &format_float(x_min));
    write_text(w, "tt:Max", &format_float(x_max));
    w.write_event(Event::End(BytesEnd::new("tt:XRange")))
        .expect("close XRange");
    // YRange
    w.write_event(Event::Start(BytesStart::new("tt:YRange")))
        .expect("write YRange");
    write_text(w, "tt:Min", &format_float(y_min));
    write_text(w, "tt:Max", &format_float(y_max));
    w.write_event(Event::End(BytesEnd::new("tt:YRange")))
        .expect("close YRange");
    w.write_event(Event::End(BytesEnd::new(elem_name)))
        .expect("close space");
}

/// Write a 1D coordinate space definition.
fn write_zoom_space(w: &mut Writer<Vec<u8>>, elem_name: &str, uri: &str, x_min: f64, x_max: f64) {
    w.write_event(Event::Start(BytesStart::new(elem_name)))
        .expect("write space start");
    write_text(w, "tt:URI", uri);
    // XRange
    w.write_event(Event::Start(BytesStart::new("tt:XRange")))
        .expect("write XRange");
    write_text(w, "tt:Min", &format_float(x_min));
    write_text(w, "tt:Max", &format_float(x_max));
    w.write_event(Event::End(BytesEnd::new("tt:XRange")))
        .expect("close XRange");
    w.write_event(Event::End(BytesEnd::new(elem_name)))
        .expect("close space");
}

/// Build an empty `<tptz:XxxResponse/>` for commands that return no data.
fn empty_response(action: &str) -> String {
    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);
    let name = format!("tptz:{}Response", action);
    let mut root = BytesStart::new(&name);
    root.push_attribute(("xmlns:tptz", PTZ_SERVICE));
    w.write_event(Event::Empty(root))
        .expect("write empty response");
    String::from_utf8(w.into_inner()).expect("UTF-8 body")
}

/// Format a float with minimal precision (strip trailing zeros).
fn format_float(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{:.0}", v)
    } else if (v * 10.0).fract() == 0.0 {
        format!("{:.1}", v)
    } else {
        format!("{:.4}", v)
    }
}

// ---------------------------------------------------------------------------
// XML parsing helpers
// ---------------------------------------------------------------------------

/// Extract a float attribute from XML near a given tag.
///
/// Searches for `<tag ... attr="value"` or self-closing `<tag ... attr="value"/`
/// in the XML string `s` and returns the parsed float value.
fn parse_float_attr(s: &str, tag: &str, attr: &str) -> f64 {
    let tag_idx = s.find(tag).unwrap_or(usize::MAX);
    if tag_idx == usize::MAX {
        return 0.0;
    }
    let rest = &s[tag_idx..];
    let search_attr = format!("{}=\"", attr);
    let attr_idx = rest.find(&search_attr).unwrap_or(usize::MAX);
    if attr_idx == usize::MAX {
        return 0.0;
    }
    let val_start = attr_idx + search_attr.len();
    let val_rest = &rest[val_start..];
    let end_idx = val_rest.find('"').unwrap_or(usize::MAX);
    if end_idx == usize::MAX {
        return 0.0;
    }
    val_rest[..end_idx].parse::<f64>().unwrap_or(0.0)
}

/// Extract the text content of a named element (e.g., `<PresetToken>value</PresetToken>`).
fn parse_text_content(s: &str, tag: &str) -> Option<String> {
    // Try with namespace prefix
    let patterns = [format!("<{}>", tag), format!("<tptz:{}>", tag)];
    for pattern in &patterns {
        if let Some(start) = s.find(pattern.as_str()) {
            let content_start = start + pattern.len();
            let remaining = &s[content_start..];
            if let Some(end) = remaining.find("</") {
                let val = remaining[..end].trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Parse ONVIF Velocity from a SOAP body fragment (PanTilt x/y, Zoom x).
fn parse_velocity(s: &str) -> Velocity {
    Velocity {
        x: parse_float_attr(s, "PanTilt", "x"),
        y: parse_float_attr(s, "PanTilt", "y"),
        zoom: parse_float_attr(s, "Zoom", "x"),
    }
}

/// Parse ONVIF Position from a SOAP body fragment (PanTilt x/y, Zoom x).
fn parse_position(s: &str) -> Position {
    Position {
        x: parse_float_attr(s, "PanTilt", "x"),
        y: parse_float_attr(s, "PanTilt", "y"),
        zoom: parse_float_attr(s, "Zoom", "x"),
    }
}

/// Parse `PresetToken` text content from a SOAP body fragment.
fn parse_preset_token(s: &str) -> Option<String> {
    parse_text_content(s, "PresetToken")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuthResult;

    fn test_state() -> Arc<PtzState> {
        Arc::new(PtzState::new())
    }

    fn test_info() -> RequestInfo {
        RequestInfo {
            client_ip: "10.0.0.1".to_string(),
            server_ip: "192.168.1.100".to_string(),
            auth_result: AuthResult {
                username: "admin".into(),
                authenticated: true,
            },
        }
    }

    // --------------------------------------------------------------
    // Parsing
    // --------------------------------------------------------------

    #[test]
    fn test_parse_float_attr_pan_tilt() {
        let xml = r#"<PanTilt x="0.5" y="-0.3" space="http://www.onvif.org/ver10/schema/PanTiltPositionSpace"/>"#;
        assert!((parse_float_attr(xml, "PanTilt", "x") - 0.5).abs() < f64::EPSILON);
        assert!((parse_float_attr(xml, "PanTilt", "y") - (-0.3)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_float_attr_zoom() {
        let xml = r#"<Zoom x="0.8" space="http://www.onvif.org/ver10/schema/ZoomPositionSpace"/>"#;
        assert!((parse_float_attr(xml, "Zoom", "x") - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_float_attr_not_found() {
        assert!((parse_float_attr("<Foo/>", "Bar", "x") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_preset_token_found() {
        let xml = r#"<SetPreset><PresetToken>my-preset</PresetToken></SetPreset>"#;
        assert_eq!(parse_preset_token(xml), Some("my-preset".into()));
    }

    #[test]
    fn test_parse_preset_token_missing() {
        assert_eq!(parse_preset_token("<SetPreset/>"), None);
    }

    #[test]
    fn test_parse_velocity_from_body() {
        let body = r#"<ContinuousMove xmlns="http://www.onvif.org/ver20/ptz/wsdl">
            <Velocity>
                <PanTilt x="0.8" y="-0.5" space="..."/>
                <Zoom x="0.3" space="..."/>
            </Velocity>
        </ContinuousMove>"#;
        let vel = parse_velocity(body);
        assert!((vel.x - 0.8).abs() < f64::EPSILON);
        assert!((vel.y - (-0.5)).abs() < f64::EPSILON);
        assert!((vel.zoom - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_position_from_body() {
        let body = r#"<AbsoluteMove xmlns="http://www.onvif.org/ver20/ptz/wsdl">
            <Position>
                <PanTilt x="-0.2" y="0.7" space="..."/>
                <Zoom x="0.5" space="..."/>
            </Position>
        </AbsoluteMove>"#;
        let pos = parse_position(body);
        assert!((pos.x - (-0.2)).abs() < f64::EPSILON);
        assert!((pos.y - 0.7).abs() < f64::EPSILON);
        assert!((pos.zoom - 0.5).abs() < f64::EPSILON);
    }

    // --------------------------------------------------------------
    // Command handlers (integration with PtzState)
    // --------------------------------------------------------------

    #[tokio::test]
    async fn test_continuous_move_updates_position() {
        let state = test_state();
        let handler = PtzHandler(state.clone());
        let body = r#"<ContinuousMove>
            <Velocity>
                <PanTilt x="1.0" y="0.5" space="..."/>
                <Zoom x="0.2" space="..."/>
            </Velocity>
        </ContinuousMove>"#;
        let resp = handler.handle(body, &test_info()).await.unwrap();
        assert!(resp.contains("ContinuousMoveResponse"));
        assert!(resp.contains("soap:Envelope"));

        // Position should have been set moving (tick to advance)
        state.tick(50);
        let pos = state.get_position();
        assert!(pos.x > 0.0);
        assert!(pos.y > 0.0);
        assert!(pos.zoom > 0.0);
    }

    #[tokio::test]
    async fn test_absolute_move_reaches_target() {
        let state = test_state();
        let handler = PtzHandler(state.clone());
        let body = r#"<AbsoluteMove>
            <Position>
                <PanTilt x="0.5" y="-0.3" space="..."/>
                <Zoom x="0.8" space="..."/>
            </Position>
        </AbsoluteMove>"#;
        let resp = handler.handle(body, &test_info()).await.unwrap();
        assert!(resp.contains("AbsoluteMoveResponse"));

        // Tick to reach target
        for _ in 0..25 {
            state.tick(50);
        }
        let pos = state.get_position();
        assert!((pos.x - 0.5).abs() < 0.01);
        assert!((pos.y - (-0.3)).abs() < 0.01);
        assert!((pos.zoom - 0.8).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_relative_move_updates_immediately() {
        let state = test_state();
        let handler = PtzHandler(state.clone());
        let body = r#"<RelativeMove>
            <Translation>
                <PanTilt x="0.3" y="-0.2" space="..."/>
                <Zoom x="0.1" space="..."/>
            </Translation>
        </RelativeMove>"#;
        let resp = handler.handle(body, &test_info()).await.unwrap();
        assert!(resp.contains("RelativeMoveResponse"));

        let pos = state.get_position();
        assert!((pos.x - 0.3).abs() < f64::EPSILON);
        assert!((pos.y - (-0.2)).abs() < f64::EPSILON);
        assert!((pos.zoom - 0.1).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_stop_halts_movement() {
        let state = test_state();
        let handler = PtzHandler(state.clone());

        // Start moving
        state.continuous_move(Velocity {
            x: 1.0,
            y: 0.5,
            zoom: 0.2,
        });
        state.tick(50);
        assert_eq!(state.get_status(), "MOVING");

        // Stop
        let body = "<Stop/>";
        let resp = handler.handle(body, &test_info()).await.unwrap();
        assert!(resp.contains("StopResponse"));

        assert_eq!(state.get_status(), "IDLE");
        let pos_before = state.get_position();
        state.tick(50);
        let pos_after = state.get_position();
        assert_eq!(
            pos_before, pos_after,
            "position should not change after stop"
        );
    }

    #[tokio::test]
    async fn test_get_status_returns_position_and_status() {
        let state = test_state();
        let handler = PtzHandler(state.clone());

        // Move to a known position
        state.absolute_move(Position {
            x: 0.5,
            y: 0.3,
            zoom: 0.7,
        });
        for _ in 0..25 {
            state.tick(50);
        }

        let body = "<GetStatus/>";
        let resp = handler.handle(body, &test_info()).await.unwrap();
        assert!(resp.contains("GetStatusResponse"));
        assert!(resp.contains("PTZStatus"));
        assert!(resp.contains("PanTilt"));
        assert!(resp.contains("Zoom"));
        assert!(resp.contains("IDLE"));
        assert!(resp.contains("0.5"));
        assert!(resp.contains("0.3"));
        assert!(resp.contains("0.7"));
    }

    #[tokio::test]
    async fn test_preset_lifecycle() {
        let state = test_state();
        let handler = PtzHandler(state.clone());

        // Set a preset at current position
        let set_body = r#"<SetPreset><PresetToken>home</PresetToken></SetPreset>"#;
        let resp = handler.handle(set_body, &test_info()).await.unwrap();
        assert!(resp.contains("SetPresetResponse"));
        assert!(resp.contains("PresetToken"));
        assert!(resp.contains("home"));

        // Get presets
        let get_body = "<GetPresets/>";
        let resp = handler.handle(get_body, &test_info()).await.unwrap();
        assert!(resp.contains("GetPresetsResponse"));
        assert!(resp.contains("home"));

        // Goto preset
        let goto_body = r#"<GotoPreset><PresetToken>home</PresetToken></GotoPreset>"#;
        let resp = handler.handle(goto_body, &test_info()).await.unwrap();
        assert!(resp.contains("GotoPresetResponse"));

        // Remove preset
        let remove_body = r#"<RemovePreset><PresetToken>home</PresetToken></RemovePreset>"#;
        let resp = handler.handle(remove_body, &test_info()).await.unwrap();
        assert!(resp.contains("RemovePresetResponse"));

        // Verify removed
        assert_eq!(state.get_presets().len(), 0);
    }

    #[tokio::test]
    async fn test_get_nodes_contains_ptz_spaces() {
        let handler = PtzHandler(test_state());
        let body = "<GetNodes/>";
        let resp = handler.handle(body, &test_info()).await.unwrap();
        assert!(resp.contains("GetNodesResponse"));
        assert!(resp.contains("PTZNode"));
        assert!(resp.contains("SupportedPTZSpaces"));
        assert!(resp.contains("AbsolutePanTiltPositionSpace"));
        assert!(resp.contains("ContinuousPanTiltVelocitySpace"));
        assert!(resp.contains("ContinuousZoomVelocitySpace"));
    }

    #[tokio::test]
    async fn test_get_configurations_contains_default_config() {
        let handler = PtzHandler(test_state());
        let body = "<GetConfigurations/>";
        let resp = handler.handle(body, &test_info()).await.unwrap();
        assert!(resp.contains("GetConfigurationsResponse"));
        assert!(resp.contains("PTZConfiguration"));
        assert!(resp.contains("Default PTZ Configuration"));
        assert!(resp.contains("NodeToken"));
        assert!(resp.contains("DefaultPTZSpeed"));
    }

    #[tokio::test]
    async fn test_unknown_action_returns_error() {
        let handler = PtzHandler(test_state());
        let body = "<GetFoo/>";
        let result = handler.handle(body, &test_info()).await;
        assert!(result.is_err());
        match result {
            Err(OnvifError::ActionNotSupported(msg)) => {
                assert!(msg.contains("unknown ptz action"));
            }
            _ => panic!("expected ActionNotSupported"),
        }
    }

    #[tokio::test]
    async fn test_goto_missing_preset_returns_error() {
        let handler = PtzHandler(test_state());
        let body = r#"<GotoPreset><PresetToken>nonexistent</PresetToken></GotoPreset>"#;
        let result = handler.handle(body, &test_info()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_set_preset_auto_generates_token() {
        let state = test_state();
        let handler = PtzHandler(state.clone());

        // No PresetToken in request body — should auto-generate
        let body = r#"<SetPreset><PresetName>TestPreset</PresetName></SetPreset>"#;
        let resp = handler.handle(body, &test_info()).await.unwrap();
        assert!(resp.contains("SetPresetResponse"));
        assert!(resp.contains("PresetToken"));

        // State should have one preset with an auto-generated token
        assert_eq!(state.get_presets().len(), 1);
    }

    #[tokio::test]
    async fn test_set_preset_honors_preset_name() {
        // ONVIF WSDL: SetPreset carries PresetName — the stored preset (and
        // later GetPresets) must show it, not the hardcoded fallback.
        let state = test_state();
        let handler = PtzHandler(state.clone());

        let body = r#"<SetPreset><ProfileToken>p1</ProfileToken><PresetName>gate</PresetName></SetPreset>"#;
        handler.handle(body, &test_info()).await.unwrap();

        let presets = state.list_presets();
        assert_eq!(presets.len(), 1);
        assert_eq!(presets[0].name, "gate", "PresetName must be honored");
    }
}
