// ---------------------------------------------------------------------------
// ONVIF Media Service — handler implementations for GetProfiles,
// GetStreamUri, and GetVideoSources.
//
// Each handler implements the OnvifActionHandler trait and holds a shared
// reference to OnvifMediaConfig (camera resolution, fps, bitrate, RTSP port,
// device IP).
//
// GetStreamUri uses the per-request server IP (the local interface that
// received the ONVIF connection) so the returned RTSP URL is reachable from
// the caller.  When `server_ip` is empty — e.g. during unit tests or when
// local_addr could not be determined — it falls back to the startup-detected
// `device_ip`.
// ---------------------------------------------------------------------------

use std::sync::Arc;

use async_trait::async_trait;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;

use crate::server::OnvifActionHandler;
use crate::types::{resolve_server_ip, serialize_soap_response, OnvifError, RequestInfo};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Camera/media configuration consumed by the ONVIF Media service handlers.
#[derive(Debug, Clone)]
pub struct OnvifMediaConfig {
    pub camera_width: u32,
    pub camera_height: u32,
    pub camera_fps: u32,
    pub camera_bitrate: u32,
    pub rtsp_port: u16,
    pub device_ip: String,
}

// ---------------------------------------------------------------------------
// XML building helper
// ---------------------------------------------------------------------------

fn write_text_element(writer: &mut Writer<Vec<u8>>, name: &str, text: &str) {
    let _ = writer.write_event(Event::Start(BytesStart::new(name)));
    let _ = writer.write_event(Event::Text(BytesText::new(text)));
    let _ = writer.write_event(Event::End(BytesEnd::new(name)));
}

// ---------------------------------------------------------------------------
// GetProfilesHandler
// ---------------------------------------------------------------------------

/// Handler for the ONVIF GetProfiles SOAP action.
///
/// Returns a single Profile S compatible profile containing:
/// - VideoSourceConfiguration (bounds from camera resolution)
/// - VideoEncoderConfiguration (H.264, rate control from config)
pub struct GetProfilesHandler {
    config: Arc<OnvifMediaConfig>,
}

impl GetProfilesHandler {
    pub fn new(config: Arc<OnvifMediaConfig>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl OnvifActionHandler for GetProfilesHandler {
    async fn handle(&self, _body: &str, _request_info: &RequestInfo) -> Result<String, OnvifError> {
        let w = self.config.camera_width;
        let h = self.config.camera_height;
        let fps = self.config.camera_fps;
        let bitrate = self.config.camera_bitrate;

        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);

        // <GetProfilesResponse>
        writer
            .write_event(Event::Start(BytesStart::new("GetProfilesResponse")))
            .unwrap();

        // <Profiles token="main">
        {
            let mut profiles = BytesStart::new("Profiles");
            profiles.push_attribute(("token", "main"));
            writer.write_event(Event::Start(profiles)).unwrap();
        }

        write_text_element(&mut writer, "Name", "main");

        // <VideoSourceConfiguration token="videoSrc0">
        {
            let mut vs_cfg = BytesStart::new("VideoSourceConfiguration");
            vs_cfg.push_attribute(("token", "videoSrc0"));
            writer.write_event(Event::Start(vs_cfg)).unwrap();
        }
        write_text_element(&mut writer, "Name", "VideoSourceConfig");
        write_text_element(&mut writer, "SourceToken", "videoSrc0");
        write_text_element(&mut writer, "UseCount", "1");
        // <Bounds width="W" height="H"/>
        {
            let mut bounds = BytesStart::new("Bounds");
            let w_str = w.to_string();
            let h_str = h.to_string();
            bounds.push_attribute(("width", w_str.as_str()));
            bounds.push_attribute(("height", h_str.as_str()));
            writer.write_event(Event::Empty(bounds)).unwrap();
        }
        writer
            .write_event(Event::End(BytesEnd::new("VideoSourceConfiguration")))
            .unwrap();

        // <VideoEncoderConfiguration token="enc0">
        {
            let mut ve_cfg = BytesStart::new("VideoEncoderConfiguration");
            ve_cfg.push_attribute(("token", "enc0"));
            writer.write_event(Event::Start(ve_cfg)).unwrap();
        }
        write_text_element(&mut writer, "Name", "VideoEncoderConfig");
        write_text_element(&mut writer, "UseCount", "1");
        write_text_element(&mut writer, "Encoding", "H264");

        // <Resolution>
        writer
            .write_event(Event::Start(BytesStart::new("Resolution")))
            .unwrap();
        write_text_element(&mut writer, "Width", &w.to_string());
        write_text_element(&mut writer, "Height", &h.to_string());
        writer
            .write_event(Event::End(BytesEnd::new("Resolution")))
            .unwrap();

        // <RateControl>
        writer
            .write_event(Event::Start(BytesStart::new("RateControl")))
            .unwrap();
        write_text_element(&mut writer, "FrameRateLimit", &fps.to_string());
        write_text_element(&mut writer, "BitrateLimit", &bitrate.to_string());
        write_text_element(&mut writer, "EncodingInterval", "1");
        writer
            .write_event(Event::End(BytesEnd::new("RateControl")))
            .unwrap();

        writer
            .write_event(Event::End(BytesEnd::new("VideoEncoderConfiguration")))
            .unwrap();
        writer
            .write_event(Event::End(BytesEnd::new("Profiles")))
            .unwrap();
        writer
            .write_event(Event::End(BytesEnd::new("GetProfilesResponse")))
            .unwrap();

        let body = String::from_utf8(writer.into_inner())
            .map_err(|e| OnvifError::Internal(format!("non-UTF-8 output from XML writer: {e}")))?;
        Ok(serialize_soap_response(&body))
    }
}

// ---------------------------------------------------------------------------
// GetStreamUriHandler
// ---------------------------------------------------------------------------

/// Handler for the ONVIF GetStreamUri SOAP action.
///
/// Returns an RTSP URL built from the device IP and the configured RTSP port.
pub struct GetStreamUriHandler {
    config: Arc<OnvifMediaConfig>,
}

impl GetStreamUriHandler {
    pub fn new(config: Arc<OnvifMediaConfig>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl OnvifActionHandler for GetStreamUriHandler {
    async fn handle(&self, _body: &str, request_info: &RequestInfo) -> Result<String, OnvifError> {
        let ip = resolve_server_ip(&request_info.server_ip, &self.config.device_ip);
        let uri = format!("rtsp://{}:{}/stream", ip, self.config.rtsp_port);

        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
        writer
            .write_event(Event::Start(BytesStart::new("GetStreamUriResponse")))
            .unwrap();

        writer
            .write_event(Event::Start(BytesStart::new("MediaUri")))
            .unwrap();
        write_text_element(&mut writer, "Uri", &uri);
        write_text_element(&mut writer, "InvalidAfterConnect", "false");
        write_text_element(&mut writer, "InvalidAfterReboot", "false");
        write_text_element(&mut writer, "Timeout", "PT0S");
        writer
            .write_event(Event::End(BytesEnd::new("MediaUri")))
            .unwrap();

        writer
            .write_event(Event::End(BytesEnd::new("GetStreamUriResponse")))
            .unwrap();

        let body = String::from_utf8(writer.into_inner())
            .map_err(|e| OnvifError::Internal(format!("non-UTF-8 output from XML writer: {e}")))?;
        Ok(serialize_soap_response(&body))
    }
}

// ---------------------------------------------------------------------------
// GetVideoSourcesHandler
// ---------------------------------------------------------------------------

/// Handler for the ONVIF GetVideoSources SOAP action.
///
/// Returns a single physical video source (Pi Camera) with the configured
/// resolution, frame rate, and bitrate baked into the profile.
pub struct GetVideoSourcesHandler {
    _config: Arc<OnvifMediaConfig>,
}

impl GetVideoSourcesHandler {
    pub fn new(config: Arc<OnvifMediaConfig>) -> Self {
        Self { _config: config }
    }
}

#[async_trait]
impl OnvifActionHandler for GetVideoSourcesHandler {
    async fn handle(&self, _body: &str, _request_info: &RequestInfo) -> Result<String, OnvifError> {
        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
        writer
            .write_event(Event::Start(BytesStart::new("GetVideoSourcesResponse")))
            .unwrap();

        // <VideoSources token="videoSrc0">
        {
            let mut vs = BytesStart::new("VideoSources");
            vs.push_attribute(("token", "videoSrc0"));
            writer.write_event(Event::Start(vs)).unwrap();
        }
        write_text_element(&mut writer, "Name", "Pi Camera");
        writer
            .write_event(Event::End(BytesEnd::new("VideoSources")))
            .unwrap();

        writer
            .write_event(Event::End(BytesEnd::new("GetVideoSourcesResponse")))
            .unwrap();

        let body = String::from_utf8(writer.into_inner())
            .map_err(|e| OnvifError::Internal(format!("non-UTF-8 output from XML writer: {e}")))?;
        Ok(serialize_soap_response(&body))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuthResult;

    fn test_config() -> Arc<OnvifMediaConfig> {
        Arc::new(OnvifMediaConfig {
            camera_width: 1920,
            camera_height: 1080,
            camera_fps: 30,
            camera_bitrate: 4_000_000,
            rtsp_port: 8554,
            device_ip: "192.168.1.100".to_string(),
        })
    }

    fn req_info(server_ip: &str) -> RequestInfo {
        RequestInfo {
            client_ip: "10.0.0.1".to_string(),
            server_ip: server_ip.to_string(),
            auth_result: AuthResult {
                username: "admin".to_string(),
                authenticated: true,
            },
        }
    }

    // ------------------------------------------------------------------
    // GetProfiles
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_get_profiles_response() {
        let handler = GetProfilesHandler::new(test_config());
        let result = handler.handle("", &req_info("10.0.0.1")).await.unwrap();

        // SOAP envelope wrapping
        assert!(
            result.contains("soap:Envelope"),
            "should have SOAP envelope"
        );
        assert!(result.contains("soap:Body"), "should have SOAP body");

        // Response element
        assert!(result.contains("GetProfilesResponse"));

        // Profile attributes
        assert!(result.contains("Profiles"), "should have Profiles element");
        assert!(
            result.contains(r#"token="main""#),
            "should have profile token"
        );

        // Video source configuration
        assert!(
            result.contains("VideoSourceConfiguration"),
            "should have VideoSourceConfiguration"
        );
        assert!(
            result.contains(r#"token="videoSrc0""#),
            "should have source token"
        );

        // Bounds with resolution from config
        assert!(
            result.contains(r#"width="1920""#),
            "should have correct width"
        );
        assert!(
            result.contains(r#"height="1080""#),
            "should have correct height"
        );

        // Video encoder configuration
        assert!(
            result.contains("VideoEncoderConfiguration"),
            "should have VideoEncoderConfiguration"
        );
        assert!(result.contains("H264"), "should be H.264 encoding");

        // Resolution elements
        assert!(
            result.contains("<Width>1920</Width>"),
            "should have Width element"
        );
        assert!(
            result.contains("<Height>1080</Height>"),
            "should have Height element"
        );

        // Rate control
        assert!(result.contains("<FrameRateLimit>30</FrameRateLimit>"));
        assert!(result.contains("<BitrateLimit>4000000</BitrateLimit>"));
        assert!(result.contains("<EncodingInterval>1</EncodingInterval>"));
    }

    // ------------------------------------------------------------------
    // GetStreamUri
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_get_stream_uri_dynamic_ip() {
        let handler = GetStreamUriHandler::new(test_config());
        let result = handler.handle("", &req_info("10.0.0.5")).await.unwrap();

        // Must use the per-request client IP
        assert!(
            result.contains("rtsp://10.0.0.5:8554/stream"),
            "should use dynamic client IP"
        );
        assert!(result.contains("GetStreamUriResponse"));
        assert!(result.contains("MediaUri"));
        assert!(result.contains("InvalidAfterConnect"));
        assert!(result.contains("InvalidAfterReboot"));
        assert!(result.contains("Timeout"));
    }

    #[tokio::test]
    async fn test_get_stream_uri_fallback_ip() {
        let handler = GetStreamUriHandler::new(test_config());

        // Empty client_ip -> fallback to device_ip from config
        let result = handler.handle("", &req_info("")).await.unwrap();

        assert!(
            result.contains("rtsp://192.168.1.100:8554/stream"),
            "should fall back to device IP when client IP is empty"
        );
    }

    #[tokio::test]
    async fn test_get_stream_uri_different_port() {
        let mut cfg = (*test_config()).clone();
        cfg.rtsp_port = 554;
        let config = Arc::new(cfg);
        let handler = GetStreamUriHandler::new(config);

        let result = handler.handle("", &req_info("10.0.0.1")).await.unwrap();
        assert!(
            result.contains("rtsp://10.0.0.1:554/stream"),
            "should use configured RTSP port"
        );
    }

    // ------------------------------------------------------------------
    // GetVideoSources
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_get_video_sources_response() {
        let handler = GetVideoSourcesHandler::new(test_config());
        let result = handler.handle("", &req_info("")).await.unwrap();

        assert!(result.contains("GetVideoSourcesResponse"));
        assert!(result.contains(r#"token="videoSrc0""#));
        assert!(result.contains("Pi Camera"));
        assert!(result.contains("soap:Envelope"));
    }

    // ------------------------------------------------------------------
    // Malformed request handling — handlers must not panic on arbitrary
    // body input (they ignore the body, so any content is acceptable).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_ignores_malformed_body() {
        let cfg = test_config();
        let handlers: Vec<Box<dyn OnvifActionHandler>> = vec![
            Box::new(GetProfilesHandler::new(Arc::clone(&cfg))),
            Box::new(GetStreamUriHandler::new(Arc::clone(&cfg))),
            Box::new(GetVideoSourcesHandler::new(Arc::clone(&cfg))),
        ];

        let garbage_bodies = vec!["", "not xml", "<broken>", "{{{{{"];

        for handler in &handlers {
            for garbage in &garbage_bodies {
                let result = handler.handle(garbage, &req_info("10.0.0.1")).await;
                assert!(result.is_ok(), "handler should not fail on garbage input");
                let xml = result.unwrap();
                assert!(
                    xml.contains("soap:Envelope"),
                    "should still produce valid SOAP envelope"
                );
            }
        }
    }
}
