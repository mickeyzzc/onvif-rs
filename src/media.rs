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

/// Video encoder advertised by the Media service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoEncoding {
    /// H.264 (`<Encoding>H264</Encoding>`).
    H264,
    /// H.265 / HEVC (`<Encoding>H265</Encoding>`).
    H265,
}

impl VideoEncoding {
    /// ONVIF wire token.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            VideoEncoding::H264 => "H264",
            VideoEncoding::H265 => "H265",
        }
    }
}

/// One additional media profile advertised by GetProfiles — e.g. a
/// low-resolution bandwidth-saving substream next to the primary stream.
///
/// The primary profile stays the flat [`OnvifMediaConfig`] fields;
/// extras are listed in [`OnvifMediaConfig::extra_profiles`] in
/// advertisement order, always after the primary. Profile S consumers
/// that pick "the first profile" therefore keep getting the primary
/// stream.
#[derive(Debug, Clone)]
pub struct MediaProfileConfig {
    /// Profile token (`<Profiles token="...">`); matched against the
    /// `ProfileToken` argument of GetStreamUri.
    pub token: String,
    /// Human-readable profile name (`<Name>`); defaults to the token.
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate: u32,
    /// Advertised video encoder for this profile (default H.264).
    pub encoding: VideoEncoding,
    /// Video encoder configuration token; defaults to `<token>_encoder`,
    /// mirroring the onvif-go twin's derivation.
    pub encoder_token: String,
    /// RTSP URL path returned by GetStreamUri when this profile's token
    /// is requested.
    pub stream_path: String,
}

impl MediaProfileConfig {
    /// Construct with H.264 encoding, `name` = `token`, and the encoder
    /// token derived as `<token>_encoder`.
    #[must_use]
    pub fn new(
        token: &str,
        width: u32,
        height: u32,
        fps: u32,
        bitrate: u32,
        stream_path: &str,
    ) -> Self {
        Self {
            token: token.to_string(),
            name: token.to_string(),
            width,
            height,
            fps,
            bitrate,
            encoding: VideoEncoding::H264,
            encoder_token: format!("{token}_encoder"),
            stream_path: stream_path.to_string(),
        }
    }
}

/// Camera/media configuration consumed by the ONVIF Media service handlers.
#[derive(Debug, Clone)]
pub struct OnvifMediaConfig {
    pub camera_width: u32,
    pub camera_height: u32,
    pub camera_fps: u32,
    pub camera_bitrate: u32,
    pub rtsp_port: u16,
    pub device_ip: String,
    /// RTSP URL path returned by GetStreamUri (default `/stream`).
    ///
    /// Hosts whose RTSP server serves streams under a different path
    /// (e.g. notebook-cam's `/live/{camera_id}`) set this so the advertised
    /// URI actually resolves.
    pub stream_path: String,
    /// HTTP port of the host's JPEG snapshot endpoint, advertised by
    /// GetSnapshotUri (parameterless form, mirroring onvif-go's
    /// `SnapshotURIParameterless`). `0` disables the feature — GetSnapshotUri
    /// then faults with "snapshot not supported", the twin's
    /// `ErrSnapshotNotSupported` behavior.
    pub snapshot_port: u16,
    /// HTTP path of the snapshot endpoint (default `/snapshot.jpg`).
    pub snapshot_path: String,
    /// Profile token in GetProfiles (default `main`).
    pub profile_token: String,
    /// Video source token (default `videoSrc0`).
    pub video_source_token: String,
    /// Video encoder configuration token (default `enc0`).
    pub encoder_token: String,
    /// Advertised video encoder (default H.264; set H.265 for H.265 hosts).
    pub encoding: VideoEncoding,
    /// Human name of the video source in GetVideoSources (default
    /// `Video Source`). This is host identity, not a product name.
    pub video_source_name: String,
    /// Additional profiles advertised after the primary one (default
    /// empty). Each entry pairs its own geometry and RTSP path with a
    /// token; GetStreamUri resolves the request's `ProfileToken`
    /// against these, failing open to the primary stream for unknown or
    /// missing tokens.
    pub extra_profiles: Vec<MediaProfileConfig>,
}

impl OnvifMediaConfig {
    /// Construct with the historical default tokens (`main` / `videoSrc0` /
    /// `enc0`), H.264 encoding, and stream path `/stream`.
    #[must_use]
    pub fn new(
        camera_width: u32,
        camera_height: u32,
        camera_fps: u32,
        camera_bitrate: u32,
        rtsp_port: u16,
        device_ip: String,
    ) -> Self {
        Self {
            camera_width,
            camera_height,
            camera_fps,
            camera_bitrate,
            rtsp_port,
            device_ip,
            stream_path: "/stream".to_string(),
            snapshot_port: 0,
            snapshot_path: "/snapshot.jpg".to_string(),
            profile_token: "main".to_string(),
            video_source_token: "videoSrc0".to_string(),
            encoder_token: "enc0".to_string(),
            encoding: VideoEncoding::H264,
            video_source_name: "Video Source".to_string(),
            extra_profiles: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// XML building helper
// ---------------------------------------------------------------------------

fn write_text_element(writer: &mut Writer<Vec<u8>>, name: &str, text: &str) {
    let _ = writer.write_event(Event::Start(BytesStart::new(name)));
    let _ = writer.write_event(Event::Text(BytesText::from_escaped(
        crate::types::xml_escape(text),
    )));
    let _ = writer.write_event(Event::End(BytesEnd::new(name)));
}

// ---------------------------------------------------------------------------
// GetProfilesHandler
// ---------------------------------------------------------------------------

/// Geometry + tokens of one profile as written by [`GetProfilesHandler`].
struct ProfileWire<'a> {
    token: &'a str,
    name: &'a str,
    width: u32,
    height: u32,
    fps: u32,
    bitrate: u32,
    encoding: VideoEncoding,
    encoder_token: &'a str,
}

fn write_profile(
    writer: &mut Writer<Vec<u8>>,
    profile: &ProfileWire<'_>,
    video_source_token: &str,
) {
    // <Profiles token="...">
    let mut profiles = BytesStart::new("Profiles");
    profiles.push_attribute(("token", profile.token));
    writer
        .write_event(Event::Start(profiles))
        .unwrap_or_default();

    write_text_element(writer, "Name", profile.name);

    // <VideoSourceConfiguration token="...">
    let mut vs_cfg = BytesStart::new("VideoSourceConfiguration");
    vs_cfg.push_attribute(("token", video_source_token));
    writer.write_event(Event::Start(vs_cfg)).unwrap_or_default();
    write_text_element(writer, "Name", "VideoSourceConfig");
    write_text_element(writer, "SourceToken", video_source_token);
    write_text_element(writer, "UseCount", "1");
    // <Bounds width="W" height="H"/>
    let mut bounds = BytesStart::new("Bounds");
    let w_str = profile.width.to_string();
    let h_str = profile.height.to_string();
    bounds.push_attribute(("width", w_str.as_str()));
    bounds.push_attribute(("height", h_str.as_str()));
    writer.write_event(Event::Empty(bounds)).unwrap_or_default();
    writer
        .write_event(Event::End(BytesEnd::new("VideoSourceConfiguration")))
        .unwrap_or_default();

    // <VideoEncoderConfiguration token="...">
    let mut ve_cfg = BytesStart::new("VideoEncoderConfiguration");
    ve_cfg.push_attribute(("token", profile.encoder_token));
    writer.write_event(Event::Start(ve_cfg)).unwrap_or_default();
    write_text_element(writer, "Name", "VideoEncoderConfig");
    write_text_element(writer, "UseCount", "1");
    write_text_element(writer, "Encoding", profile.encoding.as_str());

    // <Resolution>
    writer
        .write_event(Event::Start(BytesStart::new("Resolution")))
        .unwrap_or_default();
    write_text_element(writer, "Width", &profile.width.to_string());
    write_text_element(writer, "Height", &profile.height.to_string());
    writer
        .write_event(Event::End(BytesEnd::new("Resolution")))
        .unwrap_or_default();

    // <RateControl>
    writer
        .write_event(Event::Start(BytesStart::new("RateControl")))
        .unwrap_or_default();
    write_text_element(writer, "FrameRateLimit", &profile.fps.to_string());
    write_text_element(writer, "BitrateLimit", &profile.bitrate.to_string());
    write_text_element(writer, "EncodingInterval", "1");
    writer
        .write_event(Event::End(BytesEnd::new("RateControl")))
        .unwrap_or_default();

    writer
        .write_event(Event::End(BytesEnd::new("VideoEncoderConfiguration")))
        .unwrap_or_default();
    writer
        .write_event(Event::End(BytesEnd::new("Profiles")))
        .unwrap_or_default();
}

/// Handler for the ONVIF GetProfiles SOAP action.
///
/// Returns Profile S compatible profiles — the primary one built from the
/// flat [`OnvifMediaConfig`] fields, followed by any
/// [`OnvifMediaConfig::extra_profiles`] (e.g. a low-resolution substream):
/// - VideoSourceConfiguration (bounds from the profile resolution)
/// - VideoEncoderConfiguration (rate control from the profile)
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
        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);

        // <GetProfilesResponse>
        writer
            .write_event(Event::Start(BytesStart::new("GetProfilesResponse")))
            .unwrap_or_default();

        write_profile(
            &mut writer,
            &ProfileWire {
                token: &self.config.profile_token,
                name: &self.config.profile_token,
                width: self.config.camera_width,
                height: self.config.camera_height,
                fps: self.config.camera_fps,
                bitrate: self.config.camera_bitrate,
                encoding: self.config.encoding,
                encoder_token: &self.config.encoder_token,
            },
            &self.config.video_source_token,
        );

        for extra in &self.config.extra_profiles {
            write_profile(
                &mut writer,
                &ProfileWire {
                    token: &extra.token,
                    name: &extra.name,
                    width: extra.width,
                    height: extra.height,
                    fps: extra.fps,
                    bitrate: extra.bitrate,
                    encoding: extra.encoding,
                    encoder_token: &extra.encoder_token,
                },
                &self.config.video_source_token,
            );
        }

        writer
            .write_event(Event::End(BytesEnd::new("GetProfilesResponse")))
            .unwrap_or_default();

        let body = String::from_utf8(writer.into_inner())
            .map_err(|e| OnvifError::Internal(format!("non-UTF-8 output from XML writer: {e}")))?;
        Ok(serialize_soap_response(&body))
    }
}

// ---------------------------------------------------------------------------
// GetStreamUriHandler
// ---------------------------------------------------------------------------

/// Extract the `ProfileToken` element text from a GetStreamUri SOAP body.
///
/// Tolerant by design: namespace prefixes (`tt:ProfileToken`), attributes
/// on the open tag, surrounding whitespace, and any malformed input are
/// all accepted — anything unparseable yields `None` so the handler can
/// fail open to the primary stream. Never panics on arbitrary input.
fn parse_profile_token(body: &str) -> Option<&str> {
    let mut rest = body;
    while let Some(open) = rest.find('<') {
        let after_open = &rest[open + 1..];
        let Some(tag_end) = after_open.find(|c: char| c == '>' || c.is_whitespace()) else {
            break;
        };
        let tag = &after_open[..tag_end];
        // Local name — strip any namespace prefix.
        let local = tag.rsplit(':').next().unwrap_or(tag);
        let Some(greater) = after_open.find('>') else {
            break;
        };
        if after_open[..greater].ends_with('/') {
            // Empty element (`<ProfileToken/>`) — no token text.
            rest = &after_open[greater..];
            continue;
        }
        if local == "ProfileToken" {
            let content = &after_open[greater + 1..];
            let close = content.find('<')?;
            let token = content[..close].trim();
            return (!token.is_empty()).then_some(token);
        }
        rest = &after_open[tag_end..];
    }
    None
}

/// Handler for the ONVIF GetStreamUri SOAP action.
///
/// Returns an RTSP URL built from the device IP and the configured RTSP
/// port. When the request carries a `ProfileToken` matching an entry of
/// [`OnvifMediaConfig::extra_profiles`], that profile's `stream_path` is
/// advertised; missing or unknown tokens fail open to the primary
/// `stream_path` (the historical single-profile behavior).
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
    async fn handle(&self, body: &str, request_info: &RequestInfo) -> Result<String, OnvifError> {
        let ip = resolve_server_ip(&request_info.server_ip, &self.config.device_ip);
        let stream_path = parse_profile_token(body)
            .and_then(|token| {
                self.config
                    .extra_profiles
                    .iter()
                    .find(|p| p.token == token)
                    .map(|p| p.stream_path.as_str())
            })
            .unwrap_or(&self.config.stream_path);
        let uri = format!("rtsp://{}:{}{}", ip, self.config.rtsp_port, stream_path);

        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
        writer
            .write_event(Event::Start(BytesStart::new("GetStreamUriResponse")))
            .unwrap_or_default();

        writer
            .write_event(Event::Start(BytesStart::new("MediaUri")))
            .unwrap_or_default();
        write_text_element(&mut writer, "Uri", &uri);
        write_text_element(&mut writer, "InvalidAfterConnect", "false");
        write_text_element(&mut writer, "InvalidAfterReboot", "false");
        write_text_element(&mut writer, "Timeout", "PT0S");
        writer
            .write_event(Event::End(BytesEnd::new("MediaUri")))
            .unwrap_or_default();

        writer
            .write_event(Event::End(BytesEnd::new("GetStreamUriResponse")))
            .unwrap_or_default();

        let body = String::from_utf8(writer.into_inner())
            .map_err(|e| OnvifError::Internal(format!("non-UTF-8 output from XML writer: {e}")))?;
        Ok(serialize_soap_response(&body))
    }
}

// ---------------------------------------------------------------------------
// GetSnapshotUriHandler
// ---------------------------------------------------------------------------

/// Handler for the ONVIF GetSnapshotUri SOAP action.
///
/// Advertises the host's HTTP JPEG snapshot endpoint (parameterless form,
/// mirroring onvif-go's `SnapshotURIParameterless`). Configure
/// [`OnvifMediaConfig::snapshot_port`] with the port of the HTTP server that
/// actually serves the JPEG; `0` (default) keeps the feature off and faults
/// with "snapshot not supported" — the twin's `ErrSnapshotNotSupported`.
pub struct GetSnapshotUriHandler {
    config: Arc<OnvifMediaConfig>,
}

impl GetSnapshotUriHandler {
    pub fn new(config: Arc<OnvifMediaConfig>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl OnvifActionHandler for GetSnapshotUriHandler {
    async fn handle(&self, _body: &str, request_info: &RequestInfo) -> Result<String, OnvifError> {
        if self.config.snapshot_port == 0 {
            return Err(OnvifError::ActionNotSupported(
                "snapshot not supported (OnvifMediaConfig::snapshot_port is unset)".to_string(),
            ));
        }
        let ip = resolve_server_ip(&request_info.server_ip, &self.config.device_ip);
        let uri = format!(
            "http://{}:{}{}",
            ip, self.config.snapshot_port, self.config.snapshot_path
        );

        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
        writer
            .write_event(Event::Start(BytesStart::new("GetSnapshotUriResponse")))
            .unwrap_or_default();

        writer
            .write_event(Event::Start(BytesStart::new("MediaUri")))
            .unwrap_or_default();
        write_text_element(&mut writer, "Uri", &uri);
        write_text_element(&mut writer, "InvalidAfterConnect", "false");
        write_text_element(&mut writer, "InvalidAfterReboot", "true");
        write_text_element(&mut writer, "Timeout", "PT5S");
        writer
            .write_event(Event::End(BytesEnd::new("MediaUri")))
            .unwrap_or_default();

        writer
            .write_event(Event::End(BytesEnd::new("GetSnapshotUriResponse")))
            .unwrap_or_default();

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
/// Returns a single physical video source whose token and name come from
/// [`OnvifMediaConfig`]. By design (byte-stability against raw-SOAP NVR
/// matching) the response carries only `token` + `Name` — resolution and
/// frame rate live in the profile (GetProfiles), not here.
pub struct GetVideoSourcesHandler {
    config: Arc<OnvifMediaConfig>,
}

impl GetVideoSourcesHandler {
    pub fn new(config: Arc<OnvifMediaConfig>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl OnvifActionHandler for GetVideoSourcesHandler {
    async fn handle(&self, _body: &str, _request_info: &RequestInfo) -> Result<String, OnvifError> {
        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
        writer
            .write_event(Event::Start(BytesStart::new("GetVideoSourcesResponse")))
            .unwrap_or_default();

        // <VideoSources token="...">
        {
            let mut vs = BytesStart::new("VideoSources");
            vs.push_attribute(("token", self.config.video_source_token.as_str()));
            writer.write_event(Event::Start(vs)).unwrap_or_default();
        }
        write_text_element(&mut writer, "Name", &self.config.video_source_name);
        writer
            .write_event(Event::End(BytesEnd::new("VideoSources")))
            .unwrap_or_default();

        writer
            .write_event(Event::End(BytesEnd::new("GetVideoSourcesResponse")))
            .unwrap_or_default();

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
            stream_path: "/stream".to_string(),
            snapshot_port: 0,
            snapshot_path: "/snapshot.jpg".to_string(),
            profile_token: "main".to_string(),
            video_source_token: "videoSrc0".to_string(),
            encoder_token: "enc0".to_string(),
            encoding: VideoEncoding::H264,
            video_source_name: "Video Source".to_string(),
            camera_width: 1920,
            camera_height: 1080,
            camera_fps: 30,
            camera_bitrate: 4_000_000,
            rtsp_port: 8554,
            device_ip: "192.168.1.100".to_string(),
            extra_profiles: Vec::new(),
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
    async fn test_get_stream_uri_honors_custom_stream_path() {
        let config = Arc::new(OnvifMediaConfig {
            stream_path: "/live/cam-42".to_string(),
            snapshot_port: 0,
            snapshot_path: "/snapshot.jpg".to_string(),
            profile_token: "main".to_string(),
            video_source_token: "videoSrc0".to_string(),
            encoder_token: "enc0".to_string(),
            encoding: VideoEncoding::H264,
            video_source_name: "Video Source".to_string(),
            camera_width: 1280,
            camera_height: 720,
            camera_fps: 25,
            camera_bitrate: 2_500_000,
            rtsp_port: 8554,
            device_ip: "192.168.1.10".to_string(),
            extra_profiles: Vec::new(),
        });
        let handler = GetStreamUriHandler::new(config);
        let result = handler.handle("", &req_info("192.168.1.10")).await.unwrap();
        assert!(
            result.contains("rtsp://192.168.1.10:8554/live/cam-42"),
            "custom stream path must be advertised, got: {result}"
        );
    }

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
    // GetSnapshotUri
    // ------------------------------------------------------------------

    fn snapshot_config() -> OnvifMediaConfig {
        let mut cfg = (*test_config()).clone();
        cfg.snapshot_port = 8088;
        cfg
    }

    #[tokio::test]
    async fn test_get_snapshot_uri_advertises_http_snapshot() {
        let handler = GetSnapshotUriHandler::new(Arc::new(snapshot_config()));
        let result = handler.handle("", &req_info("10.0.0.5")).await.unwrap();

        assert!(result.contains("GetSnapshotUriResponse"));
        assert!(result.contains("MediaUri"));
        assert!(
            result.contains("http://10.0.0.5:8088/snapshot.jpg"),
            "should advertise the host snapshot endpoint, got: {result}"
        );
        // MediaUri semantics mirror the onvif-go twin (snapshot: fresh fetch,
        // invalid after reboot, 5 s validity).
        assert!(result.contains("<InvalidAfterConnect>false</InvalidAfterConnect>"));
        assert!(result.contains("<InvalidAfterReboot>true</InvalidAfterReboot>"));
        assert!(result.contains("<Timeout>PT5S</Timeout>"));
    }

    #[tokio::test]
    async fn test_get_snapshot_uri_honors_custom_path_and_fallback_ip() {
        let mut cfg = snapshot_config();
        cfg.snapshot_path = "/cgi-bin/snap.jpeg".to_string();
        let handler = GetSnapshotUriHandler::new(Arc::new(cfg));

        // Empty per-request IP → fall back to the configured device IP.
        let result = handler.handle("", &req_info("")).await.unwrap();
        assert!(
            result.contains("http://192.168.1.100:8088/cgi-bin/snap.jpeg"),
            "custom path + fallback IP, got: {result}"
        );
    }

    #[tokio::test]
    async fn test_get_snapshot_uri_disabled_faults() {
        // snapshot_port = 0 (the default) → the handler must fault instead of
        // advertising a URI nothing serves (onvif-go's ErrSnapshotNotSupported).
        let handler = GetSnapshotUriHandler::new(test_config());
        let err = handler.handle("", &req_info("10.0.0.1")).await.unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("not supported"),
            "expected a not-supported fault, got: {err}"
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
        assert!(result.contains("Video Source"), "neutral default name");
        assert!(!result.contains("Pi Camera"), "no origin-hardware branding");
        assert!(result.contains("soap:Envelope"));
    }

    // ------------------------------------------------------------------
    // Multiple profiles (main + substreams) — GetProfiles advertises the
    // primary profile first, extras after; GetStreamUri routes by the
    // request's ProfileToken.
    // ------------------------------------------------------------------

    fn multi_profile_config() -> Arc<OnvifMediaConfig> {
        let mut cfg = (*test_config()).clone();
        cfg.extra_profiles = vec![MediaProfileConfig {
            token: "sub".to_string(),
            name: "sub".to_string(),
            width: 640,
            height: 360,
            fps: 15,
            bitrate: 400_000,
            encoding: VideoEncoding::H264,
            encoder_token: "sub_encoder".to_string(),
            stream_path: "/sub".to_string(),
        }];
        Arc::new(cfg)
    }

    #[tokio::test]
    async fn test_get_profiles_extra_profiles_advertised_after_primary() {
        let handler = GetProfilesHandler::new(multi_profile_config());
        let result = handler.handle("", &req_info("10.0.0.1")).await.unwrap();

        assert!(
            result.contains(r#"token="main""#) && result.contains(r#"token="sub""#),
            "both profiles advertised, got: {result}"
        );
        let main_at = result.find(r#"token="main""#).unwrap_or_default();
        let sub_at = result.find(r#"token="sub""#).unwrap_or_default();
        assert!(
            main_at < sub_at,
            "primary profile must come first (Profile S clients pick the first), got: {result}"
        );

        // The sub profile block carries its own encoder geometry.
        assert!(
            result.contains("<Width>640</Width>"),
            "sub width, got: {result}"
        );
        assert!(result.contains("<Height>360</Height>"));
        assert!(result.contains("<FrameRateLimit>15</FrameRateLimit>"));
        assert!(result.contains("<BitrateLimit>400000</BitrateLimit>"));
        assert!(result.contains(r#"token="sub_encoder""#));

        // Exactly two Profiles elements — no duplication of the primary.
        assert_eq!(
            result.matches("<Profiles ").count(),
            2,
            "expected exactly two Profiles elements, got: {result}"
        );
    }

    #[tokio::test]
    async fn test_get_profiles_single_profile_shape_unchanged() {
        // No extra_profiles → exactly one Profiles element, primary geometry.
        let handler = GetProfilesHandler::new(test_config());
        let result = handler.handle("", &req_info("10.0.0.1")).await.unwrap();
        assert_eq!(result.matches("<Profiles ").count(), 1);
        assert!(!result.contains(r#"token="sub""#));
    }

    fn stream_uri_body(token: &str) -> String {
        format!(
            "<GetStreamUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\">\
             <ProfileToken>{token}</ProfileToken></GetStreamUri>"
        )
    }

    #[tokio::test]
    async fn test_get_stream_uri_routes_extra_profile_token() {
        let handler = GetStreamUriHandler::new(multi_profile_config());

        let sub = handler
            .handle(&stream_uri_body("sub"), &req_info("10.0.0.1"))
            .await
            .unwrap();
        assert!(
            sub.contains("rtsp://10.0.0.1:8554/sub"),
            "sub token must map to the sub stream path, got: {sub}"
        );

        let main = handler
            .handle(&stream_uri_body("main"), &req_info("10.0.0.1"))
            .await
            .unwrap();
        assert!(main.contains("rtsp://10.0.0.1:8554/stream"));

        // Unknown and missing tokens fail open to the primary stream —
        // legacy clients that never send a token keep the historical URI.
        let unknown = handler
            .handle(&stream_uri_body("profile_7"), &req_info("10.0.0.1"))
            .await
            .unwrap();
        assert!(unknown.contains("rtsp://10.0.0.1:8554/stream"));

        let missing = handler.handle("", &req_info("10.0.0.1")).await.unwrap();
        assert!(missing.contains("rtsp://10.0.0.1:8554/stream"));
    }

    #[tokio::test]
    async fn test_get_stream_uri_token_namespaced_and_attributed() {
        let handler = GetStreamUriHandler::new(multi_profile_config());

        let namespaced = handler
            .handle(
                "<GetStreamUri><tt:ProfileToken>sub</tt:ProfileToken></GetStreamUri>",
                &req_info("10.0.0.1"),
            )
            .await
            .unwrap();
        assert!(
            namespaced.contains("rtsp://10.0.0.1:8554/sub"),
            "namespace prefixes must not defeat token routing, got: {namespaced}"
        );

        let attributed = handler
            .handle(
                "<GetStreamUri><ProfileToken xmlns=\"http://www.onvif.org/ver10/media/wsdl\">sub</ProfileToken></GetStreamUri>",
                &req_info("10.0.0.1"),
            )
            .await
            .unwrap();
        assert!(attributed.contains("rtsp://10.0.0.1:8554/sub"));
    }

    #[test]
    fn test_parse_profile_token_forms() {
        // Plain element.
        assert_eq!(
            parse_profile_token("<GetStreamUri><ProfileToken>sub</ProfileToken></GetStreamUri>"),
            Some("sub")
        );
        // Namespaced element.
        assert_eq!(
            parse_profile_token("<tt:ProfileToken>sub</tt:ProfileToken>"),
            Some("sub")
        );
        // Attributes on the open tag.
        assert_eq!(
            parse_profile_token(r#"<ProfileToken xmlns="x">sub</ProfileToken>"#),
            Some("sub")
        );
        // Whitespace around the token text is trimmed.
        assert_eq!(
            parse_profile_token("<ProfileToken>\n  sub  </ProfileToken>"),
            Some("sub")
        );
        // Empty element / empty content / absent / garbage → no token.
        assert_eq!(parse_profile_token("<ProfileToken/>"), None);
        assert_eq!(parse_profile_token("<ProfileToken></ProfileToken>"), None);
        assert_eq!(parse_profile_token("<GetStreamUri/>"), None);
        assert_eq!(parse_profile_token("not xml at all"), None);
        assert_eq!(parse_profile_token("<<<<"), None);
        assert_eq!(parse_profile_token(""), None);
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
