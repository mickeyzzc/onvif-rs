//! ONVIF Media2 service client family (tr2, ver20/media/wsdl) — the twin
//! of the Go library's `media2` package: the codec-agnostic configuration
//! model where `Encoding` is a free media subtype name (H264/H265 + IANA
//! types like AV1), which is what makes H.265/AV1 configuration possible.
//!
//! Endpoint routing mirrors the Go twin's `EndpointFor(api.ServiceMedia2)`:
//! Media2 posts to its OWN discovered endpoint — the ver20/media XAddr
//! from GetServices (authoritative for dual-face and Media2-only devices),
//! falling back to the media1 endpoint and then the device endpoint. The
//! Rust [`SoapClient`] carries no discovery state, so every method here
//! takes the endpoint URL as its first argument: pass the discovered
//! ver20/media XAddr when you have one, or the client's device endpoint
//! (Go's final fallback — plenty of single-face devices dispatch tr2
//! actions there).
//!
//! Method names carry a `media2_` prefix: they are inherent methods on the
//! same [`SoapClient`] as the ver10 media family ([`crate::client::media`]),
//! whose `GetProfiles`/`GetStreamUri`/`GetSnapshotUri`/
//! `GetVideoEncoderConfigurations` would otherwise collide.

use crate::types::xml_escape;

use super::media::{find_desc, parse_xml_tree, XmlElem};
use super::{ClientError, SoapClient};

/// The Media2 service WSDL namespace (`tr2`).
const TR2_NS: &str = "http://www.onvif.org/ver20/media/wsdl";
/// The ver10 schema namespace (`tt`) — the namespace of the
/// configuration-typed payload children.
const TT_NS: &str = "http://www.onvif.org/ver10/schema";

// ---------------------------------------------------------------------------
// Types (the Go media2 package's shapes, snake_case)
// ---------------------------------------------------------------------------

/// One tr2:MediaProfile: video encoding carried inline (fully), the other
/// configuration families by reference (token + name).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Profile {
    pub token: String,
    /// Whether the device forbids deleting this profile.
    pub fixed: bool,
    pub name: String,
    /// The inline video encoder configuration.
    pub video_encoder: Option<VideoEncoderConfiguration>,
    pub video_source: Option<ConfigurationRef>,
    pub audio_source: Option<ConfigurationRef>,
    pub audio_encoder: Option<ConfigurationRef>,
    pub analytics: Option<ConfigurationRef>,
    pub ptz: Option<ConfigurationRef>,
    pub metadata: Option<ConfigurationRef>,
}

/// A reference to one inline configuration by token and name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigurationRef {
    pub token: String,
    pub name: String,
    pub use_count: i64,
}

/// tt:VideoEncoder2Configuration — a free `Encoding` media subtype
/// (H264/H265/AV1/…) plus resolution, rate control, quality and the GOP
/// attributes (`quality` is a float → `PartialEq` only).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VideoEncoderConfiguration {
    pub token: String,
    pub name: String,
    pub use_count: i64,
    pub encoding: String,
    pub resolution: Resolution,
    pub rate_control: Option<RateControl>,
    pub quality: f32,
    /// Attribute on the wire; `None` when the device reports none.
    pub gov_length: Option<i64>,
    /// Attribute on the wire; `None` when the device reports none.
    pub anchor_frame_distance: Option<i64>,
}

/// tt:VideoResolution2.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolution {
    pub width: i64,
    pub height: i64,
}

/// tt:VideoRateControl2.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RateControl {
    pub frame_rate_limit: f32,
    pub bitrate_limit: i64,
    pub encoding_interval: Option<i64>,
}

/// One tt:VideoEncoder2ConfigurationOptions answer — the device returns
/// one per supported encoding.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VideoEncoderOptions {
    pub encoding: String,
    pub quality_range: Option<FloatRange>,
    pub resolutions: Vec<Resolution>,
    pub bitrate_range: Option<IntRange>,
    /// Space-separated xs:list attribute on the wire.
    pub gov_length_range: Vec<i64>,
    /// Space-separated xs:list attribute on the wire.
    pub frame_rate_range: Vec<f32>,
}

/// tt:FloatRange.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FloatRange {
    pub min: f32,
    pub max: f32,
}

/// tt:IntRange.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntRange {
    pub min: i64,
    pub max: i64,
}

/// How many concurrent encoder applications one codec supports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EncoderInstance {
    pub encoding: String,
    pub number: i64,
}

/// The GetVideoEncoderInstances answer: per-codec limits plus the
/// guaranteed total.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EncoderInstanceInfo {
    pub codecs: Vec<EncoderInstance>,
    pub total: i64,
}

/// The Media2 capabilities answer (the flags an NVR probes before using
/// snapshot / OSD / streaming features).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceCapabilities {
    pub snapshot_uri: bool,
    pub rotation: bool,
    pub osd: bool,
    /// From ProfileCapabilities.
    pub maximum_number_of_profiles: i64,
    /// From StreamingCapabilities.
    pub rtsp_streaming: bool,
}

/// tt:AudioEncoder2Configuration — Media2's codec-agnostic audio config
/// (`Encoding` is an IANA media subtype such as `audio/PCMA`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioEncoderConfiguration {
    pub token: String,
    pub name: String,
    pub use_count: i64,
    pub encoding: String,
    pub bitrate: i64,
    pub sample_rate: i64,
}

/// Which PTZ fields a Media2 metadata stream carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataPtzStatus {
    pub status: bool,
    pub position: bool,
}

/// tt:MetadataConfiguration (Media2 flavor).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataConfiguration {
    pub token: String,
    pub name: String,
    pub use_count: i64,
    pub ptz_status: Option<MetadataPtzStatus>,
    pub analytics: bool,
}

// ---------------------------------------------------------------------------
// Request builders (byte-compatible with the Go envelopes)
// ---------------------------------------------------------------------------

fn tr2_empty_op(op: &str) -> String {
    format!("<tr2:{op} xmlns:tr2=\"{TR2_NS}\"></tr2:{op}>")
}

fn tr2_token_op(op: &str, child: &str, value: &str) -> String {
    format!(
        "<tr2:{op} xmlns:tr2=\"{TR2_NS}\"><tr2:{child}>{}</tr2:{child}></tr2:{op}>",
        xml_escape(value)
    )
}

/// An operation whose optional `ConfigurationToken` filter is omitted when
/// empty (Go `omitempty`).
fn tr2_opt_config_op(op: &str, configuration_token: &str) -> String {
    if configuration_token.is_empty() {
        tr2_empty_op(op)
    } else {
        tr2_token_op(op, "ConfigurationToken", configuration_token)
    }
}

/// GetProfiles: optional `Token` selector then repeated `Type` filters
/// (VideoSource/AudioSource/VideoEncoder/…, tr2:ConfigurationEnumeration).
fn build_get_profiles_request(token: &str, types: &[&str]) -> String {
    let mut body = format!("<tr2:GetProfiles xmlns:tr2=\"{TR2_NS}\">");
    if !token.is_empty() {
        body.push_str(&format!("<tr2:Token>{}</tr2:Token>", xml_escape(token)));
    }
    for ty in types {
        body.push_str(&format!("<tr2:Type>{}</tr2:Type>", xml_escape(ty)));
    }
    body.push_str("</tr2:GetProfiles>");
    body
}

/// GetVideoEncoderConfigurationOptions: optional ConfigurationToken then
/// ProfileToken (Go struct order).
fn build_configuration_options_request(configuration_token: &str, profile_token: &str) -> String {
    let mut body = format!("<tr2:GetVideoEncoderConfigurationOptions xmlns:tr2=\"{TR2_NS}\">");
    if !configuration_token.is_empty() {
        body.push_str(&format!(
            "<tr2:ConfigurationToken>{}</tr2:ConfigurationToken>",
            xml_escape(configuration_token)
        ));
    }
    if !profile_token.is_empty() {
        body.push_str(&format!(
            "<tr2:ProfileToken>{}</tr2:ProfileToken>",
            xml_escape(profile_token)
        ));
    }
    body.push_str("</tr2:GetVideoEncoderConfigurationOptions>");
    body
}

/// SetVideoEncoderConfiguration: the tt:VideoEncoder2Configuration
/// serialization shape — attributes (`token`, then the optional
/// `GovLength`/`AnchorFrameDistance`) first, then the tt-typed children in
/// Go struct order. The `Encoding` passes through verbatim
/// (H264/H265/AV1/…).
fn build_set_video_encoder_configuration_request(config: &VideoEncoderConfiguration) -> String {
    let mut attrs = format!(" token=\"{}\"", xml_escape(&config.token));
    if let Some(gov) = config.gov_length {
        attrs.push_str(&format!(" GovLength=\"{gov}\""));
    }
    if let Some(anchor) = config.anchor_frame_distance {
        attrs.push_str(&format!(" AnchorFrameDistance=\"{anchor}\""));
    }

    let mut body = format!(
        "<tr2:SetVideoEncoderConfiguration xmlns:tr2=\"{TR2_NS}\" xmlns:tt=\"{TT_NS}\"\
         ><tr2:Configuration{attrs}>\
         <tt:Name>{}</tt:Name><tt:UseCount>{}</tt:UseCount>\
         <tt:Encoding>{}</tt:Encoding>\
         <tt:Resolution><tt:Width>{}</tt:Width><tt:Height>{}</tt:Height></tt:Resolution>",
        xml_escape(&config.name),
        config.use_count,
        xml_escape(&config.encoding),
        config.resolution.width,
        config.resolution.height
    );
    if let Some(rc) = &config.rate_control {
        body.push_str(&format!(
            "<tt:RateControl><tt:FrameRateLimit>{}</tt:FrameRateLimit>\
             <tt:BitrateLimit>{}</tt:BitrateLimit>",
            rc.frame_rate_limit, rc.bitrate_limit
        ));
        if let Some(interval) = rc.encoding_interval {
            body.push_str(&format!(
                "<tt:EncodingInterval>{interval}</tt:EncodingInterval>"
            ));
        }
        body.push_str("</tt:RateControl>");
    }
    body.push_str(&format!(
        "<tt:Quality>{}</tt:Quality></tr2:Configuration></tr2:SetVideoEncoderConfiguration>",
        config.quality
    ));
    body
}

// ---------------------------------------------------------------------------
// Response decode
// ---------------------------------------------------------------------------

fn response_el<'a>(root: &'a XmlElem, name: &str) -> Result<&'a XmlElem, ClientError> {
    find_desc(root, name)
        .ok_or_else(|| ClientError::Parse(format!("expected <{name}> response element")))
}

fn token_of(el: &XmlElem) -> String {
    el.attr("token").unwrap_or_default().to_string()
}

fn text(el: &XmlElem, name: &str) -> String {
    el.child_text(name).unwrap_or_default()
}

fn int(el: &XmlElem, name: &str) -> i64 {
    el.child_text(name)
        .and_then(|t| t.parse().ok())
        .unwrap_or(0)
}

fn float(el: &XmlElem, name: &str) -> f32 {
    el.child_text(name)
        .and_then(|t| t.parse().ok())
        .unwrap_or(0.0)
}

fn boolean(el: &XmlElem, name: &str) -> bool {
    el.child_text(name)
        .map(|t| t == "true" || t == "1")
        .unwrap_or(false)
}

fn attr_bool(el: &XmlElem, name: &str) -> bool {
    el.attr(name)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

fn attr_i64(el: &XmlElem, name: &str) -> Option<i64> {
    el.attr(name).and_then(|v| v.parse().ok())
}

/// Decode a space-separated xs:list attribute of integers (the Go
/// `parseIntList` — unparseable tokens are skipped).
fn parse_int_list(s: &str) -> Vec<i64> {
    s.split_whitespace()
        .filter_map(|p| p.parse().ok())
        .collect()
}

/// Decode a space-separated xs:list attribute of floats (the Go
/// `parseFloatList` — unparseable tokens are skipped).
fn parse_float_list(s: &str) -> Vec<f32> {
    s.split_whitespace()
        .filter_map(|p| p.parse().ok())
        .collect()
}

fn map_configuration_ref(el: &XmlElem) -> ConfigurationRef {
    ConfigurationRef {
        token: token_of(el),
        name: text(el, "Name"),
        use_count: int(el, "UseCount"),
    }
}

fn map_video_encoder_configuration(el: &XmlElem) -> VideoEncoderConfiguration {
    VideoEncoderConfiguration {
        token: token_of(el),
        name: text(el, "Name"),
        use_count: int(el, "UseCount"),
        encoding: text(el, "Encoding"),
        resolution: el
            .find("Resolution")
            .map(|r| Resolution {
                width: int(r, "Width"),
                height: int(r, "Height"),
            })
            .unwrap_or_default(),
        rate_control: el.find("RateControl").map(|r| RateControl {
            frame_rate_limit: float(r, "FrameRateLimit"),
            bitrate_limit: int(r, "BitrateLimit"),
            encoding_interval: r
                .child_text("EncodingInterval")
                .and_then(|t| t.parse().ok()),
        }),
        quality: float(el, "Quality"),
        gov_length: attr_i64(el, "GovLength"),
        anchor_frame_distance: attr_i64(el, "AnchorFrameDistance"),
    }
}

fn map_profile(el: &XmlElem) -> Profile {
    let configs = el.find("Configurations");
    Profile {
        token: token_of(el),
        fixed: attr_bool(el, "fixed"),
        name: text(el, "Name"),
        video_encoder: configs
            .and_then(|c| c.find("VideoEncoder"))
            .map(map_video_encoder_configuration),
        video_source: configs
            .and_then(|c| c.find("VideoSource"))
            .map(map_configuration_ref),
        audio_source: configs
            .and_then(|c| c.find("AudioSource"))
            .map(map_configuration_ref),
        audio_encoder: configs
            .and_then(|c| c.find("AudioEncoder"))
            .map(map_configuration_ref),
        analytics: configs
            .and_then(|c| c.find("Analytics"))
            .map(map_configuration_ref),
        ptz: configs
            .and_then(|c| c.find("PTZ"))
            .map(map_configuration_ref),
        metadata: configs
            .and_then(|c| c.find("Metadata"))
            .map(map_configuration_ref),
    }
}

fn map_video_encoder_options(el: &XmlElem) -> VideoEncoderOptions {
    VideoEncoderOptions {
        encoding: text(el, "Encoding"),
        quality_range: el.find("QualityRange").map(|q| FloatRange {
            min: float(q, "Min"),
            max: float(q, "Max"),
        }),
        resolutions: el
            .find_all("ResolutionsAvailable")
            .iter()
            .map(|r| Resolution {
                width: int(r, "Width"),
                height: int(r, "Height"),
            })
            .collect(),
        bitrate_range: el.find("BitrateRange").map(|b| IntRange {
            min: int(b, "Min"),
            max: int(b, "Max"),
        }),
        gov_length_range: parse_int_list(el.attr("GovLengthRange").unwrap_or("")),
        frame_rate_range: parse_float_list(el.attr("FrameRateRange").unwrap_or("")),
    }
}

fn map_audio_encoder_configuration(el: &XmlElem) -> AudioEncoderConfiguration {
    AudioEncoderConfiguration {
        token: token_of(el),
        name: text(el, "Name"),
        use_count: int(el, "UseCount"),
        encoding: text(el, "Encoding"),
        bitrate: int(el, "Bitrate"),
        sample_rate: int(el, "SampleRate"),
    }
}

fn map_metadata_configuration(el: &XmlElem) -> MetadataConfiguration {
    MetadataConfiguration {
        token: token_of(el),
        name: text(el, "Name"),
        use_count: int(el, "UseCount"),
        ptz_status: el.find("PTZStatus").map(|p| MetadataPtzStatus {
            status: boolean(p, "Status"),
            position: boolean(p, "Position"),
        }),
        analytics: boolean(el, "Analytics"),
    }
}

// ---------------------------------------------------------------------------
// SoapClient operations
// ---------------------------------------------------------------------------

impl SoapClient {
    /// List the Media2 profiles. An optional `token` selects one; optional
    /// `types` (VideoSource/AudioSource/VideoEncoder/…, see
    /// tr2:ConfigurationEnumeration) restrict the returned configurations.
    pub async fn media2_get_profiles(
        &self,
        endpoint: &str,
        token: &str,
        types: &[&str],
    ) -> Result<Vec<Profile>, ClientError> {
        let body = build_get_profiles_request(token, types);
        let resp = self.soap_call(endpoint, &body).await?;
        let root = parse_xml_tree(&resp)?;
        let el = response_el(&root, "GetProfilesResponse")?;
        Ok(el
            .find_all("Profiles")
            .iter()
            .map(|p| map_profile(p))
            .collect())
    }

    /// List the video encoder configurations.
    pub async fn media2_get_video_encoder_configurations(
        &self,
        endpoint: &str,
    ) -> Result<Vec<VideoEncoderConfiguration>, ClientError> {
        let body = tr2_empty_op("GetVideoEncoderConfigurations");
        let resp = self.soap_call(endpoint, &body).await?;
        let root = parse_xml_tree(&resp)?;
        let el = response_el(&root, "GetVideoEncoderConfigurationsResponse")?;
        Ok(el
            .find_all("Configurations")
            .iter()
            .map(|c| map_video_encoder_configuration(c))
            .collect())
    }

    /// The per-encoding video encoder options — one entry per supported
    /// codec (the H.265/AV1 answer Media2 was made for).
    pub async fn media2_get_video_encoder_configuration_options(
        &self,
        endpoint: &str,
        configuration_token: &str,
        profile_token: &str,
    ) -> Result<Vec<VideoEncoderOptions>, ClientError> {
        let body = build_configuration_options_request(configuration_token, profile_token);
        let resp = self.soap_call(endpoint, &body).await?;
        let root = parse_xml_tree(&resp)?;
        let el = response_el(&root, "GetVideoEncoderConfigurationOptionsResponse")?;
        Ok(el
            .find_all("Options")
            .iter()
            .map(|o| map_video_encoder_options(o))
            .collect())
    }

    /// Write a video encoder configuration; the `encoding` passes through
    /// verbatim (H264/H265/AV1/…).
    pub async fn media2_set_video_encoder_configuration(
        &self,
        endpoint: &str,
        config: &VideoEncoderConfiguration,
    ) -> Result<(), ClientError> {
        let body = build_set_video_encoder_configuration_request(config);
        self.soap_call(endpoint, &body).await?;
        Ok(())
    }

    /// The stream URI for a profile (`protocol` as in
    /// tr2:TransportProtocol, e.g. `RtspUnicast`).
    pub async fn media2_get_stream_uri(
        &self,
        endpoint: &str,
        protocol: &str,
        profile_token: &str,
    ) -> Result<String, ClientError> {
        let body = format!(
            "<tr2:GetStreamUri xmlns:tr2=\"{TR2_NS}\"><tr2:Protocol>{}</tr2:Protocol>\
             <tr2:ProfileToken>{}</tr2:ProfileToken></tr2:GetStreamUri>",
            xml_escape(protocol),
            xml_escape(profile_token)
        );
        let resp = self.soap_call(endpoint, &body).await?;
        let root = parse_xml_tree(&resp)?;
        let el = response_el(&root, "GetStreamUriResponse")?;
        Ok(el.child_text("Uri").unwrap_or_default())
    }

    /// The JPEG snapshot URI for a profile — Media2's flavor answers a
    /// plain Uri element (no MediaUri wrapper).
    pub async fn media2_get_snapshot_uri(
        &self,
        endpoint: &str,
        profile_token: &str,
    ) -> Result<String, ClientError> {
        let body = tr2_token_op("GetSnapshotUri", "ProfileToken", profile_token);
        let resp = self.soap_call(endpoint, &body).await?;
        let root = parse_xml_tree(&resp)?;
        let el = response_el(&root, "GetSnapshotUriResponse")?;
        Ok(el.child_text("Uri").unwrap_or_default())
    }

    /// Request an iframe on the profile's stream — the call an NVR makes
    /// when event-triggered recording starts.
    pub async fn media2_set_synchronization_point(
        &self,
        endpoint: &str,
        profile_token: &str,
    ) -> Result<(), ClientError> {
        let body = tr2_token_op("SetSynchronizationPoint", "ProfileToken", profile_token);
        self.soap_call(endpoint, &body).await?;
        Ok(())
    }

    /// The guaranteed encoder instance counts for a video source
    /// configuration.
    pub async fn media2_get_video_encoder_instances(
        &self,
        endpoint: &str,
        configuration_token: &str,
    ) -> Result<EncoderInstanceInfo, ClientError> {
        let body = tr2_token_op(
            "GetVideoEncoderInstances",
            "ConfigurationToken",
            configuration_token,
        );
        let resp = self.soap_call(endpoint, &body).await?;
        let root = parse_xml_tree(&resp)?;
        let el = response_el(&root, "GetVideoEncoderInstancesResponse")?;
        let Some(info) = el.find("Info") else {
            return Ok(EncoderInstanceInfo::default());
        };
        Ok(EncoderInstanceInfo {
            codecs: info
                .find_all("Codec")
                .iter()
                .map(|c| EncoderInstance {
                    encoding: text(c, "Encoding"),
                    number: int(c, "Number"),
                })
                .collect(),
            total: int(info, "Total"),
        })
    }

    /// Start the multicast stream of a profile.
    pub async fn media2_start_multicast_streaming(
        &self,
        endpoint: &str,
        profile_token: &str,
    ) -> Result<(), ClientError> {
        let body = tr2_token_op("StartMulticastStreaming", "ProfileToken", profile_token);
        self.soap_call(endpoint, &body).await?;
        Ok(())
    }

    /// Stop the multicast stream of a profile.
    pub async fn media2_stop_multicast_streaming(
        &self,
        endpoint: &str,
        profile_token: &str,
    ) -> Result<(), ClientError> {
        let body = tr2_token_op("StopMulticastStreaming", "ProfileToken", profile_token);
        self.soap_call(endpoint, &body).await?;
        Ok(())
    }

    /// The Media2 feature flags.
    pub async fn media2_get_service_capabilities(
        &self,
        endpoint: &str,
    ) -> Result<ServiceCapabilities, ClientError> {
        let body = tr2_empty_op("GetServiceCapabilities");
        let resp = self.soap_call(endpoint, &body).await?;
        let root = parse_xml_tree(&resp)?;
        let el = response_el(&root, "GetServiceCapabilitiesResponse")?;
        let Some(caps) = el.find("Capabilities") else {
            return Ok(ServiceCapabilities::default());
        };
        Ok(ServiceCapabilities {
            snapshot_uri: attr_bool(caps, "SnapshotUri"),
            rotation: attr_bool(caps, "Rotation"),
            osd: attr_bool(caps, "OSD"),
            maximum_number_of_profiles: caps
                .find("ProfileCapabilities")
                .and_then(|p| attr_i64(p, "MaximumNumberOfProfiles"))
                .unwrap_or(0),
            rtsp_streaming: caps
                .find("StreamingCapabilities")
                .map(|s| attr_bool(s, "RTSPStreaming"))
                .unwrap_or(false),
        })
    }

    /// List audio encoder configurations; a non-empty `configuration_token`
    /// filters to one configuration.
    pub async fn media2_get_audio_encoder_configurations(
        &self,
        endpoint: &str,
        configuration_token: &str,
    ) -> Result<Vec<AudioEncoderConfiguration>, ClientError> {
        let body = tr2_opt_config_op("GetAudioEncoderConfigurations", configuration_token);
        let resp = self.soap_call(endpoint, &body).await?;
        let root = parse_xml_tree(&resp)?;
        let el = response_el(&root, "GetAudioEncoderConfigurationsResponse")?;
        Ok(el
            .find_all("Configurations")
            .iter()
            .map(|c| map_audio_encoder_configuration(c))
            .collect())
    }

    /// List metadata configurations; a non-empty `configuration_token`
    /// filters to one configuration.
    pub async fn media2_get_metadata_configurations(
        &self,
        endpoint: &str,
        configuration_token: &str,
    ) -> Result<Vec<MetadataConfiguration>, ClientError> {
        let body = tr2_opt_config_op("GetMetadataConfigurations", configuration_token);
        let resp = self.soap_call(endpoint, &body).await?;
        let root = parse_xml_tree(&resp)?;
        let el = response_el(&root, "GetMetadataConfigurationsResponse")?;
        Ok(el
            .find_all("Configurations")
            .iter()
            .map(|c| map_metadata_configuration(c))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENVELOPE_OPEN: &str =
        r#"<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body>"#;
    const ENVELOPE_CLOSE: &str = "</Body></Envelope>";

    fn wrapped(body: &str) -> String {
        format!("{ENVELOPE_OPEN}{body}{ENVELOPE_CLOSE}")
    }

    fn parse_profiles(resp: &str) -> Vec<Profile> {
        let root = parse_xml_tree(resp).unwrap();
        let el = response_el(&root, "GetProfilesResponse").unwrap();
        el.find_all("Profiles")
            .iter()
            .map(|p| map_profile(p))
            .collect()
    }

    // --- request goldens ---------------------------------------------------

    #[test]
    fn request_goldens() {
        assert_eq!(
            build_get_profiles_request("", &[]),
            "<tr2:GetProfiles xmlns:tr2=\"http://www.onvif.org/ver20/media/wsdl\"></tr2:GetProfiles>"
        );
        assert_eq!(
            build_get_profiles_request("main", &["VideoEncoder", "Metadata"]),
            "<tr2:GetProfiles xmlns:tr2=\"http://www.onvif.org/ver20/media/wsdl\">\
             <tr2:Token>main</tr2:Token>\
             <tr2:Type>VideoEncoder</tr2:Type><tr2:Type>Metadata</tr2:Type></tr2:GetProfiles>"
        );
        assert_eq!(
            build_configuration_options_request("enc-1", ""),
            "<tr2:GetVideoEncoderConfigurationOptions xmlns:tr2=\"http://www.onvif.org/ver20/media/wsdl\">\
             <tr2:ConfigurationToken>enc-1</tr2:ConfigurationToken></tr2:GetVideoEncoderConfigurationOptions>"
        );
        assert_eq!(
            tr2_token_op("GetSnapshotUri", "ProfileToken", "Profile_1"),
            "<tr2:GetSnapshotUri xmlns:tr2=\"http://www.onvif.org/ver20/media/wsdl\">\
             <tr2:ProfileToken>Profile_1</tr2:ProfileToken></tr2:GetSnapshotUri>"
        );
        // Optional configuration-token filter omitted when empty.
        assert_eq!(
            tr2_opt_config_op("GetMetadataConfigurations", ""),
            "<tr2:GetMetadataConfigurations xmlns:tr2=\"http://www.onvif.org/ver20/media/wsdl\"></tr2:GetMetadataConfigurations>"
        );
        assert_eq!(
            tr2_opt_config_op("GetAudioEncoderConfigurations", "aec-1"),
            "<tr2:GetAudioEncoderConfigurations xmlns:tr2=\"http://www.onvif.org/ver20/media/wsdl\">\
             <tr2:ConfigurationToken>aec-1</tr2:ConfigurationToken></tr2:GetAudioEncoderConfigurations>"
        );
    }

    /// The Go TestSetVideoEncoderConfigurationH265Wire scenario: the full
    /// payload the H.265 write builds, byte-exact.
    #[test]
    fn set_video_encoder_configuration_wire_golden() {
        let body = build_set_video_encoder_configuration_request(&VideoEncoderConfiguration {
            token: "enc-1".into(),
            name: "Main".into(),
            use_count: 1,
            encoding: "H265".into(),
            resolution: Resolution {
                width: 1920,
                height: 1080,
            },
            rate_control: Some(RateControl {
                frame_rate_limit: 15.0,
                bitrate_limit: 2048,
                encoding_interval: None,
            }),
            quality: 5.0,
            gov_length: None,
            anchor_frame_distance: None,
        });
        assert_eq!(
            body,
            "<tr2:SetVideoEncoderConfiguration xmlns:tr2=\"http://www.onvif.org/ver20/media/wsdl\" \
             xmlns:tt=\"http://www.onvif.org/ver10/schema\">\
             <tr2:Configuration token=\"enc-1\">\
             <tt:Name>Main</tt:Name><tt:UseCount>1</tt:UseCount>\
             <tt:Encoding>H265</tt:Encoding>\
             <tt:Resolution><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:Resolution>\
             <tt:RateControl><tt:FrameRateLimit>15</tt:FrameRateLimit><tt:BitrateLimit>2048</tt:BitrateLimit></tt:RateControl>\
             <tt:Quality>5</tt:Quality></tr2:Configuration></tr2:SetVideoEncoderConfiguration>"
        );

        // GOP attrs and the optional EncodingInterval when present; minimal
        // fields render without a RateControl block.
        let full = build_set_video_encoder_configuration_request(&VideoEncoderConfiguration {
            token: "enc-2".into(),
            encoding: "AV1".into(),
            quality: 3.5,
            gov_length: Some(60),
            anchor_frame_distance: Some(2),
            rate_control: Some(RateControl {
                frame_rate_limit: 12.5,
                bitrate_limit: 4096,
                encoding_interval: Some(1),
            }),
            ..Default::default()
        });
        assert!(full.contains(
            "<tr2:Configuration token=\"enc-2\" GovLength=\"60\" AnchorFrameDistance=\"2\">"
        ));
        assert!(full.contains("<tt:Encoding>AV1</tt:Encoding>"));
        assert!(full.contains("<tt:EncodingInterval>1</tt:EncodingInterval>"));
        assert!(full.contains("<tt:Quality>3.5</tt:Quality>"));
        assert!(!full.contains("RateControl\"/>"));

        let minimal = build_set_video_encoder_configuration_request(&VideoEncoderConfiguration {
            token: "enc-3".into(),
            encoding: "H264".into(),
            ..Default::default()
        });
        assert!(!minimal.contains("RateControl"));
    }

    // --- GetProfiles (Go media2_test fixture) -------------------------------

    #[test]
    fn decodes_profiles() {
        // The Go TestGetProfiles fixture.
        let doc = wrapped(
            "<GetProfilesResponse>\
             <Profiles token=\"main\" fixed=\"true\">\
             <Name>Main</Name>\
             <Configurations>\
             <VideoSource token=\"src-1\"><Name>Source</Name><UseCount>1</UseCount></VideoSource>\
             <VideoEncoder token=\"enc-1\">\
             <Name>Encoder</Name><UseCount>1</UseCount>\
             <Encoding>H265</Encoding>\
             <Resolution><Width>1920</Width><Height>1080</Height></Resolution>\
             <RateControl><FrameRateLimit>15</FrameRateLimit><BitrateLimit>2048</BitrateLimit></RateControl>\
             <Quality>5</Quality>\
             </VideoEncoder>\
             <Metadata token=\"meta-1\"><Name>Metadata</Name><UseCount>1</UseCount></Metadata>\
             </Configurations>\
             </Profiles>\
             </GetProfilesResponse>",
        );
        let profiles = parse_profiles(&doc);
        assert_eq!(profiles.len(), 1);
        let p = &profiles[0];
        assert_eq!(
            (p.token.as_str(), p.fixed, p.name.as_str()),
            ("main", true, "Main")
        );
        assert_eq!(p.video_source.as_ref().unwrap().token, "src-1");
        assert_eq!(p.metadata.as_ref().unwrap().token, "meta-1");
        let enc = p.video_encoder.as_ref().unwrap();
        assert_eq!(enc.encoding, "H265");
        assert_eq!((enc.resolution.width, enc.resolution.height), (1920, 1080));
        let rc = enc.rate_control.as_ref().unwrap();
        assert_eq!((rc.frame_rate_limit, rc.bitrate_limit), (15.0, 2048));
        assert!(rc.encoding_interval.is_none());
        assert!(p.audio_source.is_none() && p.ptz.is_none());
    }

    #[test]
    fn decodes_video_encoder_configurations_list() {
        let doc = wrapped(
            "<GetVideoEncoderConfigurationsResponse>\
             <Configurations token=\"enc-1\" GovLength=\"30\" AnchorFrameDistance=\"2\">\
             <Name>Main</Name><UseCount>1</UseCount><Encoding>H264</Encoding>\
             <Resolution><Width>2560</Width><Height>1440</Height></Resolution>\
             <RateControl><FrameRateLimit>20</FrameRateLimit><BitrateLimit>4096</BitrateLimit>\
             <EncodingInterval>1</EncodingInterval></RateControl>\
             <Quality>4</Quality>\
             </Configurations>\
             </GetVideoEncoderConfigurationsResponse>",
        );
        let root = parse_xml_tree(&doc).unwrap();
        let el = response_el(&root, "GetVideoEncoderConfigurationsResponse").unwrap();
        let configs: Vec<VideoEncoderConfiguration> = el
            .find_all("Configurations")
            .iter()
            .map(|c| map_video_encoder_configuration(c))
            .collect();
        let c = &configs[0];
        assert_eq!((c.gov_length, c.anchor_frame_distance), (Some(30), Some(2)));
        assert_eq!(c.rate_control.as_ref().unwrap().encoding_interval, Some(1));
        assert_eq!(c.quality, 4.0);
    }

    // --- encoder options (Go media2_test fixture, xs:list attrs) -------------

    #[test]
    fn decodes_video_encoder_options_per_codec() {
        // The Go TestGetVideoEncoderConfigurationOptions fixture.
        let doc = wrapped(
            "<GetVideoEncoderConfigurationOptionsResponse>\
             <Options GovLengthRange=\"1 120\" FrameRateRange=\"1 30\">\
             <Encoding>H264</Encoding>\
             <QualityRange><Min>1</Min><Max>6</Max></QualityRange>\
             <ResolutionsAvailable><Width>1920</Width><Height>1080</Height></ResolutionsAvailable>\
             <BitrateRange><Min>64</Min><Max>8192</Max></BitrateRange>\
             </Options>\
             <Options GovLengthRange=\"1 240\" FrameRateRange=\"1 25\">\
             <Encoding>H265</Encoding>\
             <QualityRange><Min>1</Min><Max>6</Max></QualityRange>\
             <ResolutionsAvailable><Width>2560</Width><Height>1440</Height></ResolutionsAvailable>\
             <BitrateRange><Min>128</Min><Max>16384</Max></BitrateRange>\
             </Options>\
             </GetVideoEncoderConfigurationOptionsResponse>",
        );
        let root = parse_xml_tree(&doc).unwrap();
        let el = response_el(&root, "GetVideoEncoderConfigurationOptionsResponse").unwrap();
        let options: Vec<VideoEncoderOptions> = el
            .find_all("Options")
            .iter()
            .map(|o| map_video_encoder_options(o))
            .collect();
        assert_eq!(options.len(), 2);
        let (h264, h265) = (&options[0], &options[1]);
        assert_eq!(h264.encoding, "H264");
        assert_eq!(h264.gov_length_range, vec![1, 120]);
        assert_eq!(h264.gov_length_range[1], 120);
        assert_eq!(h265.encoding, "H265");
        assert_eq!(h265.bitrate_range.as_ref().unwrap().max, 16384);
        assert_eq!(h265.frame_rate_range, vec![1.0, 25.0]);
        assert_eq!(h265.resolutions[0].width, 2560);
    }

    #[test]
    fn int_and_float_lists_skip_garbage_tokens() {
        assert_eq!(parse_int_list("1 120 x 5"), vec![1, 120, 5]);
        assert_eq!(parse_int_list("   "), Vec::<i64>::new());
        assert_eq!(parse_float_list("1 2.5 oops 30"), vec![1.0, 2.5, 30.0]);
        assert_eq!(parse_float_list(""), Vec::<f32>::new());
    }

    // --- URI / sync point / instances / multicast / capabilities --------------

    #[test]
    fn decodes_plain_uri_answers() {
        // Go TestGetStreamUri and TestGetSnapshotUriReturnsPlainUri
        // fixtures: Media2 answers a bare Uri element.
        let stream =
            wrapped("<GetStreamUriResponse><Uri>rtsp://cam:8554/main</Uri></GetStreamUriResponse>");
        let root = parse_xml_tree(&stream).unwrap();
        let el = response_el(&root, "GetStreamUriResponse").unwrap();
        assert_eq!(
            el.child_text("Uri").as_deref(),
            Some("rtsp://cam:8554/main")
        );

        let snap = wrapped(
            "<GetSnapshotUriResponse><Uri>http://192.168.1.10/onvif-http/snapshot?Profile_1</Uri></GetSnapshotUriResponse>",
        );
        let root = parse_xml_tree(&snap).unwrap();
        let el = response_el(&root, "GetSnapshotUriResponse").unwrap();
        assert!(el
            .child_text("Uri")
            .unwrap()
            .starts_with("http://192.168.1.10/onvif-http/snapshot"));

        // Sync-point bodies carry the profile token (Go completion test).
        assert!(
            tr2_token_op("SetSynchronizationPoint", "ProfileToken", "profile-1")
                .contains("<tr2:ProfileToken>profile-1</tr2:ProfileToken>")
        );
        assert!(
            tr2_token_op("StartMulticastStreaming", "ProfileToken", "profile-1")
                .contains("<tr2:ProfileToken>profile-1</tr2:ProfileToken>")
        );
    }

    #[test]
    fn decodes_encoder_instances() {
        // The Go TestGetVideoEncoderInstancesParsesCodecBreakdown fixture.
        let doc = wrapped(
            "<GetVideoEncoderInstancesResponse>\
             <Info>\
             <Codec><Encoding>H264</Encoding><Number>2</Number></Codec>\
             <Codec><Encoding>H265</Encoding><Number>1</Number></Codec>\
             <Total>3</Total>\
             </Info>\
             </GetVideoEncoderInstancesResponse>",
        );
        let root = parse_xml_tree(&doc).unwrap();
        let el = response_el(&root, "GetVideoEncoderInstancesResponse").unwrap();
        let info = el.find("Info").unwrap();
        let codecs: Vec<EncoderInstance> = info
            .find_all("Codec")
            .iter()
            .map(|c| EncoderInstance {
                encoding: text(c, "Encoding"),
                number: int(c, "Number"),
            })
            .collect();
        assert_eq!(codecs.len(), 2);
        assert_eq!((codecs[0].encoding.as_str(), codecs[0].number), ("H264", 2));
        assert_eq!(int(info, "Total"), 3);
    }

    #[test]
    fn decodes_service_capabilities() {
        // The Go TestGetServiceCapabilitiesParsesFlags fixture.
        let doc = wrapped(
            "<GetServiceCapabilitiesResponse>\
             <Capabilities SnapshotUri=\"true\" Rotation=\"false\" OSD=\"true\">\
             <ProfileCapabilities MaximumNumberOfProfiles=\"16\"/>\
             <StreamingCapabilities RTSPStreaming=\"true\"/>\
             </Capabilities>\
             </GetServiceCapabilitiesResponse>",
        );
        let root = parse_xml_tree(&doc).unwrap();
        let el = response_el(&root, "GetServiceCapabilitiesResponse").unwrap();
        let caps = el.find("Capabilities").unwrap();
        assert_eq!(
            (
                attr_bool(caps, "SnapshotUri"),
                attr_bool(caps, "Rotation"),
                attr_bool(caps, "OSD")
            ),
            (true, false, true)
        );
        assert_eq!(
            caps.find("ProfileCapabilities")
                .and_then(|p| attr_i64(p, "MaximumNumberOfProfiles")),
            Some(16)
        );
        assert_eq!(
            caps.find("StreamingCapabilities")
                .map(|s| attr_bool(s, "RTSPStreaming")),
            Some(true)
        );
    }

    // --- audio / metadata configuration families ------------------------------

    #[test]
    fn decodes_audio_encoder_configurations() {
        // The Go TestGetAudioEncoderConfigurations fixture.
        let doc = wrapped(
            "<GetAudioEncoderConfigurationsResponse>\
             <Configurations token=\"aec-1\">\
             <Name>Audio in</Name><UseCount>1</UseCount>\
             <Encoding>audio/PCMA</Encoding><Bitrate>64</Bitrate><SampleRate>8</SampleRate>\
             </Configurations>\
             </GetAudioEncoderConfigurationsResponse>",
        );
        let root = parse_xml_tree(&doc).unwrap();
        let el = response_el(&root, "GetAudioEncoderConfigurationsResponse").unwrap();
        let configs: Vec<AudioEncoderConfiguration> = el
            .find_all("Configurations")
            .iter()
            .map(|c| map_audio_encoder_configuration(c))
            .collect();
        let c = &configs[0];
        assert_eq!(
            (
                c.token.as_str(),
                c.encoding.as_str(),
                c.bitrate,
                c.sample_rate
            ),
            ("aec-1", "audio/PCMA", 64, 8)
        );
    }

    #[test]
    fn decodes_metadata_configurations() {
        // The Go TestGetMetadataConfigurations fixture.
        let doc = wrapped(
            "<GetMetadataConfigurationsResponse>\
             <Configurations token=\"mdc-1\">\
             <Name>Metadata</Name><UseCount>2</UseCount>\
             <PTZStatus><Status>true</Status><Position>true</Position></PTZStatus>\
             <Events><Filter/></Events><Analytics>false</Analytics>\
             </Configurations>\
             </GetMetadataConfigurationsResponse>",
        );
        let root = parse_xml_tree(&doc).unwrap();
        let el = response_el(&root, "GetMetadataConfigurationsResponse").unwrap();
        let configs: Vec<MetadataConfiguration> = el
            .find_all("Configurations")
            .iter()
            .map(|c| map_metadata_configuration(c))
            .collect();
        let c = &configs[0];
        assert_eq!((c.token.as_str(), c.name.as_str()), ("mdc-1", "Metadata"));
        let ptz = c.ptz_status.as_ref().unwrap();
        assert!(ptz.status && ptz.position);
        assert!(!c.analytics);
    }

    #[test]
    fn missing_response_element_errors() {
        let root = parse_xml_tree(&wrapped("<Other/>")).unwrap();
        assert!(response_el(&root, "GetProfilesResponse").is_err());
    }
}
