//! ONVIF media service client family (trt, ver10/media/wsdl) — the twin of
//! the Go library's `media` package read families: profile listing plus the
//! main/sub-stream selection heuristics, stream/snapshot URI resolution,
//! and the video-encoder / video-source / audio / metadata / OSD read
//! operations.
//!
//! Endpoint routing mirrors the Go twin's `EndpointFor(api.ServiceMedia)`:
//! the media operations ride the DEVICE endpoint unless discovery resolved
//! a service-specific media address — here every call goes through
//! [`SoapClient::device_call`], so point the [`SoapClient`] at the device
//! endpoint (or a discovered media XAddr; a client constructed with the
//! media endpoint serves the same role).
//!
//! Request envelopes are byte-compatible with what the Go package marshals
//! (`trt:` prefixes, `xmlns:trt`/`xmlns:tt` attribute placement, child
//! order); response decode is local-name tolerant. Mutating media
//! operations (Set/Add/Remove/Create/Delete, multicast streaming control,
//! `SetSynchronizationPoint`) are out of this port's scope — the ver10
//! write path is owned by the device half, and Media2 carries the modern
//! write flavor (see [`crate::client::media2`]).

use crate::types::xml_escape;
use crate::types::TextAccumulator;

use super::{ClientError, SoapClient};

/// The ver10 media service WSDL namespace (`trt`).
const TRT_NS: &str = "http://www.onvif.org/ver10/media/wsdl";
/// The ver10 schema namespace (`tt`).
const TT_NS: &str = "http://www.onvif.org/ver10/schema";

/// Cap on raw response XML embedded in empty-media-URI errors (the Go
/// twin's `maxMediaURIErrBody`).
const MAX_MEDIA_URI_ERR_BODY: usize = 512;

// ---------------------------------------------------------------------------
// Minimal decode tree
// ---------------------------------------------------------------------------

/// One decoded XML element: local name (prefix stripped), attributes
/// (local names), concatenated text, children. The decode half of this
/// module (and of [`crate::client::media2`] / [`crate::client::metadata`],
/// which reuse this) maps typed structs out of these trees instead of
/// running per-type event-stream walks — the media response shapes nest
/// (Profiles > VideoEncoderConfiguration > Resolution > Width/Height) and a
/// tree makes the mappings total and testable.
pub(crate) struct XmlElem {
    /// Local element name (`tt:VideoEncoder` → `VideoEncoder`).
    pub(crate) name: String,
    /// Attributes as (local name, unescaped value) pairs, in document order.
    pub(crate) attrs: Vec<(String, String)>,
    /// Concatenated (entity-resolved) text content of the element.
    pub(crate) text: String,
    /// Child elements in document order.
    pub(crate) children: Vec<XmlElem>,
}

impl XmlElem {
    /// First attribute with this local name.
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// First direct child with this local name.
    pub(crate) fn find(&self, name: &str) -> Option<&XmlElem> {
        self.children.iter().find(|c| c.name == name)
    }

    /// All direct children with this local name, in document order.
    pub(crate) fn find_all(&self, name: &str) -> Vec<&XmlElem> {
        self.children.iter().filter(|c| c.name == name).collect()
    }

    /// Text of the first direct child with this local name.
    pub(crate) fn child_text(&self, name: &str) -> Option<String> {
        self.find(name).map(|c| c.text.clone())
    }
}

/// Depth-first search for the first element (self or descendant) with the
/// given local name — how response elements are located inside the SOAP
/// envelope regardless of prefix dialect.
pub(crate) fn find_desc<'a>(el: &'a XmlElem, name: &str) -> Option<&'a XmlElem> {
    if el.name == name {
        return Some(el);
    }
    el.children.iter().find_map(|c| find_desc(c, name))
}

/// Parse one XML document into an [`XmlElem`] tree (the first root
/// element). Malformed input errors; namespace prefixes are dropped.
pub(crate) fn parse_xml_tree(resp: &str) -> Result<XmlElem, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<XmlElem> = Vec::new();
    let mut root: Option<XmlElem> = None;
    let mut acc = TextAccumulator::new();
    let mut buf = Vec::new();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                take_text(&mut stack, &mut acc);
                stack.push(elem_from_start(&e));
            }
            Ok(XmlEvent::Empty(e)) => {
                take_text(&mut stack, &mut acc);
                let el = elem_from_start(&e);
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(el);
                } else if root.is_none() {
                    root = Some(el);
                }
            }
            Ok(XmlEvent::End(_)) => {
                take_text(&mut stack, &mut acc);
                if let Some(el) = stack.pop() {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(el);
                    } else if root.is_none() {
                        root = Some(el);
                    }
                }
            }
            Ok(XmlEvent::Text(t)) => {
                if let Err(e) = acc.push_text(&t) {
                    return Err(ClientError::Parse(format!("decode response: {e}")));
                }
            }
            Ok(XmlEvent::GeneralRef(r)) => {
                if let Err(e) = acc.push_ref(&r) {
                    return Err(ClientError::Parse(format!("decode response: {e}")));
                }
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!("decode response: {e}")));
            }
        }
        buf.clear();
    }

    root.ok_or_else(|| ClientError::Parse("decode response: no XML element".into()))
}

/// Flush accumulated text into the currently open element (text before the
/// next tag belongs to the element on top of the stack).
fn take_text(stack: &mut [XmlElem], acc: &mut TextAccumulator) {
    if let Some(text) = acc.flush() {
        if let Some(top) = stack.last_mut() {
            top.text.push_str(&text);
        }
    }
}

fn elem_from_start(e: &quick_xml::events::BytesStart<'_>) -> XmlElem {
    let full = String::from_utf8_lossy(e.name().as_ref()).into_owned();
    let name = match full.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => full,
    };
    let mut attrs = Vec::new();
    for a in e.attributes().flatten() {
        let key_full = String::from_utf8_lossy(a.key.as_ref()).into_owned();
        let key = match key_full.rsplit_once(':') {
            Some((_, local)) => local.to_string(),
            None => key_full,
        };
        let raw = String::from_utf8_lossy(&a.value).into_owned();
        let value = match quick_xml::escape::unescape(raw.as_str()) {
            Ok(v) => v.into_owned(),
            Err(_) => raw,
        };
        attrs.push((key, value));
    }
    XmlElem {
        name,
        attrs,
        text: String::new(),
        children: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Types (the Go media package's response shapes, snake_case)
// ---------------------------------------------------------------------------

/// A media profile as the read families decode it (the Go `media.Profile`
/// scoped to the fields its responses carry).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Profile {
    /// The profile token.
    pub token: String,
    /// The profile name.
    pub name: String,
    /// Video source configuration, when the profile lists one.
    pub video_source_configuration: Option<VideoSourceConfiguration>,
    /// Video encoder configuration, when the profile lists one.
    pub video_encoder_configuration: Option<VideoEncoderConfiguration>,
    /// PTZ configuration, when the profile lists one.
    pub ptz_configuration: Option<PtzConfiguration>,
}

/// A video source configuration (the Go `media.VideoSourceConfiguration`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VideoSourceConfiguration {
    pub token: String,
    pub name: String,
    pub use_count: i64,
    /// The video source this configuration reads from.
    pub source_token: String,
    /// Crop rectangle on the source.
    pub bounds: Option<IntRectangle>,
}

/// An axis-aligned integer rectangle (`tt:IntRectangle`; attributes
/// `x`/`y`/`width`/`height`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntRectangle {
    pub x: i64,
    pub y: i64,
    pub width: i64,
    pub height: i64,
}

/// A video encoder configuration (the Go `media.VideoEncoderConfiguration`;
/// `quality` is a float, so `Eq` is dropped).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VideoEncoderConfiguration {
    pub token: String,
    pub name: String,
    pub use_count: i64,
    /// `JPEG`, `MPEG4`, `H264` (passed through verbatim, like the Go twin).
    pub encoding: String,
    pub quality: f64,
    pub resolution: Option<VideoResolution>,
    pub rate_control: Option<VideoRateControl>,
    pub mpeg4: Option<Mpeg4Configuration>,
    pub h264: Option<H264Configuration>,
    pub multicast: Option<MulticastConfiguration>,
}

/// Width × height in pixels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VideoResolution {
    pub width: i64,
    pub height: i64,
}

/// Frame rate / interval / bitrate limits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VideoRateControl {
    pub frame_rate_limit: i64,
    pub encoding_interval: i64,
    pub bitrate_limit: i64,
}

/// MPEG-4 encoder attributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mpeg4Configuration {
    pub gov_length: i64,
    pub mpeg4_profile: String,
}

/// H.264 encoder attributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H264Configuration {
    pub gov_length: i64,
    pub h264_profile: String,
}

/// Multicast settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MulticastConfiguration {
    pub address: Option<IpAddress>,
    pub port: i64,
    pub ttl: i64,
    pub auto_start: bool,
}

/// An `tt:IPAddress` (Go field `Type` renamed `kind` — `type` is a Rust
/// keyword).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpAddress {
    /// `IPv4`, `IPv6` or `DNS`.
    pub kind: String,
    pub ipv4_address: String,
    pub ipv6_address: String,
}

/// The PTZ configuration fields the media family reads (the Go
/// `ptz.PTZConfiguration` scoped to what media responses carry).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PtzConfiguration {
    pub token: String,
    pub name: String,
    pub use_count: i64,
    pub node_token: String,
}

/// A video source (Go fills the resolution unconditionally; a source that
/// reports none decodes as 0×0).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VideoSource {
    pub token: String,
    pub framerate: f64,
    pub resolution: VideoResolution,
}

/// One selectable video source mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VideoSourceMode {
    pub token: String,
    pub enabled: bool,
    pub resolution: VideoResolution,
}

/// Guaranteed concurrent encoder instance counts (the Go
/// `media.GuaranteedNumberOfVideoEncoderInstances`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuaranteedNumberOfVideoEncoderInstances {
    pub total_number: i64,
    pub jpeg: i64,
    pub h264: i64,
    pub mpeg4: i64,
}

/// Video encoder options (contains float ranges → `PartialEq` only).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VideoEncoderConfigurationOptions {
    pub quality_range: Option<FloatRange>,
    pub jpeg: Option<JpegOptions>,
    pub mpeg4: Option<Mpeg4Options>,
    pub h264: Option<H264Options>,
}

/// An inclusive float range (`tt:FloatRange`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FloatRange {
    pub min: f64,
    pub max: f64,
}

/// An inclusive integer range (`tt:IntRange`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntRange {
    pub min: i64,
    pub max: i64,
}

/// JPEG encoder options.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct JpegOptions {
    pub resolutions_available: Vec<VideoResolution>,
    pub frame_rate_range: Option<FloatRange>,
    pub encoding_interval_range: Option<IntRange>,
}

/// H.264 encoder options.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct H264Options {
    pub resolutions_available: Vec<VideoResolution>,
    pub gov_length_range: Option<IntRange>,
    pub frame_rate_range: Option<FloatRange>,
    pub encoding_interval_range: Option<IntRange>,
    pub h264_profiles_supported: Vec<String>,
}

/// MPEG-4 encoder options.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Mpeg4Options {
    pub resolutions_available: Vec<VideoResolution>,
    pub gov_length_range: Option<IntRange>,
    pub frame_rate_range: Option<FloatRange>,
    pub encoding_interval_range: Option<IntRange>,
    pub mpeg4_profiles_supported: Vec<String>,
}

/// Video source configuration options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VideoSourceConfigurationOptions {
    pub bounds_range: Option<BoundsRange>,
    pub video_source_tokens_available: Vec<String>,
}

/// Per-axis bounds ranges for cropping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundsRange {
    pub x: Option<IntRange>,
    pub y: Option<IntRange>,
    pub width: Option<IntRange>,
    pub height: Option<IntRange>,
}

/// An audio source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioSource {
    pub token: String,
    pub channels: i64,
}

/// An audio output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioOutput {
    pub token: String,
}

/// An audio encoder configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioEncoderConfiguration {
    pub token: String,
    pub name: String,
    pub use_count: i64,
    /// `G711`, `G726`, `AAC`.
    pub encoding: String,
    pub bitrate: i64,
    pub sample_rate: i64,
    pub multicast: Option<MulticastConfiguration>,
}

/// An audio source configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioSourceConfiguration {
    pub token: String,
    pub name: String,
    pub use_count: i64,
    pub source_token: String,
}

/// An audio output configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioOutputConfiguration {
    pub token: String,
    pub name: String,
    pub use_count: i64,
    pub output_token: String,
}

/// An audio decoder configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioDecoderConfiguration {
    pub token: String,
    pub name: String,
    pub use_count: i64,
}

/// Audio encoder options (repeated `EncodingOptions`/`BitrateList`/
/// `SampleRateList` elements, exactly as the Go twin decodes them).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioEncoderConfigurationOptions {
    pub encoding_options: Vec<String>,
    pub bitrate_list: Vec<i64>,
    pub sample_rate_list: Vec<i64>,
}

/// Audio source options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioSourceConfigurationOptions {
    pub input_tokens_available: Vec<String>,
}

/// Audio output options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioOutputConfigurationOptions {
    pub output_tokens_available: Vec<String>,
}

/// Audio decoder options (per-codec).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioDecoderConfigurationOptions {
    pub aac_dec_options: Option<AudioDecoderOptions>,
    pub g711_dec_options: Option<AudioDecoderOptions>,
    pub g726_dec_options: Option<AudioDecoderOptions>,
}

/// One codec's decoder options (G711/G726 only carry a bitrate list on the
/// wire; the sample-rate list stays empty, like the Go twin).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioDecoderOptions {
    pub bitrate_list: Vec<i64>,
    pub sample_rate_list: Vec<i64>,
}

/// A metadata configuration (the Go `media.MetadataConfiguration`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataConfiguration {
    pub token: String,
    pub name: String,
    pub use_count: i64,
    pub ptz_status: Option<PtzFilter>,
    /// Presence marker: the device listed an (unmodeled) Events
    /// subscription block.
    pub events: Option<EventSubscription>,
    pub analytics: bool,
    pub multicast: Option<MulticastConfiguration>,
}

/// The Go twin's presence marker for a metadata Events block (its filter
/// payload is unmodeled there too).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventSubscription;

/// Which PTZ status fields a metadata stream carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PtzFilter {
    pub status: bool,
    pub position: bool,
}

/// Metadata configuration options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataConfigurationOptions {
    pub ptz_status_filter_options: Option<PtzFilter>,
}

/// An OSD configuration (token-scoped, like the Go twin).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsdConfiguration {
    pub token: String,
}

/// OSD options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsdConfigurationOptions {
    pub maximum_number_of_osds: i64,
}

/// A resolved media URI (stream or snapshot). The Go twin's `Timeout`
/// field is never populated by its read methods, so it is not carried.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaUri {
    pub uri: String,
    pub invalid_after_connect: bool,
    pub invalid_after_reboot: bool,
}

/// Stream type × transport protocol selection for GetStreamUri.
///
/// A `None` transport (or empty protocol) defaults to RTSP — the same
/// defaulting the Go twin's `StreamSetup.validate` applies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamSetup {
    /// `RTP-Unicast` or `RTP-Multicast` (see [`STREAM_RTP_UNICAST`]).
    pub stream: String,
    /// Transport selection; `None` = RTSP.
    pub transport: Option<Transport>,
}

/// Transport protocol selection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Transport {
    /// `RTSP`, `HTTP`, `UDP` or `TCP` (see [`PROTOCOL_RTSP`]).
    pub protocol: String,
}

/// Request a unicast stream (the default stream type).
pub const STREAM_RTP_UNICAST: &str = "RTP-Unicast";
/// Request a multicast stream.
pub const STREAM_RTP_MULTICAST: &str = "RTP-Multicast";
/// RTSP transport (the default protocol).
pub const PROTOCOL_RTSP: &str = "RTSP";
/// RTSP-over-HTTP tunneling.
pub const PROTOCOL_HTTP: &str = "HTTP";
/// Raw UDP/RTP transport.
pub const PROTOCOL_UDP: &str = "UDP";

impl StreamSetup {
    /// Validate the stream/protocol pair, defaulting a missing transport
    /// protocol to RTSP (the twin of Go's `StreamSetup.validate`).
    fn validated(&self) -> Result<(String, String), ClientError> {
        if self.stream != STREAM_RTP_UNICAST && self.stream != STREAM_RTP_MULTICAST {
            return Err(ClientError::InvalidArgument(format!(
                "invalid parameter: stream {:?} (want {:?} or {:?})",
                self.stream, STREAM_RTP_UNICAST, STREAM_RTP_MULTICAST
            )));
        }
        let protocol = match &self.transport {
            Some(t) if !t.protocol.is_empty() => t.protocol.clone(),
            _ => PROTOCOL_RTSP.to_string(),
        };
        match protocol.as_str() {
            PROTOCOL_RTSP | PROTOCOL_HTTP | PROTOCOL_UDP | "TCP" => {}
            _ => {
                return Err(ClientError::InvalidArgument(format!(
                    "invalid parameter: protocol {:?} (want {:?}, {:?}, {:?}, or \"TCP\")",
                    protocol, PROTOCOL_RTSP, PROTOCOL_HTTP, PROTOCOL_UDP
                )));
            }
        }
        Ok((self.stream.clone(), protocol))
    }
}

// ---------------------------------------------------------------------------
// Request builders (byte-compatible with the Go envelopes)
// ---------------------------------------------------------------------------

/// An operation with no children (Go marshals an empty element with an
/// explicit end tag).
fn empty_op(op: &str) -> String {
    format!("<trt:{op} xmlns:trt=\"{TRT_NS}\"></trt:{op}>")
}

/// An operation carrying exactly one token child (`ProfileToken`,
/// `ConfigurationToken`, `VideoSourceToken`, `OSDToken`, …).
fn one_token_op(op: &str, child: &str, value: &str) -> String {
    format!(
        "<trt:{op} xmlns:trt=\"{TRT_NS}\"><trt:{child}>{}</trt:{child}></trt:{op}>",
        xml_escape(value)
    )
}

/// An operation whose optional filter children are emitted in Go struct
/// order: `ConfigurationToken` first, then `ProfileToken`; empty values are
/// omitted (`omitempty` in the Go request structs).
fn opt_tokens_op(op: &str, configuration_token: &str, profile_token: &str) -> String {
    let mut body = format!("<trt:{op} xmlns:trt=\"{TRT_NS}\">");
    if !configuration_token.is_empty() {
        body.push_str(&format!(
            "<trt:ConfigurationToken>{}</trt:ConfigurationToken>",
            xml_escape(configuration_token)
        ));
    }
    if !profile_token.is_empty() {
        body.push_str(&format!(
            "<trt:ProfileToken>{}</trt:ProfileToken>",
            xml_escape(profile_token)
        ));
    }
    body.push_str(&format!("</trt:{op}>"));
    body
}

/// GetStreamUri: the StreamSetup block rides `trt:` while its payload
/// children are `tt:`-typed, exactly as the Go struct marshals.
fn build_get_stream_uri_request(profile_token: &str, stream: &str, protocol: &str) -> String {
    format!(
        "<trt:GetStreamUri xmlns:trt=\"{TRT_NS}\" xmlns:tt=\"{TT_NS}\"\
         ><trt:StreamSetup><tt:Stream>{stream}</tt:Stream>\
         <tt:Transport><tt:Protocol>{protocol}</tt:Protocol></tt:Transport></trt:StreamSetup>\
         <trt:ProfileToken>{}</trt:ProfileToken></trt:GetStreamUri>",
        xml_escape(profile_token)
    )
}

// ---------------------------------------------------------------------------
// Response decode
// ---------------------------------------------------------------------------

/// Locate the expected response element inside the envelope (missing
/// element = the Go twin's "expected element type" unmarshal failure).
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

fn float(el: &XmlElem, name: &str) -> f64 {
    el.child_text(name)
        .and_then(|t| t.parse().ok())
        .unwrap_or(0.0)
}

fn boolean(el: &XmlElem, name: &str) -> bool {
    el.child_text(name)
        .map(|t| t == "true" || t == "1")
        .unwrap_or(false)
}

fn string_list(el: &XmlElem, name: &str) -> Vec<String> {
    el.find_all(name).iter().map(|c| c.text.clone()).collect()
}

fn int_list(el: &XmlElem, name: &str) -> Vec<i64> {
    el.find_all(name)
        .iter()
        .filter_map(|c| c.text.parse().ok())
        .collect()
}

/// A list-typed response: `response_element` wrapping repeated `item`
/// children.
fn parse_list<T>(
    resp: &str,
    response_element: &str,
    item: &str,
    map: fn(&XmlElem) -> T,
) -> Result<Vec<T>, ClientError> {
    let root = parse_xml_tree(resp)?;
    let el = response_el(&root, response_element)?;
    Ok(el.find_all(item).into_iter().map(map).collect())
}

/// A single-configuration response: `response_element` wrapping one
/// `Configuration` child (absent child decodes as the zero value, matching
/// the Go twin).
fn parse_configuration<T: Default>(
    resp: &str,
    response_element: &str,
    map: fn(&XmlElem) -> T,
) -> Result<T, ClientError> {
    let root = parse_xml_tree(resp)?;
    let el = response_el(&root, response_element)?;
    Ok(el.find("Configuration").map(map).unwrap_or_default())
}

fn map_profile(el: &XmlElem) -> Profile {
    Profile {
        token: token_of(el),
        name: text(el, "Name"),
        video_source_configuration: el
            .find("VideoSourceConfiguration")
            .map(map_video_source_configuration),
        video_encoder_configuration: el
            .find("VideoEncoderConfiguration")
            .map(map_video_encoder_configuration),
        ptz_configuration: el.find("PTZConfiguration").map(map_ptz_configuration),
    }
}

fn map_ptz_configuration(el: &XmlElem) -> PtzConfiguration {
    PtzConfiguration {
        token: token_of(el),
        name: text(el, "Name"),
        use_count: int(el, "UseCount"),
        node_token: text(el, "NodeToken"),
    }
}

fn map_video_source_configuration(el: &XmlElem) -> VideoSourceConfiguration {
    VideoSourceConfiguration {
        token: token_of(el),
        name: text(el, "Name"),
        use_count: int(el, "UseCount"),
        source_token: text(el, "SourceToken"),
        bounds: el.find("Bounds").map(map_int_rectangle),
    }
}

fn map_int_rectangle(el: &XmlElem) -> IntRectangle {
    IntRectangle {
        x: el.attr("x").and_then(|v| v.parse().ok()).unwrap_or(0),
        y: el.attr("y").and_then(|v| v.parse().ok()).unwrap_or(0),
        width: el.attr("width").and_then(|v| v.parse().ok()).unwrap_or(0),
        height: el.attr("height").and_then(|v| v.parse().ok()).unwrap_or(0),
    }
}

fn map_video_encoder_configuration(el: &XmlElem) -> VideoEncoderConfiguration {
    VideoEncoderConfiguration {
        token: token_of(el),
        name: text(el, "Name"),
        use_count: int(el, "UseCount"),
        encoding: text(el, "Encoding"),
        quality: float(el, "Quality"),
        resolution: el.find("Resolution").map(map_video_resolution),
        rate_control: el.find("RateControl").map(map_video_rate_control),
        mpeg4: el.find("MPEG4").map(map_mpeg4_configuration),
        h264: el.find("H264").map(map_h264_configuration),
        multicast: el.find("Multicast").map(map_multicast_configuration),
    }
}

fn map_video_resolution(el: &XmlElem) -> VideoResolution {
    VideoResolution {
        width: int(el, "Width"),
        height: int(el, "Height"),
    }
}

fn map_video_rate_control(el: &XmlElem) -> VideoRateControl {
    VideoRateControl {
        frame_rate_limit: int(el, "FrameRateLimit"),
        encoding_interval: int(el, "EncodingInterval"),
        bitrate_limit: int(el, "BitrateLimit"),
    }
}

fn map_mpeg4_configuration(el: &XmlElem) -> Mpeg4Configuration {
    Mpeg4Configuration {
        gov_length: int(el, "GovLength"),
        mpeg4_profile: text(el, "MPEG4Profile"),
    }
}

fn map_h264_configuration(el: &XmlElem) -> H264Configuration {
    H264Configuration {
        gov_length: int(el, "GovLength"),
        h264_profile: text(el, "H264Profile"),
    }
}

fn map_multicast_configuration(el: &XmlElem) -> MulticastConfiguration {
    MulticastConfiguration {
        address: el.find("Address").map(map_ip_address),
        port: int(el, "Port"),
        ttl: int(el, "TTL"),
        auto_start: boolean(el, "AutoStart"),
    }
}

fn map_ip_address(el: &XmlElem) -> IpAddress {
    IpAddress {
        kind: text(el, "Type"),
        ipv4_address: text(el, "IPv4Address"),
        ipv6_address: text(el, "IPv6Address"),
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
        multicast: el.find("Multicast").map(map_multicast_configuration),
    }
}

fn map_audio_source_configuration(el: &XmlElem) -> AudioSourceConfiguration {
    AudioSourceConfiguration {
        token: token_of(el),
        name: text(el, "Name"),
        use_count: int(el, "UseCount"),
        source_token: text(el, "SourceToken"),
    }
}

fn map_audio_output_configuration(el: &XmlElem) -> AudioOutputConfiguration {
    AudioOutputConfiguration {
        token: token_of(el),
        name: text(el, "Name"),
        use_count: int(el, "UseCount"),
        output_token: text(el, "OutputToken"),
    }
}

fn map_audio_decoder_configuration(el: &XmlElem) -> AudioDecoderConfiguration {
    AudioDecoderConfiguration {
        token: token_of(el),
        name: text(el, "Name"),
        use_count: int(el, "UseCount"),
    }
}

fn map_metadata_configuration(el: &XmlElem) -> MetadataConfiguration {
    MetadataConfiguration {
        token: token_of(el),
        name: text(el, "Name"),
        use_count: int(el, "UseCount"),
        ptz_status: el.find("PTZStatus").map(map_ptz_filter),
        events: el.find("Events").map(|_| EventSubscription),
        analytics: boolean(el, "Analytics"),
        multicast: el.find("Multicast").map(map_multicast_configuration),
    }
}

fn map_ptz_filter(el: &XmlElem) -> PtzFilter {
    PtzFilter {
        status: boolean(el, "Status"),
        position: boolean(el, "Position"),
    }
}

fn map_video_source(el: &XmlElem) -> VideoSource {
    VideoSource {
        token: token_of(el),
        framerate: float(el, "Framerate"),
        resolution: el
            .find("Resolution")
            .map(map_video_resolution)
            .unwrap_or_default(),
    }
}

fn map_video_source_mode(el: &XmlElem) -> VideoSourceMode {
    VideoSourceMode {
        token: token_of(el),
        enabled: boolean(el, "Enabled"),
        resolution: el
            .find("Resolution")
            .map(map_video_resolution)
            .unwrap_or_default(),
    }
}

fn map_osd(el: &XmlElem) -> OsdConfiguration {
    OsdConfiguration {
        token: token_of(el),
    }
}

fn map_float_range(el: &XmlElem) -> FloatRange {
    FloatRange {
        min: float(el, "Min"),
        max: float(el, "Max"),
    }
}

fn map_int_range(el: &XmlElem) -> IntRange {
    IntRange {
        min: int(el, "Min"),
        max: int(el, "Max"),
    }
}

fn map_resolutions(el: &XmlElem) -> Vec<VideoResolution> {
    el.find_all("ResolutionsAvailable")
        .iter()
        .map(|r| VideoResolution {
            width: int(r, "Width"),
            height: int(r, "Height"),
        })
        .collect()
}

fn map_jpeg_options(el: &XmlElem) -> JpegOptions {
    JpegOptions {
        resolutions_available: map_resolutions(el),
        frame_rate_range: el.find("FrameRateRange").map(map_float_range),
        encoding_interval_range: el.find("EncodingIntervalRange").map(map_int_range),
    }
}

fn map_h264_options(el: &XmlElem) -> H264Options {
    H264Options {
        resolutions_available: map_resolutions(el),
        gov_length_range: el.find("GovLengthRange").map(map_int_range),
        frame_rate_range: el.find("FrameRateRange").map(map_float_range),
        encoding_interval_range: el.find("EncodingIntervalRange").map(map_int_range),
        h264_profiles_supported: string_list(el, "H264ProfilesSupported"),
    }
}

fn map_mpeg4_options(el: &XmlElem) -> Mpeg4Options {
    Mpeg4Options {
        resolutions_available: map_resolutions(el),
        gov_length_range: el.find("GovLengthRange").map(map_int_range),
        frame_rate_range: el.find("FrameRateRange").map(map_float_range),
        encoding_interval_range: el.find("EncodingIntervalRange").map(map_int_range),
        mpeg4_profiles_supported: string_list(el, "Mpeg4ProfilesSupported"),
    }
}

fn map_video_encoder_options(el: &XmlElem) -> VideoEncoderConfigurationOptions {
    VideoEncoderConfigurationOptions {
        quality_range: el.find("QualityRange").map(map_float_range),
        jpeg: el.find("JPEG").map(map_jpeg_options),
        mpeg4: el.find("MPEG4").map(map_mpeg4_options),
        h264: el.find("H264").map(map_h264_options),
    }
}

fn map_bounds_range(el: &XmlElem) -> BoundsRange {
    BoundsRange {
        x: el.find("X").map(map_int_range),
        y: el.find("Y").map(map_int_range),
        width: el.find("Width").map(map_int_range),
        height: el.find("Height").map(map_int_range),
    }
}

fn map_video_source_options(el: &XmlElem) -> VideoSourceConfigurationOptions {
    VideoSourceConfigurationOptions {
        bounds_range: el.find("BoundsRange").map(map_bounds_range),
        video_source_tokens_available: string_list(el, "VideoSourceTokensAvailable"),
    }
}

fn map_audio_encoder_options(el: &XmlElem) -> AudioEncoderConfigurationOptions {
    AudioEncoderConfigurationOptions {
        encoding_options: string_list(el, "EncodingOptions"),
        bitrate_list: int_list(el, "BitrateList"),
        sample_rate_list: int_list(el, "SampleRateList"),
    }
}

fn map_audio_decoder_options(el: &XmlElem) -> AudioDecoderConfigurationOptions {
    AudioDecoderConfigurationOptions {
        aac_dec_options: el.find("AACDecOptions").map(map_full_decoder_options),
        g711_dec_options: el.find("G711DecOptions").map(map_bitrate_decoder_options),
        g726_dec_options: el.find("G726DecOptions").map(map_bitrate_decoder_options),
    }
}

fn map_full_decoder_options(el: &XmlElem) -> AudioDecoderOptions {
    AudioDecoderOptions {
        bitrate_list: int_list(el, "BitrateList"),
        sample_rate_list: int_list(el, "SampleRateList"),
    }
}

fn map_bitrate_decoder_options(el: &XmlElem) -> AudioDecoderOptions {
    AudioDecoderOptions {
        bitrate_list: int_list(el, "BitrateList"),
        sample_rate_list: Vec::new(),
    }
}

/// An options response: `response_element > Options`, mapped (absent
/// Options decodes as the zero value).
fn parse_options<T: Default>(
    resp: &str,
    response_element: &str,
    map: fn(&XmlElem) -> T,
) -> Result<T, ClientError> {
    let root = parse_xml_tree(resp)?;
    let el = response_el(&root, response_element)?;
    Ok(el.find("Options").map(map).unwrap_or_default())
}

/// The GetStreamUri/GetSnapshotUri shared response: typed `MediaUri` walk
/// first, then the namespace-agnostic loose-URI scan (issue #3 in the Go
/// twin), then the explicit empty-URI error.
fn parse_media_uri_response(
    resp: &str,
    op: &str,
    profile_token: &str,
) -> Result<MediaUri, ClientError> {
    let root = parse_xml_tree(resp)?;
    let el = response_el(&root, &format!("{op}Response"))?;
    let media_uri = el.find("MediaUri");
    let uri_el = media_uri
        .and_then(|m| m.find("Uri"))
        .or_else(|| find_desc(el, "Uri"));
    let uri = uri_el
        .map(|u| u.text.trim().to_string())
        .unwrap_or_default();
    if uri.is_empty() {
        return Err(ClientError::Parse(format!(
            "device returned an empty media URI: {op} (profile {}) response carried no Uri element; body: {}",
            profile_token,
            truncate_for_error(resp, MAX_MEDIA_URI_ERR_BODY)
        )));
    }
    Ok(MediaUri {
        uri,
        invalid_after_connect: media_uri
            .map(|m| boolean(m, "InvalidAfterConnect"))
            .unwrap_or(false),
        invalid_after_reboot: media_uri
            .map(|m| boolean(m, "InvalidAfterReboot"))
            .unwrap_or(false),
    })
}

/// Shorten `s` to at most `limit` bytes for error messages (the Go twin's
/// `truncateForError`).
fn truncate_for_error(s: &str, limit: usize) -> String {
    if s.len() <= limit {
        return s.to_string();
    }
    format!("{}...(truncated)", &s[..limit])
}

// ---------------------------------------------------------------------------
// Main/sub stream selection (the Go pure helpers)
// ---------------------------------------------------------------------------

/// Naming hints used ONLY as a tie-breaker between profiles of equal
/// resolution (OEM firmware assigns arbitrary names — issue #7 in the Go
/// twin); these settle exact ties and demote obviously-secondary profiles.
const MAIN_STREAM_HINTS: [&str; 5] = ["main", "primary", "主流", "主码流", "channel1"];
const SUB_STREAM_HINTS: [&str; 5] = ["sub", "secondary", "辅流", "辅码流", "extra"];

/// The main-stream profile token: the profile with the most pixels (W×H).
/// Blindly using `profiles[0]` silently records a substream on devices
/// that list the low-resolution profile first.
///
/// Heuristics (field-tested against Hikvision, Dahua, Amcrest, HiSilicon
/// OEM and ESP32 hardware, per the Go twin):
/// - Resolution rules. Exact ties are settled by naming hints only: a
///   candidate whose token/name contains a main hint wins; sub hints lose
///   ties.
/// - When no profile carries resolution information at all, the first
///   profile is returned (list-order fallback).
///
/// Returns `""` for an empty list.
#[must_use]
pub fn select_main_profile(profiles: &[Profile]) -> String {
    if profiles.is_empty() {
        return String::new();
    }

    let mut best: Option<usize> = None;
    let mut best_pixels: i64 = -1;
    let mut any_known = false;

    for (i, p) in profiles.iter().enumerate() {
        let Some(pixels) = profile_pixels(p) else {
            continue;
        };
        any_known = true;
        match pixels.cmp(&best_pixels) {
            std::cmp::Ordering::Greater => {
                best = Some(i);
                best_pixels = pixels;
            }
            std::cmp::Ordering::Equal => {
                if let Some(b) = best {
                    if main_tie_break(&profiles[i], &profiles[b]) < 0 {
                        best = Some(i);
                    }
                }
            }
            std::cmp::Ordering::Less => {}
        }
    }

    if !any_known {
        return profiles[0].token.clone();
    }
    profiles[best.unwrap_or(0)].token.clone()
}

/// The sub-stream profile token given the already-selected main token:
/// among the remaining profiles it is the one with the most pixels that is
/// still STRICTLY smaller than the main resolution. A second profile with
/// the SAME resolution as main is not a substream — on some hardware
/// (e.g. Amcrest IP4M) two tokens at the same resolution are two handles
/// onto the same stream.
///
/// Returns `""` when there is no independent substream. If `main_token`
/// does not resolve to any profile, the same-resolution guard is disabled
/// and the largest profile wins (pass a token from
/// [`select_main_profile`] to avoid this). Without resolution information
/// anywhere, the first non-main profile is returned as a list-order
/// fallback.
#[must_use]
pub fn select_sub_profile(profiles: &[Profile], main_token: &str) -> String {
    if profiles.is_empty() {
        return String::new();
    }

    let mut main_pixels: i64 = -1;
    let mut any_known = false;
    for p in profiles {
        if let Some(pixels) = profile_pixels(p) {
            any_known = true;
            if p.token == main_token {
                main_pixels = pixels;
            }
        }
    }

    let mut best = String::new();
    let mut best_pixels: i64 = -1;

    for p in profiles {
        if p.token.is_empty() || p.token == main_token {
            continue;
        }
        let Some(pixels) = profile_pixels(p) else {
            continue;
        };
        // Same resolution as main = same stream under another token.
        if main_pixels >= 0 && pixels >= main_pixels {
            continue;
        }
        match pixels.cmp(&best_pixels) {
            std::cmp::Ordering::Greater => {
                best = p.token.clone();
                best_pixels = pixels;
            }
            std::cmp::Ordering::Equal => {
                if !best.is_empty() {
                    if let Some(current) = profile_by_token(profiles, &best) {
                        if sub_tie_break(p, current) < 0 {
                            best = p.token.clone();
                        }
                    }
                }
            }
            std::cmp::Ordering::Less => {}
        }
    }

    if !best.is_empty() {
        return best;
    }

    // List-order fallback when resolution information is absent.
    if !any_known {
        for p in profiles {
            if !p.token.is_empty() && p.token != main_token {
                return p.token.clone();
            }
        }
    }

    String::new()
}

/// W×H of the profile's video encoder configuration, or `None` when the
/// profile or its resolution is unknown.
fn profile_pixels(p: &Profile) -> Option<i64> {
    let res = p
        .video_encoder_configuration
        .as_ref()?
        .resolution
        .as_ref()?;
    if res.width <= 0 || res.height <= 0 {
        return None;
    }
    Some(res.width * res.height)
}

/// Main-stream tie-break: `< 0` when `a` wins (main-ish naming beats
/// neutral beats sub-ish).
fn main_tie_break(a: &Profile, b: &Profile) -> i32 {
    hint_score(b) - hint_score(a)
}

/// Sub-stream tie-break: `< 0` when `a` wins (sub-ish naming beats
/// neutral).
fn sub_tie_break(a: &Profile, b: &Profile) -> i32 {
    hint_score(a) - hint_score(b)
}

/// Rate a profile's naming hints: positive = main-ish, negative =
/// sub-ish, zero = neutral.
fn hint_score(p: &Profile) -> i32 {
    let name = format!("{} {}", p.token, p.name).to_lowercase();
    if MAIN_STREAM_HINTS.iter().any(|h| name.contains(h)) {
        return 1;
    }
    if SUB_STREAM_HINTS.iter().any(|h| name.contains(h)) {
        return -1;
    }
    0
}

fn profile_by_token<'a>(profiles: &'a [Profile], token: &str) -> Option<&'a Profile> {
    profiles.iter().find(|p| p.token == token)
}

// ---------------------------------------------------------------------------
// SoapClient operations
// ---------------------------------------------------------------------------

impl SoapClient {
    /// List the media profiles with their inline video source, video
    /// encoder and PTZ configurations.
    pub async fn get_profiles(&self) -> Result<Vec<Profile>, ClientError> {
        let resp = self.device_call(&empty_op("GetProfiles")).await?;
        parse_list(&resp, "GetProfilesResponse", "Profiles", map_profile)
    }

    /// One profile by token (identity fields only — the Go twin's
    /// GetProfile response carries no configurations).
    pub async fn get_profile(&self, profile_token: &str) -> Result<Profile, ClientError> {
        let resp = self
            .device_call(&one_token_op("GetProfile", "ProfileToken", profile_token))
            .await?;
        let root = parse_xml_tree(&resp)?;
        let el = response_el(&root, "GetProfileResponse")?;
        Ok(el.find("Profile").map(map_profile).unwrap_or_default())
    }

    /// The stream URI for a profile, defaulting to RTP-Unicast/RTSP (use
    /// [`SoapClient::get_stream_uri_with_options`] to select another
    /// transport).
    pub async fn get_stream_uri(&self, profile_token: &str) -> Result<MediaUri, ClientError> {
        self.get_stream_uri_with_options(
            profile_token,
            &StreamSetup {
                stream: STREAM_RTP_UNICAST.into(),
                transport: Some(Transport {
                    protocol: PROTOCOL_RTSP.into(),
                }),
            },
        )
        .await
    }

    /// The stream URI for a profile with an explicit [`StreamSetup`].
    /// Some devices (e.g. ESP32 firmwares) return different stream shapes
    /// depending on the requested protocol.
    pub async fn get_stream_uri_with_options(
        &self,
        profile_token: &str,
        setup: &StreamSetup,
    ) -> Result<MediaUri, ClientError> {
        let (stream, protocol) = setup.validated()?;
        let body = build_get_stream_uri_request(profile_token, &stream, &protocol);
        let resp = self.device_call(&body).await?;
        parse_media_uri_response(&resp, "GetStreamUri", profile_token)
    }

    /// The JPEG snapshot URI for a profile (shares the GetStreamUri
    /// response shape, including the loose-URI fallback).
    pub async fn get_snapshot_uri(&self, profile_token: &str) -> Result<MediaUri, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetSnapshotUri",
                "ProfileToken",
                profile_token,
            ))
            .await?;
        parse_media_uri_response(&resp, "GetSnapshotUri", profile_token)
    }

    /// One video encoder configuration by token.
    pub async fn get_video_encoder_configuration(
        &self,
        configuration_token: &str,
    ) -> Result<VideoEncoderConfiguration, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetVideoEncoderConfiguration",
                "ConfigurationToken",
                configuration_token,
            ))
            .await?;
        parse_configuration(
            &resp,
            "GetVideoEncoderConfigurationResponse",
            map_video_encoder_configuration,
        )
    }

    /// All video encoder configurations (the fullest decode: resolution,
    /// rate control, MPEG4/H264 blocks and multicast included).
    pub async fn get_video_encoder_configurations(
        &self,
    ) -> Result<Vec<VideoEncoderConfiguration>, ClientError> {
        let resp = self
            .device_call(&empty_op("GetVideoEncoderConfigurations"))
            .await?;
        parse_list(
            &resp,
            "GetVideoEncoderConfigurationsResponse",
            "Configurations",
            map_video_encoder_configuration,
        )
    }

    /// Video encoder options for one configuration token (JPEG / MPEG4 /
    /// H264 ranges; empty token = device defaults).
    pub async fn get_video_encoder_configuration_options(
        &self,
        configuration_token: &str,
    ) -> Result<VideoEncoderConfigurationOptions, ClientError> {
        let resp = self
            .device_call(&opt_tokens_op(
                "GetVideoEncoderConfigurationOptions",
                configuration_token,
                "",
            ))
            .await?;
        parse_options(
            &resp,
            "GetVideoEncoderConfigurationOptionsResponse",
            map_video_encoder_options,
        )
    }

    /// The video encoder configurations compatible with a profile.
    pub async fn get_compatible_video_encoder_configurations(
        &self,
        profile_token: &str,
    ) -> Result<Vec<VideoEncoderConfiguration>, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetCompatibleVideoEncoderConfigurations",
                "ProfileToken",
                profile_token,
            ))
            .await?;
        parse_list(
            &resp,
            "GetCompatibleVideoEncoderConfigurationsResponse",
            "Configurations",
            map_video_encoder_configuration,
        )
    }

    /// One video source configuration by token.
    pub async fn get_video_source_configuration(
        &self,
        configuration_token: &str,
    ) -> Result<VideoSourceConfiguration, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetVideoSourceConfiguration",
                "ConfigurationToken",
                configuration_token,
            ))
            .await?;
        parse_configuration(
            &resp,
            "GetVideoSourceConfigurationResponse",
            map_video_source_configuration,
        )
    }

    /// All video source configurations.
    pub async fn get_video_source_configurations(
        &self,
    ) -> Result<Vec<VideoSourceConfiguration>, ClientError> {
        let resp = self
            .device_call(&empty_op("GetVideoSourceConfigurations"))
            .await?;
        parse_list(
            &resp,
            "GetVideoSourceConfigurationsResponse",
            "Configurations",
            map_video_source_configuration,
        )
    }

    /// Video source configuration options (bounds ranges, available
    /// source tokens); empty tokens are omitted.
    pub async fn get_video_source_configuration_options(
        &self,
        configuration_token: &str,
        profile_token: &str,
    ) -> Result<VideoSourceConfigurationOptions, ClientError> {
        let resp = self
            .device_call(&opt_tokens_op(
                "GetVideoSourceConfigurationOptions",
                configuration_token,
                profile_token,
            ))
            .await?;
        parse_options(
            &resp,
            "GetVideoSourceConfigurationOptionsResponse",
            map_video_source_options,
        )
    }

    /// The video source configurations compatible with a profile.
    pub async fn get_compatible_video_source_configurations(
        &self,
        profile_token: &str,
    ) -> Result<Vec<VideoSourceConfiguration>, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetCompatibleVideoSourceConfigurations",
                "ProfileToken",
                profile_token,
            ))
            .await?;
        parse_list(
            &resp,
            "GetCompatibleVideoSourceConfigurationsResponse",
            "Configurations",
            map_video_source_configuration,
        )
    }

    /// The video sources (token, framerate, max resolution).
    pub async fn get_video_sources(&self) -> Result<Vec<VideoSource>, ClientError> {
        let resp = self.device_call(&empty_op("GetVideoSources")).await?;
        parse_list(
            &resp,
            "GetVideoSourcesResponse",
            "VideoSources",
            map_video_source,
        )
    }

    /// The selectable modes of one video source.
    pub async fn get_video_source_modes(
        &self,
        video_source_token: &str,
    ) -> Result<Vec<VideoSourceMode>, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetVideoSourceModes",
                "VideoSourceToken",
                video_source_token,
            ))
            .await?;
        parse_list(
            &resp,
            "GetVideoSourceModesResponse",
            "VideoSourceModes",
            map_video_source_mode,
        )
    }

    /// Guaranteed concurrent encoder instance counts for one video source
    /// configuration.
    pub async fn get_guaranteed_number_of_video_encoder_instances(
        &self,
        configuration_token: &str,
    ) -> Result<GuaranteedNumberOfVideoEncoderInstances, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetGuaranteedNumberOfVideoEncoderInstances",
                "ConfigurationToken",
                configuration_token,
            ))
            .await?;
        let root = parse_xml_tree(&resp)?;
        let el = response_el(&root, "GetGuaranteedNumberOfVideoEncoderInstancesResponse")?;
        Ok(GuaranteedNumberOfVideoEncoderInstances {
            total_number: int(el, "TotalNumber"),
            jpeg: int(el, "JPEG"),
            h264: int(el, "H264"),
            mpeg4: int(el, "MPEG4"),
        })
    }

    /// The audio sources (token, channel count).
    pub async fn get_audio_sources(&self) -> Result<Vec<AudioSource>, ClientError> {
        let resp = self.device_call(&empty_op("GetAudioSources")).await?;
        parse_list(
            &resp,
            "GetAudioSourcesResponse",
            "AudioSources",
            map_audio_source,
        )
    }

    /// The audio outputs (tokens).
    pub async fn get_audio_outputs(&self) -> Result<Vec<AudioOutput>, ClientError> {
        let resp = self.device_call(&empty_op("GetAudioOutputs")).await?;
        parse_list(
            &resp,
            "GetAudioOutputsResponse",
            "AudioOutputs",
            map_audio_output,
        )
    }

    /// One audio source configuration by token.
    pub async fn get_audio_source_configuration(
        &self,
        configuration_token: &str,
    ) -> Result<AudioSourceConfiguration, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetAudioSourceConfiguration",
                "ConfigurationToken",
                configuration_token,
            ))
            .await?;
        parse_configuration(
            &resp,
            "GetAudioSourceConfigurationResponse",
            map_audio_source_configuration,
        )
    }

    /// All audio source configurations.
    pub async fn get_audio_source_configurations(
        &self,
    ) -> Result<Vec<AudioSourceConfiguration>, ClientError> {
        let resp = self
            .device_call(&empty_op("GetAudioSourceConfigurations"))
            .await?;
        parse_list(
            &resp,
            "GetAudioSourceConfigurationsResponse",
            "Configurations",
            map_audio_source_configuration,
        )
    }

    /// Audio source options (available input tokens).
    pub async fn get_audio_source_configuration_options(
        &self,
        configuration_token: &str,
        profile_token: &str,
    ) -> Result<AudioSourceConfigurationOptions, ClientError> {
        let resp = self
            .device_call(&opt_tokens_op(
                "GetAudioSourceConfigurationOptions",
                configuration_token,
                profile_token,
            ))
            .await?;
        parse_options(
            &resp,
            "GetAudioSourceConfigurationOptionsResponse",
            map_audio_source_options,
        )
    }

    /// The audio source configurations compatible with a profile.
    pub async fn get_compatible_audio_source_configurations(
        &self,
        profile_token: &str,
    ) -> Result<Vec<AudioSourceConfiguration>, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetCompatibleAudioSourceConfigurations",
                "ProfileToken",
                profile_token,
            ))
            .await?;
        parse_list(
            &resp,
            "GetCompatibleAudioSourceConfigurationsResponse",
            "Configurations",
            map_audio_source_configuration,
        )
    }

    /// One audio encoder configuration by token (multicast included).
    pub async fn get_audio_encoder_configuration(
        &self,
        configuration_token: &str,
    ) -> Result<AudioEncoderConfiguration, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetAudioEncoderConfiguration",
                "ConfigurationToken",
                configuration_token,
            ))
            .await?;
        parse_configuration(
            &resp,
            "GetAudioEncoderConfigurationResponse",
            map_audio_encoder_configuration,
        )
    }

    /// All audio encoder configurations.
    pub async fn get_audio_encoder_configurations(
        &self,
    ) -> Result<Vec<AudioEncoderConfiguration>, ClientError> {
        let resp = self
            .device_call(&empty_op("GetAudioEncoderConfigurations"))
            .await?;
        parse_list(
            &resp,
            "GetAudioEncoderConfigurationsResponse",
            "Configurations",
            map_audio_encoder_configuration,
        )
    }

    /// Audio encoder options (encodings, bitrates, sample rates).
    pub async fn get_audio_encoder_configuration_options(
        &self,
        configuration_token: &str,
        profile_token: &str,
    ) -> Result<AudioEncoderConfigurationOptions, ClientError> {
        let resp = self
            .device_call(&opt_tokens_op(
                "GetAudioEncoderConfigurationOptions",
                configuration_token,
                profile_token,
            ))
            .await?;
        parse_options(
            &resp,
            "GetAudioEncoderConfigurationOptionsResponse",
            map_audio_encoder_options,
        )
    }

    /// The audio encoder configurations compatible with a profile.
    pub async fn get_compatible_audio_encoder_configurations(
        &self,
        profile_token: &str,
    ) -> Result<Vec<AudioEncoderConfiguration>, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetCompatibleAudioEncoderConfigurations",
                "ProfileToken",
                profile_token,
            ))
            .await?;
        parse_list(
            &resp,
            "GetCompatibleAudioEncoderConfigurationsResponse",
            "Configurations",
            map_audio_encoder_configuration,
        )
    }

    /// One audio output configuration by token.
    pub async fn get_audio_output_configuration(
        &self,
        configuration_token: &str,
    ) -> Result<AudioOutputConfiguration, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetAudioOutputConfiguration",
                "ConfigurationToken",
                configuration_token,
            ))
            .await?;
        parse_configuration(
            &resp,
            "GetAudioOutputConfigurationResponse",
            map_audio_output_configuration,
        )
    }

    /// All audio output configurations.
    pub async fn get_audio_output_configurations(
        &self,
    ) -> Result<Vec<AudioOutputConfiguration>, ClientError> {
        let resp = self
            .device_call(&empty_op("GetAudioOutputConfigurations"))
            .await?;
        parse_list(
            &resp,
            "GetAudioOutputConfigurationsResponse",
            "Configurations",
            map_audio_output_configuration,
        )
    }

    /// Audio output options (available output tokens).
    pub async fn get_audio_output_configuration_options(
        &self,
        configuration_token: &str,
    ) -> Result<AudioOutputConfigurationOptions, ClientError> {
        let resp = self
            .device_call(&opt_tokens_op(
                "GetAudioOutputConfigurationOptions",
                configuration_token,
                "",
            ))
            .await?;
        parse_options(
            &resp,
            "GetAudioOutputConfigurationOptionsResponse",
            map_audio_output_options,
        )
    }

    /// The audio output configurations compatible with a profile.
    pub async fn get_compatible_audio_output_configurations(
        &self,
        profile_token: &str,
    ) -> Result<Vec<AudioOutputConfiguration>, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetCompatibleAudioOutputConfigurations",
                "ProfileToken",
                profile_token,
            ))
            .await?;
        parse_list(
            &resp,
            "GetCompatibleAudioOutputConfigurationsResponse",
            "Configurations",
            map_audio_output_configuration,
        )
    }

    /// One audio decoder configuration by token.
    pub async fn get_audio_decoder_configuration(
        &self,
        configuration_token: &str,
    ) -> Result<AudioDecoderConfiguration, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetAudioDecoderConfiguration",
                "ConfigurationToken",
                configuration_token,
            ))
            .await?;
        parse_configuration(
            &resp,
            "GetAudioDecoderConfigurationResponse",
            map_audio_decoder_configuration,
        )
    }

    /// All audio decoder configurations.
    pub async fn get_audio_decoder_configurations(
        &self,
    ) -> Result<Vec<AudioDecoderConfiguration>, ClientError> {
        let resp = self
            .device_call(&empty_op("GetAudioDecoderConfigurations"))
            .await?;
        parse_list(
            &resp,
            "GetAudioDecoderConfigurationsResponse",
            "Configurations",
            map_audio_decoder_configuration,
        )
    }

    /// Audio decoder options (per-codec bitrate/sample-rate lists).
    pub async fn get_audio_decoder_configuration_options(
        &self,
        configuration_token: &str,
    ) -> Result<AudioDecoderConfigurationOptions, ClientError> {
        let resp = self
            .device_call(&opt_tokens_op(
                "GetAudioDecoderConfigurationOptions",
                configuration_token,
                "",
            ))
            .await?;
        parse_options(
            &resp,
            "GetAudioDecoderConfigurationOptionsResponse",
            map_audio_decoder_options,
        )
    }

    /// The audio decoder configurations compatible with a profile.
    pub async fn get_compatible_audio_decoder_configurations(
        &self,
        profile_token: &str,
    ) -> Result<Vec<AudioDecoderConfiguration>, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetCompatibleAudioDecoderConfigurations",
                "ProfileToken",
                profile_token,
            ))
            .await?;
        parse_list(
            &resp,
            "GetCompatibleAudioDecoderConfigurationsResponse",
            "Configurations",
            map_audio_decoder_configuration,
        )
    }

    /// One metadata configuration by token (PTZ filter, events presence,
    /// analytics flag, multicast).
    pub async fn get_metadata_configuration(
        &self,
        configuration_token: &str,
    ) -> Result<MetadataConfiguration, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetMetadataConfiguration",
                "ConfigurationToken",
                configuration_token,
            ))
            .await?;
        parse_configuration(
            &resp,
            "GetMetadataConfigurationResponse",
            map_metadata_configuration,
        )
    }

    /// All metadata configurations.
    pub async fn get_metadata_configurations(
        &self,
    ) -> Result<Vec<MetadataConfiguration>, ClientError> {
        let resp = self
            .device_call(&empty_op("GetMetadataConfigurations"))
            .await?;
        parse_list(
            &resp,
            "GetMetadataConfigurationsResponse",
            "Configurations",
            map_metadata_configuration,
        )
    }

    /// Metadata configuration options (PTZ status filter flags).
    pub async fn get_metadata_configuration_options(
        &self,
        configuration_token: &str,
        profile_token: &str,
    ) -> Result<MetadataConfigurationOptions, ClientError> {
        let resp = self
            .device_call(&opt_tokens_op(
                "GetMetadataConfigurationOptions",
                configuration_token,
                profile_token,
            ))
            .await?;
        parse_options(
            &resp,
            "GetMetadataConfigurationOptionsResponse",
            map_metadata_options,
        )
    }

    /// The metadata configurations compatible with a profile.
    pub async fn get_compatible_metadata_configurations(
        &self,
        profile_token: &str,
    ) -> Result<Vec<MetadataConfiguration>, ClientError> {
        let resp = self
            .device_call(&one_token_op(
                "GetCompatibleMetadataConfigurations",
                "ProfileToken",
                profile_token,
            ))
            .await?;
        parse_list(
            &resp,
            "GetCompatibleMetadataConfigurationsResponse",
            "Configurations",
            map_metadata_configuration,
        )
    }

    /// The OSD configurations of one video source configuration (empty
    /// token = all).
    pub async fn get_osds(
        &self,
        configuration_token: &str,
    ) -> Result<Vec<OsdConfiguration>, ClientError> {
        let resp = self
            .device_call(&opt_tokens_op("GetOSDs", configuration_token, ""))
            .await?;
        parse_list(&resp, "GetOSDsResponse", "OSDs", map_osd)
    }

    /// One OSD configuration by token.
    pub async fn get_osd(&self, osd_token: &str) -> Result<OsdConfiguration, ClientError> {
        let resp = self
            .device_call(&one_token_op("GetOSD", "OSDToken", osd_token))
            .await?;
        let root = parse_xml_tree(&resp)?;
        let el = response_el(&root, "GetOSDResponse")?;
        Ok(el.find("OSD").map(map_osd).unwrap_or_default())
    }

    /// OSD options for one video source configuration.
    pub async fn get_osd_options(
        &self,
        configuration_token: &str,
    ) -> Result<OsdConfigurationOptions, ClientError> {
        let resp = self
            .device_call(&opt_tokens_op("GetOSDOptions", configuration_token, ""))
            .await?;
        parse_options(&resp, "GetOSDOptionsResponse", map_osd_options)
    }
}

// The small options mappers used by the closures above, hoisted so the
// async methods can pass plain fn pointers.
fn map_audio_source_options(el: &XmlElem) -> AudioSourceConfigurationOptions {
    AudioSourceConfigurationOptions {
        input_tokens_available: string_list(el, "InputTokensAvailable"),
    }
}

fn map_audio_output_options(el: &XmlElem) -> AudioOutputConfigurationOptions {
    AudioOutputConfigurationOptions {
        output_tokens_available: string_list(el, "OutputTokensAvailable"),
    }
}

fn map_metadata_options(el: &XmlElem) -> MetadataConfigurationOptions {
    MetadataConfigurationOptions {
        ptz_status_filter_options: el.find("PTZStatusFilterOptions").map(map_ptz_filter),
    }
}

fn map_osd_options(el: &XmlElem) -> OsdConfigurationOptions {
    OsdConfigurationOptions {
        maximum_number_of_osds: int(el, "MaximumNumberOfOSDs"),
    }
}

fn map_audio_source(el: &XmlElem) -> AudioSource {
    AudioSource {
        token: token_of(el),
        channels: int(el, "Channels"),
    }
}

fn map_audio_output(el: &XmlElem) -> AudioOutput {
    AudioOutput {
        token: token_of(el),
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

    // --- decode tree ------------------------------------------------------

    #[test]
    fn tree_builds_nested_elements_with_attrs_and_entities() {
        let doc = wrapped(
            r#"<R><A token="x&amp;y"><B>1</B><B>2</B></A><C val="3"/><D>be&#102;ore<E>after</E></D></R>"#,
        );
        let root = parse_xml_tree(&doc).unwrap();
        assert_eq!(root.name, "Envelope");
        let r = find_desc(&root, "R").unwrap();
        let a = r.find("A").unwrap();
        assert_eq!(a.attr("token"), Some("x&y"));
        assert_eq!(a.find_all("B").len(), 2);
        assert_eq!(a.child_text("B").as_deref(), Some("1"));
        assert_eq!(r.find("C").unwrap().attr("val"), Some("3"));
        assert_eq!(r.find("C").unwrap().children.len(), 0);
        let d = r.find("D").unwrap();
        assert_eq!(d.text, "before");
        assert_eq!(d.child_text("E").as_deref(), Some("after"));
    }

    #[test]
    fn tree_rejects_malformed_and_elementless_input() {
        assert!(parse_xml_tree("<not-xml").is_err());
        assert!(parse_xml_tree("just text").is_err());
    }

    // --- request goldens ---------------------------------------------------

    #[test]
    fn request_goldens() {
        assert_eq!(
            empty_op("GetProfiles"),
            "<trt:GetProfiles xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"></trt:GetProfiles>"
        );
        assert_eq!(
            one_token_op("GetProfile", "ProfileToken", "profile-1"),
            "<trt:GetProfile xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\">\
             <trt:ProfileToken>profile-1</trt:ProfileToken></trt:GetProfile>"
        );
        assert_eq!(
            one_token_op("GetOSD", "OSDToken", "osd-1"),
            "<trt:GetOSD xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\">\
             <trt:OSDToken>osd-1</trt:OSDToken></trt:GetOSD>"
        );
        assert_eq!(
            one_token_op("GetVideoSourceModes", "VideoSourceToken", "src-1"),
            "<trt:GetVideoSourceModes xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\">\
             <trt:VideoSourceToken>src-1</trt:VideoSourceToken></trt:GetVideoSourceModes>"
        );
        // Optional filter children: omitted when empty, both when present.
        assert_eq!(
            opt_tokens_op("GetVideoEncoderConfigurationOptions", "vec-1", ""),
            "<trt:GetVideoEncoderConfigurationOptions xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\">\
             <trt:ConfigurationToken>vec-1</trt:ConfigurationToken></trt:GetVideoEncoderConfigurationOptions>"
        );
        assert_eq!(
            opt_tokens_op("GetAudioSourceConfigurationOptions", "asc-1", "prof-1"),
            "<trt:GetAudioSourceConfigurationOptions xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\">\
             <trt:ConfigurationToken>asc-1</trt:ConfigurationToken>\
             <trt:ProfileToken>prof-1</trt:ProfileToken></trt:GetAudioSourceConfigurationOptions>"
        );
    }

    #[test]
    fn stream_uri_request_golden() {
        assert_eq!(
            build_get_stream_uri_request("profile-1", "RTP-Unicast", "RTSP"),
            "<trt:GetStreamUri xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" \
             xmlns:tt=\"http://www.onvif.org/ver10/schema\">\
             <trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream>\
             <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup>\
             <trt:ProfileToken>profile-1</trt:ProfileToken></trt:GetStreamUri>"
        );
    }

    // --- StreamSetup validation (Go stream_helpers_test) --------------------

    #[test]
    fn stream_setup_defaults_empty_transport_to_rtsp() {
        for transport in [None, Some(Transport::default())] {
            let setup = StreamSetup {
                stream: STREAM_RTP_UNICAST.into(),
                transport,
            };
            let (stream, protocol) = setup.validated().unwrap();
            assert_eq!(stream, "RTP-Unicast");
            assert_eq!(protocol, "RTSP");
        }
    }

    #[test]
    fn stream_setup_rejects_bad_values() {
        let bad_stream = StreamSetup {
            stream: "UDP-Unicast".into(),
            transport: Some(Transport {
                protocol: "RTSP".into(),
            }),
        };
        assert!(bad_stream.validated().is_err());

        let bad_protocol = StreamSetup {
            stream: "RTP-Unicast".into(),
            transport: Some(Transport {
                protocol: "SMTP".into(),
            }),
        };
        assert!(bad_protocol.validated().is_err());

        let tcp = StreamSetup {
            stream: "RTP-Multicast".into(),
            transport: Some(Transport {
                protocol: "TCP".into(),
            }),
        };
        assert!(tcp.validated().is_ok());
    }

    // --- GetProfiles (Go media_profiles_full_test fixture) ------------------

    const PROFILES_RESP: &str = r#"<GetProfilesResponse>
        <Profiles token="prof-1">
            <Name>Main</Name>
            <VideoSourceConfiguration token="vsc-1"><Name>Src</Name><UseCount>3</UseCount><SourceToken>src-0</SourceToken><Bounds x="0" y="0" width="2560" height="1440"/></VideoSourceConfiguration>
            <VideoEncoderConfiguration token="vec-1"><Name>H264</Name><UseCount>3</UseCount><Encoding>H264</Encoding><Quality>5</Quality><Resolution><Width>2560</Width><Height>1440</Height></Resolution><RateControl><FrameRateLimit>25</FrameRateLimit><EncodingInterval>1</EncodingInterval><BitrateLimit>4096</BitrateLimit></RateControl></VideoEncoderConfiguration>
            <PTZConfiguration token="ptz-1"><Name>PTZ</Name><UseCount>1</UseCount><NodeToken>node-0</NodeToken></PTZConfiguration>
        </Profiles>
        <Profiles token="prof-2"><Name>Bare</Name></Profiles>
        </GetProfilesResponse>"#;

    #[test]
    fn decodes_profiles_full_mapping() {
        let profiles = parse_list(
            &wrapped(PROFILES_RESP),
            "GetProfilesResponse",
            "Profiles",
            map_profile,
        )
        .unwrap();
        assert_eq!(profiles.len(), 2);

        let main = &profiles[0];
        assert_eq!(
            (main.token.as_str(), main.name.as_str()),
            ("prof-1", "Main")
        );

        let vsc = main.video_source_configuration.as_ref().unwrap();
        assert_eq!(
            (vsc.token.as_str(), vsc.source_token.as_str(), vsc.use_count),
            ("vsc-1", "src-0", 3)
        );
        let bounds = vsc.bounds.as_ref().unwrap();
        assert_eq!((bounds.width, bounds.height), (2560, 1440));

        let vec = main.video_encoder_configuration.as_ref().unwrap();
        assert_eq!(
            (vec.encoding.as_str(), vec.token.as_str(), vec.quality),
            ("H264", "vec-1", 5.0)
        );
        let res = vec.resolution.as_ref().unwrap();
        assert_eq!((res.width, res.height), (2560, 1440));
        let rc = vec.rate_control.as_ref().unwrap();
        assert_eq!(
            (rc.frame_rate_limit, rc.encoding_interval, rc.bitrate_limit),
            (25, 1, 4096)
        );

        let ptz = main.ptz_configuration.as_ref().unwrap();
        assert_eq!(ptz.node_token, "node-0");

        let bare = &profiles[1];
        assert!(bare.video_source_configuration.is_none());
        assert!(bare.video_encoder_configuration.is_none());
        assert!(bare.ptz_configuration.is_none());
    }

    #[test]
    fn decodes_single_profile() {
        let doc = wrapped(
            "<GetProfileResponse><Profile token=\"p-1\"><Name>Main</Name></Profile></GetProfileResponse>",
        );
        let root = parse_xml_tree(&doc).unwrap();
        let el = response_el(&root, "GetProfileResponse").unwrap();
        let p = el.find("Profile").map(map_profile).unwrap();
        assert_eq!((p.token.as_str(), p.name.as_str()), ("p-1", "Main"));
    }

    #[test]
    fn missing_response_element_errors_but_empty_list_is_valid() {
        assert!(parse_list(
            &wrapped("<SomethingElse/>"),
            "GetProfilesResponse",
            "Profiles",
            map_profile
        )
        .is_err());
        // Present but empty: empty list is valid (devices without audio).
        assert_eq!(
            parse_list(
                &wrapped("<GetAudioSourceConfigurationsResponse/>"),
                "GetAudioSourceConfigurationsResponse",
                "Configurations",
                map_audio_source_configuration
            )
            .unwrap()
            .len(),
            0
        );
    }

    // --- stream / snapshot URIs ---------------------------------------------

    #[test]
    fn decodes_stream_uri_mapping() {
        // The Go TestGetStreamURIMapping fixture.
        let doc = wrapped(
            "<GetStreamUriResponse><MediaUri><Uri>rtsp://192.0.2.9:554/main</Uri>\
             <InvalidAfterConnect>false</InvalidAfterConnect>\
             <InvalidAfterReboot>true</InvalidAfterReboot></MediaUri></GetStreamUriResponse>",
        );
        let uri = parse_media_uri_response(&doc, "GetStreamUri", "profile-1").unwrap();
        assert_eq!(uri.uri, "rtsp://192.0.2.9:554/main");
        assert!(!uri.invalid_after_connect);
        assert!(uri.invalid_after_reboot);
    }

    #[test]
    fn snapshot_uri_decodes_and_uses_loose_fallback() {
        // Typed path.
        let typed = wrapped(
            "<GetSnapshotUriResponse><MediaUri><Uri>http://x/snap</Uri></MediaUri></GetSnapshotUriResponse>",
        );
        assert_eq!(
            parse_media_uri_response(&typed, "GetSnapshotUri", "p")
                .unwrap()
                .uri,
            "http://x/snap"
        );

        // Loose path shapes that motivated the Go loose scan (issue #3):
        // a prefixed Uri (whitespace to trim) and a bare Uri with no
        // MediaUri wrapper at all.
        let prefixed = wrapped(
            "<GetSnapshotUriResponse><MediaUri><tt:Uri>  http://cam/snap  </tt:Uri></MediaUri></GetSnapshotUriResponse>",
        );
        assert_eq!(
            parse_media_uri_response(&prefixed, "GetSnapshotUri", "p")
                .unwrap()
                .uri,
            "http://cam/snap"
        );
        let loose = wrapped(
            "<GetSnapshotUriResponse><Uri>rtsp://cam/stream</Uri></GetSnapshotUriResponse>",
        );
        assert_eq!(
            parse_media_uri_response(&loose, "GetSnapshotUri", "p")
                .unwrap()
                .uri,
            "rtsp://cam/stream"
        );
    }

    #[test]
    fn empty_media_uri_rejected_with_diagnostics() {
        let doc =
            wrapped("<GetStreamUriResponse><MediaUri><Uri/></MediaUri></GetStreamUriResponse>");
        let err = parse_media_uri_response(&doc, "GetStreamUri", "profile-1").unwrap_err();
        match err {
            ClientError::Parse(m) => {
                assert!(m.contains("device returned an empty media URI"), "{m}");
                assert!(m.contains("profile-1"), "{m}");
            }
            other => panic!("expected parse error, got {other:?}"),
        }
    }

    #[test]
    fn truncate_for_error_limits_body() {
        assert_eq!(truncate_for_error("err", 100), "err");
        let long = "x".repeat(10_000);
        let out = truncate_for_error(&long, 100);
        assert!(out.len() < long.len());
        assert!(out.ends_with("...(truncated)"));
    }

    // --- encoder configurations ----------------------------------------------

    #[test]
    fn decodes_video_encoder_configurations_list() {
        let doc = wrapped(
            "<GetVideoEncoderConfigurationsResponse>\
             <Configurations token=\"vec-1\">\
             <Name>main h264</Name><UseCount>3</UseCount><Encoding>H264</Encoding><Quality>4</Quality>\
             <Resolution><Width>2560</Width><Height>1440</Height></Resolution>\
             <RateControl><FrameRateLimit>15</FrameRateLimit><EncodingInterval>1</EncodingInterval><BitrateLimit>4096</BitrateLimit></RateControl>\
             <H264><GovLength>50</GovLength><H264Profile>Main</H264Profile></H264>\
             <MPEG4><GovLength>30</GovLength><MPEG4Profile>ASP</MPEG4Profile></MPEG4>\
             <Multicast><Address><Type>IPv4</Type><IPv4Address>239.255.0.1</IPv4Address></Address><Port>5000</Port><TTL>5</TTL><AutoStart>false</AutoStart></Multicast>\
             </Configurations></GetVideoEncoderConfigurationsResponse>",
        );
        let configs = parse_list(
            &doc,
            "GetVideoEncoderConfigurationsResponse",
            "Configurations",
            map_video_encoder_configuration,
        )
        .unwrap();
        assert_eq!(configs.len(), 1);
        let c = &configs[0];
        assert_eq!((c.token.as_str(), c.encoding.as_str()), ("vec-1", "H264"));
        assert_eq!(c.h264.as_ref().unwrap().gov_length, 50);
        assert_eq!(c.h264.as_ref().unwrap().h264_profile, "Main");
        assert_eq!(c.mpeg4.as_ref().unwrap().mpeg4_profile, "ASP");
        let mc = c.multicast.as_ref().unwrap();
        assert_eq!(mc.address.as_ref().unwrap().ipv4_address, "239.255.0.1");
        assert_eq!((mc.port, mc.ttl, mc.auto_start), (5000, 5, false));
    }

    #[test]
    fn decodes_single_video_encoder_configuration() {
        let doc = wrapped(
            "<GetVideoEncoderConfigurationResponse>\
             <Configuration token=\"vec-1\"><Name>H264</Name><UseCount>1</UseCount>\
             <Encoding>H264</Encoding><Quality>5</Quality>\
             <Resolution><Width>1920</Width><Height>1080</Height></Resolution>\
             <RateControl><FrameRateLimit>25</FrameRateLimit><EncodingInterval>1</EncodingInterval><BitrateLimit>4096</BitrateLimit></RateControl>\
             </Configuration></GetVideoEncoderConfigurationResponse>",
        );
        let c = parse_configuration(
            &doc,
            "GetVideoEncoderConfigurationResponse",
            map_video_encoder_configuration,
        )
        .unwrap();
        assert_eq!(c.token, "vec-1");
        assert_eq!(
            (
                c.resolution.unwrap().width,
                c.rate_control.unwrap().bitrate_limit
            ),
            (1920, 4096)
        );

        // Absent Configuration element: zero value, like the Go twin.
        let empty = wrapped("<GetVideoEncoderConfigurationResponse/>");
        let zero = parse_configuration(
            &empty,
            "GetVideoEncoderConfigurationResponse",
            map_video_encoder_configuration,
        )
        .unwrap();
        assert_eq!(zero, VideoEncoderConfiguration::default());
    }

    #[test]
    fn decodes_video_encoder_options_jpeg_h264_mpeg4() {
        // JPEG+H264 from media_profiles_full_test, MPEG4 from
        // encoder_options_test.
        let doc = wrapped(
            "<GetVideoEncoderConfigurationOptionsResponse><Options>\
             <QualityRange><Min>1</Min><Max>6</Max></QualityRange>\
             <JPEG>\
             <ResolutionsAvailable><Width>1920</Width><Height>1080</Height></ResolutionsAvailable>\
             <FrameRateRange><Min>1</Min><Max>30</Max></FrameRateRange>\
             <EncodingIntervalRange><Min>1</Min><Max>3</Max></EncodingIntervalRange>\
             </JPEG>\
             <H264>\
             <ResolutionsAvailable><Width>2560</Width><Height>1440</Height></ResolutionsAvailable>\
             <GovLengthRange><Min>1</Min><Max>120</Max></GovLengthRange>\
             <FrameRateRange><Min>1</Min><Max>25</Max></FrameRateRange>\
             <EncodingIntervalRange><Min>1</Min><Max>2</Max></EncodingIntervalRange>\
             <H264ProfilesSupported>Main</H264ProfilesSupported>\
             <H264ProfilesSupported>High</H264ProfilesSupported>\
             </H264>\
             <MPEG4>\
             <ResolutionsAvailable><Width>1280</Width><Height>720</Height></ResolutionsAvailable>\
             <GovLengthRange><Min>1</Min><Max>60</Max></GovLengthRange>\
             <Mpeg4ProfilesSupported>Simple</Mpeg4ProfilesSupported>\
             </MPEG4>\
             </Options></GetVideoEncoderConfigurationOptionsResponse>",
        );
        let opts = parse_options(
            &doc,
            "GetVideoEncoderConfigurationOptionsResponse",
            map_video_encoder_options,
        )
        .unwrap();
        let qr = opts.quality_range.unwrap();
        assert_eq!((qr.min, qr.max), (1.0, 6.0));
        let jpeg = opts.jpeg.unwrap();
        assert_eq!(jpeg.resolutions_available[0].width, 1920);
        assert_eq!(jpeg.frame_rate_range.unwrap().max, 30.0);
        assert_eq!(jpeg.encoding_interval_range.unwrap().max, 3);
        let h264 = opts.h264.unwrap();
        assert_eq!(h264.gov_length_range.unwrap().max, 120);
        assert_eq!(h264.resolutions_available[0].height, 1440);
        assert_eq!(h264.h264_profiles_supported, vec!["Main", "High"]);
        let mpeg4 = opts.mpeg4.unwrap();
        assert_eq!(mpeg4.gov_length_range.unwrap().max, 60);
        assert_eq!(mpeg4.mpeg4_profiles_supported, vec!["Simple"]);

        // Empty options decode to the zero value.
        let empty = wrapped(
            "<GetVideoEncoderConfigurationOptionsResponse><Options/></GetVideoEncoderConfigurationOptionsResponse>",
        );
        let zero = parse_options(
            &empty,
            "GetVideoEncoderConfigurationOptionsResponse",
            map_video_encoder_options,
        )
        .unwrap();
        assert_eq!(zero, VideoEncoderConfigurationOptions::default());
    }

    // --- video sources --------------------------------------------------------

    #[test]
    fn decodes_video_sources_modes_and_instances() {
        let sources = wrapped(
            "<GetVideoSourcesResponse><VideoSources token=\"src-0\">\
             <Framerate>25.5</Framerate><Resolution><Width>2592</Width><Height>1944</Height></Resolution>\
             </VideoSources></GetVideoSourcesResponse>",
        );
        let src = parse_list(
            &sources,
            "GetVideoSourcesResponse",
            "VideoSources",
            map_video_source,
        )
        .unwrap();
        assert_eq!(src[0].token, "src-0");
        assert_eq!(src[0].framerate, 25.5);
        assert_eq!(
            (src[0].resolution.width, src[0].resolution.height),
            (2592, 1944)
        );

        let modes = wrapped(
            "<GetVideoSourceModesResponse><VideoSourceModes token=\"mode-1\">\
             <Enabled>true</Enabled>\
             <Resolution><Width>1920</Width><Height>1080</Height></Resolution>\
             </VideoSourceModes></GetVideoSourceModesResponse>",
        );
        let m = parse_list(
            &modes,
            "GetVideoSourceModesResponse",
            "VideoSourceModes",
            map_video_source_mode,
        )
        .unwrap();
        assert_eq!(
            (m[0].token.as_str(), m[0].enabled, m[0].resolution.width),
            ("mode-1", true, 1920)
        );

        let instances = wrapped(
            "<GetGuaranteedNumberOfVideoEncoderInstancesResponse>\
             <TotalNumber>3</TotalNumber><JPEG>1</JPEG><H264>2</H264><MPEG4>0</MPEG4>\
             </GetGuaranteedNumberOfVideoEncoderInstancesResponse>",
        );
        let root = parse_xml_tree(&instances).unwrap();
        let el = response_el(&root, "GetGuaranteedNumberOfVideoEncoderInstancesResponse").unwrap();
        assert_eq!(
            (
                int(el, "TotalNumber"),
                int(el, "JPEG"),
                int(el, "H264"),
                int(el, "MPEG4")
            ),
            (3, 1, 2, 0)
        );
    }

    #[test]
    fn decodes_video_source_configuration_and_options() {
        let doc = wrapped(
            "<GetVideoSourceConfigurationResponse>\
             <Configuration token=\"vsc-1\"><Name>cam</Name><UseCount>2</UseCount>\
             <SourceToken>src-0</SourceToken><Bounds x=\"8\" y=\"16\" width=\"1920\" height=\"1080\"/>\
             </Configuration></GetVideoSourceConfigurationResponse>",
        );
        let c = parse_configuration(
            &doc,
            "GetVideoSourceConfigurationResponse",
            map_video_source_configuration,
        )
        .unwrap();
        assert_eq!(c.source_token, "src-0");
        let bounds = c.bounds.unwrap();
        assert_eq!((bounds.x, bounds.width), (8, 1920));

        let options = wrapped(
            "<GetVideoSourceConfigurationOptionsResponse><Options>\
             <BoundsRange><X><Min>0</Min><Max>100</Max></X><Width><Min>16</Min><Max>2592</Max></Width></BoundsRange>\
             <VideoSourceTokensAvailable>src-0</VideoSourceTokensAvailable>\
             <VideoSourceTokensAvailable>src-1</VideoSourceTokensAvailable>\
             </Options></GetVideoSourceConfigurationOptionsResponse>",
        );
        let o = parse_options(
            &options,
            "GetVideoSourceConfigurationOptionsResponse",
            map_video_source_options,
        )
        .unwrap();
        let br = o.bounds_range.unwrap();
        assert_eq!(br.x.as_ref().unwrap().max, 100);
        assert_eq!(br.width.as_ref().unwrap().max, 2592);
        assert_eq!(o.video_source_tokens_available, vec!["src-0", "src-1"]);
    }

    // --- audio families -------------------------------------------------------

    #[test]
    fn decodes_audio_sources_and_outputs() {
        let sources = wrapped(
            "<GetAudioSourcesResponse><AudioSources token=\"src-1\"><Channels>1</Channels></AudioSources></GetAudioSourcesResponse>",
        );
        let list = parse_list(
            &sources,
            "GetAudioSourcesResponse",
            "AudioSources",
            map_audio_source,
        )
        .unwrap();
        assert_eq!((list[0].token.as_str(), list[0].channels), ("src-1", 1));

        let outputs = wrapped(
            "<GetAudioOutputsResponse><AudioOutputs token=\"out-1\"/></GetAudioOutputsResponse>",
        );
        let list = parse_list(
            &outputs,
            "GetAudioOutputsResponse",
            "AudioOutputs",
            map_audio_output,
        )
        .unwrap();
        assert_eq!(list[0].token, "out-1");
    }

    #[test]
    fn decodes_audio_encoder_configuration_with_multicast() {
        // The Go TestAudioEncoderListParsesMulticast fixture.
        let doc = wrapped(
            "<GetAudioEncoderConfigurationsResponse>\
             <Configurations token=\"aenc-1\">\
             <Name>mic g711</Name><UseCount>3</UseCount><Encoding>G711</Encoding>\
             <Bitrate>64</Bitrate><SampleRate>8000</SampleRate>\
             <SessionTimeout>PT60S</SessionTimeout>\
             <Multicast><Port>5000</Port><TTL>5</TTL><AutoStart>false</AutoStart></Multicast>\
             </Configurations>\
             </GetAudioEncoderConfigurationsResponse>",
        );
        let configs = parse_list(
            &doc,
            "GetAudioEncoderConfigurationsResponse",
            "Configurations",
            map_audio_encoder_configuration,
        )
        .unwrap();
        let c = &configs[0];
        assert_eq!(
            (
                c.token.as_str(),
                c.encoding.as_str(),
                c.bitrate,
                c.sample_rate
            ),
            ("aenc-1", "G711", 64, 8000)
        );
        let mc = c.multicast.as_ref().unwrap();
        assert_eq!((mc.port, mc.ttl), (5000, 5));
    }

    #[test]
    fn decodes_audio_options_families() {
        let encoder = wrapped(
            "<GetAudioEncoderConfigurationOptionsResponse><Options>\
             <EncodingOptions>G711</EncodingOptions><EncodingOptions>AAC</EncodingOptions>\
             <BitrateList>64</BitrateList><BitrateList>128</BitrateList>\
             <SampleRateList>8000</SampleRateList><SampleRateList>16000</SampleRateList>\
             </Options></GetAudioEncoderConfigurationOptionsResponse>",
        );
        let o = parse_options(
            &encoder,
            "GetAudioEncoderConfigurationOptionsResponse",
            map_audio_encoder_options,
        )
        .unwrap();
        assert_eq!(o.encoding_options, vec!["G711", "AAC"]);
        assert_eq!(o.bitrate_list, vec![64, 128]);
        assert_eq!(o.sample_rate_list, vec![8000, 16000]);

        // Go TestAudioSourceConfigurationOptions fixture.
        let source = wrapped(
            "<GetAudioSourceConfigurationOptionsResponse>\
             <Options><InputTokensAvailable>src-1</InputTokensAvailable><InputTokensAvailable>src-2</InputTokensAvailable></Options>\
             </GetAudioSourceConfigurationOptionsResponse>",
        );
        let o = parse_options(
            &source,
            "GetAudioSourceConfigurationOptionsResponse",
            map_audio_source_options,
        )
        .unwrap();
        assert_eq!(o.input_tokens_available, vec!["src-1", "src-2"]);

        let output = wrapped(
            "<GetAudioOutputConfigurationOptionsResponse>\
             <Options><OutputTokensAvailable>out-1</OutputTokensAvailable></Options>\
             </GetAudioOutputConfigurationOptionsResponse>",
        );
        let o = parse_options(
            &output,
            "GetAudioOutputConfigurationOptionsResponse",
            map_audio_output_options,
        )
        .unwrap();
        assert_eq!(o.output_tokens_available, vec!["out-1"]);

        let decoder = wrapped(
            "<GetAudioDecoderConfigurationOptionsResponse><Options>\
             <AACDecOptions><BitrateList>64</BitrateList><SampleRateList>16000</SampleRateList></AACDecOptions>\
             <G711DecOptions><BitrateList>64</BitrateList></G711DecOptions>\
             <G726DecOptions><BitrateList>32</BitrateList></G726DecOptions>\
             </Options></GetAudioDecoderConfigurationOptionsResponse>",
        );
        let o = parse_options(
            &decoder,
            "GetAudioDecoderConfigurationOptionsResponse",
            map_audio_decoder_options,
        )
        .unwrap();
        assert_eq!(o.aac_dec_options.unwrap().sample_rate_list, vec![16000]);
        let g711 = o.g711_dec_options.unwrap();
        assert_eq!(g711.bitrate_list, vec![64]);
        assert!(g711.sample_rate_list.is_empty());
        assert_eq!(o.g726_dec_options.unwrap().bitrate_list, vec![32]);
    }

    #[test]
    fn decodes_audio_output_and_decoder_configurations() {
        let out = wrapped(
            "<GetAudioOutputConfigurationResponse>\
             <Configuration token=\"aoc-1\"><Name>speaker</Name><UseCount>1</UseCount><OutputToken>out-1</OutputToken></Configuration>\
             </GetAudioOutputConfigurationResponse>",
        );
        let c = parse_configuration(
            &out,
            "GetAudioOutputConfigurationResponse",
            map_audio_output_configuration,
        )
        .unwrap();
        assert_eq!(
            (c.token.as_str(), c.output_token.as_str()),
            ("aoc-1", "out-1")
        );

        let dec = wrapped(
            "<GetAudioDecoderConfigurationResponse>\
             <Configuration token=\"adc-1\"><Name>dec</Name><UseCount>1</UseCount></Configuration>\
             </GetAudioDecoderConfigurationResponse>",
        );
        let c = parse_configuration(
            &dec,
            "GetAudioDecoderConfigurationResponse",
            map_audio_decoder_configuration,
        )
        .unwrap();
        assert_eq!(c.token, "adc-1");
    }

    // --- metadata configurations -----------------------------------------------

    #[test]
    fn decodes_metadata_configuration_single() {
        let doc = wrapped(
            "<GetMetadataConfigurationResponse>\
             <Configuration token=\"mc-1\"><Name>meta</Name><UseCount>2</UseCount>\
             <PTZStatus><Status>true</Status><Position>false</Position></PTZStatus>\
             <Events><Filter/></Events><Analytics>true</Analytics>\
             <Multicast><Port>5000</Port><TTL>5</TTL><AutoStart>false</AutoStart></Multicast>\
             </Configuration></GetMetadataConfigurationResponse>",
        );
        let c = parse_configuration(
            &doc,
            "GetMetadataConfigurationResponse",
            map_metadata_configuration,
        )
        .unwrap();
        assert_eq!(c.token, "mc-1");
        assert_eq!((c.ptz_status.unwrap().status, c.analytics), (true, true));
        assert!(c.events.is_some());
        assert!(c.multicast.is_some());
    }

    #[test]
    fn decodes_metadata_configurations_list_and_options() {
        let list = wrapped(
            "<GetMetadataConfigurationsResponse>\
             <Configurations token=\"mc-1\"><Name>meta</Name><UseCount>1</UseCount><Analytics>true</Analytics></Configurations>\
             <Configurations token=\"mc-2\"><Name>meta2</Name><UseCount>1</UseCount><Analytics>false</Analytics></Configurations>\
             </GetMetadataConfigurationsResponse>",
        );
        let configs = parse_list(
            &list,
            "GetMetadataConfigurationsResponse",
            "Configurations",
            map_metadata_configuration,
        )
        .unwrap();
        assert_eq!(configs.len(), 2);
        assert!(configs[0].analytics);
        assert!(configs[0].ptz_status.is_none());

        let options = wrapped(
            "<GetMetadataConfigurationOptionsResponse>\
             <Options><PTZStatusFilterOptions><Status>true</Status><Position>true</Position></PTZStatusFilterOptions></Options>\
             </GetMetadataConfigurationOptionsResponse>",
        );
        let o = parse_options(
            &options,
            "GetMetadataConfigurationOptionsResponse",
            map_metadata_options,
        )
        .unwrap();
        let f = o.ptz_status_filter_options.unwrap();
        assert!(f.status && f.position);
    }

    // --- OSD --------------------------------------------------------------------

    #[test]
    fn decodes_osd_family() {
        let osds = wrapped(
            "<GetOSDsResponse><OSDs token=\"osd-1\"/><OSDs token=\"osd-2\"/></GetOSDsResponse>",
        );
        let list = parse_list(&osds, "GetOSDsResponse", "OSDs", map_osd).unwrap();
        assert_eq!(
            list.iter().map(|o| o.token.as_str()).collect::<Vec<_>>(),
            vec!["osd-1", "osd-2"]
        );

        let single = wrapped("<GetOSDResponse><OSD token=\"osd-1\"/></GetOSDResponse>");
        let root = parse_xml_tree(&single).unwrap();
        let el = response_el(&root, "GetOSDResponse").unwrap();
        assert_eq!(el.find("OSD").map(map_osd).unwrap().token, "osd-1");

        let options = wrapped(
            "<GetOSDOptionsResponse><Options><MaximumNumberOfOSDs>4</MaximumNumberOfOSDs></Options></GetOSDOptionsResponse>",
        );
        let o = parse_options(&options, "GetOSDOptionsResponse", map_osd_options).unwrap();
        assert_eq!(o.maximum_number_of_osds, 4);
    }

    // --- main/sub selection (Go profile_select_test fixtures) -------------------

    fn profile_with_res(token: &str, name: &str, w: i64, h: i64) -> Profile {
        Profile {
            token: token.into(),
            name: name.into(),
            video_encoder_configuration: Some(VideoEncoderConfiguration {
                resolution: Some(VideoResolution {
                    width: w,
                    height: h,
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn select_main_profile_table() {
        let cases: Vec<(&str, Vec<Profile>, &str)> = vec![
            ("empty", vec![], ""),
            (
                "highest resolution wins",
                vec![
                    profile_with_res("sub_1", "Sub", 640, 480),
                    profile_with_res("main_1", "Main", 2560, 1440),
                ],
                "main_1",
            ),
            (
                "resolution beats list order",
                vec![
                    profile_with_res("first_low", "First", 800, 448),
                    profile_with_res("second_high", "Second", 1920, 1080),
                ],
                "second_high",
            ),
            (
                "tie broken by main hint",
                vec![
                    profile_with_res("profile_2", "Secondary", 1920, 1080),
                    profile_with_res("profile_1_main", "Main", 1920, 1080),
                ],
                "profile_1_main",
            ),
            (
                "no resolution info falls back to first",
                vec![
                    Profile {
                        token: "opaque_a".into(),
                        ..Default::default()
                    },
                    Profile {
                        token: "opaque_b".into(),
                        ..Default::default()
                    },
                ],
                "opaque_a",
            ),
        ];
        for (name, profiles, want) in cases {
            assert_eq!(select_main_profile(&profiles), want, "{name}");
        }
    }

    #[test]
    fn select_sub_profile_table() {
        let cases: Vec<(&str, Vec<Profile>, &str, &str)> = vec![
            ("empty", vec![], "main_1", ""),
            (
                "largest strictly-smaller wins",
                vec![
                    profile_with_res("main_1", "Main", 2560, 1440),
                    profile_with_res("sub_small", "Small", 320, 240),
                    profile_with_res("sub_big", "Big", 704, 576),
                ],
                "main_1",
                "sub_big",
            ),
            (
                "same resolution as main is not a substream",
                vec![
                    profile_with_res("main_1", "Main", 1920, 1080),
                    profile_with_res("alias", "Alias", 1920, 1080),
                ],
                "main_1",
                "",
            ),
            (
                "missing main token yields largest overall",
                vec![
                    profile_with_res("a", "A", 1920, 1080),
                    profile_with_res("b", "B", 640, 360),
                ],
                "nonexistent",
                "a",
            ),
            (
                "no resolution info falls back to first non-main",
                vec![
                    Profile {
                        token: "opaque_main".into(),
                        ..Default::default()
                    },
                    Profile {
                        token: "opaque_other".into(),
                        ..Default::default()
                    },
                ],
                "opaque_main",
                "opaque_other",
            ),
        ];
        for (name, profiles, main_token, want) in cases {
            assert_eq!(select_sub_profile(&profiles, main_token), want, "{name}");
        }
    }

    #[test]
    fn profile_pixels_rejects_unusable_input() {
        assert_eq!(profile_pixels(&Profile::default()), None);
        assert_eq!(profile_pixels(&profile_with_res("x", "x", 0, 100)), None);
        let p = profile_with_res("x", "x", 1920, 1080);
        assert_eq!(profile_pixels(&p), Some(1920 * 1080));
    }

    #[test]
    fn tie_breaks_are_hint_driven() {
        let mainish = profile_with_res("token_main", "Main", 100, 100);
        let subish = profile_with_res("token_sub", "Sub", 100, 100);
        assert!(main_tie_break(&mainish, &subish) < 0);
        assert!(main_tie_break(&subish, &mainish) > 0);
        assert_eq!(main_tie_break(&mainish, &mainish), 0);
        assert!(sub_tie_break(&subish, &mainish) < 0);
        assert!(sub_tie_break(&mainish, &subish) > 0);
    }
}
