//! ONVIF Events service — pull-point subscriptions (WS-BaseNotification).
//!
//! Mirrors onvif-go's `server/events.go` (the golden wire source): with the
//! service enabled the SOAP server routes `{base}/events_service`
//! (GetServiceCapabilities / GetEventProperties / CreatePullPointSubscription)
//! and the per-subscription `{base}/events_service/sub/<id>` subtree
//! (PullMessages / Renew / Unsubscribe) to this module on the listener the
//! server already owns.
//!
//! Notifications use the canonical WS-BaseNotification + ONVIF double-layer
//! shape: outer `wsnt:NotificationMessage` > `wsnt:Topic` +
//! `wsnt:Message` > inner `tt:Message` with PropertyOperation/UtcTime
//! attributes and Source/Key/Data `tt:SimpleItem` groups.
//!
//! ## Host seam
//!
//! [`EventsService::publish_event`] is the host-facing injection point
//! (parity with onvif-go's `Server.PublishEvent`): fan-out to every live
//! subscription, filtered per-subscription by its topic expression, safe
//! no-op with no subscribers, queues lossy at the head.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event as XmlEvent};
use quick_xml::{Reader, Writer};
use tokio::sync::Notify;

use crate::namespaces::{EVENTS_SERVICE, SCHEMAS, WS_ADDRESSING, WS_NOTIFICATION, WS_TOPICS};
use crate::types::{serialize_soap_response, OnvifError};

// ---------------------------------------------------------------------------
// Tuning (parity with onvif-go server/events.go)
// ---------------------------------------------------------------------------

/// Advertised cap on concurrent pull-point subscriptions
/// (GetServiceCapabilities / MaxPullPoints).
pub const DEFAULT_MAX_PULL_POINTS: usize = 10;
/// Termination granted when CreatePullPointSubscription omits
/// InitialTerminationTime (1 h).
pub const DEFAULT_TERMINATION: Duration = Duration::from_secs(60 * 60);
/// Upper clamp for requested and renewed terminations (ONVIF-typical 24 h).
pub const MAX_TERMINATION: Duration = Duration::from_secs(24 * 60 * 60);
/// Server-side clamp on a PullMessages long poll — a hostile Timeout cannot
/// pin connections.
pub const MAX_PULL_WAIT: Duration = Duration::from_secs(60);
/// Per-subscription notification queue bound; queues are lossy at the head
/// (newest wins) like real device notification buffers.
pub const MAX_EVENT_QUEUE: usize = 100;

/// HTTP path of the events service endpoint on the SOAP server's listener
/// (the crate's base path is `/onvif`, parity with onvif-go's BasePath).
pub const EVENTS_SERVICE_PATH: &str = "/onvif/events_service";
/// HTTP path prefix of the per-subscription endpoints returned in
/// SubscriptionReference addresses.
pub const SUBSCRIPTION_PATH_PREFIX: &str = "/onvif/events_service/sub/";

/// Canonical topic-namespace location advertised in GetEventProperties.
const TOPIC_NAMESPACE_LOCATION: &str = "http://www.onvif.org/ver10/tev/topicns.xml";
/// The two mandatory ONVIF topic-expression dialects (both honored — see
/// [`TopicFilter`]).
const DIALECT_CONCRETE: &str = "http://docs.oasis-open.org/wsn/t-1/TopicExpression/Concrete";
const DIALECT_CONCRETE_SET: &str = "http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet";
/// Message-content filtering is not applied — the spec-blessed single empty
/// MessageContentFilterDialect is advertised.
const MESSAGE_SCHEMA_LOCATION: &str = "http://www.onvif.org/ver10/schema/onvif.xsd";

// ---------------------------------------------------------------------------
// Host-facing event types
// ---------------------------------------------------------------------------

/// One `tt:SimpleItem` name/value pair of an event's Source/Key/Data group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleItem {
    pub name: String,
    pub value: String,
}

impl SimpleItem {
    /// Convenience constructor.
    #[must_use]
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

/// One property-event notification handed to the server by the host (the
/// [`EventsService::publish_event`] seam): an AI motion alarm, a tamper
/// switch, a signal-loss detector, … `UtcTime` and the default
/// `PropertyOperation` are stamped at publish time.
#[derive(Debug, Clone, Default)]
pub struct Event {
    /// Topic expression, e.g. `"tns1:VideoSource/MotionAlarm"`.
    pub topic: String,
    /// Property operation; empty defaults to `"Changed"`.
    pub property_operation: String,
    /// Source/Key/Data `SimpleItem` groups of the inner `tt:Message`.
    pub source: Vec<SimpleItem>,
    pub key: Vec<SimpleItem>,
    pub data: Vec<SimpleItem>,
}

impl Event {
    /// An event with just a topic (PropertyOperation defaults to `"Changed"`).
    #[must_use]
    pub fn new(topic: &str) -> Self {
        Self {
            topic: topic.to_string(),
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// ISO 8601 duration parsing
// ---------------------------------------------------------------------------

/// Parse the ISO 8601 duration subset ONVIF uses on the wire (`PnDTnHnMnS`,
/// `PT0S` included). Date-only forms are rejected — a lifetime without a
/// time component is not meaningful for subscription terminations and pull
/// timeouts (parity with onvif-go's `parseISO8601Duration`).
pub(crate) fn parse_iso8601_duration(s: &str) -> Option<Duration> {
    let _ = s;
    None // TODO(red): implement
}

// ---------------------------------------------------------------------------
// Topic-expression filter
// ---------------------------------------------------------------------------

/// One subscription's topic-expression filter: the Concrete dialect (exact
/// local topic path) or the ConcreteSet dialect (`'|'` alternatives with
/// per-segment `'*'` wildcards) — the two dialects GetEventProperties
/// advertises.
#[derive(Debug, Clone)]
struct TopicFilter {
    dialect: String,
    expression: String,
}

impl TopicFilter {
    /// Whether a notification topic satisfies the filter. Prefixes are
    /// namespace bindings, not identity: matching compares the `/`-separated
    /// local path segments (`"tns1:VideoSource/MotionAlarm"` matches
    /// `"VideoSource/MotionAlarm"` and any equivalent binding).
    fn matches(&self, topic: &str) -> bool {
        let _ = topic;
        false // TODO(red): implement
    }
}

/// Split a topic expression into local-name segments, stripping any
/// namespace prefix from each segment.
fn topic_path_segments(expr: &str) -> Vec<String> {
    let _ = expr;
    Vec::new() // TODO(red): implement
}

/// Compare a filter path against a topic path; a `"*"` filter segment
/// matches any single topic segment.
fn match_topic_path(filter: &[String], topic: &[String]) -> bool {
    let _ = (filter, topic);
    false // TODO(red): implement
}

/// Validate the CreatePullPointSubscription filter. An absent filter means
/// every topic is delivered; an empty dialect defaults to Concrete (the
/// WS-BaseNotification default); unsupported dialects and empty expressions
/// are Sender faults instead of being silently ignored.
fn parse_topic_filter(expr: Option<&TopicExpressionRequest>) -> Result<Option<TopicFilter>, OnvifError> {
    let _ = expr;
    Err(OnvifError::Internal("not implemented".into())) // TODO(red): implement
}

// ---------------------------------------------------------------------------
// Subscription registry
// ---------------------------------------------------------------------------

/// One queued event, stamped and buffered for one subscriber.
#[derive(Debug, Clone)]
struct QueuedNotification {
    topic: String,
    message: QueuedMessage,
}

/// The inner `tt:Message` payload (attributes + SimpleItem groups).
#[derive(Debug, Clone)]
struct QueuedMessage {
    property_operation: String,
    utc_time: String,
    source: Vec<SimpleItem>,
    key: Vec<SimpleItem>,
    data: Vec<SimpleItem>,
}

/// One live pull-point subscription.
struct PullPoint {
    /// Termination as unix seconds (second-resolution, like the RFC3339
    /// wire form).
    termination_unix: u64,
    queue: VecDeque<QueuedNotification>,
    /// Cap-1-style wakeup for long-polling PullMessages.
    notify: Arc<Notify>,
    /// `None` → every topic is delivered.
    filter: Option<TopicFilter>,
}

/// Address book for building SubscriptionReference / ProducerReference
/// addresses on the listener the server already owns.
#[derive(Debug, Clone)]
pub(crate) struct ServiceEndpoint {
    /// Local IP that received the client's connection.
    pub host: String,
    /// The listener's actual port (an ephemeral port with `start_on`).
    pub port: u16,
}

impl ServiceEndpoint {
    /// `http://host:port/onvif/events_service/sub/<id>`
    fn subscription_address(&self, id: &str) -> String {
        format!("http://{}:{}{SUBSCRIPTION_PATH_PREFIX}{id}", self.host, self.port)
    }

    /// The producer reference: the advertised device service endpoint.
    fn device_service_address(&self) -> String {
        format!("http://{}:{}/onvif/device_service", self.host, self.port)
    }
}

/// The events pull-point service: the subscription registry plus the host
/// publish seam. Shared between the SOAP server (routing) and the host
/// ([`EventsService::publish_event`]) via `Arc`.
pub struct EventsService {
    subs: Mutex<HashMap<String, PullPoint>>,
}

impl Default for EventsService {
    fn default() -> Self {
        Self::new()
    }
}

impl EventsService {
    /// A fresh service with an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subs: Mutex::new(HashMap::new()),
        }
    }

    /// Fan an event out to every live pull-point subscription (the host
    /// seam, parity with onvif-go's `Server.PublishEvent`). With no
    /// subscribers it is a safe no-op. Queues are lossy at the head: a slow
    /// subscriber beyond [`MAX_EVENT_QUEUE`] pending messages loses the
    /// oldest first.
    pub fn publish_event(&self, ev: Event) {
        let _ = ev;
        // TODO(red): implement
    }

    /// Whether `action` belongs to the events service endpoint.
    #[must_use]
    pub(crate) fn is_service_action(action: &str) -> bool {
        matches!(
            action,
            "GetServiceCapabilities" | "GetEventProperties" | "CreatePullPointSubscription"
        )
    }

    /// Whether `action` belongs to the per-subscription endpoint.
    #[must_use]
    pub(crate) fn is_subscription_action(action: &str) -> bool {
        matches!(action, "PullMessages" | "Renew" | "Unsubscribe")
    }

    /// Auth policy for events actions, mirroring onvif-go's
    /// `DefaultAuthPolicy` (write-style prefixes `Set`/`Remove`/`Create`/
    /// `Go` are protected, reads stay open):
    /// `CreatePullPointSubscription` requires WS-Security credentials;
    /// GetServiceCapabilities/GetEventProperties/PullMessages/Renew/
    /// Unsubscribe stay open.
    #[must_use]
    pub(crate) fn action_requires_auth(action: &str) -> bool {
        ["Set", "Remove", "Create", "Go"].iter().any(|p| action.starts_with(p))
    }

    /// Dispatch a service-endpoint action (router pre-checked membership).
    pub(crate) async fn handle_service_action(
        &self,
        action: &str,
        body: &str,
        endpoint: &ServiceEndpoint,
    ) -> Result<String, OnvifError> {
        match action {
            "GetServiceCapabilities" => Ok(serialize_soap_response(&build_get_service_capabilities())),
            "GetEventProperties" => Ok(serialize_soap_response(&build_get_event_properties())),
            "CreatePullPointSubscription" => self
                .create_subscription(body, endpoint)
                .await
                .map(|fragment| serialize_soap_response(&fragment)),
            _ => Err(OnvifError::ActionNotSupported(format!(
                "unsupported action: {action}"
            ))),
        }
    }

    /// Dispatch a subscription-endpoint action. `path` is the raw request
    /// URL path (the subscription id is addressed by the URL, not the body).
    pub(crate) async fn handle_subscription_action(
        &self,
        path: &str,
        action: &str,
        body: &str,
        endpoint: &ServiceEndpoint,
    ) -> Result<String, OnvifError> {
        match action {
            "PullMessages" => self.pull_messages(path, body, endpoint).await,
            "Renew" => self.renew(path, body).await,
            "Unsubscribe" => self.unsubscribe(path).await,
            _ => Err(OnvifError::ActionNotSupported(format!(
                "unsupported action: {action}"
            ))),
        }
    }

    /// CreatePullPointSubscription: parse the filter and termination time,
    /// mint an opaque subscription id, and answer the SubscriptionReference
    /// address plus the granted termination window.
    async fn create_subscription(
        &self,
        body: &str,
        endpoint: &ServiceEndpoint,
    ) -> Result<String, OnvifError> {
        let _ = (body, endpoint);
        Err(OnvifError::Internal("not implemented".into())) // TODO(red): implement
    }

    /// PullMessages: long-poll the subscription addressed by `path`; answer
    /// as soon as a notification is queued, when the requested Timeout
    /// (clamped to [`MAX_PULL_WAIT`]) elapses, or the client goes away.
    /// `PT0S` is legal — an immediate, non-blocking poll.
    async fn pull_messages(
        &self,
        path: &str,
        body: &str,
        endpoint: &ServiceEndpoint,
    ) -> Result<String, OnvifError> {
        let _ = (path, body, endpoint);
        Err(OnvifError::Internal("not implemented".into())) // TODO(red): implement
    }

    /// Renew: extend the addressed subscription's termination time.
    async fn renew(&self, path: &str, body: &str) -> Result<String, OnvifError> {
        let _ = (path, body);
        Err(OnvifError::Internal("not implemented".into())) // TODO(red): implement
    }

    /// Unsubscribe: remove the addressed subscription.
    async fn unsubscribe(&self, path: &str) -> Result<String, OnvifError> {
        let _ = path;
        Err(OnvifError::Internal("not implemented".into())) // TODO(red): implement
    }
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/// A parsed TopicExpression (Dialect attribute + chardata expression).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct TopicExpressionRequest {
    dialect: String,
    value: String,
}

/// Parsed CreatePullPointSubscription body.
#[derive(Debug, Default)]
struct CreateRequest {
    initial_termination_time: Option<String>,
    topic_expression: Option<TopicExpressionRequest>,
}

/// Parsed PullMessages body. Absent fields keep the zero values the Go twin
/// faults on (MessageLimit 0, empty Timeout).
#[derive(Debug, Default)]
struct PullRequest {
    timeout: String,
    message_limit: i64,
}

/// Parsed Renew body.
#[derive(Debug, Default)]
struct RenewRequest {
    termination_time: String,
}

fn parse_create_request(body: &str) -> Result<CreateRequest, OnvifError> {
    let _ = body;
    Err(OnvifError::Internal("not implemented".into())) // TODO(red): implement
}

fn parse_pull_request(body: &str) -> Result<PullRequest, OnvifError> {
    let _ = body;
    Err(OnvifError::Internal("not implemented".into())) // TODO(red): implement
}

fn parse_renew_request(body: &str) -> Result<RenewRequest, OnvifError> {
    let _ = body;
    Err(OnvifError::Internal("not implemented".into())) // TODO(red): implement
}

/// Extract the opaque subscription id from a per-subscription request path,
/// mirroring onvif-go's `subscriptionIDFromRequest`: the remainder after
/// [`SUBSCRIPTION_PATH_PREFIX`] must be non-empty and slash-free.
fn subscription_id_from_path(path: &str) -> Result<String, OnvifError> {
    let _ = path;
    Err(OnvifError::Internal("not implemented".into())) // TODO(red): implement
}

/// Mint an opaque subscription token (16 random bytes, hex).
fn random_subscription_id() -> String {
    String::new() // TODO(red): implement
}

/// Unix seconds now (the single time base for terminations and stamps).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// RFC3339 UTC, second resolution (parity with Go's
/// `time.Format(time.RFC3339)` on truncated times).
fn rfc3339(unix_secs: u64) -> String {
    let (y, mo, d, h, mi, s) = crate::device::secs_to_utc(unix_secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

// ---------------------------------------------------------------------------
// Response builders (pure — byte-golden test targets)
// ---------------------------------------------------------------------------

fn build_get_service_capabilities() -> String {
    String::new() // TODO(red): implement
}

fn build_get_event_properties() -> String {
    String::new() // TODO(red): implement
}

fn build_create_subscription_response(address: &str, current: u64, termination: u64) -> String {
    let _ = (address, current, termination);
    String::new() // TODO(red): implement
}

fn build_pull_messages_response(
    current: u64,
    termination: u64,
    drained: &[QueuedNotification],
    endpoint: &ServiceEndpoint,
) -> String {
    let _ = (current, termination, drained, endpoint);
    String::new() // TODO(red): implement
}

fn build_renew_response(current: u64, termination: u64) -> String {
    let _ = (current, termination);
    String::new() // TODO(red): implement
}

fn build_unsubscribe_response() -> String {
    String::new() // TODO(red): implement
}

// ---------------------------------------------------------------------------
// Small quick-xml helpers (crate writer style)
// ---------------------------------------------------------------------------

fn write_text(w: &mut Writer<Vec<u8>>, name: &str, text: &str) {
    w.write_event(XmlEvent::Start(BytesStart::new(name)))
        .unwrap_or_default();
    w.write_event(XmlEvent::Text(BytesText::from_escaped(
        crate::types::xml_escape(text),
    )))
    .unwrap_or_default();
    w.write_event(XmlEvent::End(BytesEnd::new(name)))
        .unwrap_or_default();
}

/// Open an element, call `f` to write children, close it.
fn open_close<F>(w: &mut Writer<Vec<u8>>, name: &str, f: F)
where
    F: FnOnce(&mut Writer<Vec<u8>>),
{
    w.write_event(XmlEvent::Start(BytesStart::new(name)))
        .unwrap_or_default();
    f(w);
    w.write_event(XmlEvent::End(BytesEnd::new(name)))
        .unwrap_or_default();
}

/// Local name of a (possibly prefixed) XML element name — matches the
/// namespace-agnostic parsing convention used across the crate.
fn local_name(qname: &[u8]) -> &str {
    let qname = std::str::from_utf8(qname).unwrap_or("");
    qname.rsplit(':').next().unwrap_or(qname)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> ServiceEndpoint {
        ServiceEndpoint {
            host: "192.0.2.10".to_string(),
            port: 8080,
        }
    }

    // 2026-09-19T12:00:00Z / 13:00:00Z (deterministic golden anchors).
    const T0: u64 = 1_789_780_800;
    const T1: u64 = 1_789_784_400;

    // ------------------------------------------------------------------
    // Byte goldens — the wire contract (parity with onvif-go events.go)
    // ------------------------------------------------------------------

    #[test]
    fn golden_get_service_capabilities() {
        assert_eq!(
            build_get_service_capabilities(),
            "<tev:GetServiceCapabilitiesResponse xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\">\n  \
             <tev:Capabilities WSPullPointSupport=\"true\" MaxPullPoints=\"10\"></tev:Capabilities>\n\
             </tev:GetServiceCapabilitiesResponse>"
        );
    }

    #[test]
    fn golden_get_event_properties() {
        assert_eq!(
            build_get_event_properties(),
            "<tev:GetEventPropertiesResponse xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\" xmlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\" xmlns:wstop=\"http://docs.oasis-open.org/wsn/t-1\">\n  \
             <tev:TopicNamespaceLocation>http://www.onvif.org/ver10/tev/topicns.xml</tev:TopicNamespaceLocation>\n  \
             <wsnt:FixedTopicSet>true</wsnt:FixedTopicSet>\n  \
             <wstop:TopicSet></wstop:TopicSet>\n  \
             <wsnt:TopicExpressionDialect>http://docs.oasis-open.org/wsn/t-1/TopicExpression/Concrete</wsnt:TopicExpressionDialect>\n  \
             <wsnt:TopicExpressionDialect>http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet</wsnt:TopicExpressionDialect>\n  \
             <wsnt:MessageContentFilterDialect></wsnt:MessageContentFilterDialect>\n  \
             <tev:MessageContentSchemaLocation>http://www.onvif.org/ver10/schema/onvif.xsd</tev:MessageContentSchemaLocation>\n\
             </tev:GetEventPropertiesResponse>"
        );
    }

    #[test]
    fn golden_create_subscription_response() {
        let address = "http://192.0.2.10:8080/onvif/events_service/sub/0123456789abcdef0123456789abcdef";
        assert_eq!(
            build_create_subscription_response(address, T0, T1),
            "<tev:CreatePullPointSubscriptionResponse xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\" xmlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">\n  \
             <tev:SubscriptionReference>\n    \
             <wsa:Address>http://192.0.2.10:8080/onvif/events_service/sub/0123456789abcdef0123456789abcdef</wsa:Address>\n  \
             </tev:SubscriptionReference>\n  \
             <wsnt:CurrentTime>2026-09-19T12:00:00Z</wsnt:CurrentTime>\n  \
             <wsnt:TerminationTime>2026-09-19T13:00:00Z</wsnt:TerminationTime>\n\
             </tev:CreatePullPointSubscriptionResponse>"
        );
    }

    #[test]
    fn golden_pull_messages_response_with_simple_item_event() {
        let drained = vec![QueuedNotification {
            topic: "tns1:VideoSource/MotionAlarm".to_string(),
            message: QueuedMessage {
                property_operation: "Changed".to_string(),
                utc_time: "2026-09-19T12:00:00Z".to_string(),
                source: vec![SimpleItem::new("Source", "CSI")],
                key: vec![],
                data: vec![SimpleItem::new("State", "true"), SimpleItem::new("Score", "87")],
            },
        }];
        assert_eq!(
            build_pull_messages_response(T0, T1, &drained, &endpoint()),
            "<tev:PullMessagesResponse xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\" xmlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">\n  \
             <tev:CurrentTime>2026-09-19T12:00:00Z</tev:CurrentTime>\n  \
             <tev:TerminationTime>2026-09-19T13:00:00Z</tev:TerminationTime>\n  \
             <wsnt:NotificationMessage>\n    \
             <wsnt:Topic>tns1:VideoSource/MotionAlarm</wsnt:Topic>\n    \
             <wsnt:ProducerReference>\n      \
             <wsa:Address>http://192.0.2.10:8080/onvif/device_service</wsa:Address>\n    \
             </wsnt:ProducerReference>\n    \
             <wsnt:Message>\n      \
             <tt:Message PropertyOperation=\"Changed\" UtcTime=\"2026-09-19T12:00:00Z\">\n        \
             <tt:Source>\n          \
             <tt:SimpleItem Name=\"Source\" Value=\"CSI\"/>\n        \
             </tt:Source>\n        \
             <tt:Key></tt:Key>\n        \
             <tt:Data>\n          \
             <tt:SimpleItem Name=\"State\" Value=\"true\"/>\n          \
             <tt:SimpleItem Name=\"Score\" Value=\"87\"/>\n        \
             </tt:Data>\n      \
             </tt:Message>\n    \
             </wsnt:Message>\n  \
             </wsnt:NotificationMessage>\n\
             </tev:PullMessagesResponse>"
        );
    }

    #[test]
    fn golden_pull_messages_empty() {
        assert_eq!(
            build_pull_messages_response(T0, T1, &[], &endpoint()),
            "<tev:PullMessagesResponse xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\" xmlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\">\n  \
             <tev:CurrentTime>2026-09-19T12:00:00Z</tev:CurrentTime>\n  \
             <tev:TerminationTime>2026-09-19T13:00:00Z</tev:TerminationTime>\n\
             </tev:PullMessagesResponse>"
        );
    }

    #[test]
    fn golden_renew_and_unsubscribe() {
        assert_eq!(
            build_renew_response(T0, T1),
            "<wsnt:RenewResponse xmlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\">\n  \
             <wsnt:CurrentTime>2026-09-19T12:00:00Z</wsnt:CurrentTime>\n  \
             <wsnt:TerminationTime>2026-09-19T13:00:00Z</wsnt:TerminationTime>\n\
             </wsnt:RenewResponse>"
        );
        assert_eq!(
            build_unsubscribe_response(),
            "<wsnt:UnsubscribeResponse xmlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\"/>"
        );
    }

    #[test]
    fn rfc3339_formatting() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(T0), "2026-09-19T12:00:00Z");
        assert_eq!(rfc3339(951_827_696), "2000-02-29T12:34:56Z"); // leap day
    }

    // ------------------------------------------------------------------
    // ISO 8601 durations (grammar ported from onvif-go, table included)
    // ------------------------------------------------------------------

    #[test]
    fn parse_iso8601_duration_table() {
        let cases: &[(&str, Option<u64>)] = &[
            ("PT30S", Some(30)),
            ("PT5M", Some(300)),
            ("PT1M30S", Some(90)),
            ("PT1H", Some(3600)),
            ("PT1H5M10S", Some(3910)),
            ("P1DT2H", Some(93_600)),
            ("PT0S", Some(0)),
            ("", None),
            ("5M", None),
            ("PTxS", None),
            ("PT", None),
            ("P1D", None), // date-only carries no time component
        ];
        for (input, want) in cases {
            let got = parse_iso8601_duration(input);
            assert_eq!(
                got.map(|d| d.as_secs()),
                *want,
                "parse_iso8601_duration({input:?})"
            );
        }
    }

    // ------------------------------------------------------------------
    // Topic filters
    // ------------------------------------------------------------------

    fn concrete(expr: &str) -> TopicFilter {
        TopicFilter {
            dialect: DIALECT_CONCRETE.to_string(),
            expression: expr.to_string(),
        }
    }

    fn concrete_set(expr: &str) -> TopicFilter {
        TopicFilter {
            dialect: DIALECT_CONCRETE_SET.to_string(),
            expression: expr.to_string(),
        }
    }

    #[test]
    fn concrete_filter_matches_exact_local_path_only() {
        let f = concrete("tns1:VideoSource/MotionAlarm");
        assert!(f.matches("tns1:VideoSource/MotionAlarm"));
        assert!(f.matches("VideoSource/MotionAlarm")); // prefix is a binding
        assert!(f.matches("x:VideoSource/MotionAlarm"));
        assert!(!f.matches("tns1:VideoSource/SignalLoss"));
        assert!(!f.matches("tns1:VideoSource"));
        assert!(!f.matches("tns1:Device/HardwareFailure/StorageFailure"));
    }

    #[test]
    fn concrete_set_filter_matches_alternatives_and_wildcards() {
        let f = concrete_set("tns1:Device/*/*|tns1:VideoSource/*");
        assert!(f.matches("tns1:Device/HardwareFailure/StorageFailure"));
        assert!(f.matches("tns1:VideoSource/MotionAlarm"));
        assert!(!f.matches("tns1:VideoAnalytics/LineDetector/Crossed"));
        assert!(!f.matches("tns1:Device/HardwareFailure")); // depth matters
    }

    #[test]
    fn topic_path_segments_strips_prefixes() {
        assert_eq!(
            topic_path_segments("tns1:VideoSource/MotionAlarm"),
            ["VideoSource", "MotionAlarm"]
        );
        assert_eq!(topic_path_segments(" VideoSource "), ["VideoSource"]);
    }

    #[test]
    fn match_topic_path_requires_equal_length() {
        let f: Vec<String> = vec!["a".into(), "*".into()];
        let yes: Vec<String> = vec!["a".into(), "anything".into()];
        let no: Vec<String> = vec!["a".into()];
        let deep: Vec<String> = vec!["a".into(), "x".into(), "y".into()];
        assert!(match_topic_path(&f, &yes));
        assert!(!match_topic_path(&f, &no));
        assert!(!match_topic_path(&f, &deep));
        assert!(!match_topic_path(&[], &[]));
    }

    #[test]
    fn parse_topic_filter_rules() {
        // Absent filter → no filtering.
        assert!(parse_topic_filter(None).unwrap().is_none());

        // Filter without TopicExpression → no filtering.
        let no_expr = parse_topic_filter(None).unwrap();
        assert!(no_expr.is_none());

        // Empty dialect defaults to Concrete.
        let expr = TopicExpressionRequest {
            dialect: String::new(),
            value: "VideoSource/MotionAlarm".into(),
        };
        let f = parse_topic_filter(Some(&expr)).unwrap().unwrap();
        assert_eq!(f.dialect, DIALECT_CONCRETE);

        // Unsupported dialect → Sender fault, never silently ignored.
        let xpath = TopicExpressionRequest {
            dialect: "http://www.w3.org/TR/1999/REC-xpath-19991116".into(),
            value: "tns1:VideoSource".into(),
        };
        match parse_topic_filter(Some(&xpath)) {
            Err(OnvifError::SenderFault(m)) => {
                assert!(m.contains("Unsupported TopicExpression dialect"), "{m}")
            }
            other => panic!("want SenderFault, got {other:?}"),
        }

        // Empty expression → Sender fault.
        let empty = TopicExpressionRequest {
            dialect: DIALECT_CONCRETE.into(),
            value: "  ".into(),
        };
        match parse_topic_filter(Some(&empty)) {
            Err(OnvifError::SenderFault(m)) => {
                assert!(m.contains("Invalid TopicExpression"), "{m}")
            }
            other => panic!("want SenderFault, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Subscription id from path (parity with subscriptionIDFromRequest)
    // ------------------------------------------------------------------

    #[test]
    fn subscription_id_from_path_rules() {
        assert_eq!(
            subscription_id_from_path("/onvif/events_service/sub/abc123").unwrap(),
            "abc123"
        );
        for bad in [
            "/onvif/events_service/sub/",
            "/onvif/events_service/sub/a/b",
            "/onvif/other",
        ] {
            match subscription_id_from_path(bad) {
                Err(OnvifError::SenderFault(m)) => {
                    assert!(m.contains("not a subscription endpoint"), "{m}")
                }
                other => panic!("path {bad:?}: want SenderFault, got {other:?}"),
            }
        }
    }

    #[test]
    fn random_subscription_id_is_opaque_hex() {
        let id = random_subscription_id();
        assert_eq!(id.len(), 32, "16 bytes hex-encoded");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(id, random_subscription_id());
    }

    // ------------------------------------------------------------------
    // Request body parsing
    // ------------------------------------------------------------------

    #[test]
    fn parse_create_request_fields() {
        let body = r#"<CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl">
            <InitialTerminationTime>PT5M</InitialTerminationTime>
            <Filter><wsnt:TopicExpression xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">tns1:Device/*</wsnt:TopicExpression></Filter>
        </CreatePullPointSubscription>"#;
        let req = parse_create_request(body).unwrap();
        assert_eq!(req.initial_termination_time.as_deref(), Some("PT5M"));
        let expr = req.topic_expression.expect("topic expression");
        assert_eq!(expr.dialect, DIALECT_CONCRETE_SET);
        assert_eq!(expr.value, "tns1:Device/*");
    }

    #[test]
    fn parse_create_request_defaults() {
        let req = parse_create_request(
            r#"<CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl"/>"#,
        )
        .unwrap();
        assert!(req.initial_termination_time.is_none());
        assert!(req.topic_expression.is_none());
    }

    #[test]
    fn parse_pull_request_fields() {
        let req = parse_pull_request(
            r#"<PullMessages xmlns="http://www.onvif.org/ver10/events/wsdl"><Timeout>PT2S</Timeout><MessageLimit>5</MessageLimit></PullMessages>"#,
        )
        .unwrap();
        assert_eq!(req.timeout, "PT2S");
        assert_eq!(req.message_limit, 5);
    }

    #[test]
    fn parse_pull_request_zero_defaults() {
        let req = parse_pull_request(
            r#"<PullMessages xmlns="http://www.onvif.org/ver10/events/wsdl"/>"#,
        )
        .unwrap();
        assert_eq!(req.timeout, "");
        assert_eq!(req.message_limit, 0);
    }

    #[test]
    fn parse_renew_request_fields() {
        let req = parse_renew_request(
            r#"<Renew xmlns="http://docs.oasis-open.org/wsn/b-2"><TerminationTime>PT10M</TerminationTime></Renew>"#,
        )
        .unwrap();
        assert_eq!(req.termination_time, "PT10M");
    }

    // ------------------------------------------------------------------
    // Registry semantics (handler level, no HTTP)
    // ------------------------------------------------------------------

    fn tokio_rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
    }

    #[test]
    fn create_pull_point_wire_and_defaults() {
        let rt = tokio_rt();
        rt.block_on(async {
            let svc = EventsService::new();
            let ep = endpoint();

            // Default termination (~1h) when InitialTerminationTime absent.
            let fragment = svc
                .create_subscription(
                    r#"<CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl"/>"#,
                    &ep,
                )
                .await
                .unwrap();
            assert!(fragment.contains(&format!(
                "http://192.0.2.10:8080{SUBSCRIPTION_PATH_PREFIX}"
            )));
            assert!(fragment.contains("CreatePullPointSubscriptionResponse"));

            // Requested PT5M is honored (5-minute window).
            let before = unix_now();
            let fragment = svc
                .create_subscription(
                    r#"<CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl"><InitialTerminationTime>PT5M</InitialTerminationTime></CreatePullPointSubscription>"#,
                    &ep,
                )
                .await
                .unwrap();
            let term = fragment
                .split("<wsnt:TerminationTime>")
                .nth(1)
                .and_then(|rest| rest.split('<').next())
                .unwrap_or_default()
                .to_string();
            let term_secs = parse_rfc3339_to_unix(&term);
            let remaining = term_secs.saturating_sub(before);
            assert!(
                (240..=360).contains(&remaining),
                "PT5M termination remaining {remaining}s"
            );

            // Unparseable InitialTerminationTime → Sender fault.
            match svc
                .create_subscription(
                    r#"<CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl"><InitialTerminationTime>whenever</InitialTerminationTime></CreatePullPointSubscription>"#,
                    &ep,
                )
                .await
            {
                Err(OnvifError::SenderFault(m)) => {
                    assert!(m.contains("Invalid InitialTerminationTime"), "{m}")
                }
                other => panic!("want SenderFault, got {other:?}"),
            }
        });
    }

    /// Parse an RFC3339 second-resolution timestamp back to unix seconds
    /// (test helper — the inverse of `rfc3339` for rough time assertions).
    fn parse_rfc3339_to_unix(ts: &str) -> u64 {
        let bytes = ts.as_bytes();
        if bytes.len() != 20 {
            return 0;
        }
        let num = |from: usize, to: usize| -> u64 {
            ts[from..to].parse::<u64>().unwrap_or(0)
        };
        let (y, mo, d) = (num(0, 4), num(5, 7), num(8, 10));
        let (h, mi, s) = (num(11, 13), num(14, 16), num(17, 19));
        // days-from-civil (Howard Hinnant)
        let y = if mo <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        days as u64 * 86_400 + h * 3600 + mi * 60 + s
    }

    #[test]
    fn pull_messages_drains_published_events_in_order() {
        let rt = tokio_rt();
        rt.block_on(async {
            let svc = EventsService::new();
            let ep = endpoint();
            let sub_path = create(&svc, &ep, "PT10M").await;

            svc.publish_event(Event {
                topic: "tns1:VideoSource/MotionAlarm".into(),
                source: vec![SimpleItem::new("Source", "CSI")],
                data: vec![SimpleItem::new("State", "true")],
                ..Event::new("tns1:VideoSource/MotionAlarm")
            });
            svc.publish_event(Event::new("tns1:VideoSource/SignalLoss"));

            // MessageLimit=1 → only the first event; the rest stay queued.
            let fragment = pull(&svc, &sub_path, "PT0S", 1).await.unwrap();
            assert_eq!(fragment.matches("<wsnt:NotificationMessage>").count(), 1);
            assert!(fragment.contains("MotionAlarm"));

            // Second pull drains the still-queued event.
            let fragment = pull(&svc, &sub_path, "PT0S", 10).await.unwrap();
            assert_eq!(fragment.matches("<wsnt:NotificationMessage>").count(), 1);
            assert!(fragment.contains("SignalLoss"));

            // Third pull is empty.
            let fragment = pull(&svc, &sub_path, "PT0S", 10).await.unwrap();
            assert_eq!(fragment.matches("<wsnt:NotificationMessage>").count(), 0);
        });
    }

    #[test]
    fn pull_messages_validates_request() {
        let rt = tokio_rt();
        rt.block_on(async {
            let svc = EventsService::new();
            let ep = endpoint();
            let sub_path = create(&svc, &ep, "PT10M").await;

            // MessageLimit <= 0 → Sender fault.
            match pull(&svc, &sub_path, "PT0S", 0).await {
                Err(OnvifError::SenderFault(m)) => {
                    assert!(m.contains("Invalid MessageLimit"), "{m}")
                }
                other => panic!("want SenderFault, got {other:?}"),
            }

            // Unparsable Timeout → Sender fault; PT0S is legal.
            match pull(&svc, &sub_path, "soon", 5).await {
                Err(OnvifError::SenderFault(m)) => {
                    assert!(m.contains("Invalid Timeout"), "{m}")
                }
                other => panic!("want SenderFault, got {other:?}"),
            }
            assert!(pull(&svc, &sub_path, "PT0S", 5).await.is_ok());
        });
    }

    #[test]
    fn unknown_and_expired_subscriptions_fault() {
        let rt = tokio_rt();
        rt.block_on(async {
            let svc = EventsService::new();
            let ep = endpoint();

            // Never existed.
            match pull(&svc, "/onvif/events_service/sub/deadbeef", "PT0S", 5).await {
                Err(OnvifError::SenderFault(m)) => {
                    assert!(m.contains("Unknown subscription"), "{m}")
                }
                other => panic!("want SenderFault, got {other:?}"),
            }

            // Expired subscriptions are pruned lazily and fault as unknown.
            let sub_path = create(&svc, &ep, "PT1S").await;
            tokio::time::sleep(Duration::from_millis(1100)).await;
            match pull(&svc, &sub_path, "PT0S", 5).await {
                Err(OnvifError::SenderFault(m)) => {
                    assert!(m.contains("Unknown subscription"), "{m}")
                }
                other => panic!("want SenderFault, got {other:?}"),
            }
        });
    }

    #[test]
    fn renew_and_unsubscribe_semantics() {
        let rt = tokio_rt();
        rt.block_on(async {
            let svc = EventsService::new();
            let ep = endpoint();
            let sub_path = create(&svc, &ep, "PT2M").await;

            let fragment = svc
                .renew(
                    &sub_path,
                    r#"<Renew xmlns="http://docs.oasis-open.org/wsn/b-2"><TerminationTime>PT10M</TerminationTime></Renew>"#,
                )
                .await
                .unwrap();
            assert!(fragment.contains("RenewResponse"));

            // Invalid TerminationTime → Sender fault.
            match svc
                .renew(
                    &sub_path,
                    r#"<Renew xmlns="http://docs.oasis-open.org/wsn/b-2"><TerminationTime>later</TerminationTime></Renew>"#,
                )
                .await
            {
                Err(OnvifError::SenderFault(m)) => {
                    assert!(m.contains("Invalid TerminationTime"), "{m}")
                }
                other => panic!("want SenderFault, got {other:?}"),
            }

            svc.unsubscribe(&sub_path).await.unwrap();
            assert!(matches!(
                pull(&svc, &sub_path, "PT0S", 5).await,
                Err(OnvifError::SenderFault(_))
            ));
        });
    }

    #[test]
    fn publish_fans_out_and_filters_per_subscription() {
        let rt = tokio_rt();
        rt.block_on(async {
            let svc = EventsService::new();
            let ep = endpoint();

            let plain = create(&svc, &ep, "PT10M").await;
            let filtered = create_with_filter(
                &svc,
                &ep,
                DIALECT_CONCRETE,
                "tns1:VideoSource/MotionAlarm",
            )
            .await;

            svc.publish_event(Event::new("tns1:VideoSource/MotionAlarm"));
            svc.publish_event(Event::new("tns1:Device/HardwareFailure"));

            let got = pull(&svc, &plain, "PT0S", 10).await.unwrap();
            assert_eq!(got.matches("<wsnt:NotificationMessage>").count(), 2);
            let got = pull(&svc, &filtered, "PT0S", 10).await.unwrap();
            assert_eq!(got.matches("<wsnt:NotificationMessage>").count(), 1);
            assert!(got.contains("MotionAlarm"));
        });
    }

    #[test]
    fn queue_is_lossy_at_the_head_beyond_the_bound() {
        let rt = tokio_rt();
        rt.block_on(async {
            let svc = EventsService::new();
            let ep = endpoint();
            let sub_path = create(&svc, &ep, "PT10M").await;

            for i in 0..=(MAX_EVENT_QUEUE + 5) {
                svc.publish_event(Event::new(&format!("tns1:Counter/Tick{i}")));
            }

            // The oldest events were dropped; the newest MAX_EVENT_QUEUE stay.
            let fragment = pull(&svc, &sub_path, "PT0S", i64::try_from(MAX_EVENT_QUEUE + 10).unwrap_or(200))
                .await
                .unwrap();
            let count = fragment.matches("<wsnt:NotificationMessage>").count();
            assert_eq!(count, MAX_EVENT_QUEUE);
            // Head of the queue = the event after the dropped ones.
            let first_tick = (MAX_EVENT_QUEUE + 5) - MAX_EVENT_QUEUE + 1;
            let head = fragment
                .split("<wsnt:Topic>")
                .nth(1)
                .and_then(|rest| rest.split('<').next())
                .unwrap_or_default();
            assert_eq!(head, format!("tns1:Counter/Tick{first_tick}"));
        });
    }

    #[test]
    fn long_poll_waits_for_the_timeout_then_answers_empty() {
        let rt = tokio_rt();
        rt.block_on(async {
            let svc = EventsService::new();
            let ep = endpoint();
            let sub_path = create(&svc, &ep, "PT10M").await;

            let started = std::time::Instant::now();
            let fragment = pull(&svc, &sub_path, "PT1S", 5).await.unwrap();
            assert!(started.elapsed() >= Duration::from_millis(900));
            assert_eq!(fragment.matches("<wsnt:NotificationMessage>").count(), 0);
        });
    }

    #[test]
    fn long_poll_wakes_on_publish() {
        let rt = tokio_rt();
        rt.block_on(async {
            let svc = Arc::new(EventsService::new());
            let ep = endpoint();
            let sub_path = create(&svc, &ep, "PT10M").await;

            let svc2 = Arc::clone(&svc);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                svc2.publish_event(Event::new("tns1:VideoSource/MotionAlarm"));
            });

            let started = std::time::Instant::now();
            let fragment = pull(&svc, &sub_path, "PT10S", 5).await.unwrap();
            assert!(started.elapsed() < Duration::from_secs(5));
            assert!(fragment.contains("MotionAlarm"));
        });
    }

    #[test]
    fn max_pull_points_enforced() {
        let rt = tokio_rt();
        rt.block_on(async {
            let svc = EventsService::new();
            let ep = endpoint();
            for _ in 0..DEFAULT_MAX_PULL_POINTS {
                create(&svc, &ep, "PT10M").await;
            }
            match svc
                .create_subscription(
                    r#"<CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl"/>"#,
                    &ep,
                )
                .await
            {
                Err(OnvifError::SenderFault(m)) => {
                    assert!(m.contains("Too many active pull point subscriptions"), "{m}")
                }
                other => panic!("want SenderFault, got {other:?}"),
            }
        });
    }

    #[test]
    fn property_operation_and_utc_time_stamped_at_publish() {
        let rt = tokio_rt();
        rt.block_on(async {
            let svc = EventsService::new();
            let ep = endpoint();
            let sub_path = create(&svc, &ep, "PT10M").await;

            let before = unix_now();
            svc.publish_event(Event {
                property_operation: "Initialized".into(),
                ..Event::new("tns1:Device/Time")
            });
            svc.publish_event(Event::new("tns1:Device/Time")); // → Changed

            let fragment = pull(&svc, &sub_path, "PT0S", 10).await.unwrap();
            assert!(fragment.contains("PropertyOperation=\"Initialized\""));
            assert!(fragment.contains("PropertyOperation=\"Changed\""));
            assert!(fragment.contains("UtcTime=\""));
            let stamped = fragment
                .split("UtcTime=\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_default();
            let stamped_secs = parse_rfc3339_to_unix(stamped);
            assert!(stamped_secs >= before);
        });
    }

    // -- shared test helpers ------------------------------------------------

    async fn create(svc: &EventsService, ep: &ServiceEndpoint, termination: &str) -> String {
        let body = format!(
            r#"<CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl"><InitialTerminationTime>{termination}</InitialTerminationTime></CreatePullPointSubscription>"#
        );
        let fragment = svc.create_subscription(&body, ep).await.unwrap();
        let address = fragment
            .split("<wsa:Address>")
            .nth(1)
            .and_then(|rest| rest.split('<').next())
            .unwrap_or_default();
        format!("{SUBSCRIPTION_PATH_PREFIX}{}", address.rsplit('/').next().unwrap_or(""))
    }

    async fn create_with_filter(
        svc: &EventsService,
        ep: &ServiceEndpoint,
        dialect: &str,
        expression: &str,
    ) -> String {
        let body = format!(
            r#"<CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl"><Filter><wsnt:TopicExpression xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" Dialect="{dialect}">{expression}</wsnt:TopicExpression></Filter><InitialTerminationTime>PT10M</InitialTerminationTime></CreatePullPointSubscription>"#
        );
        let fragment = svc.create_subscription(&body, ep).await.unwrap();
        let address = fragment
            .split("<wsa:Address>")
            .nth(1)
            .and_then(|rest| rest.split('<').next())
            .unwrap_or_default();
        format!("{SUBSCRIPTION_PATH_PREFIX}{}", address.rsplit('/').next().unwrap_or(""))
    }

    async fn pull(
        svc: &EventsService,
        sub_path: &str,
        timeout: &str,
        limit: i64,
    ) -> Result<String, OnvifError> {
        svc.pull_messages(
            sub_path,
            &format!(
                r#"<PullMessages xmlns="http://www.onvif.org/ver10/events/wsdl"><Timeout>{timeout}</Timeout><MessageLimit>{limit}</MessageLimit></PullMessages>"#
            ),
            &endpoint(),
        )
        .await
    }
}
