//! ONVIF events service — the pull-point client half (the twin of the Go
//! library's `events` package, pull-point flavor): service capabilities,
//! event properties with the topic-set tree decoded, subscription creation,
//! and the subscription-addressed operations PullMessages / Renew /
//! Unsubscribe / Seek / SetSynchronizationPoint plus the event-broker CRUD.
//!
//! PullMessages and the other subscription operations post to the
//! subscription reference address returned by
//! [`SoapClient::create_pull_point_subscription`] — a per-subscription
//! endpoint, not the events service itself (the same address split the
//! push twin in `crate::client::push` enforces for its manager). Message
//! decoding reuses `crate::client::notify`'s types and parser — one parser,
//! both transports: the response's `NotificationMessage` fragments are
//! re-mounted under a synthetic `Notify` root and run through
//! [`notify::parse_notify_events`], so the two-layer `Message` semantics
//! (inner `tt:Message` wins over lax outer attributes) stay identical
//! across pull and push.
//!
//! Deliberately NOT ported from the Go package: the managed polling loop
//! (`SubscribeEvents`/`EventStream` — host-side orchestration around these
//! primitives) and the push family (`crate::client::push` owns it).
//!
//! Long-pull note: `PullMessages` blocks on the device for up to its
//! `timeout`; the whole HTTP exchange is bounded by the client's configured
//! timeout ([`SoapClient::with_timeout`], default 30 s) — raise it when
//! pulling with a longer long-poll timeout.

use std::time::Duration;

use super::notify;
use super::push::WSNT_NS;
use super::{
    format_xs_duration, local_name, parse_xsd_datetime, text_content, ClientError, SoapClient,
    UtcStamp,
};

/// tev (events service) namespace.
const TEV_NS: &str = "http://www.onvif.org/ver10/events/wsdl";

/// The capabilities of a device's event service (the twin of the Go
/// `events.EventServiceCapabilities`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventServiceCapabilities {
    /// WS-SubscriptionPolicy support.
    pub ws_subscription_policy_support: bool,
    /// WS-PausableSubscriptionManagerInterface support.
    pub ws_pausable_subscription_manager_interface_support: bool,
    /// Maximum notification producers; 0 when unreported.
    pub max_notification_producers: i32,
    /// Maximum concurrent pull points; 0 when unreported.
    pub max_pull_points: i32,
    /// Persistent notification storage.
    pub persistent_notification_storage: bool,
    /// Supported event-broker protocols (space-separated attribute split).
    pub event_broker_protocols: Vec<String>,
    /// Maximum event brokers; 0 when unreported.
    pub max_event_brokers: i32,
    /// Event metadata carried over the MQTT transport.
    pub metadata_over_mqtt: bool,
}

/// A created pull-point subscription: the address every subsequent
/// operation must be posted to, plus the device's granted window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullPointSubscription {
    /// The subscription's own endpoint — pass this to
    /// [`SoapClient::pull_messages`] and friends.
    pub subscription_reference: String,
    /// Device-reported current time, when present.
    pub current_time: Option<UtcStamp>,
    /// Granted termination time, when the device reported one.
    pub termination_time: Option<UtcStamp>,
}

/// The granted window of a successful Renew on a subscription (the twin of
/// the Go `RenewSubscription`'s two return times; absent fields are `None`
/// where Go leaves a zero `time.Time`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullRenewal {
    /// Device-reported current time, when present.
    pub current_time: Option<UtcStamp>,
    /// The newly granted termination time, when the device reported one.
    pub termination_time: Option<UtcStamp>,
}

/// One node of a device's topic set: element name, optional description,
/// nested topics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Topic {
    /// Topic path segment (the wire element's local name).
    pub name: String,
    /// Human-readable description, when the device carries one in a
    /// `Description` child element.
    pub description: String,
    /// Nested topics.
    pub children: Vec<Topic>,
}

/// The topic tree a device advertises in GetEventProperties.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TopicSet {
    /// Top-level topic nodes.
    pub topics: Vec<Topic>,
}

/// The event properties of a device (the twin of the Go
/// `events.EventProperties` — including the `TopicSet` tree this port
/// decodes, where the Go twin defines the type but never fills it).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventProperties {
    /// Topic namespace locations.
    pub topic_namespace_location: Vec<String>,
    /// Whether the topic set is fixed.
    pub fixed_topic_set: bool,
    /// The advertised topic tree.
    pub topic_set: TopicSet,
    /// Supported topic expression dialects.
    pub topic_expression_dialects: Vec<String>,
    /// Supported message content filter dialects.
    pub message_content_filter_dialects: Vec<String>,
    /// Supported producer properties filter dialects.
    pub producer_properties_filter_dialects: Vec<String>,
    /// Message content schema locations.
    pub message_content_schema_location: Vec<String>,
}

/// An event broker configuration (MQTT etc.) — the create payload of
/// [`SoapClient::add_event_broker`] and the decoded row of
/// [`SoapClient::get_event_brokers`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventBrokerConfig {
    /// Broker address (e.g. `mqtt://broker.example.org`); required on add.
    pub address: String,
    /// Topic prefix the device publishes under.
    pub topic_prefix: String,
    /// Broker user name.
    pub user_name: String,
    /// Broker password.
    pub password: String,
    /// ID of the certificate to authenticate with.
    pub certificate_id: String,
    /// Topic filter for published events.
    pub publish_filter: String,
    /// MQTT QoS level.
    pub qos: i32,
    /// Connection status (decode only: `Connected`, …).
    pub status: String,
    /// Whether certificate path validation is enforced.
    pub cert_path_validation: bool,
    /// Filter for event metadata published to the broker.
    pub metadata_filter: String,
}

impl SoapClient {
    /// Read the event service capabilities (GetServiceCapabilities). Posted
    /// to the client's configured device endpoint — the Rust client keeps a
    /// single endpoint where the Go twin resolves a discovered events
    /// service address.
    pub async fn get_event_service_capabilities(
        &self,
    ) -> Result<EventServiceCapabilities, ClientError> {
        let body = tev_action("tev:GetServiceCapabilities");
        let resp = self.device_call(&body).await?;
        parse_capabilities_response(&resp)
    }

    /// Read the event properties (GetEventProperties): dialects plus the
    /// device's topic-set tree, decoded into [`TopicSet`] nodes (element
    /// local names as topic segments; a `Description` child element becomes
    /// the node's description instead of a child node).
    pub async fn get_event_properties(&self) -> Result<EventProperties, ClientError> {
        let body = tev_action("tev:GetEventProperties");
        let resp = self.device_call(&body).await?;
        parse_properties_response(&resp)
    }

    /// Create a pull-point subscription (CreatePullPointSubscription).
    /// `filter` is an optional topic expression, `initial_termination_time`
    /// an optional requested lifetime (must be positive when given),
    /// `subscription_policy` optional verbatim policy content. The returned
    /// [`PullPointSubscription::subscription_reference`] is the address
    /// every subsequent operation on this subscription posts to.
    pub async fn create_pull_point_subscription(
        &self,
        filter: &str,
        initial_termination_time: Option<Duration>,
        subscription_policy: &str,
    ) -> Result<PullPointSubscription, ClientError> {
        if initial_termination_time.is_some_and(|t| t.is_zero()) {
            return Err(ClientError::InvalidArgument(
                "invalid termination time".into(),
            ));
        }
        let body = build_create_pull_point_subscription_request(
            filter,
            initial_termination_time,
            subscription_policy,
        );
        let resp = self.device_call(&body).await?;
        parse_create_subscription_response(&resp)
    }

    /// Long-poll the subscription for messages (PullMessages), posting to
    /// the subscription reference address. Blocks on the device for up to
    /// `timeout`; at most `message_limit` messages are returned. Decoding
    /// reuses [`notify::NotificationMessage`] through the same parser as
    /// the push path — an empty response is an empty vector, not an error.
    pub async fn pull_messages(
        &self,
        subscription_reference: &str,
        timeout: Duration,
        message_limit: u32,
    ) -> Result<Vec<notify::NotificationMessage>, ClientError> {
        if subscription_reference.is_empty() {
            return Err(ClientError::InvalidArgument(
                "invalid subscription reference".into(),
            ));
        }
        if timeout.is_zero() {
            return Err(ClientError::InvalidArgument(
                "invalid timeout: must be positive".into(),
            ));
        }
        if message_limit == 0 {
            return Err(ClientError::InvalidArgument(
                "invalid message limit: must be positive".into(),
            ));
        }

        let body = format!(
            "<tev:PullMessages xmlns:tev=\"{TEV_NS}\">\
             <tev:Timeout>{}</tev:Timeout><tev:MessageLimit>{message_limit}</tev:MessageLimit>\
             </tev:PullMessages>",
            format_xs_duration(timeout)
        );
        let resp = self.soap_call(subscription_reference, &body).await?;
        parse_pull_messages_response(&resp)
    }

    /// Extend the subscription by a new requested lifetime (wsnt:Renew),
    /// posted to the subscription reference address; returns the device's
    /// reported times.
    pub async fn renew_subscription(
        &self,
        subscription_reference: &str,
        termination_time: Duration,
    ) -> Result<PullRenewal, ClientError> {
        if subscription_reference.is_empty() {
            return Err(ClientError::InvalidArgument(
                "invalid subscription reference".into(),
            ));
        }
        if termination_time.is_zero() {
            return Err(ClientError::InvalidArgument(
                "invalid termination time".into(),
            ));
        }

        let body = format!(
            "<wsnt:Renew xmlns:wsnt=\"{WSNT_NS}\">\
             <wsnt:TerminationTime>{}</wsnt:TerminationTime></wsnt:Renew>",
            format_xs_duration(termination_time)
        );
        let resp = self.soap_call(subscription_reference, &body).await?;
        parse_renewal_response(&resp)
    }

    /// Terminate the subscription (wsnt:Unsubscribe), posted to the
    /// subscription reference address. Best-effort semantics stay with the
    /// caller: the device reclaims the subscription at its TTL regardless.
    pub async fn unsubscribe(&self, subscription_reference: &str) -> Result<(), ClientError> {
        if subscription_reference.is_empty() {
            return Err(ClientError::InvalidArgument(
                "invalid subscription reference".into(),
            ));
        }
        let body = format!("<wsnt:Unsubscribe xmlns:wsnt=\"{WSNT_NS}\"></wsnt:Unsubscribe>");
        self.soap_call(subscription_reference, &body).await?;
        Ok(())
    }

    /// Replay-position the subscription's event stream (Seek), posted to
    /// the subscription reference address. `utc_time` is sent as RFC 3339;
    /// `reverse` requests backwards replay from that instant.
    pub async fn seek(
        &self,
        subscription_reference: &str,
        utc_time: UtcStamp,
        reverse: bool,
    ) -> Result<(), ClientError> {
        if subscription_reference.is_empty() {
            return Err(ClientError::InvalidArgument(
                "invalid subscription reference".into(),
            ));
        }
        let body = build_seek_request(utc_time, reverse);
        self.soap_call(subscription_reference, &body).await?;
        Ok(())
    }

    /// Ask the device to re-send the current property states to this
    /// subscription (SetSynchronizationPoint), posted to the subscription
    /// reference address.
    pub async fn set_event_synchronization_point(
        &self,
        subscription_reference: &str,
    ) -> Result<(), ClientError> {
        if subscription_reference.is_empty() {
            return Err(ClientError::InvalidArgument(
                "invalid subscription reference".into(),
            ));
        }
        let body = tev_action("tev:SetSynchronizationPoint");
        self.soap_call(subscription_reference, &body).await?;
        Ok(())
    }

    /// Register an event broker configuration (AddEventBroker). The address
    /// must be non-empty.
    pub async fn add_event_broker(&self, config: &EventBrokerConfig) -> Result<(), ClientError> {
        if config.address.is_empty() {
            return Err(ClientError::InvalidArgument(
                "invalid event broker address: cannot be empty".into(),
            ));
        }
        let body = build_add_event_broker_request(config);
        self.device_call(&body).await?;
        Ok(())
    }

    /// Remove the event broker configuration for `address`
    /// (DeleteEventBroker).
    pub async fn delete_event_broker(&self, address: &str) -> Result<(), ClientError> {
        if address.is_empty() {
            return Err(ClientError::InvalidArgument(
                "invalid event broker address: cannot be empty".into(),
            ));
        }
        let body = format!(
            "<tev:DeleteEventBroker xmlns:tev=\"{TEV_NS}\">\
             <tev:Address>{}</tev:Address></tev:DeleteEventBroker>",
            crate::types::xml_escape(address)
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// List the device's event broker configurations (GetEventBrokers).
    pub async fn get_event_brokers(&self) -> Result<Vec<EventBrokerConfig>, ClientError> {
        let body = tev_action("tev:GetEventBrokers");
        let resp = self.device_call(&body).await?;
        parse_event_brokers_response(&resp)
    }
}

/// A bare `tev:` action element (the Go twin's no-argument requests).
fn tev_action(action: &str) -> String {
    format!("<{action} xmlns:tev=\"{TEV_NS}\"></{action}>")
}

/// CreatePullPointSubscription body — byte-compatible with the Go marshal
/// (attribute order tev/wsnt, child order Filter / InitialTerminationTime /
/// SubscriptionPolicy, omitempty semantics).
fn build_create_pull_point_subscription_request(
    filter: &str,
    initial_termination_time: Option<Duration>,
    subscription_policy: &str,
) -> String {
    let mut inner = String::new();
    if !filter.is_empty() {
        inner.push_str(&format!(
            "<tev:Filter><wsnt:TopicExpression>{}</wsnt:TopicExpression></tev:Filter>",
            crate::types::xml_escape(filter)
        ));
    }
    if let Some(t) = initial_termination_time {
        inner.push_str(&format!(
            "<tev:InitialTerminationTime>{}</tev:InitialTerminationTime>",
            format_xs_duration(t)
        ));
    }
    if !subscription_policy.is_empty() {
        inner.push_str(&format!(
            "<tev:SubscriptionPolicy>{}</tev:SubscriptionPolicy>",
            crate::types::xml_escape(subscription_policy)
        ));
    }
    format!(
        "<tev:CreatePullPointSubscription xmlns:tev=\"{TEV_NS}\" xmlns:wsnt=\"{WSNT_NS}\">{inner}\
         </tev:CreatePullPointSubscription>"
    )
}

/// Seek body — `tev:Reverse` only present when set (the Go `omitempty`).
fn build_seek_request(utc_time: UtcStamp, reverse: bool) -> String {
    let reverse_elem = if reverse {
        "<tev:Reverse>true</tev:Reverse>"
    } else {
        ""
    };
    format!(
        "<tev:Seek xmlns:tev=\"{TEV_NS}\">\
         <tev:UtcTime>{}</tev:UtcTime>{reverse_elem}</tev:Seek>",
        utc_time.to_rfc3339()
    )
}

/// AddEventBroker body — child order and omitempty semantics mirror the Go
/// marshal.
fn build_add_event_broker_request(config: &EventBrokerConfig) -> String {
    let esc = crate::types::xml_escape;
    let mut inner = format!("<tev:Address>{}</tev:Address>", esc(&config.address));
    if !config.topic_prefix.is_empty() {
        inner.push_str(&format!(
            "<tev:TopicPrefix>{}</tev:TopicPrefix>",
            esc(&config.topic_prefix)
        ));
    }
    if !config.user_name.is_empty() {
        inner.push_str(&format!(
            "<tev:UserName>{}</tev:UserName>",
            esc(&config.user_name)
        ));
    }
    if !config.password.is_empty() {
        inner.push_str(&format!(
            "<tev:Password>{}</tev:Password>",
            esc(&config.password)
        ));
    }
    if !config.certificate_id.is_empty() {
        inner.push_str(&format!(
            "<tev:CertificateID>{}</tev:CertificateID>",
            esc(&config.certificate_id)
        ));
    }
    if !config.publish_filter.is_empty() {
        inner.push_str(&format!(
            "<tev:PublishFilter>{}</tev:PublishFilter>",
            esc(&config.publish_filter)
        ));
    }
    if config.qos != 0 {
        inner.push_str(&format!("<tev:QoS>{}</tev:QoS>", config.qos));
    }
    if config.cert_path_validation {
        inner.push_str("<tev:CertPathValidation>true</tev:CertPathValidation>");
    }
    if !config.metadata_filter.is_empty() {
        inner.push_str(&format!(
            "<tev:MetadataFilter>{}</tev:MetadataFilter>",
            esc(&config.metadata_filter)
        ));
    }
    format!(
        "<tev:AddEventBroker xmlns:tev=\"{TEV_NS}\">\
         <tev:EventBrokerConfig>{inner}</tev:EventBrokerConfig></tev:AddEventBroker>"
    )
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Attribute value by local name (namespace-prefix tolerant).
fn attr(e: &quick_xml::events::BytesStart<'_>, name: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| {
            let key = String::from_utf8_lossy(a.key.as_ref());
            match key.rsplit_once(':') {
                Some((_, local)) => local == name,
                None => key == name,
            }
        })
        .map(|a| String::from_utf8_lossy(&a.value).into_owned())
}

/// Boolean attribute (`true`/`1` true, anything else false — the Go
/// `encoding/xml` bool convention).
fn attr_bool(e: &quick_xml::events::BytesStart<'_>, name: &str) -> bool {
    matches!(attr(e, name).as_deref(), Some("true" | "1"))
}

/// Integer attribute, 0 when absent or garbage (lenient like the Go twin's
/// zero-value decode).
fn attr_i32(e: &quick_xml::events::BytesStart<'_>, name: &str) -> i32 {
    attr(e, name)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// Lift the Capabilities element of a GetServiceCapabilitiesResponse. A
/// missing element decodes as the zero value, matching the Go twin.
fn parse_capabilities_response(resp: &str) -> Result<EventServiceCapabilities, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut caps = EventServiceCapabilities::default();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) | Ok(XmlEvent::Empty(e)) => {
                if local_name(&e) == "Capabilities" {
                    caps.ws_subscription_policy_support =
                        attr_bool(&e, "WSSubscriptionPolicySupport");
                    caps.ws_pausable_subscription_manager_interface_support =
                        attr_bool(&e, "WSPausableSubscriptionManagerInterfaceSupport");
                    caps.max_notification_producers = attr_i32(&e, "MaxNotificationProducers");
                    caps.max_pull_points = attr_i32(&e, "MaxPullPoints");
                    caps.persistent_notification_storage =
                        attr_bool(&e, "PersistentNotificationStorage");
                    caps.max_event_brokers = attr_i32(&e, "MaxEventBrokers");
                    caps.metadata_over_mqtt = attr_bool(&e, "MetadataOverMQTT");
                    if let Some(protocols) = attr(&e, "EventBrokerProtocols") {
                        caps.event_broker_protocols =
                            protocols.split_whitespace().map(str::to_string).collect();
                    }
                }
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse GetServiceCapabilitiesResponse: {e}"
                )))
            }
        }
        buf.clear();
    }
    Ok(caps)
}

/// Lift a CreatePullPointSubscriptionResponse: SubscriptionReference /
/// CurrentTime / TerminationTime (local-name tolerant). A missing
/// subscription reference is an error — every subsequent operation needs
/// it (the push twin's subscribe parser enforces the same).
fn parse_create_subscription_response(resp: &str) -> Result<PullPointSubscription, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    let mut sub_ref = String::new();
    let mut current = String::new();
    let mut termination = String::new();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                stack.push(local_name(&e));
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                let parent = stack.last().map(String::as_str).unwrap_or("");
                let grandparent = stack.iter().rev().nth(1).map(String::as_str).unwrap_or("");
                match (grandparent, parent) {
                    ("SubscriptionReference", "Address") if sub_ref.is_empty() => {
                        sub_ref = text.trim().to_string();
                    }
                    (_, "CurrentTime") => current = text,
                    (_, "TerminationTime") => termination = text,
                    _ => {}
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse CreatePullPointSubscriptionResponse: {e}"
                )))
            }
        }
        buf.clear();
    }

    if sub_ref.is_empty() {
        return Err(ClientError::Parse(
            "parse CreatePullPointSubscriptionResponse: no SubscriptionReference address".into(),
        ));
    }

    Ok(PullPointSubscription {
        subscription_reference: sub_ref,
        current_time: parse_xsd_datetime(&current).map(|unix| UtcStamp { unix }),
        termination_time: parse_xsd_datetime(&termination).map(|unix| UtcStamp { unix }),
    })
}

/// Lift a PullMessagesResponse into parsed notification messages. The
/// `NotificationMessage` fragments are re-mounted under a synthetic
/// `Notify` root and decoded by [`notify::parse_notify_events`] — the same
/// two-layer Message parser the push path uses. An empty response decodes
/// to an empty vector (parity with the Go twin returning an empty slice).
fn parse_pull_messages_response(
    resp: &str,
) -> Result<Vec<notify::NotificationMessage>, ClientError> {
    let fragments = extract_elements_by_name(resp, "NotificationMessage")?;
    if fragments.is_empty() {
        return Ok(Vec::new());
    }
    let doc = format!("<Notify>{}</Notify>", fragments.concat());
    notify::parse_notify_events(&doc)
}

/// Lift the times of a RenewResponse (either may be absent — the Go twin
/// returns zero `time.Time`s there; this port makes absence explicit).
fn parse_renewal_response(resp: &str) -> Result<PullRenewal, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    let mut current = String::new();
    let mut termination = String::new();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                stack.push(local_name(&e));
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                match stack.last().map(String::as_str) {
                    Some("CurrentTime") => current = text,
                    Some("TerminationTime") => termination = text,
                    _ => {}
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(ClientError::Parse(format!("parse RenewResponse: {e}"))),
        }
        buf.clear();
    }

    Ok(PullRenewal {
        current_time: parse_xsd_datetime(&current).map(|unix| UtcStamp { unix }),
        termination_time: parse_xsd_datetime(&termination).map(|unix| UtcStamp { unix }),
    })
}

/// Lift a GetEventPropertiesResponse: the repeated dialect/location
/// elements plus the `TopicSet` tree (every child element under TopicSet is
/// a topic node named by its local name; a `Description` child element
/// contributes its text to the parent node's description instead of
/// becoming a node).
fn parse_properties_response(resp: &str) -> Result<EventProperties, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut props = EventProperties::default();

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    // TopicSet build state.
    let mut in_topic_set = false;
    let mut topic_stack: Vec<Topic> = Vec::new();
    let mut capturing_description = false;

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                if name == "TopicSet" && !in_topic_set {
                    in_topic_set = true;
                } else if in_topic_set {
                    if name == "Description" && !topic_stack.is_empty() {
                        capturing_description = true;
                    } else {
                        topic_stack.push(Topic {
                            name: name.clone(),
                            description: String::new(),
                            children: Vec::new(),
                        });
                    }
                }
                stack.push(name);
            }
            Ok(XmlEvent::Empty(e)) => {
                let name = local_name(&e);
                if in_topic_set && name != "Description" {
                    let node = Topic {
                        name,
                        description: String::new(),
                        children: Vec::new(),
                    };
                    attach_topic(node, &mut topic_stack, &mut props.topic_set);
                }
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                if in_topic_set {
                    if capturing_description {
                        if let Some(topic) = topic_stack.last_mut() {
                            topic.description = text;
                        }
                    }
                } else {
                    match stack.last().map(String::as_str) {
                        Some("TopicNamespaceLocation") => {
                            props.topic_namespace_location.push(text);
                        }
                        Some("FixedTopicSet") => {
                            props.fixed_topic_set = text == "true" || text == "1";
                        }
                        Some("TopicExpressionDialect") => {
                            props.topic_expression_dialects.push(text);
                        }
                        Some("MessageContentFilterDialect") => {
                            props.message_content_filter_dialects.push(text);
                        }
                        Some("ProducerPropertiesFilterDialect") => {
                            props.producer_properties_filter_dialects.push(text);
                        }
                        Some("MessageContentSchemaLocation") => {
                            props.message_content_schema_location.push(text);
                        }
                        _ => {}
                    }
                }
            }
            Ok(XmlEvent::End(_)) => {
                let name = stack.pop().unwrap_or_default();
                if in_topic_set {
                    if name == "Description" && capturing_description {
                        capturing_description = false;
                    } else if name == "TopicSet" && topic_stack.is_empty() {
                        in_topic_set = false;
                    } else if let Some(done) = topic_stack.pop() {
                        attach_topic(done, &mut topic_stack, &mut props.topic_set);
                    }
                }
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse GetEventPropertiesResponse: {e}"
                )))
            }
        }
        buf.clear();
    }

    Ok(props)
}

/// Attach a finished topic node to its parent (or the root set when the
/// parent stack is empty).
fn attach_topic(node: Topic, stack: &mut [Topic], root: &mut TopicSet) {
    match stack.last_mut() {
        Some(parent) => parent.children.push(node),
        None => root.topics.push(node),
    }
}

/// Lift the EventBroker rows of a GetEventBrokersResponse.
fn parse_event_brokers_response(resp: &str) -> Result<Vec<EventBrokerConfig>, ClientError> {
    let fragments = extract_elements_by_name(resp, "EventBroker")?;
    fragments
        .iter()
        .map(|f| parse_event_broker_fragment(f))
        .collect()
}

/// Decode one EventBroker element.
fn parse_event_broker_fragment(fragment: &str) -> Result<EventBrokerConfig, ClientError> {
    let mut reader = quick_xml::Reader::from_str(fragment);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    let mut broker = EventBrokerConfig::default();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                stack.push(local_name(&e));
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                match stack.last().map(String::as_str) {
                    Some("Address") => broker.address = text,
                    Some("TopicPrefix") => broker.topic_prefix = text,
                    Some("UserName") => broker.user_name = text,
                    Some("Password") => broker.password = text,
                    Some("CertificateID") => broker.certificate_id = text,
                    Some("PublishFilter") => broker.publish_filter = text,
                    Some("QoS") => broker.qos = text.trim().parse().unwrap_or(0),
                    Some("Status") => broker.status = text,
                    Some("CertPathValidation") => {
                        broker.cert_path_validation = text == "true" || text == "1";
                    }
                    Some("MetadataFilter") => broker.metadata_filter = text,
                    _ => {}
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(ClientError::Parse(format!("parse EventBroker: {e}"))),
        }
        buf.clear();
    }
    Ok(broker)
}

/// Extract the raw XML of every element with local name `name` (any depth,
/// both paired and self-closing forms). Shared with the deviceio module
/// for its repeated entity rows.
pub(crate) fn extract_elements_by_name(body: &str, name: &str) -> Result<Vec<String>, ClientError> {
    let mut reader = quick_xml::Reader::from_str(body);
    reader.config_mut().trim_text(false);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut fragments = Vec::new();

    let mut start: Option<usize> = None;
    let mut depth_of_start = 0usize;

    loop {
        use quick_xml::events::Event as XmlEvent;
        let pos_before = reader.buffer_position() as usize;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let local = local_name(&e);
                if local == name && start.is_none() {
                    start = Some(pos_before);
                    depth_of_start = stack.len();
                }
                stack.push(local);
            }
            Ok(XmlEvent::Empty(e)) => {
                if local_name(&e) == name && start.is_none() {
                    let end = reader.buffer_position() as usize;
                    fragments.push(body[pos_before..end].to_string());
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
                if let Some(s) = start {
                    if stack.len() == depth_of_start {
                        let end = reader.buffer_position() as usize;
                        fragments.push(body[s..end].to_string());
                        start = None;
                    }
                }
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(ClientError::Parse(format!("extract <{name}>: {e}"))),
        }
        buf.clear();
    }

    Ok(fragments)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- fixtures lifted from the Go twin's event_test.go / event_brokers_test.go ---

    const CAPABILITIES_RESP: &str = r#"<GetServiceCapabilitiesResponse>
	<Capabilities WSSubscriptionPolicySupport="true" MaxPullPoints="8" MaxNotificationProducers="16"
		PersistentStorage="true" EventBrokerProtocols="mqtt mqtts" MetadataOverMQTT="false"/>
</GetServiceCapabilitiesResponse>"#;

    const CREATE_SUB_RESP: &str = r#"<CreatePullPointSubscriptionResponse>
	<SubscriptionReference><Address>http://fake/sub/1</Address></SubscriptionReference>
	<CurrentTime>2026-08-28T10:00:00Z</CurrentTime>
	<TerminationTime>2026-08-28T11:00:00Z</TerminationTime>
</CreatePullPointSubscriptionResponse>"#;

    const PULL_ONE: &str = r#"<PullMessagesResponse>
	<NotificationMessage>
		<Topic xmlns:tns1="http://www.onvif.org/ver10/topics">tns1:VideoSource/MotionAlarm</Topic>
		<ProducerReference><Address>urn:uuid:producer-1</Address></ProducerReference>
		<Message UtcTime="2026-08-28T10:00:01Z" PropertyOperation="Changed">
			<Source><SimpleItem Name="Source" Value="VideoSource_1"/></Source>
			<Data><SimpleItem Name="State" Value="true"/></Data>
		</Message>
	</NotificationMessage>
</PullMessagesResponse>"#;

    /// The WS-BaseNotification + ONVIF spec shape real cameras emit (Go
    /// issue #82): attributes and items on the INNER tt:Message.
    const PULL_CANONICAL: &str = r#"<PullMessagesResponse>
	<wsnt:NotificationMessage xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2"
		xmlns:tt="http://www.onvif.org/ver10/schema">
		<wsnt:Topic Dialect="http://docs.oasis-open.org/wsn/t-1/TopicExpression/Concrete">tns1:VideoSource/MotionAlarm</wsnt:Topic>
		<wsnt:ProducerReference><wsa:Address xmlns:wsa="http://www.w3.org/2005/08/addressing">urn:uuid:producer-1</wsa:Address></wsnt:ProducerReference>
		<wsnt:Message>
			<tt:Message UtcTime="2026-09-15T12:12:46Z" PropertyOperation="Changed">
				<tt:Source><tt:SimpleItem Name="Source" Value="CSI"/></tt:Source>
				<tt:Data>
					<tt:SimpleItem Name="State" Value="true"/>
					<tt:SimpleItem Name="Score" Value="87"/>
				</tt:Data>
			</tt:Message>
		</wsnt:Message>
	</wsnt:NotificationMessage>
</PullMessagesResponse>"#;

    const PROPERTIES_RESP: &str = r#"<GetEventPropertiesResponse>
	<TopicNamespaceLocation>http://www.onvif.org/onvif/ver10/topics/topicns.xml</TopicNamespaceLocation>
	<FixedTopicSet>true</FixedTopicSet>
	<TopicSet>
		<VideoSource><MotionAlarm><State/></MotionAlarm></VideoSource>
	</TopicSet>
	<TopicExpressionDialect>http://docs.oasis-open.org/wsn/t-1/TopicExpression/Concrete</TopicExpressionDialect>
	<MessageContentFilterDialect>http://www.onvif.org/ver10/tev/messageContentFilter/ItemFilter</MessageContentFilterDialect>
</GetEventPropertiesResponse>"#;

    // --- decode tests ---

    #[test]
    fn capabilities_decode() {
        let caps = parse_capabilities_response(CAPABILITIES_RESP).unwrap();
        assert!(caps.ws_subscription_policy_support);
        assert_eq!(caps.max_pull_points, 8);
        assert_eq!(caps.max_notification_producers, 16);
        // The fixture's short "PersistentStorage" attribute is NOT the
        // name the Go twin decodes — parity keeps it false here.
        assert!(!caps.persistent_notification_storage);
        assert!(!caps.metadata_over_mqtt);
        assert_eq!(caps.event_broker_protocols, vec!["mqtt", "mqtts"]);
    }

    #[test]
    fn create_subscription_decode() {
        let sub = parse_create_subscription_response(CREATE_SUB_RESP).unwrap();
        assert_eq!(sub.subscription_reference, "http://fake/sub/1");
        assert_eq!(
            sub.current_time.map(|t| t.to_rfc3339()).as_deref(),
            Some("2026-08-28T10:00:00Z")
        );
        assert_eq!(
            sub.termination_time.map(|t| t.to_rfc3339()).as_deref(),
            Some("2026-08-28T11:00:00Z")
        );

        assert!(
            parse_create_subscription_response("<CreatePullPointSubscriptionResponse/>").is_err()
        );
    }

    #[test]
    fn pull_messages_single_layer_decode() {
        let msgs = parse_pull_messages_response(PULL_ONE).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].topic, "tns1:VideoSource/MotionAlarm");
        assert_eq!(msgs[0].producer_reference, "urn:uuid:producer-1");
        assert_eq!(msgs[0].message.property_operation, "Changed");
        assert_eq!(
            msgs[0].message.source,
            vec![notify::SimpleItem::new("Source", "VideoSource_1")]
        );
        assert_eq!(
            msgs[0].message.data,
            vec![notify::SimpleItem::new("State", "true")]
        );
    }

    /// Go issue #82 pin: the inner tt:Message must win over the lax outer
    /// layer.
    #[test]
    fn pull_messages_two_layer_decode() {
        let msgs = parse_pull_messages_response(PULL_CANONICAL).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].topic, "tns1:VideoSource/MotionAlarm");
        assert_eq!(msgs[0].producer_reference, "urn:uuid:producer-1");
        assert_eq!(msgs[0].message.property_operation, "Changed");
        assert_eq!(msgs[0].message.utc_time, "2026-09-15T12:12:46Z");
        assert_eq!(
            msgs[0].message.source,
            vec![notify::SimpleItem::new("Source", "CSI")]
        );
        assert_eq!(
            msgs[0].message.data,
            vec![
                notify::SimpleItem::new("State", "true"),
                notify::SimpleItem::new("Score", "87")
            ]
        );
    }

    #[test]
    fn pull_messages_empty_is_empty() {
        let msgs = parse_pull_messages_response("<PullMessagesResponse>\n</PullMessagesResponse>")
            .unwrap();
        assert!(msgs.is_empty());
    }

    /// Interop pin against this crate's own events SERVER: the exact
    /// PullMessagesResponse byte shape `build_pull_messages_response`
    /// emits (tev: times, wsnt: notification, wsa: producer address).
    #[test]
    fn pull_messages_decodes_own_server_shape() {
        let resp = r#"<tev:PullMessagesResponse xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:tt="http://www.onvif.org/ver10/schema">
  <tev:CurrentTime>2026-10-12T09:00:00Z</tev:CurrentTime>
  <tev:TerminationTime>2026-10-12T10:00:00Z</tev:TerminationTime>
  <wsnt:NotificationMessage>
    <wsnt:Topic>tns1:VideoSource/MotionAlarm</wsnt:Topic>
    <wsnt:ProducerReference><wsa:Address>http://192.168.63.104:8080/onvif/device_service</wsa:Address></wsnt:ProducerReference>
    <wsnt:Message><tt:Message UtcTime="2026-10-12T09:00:01Z" PropertyOperation="Changed"><tt:Source></tt:Source><tt:Key></tt:Key><tt:Data><tt:SimpleItem Name="State" Value="true"/></tt:Data></tt:Message></wsnt:Message>
  </wsnt:NotificationMessage>
</tev:PullMessagesResponse>"#;
        let msgs = parse_pull_messages_response(resp).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].topic, "tns1:VideoSource/MotionAlarm");
        assert_eq!(msgs[0].message.property_operation, "Changed");
        assert_eq!(msgs[0].message.utc_time, "2026-10-12T09:00:01Z");
        assert_eq!(
            msgs[0].message.data,
            vec![notify::SimpleItem::new("State", "true")]
        );
    }

    #[test]
    fn renewal_decode() {
        let resp = r#"<RenewResponse>
	<CurrentTime>2026-10-12T09:00:00Z</CurrentTime>
	<TerminationTime>2026-10-12T10:00:00Z</TerminationTime>
</RenewResponse>"#;
        let renewal = parse_renewal_response(resp).unwrap();
        assert_eq!(
            renewal.termination_time.map(|t| t.to_rfc3339()).as_deref(),
            Some("2026-10-12T10:00:00Z")
        );
        assert_eq!(
            renewal.current_time.map(|t| t.to_rfc3339()).as_deref(),
            Some("2026-10-12T09:00:00Z")
        );

        // Absent times stay None (the Go twin's zero time.Time).
        let bare = parse_renewal_response("<RenewResponse/>").unwrap();
        assert!(bare.termination_time.is_none());
        assert!(bare.current_time.is_none());
    }

    #[test]
    fn properties_decode_including_topic_tree() {
        let props = parse_properties_response(PROPERTIES_RESP).unwrap();
        assert!(props.fixed_topic_set);
        assert_eq!(props.topic_namespace_location.len(), 1);
        assert_eq!(props.topic_expression_dialects.len(), 1);
        assert_eq!(
            props.message_content_filter_dialects,
            vec!["http://www.onvif.org/ver10/tev/messageContentFilter/ItemFilter"]
        );

        // TopicSet tree (beyond the Go twin, which never fills it).
        assert_eq!(props.topic_set.topics.len(), 1);
        let video_source = &props.topic_set.topics[0];
        assert_eq!(video_source.name, "VideoSource");
        assert_eq!(video_source.children.len(), 1);
        assert_eq!(video_source.children[0].name, "MotionAlarm");
        assert_eq!(video_source.children[0].children.len(), 1);
        assert_eq!(video_source.children[0].children[0].name, "State");
    }

    /// A `Description` child element becomes the parent node's description
    /// instead of a child topic.
    #[test]
    fn topic_tree_description_child() {
        let resp = r#"<GetEventPropertiesResponse><TopicSet>
	<VideoSource><MotionAlarm><wstop:Description>Motion alarm state</wstop:Description><State/></MotionAlarm></VideoSource>
</TopicSet></GetEventPropertiesResponse>"#;
        let props = parse_properties_response(resp).unwrap();
        let motion = &props.topic_set.topics[0].children[0];
        assert_eq!(motion.name, "MotionAlarm");
        assert_eq!(motion.description, "Motion alarm state");
        assert_eq!(motion.children.len(), 1);
        assert_eq!(motion.children[0].name, "State");
    }

    #[test]
    fn event_brokers_decode() {
        let resp = r#"<GetEventBrokersResponse><EventBroker><Address>mqtt://a</Address><TopicPrefix>t</TopicPrefix><Status>Connected</Status></EventBroker></GetEventBrokersResponse>"#;
        let brokers = parse_event_brokers_response(resp).unwrap();
        assert_eq!(brokers.len(), 1);
        assert_eq!(brokers[0].address, "mqtt://a");
        assert_eq!(brokers[0].topic_prefix, "t");
        assert_eq!(brokers[0].status, "Connected");

        assert!(parse_event_brokers_response("<GetEventBrokersResponse/>")
            .unwrap()
            .is_empty());
    }

    // --- request goldens ---

    #[test]
    fn request_goldens() {
        assert_eq!(
            tev_action("tev:GetServiceCapabilities"),
            "<tev:GetServiceCapabilities xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\"></tev:GetServiceCapabilities>"
        );
        assert_eq!(
            build_seek_request(UtcStamp::from_components(2026, 1, 2, 3, 4, 5), false),
            "<tev:Seek xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\"><tev:UtcTime>2026-01-02T03:04:05Z</tev:UtcTime></tev:Seek>"
        );
        assert!(
            build_seek_request(UtcStamp::from_components(2026, 1, 2, 3, 4, 5), true)
                .contains("<tev:Reverse>true</tev:Reverse>")
        );
    }

    #[test]
    fn create_subscription_request_goldens() {
        assert_eq!(
            build_create_pull_point_subscription_request("", None, ""),
            "<tev:CreatePullPointSubscription xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\" xmlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\"></tev:CreatePullPointSubscription>"
        );
        assert_eq!(
            build_create_pull_point_subscription_request(
                "tns1:VideoSource//.",
                Some(Duration::from_secs(30 * 60)),
                ""
            ),
            "<tev:CreatePullPointSubscription xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\" xmlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\">\
             <tev:Filter><wsnt:TopicExpression>tns1:VideoSource//.</wsnt:TopicExpression></tev:Filter>\
             <tev:InitialTerminationTime>PT30M</tev:InitialTerminationTime>\
             </tev:CreatePullPointSubscription>"
        );
    }

    #[test]
    fn add_event_broker_request_golden() {
        let config = EventBrokerConfig {
            address: "mqtt://broker.example.org".into(),
            topic_prefix: "onvif".into(),
            ..EventBrokerConfig::default()
        };
        assert_eq!(
            build_add_event_broker_request(&config),
            "<tev:AddEventBroker xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\">\
             <tev:EventBrokerConfig><tev:Address>mqtt://broker.example.org</tev:Address>\
             <tev:TopicPrefix>onvif</tev:TopicPrefix></tev:EventBrokerConfig></tev:AddEventBroker>"
        );
    }

    // --- validation (no I/O: rejected before the wire) ---

    fn client() -> SoapClient {
        SoapClient::new("http://127.0.0.1:1/onvif/device_service").unwrap()
    }

    #[tokio::test]
    async fn pull_messages_validation() {
        let c = client();
        assert!(matches!(
            c.pull_messages("", Duration::from_secs(1), 1).await,
            Err(ClientError::InvalidArgument(m)) if m == "invalid subscription reference"
        ));
        assert!(matches!(
            c.pull_messages("ref", Duration::ZERO, 1).await,
            Err(ClientError::InvalidArgument(m)) if m == "invalid timeout: must be positive"
        ));
        assert!(matches!(
            c.pull_messages("ref", Duration::from_secs(1), 0).await,
            Err(ClientError::InvalidArgument(m)) if m == "invalid message limit: must be positive"
        ));
    }

    #[tokio::test]
    async fn subscription_ops_require_reference() {
        let c = client();
        let when = UtcStamp::from_components(2026, 1, 2, 3, 4, 5);
        assert!(c
            .renew_subscription("", Duration::from_secs(60))
            .await
            .is_err());
        assert!(c.unsubscribe("").await.is_err());
        assert!(c.seek("", when, false).await.is_err());
        assert!(c.set_event_synchronization_point("").await.is_err());
        assert!(c
            .create_pull_point_subscription("", Some(Duration::ZERO), "")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn broker_validation() {
        let c = client();
        assert!(c
            .add_event_broker(&EventBrokerConfig::default())
            .await
            .is_err());
        assert!(c.delete_event_broker("").await.is_err());
    }
}
