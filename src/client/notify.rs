//! wsnt:Notify parsing — what a device POSTs to a push consumer, decoded
//! through the same two-layer `Message` contract as the Go twin's
//! PullMessages/ParseNotifyEvents pair (one parser, both transports).
//!
//! The canonical ONVIF payload is double-layer: the WSN `wsnt:Message`
//! wrapper around an inner payload element (`tt:Message`) carrying
//! `PropertyOperation`/`UtcTime` and the Source/Key/Data SimpleItem
//! groups. Lax firmwares put the attributes and items directly on the
//! outer element — both shapes are decoded, the inner layer winning when
//! present. Documents arrive either as a full SOAP envelope
//! (`Body>Notify>NotificationMessage*`) or as a bare `Notify` root; both
//! are accepted.

use crate::client::{local_name, text_content, ClientError};

/// One `tt:SimpleItem` of an event's Source/Key/Data group (the same
/// shape the server half publishes — [`crate::events::SimpleItem`]).
pub type SimpleItem = crate::events::SimpleItem;

/// The decoded content of one notification message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventMessage {
    /// `PropertyOperation` attribute (`Changed`, `Initialized`, …).
    pub property_operation: String,
    /// `UtcTime` attribute, verbatim wire form (typically RFC 3339).
    pub utc_time: String,
    /// `Source` group items.
    pub source: Vec<SimpleItem>,
    /// `Key` group items.
    pub key: Vec<SimpleItem>,
    /// `Data` group items.
    pub data: Vec<SimpleItem>,
}

/// One notification message: topic + decoded message content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NotificationMessage {
    /// Topic expression (e.g. `tns1:VideoSource/MotionAlarm`).
    pub topic: String,
    /// `ProducerReference/Address`, when present.
    pub producer_reference: String,
    /// The message content (two-layer merged).
    pub message: EventMessage,
}

/// Parse a wsnt:Notify SOAP document into its notification messages.
///
/// Errors on non-XML input and on documents that contain no
/// `NotificationMessage` element at all.
pub fn parse_notify_events(body: &str) -> Result<Vec<NotificationMessage>, ClientError> {
    let fragments = extract_notification_fragments(body)?;
    if fragments.is_empty() {
        return Err(ClientError::Parse(
            "parse Notify: no NotificationMessage elements".into(),
        ));
    }
    fragments.iter().map(|f| parse_one(f)).collect()
}

/// Extract the raw XML of every `NotificationMessage` whose direct parent
/// element is named `Notify` — covering `Body>Notify>` of a full envelope
/// AND a bare `Notify` document root (the Go twin initially got this
/// wrong with path-based matching; parent-based matching is the fix both
/// twins now pin by test).
fn extract_notification_fragments(body: &str) -> Result<Vec<String>, ClientError> {
    let mut reader = quick_xml::Reader::from_str(body);
    reader.config_mut().trim_text(false);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut fragments = Vec::new();

    // Byte offsets of the NotificationMessage start under a Notify parent.
    let mut start: Option<usize> = None;
    let mut depth_of_start = 0usize;

    loop {
        use quick_xml::events::Event as XmlEvent;
        let pos_before = reader.buffer_position() as usize;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                let parent_is_notify = stack.last().map(String::as_str) == Some("Notify");
                if name == "NotificationMessage" && parent_is_notify && start.is_none() {
                    start = Some(pos_before);
                    depth_of_start = stack.len();
                }
                stack.push(name);
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
            Err(e) => return Err(ClientError::Parse(format!("parse Notify: {e}"))),
        }
        buf.clear();
    }

    Ok(fragments)
}

/// Decode one `NotificationMessage` fragment.
fn parse_one(fragment: &str) -> Result<NotificationMessage, ClientError> {
    let mut reader = quick_xml::Reader::from_str(fragment);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    let mut out = NotificationMessage::default();

    // Two-layer merge state (inner layer wins when present — issue #82 in
    // the Go twin: MotionAlarm State/Score were dropped when only the
    // outer layer was read).
    let mut outer = Layer::default();
    let mut inner = Layer::default();

    // Which layer receives subsequent items: false until the inner
    // Message opens, true while inside it, false again after it closes.
    let mut in_inner = false;

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                if stack.len() == 1 && name == "Message" {
                    // outer Message (direct child of NotificationMessage)
                    outer.property_operation = attr(&e, "PropertyOperation");
                    outer.utc_time = attr(&e, "UtcTime");
                } else if stack.last().map(String::as_str) == Some("Message") && name == "Message" {
                    // inner payload Message
                    in_inner = true;
                    inner.property_operation = attr(&e, "PropertyOperation");
                    inner.utc_time = attr(&e, "UtcTime");
                }
                stack.push(name);
            }
            Ok(XmlEvent::Empty(e)) => {
                let name = local_name(&e);
                if name == "SimpleItem" {
                    if let (Some(n), Some(v)) = (attr(&e, "Name"), attr(&e, "Value")) {
                        push_item(&stack, in_inner, n, v, &mut inner, &mut outer);
                    }
                }
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                if stack.len() == 2 && stack[1] == "Topic" {
                    out.topic = text;
                } else if stack.last().map(String::as_str) == Some("Address")
                    && stack.iter().any(|s| s == "ProducerReference")
                {
                    out.producer_reference = text;
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
                if stack.len() == 1 && stack[0] == "NotificationMessage" {
                    in_inner = false;
                }
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse NotificationMessage: {e}"
                )))
            }
        }
        buf.clear();
    }

    // Inner layer wins when it carries anything at all.
    let inner_has_any = inner.property_operation.is_some()
        || inner.utc_time.is_some()
        || !inner.source.is_empty()
        || !inner.key.is_empty()
        || !inner.data.is_empty();
    let (chosen, fallback) = if inner_has_any {
        (&inner, &outer)
    } else {
        (&outer, &inner)
    };

    out.message.property_operation = chosen
        .property_operation
        .clone()
        .or_else(|| fallback.property_operation.clone())
        .unwrap_or_default();
    out.message.utc_time = chosen
        .utc_time
        .clone()
        .or_else(|| fallback.utc_time.clone())
        .unwrap_or_default();
    out.message.source = chosen.source.clone();
    out.message.key = chosen.key.clone();
    out.message.data = chosen.data.clone();

    Ok(out)
}

/// One decoded Message layer: the inner payload element or the lax outer
/// element. [`parse_one`] keeps both and lets the inner layer win when it
/// carries anything.
#[derive(Default)]
struct Layer {
    property_operation: Option<String>,
    utc_time: Option<String>,
    source: Vec<SimpleItem>,
    key: Vec<SimpleItem>,
    data: Vec<SimpleItem>,
}

fn push_item(
    stack: &[String],
    in_inner: bool,
    name: String,
    value: String,
    inner: &mut Layer,
    outer: &mut Layer,
) {
    let target = if in_inner { inner } else { outer };
    let item = SimpleItem { name, value };
    match stack.last().map(String::as_str) {
        Some("Source") => target.source.push(item),
        Some("Key") => target.key.push(item),
        Some("Data") => target.data.push(item),
        _ => {}
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Field-shaped dual-message Notify in the canonical two-layer form
    /// (the Go twin's Hikvision golden).
    const TWO_LAYER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:tt="http://www.onvif.org/ver10/schema">
<SOAP-ENV:Body>
<wsnt:Notify>
<wsnt:NotificationMessage>
<wsnt:Topic Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">tns1:VideoSource/MotionAlarm</wsnt:Topic>
<wsnt:Message><tt:Message UtcTime="2026-10-12T08:57:05Z" PropertyOperation="Changed">
<tt:Source><tt:SimpleItem Name="Source" Value="VideoSource_1"/></tt:Source>
<tt:Data><tt:SimpleItem Name="State" Value="true"/><tt:SimpleItem Name="Score" Value="87"/></tt:Data>
</tt:Message></wsnt:Message>
</wsnt:NotificationMessage>
<wsnt:NotificationMessage>
<wsnt:Topic Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">tns1:RuleEngine/CellMotionDetector/Motion</wsnt:Topic>
<wsnt:Message><tt:Message UtcTime="2026-10-12T08:57:05Z" PropertyOperation="Changed">
<tt:Source><tt:SimpleItem Name="VideoSourceConfigurationToken" Value="VideoSourceToken"/></tt:Source>
<tt:Data><tt:SimpleItem Name="IsMotion" Value="true"/></tt:Data>
</tt:Message></wsnt:Message>
</wsnt:NotificationMessage>
</wsnt:Notify>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#;

    /// Lax single-layer form: attributes and items directly on the outer
    /// Message element.
    const SINGLE_LAYER: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2">
<s:Body><wsnt:Notify><wsnt:NotificationMessage>
<wsnt:Topic>tns1:VideoSource/MotionAlarm</wsnt:Topic>
<wsnt:Message UtcTime="2026-10-12T08:57:05Z" PropertyOperation="Initialized">
<Source><SimpleItem Name="Source" Value="CSI"/></Source>
<Data><SimpleItem Name="State" Value="true"/></Data>
</wsnt:Message>
</wsnt:NotificationMessage></wsnt:Notify></s:Body></s:Envelope>"#;

    /// A device that POSTs the Notify element itself as the document root.
    const BARE_ROOT: &str = r#"<wsnt:Notify xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2">
<wsnt:NotificationMessage><wsnt:Topic>tns1:Device/Humidity</wsnt:Topic></wsnt:NotificationMessage>
</wsnt:Notify>"#;

    #[test]
    fn two_layer_decode() {
        let msgs = parse_notify_events(TWO_LAYER).unwrap();
        assert_eq!(msgs.len(), 2);

        assert_eq!(msgs[0].topic, "tns1:VideoSource/MotionAlarm");
        assert_eq!(msgs[0].message.property_operation, "Changed");
        assert_eq!(msgs[0].message.utc_time, "2026-10-12T08:57:05Z");
        assert_eq!(
            msgs[0].message.source,
            vec![SimpleItem::new("Source", "VideoSource_1")]
        );
        assert_eq!(
            msgs[0].message.data,
            vec![
                SimpleItem::new("State", "true"),
                SimpleItem::new("Score", "87")
            ]
        );

        assert_eq!(msgs[1].topic, "tns1:RuleEngine/CellMotionDetector/Motion");
    }

    #[test]
    fn single_layer_decode() {
        let msgs = parse_notify_events(SINGLE_LAYER).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].topic, "tns1:VideoSource/MotionAlarm");
        assert_eq!(msgs[0].message.property_operation, "Initialized");
        assert_eq!(
            msgs[0].message.source,
            vec![SimpleItem::new("Source", "CSI")]
        );
        assert_eq!(msgs[0].message.data, vec![SimpleItem::new("State", "true")]);
    }

    #[test]
    fn bare_notify_root_tolerated() {
        let msgs = parse_notify_events(BARE_ROOT).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].topic, "tns1:Device/Humidity");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_notify_events("").is_err());
        assert!(parse_notify_events("this is not xml").is_err());
        assert!(parse_notify_events("<s:Envelope xmlns:s='x'><s:Body/></s:Envelope>").is_err());
    }
}
