//! Standard motion-topic semantic parsing (the twin of the Go library's
//! `events.ParseMotionAlarm` / `IsMotionTopic`, landed there via the
//! external MiBeeNvr contribution): recognize the two standard motion
//! topics on a parsed [`NotificationMessage`] and lift the boolean state.
//!
//! Field evidence behind the two topics (MiBeeNvr interop): many cameras
//! — all TP-Link models tested — emit only
//! `tns1:RuleEngine/CellMotionDetector/Motion` (`IsMotion`) and never
//! `tns1:VideoSource/MotionAlarm` (`State`), so consumers that recognize
//! only the latter never fire for them; dual-signal cameras (Hikvision)
//! emit both.

use super::notify::NotificationMessage;

/// The motion state carried by a standard motion notification.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MotionAlarm {
    /// Whether motion is active.
    pub active: bool,
    /// 0–100; 0 when the device does not provide a score.
    pub score: f64,
    /// Source `SimpleItem` value (e.g. `"CSI"` or a video source token).
    pub source: String,
}

/// The recognized motion topics, normalized by [`normalize_topic`], and
/// the Data item that carries each one's boolean state.
fn motion_state_key(topic: &str) -> Option<&'static str> {
    match normalize_topic(topic).as_str() {
        "videosource/motionalarm" => Some("State"),
        "ruleengine/cellmotiondetector/motion" => Some("IsMotion"),
        _ => None,
    }
}

/// Lower-case a topic path and drop every segment's namespace prefix, so
/// `tns1:`, `tnsalias:` and vendor prefixes all compare equal.
fn normalize_topic(topic: &str) -> String {
    topic
        .trim()
        .split('/')
        .map(|seg| match seg.rsplit_once(':') {
            Some((_, local)) => local.to_lowercase(),
            None => seg.to_lowercase(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Whether `topic` is a motion topic [`parse_motion_alarm`] recognizes.
/// Case-insensitive; namespace prefixes are ignored; an exact path match
/// (so `…/MotionAlarmExtra` and truncated paths are NOT motion topics).
#[must_use]
pub fn is_motion_topic(topic: &str) -> bool {
    motion_state_key(topic).is_some()
}

/// Extract the motion state from a notification. Two standard topics are
/// recognized (see the module docs); the state is read from the **Data**
/// slot only — a `State`/`IsMotion` item inside Source is not read. The
/// optional vendor `Score` in Data parses leniently (missing or garbage
/// → 0). `source` is the Source item named `Source`, else
/// `VideoSourceConfigurationToken`, else the first Source item.
///
/// Returns `None` for any other topic, a missing state item, or an
/// unparseable boolean.
#[must_use]
pub fn parse_motion_alarm(msg: &NotificationMessage) -> Option<MotionAlarm> {
    let key = motion_state_key(&msg.topic)?;

    let raw = item_value(&msg.message.data, key)?;

    let active = match raw.trim() {
        "true" | "1" => true,
        "false" | "0" => false,
        _ => return None,
    };

    let score = item_value(&msg.message.data, "Score")
        .and_then(|s| s.trim().parse::<f64>().ok())
        .unwrap_or(0.0);

    let source = item_value(&msg.message.source, "Source")
        .or_else(|| item_value(&msg.message.source, "VideoSourceConfigurationToken"))
        .or_else(|| msg.message.source.first().map(|i| i.value.clone()))
        .unwrap_or_default();

    Some(MotionAlarm {
        active,
        score,
        source,
    })
}

fn item_value(items: &[super::notify::SimpleItem], name: &str) -> Option<String> {
    items
        .iter()
        .find(|i| i.name == name)
        .map(|i| i.value.clone())
}

#[cfg(test)]
mod tests {
    use super::super::notify::SimpleItem;
    use super::*;

    fn msg(topic: &str, source: &[(&str, &str)], data: &[(&str, &str)]) -> NotificationMessage {
        NotificationMessage {
            topic: topic.to_string(),
            message: super::super::notify::EventMessage {
                source: source.iter().map(|(n, v)| SimpleItem::new(n, v)).collect(),
                data: data.iter().map(|(n, v)| SimpleItem::new(n, v)).collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn motion_alarm_state_with_score() {
        let m = msg(
            "tns1:VideoSource/MotionAlarm",
            &[("Source", "CSI")],
            &[("State", "true"), ("Score", "87")],
        );
        let a = parse_motion_alarm(&m).unwrap();
        assert!(a.active);
        assert_eq!(a.score, 87.0);
        assert_eq!(a.source, "CSI");
    }

    #[test]
    fn garbage_score_tolerated_as_zero() {
        let m = msg(
            "tns1:VideoSource/MotionAlarm",
            &[("Source", "VideoSource_1")],
            &[("State", "true"), ("Score", "n/a")],
        );
        let a = parse_motion_alarm(&m).unwrap();
        assert!(a.active);
        assert_eq!(a.score, 0.0);
    }

    #[test]
    fn cell_motion_detector_is_motion() {
        let m = msg(
            "tns1:RuleEngine/CellMotionDetector/Motion",
            &[
                ("VideoSourceConfigurationToken", "VideoSourceToken"),
                ("Rule", "MyMotionDetectorRule"),
            ],
            &[("IsMotion", "true")],
        );
        let a = parse_motion_alarm(&m).unwrap();
        assert!(a.active);
        assert_eq!(a.source, "VideoSourceToken");

        let m_false = msg(
            "tns1:RuleEngine/CellMotionDetector/Motion",
            &[],
            &[("IsMotion", "false")],
        );
        assert!(!parse_motion_alarm(&m_false).unwrap().active);
    }

    #[test]
    fn missing_state_rejected() {
        // CellMotionDetector without IsMotion (a State item instead).
        assert!(parse_motion_alarm(&msg(
            "tns1:RuleEngine/CellMotionDetector/Motion",
            &[],
            &[("State", "true")]
        ))
        .is_none());

        // MotionAlarm without State (an IsMotion item instead).
        assert!(parse_motion_alarm(&msg(
            "tns1:VideoSource/MotionAlarm",
            &[],
            &[("IsMotion", "true")]
        ))
        .is_none());
    }

    #[test]
    fn state_key_in_source_slot_is_not_read() {
        let m = msg(
            "tns1:RuleEngine/CellMotionDetector/Motion",
            &[("IsMotion", "true")],
            &[],
        );
        assert!(parse_motion_alarm(&m).is_none());
    }

    #[test]
    fn unparseable_state_rejected() {
        assert!(parse_motion_alarm(&msg(
            "tns1:VideoSource/MotionAlarm",
            &[],
            &[("State", "maybe")]
        ))
        .is_none());
    }

    #[test]
    fn upper_case_topic_accepted() {
        let m = msg(
            "TNS1:RULEENGINE/CELLMOTIONDETECTOR/MOTION",
            &[],
            &[("IsMotion", "true")],
        );
        assert!(parse_motion_alarm(&m).unwrap().active);
    }

    #[test]
    fn other_rule_engine_topic_rejected() {
        let m = msg(
            "tns1:RuleEngine/TamperDetector/Tamper",
            &[],
            &[("IsTamper", "true")],
        );
        assert!(parse_motion_alarm(&m).is_none());
    }

    #[test]
    fn motion_topics_table() {
        assert!(is_motion_topic("tns1:VideoSource/MotionAlarm"));
        assert!(is_motion_topic("tns1:RuleEngine/CellMotionDetector/Motion"));
        assert!(is_motion_topic("TNS1:RULEENGINE/CELLMOTIONDETECTOR/MOTION"));
        assert!(is_motion_topic("tnsalias:VideoSource/MotionAlarm"));
        assert!(is_motion_topic(
            "tns1:RuleEngine/tns1:CellMotionDetector/tns1:Motion"
        ));
        assert!(is_motion_topic(" tns1:VideoSource/MotionAlarm "));
        assert!(!is_motion_topic("tns1:RuleEngine/TamperDetector/Tamper"));
        assert!(!is_motion_topic("tns1:Device/Humidity"));
        assert!(!is_motion_topic("tns1:VideoSource/MotionAlarmExtra"));
        assert!(!is_motion_topic("tns1:RuleEngine/CellMotionDetector"));
        assert!(!is_motion_topic(""));
    }
}
