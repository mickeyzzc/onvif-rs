//! Thermal Service RadiometryAlarm semantic parsing (the twin of the Go
//! library's `events.ParseRadiometryAlarm` / `IsRadiometryTopic`):
//! recognize the thermal radiometry topics on a parsed
//! [`NotificationMessage`] and lift the fire/over-temperature verdict.
//!
//! Camera-side temperature rules (spot/region thresholds, fire-point
//! detection) evaluate on the device; the event only carries the verdict —
//! the same role the motion topics play for visible-light motion.

use super::motion::{item_value, normalize_topic};
use super::notify::NotificationMessage;

/// The fire/over-temperature state carried by the Thermal Service's
/// RadiometryAlarm notification.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RadiometryAlarm {
    /// Whether a thermal rule is currently firing.
    pub active: bool,
    /// °C when the device reports a reading; 0 otherwise.
    pub temperature: f64,
    /// Source `SimpleItem` value (e.g. a thermal source token).
    pub source: String,
}

/// The Data items that may carry each recognized topic's boolean state, in
/// preference order: the spec shape is `Active`; `State` is accepted as
/// vendor variance (the same leniency the motion topics need in the field).
/// The Data items that may carry each recognized topic's boolean state, in
/// preference order: the spec shape is `Active`; `State` is accepted as
/// vendor variance (the same leniency the motion topics need in the field).
/// The `TemperatureAlarm` family is the shape a real dual-spectrum camera
/// emits (Hikvision DS-2TB2617-6/QA, fw V5.5.38 — field-verified 2026-11-09):
/// topic `tns1:RuleEngine/Radiometry/TemperatureAlarm`, boolean Data item
/// `AlarmActive`, Key `RadiometryModuleID`; its fixed topic set declares no
/// Temperature item.
fn radiometry_state_keys(topic: &str) -> Option<&'static [&'static str]> {
    match normalize_topic(topic).as_str() {
        "thermal/radiometryalarm" => Some(&["Active", "State"]),
        "ruleengine/thermal/radiometryalarm" => Some(&["Active", "State"]),
        "radiometry/temperaturealarm" => Some(&["AlarmActive"]),
        "ruleengine/radiometry/temperaturealarm" => Some(&["AlarmActive"]),
        _ => None,
    }
}

/// Whether `topic` is a radiometry topic [`parse_radiometry_alarm`]
/// recognizes. Case-insensitive; namespace prefixes are ignored; an exact
/// path match.
#[must_use]
pub fn is_radiometry_topic(topic: &str) -> bool {
    radiometry_state_keys(topic).is_some()
}

/// Extract the radiometry state from a notification. The spec topic is
/// `tns1:Thermal/RadiometryAlarm`; RuleEngine-qualified vendor variants
/// compare equal. The state is read from the **Data** slot only — `Active`
/// (spec shape) first, `State` as vendor variance; when both are present
/// `Active` wins. `Temperature` is an optional numeric Data item (°C); a
/// missing or unparseable reading is 0. `source` follows the same rules as
/// [`super::motion::parse_motion_alarm`].
///
/// Returns `None` for any other topic, a missing state item, or an
/// unparseable boolean.
#[must_use]
pub fn parse_radiometry_alarm(msg: &NotificationMessage) -> Option<RadiometryAlarm> {
    let keys = radiometry_state_keys(&msg.topic)?;

    // First present key wins (Active before State).
    let raw = keys.iter().find_map(|k| item_value(&msg.message.data, k))?;

    let active = match raw.trim() {
        "true" | "1" => true,
        "false" | "0" => false,
        _ => return None,
    };

    let temperature = item_value(&msg.message.data, "Temperature")
        .and_then(|s| s.trim().parse::<f64>().ok())
        .unwrap_or(0.0);

    let source = item_value(&msg.message.source, "Source")
        .or_else(|| item_value(&msg.message.source, "VideoSourceConfigurationToken"))
        .or_else(|| msg.message.source.first().map(|i| i.value.clone()))
        .unwrap_or_default();

    Some(RadiometryAlarm {
        active,
        temperature,
        source,
    })
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
    fn spec_topic_active_with_temperature() {
        let m = msg(
            "tns1:Thermal/RadiometryAlarm",
            &[("Source", "ThermalSource_1")],
            &[("Active", "true"), ("Temperature", "87.5")],
        );
        let a = parse_radiometry_alarm(&m).unwrap();
        assert!(a.active);
        assert_eq!(a.temperature, 87.5);
        assert_eq!(a.source, "ThermalSource_1");
    }

    /// Field-verified on a Hikvision DS-2TB2617-6/QA (fw V5.5.38, 2026-11-09):
    /// topic tns1:RuleEngine/Radiometry/TemperatureAlarm, Source
    /// VideoSourceToken, Key RadiometryModuleID, Data AlarmActive +
    /// TimeStamp (+ ElementItem AlarmGeoLocation) — no Temperature item.
    #[test]
    fn hikvision_temperature_alarm_shape() {
        let m = msg(
            "tns1:RuleEngine/Radiometry/TemperatureAlarm",
            &[("Source", "VideoSource_2")],
            &[
                ("AlarmActive", "true"),
                ("TimeStamp", "2026-11-09T12:00:00Z"),
            ],
        );
        let a = parse_radiometry_alarm(&m).unwrap();
        assert!(a.active);
        assert_eq!(a.temperature, 0.0);
        assert_eq!(a.source, "VideoSource_2");
    }

    #[test]
    fn temperature_alarm_unqualified_variant_false_state() {
        let m = msg(
            "tns1:Radiometry/TemperatureAlarm",
            &[],
            &[("AlarmActive", "false")],
        );
        assert!(!parse_radiometry_alarm(&m).unwrap().active);
    }

    #[test]
    fn temperature_alarm_without_alarm_active_is_none() {
        let m = msg(
            "tns1:RuleEngine/Radiometry/TemperatureAlarm",
            &[],
            &[("Active", "true")],
        );
        assert!(parse_radiometry_alarm(&m).is_none());
    }

    #[test]
    fn ruleengine_qualified_variant_compares_equal() {
        let m = msg(
            "tns1:RuleEngine/Thermal/RadiometryAlarm",
            &[],
            &[("Active", "true")],
        );
        assert!(parse_radiometry_alarm(&m).unwrap().active);
    }

    #[test]
    fn case_insensitive_and_prefix_blind() {
        let m = msg(
            "tnsalias:THERMAL/RadiometryAlarm",
            &[],
            &[("Active", "true")],
        );
        assert!(parse_radiometry_alarm(&m).unwrap().active);
    }

    #[test]
    fn state_key_accepted_as_vendor_variance() {
        let m = msg("tns1:Thermal/RadiometryAlarm", &[], &[("State", "true")]);
        assert!(parse_radiometry_alarm(&m).unwrap().active);
    }

    #[test]
    fn active_wins_when_both_present() {
        let m = msg(
            "tns1:Thermal/RadiometryAlarm",
            &[],
            &[("State", "true"), ("Active", "false")],
        );
        assert!(!parse_radiometry_alarm(&m).unwrap().active);
    }

    #[test]
    fn missing_state_is_none() {
        let m = msg(
            "tns1:Thermal/RadiometryAlarm",
            &[],
            &[("Temperature", "50")],
        );
        assert!(parse_radiometry_alarm(&m).is_none());
    }

    #[test]
    fn non_boolean_state_is_none() {
        let m = msg("tns1:Thermal/RadiometryAlarm", &[], &[("Active", "maybe")]);
        assert!(parse_radiometry_alarm(&m).is_none());
    }

    #[test]
    fn unparseable_temperature_tolerated_as_zero() {
        let m = msg(
            "tns1:Thermal/RadiometryAlarm",
            &[],
            &[("Active", "true"), ("Temperature", "n/a")],
        );
        let a = parse_radiometry_alarm(&m).unwrap();
        assert!(a.active);
        assert_eq!(a.temperature, 0.0);
    }

    #[test]
    fn other_topics_are_not_radiometry() {
        assert!(!is_radiometry_topic("tns1:VideoSource/MotionAlarm"));
        assert!(!is_radiometry_topic("tns1:Thermal/Radiometry"));
        assert!(!is_radiometry_topic(""));
        assert!(is_radiometry_topic("tns1:Thermal/RadiometryAlarm"));
        assert!(is_radiometry_topic(
            "tns1:RuleEngine/Thermal/RadiometryAlarm"
        ));
    }
}
