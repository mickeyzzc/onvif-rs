//! ONVIF device identity configuration (serde-friendly).
//!
//! TOML/JSON shapes are identical to the `mibee-eye-raspi-rs` `[device]`
//! section, so hosts can re-export [`DeviceConfig`] directly into their own
//! config structs without changing config files.
//!
//! Defaults describe the origin hardware (Raspberry Pi + OV5647 sensor);
//! non-Pi hosts should set their own values in config.

use serde::{Deserialize, Serialize};

/// ONVIF device information exposed via GetDeviceInformation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    #[serde(default = "default_device_name")]
    pub name: String,
    #[serde(default = "default_manufacturer")]
    pub manufacturer: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_firmware")]
    pub firmware: String,
    #[serde(default = "default_hardware_id")]
    pub hardware_id: String,
    #[serde(default)]
    pub serial_number: String,
}

fn default_device_name() -> String {
    "Pi Camera V1".to_string()
}
fn default_manufacturer() -> String {
    "Raspberry Pi".to_string()
}
fn default_model() -> String {
    "OV5647".to_string()
}
fn default_firmware() -> String {
    "1.0.0".to_string()
}
fn default_hardware_id() -> String {
    "OV5647".to_string()
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            name: default_device_name(),
            manufacturer: default_manufacturer(),
            model: default_model(),
            firmware: default_firmware(),
            hardware_id: default_hardware_id(),
            serial_number: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Default` must stay in lockstep with the serde defaults so hosts
    /// constructing `DeviceConfig::default()` and hosts deserializing an
    /// empty `[device]` section see the same values.
    #[test]
    fn default_matches_serde_defaults() {
        let d = DeviceConfig::default();
        let s: DeviceConfig = toml::from_str("").expect("empty TOML deserializes");
        assert_eq!(d.name, s.name);
        assert_eq!(d.manufacturer, s.manufacturer);
        assert_eq!(d.model, s.model);
        assert_eq!(d.firmware, s.firmware);
        assert_eq!(d.hardware_id, s.hardware_id);
        assert_eq!(d.serial_number, s.serial_number);
    }

    #[test]
    fn empty_toml_section_yields_documented_defaults() {
        let c: DeviceConfig = toml::from_str("").unwrap();
        assert_eq!(c.name, "Pi Camera V1");
        assert_eq!(c.manufacturer, "Raspberry Pi");
        assert_eq!(c.model, "OV5647");
        assert_eq!(c.firmware, "1.0.0");
        assert_eq!(c.hardware_id, "OV5647");
        assert_eq!(c.serial_number, "");
    }

    #[test]
    fn partial_toml_overrides_only_given_fields() {
        // The mibee-eye-raspi-rs `[device]` section sets exactly these.
        let c: DeviceConfig = toml::from_str(
            "\
             name = \"Desk Cam\"\n\
             model = \"IMX219\"\n\
             serial_number = \"SN-42\"\n\
             ",
        )
        .unwrap();
        assert_eq!(c.name, "Desk Cam");
        assert_eq!(c.model, "IMX219");
        assert_eq!(c.serial_number, "SN-42");
        // Untouched fields keep their defaults.
        assert_eq!(c.manufacturer, "Raspberry Pi");
        assert_eq!(c.firmware, "1.0.0");
    }

    #[test]
    fn serialize_roundtrip_preserves_identity() {
        let c = DeviceConfig {
            name: "Notebook Cam".into(),
            manufacturer: "MiBee".into(),
            model: "Virtual".into(),
            firmware: "9.9.9".into(),
            hardware_id: "HW-X".into(),
            serial_number: "SER-1".into(),
        };
        let toml_str = toml::to_string(&c).unwrap();
        let back: DeviceConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(back.name, c.name);
        assert_eq!(back.manufacturer, c.manufacturer);
        assert_eq!(back.model, c.model);
        assert_eq!(back.firmware, c.firmware);
        assert_eq!(back.hardware_id, c.hardware_id);
        assert_eq!(back.serial_number, c.serial_number);
    }
}
