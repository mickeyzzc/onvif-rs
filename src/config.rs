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
