//! ONVIF Device (server) library for Rust.
//!
//! Hand-written SOAP implementation of the ONVIF Device role: Device, Media,
//! Imaging, and (virtual) PTZ services over HTTP, plus a WS-Discovery UDP
//! responder and WS-Security UsernameToken verification (PasswordText and
//! PasswordDigest).
//!
//! Extracted verbatim from the production implementation in
//! `mibee-eye-raspi-rs`, whose response XML is byte-stable against the
//! MiBee NVR (raw SOAP local-name matching) — consumers with the same
//! constraint inherit that property unchanged.
//!
//! ## Host integration seams
//!
//! - [`config::DeviceConfig`] — device identity for GetDeviceInformation
//! - [`imaging::ImagingParams`] — camera parameter source for the Imaging
//!   service (implement over your capture pipeline's parameter manager)
//! - [`ptz_state`] — pure virtual-PTZ state machine used by the PTZ service
//! - Media service handlers take URIs/profiles as plain data at registration
//!
//! ## Byte stability
//!
//! Response element names and namespace prefixes follow the official WSDL
//! (`GetStreamUriResponse → MediaUri → Uri`, lowercase `ri` action URIs).
//! Do not change serialization without re-running consumer interop tests.

pub mod auth;
pub mod config;
pub mod device;
pub mod discovery;
pub mod imaging;
pub mod media;
pub mod namespaces;
pub mod ptz;
pub mod ptz_state;
pub mod server;
pub mod types;

pub use config::DeviceConfig;
pub use imaging::ImagingParams;
pub use ptz_state::{Position, PtzState, Velocity};
pub use server::{OnvifConfig, OnvifServer};
