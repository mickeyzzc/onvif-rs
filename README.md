# onvif-rs

**English** | [中文](README.zh-CN.md)

[![CI](https://github.com/mickeyzzc/onvif-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/mickeyzzc/onvif-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Language: Rust](https://img.shields.io/badge/language-Rust-dea584.svg)
![Tests](https://img.shields.io/badge/tests-133%20passing-brightgreen.svg)

ONVIF **Device (server)** library for Rust — expose a camera or media source to ONVIF consumers (NVRs, video management systems) over SOAP + WS-Discovery.

> **Naming decision**: this project is unrelated to [lumeohq/onvif-rs](https://github.com/lumeohq/onvif-rs) (a WSDL-generated ONVIF *client*). The crates.io name `onvif-rs` is held by an abandoned 2018 placeholder, so **the supported distribution is the git dependency pinned by tag** (see the install snippet above). A crates.io release is intentionally not planned while there are no external consumers; if one becomes warranted it would ship under a different package name (e.g. `onvif-device-rs`).

## Features

- **SOAP HTTP server** with per-action handler registration — Device, Media, Imaging, and (virtual) PTZ services
- **WS-Discovery responder** — UDP multicast 239.255.255.250:3702 Probe/ProbeMatches with per-request XAddr echo
- **WS-Security** — UsernameToken verification, PasswordText and PasswordDigest (SHA-1), constant-time comparison
- **Namespace-agnostic request parsing** (clients send arbitrary XML prefixes) and explicit-prefix serialization (`tds:`/`trt:`/`timg:`/`tt:`)
- **Virtual PTZ** — a pure state machine (`ptz_state`) behind the PTZ service for devices without motors

Extracted verbatim from the production implementation in [mibee-eye-raspi-rs](https://github.com/Mi-Bee-Studio), whose response XML is **byte-stable against the MiBee NVR** (raw SOAP local-name matching). Element names follow the official WSDL (`GetStreamUriResponse → MediaUri → Uri`).

## Usage

```toml
[dependencies]
onvif-rs = { git = "https://github.com/mickeyzzc/onvif-rs.git", tag = "v0.1.0" }
```

```rust
use onvif_rs::{DeviceConfig, OnvifConfig, OnvifServer};
use onvif_rs::imaging::{ImagingParams, ImagingParamError, register_imaging_actions};
use std::sync::Arc;

// Implement the Imaging seam over your camera's parameter manager.
struct MyParams;
impl ImagingParams for MyParams {
    fn get_param(&self, name: &str) -> Result<f64, ImagingParamError> { /* ... */ }
    fn set_param(&self, name: &str, value: f64) -> Result<(), ImagingParamError> { /* ... */ }
}

#[tokio::main]
async fn main() {
    let device = DeviceConfig {
        name: "My Camera".into(),
        manufacturer: "Example".into(),
        model: "Model X".into(),
        ..Default::default()
    };

    let mut server = OnvifServer::new(OnvifConfig { /* port, auth, ... */ });
    onvif_rs::device::register_device_actions(&mut server, /* ... */);
    onvif_rs::media::register_media_actions(&mut server, /* ... */);
    register_imaging_actions(&mut server, Arc::new(MyParams));
    server.run().await;
}
```

See the `mibee-eye-raspi-rs` `main.rs` for a complete production wiring example (discovery responder, snapshot URI, stream URIs, PTZ).

## Byte stability guarantee

Consumers like the MiBee NVR match SOAP responses by local element names on the raw byte stream. The serialization in this crate is load-bearing: **do not change response element names, namespace prefixes, or attribute order** without re-running consumer interop tests. The crate's 133 tests include golden response strings that pin this.

## Development

This project follows strict **TDD** — see [CONTRIBUTING.md](CONTRIBUTING.md). CI enforces `rustfmt`, `clippy -D warnings`, and the full test suite (133 tests incl. golden response strings); `main` is protected (PR-only merges, CI required).

## Status

v0.1.0 — seams (`ImagingParams`, `DeviceConfig`, media registration) are settling but not frozen. Production-tested daily at [Mi-Bee Studio](https://github.com/Mi-Bee-Studio) against the MiBee NVR.

## License

MIT — see [LICENSE](LICENSE). Extracted from Mi-Bee Studio camera projects.
