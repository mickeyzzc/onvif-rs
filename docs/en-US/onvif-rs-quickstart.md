# Quick start: a minimal ONVIF device

`onvif-device-rs` is the ONVIF Device server: register a few handlers
and your device identity and media endpoints are advertised to any NVR.
This page is the minimal compilable example.

## Install

```bash
cargo add onvif-device-rs@0.7.0  # crate name differs from the repo (onvif-rs)
```

The example also needs an async runtime:

```toml
[dependencies]
onvif-device-rs = "=0.6.0"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Minimal example

```rust
use std::sync::Arc;

use onvif_device_rs::config::DeviceConfig;
use onvif_device_rs::device::{DeviceHandler, DeviceServiceHandlers};
use onvif_device_rs::media::{GetProfilesHandler, GetStreamUriHandler, OnvifMediaConfig};
use onvif_device_rs::server::{OnvifConfig, OnvifServer};

#[tokio::main]
async fn main() {
    let port = 8080u16;
    let device_ip = "192.0.2.10".to_string();

    let mut soap = OnvifServer::new(&OnvifConfig {
        port,
        username: "admin".to_string(),
        password: "secret".to_string(),
        ..Default::default()
    });

    let device = Arc::new(
        DeviceServiceHandlers::new(
            DeviceConfig {
                name: "quickstart camera".into(),
                manufacturer: "MiBee".into(),
                model: "QS".into(),
                firmware: "0.0.1".into(),
                hardware_id: "qs-hw".into(),
                serial_number: "QS-0001".into(),
            },
            port,
            device_ip.clone(),
        )
        .expect("device identity must be configured explicitly"),
    );
    for action in [
        "GetSystemDateAndTime",
        "GetDeviceInformation",
        "GetCapabilities",
        "GetServices",
        "GetScopes",
    ] {
        soap.register_handler(action, Box::new(DeviceHandler(Arc::clone(&device))));
    }
    for action in ["GetSystemDateAndTime", "GetCapabilities", "GetServices"] {
        soap.register_anonymous_action(action);
    }

    let media = Arc::new(OnvifMediaConfig::new(
        1280, 720, 25, 2_500_000, 8554, device_ip,
    ));
    soap.register_handler("GetProfiles", Box::new(GetProfilesHandler::new(Arc::clone(&media))));
    soap.register_handler("GetStreamUri", Box::new(GetStreamUriHandler::new(Arc::clone(&media))));

    tokio::spawn(soap.start());
}
```

Notes:

- Device identity must be configured explicitly
  (`DeviceServiceHandlers::new` validates it); anonymous actions are
  allow-listed one by one (the spec requires anonymous clock and
  capabilities).
- The ONVIF layer only **advertises** URLs: the RTSP server and snapshot
  HTTP endpoint live in your host ([media service](onvif-rs-media.md)).
- Add a `DiscoveryServer` to become discoverable by NVR WS-Discovery
  probes ([WS-Discovery](onvif-rs-discovery.md)).
- Example values use documentation-safe ranges (`192.0.2.x`, placeholder
  password).

## Next steps

- [Handler model](onvif-rs-handlers.md): registering and wiring each SOAP action.
- [Security](onvif-rs-security.md): WS-UsernameToken digest and the anonymous surface.
- [PTZ](onvif-rs-ptz.md) / [imaging](onvif-rs-imaging.md): optional services.
- The repo ships `cargo run --example device_demo`: a self-checking
  end-to-end demo.
