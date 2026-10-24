# The action-handler model

The SOAP server routes by **local name**: the first child element of the
SOAP body is the action (`GetProfiles`, `GetStreamUri`, …). Each action
maps to one handler:

```rust
use onvif_device_rs::server::{OnvifActionHandler, OnvifServer};
use onvif_device_rs::types::{OnvifError, RequestInfo};

#[async_trait::async_trait]
impl OnvifActionHandler for MyHandler {
    async fn handle(&self, body: &str, info: &RequestInfo) -> Result<String, OnvifError> {
        // body: the raw SOAP body fragment
        // return: the complete response envelope
    }
}

soap.register_handler("GetProfiles", Box::new(MyHandler));
```

`RequestInfo` carries per-request context:

```rust
pub struct RequestInfo {
    pub client_ip: String,   // peer address (logging, access control)
    pub server_ip: String,   // local IP that received the connection (URI building)
    pub auth_result: AuthResult, // username + whether auth succeeded
}
```

The `server_ip` drives multi-interface correctness: stream/service URIs
are built from the interface the client actually reached, falling back
to the startup `device_ip` for loopback-sourced requests (reverse-proxy
scenario).

## Install

```bash
cargo add onvif-device-rs@0.7.0  # crate name differs from the repo (onvif-rs)
```

## Anonymous (pre-auth) actions

Real cameras answer some actions before credentials are presented —
clients probe GetSystemDateAndTime, GetCapabilities, GetServices first.
Register those as anonymous:

```rust
for action in ["GetSystemDateAndTime", "GetCapabilities", "GetServices"] {
    soap.register_anonymous_action(action);
}
```

Everything else requires a valid WS-UsernameToken.

## Built-in services

The crate ships handler implementations for the common services —
register the actions you want:

```rust
use std::sync::Arc;
use onvif_device_rs::device::{DeviceHandler, DeviceServiceHandlers};
use onvif_device_rs::DeviceConfig;

// Device service: five actions, one shared state
let device = Arc::new(DeviceServiceHandlers::new(device_config, port, device_ip));
for action in ["GetSystemDateAndTime", "GetDeviceInformation",
               "GetCapabilities", "GetServices", "GetScopes"] {
    soap.register_handler(action, Box::new(DeviceHandler(Arc::clone(&device))));
}
```

Media (GetProfiles / GetStreamUri / GetSnapshotUri /
GetVideoSources), Imaging (register_imaging_actions), and PTZ
(PtzHandler) have their own guides.

## Response envelopes

Handlers return the **complete SOAP envelope** (not a fragment). The
built-in builders produce the canonical form this crate guarantees
byte-stable; custom handlers should reuse the same element names and
namespace prefixes — many clients do raw local-name matching rather
than full SOAP parsing.

## Reference wiring

`examples/device_demo.rs` is a self-checking wiring: it starts the
server, asserts anonymous actions answer `200`, asserts credentialed
actions answer `401` without a token, and exits 0 — use it as the
template for your own bootstrap.

## SystemReboot (v0.7.0)

The Device service answers a `SystemReboot` action with the WSDL
`SystemRebootResponse/Message` form ("Device rebooting"). It is a
protocol answer only — the library never performs the reboot side
effect; hook a real one in your own handler layer if the hardware
supports it. The action stays credential-protected, matching the go
twin's policy for write-style actions.
