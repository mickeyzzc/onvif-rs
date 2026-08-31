# WS-Discovery: being findable

Clients find ONVIF devices via WS-Discovery probes. This crate answers
both probe paths real clients use: **UDP multicast** (239.255.255.250:3702)
and **HTTP POST** probes.

## Basic responder

```rust
use onvif_device_rs::discovery::DiscoveryServer;

// Neutral scopes: onvif://www.onvif.org/Profile/Streaming
let discovery = DiscoveryServer::new(&device_ip, onvif_port);
let mut handle = discovery.start().await?;
// handle.shutdown().await? when done
```

## Identity and scopes

```rust
let discovery = DiscoveryServer::with_identity(&device_ip, onvif_port, "Gate Camera", "CamX-SoC")
    .with_scopes(vec!["onvif://www.onvif.org/Profile/G".to_string()])
    .with_uuid("6f3f1a2e-...");        // stable device UUID if you have one
```

- `with_identity` sets the friendly name + hardware id scopes.
- `with_scopes` **replaces** the scope list (URIs are percent-encoded;
  spaces in scope text are safe).
- A random UUID is generated per `DiscoveryServer` otherwise.

## What a ProbeMatches answer contains

Types `tdn:NetworkVideoTransmitter`, the scopes, and **XAddrs built
from the requesting interface** — `xaddrs(host_ip)` echoes a URL
reachable *from that client*, which is what multi-homed hosts need.
Message IDs and scopes are XML-escaped.

## HTTP POST probes

Some clients probe over HTTP instead of multicast. Route the POST body
through:

```rust
use onvif_device_rs::discovery::handle_http_probe;

let (status, body) = handle_http_probe(&discovery, &http_body, &server_ip);
// answer the HTTP request with this status + body
```

## Helpers

- `detect_local_ip()` — best-effort local address detection for hosts
  that don't know their IP at startup.

Byte layout of ProbeMatches is golden-tested — see
`src/discovery.rs` tests for the exact pinned envelope.
