# Configuration reference

Two structs configure an ONVIF device: [`OnvifConfig`] for the SOAP
server (ports, auth, limits) and [`DeviceConfig`] for the device
identity reported through GetDeviceInformation.

## OnvifConfig

```rust
use std::time::Duration;
use onvif_device_rs::OnvifConfig;

let config = OnvifConfig {
    port: 8080,
    username: "admin".to_string(),
    password: "secret".to_string(),
    allow_no_auth: false,
    max_body_bytes: 1024 * 1024,
    read_timeout: Duration::from_secs(30),
};
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `port` | `u16` | `8080` | Port bound by `start()`. Ignored by `start_on()` (you pass the listener). |
| `username` | `String` | `""` | WS-UsernameToken username expected from clients. |
| `password` | `String` | `""` | WS-UsernameToken password. **Empty password fails closed** unless `allow_no_auth` is set. |
| `allow_no_auth` | `bool` | `false` | Explicitly permit auth-free operation (every action open). |
| `max_body_bytes` | `usize` | 1 MiB | HTTP request body cap; larger bodies get `413`. |
| `read_timeout` | `Duration` | 30 s | Per-connection read timeout (header + body). |

The empty-credential default is deliberate: a host that forgets to
configure auth gets a server that **rejects authenticated actions**
rather than one that accepts everything. To run a genuinely open device
(lab, isolated network), set `allow_no_auth: true` explicitly — the
choice is then in your code, not an accident of defaults.

## DeviceConfig

Identity returned by GetDeviceInformation:

```rust
use onvif_device_rs::device::DeviceConfig;

let device = DeviceConfig {
    name: "Front gate camera".into(),
    manufacturer: "Acme".into(),
    model: "Cam-X".into(),
    firmware: env!("CARGO_PKG_VERSION").into(),
    hardware_id: "Cam-X-SoC".into(),
    serial_number: "SN-000042".into(),
};
```

Defaults describe the origin hardware (`Pi Camera V1` / `Raspberry Pi`
/ `OV5647`) — they are placeholders kept for config-file compatibility
with the extraction source. **Set your own values in production**;
`Default` and an empty serde section produce identical values (pinned
by test). TOML/JSON friendly, so it can be re-exported into the host's
own config struct.

## Server lifecycle

```rust
let mut soap = OnvifServer::new(&config);
// ... register handlers (see handlers.md) ...
let mut handle = soap.start().await?;       // binds config.port
// or: soap.start_on(listener).await?;      // your own TcpListener (port 0, socket activation, ...)
handle.shutdown().await?;                   // graceful stop; handle.await waits for exit
```

`start_on` exists for hosts that manage their own listeners (dynamic
ports, systemd socket activation, test harnesses).

> **Keep the handle.** `start()` resolves as soon as the accept loop is
> spawned and the returned handle's `Drop` **stops the server**. Await it in
> the spawning task (`let handle = soap.start().await?; handle.await;`) or
> store it and call `shutdown()`. Discarding the `Ok` value silently kills
> the server — both handles are `#[must_use]` since 0.3.1 to catch this at
> compile time.
