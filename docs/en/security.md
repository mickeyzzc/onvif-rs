# Authentication and hardening

## WS-UsernameToken, both modes

Clients authenticate with WS-Security UsernameToken headers. Both
profile modes are verified:

- **PasswordText** — plaintext password in the token.
- **PasswordDigest** — `base64(SHA1(base64_decode(Nonce) + Created + Password))`.

Comparisons are constant-time; username mismatches and wrong digests
both simply fail. To compute a digest yourself (client-side tooling):

```rust
use onvif_device_rs::auth::compute_password_digest;

let digest = compute_password_digest(&nonce_b64, &created, &password);
```

## Fail-closed credentials

`OnvifConfig` defaults to **empty credentials with `allow_no_auth =
false`**: a host that forgets to configure auth gets a server that
rejects every authenticated action (401), not an open one. To run an
intentionally open device (isolated lab network), set
`allow_no_auth: true` explicitly:

```rust
let config = OnvifConfig {
    port: 8080,
    username: String::new(),
    password: String::new(),
    allow_no_auth: true, // every action open — your explicit choice
    ..Default::default()
};
```

Invalid configs (empty password without `allow_no_auth`) fail at
`start()` with a config error — never a silently-open server.

## Pre-auth actions

`register_anonymous_action(action)` answers specific actions without
credentials (GetSystemDateAndTime, GetCapabilities, GetServices) —
mirroring real camera behavior. The choice is per-action and visible
in code.

## Transport hardening

- **Body cap** — requests larger than `max_body_bytes` (default 1 MiB)
  get `413 Content Too Large`; the connection is drained briefly then
  closed so clients can read the status.
- **Read timeout** — connections stalled mid-request are dropped after
  `read_timeout` (default 30 s).
- **Header cap** — oversized/never-terminating header reads are cut at
  a fixed bound.
- No TLS on the SOAP listener — front it with your own reverse proxy
  if the deployment requires HTTPS.

## What the hygiene suite pins

`tests/library_hygiene.rs` guards the neutrality guarantees: no
branding strings, no panic paths, no lab addresses in library code,
and the auth-config fail-closed behavior above.
