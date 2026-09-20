# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project follows [semantic versioning](https://semver.org/). SOAP wire
goldens are contracts — any golden change is a breaking change.

Releases are capability packages: merges accumulate on `main` silently
and ship with the next tag (merge ≠ release). Only urgent security fixes
are released out of band.

## [Unreleased]

## [v0.7.0] — 2026-09-20

Capability parity with onvif-go, plus the quick-xml security upgrade.

- `fix(deps)` **quick-xml 0.36 → 0.41** (#37, RUSTSEC-2026-0194/0195,
  high 7.5): both advisories are untrusted-XML parse surface — this
  library's day job. Parsing loops were restructured onto the new event
  model (`TextAccumulator`: region accumulation, entity resolution,
  undefined-entity poisoning preserving the old unescape semantics);
  entity-carrying passwords now accumulate correctly across split text
  events (the old per-event overwrite dropped them).

- `feat(device)` **SystemReboot** — the Device service answers the
  SystemReboot action with the WSDL `SystemRebootResponse/Message` form
  (`Message` = "Device rebooting", parity with onvif-go's
  `HandleSystemReboot`). Protocol answer only: the library never performs
  the reboot side effect; hosts decide whether to hook a real one.
- `feat(discovery)` **Hello/Bye announcements** — the responder multicasts
  a WS-Discovery Hello on `start()` and a Bye when it stops (explicit
  `shutdown()` or dropping the handle), same envelope family and
  announcement fields as ProbeMatches (parity with onvif-go's
  discovery.Responder). Best effort: a lost announcement never stops
  Probe answering.
- `feat(server)` **TLS listener** behind the new `tls` cargo feature
  (off by default — default-feature dependents gain nothing): configure
  `tls_cert_file` + `tls_key_file` PEM paths (both-or-neither, parity
  with onvif-go) and the listener serves HTTPS via tokio-rustls.
  Configuring TLS without the feature fails at `start()` (no silent
  plain-HTTP fallback). Test certificates are generated per-run with
  `rcgen`.
- `feat(events)` **Events pull-point family** (parity with onvif-go's
  `SupportEvents` + `provider.PublishEvent`): `enable_events()` /
  `OnvifConfig::support_events` route `{base}/events_service`
  (GetServiceCapabilities / GetEventProperties /
  CreatePullPointSubscription) and the per-subscription
  `{base}/events_service/sub/<id>` subtree (PullMessages / Renew /
  Unsubscribe) on the listener the server already owns. Hosts inject
  property events via the shared `EventsService::publish_event` seam
  (`Event`/`SimpleItem` re-exported at the crate root) — fan-out to
  every live subscription with Concrete/ConcreteSet topic filters,
  ISO8601 InitialTerminationTime clamping, lossy bounded
  per-subscription queues, a max-pull-points bound with lazy expiry,
  and long-poll PullMessages (PT0S legal, publish wakes waiters), all in
  the wsnt double-layer NotificationMessage wire form with byte goldens
  against the go twin. GetCapabilities and GetServices advertise the
  service only while enabled; Create* actions sit behind WS-Security
  while reads stay open; with events disabled the routes answer 404 and
  the wire is byte-identical to before.

- `ci` coverage gate at **85% lines** (#39 + #43, measured baseline
  ~94%); the `tls` feature is now compiled, linted, and tested in CI
  (#40); repo hygiene gate (#35).
- `test` property arms for the untrusted parse surfaces (#42, #44):
  the SOAP request parser, discovery Probe datagrams, and UsernameToken
  Created fields never panic on arbitrary input.
- `docs` manuals migrated to the documentation hub (#36).

## [v0.6.0] — 2026-09-09

- `feat(discovery)` ProbeMatches sends retry with exponential backoff
  (#22): a unicast UDP reply can hit a transient full send buffer under
  burst load; up to 3 attempts with a doubling 10ms base backoff,
  interruptible by shutdown, replace the single-shot send.
- `bench` criterion suite for the SOAP hot paths (#22):
  parse (plain + UsernameToken envelopes) and auth verification
  (plaintext vs digest). `parse_soap_request`/`ParsedSoap` are now
  public so hosts can pre-inspect requests.

- **Changed (breaking)** `DeviceConfig` defaults are neutral placeholders
  (`ONVIF Device` / `unknown` / `unknown`) — the origin-hardware values
  (`Pi Camera V1` / `Raspberry Pi` / `OV5647`) are gone. New
  `DeviceConfig::validate` rejects the `unknown` placeholders and empty
  fields, and `DeviceServiceHandlers::new` now returns
  `Result<Self, OnvifError>` and fails fast on an unconfigured identity;
  `OnvifError::InvalidConfig` added (#20).

## [v0.5.0] — 2026-09-08

- **Fixed** panic hygiene: all production `unwrap`/`expect` eliminated
  (serializer falls back to empty values) with a CI guard keeping them
  out. (#27)
- **Added** property tests for the untrusted SOAP parser. (#26)

## [v0.4.0] — 2026-09-08

**Added** auth hardening: UsernameToken replay guard (nonce cache +
freshness window), per-source authentication lockout, handler panic
isolation. (#24)

## [v0.3.1] — 2026-09-02

**Changed (breaking)** the server handle is `must_use` — dropping it
stops the server instead of leaking it. (#14)

## [v0.3.0] — 2026-08-31

**Changed (breaking)** library hardening: fail-closed authentication,
neutral discovery identity, XML escaping, graceful shutdown. (#12)

## [v0.2.2] — 2026-08-30

- **Changed** crate renamed to `onvif-device-rs` on crates.io. (#9)
- **Added** crates.io release workflow on `vX.Y.Z` tags (#10); PTZ +
  Imaging self-check demos and a SetPreset body fix (#8); `GetSnapshotUri`
  advertising the host's HTTP snapshot endpoint (#7).
- **Fixed** publish packaging: lockless library (test-generated
  `Cargo.lock` dropped). (#11)

## [v0.2.1] — 2026-08-29

**Added** self-check example and configuration serde contract tests. (#6)

## [v0.2.0] — 2026-08-29

**Added** configurable RTSP stream path in `GetStreamUri`. (#5)

## [v0.1.1] — 2026-08-29

**Fixed** CI verifies the declared MSRV; README git dependency pinned to
tag v0.1.0; naming decision recorded. (#4)

## [v0.1.0] — 2026-08-28

Initial release: ONVIF Device (server) library — SOAP service dispatch,
WS-Discovery responder, GetServices/GetDeviceInformation/GetStreamUri/
GetSnapshotUri, media/imaging/PTZ service sets.

[v0.5.0]: https://github.com/mickeyzzc/onvif-rs/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/mickeyzzc/onvif-rs/compare/v0.3.1...v0.4.0
[v0.3.1]: https://github.com/mickeyzzc/onvif-rs/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/mickeyzzc/onvif-rs/compare/v0.2.2...v0.3.0
[v0.2.2]: https://github.com/mickeyzzc/onvif-rs/compare/v0.2.1...v0.2.2
[v0.2.1]: https://github.com/mickeyzzc/onvif-rs/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/mickeyzzc/onvif-rs/compare/v0.1.1...v0.2.0
[v0.1.1]: https://github.com/mickeyzzc/onvif-rs/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/mickeyzzc/onvif-rs/releases/tag/v0.1.0
