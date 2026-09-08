# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project follows [semantic versioning](https://semver.org/). SOAP wire
goldens are contracts — any golden change is a breaking change.

Releases are capability packages: merges accumulate on `main` silently
and ship with the next tag (merge ≠ release). Only urgent security fixes
are released out of band.

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
