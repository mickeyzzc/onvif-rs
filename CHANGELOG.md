# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project follows [semantic versioning](https://semver.org/). SOAP wire
goldens are contracts — any golden change is a breaking change.

Releases are capability packages: merges accumulate on `main` silently
and ship with the next tag (merge ≠ release). Only urgent security fixes
are released out of band.

## [Unreleased]

## [0.12.0] — 2026-10-27

### Changed

- **SOAP requests use the canonical compact wire form** (onvif-go #150
  twin): `s:`-prefixed Envelope/Header/Body, compact output, operation
  namespace declarations hoisted onto `s:Body`, and WS-Security
  UsernameToken headers in the conventional `wsse:`/`wsu:` prefixes with
  both declarations on `wsse:Security`. The previous default-namespace
  form was semantically equivalent but is rejected by strict parsers in
  old camera firmware, which answer HTTP 200 with an empty body
  (MiBeeNvr#1074). Response parsing is local-name tolerant and unchanged.

## [0.11.0] — 2026-10-24

The auth-ladder parity package (onvif-go #140/#141 port) plus log-noise
fixes.

- `fix(client)` **auth fallback ladder advances past empty 200 bodies**
  (onvif-go #140 port): old firmwares answer a rejected WS-Security
  digest with HTTP 200 + empty body — no 401, no fault — which stranded
  the ladder on the first rung. Empty bodies now advance the ladder;
  classification keeps them non-auth, so an exhausted ladder surfaces
  the new `ClientError::EmptyBody` (was `Parse("empty response body")`)
  instead of a misleading `Unauthorized`. Auto-skew stays gated on
  auth-class failures. 0.x minor: the enum gains a variant.
- `fix(server)` **client-protocol noise logs at warn, not error**
  (#75): port probes and non-SOAP bytes are warn; real faults stay
  error (mibee-eye-hub #2).
- `fix(examples)` **ptz_demo serve mode works again** (#76): hold the
  server handle (v0.3.0 handle semantics dropped it instantly) and keep
  the motion ticker live in serve mode — the example doubles as the
  zero-procurement ONVIF PTZ head.

### Fixed

- **Auth fallback ladder advances past empty 200 bodies (onvif-go #140
  port).** Old firmwares answer a rejected WS-Security digest with
  HTTP 200 and an empty body — no 401, no fault — which stranded the
  ladder on the first rung and hung `Initialize`. Empty bodies now
  advance the ladder like auth failures do; classification keeps them
  non-auth, so an exhausted ladder surfaces the new
  `ClientError::EmptyBody` (was `Parse("empty response body")`) rather
  than a misleading `Unauthorized`. The auto-skew retry stays gated on
  auth-class failures. 0.x minor: `ClientError` gains a variant.
- **Connection-error log level for client-side protocol noise.** Empty
  connections (port probes), non-SOAP HTTP clients, and malformed
  headers surfaced as `error` in the accept loop; they are a `warn`
  now. Genuine server faults keep the error level. (Reported as
  mibee-eye-hub #2: 11 `Invalid XML: empty request` error lines in 44 h
  were all probes.)

## [0.10.0] — 2026-10-16

Profile audio visibility: `media::Profile` gains the audio source and
encoder configurations (Go-twin parity) — audio-only profiles (network
microphones) are recognizable in `get_profiles` answers. Struct-literal
consumers gain two fields (0.x minor).

- `feat(client)` **Profile audio visibility — audio-only profile parity
  with the Go twin**: `media::Profile` gains `audio_source_configuration`
  and `audio_encoder_configuration` (the types already existed for the
  dedicated getters). A network microphone's audio-only profile — audio
  configs present, no video — is now recognizable in `get_profiles`
  answers (the ONVIF analog of gb28181-go #135). The media2 Profile
  already carried audio configuration refs.

## [0.9.0] — 2026-10-14

The client half — parity with the Go client's breadth: the
dependency-free SOAP-over-TCP client with the auth ladder (four
modes, sticky fallback, auto clock skew), ten service domains, active
and passive discovery, push-subscription management, and the
analytics domain with HTTP Digest transport auth. The server half is
unchanged (additions only).

- `feat(client)` **analytics domain (tan) + HTTP Digest transport auth** —
  the last two Go-client surfaces the sweep had left behind:
  - **`client::analytics`**: the ver20 analytics service behind Profile M —
    capabilities, supported module/rule types with parameter
    descriptions, module/rule instance CRUD
    (`analytics_{get,create,modify,delete}_{analytics_modules,rules}`),
    sample-frame metadata (`analytics_get_supported_metadata`), and the
    vendor parameter-range options (`analytics_get_rule_options` /
    `analytics_get_analytics_module_options`) whose option trees are
    preserved **byte-verbatim** in `inner_xml` (the Go twin's
    `,innerxml` semantics, position-sliced from the response source).
  - **`AuthMode::HttpDigest`** joins the ladder (after HttpBasic): the
    401 `WWW-Authenticate: Digest` challenge is answered with one
    authenticated retry — RFC 7616 MD5 subset (`qop="auth"` when
    offered, legacy no-qop form otherwise), per-nonce nc bookkeeping
    (a server reusing nonces sees the count advance), random cnonce.
    Challenge parsing and the response hash are pinned by the RFC 2617
    §3.5 vector; the wire exchange by an integration test against a
    challenge-issuing fake device (hash re-verified from the header's
    own fields, nc 00000001 → 00000002 on a reused nonce).
- `feat(client)` **auth ladder + full service-domain sweep** — the client
  half grows to real parity with the Go client's breadth:
  - **Auth**: four modes (`AuthMode`: PasswordDigest default /
    PasswordText / HttpBasic / None), a **sticky fallback ladder**
    (`with_auth_fallback`) that walks the modes on auth-class failures
    (HTTP 401/403 or NotAuthorized faults — the new
    `ClientError::Unauthorized` class) and remembers the first one the
    device accepts, **auto clock-skew** (`with_auto_clock_skew`) that
    measures the device clock over the anonymous GetSystemDateAndTime and
    retries once with a corrected `Created`, and **`diagnose_auth`**
    triage (Ok / ClockSkew / BadCredentials with remediation detail).
  - **Service domains** (ports of the Go packages, wire-compatible
    envelopes, local-name tolerant decode): `device` (info/caps/
    hostname/DNS/NTP/network/scopes/users-adjacent surface/storage/DP/
    geo/system log/reboot…), `security` (users + certificates family),
    `media` (profiles, stream URIs + options, snapshot, encoder/audio/OSD
    reads, SelectMain/SelectSub helpers), `media2` (Profile-T family),
    `metadata`, `ptz` (movement/status/presets/home/configs+options/
    nodes/aux/capabilities), `imaging` (settings, focus moves, status,
    presets 18.12), `events_pull` (pull-point client family reusing the
    notify decode), `deviceio` (relays/inputs/serial/audio outputs), and
    `discovery` active probing (multicast Probe sweep, directed HTTP
    probe_endpoint with the GetDeviceInformation fallback, probe_serial
    identity anchor, ParseScopes, FilterONVIF, bounded-concurrency
    enrich_devices).
- `feat(client)` **consumer half — the Go twin's v2.4.0 capability
  package** (client module + discovery listener): a minimal SOAP-over-HTTP
  caller (`SoapClient`: UsernameToken PasswordDigest — the same formula
  the server half verifies — clock-skew correction via `with_clock_skew`,
  per-exchange timeout, SOAP-fault detection regardless of HTTP status)
  with:
  - **Typed device time sync**: `get_device_time` (unauthenticated clock
    read — usable exactly when drifted clocks have broken digest auth;
    pre-2000 clocks rejected), `set_device_time` (Manual write),
    `set_ntp_server` (SetNTP + DateTimeType flip in one call; a flip
    failure keeps the "server configured" state in the error); writes
    fail fast with `ClientError::NoCredentials`.
  - **WS-BaseNotification push receiving**: `push_subscribe` (probe;
    sender faults map to `ClientError::PushNotSupported` for the
    pull-point fallback), `push_renew`/`push_unsubscribe` on the
    subscription's OWN manager endpoint, and the managed
    `push_subscribe_managed` loop (half-TTL renewal, 2 s floor, done
    signal, best-effort unsubscribe on drop).
  - **Notify parsing + motion helpers**: `notify::parse_notify_events`
    decodes device-POSTed wsnt:Notify bodies through the same two-layer
    Message contract as the Go twin (envelope-wrapped and bare-Notify
    root both accepted); `motion::parse_motion_alarm` /
    `is_motion_topic` recognize the two standard motion topics
    (MotionAlarm `State` / CellMotionDetector `IsMotion`) with the full
    field-vector table from the Go twin.
  - **Passive discovery listener** (`discovery_listener`): resident UDP
    :3702 multicast listener for camera power-on Hellos and other
    probes' ProbeMatches, with the built-in ONVIF signal gate (default
    on — non-ONVIF WSD responders are dropped before the handler) and
    configurable Types/Scopes constraints.
  Integration-pinned against this crate's own server: the server
  publishes a MotionAlarm, the client subscribes via wsnt:Subscribe,
  parses the pushed Notify and recognizes it as motion.


## [0.8.0] — 2026-09-29

The service-completion capability package (issues #47–#54 + the
cross-library interop fixes #64/#65): Device/Media/PTZ/Imaging/Events
fuller surfaces, the Media2 (tr2) Profile-T entry path, WS-Subscribe
push notifications, HTTP Digest + IP filter + AccessPolicy, and WSDL
shape fixes for GetServices/GetScopes. Consumed same-day by the
mibee-eye products (v0.5.0 train).

- `fix(device)` **GetServices/GetScopes WSDL shape** (issues #64/#65,
  caught live by cross-library interop — the onvif-go client parses zero
  entries from the old forms): GetServicesResponse now carries its
  `tds:Service` entries as **direct children** (the WSDL sequence — the
  old `tds:Services` wrapper element does not exist in the WSDL, and
  strict stacks read an empty service list); GetScopes answers the WSDL
  `tt:Scope` form — each scope a `tds:Scopes` element with
  `tt:ScopeDef` (`Fixed` for the three built-ins, `Configurable` for
  client-added ones) + `tt:ScopeItem`, replacing the bare
  `tt:ScopeItem` string list. Both are wire changes (goldens updated) —
  spec alignment, twinned with onvif-go's server forms.
- `feat(security)` **Security completion** (issue #54): HTTP Digest
  transport auth (RFC 7616 subset — MD5, `qop="auth"`, opt-in
  `OnvifConfig::http_digest`; coexists with WS-Security, a present
  UsernameToken takes precedence; bounded nonce store with 300 s expiry
  and per-nonce nc advancement — captured `Authorization` headers are
  not replayable); IP address filter (Get/Set/Add/RemoveIPAddressFilter
  over a shared `IpFilterState`, plus per-connection 403 enforcement
  via `OnvifServer::with_ip_filter`; IPv4 prefix entries, Allow/Deny
  modes, unparseable/IPv6 peers fail open with a warning); and
  Get/SetAccessPolicy (opaque Base64 `PolicyFile` blob via
  `with_access_policy` — interpretation is host-side). 802.1X is
  deliberately out of scope (documented: an EAP supplicant is host
  infrastructure, not SOAP protocol). New dependency: `md-5`
  (RustCrypto). Historical responses stay byte-stable — the challenge
  header only appears when `http_digest` is enabled.
- `feat(events)` **basic notification interface** (issue #50):
  `wsnt:Subscribe` on `/onvif/events_service` registers a push
  subscription (ConsumerReference `http://` URL only — https consumers
  are refused; the library carries no TLS client); one sender task per
  subscription POSTs each matching `publish_event` to the consumer as a
  `wsnt:Notify` SOAP document (Topic + inner-message writers shared with
  PullMessages responses; SubscriptionReference named, ProducerReference
  omitted). Delivery is fire-and-forget (5 s connect/IO timeouts); after
  three consecutive failures the subscription is auto-unsubscribed
  (spec-permissible housekeeping). Renew/Unsubscribe operate on the
  returned SubscriptionReference; PullMessages on a push subscription is
  a Sender fault; basic subscriptions share the 10-subscription cap.
  `SetSynchronizationPoint` acks empty on the events endpoint
  (route-based dispatch — no collision with the media action).
  GetEventInstances deliberately stays unimplemented (17.06+ feature,
  zero demand; unknown-action fault answers it). Existing pull-point
  response bytes are unchanged — GetEventProperties already advertises
  both mandatory TopicExpressionDialects, so no dialect line was added.

- `feat(media2)` **Media2 service** (ver20/media, `tr2` — the Profile-T
  entry path, issue #53): `OnvifServer::enable_media2(store,
  keyframe_hook)` routes `/onvif/media2_service` with its own action
  dispatch on the listener the server already owns — the Media2 action
  local names (`GetProfiles`, `GetStreamUri`,
  `SetSynchronizationPoint`, …) collide with Media1 in the shared action
  map, so the URL decides which face answers (the events-service routing
  pattern). Served actions: GetProfiles (optional `Token` filter;
  `tr2:Profiles`/`tr2:Configurations` wrappers with `tt:` configuration
  bodies — the namespace split onvif-go's ns-strict decoder test pins),
  GetStreamUri / GetSnapshotUri (plain `tr2:Uri`; stream tokens resolve
  per extra-profile with fail-open to the primary; `snapshot_port` = 0
  faults), GetVideoEncoderConfigurations (optional ConfigurationToken
  filter) / GetVideoEncoderConfiguration / GetVideoEncoderConfiguration
  Options / **SetVideoEncoderConfiguration** (Media1 partial-update
  semantics on the same `SharedMediaConfig` store — visible to both
  faces; JPEG and unknown encodings fault), GetVideoEncoderInstances
  (`tr2:Info{tr2:Codec[]{tr2:Encoding,tr2:Number}, tr2:Total}`),
  SetSynchronizationPoint (fires the same keyframe hook type
  `register_media_actions` takes), and the Media2 GetServiceCapabilities
  (SnapshotUri follows `snapshot_port`, MaximumNumberOfProfiles =
  advertised count, `RTSPStreaming="true"`). Unknown actions on the path
  are Sender faults; the path 404s while disabled. Auth: write-style
  prefixes (Set*) behind WS-Security, reads open. Advertisement:
  `DeviceServiceHandlers::with_media2_support` (default `false`) appends
  the ver20/media entry to GetServices only — the legacy GetCapabilities
  has no Media2 slot; default-off keeps every existing byte identical.
  Deliberately unimplemented: profile mutation (Create/Add/Remove/
  DeleteProfile — the profile set is host-owned) and multicast streaming
  (advertised off).

- `feat(media)` **Media service completion** (issue #48): new
  `register_media_actions(server, Arc<RwLock<OnvifMediaConfig>>,
  keyframe_hook)` registers the whole service — the four historical
  actions (now reading through the shared store, bytes unchanged) plus
  GetVideoEncoderConfigurations / GetVideoEncoderConfiguration (Sender
  fault on unknown/missing token), GetVideoEncoderConfigurationOptions
  (H264 codec block from the advertised geometry; quality range only
  for H265 — ver10 has no element for it),
  SetVideoEncoderConfiguration (partial updates land in the shared
  store every reader reflects; JPEG and encoding intervals other than 1
  fault as unsupported rather than being silently ignored),
  GetGuaranteedNumberOfVideoEncoderInstances (`TotalNumber` per the
  WSDL), SetSynchronizationPoint (fires the optional host keyframe
  hook), the media GetServiceCapabilities (element names per the ver10
  WSDL; SnapshotUri follows `snapshot_port`), and the empty audio/OSD
  sets (no audio hardware, no OSD engine — honest empty answers).
  StartMulticastStreaming/StopMulticastStreaming stay unimplemented and
  are advertised off. The standalone handler structs keep their
  immutable `Arc<OnvifMediaConfig>` API; existing responses are
  byte-stable.

- `feat(device)` **Device service completion** (issue #49): the
  devicemgmt action set beyond the historical reads — SetSystemDateAndTime
  (parse + `DeviceHooks::set_date_time`, UTC fields required), mutable
  scopes (AddScopes/RemoveScopes/SetScopes on a store seeded with the
  three historical items, so pre-write GetScopes bytes are unchanged;
  texts escaped on output), GetHostname/SetHostname (default name = the
  startup device IP), Get/SetDiscoveryMode, a user directory
  (GetUsers/CreateUsers/DeleteUsers/SetUser — level validation,
  all-or-nothing semantics, passwords never stored or echoed; the
  WS-Security layer stays the authentication source; seed via
  `with_users`), honest network statics (GetDNS, GetNTP,
  GetNetworkInterfaces — empty, GetNetworkDefaultGateway,
  GetNetworkProtocols — the HTTP port actually served),
  GetServiceCapabilities (minimal DeviceServiceCapabilities),
  GetWsdlUrl, GetEndpointReference (documented placeholder zero UUID),
  GetSystemLog/GetSystemSupportInformation (text via
  `DeviceHooks::system_log`/`support_info`), and the protocol-answer-only
  family SetSystemFactoryDefault (fires `DeviceHooks::factory_default`),
  UpgradeSystemFirmware, StartSystemRestore, plus SystemReboot now firing
  `DeviceHooks::reboot` (response bytes unchanged). New
  `DeviceServiceHandlers::with_hooks` installs the host-side effects.
  Deliberately excluded (unknown action → ActionNotSupported): the Set*
  network variants (SetDNS/SetNTP/SetNetworkInterfaces/
  SetNetworkProtocols/SetNetworkDefaultGateway — a library server does
  not mutate the host network stack), the certificate family
  (LoadCertificates/GetCertificates/…), and 802.1X — deferred to future
  Profile T / TLS-server work. Dispatch keeps full-token substring
  matching with writes-before-reads ordering within each family; an
  exhaustive routing test pins every action.
- `feat(ptz)` **PTZ completion** (issue #51): GetConfigurationOptions
  (six coordinate spaces + PTZTimeout), SetConfiguration (stored and
  reflected by GetConfigurations; default bytes unchanged),
  GotoHomePosition/SetHomePosition on the state machine,
  SendAuxiliaryCommand (ack + data echo), GetPTZServiceCapabilities.
  Preset tours stay out (spec-optional; recorded in the issue).
- `feat(imaging)` **Imaging completion** (issue #52): Move (focus via the
  new `ImagingParams::focus_move` seam), Stop, GetMoveOptions,
  GetStatus, GetServiceCapabilities; shared action names route by
  request shape (imaging carries VideoSourceToken / a `timg:` prefix)
  with the previously registered handler as fallback.

- `feat(device)` **per-service advertisement flags** (issue #47):
  `DeviceServiceHandlers` gained `with_media_support` /
  `with_ptz_support` / `with_imaging_support` (default `true`); GetServices
  and GetCapabilities enumerate exactly the services the host serves.
  Defaults keep the historical advertisement byte-for-byte.
- `feat(media)` **multiple media profiles (main + substreams)**: new
  `MediaProfileConfig` type; `OnvifMediaConfig::extra_profiles`
  (default empty) advertises additional profiles in GetProfiles after
  the primary one; GetStreamUri now parses the request's
  `ProfileToken` (namespace- and attribute-tolerant) and maps it to the
  matching profile's `stream_path`, failing open to the primary stream
  for unknown/missing tokens. Single-profile hosts and clients see no
  wire change. `OnvifMediaConfig` gained a public field
  (`extra_profiles`) — struct literals must add it (minor bump).
- Version 0.7.0 → 0.8.0 (additive API + new public field on a public
  struct).

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
