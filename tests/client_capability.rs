//! Client-half integration tests (the twin of the Go library's v2.4.0
//! push/time-sync wire suites): golden request envelopes against a fake
//! device, manager-endpoint routing, the Sender-fault probe semantics,
//! the managed renew loop — and the full-circle interop where THIS
//! crate's own server publishes a MotionAlarm that THIS crate's client
//! parses back.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use onvif_device_rs::client::{
    motion, notify, push::PushSubscription, time::NtpHost, ClientError, SoapClient, UtcStamp,
};

// ---------------------------------------------------------------------------
// Fake device: sequential SOAP exchanges over real sockets. The dispatch
// closure receives the listener port (so responses can address it back)
// and the request body; every request is captured for assertions.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Captured {
    path: String,
    body: String,
}

enum Reply {
    Ok(String),
    Fault(&'static str),
}

async fn fake_device(
    dispatch: impl Fn(u16, &str) -> Reply + Send + Sync + 'static,
) -> (u16, mpsc::Receiver<Captured>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = mpsc::channel::<Captured>(64);
    let dispatch = Arc::new(dispatch);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let tx = tx.clone();
            let dispatch = Arc::clone(&dispatch);
            tokio::spawn(async move {
                // Read headers, then exactly Content-Length body bytes —
                // real servers respond without waiting for the client's
                // FIN (the client keeps its write side open while reading
                // the response).
                let mut raw = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match sock.read(&mut byte).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            raw.push(byte[0]);
                            if raw.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let head = String::from_utf8_lossy(&raw).to_string();
                let len: usize = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut body_bytes = vec![0u8; len];
                if len > 0 {
                    let _ = sock.read_exact(&mut body_bytes).await;
                }
                let text = format!("{head}{}", String::from_utf8_lossy(&body_bytes));
                let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
                let body = String::from_utf8_lossy(&body_bytes).to_string();
                let _ = tx.try_send(Captured {
                    path,
                    body: body.clone(),
                });
                let response = match dispatch(port, &body) {
                    Reply::Ok(b) => http_200(&b),
                    Reply::Fault(code) => http_200(&fault_body(code)),
                };
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (port, rx)
}

fn http_200(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn fault_body(code: &str) -> String {
    format!(
        r#"<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body><Fault>\
         <Code><Value>{code}</Value></Code><Reason><Text>nope</Text></Reason></Fault>\
         </Body></Envelope>"#
    )
}

fn subscribe_resp(port: u16, manager_path: &str) -> String {
    format!(
        r#"<SubscribeResponse xmlns="http://docs.oasis-open.org/wsn/b-2">\
         <SubscriptionReference><Address>http://127.0.0.1:{port}/onvif/sub?idx=7</Address></SubscriptionReference>\
         <SubscriptionManager><Address>http://127.0.0.1:{port}{manager_path}?idx=7</Address></SubscriptionManager>\
         <TerminationTime>2030-01-01T00:00:00Z</TerminationTime>\
         </SubscribeResponse>"#
    )
}

const RENEW_RESP: &str = r#"<RenewResponse xmlns="http://docs.oasis-open.org/wsn/b-2"><TerminationTime>2030-01-01T00:00:00Z</TerminationTime></RenewResponse>"#;

const CLOCK_RESP: &str = r#"<GetSystemDateAndTimeResponse xmlns="http://www.onvif.org/ver10/device/wsdl">
<SystemDateAndTime><DateTimeType>NTP</DateTimeType><DaylightSavings>false</DaylightSavings>
<TimeZone><TZ>CST-8</TZ></TimeZone>
<UTCDateTime><Time><Hour>7</Hour><Minute>42</Minute><Second>13</Second></Time>
<Date><Year>2026</Year><Month>10</Month><Day>12</Day></Date></UTCDateTime>
<LocalDateTime><Time><Hour>15</Hour><Minute>42</Minute><Second>13</Second></Time>
<Date><Year>2026</Year><Month>10</Month><Day>12</Day></Date></LocalDateTime>
</SystemDateAndTime></GetSystemDateAndTimeResponse>"#;

fn url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{port}{path}")
}

// ---------------------------------------------------------------------------
// Time sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_device_time_decodes_field_response() {
    let (port, mut rx) = fake_device(|_, body| {
        if body.contains("GetSystemDateAndTime") {
            Reply::Ok(CLOCK_RESP.into())
        } else {
            Reply::Fault("s:Sender")
        }
    })
    .await;

    let client = SoapClient::new(&url(port, "/onvif/device_service")).unwrap();
    let t = client.get_device_time().await.unwrap();

    assert_eq!(t.utc.to_rfc3339(), "2026-10-12T07:42:13Z");
    assert_eq!(
        t.local.map(|l| l.to_rfc3339()).as_deref(),
        Some("2026-10-12T15:42:13Z")
    );
    assert_eq!(t.time_zone, "CST-8");
    assert_eq!(t.date_time_type, "NTP");

    let captured = rx.recv().await.unwrap();
    assert!(
        captured.body.contains("tds:GetSystemDateAndTime"),
        "body: {}",
        captured.body
    );
    // Unauthenticated read: no credentials on the client → no Security header.
    assert!(!captured.body.contains("UsernameToken"));
}

#[tokio::test]
async fn set_device_time_wire_and_gate() {
    // Without credentials: fails fast, nothing on the wire.
    {
        let (port, mut rx) = fake_device(|_, _| Reply::Ok("<x/>".into())).await;
        let client = SoapClient::new(&url(port, "/onvif/device_service")).unwrap();
        let err = client
            .set_device_time(UtcStamp::from_components(2026, 10, 12, 7, 42, 13), "CST-8")
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::NoCredentials(_)), "got {err:?}");
        assert!(rx.try_recv().is_err(), "no wire traffic expected");
    }

    // With credentials: the Manual envelope is pinned.
    let (port, mut rx) = fake_device(|_, body| {
        if body.contains("SetSystemDateAndTime") {
            Reply::Ok("<SetSystemDateAndTimeResponse/>".into())
        } else {
            Reply::Fault("s:Sender")
        }
    })
    .await;

    let client = SoapClient::new(&url(port, "/onvif/device_service"))
        .unwrap()
        .with_credentials("admin", "secret");
    client
        .set_device_time(UtcStamp::from_components(2026, 10, 12, 7, 42, 13), "CST-8")
        .await
        .unwrap();

    let captured = rx.recv().await.unwrap();
    for want in [
        "<tds:DateTimeType>Manual</tds:DateTimeType>",
        "<tt:TZ>CST-8</tt:TZ>",
        "<tt:Year>2026</tt:Year>",
        "<tt:Hour>7</tt:Hour><tt:Minute>42</tt:Minute><tt:Second>13</tt:Second>",
    ] {
        assert!(
            captured.body.contains(want),
            "missing {want}:\n{}",
            captured.body
        );
    }
    // Digest credentials ride the header.
    assert!(captured.body.contains("PasswordDigest"));
}

#[tokio::test]
async fn set_ntp_server_two_step() {
    let (port, mut rx) = fake_device(|_, body| {
        if body.contains("tds:SetNTP") {
            Reply::Ok("<SetNTPResponse/>".into())
        } else if body.contains("SetSystemDateAndTime") {
            Reply::Ok("<SetSystemDateAndTimeResponse/>".into())
        } else {
            Reply::Fault("s:Sender")
        }
    })
    .await;

    let client = SoapClient::new(&url(port, "/onvif/device_service"))
        .unwrap()
        .with_credentials("admin", "secret");
    client
        .set_ntp_server(&[NtpHost::ipv4("10.1.1.53"), NtpHost::dns("ntp.example.org")])
        .await
        .unwrap();

    let set_ntp = rx.recv().await.unwrap();
    for want in [
        "<tds:FromDHCP>false</tds:FromDHCP>",
        "<tt:Type>IPv4</tt:Type><tt:IPv4Address>10.1.1.53</tt:IPv4Address>",
        "<tt:Type>DNS</tt:Type><tt:DNSname>ntp.example.org</tt:DNSname>",
    ] {
        assert!(
            set_ntp.body.contains(want),
            "SetNTP missing {want}:\n{}",
            set_ntp.body
        );
    }

    let flip = rx.recv().await.unwrap();
    assert!(
        flip.body
            .contains("<tds:DateTimeType>NTP</tds:DateTimeType>"),
        "flip: {}",
        flip.body
    );

    // Empty host list rejected before the wire.
    assert!(matches!(
        client.set_ntp_server(&[]).await.unwrap_err(),
        ClientError::InvalidArgument(_)
    ));
}

#[tokio::test]
async fn set_ntp_server_flip_failure_keeps_server_state() {
    let (port, _rx) = fake_device(|_, body| {
        if body.contains("tds:SetNTP") {
            Reply::Ok("<SetNTPResponse/>".into())
        } else {
            Reply::Fault("s:Sender") // the mode flip refuses
        }
    })
    .await;

    let client = SoapClient::new(&url(port, "/onvif/device_service"))
        .unwrap()
        .with_credentials("admin", "secret");
    let err = client
        .set_ntp_server(&[NtpHost::ipv4("10.1.1.53")])
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("NTP server configured"),
        "error must convey partial state: {err}"
    );
}

// ---------------------------------------------------------------------------
// Push: wire goldens, manager routing, probe semantics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn push_subscribe_wire_golden_and_manager_routing() {
    // The manager rides a distinct path on the same fake device: the
    // captured renew/unsubscribe requests prove the manager endpoint (not
    // the events service path) got them.
    let (port, mut rx) = fake_device(|p, body| {
        if body.contains("wsnt:Subscribe") {
            Reply::Ok(subscribe_resp(p, "/onvif/subscriptionmanager"))
        } else if body.contains("wsnt:Renew") {
            Reply::Ok(RENEW_RESP.into())
        } else if body.contains("wsnt:Unsubscribe") {
            Reply::Ok("<UnsubscribeResponse/>".into())
        } else {
            Reply::Fault("s:Sender")
        }
    })
    .await;

    let client = SoapClient::new(&url(port, "/onvif/device_service")).unwrap();

    let sub: PushSubscription = client
        .push_subscribe(
            "http://192.168.1.10:8080/api/onvif/notify",
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
    assert_eq!(
        sub.subscription_reference,
        format!("http://127.0.0.1:{port}/onvif/sub?idx=7")
    );
    assert_eq!(
        sub.manager_address,
        format!("http://127.0.0.1:{port}/onvif/subscriptionmanager?idx=7")
    );

    let captured = rx.recv().await.unwrap();
    assert_eq!(captured.path, "/onvif/device_service");
    for want in [
        "<wsnt:Subscribe",
        "<wsnt:ConsumerReference><wsa:Address>http://192.168.1.10:8080/api/onvif/notify</wsa:Address>",
        "<wsnt:InitialTerminationTime>PT60M</wsnt:InitialTerminationTime>",
    ] {
        assert!(captured.body.contains(want), "subscribe missing {want}:\n{}", captured.body);
    }

    // Renew posts to the MANAGER endpoint.
    let term = client
        .push_renew(&sub.manager_address, Duration::from_secs(3600))
        .await
        .unwrap();
    assert_eq!(term.to_rfc3339(), "2030-01-01T00:00:00Z");
    let renew = rx.recv().await.unwrap();
    assert!(
        renew.path.starts_with("/onvif/subscriptionmanager"),
        "path: {}",
        renew.path
    );
    assert!(renew.body.contains("<wsnt:Renew"), "renew: {}", renew.body);
    assert!(renew
        .body
        .contains("<wsnt:TerminationTime>PT60M</wsnt:TerminationTime>"));

    // Unsubscribe to the manager too.
    client.push_unsubscribe(&sub.manager_address).await.unwrap();
    let unsub = rx.recv().await.unwrap();
    assert!(
        unsub.path.starts_with("/onvif/subscriptionmanager"),
        "path: {}",
        unsub.path
    );
    assert!(
        unsub.body.contains("<wsnt:Unsubscribe"),
        "unsub: {}",
        unsub.body
    );
}

#[tokio::test]
async fn push_probe_sender_fault_is_push_not_supported() {
    let (port, _rx) = fake_device(|_, _| Reply::Fault("s:Sender")).await;
    let client = SoapClient::new(&url(port, "/onvif/device_service")).unwrap();

    let err = client
        .push_subscribe("http://nvr/notify", Duration::from_secs(60))
        .await
        .unwrap_err();
    assert!(err.is_push_not_supported(), "got {err:?}");

    // Receiver faults are real failures, not the probe signal.
    let (port2, _rx2) = fake_device(|_, _| Reply::Fault("s:Receiver")).await;
    let client2 = SoapClient::new(&url(port2, "/onvif/device_service")).unwrap();
    let err2 = client2
        .push_subscribe("http://nvr/notify", Duration::from_secs(60))
        .await
        .unwrap_err();
    assert!(!err2.is_push_not_supported(), "got {err2:?}");
}

#[tokio::test]
async fn push_managed_stream_renews_and_stops() {
    let renews = Arc::new(AtomicU32::new(0));
    let unsubscribes = Arc::new(AtomicU32::new(0));
    let (renew_counter, unsub_counter) = (Arc::clone(&renews), Arc::clone(&unsubscribes));

    let (port, _rx) = fake_device(move |p, body| {
        if body.contains("wsnt:Subscribe") {
            // Termination already in the past → the loop renews every floor.
            let soon = UtcStamp { unix: 1 }.to_rfc3339();
            Reply::Ok(
                subscribe_resp(p, "/onvif/subscriptionmanager")
                    .replace("2030-01-01T00:00:00Z", &soon),
            )
        } else if body.contains("wsnt:Renew") {
            renew_counter.fetch_add(1, Ordering::SeqCst);
            let soon = UtcStamp { unix: 1 }.to_rfc3339();
            Reply::Ok(RENEW_RESP.replace("2030-01-01T00:00:00Z", &soon))
        } else if body.contains("wsnt:Unsubscribe") {
            unsub_counter.fetch_add(1, Ordering::SeqCst);
            Reply::Ok("<UnsubscribeResponse/>".into())
        } else {
            Reply::Fault("s:Sender")
        }
    })
    .await;

    let client = SoapClient::new(&url(port, "/onvif/device_service")).unwrap();
    let mut stream = client
        .push_subscribe_managed(
            "http://nvr/notify",
            Duration::from_millis(200),
            Duration::from_millis(30),
        )
        .await
        .unwrap();

    // Bounded wait: ≥2 renewals inside the window.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while renews.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        renews.load(Ordering::SeqCst) >= 2,
        "renews: {}",
        renews.load(Ordering::SeqCst)
    );

    stream.unsubscribe().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), stream.done())
        .await
        .expect("done resolves");
    assert_eq!(
        unsubscribes.load(Ordering::SeqCst),
        1,
        "exactly one device unsubscribe"
    );
}

// ---------------------------------------------------------------------------
// Full circle: this crate's own SERVER publishes; this crate's CLIENT
// parses back (the twin of mibee-eye-go's MotionAlarm interop pin).
// ---------------------------------------------------------------------------

mod interop {
    use super::*;

    use onvif_device_rs::config::DeviceConfig;
    use onvif_device_rs::device::{DeviceHandler, DeviceServiceHandlers};
    use onvif_device_rs::events::{Event, EventsService, SimpleItem, EVENTS_SERVICE_PATH};
    use onvif_device_rs::server::{OnvifConfig, OnvifServer, OnvifServerHandle};

    /// wsnt consumer on an ephemeral port: captures Notify POST bodies.
    async fn consumer() -> (u16, mpsc::Receiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("consumer bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel::<String>(16);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut raw = Vec::new();
                    let _ = sock.read_to_end(&mut raw).await;
                    let text = String::from_utf8_lossy(&raw).to_string();
                    let body = text[text.find("\r\n\r\n").map(|p| p + 4).unwrap_or(text.len())..]
                        .to_string();
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = sock.shutdown().await;
                    let _ = tx.send(body).await;
                });
            }
        });
        (port, rx)
    }

    async fn events_server() -> (u16, Arc<EventsService>) {
        let mut server = OnvifServer::new(&OnvifConfig {
            port: 0,
            username: "admin".into(),
            password: "password".into(),
            support_events: true,
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let device = Arc::new(
            DeviceServiceHandlers::new(
                DeviceConfig {
                    name: "Interop Cam".into(),
                    manufacturer: "MiBee".into(),
                    model: "IMX219".into(),
                    firmware: "1.0.0".into(),
                    hardware_id: "HW-1".into(),
                    serial_number: "SN-1".into(),
                },
                port,
                "127.0.0.1".to_string(),
            )
            .expect("identity")
            .with_events_support(true),
        );
        for action in ["GetSystemDateAndTime", "GetCapabilities"] {
            server.register_anonymous_action(action);
            server.register_handler(action, Box::new(DeviceHandler(Arc::clone(&device))));
        }
        let events = server.enable_events();
        let handle: OnvifServerHandle = server.start_on(listener).await.expect("start");
        // Leaked for the test's lifetime (shutdown in a test teardown hook
        // is not worth the plumbing; the process exits with the test).
        std::mem::forget(handle);
        (port, events)
    }

    /// Server publishes MotionAlarm → Notify POST → client parses →
    /// motion helper recognizes it.
    #[tokio::test]
    async fn published_motion_alarm_parses_through_client() {
        let (server_port, events) = events_server().await;
        let (consumer_port, mut rx) = consumer().await;

        let client = SoapClient::new(&format!(
            "http://127.0.0.1:{server_port}{EVENTS_SERVICE_PATH}"
        ))
        .unwrap();
        let sub = client
            .push_subscribe(
                &format!("http://127.0.0.1:{consumer_port}/notify"),
                Duration::from_secs(600),
            )
            .await
            .expect("subscribe against this crate's own server");
        assert!(!sub.subscription_reference.is_empty());

        events.publish_event(Event {
            topic: "tns1:VideoSource/MotionAlarm".into(),
            source: vec![SimpleItem::new("Source", "0")],
            data: vec![
                SimpleItem::new("State", "true"),
                SimpleItem::new("Targets", "3"),
            ],
            ..Event::new("tns1:VideoSource/MotionAlarm")
        });

        let notify = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("Notify POST arrives")
            .expect("consumer channel open");

        let msgs = notify::parse_notify_events(&notify).expect("parse the real Notify");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].topic, "tns1:VideoSource/MotionAlarm");

        let alarm = motion::parse_motion_alarm(&msgs[0]).expect("motion helper recognizes it");
        assert!(alarm.active);
        assert_eq!(alarm.source, "0");

        // And the clock: this crate's own server serves the unauthenticated
        // read on the DEVICE service path (the events path only routes
        // events actions).
        let device_client = SoapClient::new(&format!(
            "http://127.0.0.1:{server_port}/onvif/device_service"
        ))
        .unwrap();
        let t = device_client
            .get_device_time()
            .await
            .expect("GetSystemDateAndTime from own server");
        assert!(
            t.utc.unix > 1_600_000_000,
            "usable clock, got {}",
            t.utc.to_rfc3339()
        );
    }
}

// ---------------------------------------------------------------------------
// HTTP Digest transport auth: a challenge-issuing fake device pins the
// 401 → Authorization: Digest → 200 exchange, the response hash, and the
// nonce-count bookkeeping when the server REUSES a nonce.
// ---------------------------------------------------------------------------

fn md5_hex(s: &str) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(s.as_bytes());
    let out = h.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

fn header_param<'a>(header: &'a str, key: &str) -> &'a str {
    let needle = format!("{key}=");
    let idx = header.find(&needle).expect("param in header") + needle.len();
    let rest = &header[idx..];
    let end = rest.find(',').unwrap_or(rest.len());
    rest[..end].trim().trim_matches('"')
}

#[tokio::test]
async fn http_digest_mode_answers_the_challenge() {
    use std::sync::Mutex;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let sink = Arc::clone(&requests);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let sink = Arc::clone(&sink);
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match sock.read(&mut byte).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            raw.push(byte[0]);
                            if raw.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let head = String::from_utf8_lossy(&raw).to_string();
                let len: usize = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; len];
                if len > 0 {
                    let _ = sock.read_exact(&mut body).await;
                }
                let full = format!("{head}{}", String::from_utf8_lossy(&body));

                // The twin server's exact challenge format; the nonce is
                // deliberately REUSED so the nc bookkeeping is observable.
                let response = if full.contains("Authorization: Digest") {
                    let body = format!(
                        "<Envelope xmlns=\"http://www.w3.org/2003/05/soap-envelope\"><Body>{CLOCK_RESP}</Body></Envelope>"
                    );
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"onvif\", nonce=\"n-1\", qop=\"auth\", algorithm=MD5, stale=FALSE, opaque=\"op-1\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                };

                sink.lock().expect("sink").push(full);
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    let client = SoapClient::new(&format!("http://127.0.0.1:{port}/onvif/device_service"))
        .expect("client")
        .with_credentials("admin", "2022")
        .with_auth_mode(onvif_device_rs::client::AuthMode::HttpDigest);

    client.get_device_time().await.expect("digest exchange");

    let captured = requests.lock().expect("sink").clone();
    assert_eq!(captured.len(), 2, "anonymous probe + authenticated retry");
    assert!(
        !captured[0].contains("Authorization"),
        "probe carries no credentials"
    );
    let authed_line = captured[1]
        .lines()
        .find(|l| l.starts_with("Authorization: Digest"))
        .expect("digest header on retry");
    let header = authed_line.trim_start_matches("Authorization: ");
    assert_eq!(header_param(header, "username"), "admin");
    assert_eq!(header_param(header, "realm"), "onvif");
    assert_eq!(header_param(header, "nc"), "00000001");
    let cnonce = header_param(header, "cnonce").to_string();
    let response = header_param(header, "response").to_string();

    // The response hash is verifiable from the header's own fields.
    let ha1 = md5_hex("admin:onvif:2022");
    let ha2 = md5_hex("POST:/onvif/device_service");
    let expected = md5_hex(&format!("{ha1}:n-1:00000001:{cnonce}:auth:{ha2}"));
    assert_eq!(response, expected, "RFC 7616 MD5 qop=auth response");

    // A second call against the SAME reused nonce must advance nc.
    client.get_device_time().await.expect("second exchange");
    let captured = requests.lock().expect("sink").clone();
    assert_eq!(captured.len(), 4);
    let second = captured[3]
        .lines()
        .find(|l| l.starts_with("Authorization: Digest"))
        .expect("second digest header");
    assert_eq!(
        header_param(second.trim_start_matches("Authorization: "), "nc"),
        "00000002"
    );
}
