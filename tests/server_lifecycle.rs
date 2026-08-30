//! Server lifecycle integration tests: fail-closed auth, graceful shutdown,
//! listener injection, and request-size limits (v0.3.0 regressions).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use onvif_device_rs::server::{OnvifActionHandler, OnvifConfig, OnvifServer};
use onvif_device_rs::types::{OnvifError, RequestInfo};

struct OkHandler;
#[async_trait]
impl OnvifActionHandler for OkHandler {
    async fn handle(&self, _body: &str, _info: &RequestInfo) -> Result<String, OnvifError> {
        Ok("<OkResponse/>".to_string())
    }
}

fn config(password: &str) -> OnvifConfig {
    OnvifConfig {
        port: 0,
        username: "admin".to_string(),
        password: password.to_string(),
        ..Default::default()
    }
}

async fn free_listener() -> tokio::net::TcpListener {
    tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind")
}

/// Regression: an empty password with the default `allow_no_auth = false`
/// must FAIL to start (previously it silently disabled authentication for
/// every action).
#[tokio::test]
async fn empty_password_fails_closed() {
    let mut server = OnvifServer::new(&config(""));
    server.register_handler("GetProfiles", Box::new(OkHandler));
    let listener = free_listener().await;
    let err = server
        .start_on(listener)
        .await
        .expect_err("empty password must fail closed");
    assert!(err.to_string().contains("allow_no_auth"), "got: {err}");
}

/// The explicit `allow_no_auth = true` opt-in still works (documented open
/// server).
#[tokio::test]
async fn allow_no_auth_opt_in_works() {
    let cfg = OnvifConfig {
        allow_no_auth: true,
        ..config("")
    };
    let mut server = OnvifServer::new(&cfg);
    server.register_handler("GetProfiles", Box::new(OkHandler));
    let listener = free_listener().await;
    let mut handle = server
        .start_on(listener)
        .await
        .expect("starts when opted in");
    handle.shutdown().await.expect("clean shutdown");
}

/// Regression: graceful shutdown stops the accept loop — the port is
/// released and the handle's task finishes.
#[tokio::test]
async fn shutdown_stops_accept_loop_and_releases_port() {
    let mut server = OnvifServer::new(&config("secret"));
    server.register_handler("GetProfiles", Box::new(OkHandler));
    let listener = free_listener().await;
    let port = listener.local_addr().expect("addr").port();
    let mut handle = server.start_on(listener).await.expect("start");

    tokio::time::timeout(Duration::from_secs(3), handle.shutdown())
        .await
        .expect("shutdown within 3s")
        .expect("join ok");

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err(),
        "port must be released after shutdown"
    );
}

/// End-to-end over a real socket: authenticated action rejects bad
/// credentials with 401 and serves good ones with 200.
#[tokio::test]
async fn auth_enforced_over_the_wire() -> anyhow::Result<()> {
    let mut server = OnvifServer::new(&config("secret"));
    server.register_handler("GetProfiles", Box::new(OkHandler));
    let listener = free_listener().await;
    let port = listener.local_addr()?.port();
    let mut handle = server.start_on(listener).await?;

    let envelope = |user: &str, pass: &str| {
        format!(
            "<Envelope xmlns=\"http://www.w3.org/2003/05/soap-envelope\"><Header><Security xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><UsernameToken><Username>{user}</Username><Password>{pass}</Password></UsernameToken></Security></Header><Body><GetProfiles/></Body></Envelope>"
        )
    };

    let post = |body: String| async move {
        let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        let req = format!(
            "POST /onvif/device_service HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        sock.write_all(req.as_bytes()).await?;
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).await?;
        let head = String::from_utf8_lossy(&buf);
        Ok::<_, std::io::Error>(
            head.lines()
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_string(),
        )
    };

    assert_eq!(post(envelope("admin", "wrong")).await?, "401");
    assert_eq!(post(envelope("admin", "secret")).await?, "200");
    handle.shutdown().await?;
    Ok(())
}

/// Regression: a body larger than `max_body_bytes` is rejected with 413
/// instead of being buffered without bound.
#[tokio::test]
async fn oversized_body_rejected() -> anyhow::Result<()> {
    let cfg = OnvifConfig {
        max_body_bytes: 1024,
        ..config("secret")
    };
    let mut server = OnvifServer::new(&cfg);
    server.register_handler("GetProfiles", Box::new(OkHandler));
    let listener = free_listener().await;
    let port = listener.local_addr()?.port();
    let mut handle = server.start_on(listener).await?;

    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let body = "A".repeat(4096);
    let req = format!(
        "POST /onvif/device_service HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    sock.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await?;
    let status = String::from_utf8_lossy(&buf);
    assert!(
        status.starts_with("HTTP/1.1 413"),
        "expected 413, got: {}",
        status.lines().next().unwrap_or_default()
    );
    handle.shutdown().await?;
    Ok(())
}

/// Handler trait object stays usable behind the shared Arc (compile-level
/// smoke — keeps the public seam explicit).
#[test]
fn handler_trait_is_object_safe() {
    let _h: Box<dyn OnvifActionHandler> = Box::new(OkHandler);
    let _ = Arc::new(OkHandler);
}
