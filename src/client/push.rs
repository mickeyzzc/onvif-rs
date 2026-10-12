//! WS-BaseNotification push receiving (the twin of the Go library's #127
//! batch): subscribe a device's event service to a consumer endpoint,
//! keep the subscription alive, and tear it down — all through the
//! subscription's OWN manager endpoint, the address real devices enforce
//! (not the events service).
//!
//! Envelope shapes derive from the MiBeeNvr production implementation,
//! field-proven against Hikvision, Uniview, TP-Link and the in-house
//! firmware. The consumer HTTP endpoint itself (where the device POSTs
//! wsnt:Notify bodies) is host infrastructure: mount any handler that
//! feeds [`super::notify::parse_notify_events`].
//!
//! The managed [`PushStream`] renews at half the granted TTL with a
//! floor, mirroring the Go twin's `SubscribePushEvents` loop.

use std::time::Duration;

use tokio::sync::watch;

use super::{parse_xsd_datetime, ClientError, SoapClient, UtcStamp};

/// WS-BaseNotification namespace.
pub(crate) const WSNT_NS: &str = "http://docs.oasis-open.org/wsn/b-2";
/// WS-Addressing namespace.
pub(crate) const WSA_NS: &str = "http://www.w3.org/2005/08/addressing";

/// Minimum spacing between managed renewals (default): devices that grant
/// very short terms must not turn the renew loop into a busy cycle.
const DEFAULT_RENEW_FLOOR: Duration = Duration::from_secs(2);

/// The result of a successful push Subscribe.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushSubscription {
    /// Identifies the subscription on the device.
    pub subscription_reference: String,
    /// The endpoint Renew/Unsubscribe must be posted to — the
    /// subscription's own manager, NOT the events service.
    pub manager_address: String,
    /// Granted termination time, when the device reported one.
    pub termination_time: Option<UtcStamp>,
    /// Device-reported current time, when present.
    pub current_time: Option<UtcStamp>,
}

impl SoapClient {
    /// Probe the device's event service with a wsnt:Subscribe for
    /// `consumer_reference` (the HTTP endpoint this host will receive
    /// Notify POSTs on) with a requested `termination`. A sender-side
    /// SOAP fault maps to [`ClientError::PushNotSupported`] so callers
    /// can fall back to the pull-point path.
    pub async fn push_subscribe(
        &self,
        consumer_reference: &str,
        termination: Duration,
    ) -> Result<PushSubscription, ClientError> {
        if consumer_reference.is_empty() {
            return Err(ClientError::InvalidArgument(
                "push subscribe: consumer reference is empty".into(),
            ));
        }
        if termination.is_zero() {
            return Err(ClientError::InvalidArgument(
                "push subscribe: termination must be positive".into(),
            ));
        }

        let body = format!(
            "<wsnt:Subscribe xmlns:wsnt=\"{WSNT_NS}\" xmlns:wsa=\"{WSA_NS}\">\
             <wsnt:ConsumerReference><wsa:Address>{}</wsa:Address></wsnt:ConsumerReference>\
             <wsnt:InitialTerminationTime>{}</wsnt:InitialTerminationTime>\
             </wsnt:Subscribe>",
            crate::types::xml_escape(consumer_reference),
            super::format_xs_duration(termination)
        );

        let resp = match self.device_call(&body).await {
            Ok(r) => r,
            Err(e) if e.is_sender_fault() => {
                let ClientError::Fault { code, reason, .. } = e else {
                    unreachable!("is_sender_fault implies Fault");
                };
                return Err(ClientError::PushNotSupported { code, reason });
            }
            Err(e) => return Err(e),
        };

        parse_subscribe_response(&resp)
    }

    /// Extend the push subscription by posting wsnt:Renew to the
    /// subscription's manager address; returns the newly granted
    /// termination time.
    pub async fn push_renew(
        &self,
        manager_address: &str,
        termination: Duration,
    ) -> Result<UtcStamp, ClientError> {
        if manager_address.is_empty() {
            return Err(ClientError::InvalidArgument(
                "push renew: manager address is empty".into(),
            ));
        }
        if termination.is_zero() {
            return Err(ClientError::InvalidArgument(
                "push renew: termination must be positive".into(),
            ));
        }

        let body = format!(
            "<wsnt:Renew xmlns:wsnt=\"{WSNT_NS}\">\
             <wsnt:TerminationTime>{}</wsnt:TerminationTime></wsnt:Renew>",
            super::format_xs_duration(termination)
        );
        let resp = self.soap_call(manager_address, &body).await?;
        parse_renew_response(&resp)
    }

    /// Terminate the push subscription by posting wsnt:Unsubscribe to the
    /// manager address. Best-effort semantics stay with the caller: the
    /// device reclaims the subscription at its TTL regardless.
    pub async fn push_unsubscribe(&self, manager_address: &str) -> Result<(), ClientError> {
        if manager_address.is_empty() {
            return Err(ClientError::InvalidArgument(
                "push unsubscribe: manager address is empty".into(),
            ));
        }
        let body = format!("<wsnt:Unsubscribe xmlns:wsnt=\"{WSNT_NS}\"></wsnt:Unsubscribe>");
        self.soap_call(manager_address, &body).await?;
        Ok(())
    }

    /// Create a push subscription and manage its lifetime (the twin of
    /// the Go `SubscribePushEvents`): a spawned task renews at half the
    /// granted TTL, floored by `renew_floor` (pass
    /// [`DEFAULT_PUSH_RENEW_FLOOR`] for the production default). A device
    /// refusing push fails fast with [`ClientError::PushNotSupported`] —
    /// fall back to pull-point then. A renewal failure terminates the
    /// stream ([`PushStream::done`] fires); dropping the stream triggers
    /// a best-effort device unsubscribe.
    pub async fn push_subscribe_managed(
        &self,
        consumer_url: &str,
        duration: Duration,
        renew_floor: Duration,
    ) -> Result<PushStream, ClientError> {
        let sub = self.push_subscribe(consumer_url, duration).await?;

        let granted = sub
            .termination_time
            .map(|t| Duration::from_secs((t.unix - unix_now()).max(1) as u64))
            .filter(|g| !g.is_zero())
            .unwrap_or(duration);

        let (stop_tx, stop_rx) = watch::channel(false);
        let (done_tx, done_rx) = watch::channel(false);

        let task = tokio::spawn(renew_loop(
            self.clone(),
            sub.manager_address.clone(),
            duration,
            renew_floor.max(Duration::from_millis(1)),
            granted,
            stop_rx,
            done_tx,
        ));

        Ok(PushStream {
            client: self.clone(),
            manager: sub.manager_address,
            stop_tx,
            done_rx,
            task: Some(task),
        })
    }
}

/// The production renew floor (2 s).
pub const DEFAULT_PUSH_RENEW_FLOOR: Duration = DEFAULT_RENEW_FLOOR;

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn renew_loop(
    client: SoapClient,
    manager: String,
    duration: Duration,
    renew_floor: Duration,
    initial_grant: Duration,
    stop_rx: watch::Receiver<bool>,
    done_tx: watch::Sender<bool>,
) {
    let mut granted = initial_grant;
    let mut stopped = false;
    let mut stop_rx = stop_rx;
    loop {
        let delay = (granted / 2).max(renew_floor);
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = stop_rx.changed() => {
                stopped = *stop_rx.borrow();
                break;
            }
        }
        match client.push_renew(&manager, duration).await {
            Ok(term) => {
                granted = Duration::from_secs((term.unix - unix_now()).max(1) as u64);
            }
            // The subscription is gone or the device refuses; retrying
            // forever would just spam — terminate (done fires).
            Err(_) => break,
        }
    }
    // Dropped (not explicitly unsubscribed): reclaim the server-side
    // subscription so it does not dangle until its TTL.
    if !stopped {
        let _ = client.push_unsubscribe(&manager).await;
    }
    let _ = done_tx.send(true);
}

/// A managed push subscription: the spawned renew loop keeps it alive
/// until [`PushStream::unsubscribe`], a renewal failure, or drop.
pub struct PushStream {
    client: SoapClient,
    manager: String,
    stop_tx: watch::Sender<bool>,
    done_rx: watch::Receiver<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl PushStream {
    /// The manager endpoint the subscription renews on (diagnostics).
    #[must_use]
    pub fn manager_address(&self) -> &str {
        &self.manager
    }

    /// Resolves when the managed loop has fully exited (unsubscribe or
    /// renewal failure). Safe to await any time, including after exit.
    pub async fn done(&self) {
        let mut rx = self.done_rx.clone();
        loop {
            if *rx.borrow() {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Stop the managed loop and best-effort unsubscribe on the device:
    /// the loop is terminated even when the SOAP unsubscribe fails (the
    /// error is returned, cleanup is not blocked by it). Idempotent.
    pub async fn unsubscribe(&mut self) -> Result<(), ClientError> {
        let _ = self.stop_tx.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        self.client.push_unsubscribe(&self.manager).await
    }
}

impl Drop for PushStream {
    fn drop(&mut self) {
        // Detach the loop with stop=false: it wakes, breaks, and performs
        // the best-effort unsubscribe itself — the Go twin's
        // context-death path (cleanup unless explicitly unsubscribed).
        let _ = self.stop_tx.send(false);
        drop(self.task.take());
    }
}

/// Lift SubscriptionReference / SubscriptionManager / times out of a
/// SubscribeResponse (local-name tolerant; same-address devices fall back
/// to the reference for the manager).
fn parse_subscribe_response(resp: &str) -> Result<PushSubscription, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    let mut sub_ref = String::new();
    let mut manager = String::new();
    let mut termination = String::new();
    let mut current = String::new();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                stack.push(super::local_name(&e));
            }
            Ok(XmlEvent::Text(t)) => {
                let text = super::text_content(&t);
                let parent = stack.last().map(String::as_str).unwrap_or("");
                let grandparent = stack.iter().rev().nth(1).map(String::as_str).unwrap_or("");
                match (grandparent, parent) {
                    ("SubscriptionReference", "Address") if sub_ref.is_empty() => {
                        sub_ref = text.trim().to_string();
                    }
                    ("SubscriptionManager", "Address") if manager.is_empty() => {
                        manager = text.trim().to_string();
                    }
                    ("SubscribeResponse", "TerminationTime") => termination = text,
                    ("SubscribeResponse", "CurrentTime") => current = text,
                    _ => {}
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(ClientError::Parse(format!("parse SubscribeResponse: {e}"))),
        }
        buf.clear();
    }

    if sub_ref.is_empty() {
        return Err(ClientError::Parse(
            "parse SubscribeResponse: no SubscriptionReference address".into(),
        ));
    }
    // Plenty of devices expose the same address for both roles.
    let manager = if manager.is_empty() {
        sub_ref.clone()
    } else {
        manager
    };

    Ok(PushSubscription {
        subscription_reference: sub_ref,
        manager_address: manager,
        termination_time: parse_xsd_datetime(&termination).map(|unix| UtcStamp { unix }),
        current_time: parse_xsd_datetime(&current).map(|unix| UtcStamp { unix }),
    })
}

/// Lift the granted termination out of a RenewResponse.
fn parse_renew_response(resp: &str) -> Result<UtcStamp, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut termination = String::new();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                stack.push(super::local_name(&e));
            }
            Ok(XmlEvent::Text(t)) => {
                if stack.last().map(String::as_str) == Some("TerminationTime") {
                    termination = super::text_content(&t);
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(ClientError::Parse(format!("parse RenewResponse: {e}"))),
        }
        buf.clear();
    }

    parse_xsd_datetime(&termination)
        .map(|unix| UtcStamp { unix })
        .ok_or_else(|| ClientError::Parse("parse RenewResponse: no TerminationTime".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBSCRIBE_RESP: &str = r#"<SubscribeResponse xmlns="http://docs.oasis-open.org/wsn/b-2" xmlns:wsa="http://www.w3.org/2005/08/addressing">
<SubscriptionReference><wsa:Address>http://192.168.1.64:80/onvif/Subscription?Idx=27</wsa:Address></SubscriptionReference>
<SubscriptionManager><wsa:Address>http://192.168.1.64:80/onvif/SubscriptionManager?Idx=27</wsa:Address></SubscriptionManager>
<TerminationTime>2026-10-12T09:57:04Z</TerminationTime>
<CurrentTime>2026-10-12T08:57:04Z</CurrentTime>
</SubscribeResponse>"#;

    #[test]
    fn subscribe_response_decode() {
        let sub = parse_subscribe_response(SUBSCRIBE_RESP).unwrap();
        assert_eq!(
            sub.subscription_reference,
            "http://192.168.1.64:80/onvif/Subscription?Idx=27"
        );
        assert_eq!(
            sub.manager_address,
            "http://192.168.1.64:80/onvif/SubscriptionManager?Idx=27"
        );
        assert_eq!(
            sub.termination_time.map(|t| t.to_rfc3339()).as_deref(),
            Some("2026-10-12T09:57:04Z")
        );
        assert_eq!(
            sub.current_time.map(|t| t.to_rfc3339()).as_deref(),
            Some("2026-10-12T08:57:04Z")
        );
    }

    #[test]
    fn manager_falls_back_to_reference() {
        let same = SUBSCRIBE_RESP.replace(
            "http://192.168.1.64:80/onvif/SubscriptionManager?Idx=27",
            "http://192.168.1.64:80/onvif/Subscription?Idx=27",
        );
        let sub = parse_subscribe_response(&same).unwrap();
        assert_eq!(sub.manager_address, sub.subscription_reference);
    }

    #[test]
    fn missing_reference_rejected() {
        assert!(parse_subscribe_response("<SubscribeResponse/>").is_err());
    }

    #[test]
    fn renew_response_decode() {
        let resp = r#"<RenewResponse xmlns="http://docs.oasis-open.org/wsn/b-2">
<TerminationTime>2026-10-12T11:00:00Z</TerminationTime></RenewResponse>"#;
        assert_eq!(
            parse_renew_response(resp).unwrap().to_rfc3339(),
            "2026-10-12T11:00:00Z"
        );
        assert!(parse_renew_response("<RenewResponse/>").is_err());
    }
}
