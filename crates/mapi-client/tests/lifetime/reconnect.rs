//! Replacing a Session Context with a new one, against the server that destroys the old.

use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use mapi_client::{APPOINTMENT_PROPERTIES, Exchange, Observer, RequestType, WellKnownFolder};

/// Counts the requests of each kind a client makes.
#[derive(Debug, Default)]
struct Requests {
    connects: AtomicUsize,
    executes: AtomicUsize,
}

impl Observer for Requests {
    fn observe(&self, exchange: &Exchange<'_>) {
        let counter = match exchange.request_type() {
            RequestType::Connect => &self.connects,
            RequestType::Execute => &self.executes,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// A reconnect is a `Connect` and a logon, nothing more, and afterwards the logon names the same
/// mailbox, reads it, and answers named properties from what it resolved before — they belong to
/// the store, not to the Session Context ([MS-OXCPRPT] §3.1.2).
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_reconnect_keeps_the_mailbox_and_what_was_resolved_in_it() {
    let requests = Arc::new(Requests::default());
    let client = crate::builder()
        .observer(Arc::clone(&requests))
        .build()
        .expect("a client");
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let mailbox = logon.mailbox().mailbox_guid();
    let resolved = logon
        .resolve_names(APPOINTMENT_PROPERTIES)
        .await
        .expect("named properties")
        .clone();

    let before = (
        requests.connects.load(Ordering::Relaxed),
        requests.executes.load(Ordering::Relaxed),
    );
    logon.reconnect().await.expect("a reconnect");
    assert_eq!(logon.reconnects(), 1);
    assert_eq!(
        (
            requests.connects.load(Ordering::Relaxed),
            requests.executes.load(Ordering::Relaxed)
        ),
        (before.0 + 1, before.1 + 1),
        "one Connect and one logon"
    );
    assert_eq!(logon.mailbox().mailbox_guid(), mailbox);

    let again = logon
        .resolve_names(APPOINTMENT_PROPERTIES)
        .await
        .expect("named properties")
        .clone();
    assert_eq!(again, resolved);
    assert_eq!(
        requests.executes.load(Ordering::Relaxed),
        before.1 + 1,
        "answered from what was resolved before the reconnect"
    );

    let inbox = logon
        .well_known(WellKnownFolder::Inbox)
        .expect("the Inbox")
        .contents()
        .collect()
        .await
        .expect("the Inbox, read through the new Session Context");
    println!(
        "reconnected once; the Inbox reads {} messages through the new context",
        inbox.len()
    );

    logon.disconnect().await.expect("Disconnect");
}
