//! More than one Session Context to one mailbox, side by side.

use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use mapi_client::{APPOINTMENT_PROPERTIES, Exchange, Observer, WellKnownFolder};

/// Counts the round trips a client makes.
#[derive(Debug, Default)]
struct RoundTrips(AtomicUsize);

impl Observer for RoundTrips {
    fn observe(&self, _: &Exchange<'_>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// Two logons through clones of one client read the mailbox at the same time, and the second takes
/// the first one's named properties instead of resolving them again: the ids belong to the store
/// ([MS-OXCPRPT] §3.1.2), and seeding them costs no round trip.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn two_sessions_read_side_by_side_and_share_what_they_resolved() {
    let trips = Arc::new(RoundTrips::default());
    let client = crate::builder()
        .observer(Arc::clone(&trips))
        .build()
        .expect("a client");

    let mut first = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let resolved = first
        .resolve_names(APPOINTMENT_PROPERTIES)
        .await
        .expect("named properties")
        .clone();
    let mut second = client
        .clone()
        .connect()
        .await
        .expect("a second Connect")
        .logon()
        .await
        .expect("a second RopLogon");
    assert_eq!(
        first.mailbox().mailbox_guid(),
        second.mailbox().mailbox_guid()
    );

    let before = trips.0.load(Ordering::Relaxed);
    assert!(second.seed_names(&resolved), "the same mailbox");
    let seeded = second
        .resolve_names(APPOINTMENT_PROPERTIES)
        .await
        .expect("named properties")
        .clone();
    assert_eq!(seeded, resolved);
    assert_eq!(trips.0.load(Ordering::Relaxed), before, "nothing was asked");

    let (one, two) = tokio::join!(
        first
            .well_known(WellKnownFolder::Inbox)
            .expect("the Inbox")
            .contents()
            .collect(),
        second
            .well_known(WellKnownFolder::Inbox)
            .expect("the Inbox")
            .contents()
            .collect(),
    );
    let (one, two) = (one.expect("the first read"), two.expect("the second read"));
    assert_eq!(one.len(), two.len());
    println!(
        "two sessions read {} messages each, side by side",
        one.len()
    );

    first.disconnect().await.expect("Disconnect");
    second.disconnect().await.expect("Disconnect");
}
