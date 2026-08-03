//! Named properties against a real store.
//!
//! Its own file because it is its own question, and because `live.rs` is at the workspace's
//! 500-line limit.
//!
//! What is worth proving here cannot be proved offline. A fixture shows that *these* ids came back
//! for *those* names once; only a second mailbox shows that the numbers are a fact about one store,
//! and only the inverse ROP shows that the positional pairing this client relies on is the pairing
//! the server meant.

use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use mapi_client::{
    APPOINTMENT_PROPERTIES, CONTACT_PROPERTIES, Exchange, NamedProperty, NamedPropertyEntry,
    NamedPropertyId, Observer, PropertyName, PropertySetId,
};

use crate::{builder, client};

/// Counts the round trips a client makes, which is the only way to prove the cache is a cache.
#[derive(Debug, Default)]
struct RoundTrips(AtomicUsize);

impl Observer for RoundTrips {
    fn observe(&self, _: &Exchange<'_>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// Every property this crate catalogues, resolved and then asked about the other way round.
///
/// The inverse ROP is what makes this more than a self-consistency check.
/// `RopGetPropertyIdsFromNames` answers with a bare array of numbers whose only claim to meaning is
/// the order the server put them in — so feeding each number back through
/// `RopGetNamesFromPropertyIds` and requiring the name that comes out to be the name that went in
/// is the one check that does not come from the answer being checked.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn every_catalogued_property_resolves_and_round_trips() {
    let client = client();
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let mailbox = logon.mailbox().mailbox_guid();

    let resolved = logon
        .resolve_names(NamedProperty::ALL)
        .await
        .expect("RopGetPropertyIdsFromNames");
    let entries: Vec<NamedPropertyEntry> = resolved.iter().cloned().collect();

    println!("named properties in mailbox {mailbox}");
    for (property, entry) in NamedProperty::ALL.into_iter().zip(&entries) {
        println!("  {property:<28} {entry}");
    }

    assert_eq!(entries.len(), NamedProperty::ALL.len());
    for entry in &entries {
        let id = entry
            .id()
            .unwrap_or_else(|| panic!("{} is not registered in this mailbox", entry.name()));
        // [MS-OXCPRPT] §3.1.4.1: the id of a named property has the most significant bit set.
        assert!(id.as_u16() >= 0x8000, "{entry}");
        assert!(id.belongs_to(mailbox), "{entry}");
    }

    // Ask the store what those numbers are, and require the answers to be the questions.
    let ids: Vec<u16> = entries
        .iter()
        .filter_map(|entry| Some(entry.id()?.as_u16()))
        .collect();
    let back = logon
        .names_of(&ids)
        .await
        .expect("RopGetNamesFromPropertyIds");

    assert_eq!(back.len(), ids.len(), "one name per id, in order");
    for (entry, answered) in entries.iter().zip(&back) {
        assert_eq!(
            answered.as_ref(),
            Some(entry.name()),
            "{} resolved to an id the store calls something else",
            entry.name()
        );
    }

    logon.disconnect().await.expect("Disconnect");
}

/// **The measurement the whole binding type exists for.**
///
/// Run this against two mailboxes and compare the printed ids. If they differ, an id carried across
/// mailboxes reads a *different* property with no error anywhere — which is the failure this crate
/// makes unrepresentable by binding the id to the store that issued it.
///
/// What the ids are is a property of the lab and not of the protocol, so nothing here asserts a
/// number. What is asserted is the shape: within one mailbox every property gets a distinct id, so
/// a listing that reported two properties as the same one would be caught.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_stores_ids_are_its_own_and_distinct_within_it() {
    let client = client();
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");

    let resolved = logon
        .resolve_names(NamedProperty::ALL)
        .await
        .expect("RopGetPropertyIdsFromNames");

    let mut ids: Vec<u16> = resolved
        .iter()
        .filter_map(|entry| Some(entry.id()?.as_u16()))
        .collect();
    println!(
        "mailbox {} numbers them {}",
        resolved.store(),
        ids.iter()
            .map(|id| format!("0x{id:04X}"))
            .collect::<Vec<_>>()
            .join(" ")
    );

    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        count,
        "two properties share one id in this store"
    );

    // The LID is not the id. `PidLidLocation` is LID 0x8208 and both lab mailboxes number it
    // something else entirely, so a client that skipped this ROP and used the LID would read a
    // different property and be told nothing.
    let location = resolved
        .get(&NamedProperty::Location.name())
        .map(NamedPropertyId::as_u16);
    assert!(
        location.is_some_and(|id| u32::from(id) != NamedProperty::Location.lid()),
        "this store numbers PidLidLocation as its own LID, which is a coincidence worth recording"
    );

    logon.disconnect().await.expect("Disconnect");
}

/// A name this store has never registered, with the create flag off.
///
/// The answer is `0x0000` **alongside a successful ROP** ([MS-OXCPRPT] §2.2.12.2), which is a
/// refusal reported as a value. Asking twice is what proves the lookup did not register it on the
/// way past — a read that quietly wrote to the store's mapping table would be a poor sort of read.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn an_unregistered_name_is_unmapped_and_stays_that_way() {
    let client = client();
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");

    let invented = PropertyName::named(
        PropertySetId::PUBLIC_STRINGS,
        "mapi-client-rs-no-such-property",
    )
    .expect("a name this crate can carry");

    let entry = logon
        .resolve_names([invented.clone()])
        .await
        .expect("RopGetPropertyIdsFromNames")
        .entry(&invented)
        .cloned()
        .expect("the name that was asked about");
    println!("{entry}");
    assert!(
        !entry.is_mapped(),
        "the server registered a name this client asked it not to create"
    );

    // A second session, so the cache cannot be what is answering.
    let mut again = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    assert!(
        again
            .resolve_names([invented.clone()])
            .await
            .expect("RopGetPropertyIdsFromNames")
            .entry(&invented)
            .is_some_and(|entry| !entry.is_mapped()),
        "the first lookup registered the name after all"
    );

    again.disconnect().await.expect("Disconnect");
    logon.disconnect().await.expect("Disconnect");
}

/// The cache is a cache: the second ask for the same properties sends nothing.
///
/// Worth a test rather than a comment because the cost it avoids is per *read*, not per session — a
/// calendar listing that re-resolved its columns would double its round trips for ever.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn resolving_the_same_names_twice_sends_one_request() {
    let counter = Arc::new(RoundTrips::default());
    let client = builder()
        .observer(Arc::clone(&counter))
        .build()
        .expect("a client");

    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");

    let before = counter.0.load(Ordering::Relaxed);
    logon
        .resolve_names(APPOINTMENT_PROPERTIES)
        .await
        .expect("the appointment properties");
    let after_first = counter.0.load(Ordering::Relaxed);

    logon
        .resolve_names(APPOINTMENT_PROPERTIES)
        .await
        .expect("the same properties again");
    let after_second = counter.0.load(Ordering::Relaxed);

    // A group that overlaps nothing already resolved costs exactly one more.
    logon
        .resolve_names(CONTACT_PROPERTIES)
        .await
        .expect("the contact properties");
    let after_third = counter.0.load(Ordering::Relaxed);

    println!("round trips: {before} -> {after_first} -> {after_second} -> {after_third}");
    assert_eq!(after_first, before + 1, "the first ask is one round trip");
    assert_eq!(after_second, after_first, "the second ask sends nothing");
    assert_eq!(after_third, after_second + 1, "new names cost one");
    assert_eq!(
        logon.names().len(),
        APPOINTMENT_PROPERTIES.len() + CONTACT_PROPERTIES.len()
    );

    logon.disconnect().await.expect("Disconnect");
}

/// Two things at once, and the second is why this test exists.
///
/// An id below `0x8000` is not a named property at all, and the server answers from the `PS_MAPI`
/// set rather than refusing ([MS-OXCPRPT] §2.2.13). An id the store has never registered comes back
/// as a `Kind` of `0xFF` and **nothing else** — no property set, though [MS-OXCDATA] §2.6.1's
/// diagram marks the `GUID` field as not optional. That is the deviation this whole test is here to
/// keep an eye on: the specification's sixteen bytes are not on the wire, and reading them
/// desynchronises whatever follows. Measured on Exchange Server SE `15.02.2562.045`, where the
/// answer to `0xFFFE` framed a 30-byte ROP ending on the `0xFF` itself.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_fixed_id_is_answered_from_ps_mapi_and_an_unknown_one_carries_no_set() {
    let client = client();
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");

    // PidTagSubject's id, and one from the named range that no store is likely to have reached.
    // The unregistered one is second so that a decoder reading the specification's sixteen bytes
    // runs off the end of the buffer rather than quietly returning something.
    let answers = logon
        .names_of([0x0037_u16, 0xFFFE])
        .await
        .expect("RopGetNamesFromPropertyIds");

    for name in &answers {
        println!("{name:?}");
    }
    assert_eq!(answers.len(), 2);

    let subject = answers
        .first()
        .and_then(Option::as_ref)
        .expect("PS_MAPI names the fixed ids");
    assert_eq!(subject.set(), PropertySetId::MAPI, "{subject}");
    assert_eq!(subject.as_lid(), Some(0x0037), "{subject}");

    assert_eq!(
        answers.get(1),
        Some(&None),
        "the measurement this assertion records has changed; re-measure it rather than deleting it"
    );

    logon.disconnect().await.expect("Disconnect");
}
