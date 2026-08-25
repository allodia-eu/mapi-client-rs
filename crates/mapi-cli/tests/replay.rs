//! Replaying the committed corpus through the real client.
//!
//! CI never sees an Exchange server, so `fixtures/` is the only thing standing between CI and a
//! false green. These tests are what turn that corpus from a pile of bytes into a claim CI can
//! check, and they make two of them:
//!
//! * **What we send is what a real server accepted.** Every request body the client produces is
//!   compared byte for byte against the one that was actually sent to Exchange when the corpus was
//!   captured. A change to any ROP encoding shows up here as a byte difference rather than as a
//!   surprise against a live server months later.
//! * **What the server sent still decodes.** Each recorded response is fed back, in order, through
//!   the whole stack — transport, session, ROP decoder, row decoder — with nothing stubbed but the
//!   socket.
//!
//! Two mailboxes, deliberately. Folder names in a mailbox are localised to the language it was
//! provisioned with, so `Postvak IN` is what a Dutch mailbox calls its Inbox, and a corpus
//! captured from one locale proves nothing about another. Both are replayed here, and the Inbox is
//! identified by the folder id a logon reported rather than by its name — which is the only way
//! that works in both.
//!
//! These live in `mapi-cli` rather than in `mapi-proto` or `mapi-client` because this is the crate
//! that *produces* the corpus, and because it is never published: the fixtures are a workspace
//! artefact, and a test that reads them has no business shipping to crates.io.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a test that walks a captured layout by offset is asserting something true about it"
)]

mod corpus;
mod items;
mod replayed;
mod writes;

use std::sync::{Arc, Mutex};

use mapi_client::{
    Credentials, FOLDER_PROPERTIES, FolderId, Lcid, Logon, MAILBOX_PROPERTIES, MapiClient,
    NamedProperties, NamedProperty, PropertyName, PropertyRow, PropertySet, PropertySetId,
    PropertyTag, PropertyValue, SpecialFolder, SpecialFolders, TableString, TaggedValue,
    WellKnownFolder,
};

use crate::corpus::{assert_requests_match, fixtures, scenario, server, user_dn};
use crate::replayed::Replayed;

/// The page sizes `mapi-cli capture` used, and therefore the ones a replay has to use for the
/// requests to match byte for byte.
const HIERARCHY_PAGE: u16 = 8;
const CONTENTS_PAGE: u16 = 2;
const DEEP_PAGE: u16 = 20;

/// How many exchanges one captured session holds: `PING`, `Connect`, the logon, two property
/// exchanges, both halves of the named-property lookup, two hierarchy pages and a release, two deep
/// pages and a release, the two halves of the entry-id chain, the Calendar's properties, four
/// contents pages and a release, and the `Disconnect` — which is `01-ping` through `22-disconnect`
/// in either session directory.
const SESSION_EXCHANGES: usize = 22;

/// How many exchanges one captured item session holds, and one captured write session.
///
/// Named here as well as in the two modules that replay them because this is the file that counts
/// the whole corpus against the manifest, and a scenario nothing counts is one a stale directory
/// can hide in.
const ITEM_EXCHANGES: usize = 27;
const WRITE_EXCHANGES: usize = 18;

/// The comment `mapi-cli capture` tried to set on the Store object, and which Exchange refused.
/// Same reason as the page sizes: the request bodies only match if the replay sends the same
/// value.
const COMMENT_PROBE: &str = "mapi-client-rs probe";

/// The name, the fixed id and the unregistered id `mapi-cli capture` asked about, for the same
/// reason again — a replay that asked about anything else would send different bytes.
const UNREGISTERED_NAME: &str = "mapi-client-rs-no-such-property";
const FIXED_ID: u16 = 0x0037;
const UNREGISTERED_ID: u16 = 0xFFFE;

/// Drives one captured session, then checks every request body against the corpus.
///
/// The sequence mirrors `mapi-cli capture` exactly, because that is what produced the corpus: a
/// `PING`, a `Connect`, a logon, a paged hierarchy read, a paged contents read, and a
/// `Disconnect`.
async fn replay(name: &str, locale: Lcid) -> Replayed {
    let exchanges = scenario(name);
    let server = server(&exchanges).await;

    let client = MapiClient::builder()
        .endpoint(format!("{}/mapi/emsmdb/", server.uri()))
        .user_dn(user_dn(&exchanges))
        .credentials(Credentials::basic("replay@example.test", "hunter2"))
        .locale(locale)
        .danger_allow_plaintext_http()
        .build()
        .expect("a client");

    client.ping().await.expect("PING");

    let connection = client.connect().await.expect("Connect");
    let display_name = connection.server().display_name().to_owned();

    let mut logon = connection.logon().await.expect("RopLogon");
    let folder_ids = logon.mailbox().folder_ids().to_vec();
    let inbox = logon.folder_id(WellKnownFolder::Inbox).expect("an Inbox");
    let subtree = logon
        .folder_id(WellKnownFolder::IpmSubtree)
        .expect("the IPM subtree");

    let mailbox = logon
        .store()
        .read(MAILBOX_PROPERTIES)
        .await
        .expect("the Store object's properties");

    let refused = logon
        .store()
        .write(&[TaggedValue::new(
            PropertyTag::COMMENT,
            PropertyValue::String(COMMENT_PROBE.into()),
        )
        .expect("a string tag carrying a string")])
        .await
        .expect("RopSetProperties itself succeeds");

    let (named, named_back) = named_properties(&mut logon).await;

    let mut rows = logon
        .folder(subtree)
        .subfolders()
        .page_size(HIERARCHY_PAGE)
        .rows();
    let mut folders = Vec::new();
    while let Some(row) = rows.try_next().await.expect("a page of folders") {
        folders.push((
            row.folder_id().expect("a folder id"),
            row.string(PropertyTag::DISPLAY_NAME)
                .map(TableString::as_str)
                .unwrap_or_default()
                .to_owned(),
        ));
    }
    let folder_count = rows.row_count();
    rows.close().await.expect("releasing the hierarchy table");

    let (descendants, special, calendar_properties) = folder_tree(&mut logon, subtree).await;

    let mut rows = logon
        .well_known(WellKnownFolder::Inbox)
        .expect("the Inbox")
        .contents()
        .page_size(CONTENTS_PAGE)
        .rows();
    let mut messages = Vec::new();
    while let Some(row) = rows.try_next().await.expect("a page of messages") {
        let subject = row.string(PropertyTag::SUBJECT);
        messages.push((
            subject
                .map(TableString::as_str)
                .unwrap_or_default()
                .to_owned(),
            subject.is_some_and(TableString::is_truncated),
        ));
    }
    let message_count = rows.row_count();
    rows.close().await.expect("releasing the contents table");

    logon.disconnect().await.expect("Disconnect");

    assert_requests_match(&server, &exchanges).await;

    Replayed {
        display_name,
        folder_ids,
        inbox,
        subtree,
        mailbox,
        refused,
        named,
        named_back,
        folders,
        folder_count,
        descendants,
        special,
        calendar_properties,
        messages,
        message_count,
    }
}

/// The named-property half of a captured session: every name this crate catalogues plus one no
/// store has registered, then the ids that came back plus two the client never resolved.
///
/// The order and the extras are not free choices — they are what `mapi-cli capture` sent, and the
/// request bodies are compared byte for byte.
async fn named_properties(logon: &mut Logon) -> (NamedProperties, Vec<Option<PropertyName>>) {
    let unregistered = PropertyName::named(PropertySetId::PUBLIC_STRINGS, UNREGISTERED_NAME)
        .expect("a name this crate can carry");
    let mut wanted: Vec<PropertyName> = NamedProperty::ALL.iter().map(|p| p.name()).collect();
    wanted.push(unregistered);

    let named = logon
        .resolve_names(wanted)
        .await
        .expect("RopGetPropertyIdsFromNames")
        .clone();

    let mut ids: Vec<u16> = named
        .iter()
        .filter_map(|entry| Some(entry.id()?.as_u16()))
        .collect();
    ids.push(FIXED_ID);
    ids.push(UNREGISTERED_ID);

    let back = logon
        .names_of(&ids)
        .await
        .expect("RopGetNamesFromPropertyIds");
    (named, back)
}

/// The special-folder half of a captured session: the recursive read, the entry-id chain, and the
/// properties of the folder that chain found.
async fn folder_tree(
    logon: &mut Logon,
    subtree: FolderId,
) -> (Vec<PropertyRow>, SpecialFolders, PropertySet) {
    // The same folder as the read above, with the `Depth` bit set: every folder below the subtree,
    // at every level, in one table.
    let mut rows = logon
        .folder(subtree)
        .descendants()
        .page_size(DEEP_PAGE)
        .rows();
    let mut descendants = Vec::new();
    while let Some(row) = rows.try_next().await.expect("a page of descendants") {
        descendants.push(row);
    }
    rows.close().await.expect("releasing the deep table");

    let special = logon
        .special_folders()
        .await
        .expect("the entry-id chain on the Inbox");
    let calendar = special
        .get(SpecialFolder::Calendar)
        .expect("a Calendar folder");
    let calendar_properties = logon
        .folder(calendar)
        .properties()
        .read(FOLDER_PROPERTIES)
        .await
        .expect("the Calendar's own properties");

    (descendants, special, calendar_properties)
}

/// The en-US mailbox: the corpus everything else is compared against.
#[tokio::test]
async fn an_en_us_session_replays_byte_for_byte() {
    let replayed = replay("session-en-us", Lcid::EN_US).await;
    replayed.assert_shape_is_a_mailbox(7);

    assert_eq!(replayed.display_name, "Developer User");
    assert_eq!(replayed.folder(replayed.inbox), "Inbox");
    assert!(
        replayed
            .folders
            .iter()
            .any(|(_, name)| name == "Sent Items"),
        "{:?}",
        replayed.folders
    );
}

/// The nl-NL mailbox, which is why there are two.
///
/// Folder names are a property of the mailbox, not of the session: this one was provisioned in
/// Dutch and its Inbox is called `Postvak IN`. A client that looked folders up by name would work
/// perfectly against the mailbox above and return nothing at all against this one.
#[tokio::test]
async fn an_nl_nl_session_replays_with_localised_folder_names() {
    let replayed = replay("session-nl-nl", Lcid::new(0x0413)).await;
    replayed.assert_shape_is_a_mailbox(7);

    assert_eq!(replayed.display_name, "Developer User 2");
    assert_eq!(replayed.folder(replayed.inbox), "Postvak IN");

    for dutch in ["Verzonden items", "Verwijderde items", "Ongewenste e-mail"] {
        assert!(
            replayed.folders.iter().any(|(_, name)| name == dutch),
            "{dutch} is missing from {:?}",
            replayed.folders
        );
    }

    // A subject with characters outside ASCII, which is what proves the UTF-16LE decode rather
    // than a run of bytes that happens to look right either way.
    assert!(
        replayed
            .messages
            .iter()
            .any(|(subject, _)| subject.contains("café") && subject.contains("Zoë")),
        "{:?}",
        replayed.messages
    );
    assert!(
        replayed
            .messages
            .iter()
            .any(|(subject, _)| subject.contains('\u{1F600}')),
        "a surrogate pair survives the decode: {:?}",
        replayed.messages
    );
}

/// The refusal, which is the shape no HTTP-level check would catch: HTTP 200, `X-ResponseCode: 0`,
/// and a non-zero `ErrorCode` inside the response body.
///
/// [MS-OXCMAPIHTTP] §2.2.4.1.3 — `Connect` failure response body
#[tokio::test]
async fn a_refused_connect_replays_as_a_refusal() {
    let exchanges = scenario("connect-refused");
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0].status, 200, "the refusal arrives as a success");

    let server = server(&exchanges).await;
    let client = MapiClient::builder()
        .endpoint(format!("{}/mapi/emsmdb/", server.uri()))
        .user_dn(user_dn(&exchanges))
        .credentials(Credentials::basic("replay@example.test", "hunter2"))
        .danger_allow_plaintext_http()
        .build()
        .expect("a client");

    let error = client
        .connect()
        .await
        .expect_err("the server refused this name");
    let message = error.to_string();
    assert!(message.contains("UnknownUser"), "{message}");
    // The distinguished name it refused is named, which is the thing that turns an hour of
    // credential debugging into a glance.
    assert!(message.contains("No Such User"), "{message}");

    assert_requests_match(&server, &exchanges).await;
}

/// The corpus is only worth anything if it is the one the manifest describes.
#[test]
fn every_committed_fixture_is_in_the_manifest() {
    let manifest = std::fs::read_to_string(fixtures().join("MANIFEST.toml"))
        .expect("fixtures/MANIFEST.toml. Rebuild it with scripts\\Write-FixtureManifest.ps1.");

    assert!(
        manifest.contains("server-version = \"Exchange/15."),
        "the manifest records which server produced the corpus"
    );

    let mut counted = 0_usize;
    for scenario in [
        "session-en-us",
        "session-nl-nl",
        "items-en-us",
        "items-nl-nl",
        "writes-en-us",
        "writes-nl-nl",
        "connect-refused",
    ] {
        let directory = fixtures().join("exchange-se").join(scenario);
        assert!(manifest.contains(&format!("[scenarios.\"exchange-se/{scenario}\"]")));

        for entry in std::fs::read_dir(&directory).expect("a scenario directory") {
            let name = entry.expect("an entry").file_name();
            let name = name.to_string_lossy();
            assert!(
                manifest.contains(&format!("\"{name}\" = {{")),
                "{scenario}/{name} is committed but not in MANIFEST.toml"
            );
            counted += 1;
        }
    }

    // Three files per exchange, and every one of them accounted for. Each pair of scenarios runs
    // to the same number because both mailboxes are seeded from the same list and hold the same
    // folders, so they page identically; the only thing that differs between them is what things
    // are called. The write scenarios match for a stronger reason: everything they send, this crate
    // chose.
    assert_eq!(
        counted,
        (SESSION_EXCHANGES * 2 + ITEM_EXCHANGES * 2 + WRITE_EXCHANGES * 2 + 1) * 3
    );
}

/// A shared observer sees the same bytes the fixtures hold, which is the assumption the whole
/// capture pipeline rests on.
#[tokio::test]
async fn what_an_observer_sees_is_what_the_corpus_holds() {
    #[derive(Debug, Default)]
    struct Bodies(Mutex<Vec<Vec<u8>>>);

    impl mapi_client::Observer for Bodies {
        fn observe(&self, exchange: &mapi_client::Exchange<'_>) {
            self.0
                .lock()
                .unwrap()
                .push(exchange.response_body().to_vec());
        }
    }

    let exchanges = scenario("session-en-us");
    let server = server(&exchanges).await;
    let seen = Arc::new(Bodies::default());

    let client = MapiClient::builder()
        .endpoint(format!("{}/mapi/emsmdb/", server.uri()))
        .user_dn(user_dn(&exchanges))
        .observer(Arc::clone(&seen))
        .danger_allow_plaintext_http()
        .build()
        .expect("a client");

    client.ping().await.expect("PING");
    let recorded = seen.0.lock().unwrap().clone();
    assert_eq!(recorded, vec![exchanges[0].response_body.clone()]);
}
