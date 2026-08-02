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
    reason = "a test that walks a captured layout by offset is asserting something true about it"
)]

mod corpus;

use std::sync::{Arc, Mutex};

use mapi_client::{
    Credentials, Lcid, MAILBOX_PROPERTIES, MapiClient, PropertyProblem, PropertySet, PropertyTag,
    PropertyValue, TableString, TaggedValue, WellKnownFolder,
};

use crate::corpus::{assert_requests_match, fixtures, scenario, server, user_dn};

/// The page sizes `mapi-cli capture` used, and therefore the ones a replay has to use for the
/// requests to match byte for byte.
const HIERARCHY_PAGE: u16 = 8;
const CONTENTS_PAGE: u16 = 2;

/// The comment `mapi-cli capture` tried to set on the Store object, and which Exchange refused.
/// Same reason as the page sizes: the request bodies only match if the replay sends the same
/// value.
const COMMENT_PROBE: &str = "mapi-client-rs probe";

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
        mailbox,
        refused,
        folders,
        folder_count,
        messages,
        message_count,
    }
}

/// Everything one replay observed.
struct Replayed {
    display_name: String,
    folder_ids: Vec<mapi_client::FolderId>,
    inbox: mapi_client::FolderId,
    mailbox: PropertySet,
    refused: Vec<PropertyProblem>,
    folders: Vec<(mapi_client::FolderId, String)>,
    folder_count: Option<u32>,
    messages: Vec<(String, bool)>,
    message_count: Option<u32>,
}

impl Replayed {
    /// What every mailbox has, whatever language it speaks.
    ///
    /// The message count is a parameter because the two lab mailboxes hold different numbers of
    /// them, which is rather the point: what is being tested is the paging, not the seed data.
    fn assert_shape_is_a_mailbox(&self, messages: u32) {
        assert_eq!(self.folder_ids.len(), 13, "a private logon names thirteen");
        assert_eq!(self.folder_count, Some(15));
        assert_eq!(self.folders.len(), 15, "read across two pages of eight");
        assert_eq!(self.message_count, Some(messages));
        assert_eq!(
            u32::try_from(self.messages.len()).unwrap(),
            messages,
            "every row the server reported arrived, across pages of two"
        );

        // The Inbox is found by the id the logon gave, not by its name — which is the whole point
        // of having a second mailbox in a second language.
        assert!(
            self.folders.iter().any(|(id, _)| *id == self.inbox),
            "the Inbox is not in the hierarchy: {:?}",
            self.folders
        );

        // Exactly one seeded subject is long enough for the table to cut it at 255 characters, and
        // the table says so nowhere except in the value's own length.
        let truncated: Vec<&String> = self
            .messages
            .iter()
            .filter(|(_, truncated)| *truncated)
            .map(|(subject, _)| subject)
            .collect();
        assert_eq!(truncated.len(), 1, "{:?}", self.messages);
        assert_eq!(truncated[0].chars().count(), 255);

        self.assert_shape_of_the_store_object();
    }

    /// What a real Store object answered, and what it refused.
    ///
    /// Both halves are claims about bytes Exchange actually sent: a `RopGetPropertiesSpecific`
    /// answering for every tag it was given, two of them with an error in place of a value, and a
    /// `RopSetProperties` that succeeded while the property inside it did not.
    fn assert_shape_of_the_store_object(&self) {
        assert_eq!(
            self.mailbox.len(),
            MAILBOX_PROPERTIES.len(),
            "a property fetch answers for every tag it was given, present or not"
        );

        // A binary value, which is the corpus's only evidence that a `PtypBinary` COUNT is 16 bits
        // wide inside a ROP buffer. Read it as 32 and the two bytes that follow are swallowed, so
        // this decoding at all is the assertion.
        let owner = self
            .mailbox
            .get(PropertyTag::MAILBOX_OWNER_ENTRY_ID)
            .and_then(PropertyValue::as_binary)
            .expect("the owner's address book EntryID");
        assert!(owner.len() > 100, "{} bytes", owner.len());

        // Documented as read-only properties of every private mailbox logon, and answered with
        // `ecNotFound` by the server that produced this corpus. Recorded rather than smoothed
        // over: "not set" and "the server would not say" are different facts.
        //
        // [MS-OXCSTOR] §2.2.2.1.1.5, §2.2.2.1.1.12
        for absent in [PropertyTag::STORE_STATE, PropertyTag::LOCALE_ID] {
            assert_eq!(
                self.mailbox.error(absent),
                Some(mapi_client::ErrorCode::NOT_FOUND),
                "{absent}"
            );
        }

        // The write that succeeded as a ROP and failed as a property. A caller that only looked at
        // the ROP's return value would report this as a completed write.
        //
        // [MS-OXCSTOR] §7 note 14 — Exchange 2013 SP1 and later refuse this one
        assert_eq!(
            self.refused
                .iter()
                .map(|problem| (problem.tag(), problem.code()))
                .collect::<Vec<_>>(),
            vec![(PropertyTag::COMMENT, mapi_client::ErrorCode::ACCESS_DENIED)]
        );
    }

    /// The name of the folder with a given id.
    fn folder(&self, id: mapi_client::FolderId) -> &str {
        self.folders
            .iter()
            .find(|(candidate, _)| *candidate == id)
            .map(|(_, name)| &**name)
            .unwrap_or_default()
    }
}

/// The en-US mailbox: the corpus everything else is compared against.
#[tokio::test]
async fn an_en_us_session_replays_byte_for_byte() {
    let replayed = replay("session-en-us", Lcid::EN_US).await;
    replayed.assert_shape_is_a_mailbox(6);

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
    replayed.assert_shape_is_a_mailbox(6);

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
    for scenario in ["session-en-us", "session-nl-nl", "connect-refused"] {
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

    // Three files per exchange, and every one of them accounted for. Both sessions run to fourteen
    // because both mailboxes are seeded from the same list, so they page identically; the only
    // thing that differs between them is what the folders are called.
    assert_eq!(counted, (14 + 14 + 1) * 3);
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
