//! The folders a logon does not name, against a fake server rather than a lab.
//!
//! [`tests/live.rs`](live.rs) proves the entry-id chain finds real folders; this file proves the
//! things a lab cannot be made to do on demand — a mailbox with no Journal, a server that refuses
//! one conversion out of three, a property holding 46 bytes that are not a Folder `EntryID`. Each
//! of those is a different answer, and the whole design of [`SpecialFolderState`] is that they
//! stay different.
//!
//! **The positional claim is the one worth having.** A ROP response carries nothing saying which
//! request it belongs to, so a refused conversion in the middle of a batch has to take its place
//! in the order like any other answer. `a_refused_conversion_does_not_shift_the_folders_after_it`
//! is that assertion.
//!
//! [MS-OXOSFLD] §2.2.3 — the binary identification properties
//! [MS-OXCROPS] §2.2.3.9 — `RopIdFromLongTermId`

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test that walks a known layout by offset is asserting something true about it"
)]

mod support;

use mapi_client::{
    Error, ErrorCode, FolderId, LongTermId, SpecialFolder, SpecialFolderState, StoreObjectType,
};
use support::{
    Bytes, LOGON_HANDLE, MapiServer, connect_ok, disconnect_body, execute_body, logon_response,
    open_folder_response, well_known_folder_id,
};

/// The `MailboxGuid` [`logon_response`] reports, which is the provider every entry id below names.
const MAILBOX_GUID: [u8; 16] = [0xAB; 16];

/// The handle table the first exchange leaves behind: the bound logon, then the Inbox it opened.
const OPENED_FOLDER: [u32; 2] = [LOGON_HANDLE, 0x0000_0001];

/// The slot `RopOpenFolder` writes its handle into, and therefore the one the property fetch and
/// the release both address.
const FOLDER_SLOT: u8 = 1;

/// The folder ids the fake server converts each entry id to. Distinct on purpose: a conversion
/// paired with the wrong folder has to show up as a wrong number rather than as a coincidence.
const CALENDAR_ID: u64 = 0x0D01_0000_0000_0001;
const DRAFTS_ID: u64 = 0x0E01_0000_0000_0001;
const INBOX_ID: u64 = 0x0F01_0000_0000_0001;

/// A 46-byte Folder `EntryID` for this mailbox, differing only in its counter.
///
/// [MS-OXCDATA] §2.2.4.1 — `Flags(4) ProviderUID(16) FolderType(2) DatabaseGuid(16)
/// GlobalCounter(6) Pad(2)`
fn entry_id(counter: u8) -> Vec<u8> {
    // Flags, ProviderUID, FolderType, DatabaseGuid, GlobalCounter, Pad — in that order. Flags is
    // zero because a non-zero one marks a short-term entry id, which a stored property may not
    // hold, and the counter is the only byte that varies between the eight built here.
    let database_guid = [0xCD; 16];
    Bytes::new()
        .u32(0)
        .raw(&MAILBOX_GUID)
        .u16(StoreObjectType::PRIVATE_FOLDER.as_u16())
        .raw(&database_guid)
        .raw(&[0x00, 0x00, 0x00, 0x00, 0x00, counter])
        .u16(0)
        .done()
}

/// What the Inbox said about one of the eight properties.
enum Said {
    /// A binary value: an entry id, or something that is not one.
    Binary(Vec<u8>),
    /// The property is not set on this object.
    Absent,
    /// The server answered with an error in place of a value.
    Failed(ErrorCode),
}

/// A `RopGetPropertiesSpecific` response carrying a `FlaggedPropertyRow`.
///
/// Flagged rather than standard because a standard row cannot say "absent" at all, and absent is
/// the answer this crate has to tell apart from every other kind of nothing.
///
/// [MS-OXCROPS] §2.2.8.3.2 — success response buffer
/// [MS-OXCDATA] §2.8.1.2 — `FlaggedPropertyRow`
fn get_properties_response(slot: u8, said: &[Said]) -> Vec<u8> {
    // RopGetPropertiesSpecific, the handle slot it answers for, a zero ReturnValue, and RowFlag
    // 0x01 saying the row that follows is a FlaggedPropertyRow.
    let mut out = Bytes::new().u8(0x07).u8(slot).u32(0).u8(0x01);

    for value in said {
        out = match value {
            // The COUNT prefixing a PtypBinary is 16 bits inside a ROP buffer.
            Said::Binary(bytes) => out
                .u8(0x00)
                .u16(u16::try_from(bytes.len()).unwrap())
                .raw(bytes),
            Said::Absent => out.u8(0x01),
            Said::Failed(code) => out.u8(0x0A).u32(code.as_u32()),
        };
    }
    out.done()
}

/// A `RopIdFromLongTermId` success response. [MS-OXCROPS] §2.2.3.9.2
fn id_from_long_term_id_response(slot: u8, id: u64) -> Vec<u8> {
    Bytes::new().u8(0x44).u8(slot).u32(0).u64(id).done()
}

/// A `RopLongTermIdFromId` success response. [MS-OXCROPS] §2.2.3.8.2
fn long_term_id_from_id_response(slot: u8, counter: u8) -> Vec<u8> {
    Bytes::new()
        .u8(0x43)
        .u8(slot)
        .u32(0)
        .raw(&[0xCD; 16])
        .raw(&[0x00, 0x00, 0x00, 0x00, 0x00, counter])
        .u16(0)
        .done()
}

/// A ROP the server refused, whose body stops after `ReturnValue`.
fn refused(rop: u8, slot: u8, code: ErrorCode) -> Vec<u8> {
    Bytes::new().u8(rop).u8(slot).u32(code.as_u32()).done()
}

/// Queues `Connect` and `RopLogon`, which every test here starts with.
fn logged_on(server: &MapiServer) {
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
}

/// Queues the first exchange of the chain: the Inbox opened, read and released in one buffer.
fn queue_inbox_properties(server: &MapiServer, said: &[Said]) {
    let mut rops = open_folder_response(FOLDER_SLOT);
    rops.extend(get_properties_response(FOLDER_SLOT, said));
    server.reply_ok(execute_body(&rops, &OPENED_FOLDER));
}

/// One entry per property of [`mapi_proto::SPECIAL_FOLDER_PROPERTIES`], in that order:
/// Archive, Calendar, Contacts, Journal, Notes, Tasks, Reminders, Drafts.
fn nothing_at_all() -> Vec<Said> {
    (0..8).map(|_| Said::Absent).collect()
}

/// **Every way a mailbox can answer, in one exchange, and each one kept apart.**
///
/// The middle conversion is refused, so this is also the positional claim: `Drafts` is the third
/// entry id sent and the third answer received, and a refusal in between must not slide its id
/// onto `Contacts` — which would be a plausible folder id for the wrong folder and no error at
/// all.
#[tokio::test]
async fn a_refused_conversion_does_not_shift_the_folders_after_it() {
    let server = MapiServer::start().await;
    logged_on(&server);
    queue_inbox_properties(
        &server,
        &[
            Said::Absent,                           // Archive: this mailbox never had one
            Said::Binary(entry_id(0x01)),           // Calendar
            Said::Binary(entry_id(0x02)),           // Contacts, whose conversion is refused
            Said::Failed(ErrorCode::NOT_FOUND),     // Journal: ecNotFound is "not set"
            Said::Failed(ErrorCode::ACCESS_DENIED), // Notes: any other code is a refusal
            Said::Binary(vec![0xFF; 10]),           // Tasks: not a Folder EntryID at all
            Said::Absent,                           // Reminders
            Said::Binary(entry_id(0x03)),           // Drafts
        ],
    );

    // Three conversions, in the order the entry ids were readable, with the middle one refused.
    let mut converted = id_from_long_term_id_response(0, CALENDAR_ID);
    converted.extend(refused(0x44, 0, ErrorCode::NOT_FOUND));
    converted.extend(id_from_long_term_id_response(0, DRAFTS_ID));
    server.reply_ok(execute_body(&converted, &[LOGON_HANDLE]));
    server.reply_ok(disconnect_body());

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let special = logon.special_folders().await.unwrap();

    assert_eq!(
        special.get(SpecialFolder::Calendar),
        Some(FolderId::new(CALENDAR_ID))
    );
    assert_eq!(
        special.get(SpecialFolder::Drafts),
        Some(FolderId::new(DRAFTS_ID)),
        "the refusal in the middle shifted the answers after it"
    );
    assert_eq!(special.found(), 2);
    assert!(!special.found_none());

    // The four kinds of nothing, each of which calls for a different thing from a caller.
    assert_eq!(
        special.state(SpecialFolder::Archive),
        Some(&SpecialFolderState::Absent)
    );
    assert_eq!(
        special.state(SpecialFolder::Journal),
        Some(&SpecialFolderState::Absent),
        "ecNotFound on a property fetch means the property is not set"
    );
    assert_eq!(
        special.state(SpecialFolder::Notes),
        Some(&SpecialFolderState::Refused(ErrorCode::ACCESS_DENIED))
    );
    assert_eq!(
        special.state(SpecialFolder::Contacts),
        Some(&SpecialFolderState::Refused(ErrorCode::NOT_FOUND))
    );
    assert!(matches!(
        special.state(SpecialFolder::Tasks),
        Some(SpecialFolderState::Unreadable { .. })
    ));

    // Every entry keeps the entry id it came from, which is the only check against an id issued
    // by another mailbox.
    let calendar = special
        .iter()
        .find(|entry| entry.folder() == SpecialFolder::Calendar)
        .unwrap();
    let SpecialFolderState::Found { entry_id, .. } = calendar.state() else {
        panic!("{calendar}");
    };
    assert!(entry_id.belongs_to(logon.mailbox().mailbox_guid()));
    assert!(calendar.to_string().starts_with("Calendar"));

    logon.disconnect().await.unwrap();
}

/// A mailbox that names nothing convertible costs **one** round trip, not two: there is nothing to
/// ask the server to convert, and issuing an empty batch to find that out would be a request whose
/// answer is already known.
#[tokio::test]
async fn a_mailbox_that_names_nothing_never_sends_the_second_batch() {
    let server = MapiServer::start().await;
    logged_on(&server);
    queue_inbox_properties(&server, &nothing_at_all());
    server.reply_ok(disconnect_body());

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let special = logon.special_folders().await.unwrap();

    assert_eq!(special.found(), 0);
    assert!(special.found_none());
    assert_eq!(special.iter().count(), SpecialFolder::ALL.len());
    logon.disconnect().await.unwrap();

    // Connect, RopLogon, the property fetch, Disconnect — and no conversion exchange between the
    // last two.
    assert_eq!(server.requests().await.len(), 4);
}

/// One folder by name, which is the same two round trips and says so.
#[tokio::test]
async fn one_special_folder_can_be_asked_for_by_itself() {
    let server = MapiServer::start().await;
    logged_on(&server);

    let mut said = nothing_at_all();
    said[1] = Said::Binary(entry_id(0x01)); // Calendar
    queue_inbox_properties(&server, &said);
    server.reply_ok(execute_body(
        &id_from_long_term_id_response(0, CALENDAR_ID),
        &[LOGON_HANDLE],
    ));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    assert_eq!(
        logon.special_folder(SpecialFolder::Calendar).await.unwrap(),
        FolderId::new(CALENDAR_ID)
    );
}

/// A folder this mailbox does not have is an error that says **what the mailbox said**, not just
/// that something was missing: "never had one" and "the server would not convert it" call for
/// different things from whoever reads the message.
#[tokio::test]
async fn asking_for_a_folder_this_mailbox_lacks_names_what_it_said_instead() {
    let server = MapiServer::start().await;
    logged_on(&server);
    queue_inbox_properties(&server, &nothing_at_all());

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let error = logon
        .special_folder(SpecialFolder::Journal)
        .await
        .expect_err("this mailbox has no Journal");

    match error {
        Error::MissingSpecialFolder { folder, ref state } => {
            assert_eq!(folder, SpecialFolder::Journal);
            assert_eq!(state, "not in this mailbox");
        }
        other => panic!("{other}"),
    }
    assert!(error.to_string().contains("no Journal folder"));
}

/// A server that answers fewer conversions than it was asked for is reported, not silently paired
/// up short.
///
/// The answers are matched to the folders **by position** — a ROP response says nothing about
/// which request it belongs to — so a batch that comes back one answer light would otherwise hand
/// the last folder's id to the second-to-last folder. That is a wrong folder opened with no error
/// anywhere, which is the failure this whole file exists to rule out.
#[tokio::test]
async fn fewer_conversions_than_entry_ids_sent_is_reported_rather_than_paired_up_short() {
    let server = MapiServer::start().await;
    logged_on(&server);

    let mut said = nothing_at_all();
    said[1] = Said::Binary(entry_id(0x01)); // Calendar
    said[7] = Said::Binary(entry_id(0x03)); // Drafts
    queue_inbox_properties(&server, &said);

    // Two entry ids went out; one answer comes back.
    server.reply_ok(execute_body(
        &id_from_long_term_id_response(0, CALENDAR_ID),
        &[LOGON_HANDLE],
    ));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let error = logon.special_folders().await.expect_err("one answer short");
    assert!(
        error
            .to_string()
            .contains("one RopIdFromLongTermId response"),
        "{error}"
    );
}

/// **The identifier conversions, both ways.** A long-term id and a short-term one are not
/// interconvertible by arithmetic, so the only thing a fake server can prove is that this crate
/// writes the request the specification describes and reads the answer back out of it — which is
/// exactly what a wrong byte order would break.
///
/// [MS-OXCROPS] §2.2.3.8 — `RopLongTermIdFromId`
/// [MS-OXCROPS] §2.2.3.9 — `RopIdFromLongTermId`
#[tokio::test]
async fn an_identifier_converts_in_both_directions() {
    let server = MapiServer::start().await;
    logged_on(&server);
    server.reply_ok(execute_body(
        &long_term_id_from_id_response(0, 0x07),
        &[LOGON_HANDLE],
    ));
    server.reply_ok(execute_body(
        &id_from_long_term_id_response(0, INBOX_ID),
        &[LOGON_HANDLE],
    ));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let inbox = FolderId::new(well_known_folder_id(4));

    let long_term = logon.long_term_id(inbox.into()).await.unwrap();
    assert_eq!(long_term.global_counter(), 0x0700_0000_0000);
    assert_eq!(
        long_term,
        LongTermId::new(
            long_term.database_guid(),
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x07]
        )
    );

    let back = logon.short_term_id(&long_term).await.unwrap();
    assert_eq!(back.as_folder_id(), FolderId::new(INBOX_ID));

    // The request carried the 24 bytes verbatim, which is the half a decoder cannot check.
    let sent = server.rops(3).await;
    assert_eq!(sent[0], 0x44, "RopIdFromLongTermId");
    assert_eq!(sent.len(), 3 + 24);
    assert_eq!(&sent[3..19], &[0xCD; 16]);
}

/// A batch whose answers hold no conversion is reported rather than guessed at. A server that
/// answered `Execute` successfully and said nothing about the ROP inside it would otherwise leave
/// the caller with no id and no reason.
#[tokio::test]
async fn a_conversion_with_no_answer_in_it_is_an_error() {
    let server = MapiServer::start().await;
    logged_on(&server);
    server.reply_ok(execute_body(&[], &[LOGON_HANDLE]));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let error = logon
        .short_term_id(&LongTermId::new(
            mapi_client::Guid::from_bytes([0xCD; 16]),
            [0; 6],
        ))
        .await
        .expect_err("nothing came back");

    assert!(error.to_string().contains("RopIdFromLongTermId"), "{error}");
}
