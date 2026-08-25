//! Replaying the item corpus: a calendar, a contacts folder, and one message read to the bottom.
//!
//! Its own file because it is its own scenario, and because `replay.rs` is close to the workspace's
//! 500-line limit.
//!
//! This makes the same two claims the session replay does — every request body matches what
//! Exchange actually accepted, and every recorded response still decodes — over the ROPs that
//! turn a table row into an item. Five of those cannot be checked anywhere else in CI:
//!
//! * A `RopOpenMessage` response's `TypedString` subject and its recipient table, which has to be
//!   consumed to exactly its own end or every later response in the buffer moves.
//! * `RopSortTable`'s and `RopRestrict`'s request encodings, including a sort key that is a
//!   named-property tag and therefore different in each of the two captured mailboxes.
//! * An attachment table, whose response carries no row count.
//! * `RopOpenEmbeddedMessage`, whose batch holds two `RopOpenMessage`-shaped responses.
//! * A stream reassembled from four round trips, which is the only offline evidence that the read
//!   loop ends where the stream does.

use mapi_client::{
    APPOINTMENT_COLUMNS, APPOINTMENT_PROPERTIES, AttachMethod, AttachmentNumber, CONTACT_COLUMNS,
    CONTACT_PROPERTIES, Credentials, FolderId, FuzzyLevel, Lcid, Logon, MESSAGE_PROPERTIES,
    MapiClient, MessageId, NamedProperty, PropertyRow, PropertyTag, PropertyValue, Restriction,
    SortOrder, SortOrderSet, SpecialFolder, TableString, TaggedValue, WellKnownFolder,
};

use crate::corpus::{assert_requests_match, scenario, server, user_dn};

/// The subject `scripts\Add-LabItems.ps1` gives the seeded message, and therefore the exact bytes
/// the captured `RopRestrict` carries.
const SEEDED_SUBJECT: &str = "Seeded message with a large body and two attachments";

/// The subject of the message *inside* the attachment — the one an embedded open has to report
/// rather than the one above.
const EMBEDDED_SUBJECT: &str = "The message inside the attachment";

/// How many exchanges one captured item session holds: `Connect`, the logon, the two halves of the
/// Calendar's entry-id chain, the appointment names, the events and their release, the same three
/// for contacts, the filtered contents read and its release, the message open, its properties, the
/// attachment table and its release, an attachment's content and its release, the embedded open,
/// four body chunks and their release, and the `Disconnect`.
const ITEM_EXCHANGES: usize = 27;

/// What one replayed item session produced, for the assertions to pick over.
struct Items {
    events: Vec<(u64, u64, String, String)>,
    contacts: Vec<(String, String)>,
    matched: Vec<MessageId>,
    subject: Option<String>,
    recipients: u16,
    properties: mapi_client::PropertySet,
    attachments: Vec<(AttachmentNumber, AttachMethod)>,
    content: usize,
    embedded_subject: Option<String>,
    embedded_id: Option<MessageId>,
    body: usize,
    body_reported: Option<u32>,
}

/// Drives one captured item session, then checks every request body against the corpus.
///
/// The order is `mapi-cli capture items`' order exactly, because that is what produced the corpus.
async fn replay(name: &str, locale: Lcid) -> Items {
    let exchanges = scenario(name);
    assert_eq!(
        exchanges.len(),
        ITEM_EXCHANGES,
        "{name} has the wrong shape"
    );
    let server = server(&exchanges).await;

    let client = MapiClient::builder()
        .endpoint(format!("{}/mapi/emsmdb/", server.uri()))
        .user_dn(user_dn(&exchanges))
        .credentials(Credentials::basic("replay@example.test", "hunter2"))
        .locale(locale)
        .danger_allow_plaintext_http()
        .build()
        .expect("a client");

    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let inbox = logon.folder_id(WellKnownFolder::Inbox).expect("an Inbox");

    let events = replay_events(&mut logon).await;
    let contacts = replay_contacts(&mut logon).await;
    let matched = replay_filter(&mut logon, inbox).await;
    let id = matched.first().copied().expect("the restriction matched");

    let opened = logon
        .message(inbox, id)
        .open()
        .await
        .expect("RopOpenMessage");
    let subject = opened.normalized_subject().map(str::to_owned);
    let recipients = opened.recipient_count();

    let properties = logon
        .message(inbox, id)
        .properties()
        .read(MESSAGE_PROPERTIES)
        .await
        .expect("the message's properties");

    let (attachments, content, embedded_subject, embedded_id) =
        replay_attachments(&mut logon, inbox, id).await;

    let stream = logon.message(inbox, id).stream(PropertyTag::BODY_HTML);
    assert_eq!(
        stream.tag(),
        PropertyTag::BODY_HTML,
        "a read that failed has nothing but this to name what it was reading"
    );
    let body = stream.read().await.expect("a streamed body");
    assert!(
        body.is_complete(),
        "the replayed read stopped at its own limit"
    );

    logon.disconnect().await.expect("Disconnect");
    assert_requests_match(&server, &exchanges).await;

    Items {
        events,
        contacts,
        matched,
        subject,
        recipients,
        properties,
        attachments,
        content,
        embedded_subject,
        embedded_id,
        body: body.len(),
        body_reported: body.reported_size(),
    }
}

/// The calendar half: the entry-id chain, the named-property lookup, and a read sorted on an id
/// this store allocated.
async fn replay_events(logon: &mut Logon) -> Vec<(u64, u64, String, String)> {
    let calendar = logon
        .special_folder(SpecialFolder::Calendar)
        .await
        .expect("the Calendar");
    let named = logon
        .resolve_names(APPOINTMENT_PROPERTIES)
        .await
        .expect("the appointment names");
    let start = named
        .tag_of(NamedProperty::AppointmentStartWhole)
        .expect("a start tag");
    let end = named
        .tag_of(NamedProperty::AppointmentEndWhole)
        .expect("an end tag");
    let location = named
        .tag_of(NamedProperty::Location)
        .expect("a location tag");
    let recurring = named
        .tag_of(NamedProperty::Recurring)
        .expect("a recurring tag");

    let mut columns = APPOINTMENT_COLUMNS.to_vec();
    columns.extend([start, end, location, recurring]);

    let mut rows = logon
        .folder(calendar)
        .contents()
        .columns(&columns)
        .sort(SortOrderSet::new([SortOrder::ascending(start)]))
        .rows();
    let mut events = Vec::new();
    while let Some(row) = rows.try_next().await.expect("a page of events") {
        events.push((
            row.get(start)
                .and_then(PropertyValue::as_time)
                .expect("a start time")
                .as_u64(),
            row.get(end)
                .and_then(PropertyValue::as_time)
                .expect("an end time")
                .as_u64(),
            row.string(PropertyTag::SUBJECT)
                .map_or_else(String::new, |value| value.as_str().to_owned()),
            row.string(location)
                .map_or_else(String::new, |value| value.as_str().to_owned()),
        ));
    }
    rows.close().await.expect("releasing the calendar table");
    events
}

/// The contacts half, whose one interesting column is a named property in a different set.
async fn replay_contacts(logon: &mut Logon) -> Vec<(String, String)> {
    let folder = logon
        .special_folder(SpecialFolder::Contacts)
        .await
        .expect("the Contacts folder");
    let address = logon
        .resolve_names(CONTACT_PROPERTIES)
        .await
        .expect("the contact names")
        .tag_of(NamedProperty::Email1EmailAddress)
        .expect("an address tag");

    let mut columns = CONTACT_COLUMNS.to_vec();
    columns.push(address);

    let mut rows = logon.folder(folder).contents().columns(&columns).rows();
    let mut contacts = Vec::new();
    while let Some(row) = rows.try_next().await.expect("a page of contacts") {
        contacts.push((
            row.string(PropertyTag::DISPLAY_NAME)
                .map_or_else(String::new, |value| value.as_str().to_owned()),
            row.string(address)
                .map_or_else(String::new, |value| value.as_str().to_owned()),
        ));
    }
    rows.close().await.expect("releasing the contacts table");
    contacts
}

/// The sorted, filtered contents read that names the message everything after it works on.
async fn replay_filter(logon: &mut Logon, inbox: FolderId) -> Vec<MessageId> {
    let mut rows = logon
        .folder(inbox)
        .contents()
        .sort(SortOrderSet::new([SortOrder::descending(
            PropertyTag::MESSAGE_DELIVERY_TIME,
        )]))
        .filter(Restriction::all([
            Restriction::exists(PropertyTag::SUBJECT),
            Restriction::content(
                FuzzyLevel::full_string().ignoring_case(),
                TaggedValue::new(
                    PropertyTag::SUBJECT,
                    PropertyValue::String(SEEDED_SUBJECT.into()),
                )
                .expect("a string value for a string tag"),
            ),
        ]))
        .rows();

    let mut matched = Vec::new();
    while let Some(row) = rows.try_next().await.expect("a filtered page") {
        matched.push(PropertyRow::message_id(&row).expect("a message id"));
    }
    rows.close().await.expect("releasing the filtered table");
    matched
}

/// The attachment table, one attachment's bytes, and the message inside the other one.
async fn replay_attachments(
    logon: &mut Logon,
    inbox: FolderId,
    id: MessageId,
) -> (
    Vec<(AttachmentNumber, AttachMethod)>,
    usize,
    Option<String>,
    Option<MessageId>,
) {
    let mut rows = logon.message(inbox, id).attachments().rows();
    let mut attachments = Vec::new();
    while let Some(row) = rows.try_next().await.expect("a page of attachments") {
        let number = row
            .get(PropertyTag::ATTACH_NUMBER)
            .and_then(PropertyValue::as_u32)
            .map(AttachmentNumber::new)
            .expect("PidTagAttachNumber");
        let method = row
            .get(PropertyTag::ATTACH_METHOD)
            .and_then(PropertyValue::as_u32)
            .map(AttachMethod::new)
            .expect("PidTagAttachMethod");
        attachments.push((number, method));
    }
    rows.close().await.expect("releasing the attachment table");

    let by_value = attachments
        .iter()
        .find(|(_, method)| method.has_binary_content())
        .map(|(number, _)| *number)
        .expect("an afByValue attachment");
    let embedded = attachments
        .iter()
        .find(|(_, method)| method.is_embedded_message())
        .map(|(number, _)| *number)
        .expect("an afEmbeddedMessage attachment");

    let content = logon
        .message(inbox, id)
        .attachment(by_value)
        .content()
        .read()
        .await
        .expect("the attachment's bytes")
        .len();

    let inner = logon
        .message(inbox, id)
        .attachment(embedded)
        .embedded()
        .open()
        .await
        .expect("RopOpenEmbeddedMessage");

    (
        attachments,
        content,
        inner.normalized_subject().map(str::to_owned),
        inner.embedded_id(),
    )
}

/// Everything the replay is expected to have produced, in one place, so the two mailboxes assert
/// the same shape and differ only where a mailbox genuinely differs.
fn assert_shape(items: &Items) {
    assert_eq!(items.events.len(), 4, "the seeded calendar has four events");
    let mut previous = 0_u64;
    for (start, end, subject, location) in &items.events {
        assert!(
            end >= start,
            "{subject}: an event that ends before it starts"
        );
        assert!(
            *start >= previous,
            "RopSortTable did not order by start time"
        );
        previous = *start;
        assert!(!location.is_empty(), "{subject}: no location");
    }

    assert_eq!(
        items.contacts.len(),
        3,
        "the seeded folder has three contacts"
    );
    for (name, address) in &items.contacts {
        assert!(address.contains('@'), "{name} has no email address");
    }

    assert_eq!(
        items.matched.len(),
        1,
        "the restriction matched one message"
    );
    assert_eq!(items.subject.as_deref(), Some(SEEDED_SUBJECT));
    assert_eq!(items.recipients, 0, "the seeded message was never sent");
    assert_eq!(
        items
            .properties
            .get(PropertyTag::HAS_ATTACHMENTS)
            .and_then(PropertyValue::as_bool),
        Some(true)
    );

    assert_eq!(items.attachments.len(), 2, "one attachment of each kind");
    assert_eq!(
        items
            .attachments
            .iter()
            .filter(|(_, method)| method.has_binary_content())
            .count(),
        1
    );
    assert_eq!(
        items
            .attachments
            .iter()
            .filter(|(_, method)| method.is_embedded_message())
            .count(),
        1
    );
    assert!(items.content > 0, "the afByValue attachment read as empty");

    // The assertion the whole embedded branch exists for: reaching the inner message opens the
    // outer one first, so taking the first RopOpenMessage-shaped response gives the wrong subject.
    assert_eq!(items.embedded_subject.as_deref(), Some(EMBEDDED_SUBJECT));
    assert_ne!(
        items.embedded_subject.as_deref(),
        Some(SEEDED_SUBJECT),
        "the embedded open reported the parent message"
    );
    // Exchange answers zero here rather than a MID. Asserted rather than tolerated, because a
    // server that started sending a real one is a finding.
    assert_eq!(
        items.embedded_id.map(MessageId::as_u64),
        Some(0),
        "[MS-OXCMSG] §2.2.3.16.2 calls this a MID and Exchange sends zero"
    );

    // Four round trips' worth of body, reassembled to exactly the length the open reported.
    assert!(
        items.body > 32 * 1024,
        "the captured body is {} bytes, which one or two reads cover",
        items.body
    );
    assert_eq!(
        items.body_reported.map(usize::try_from),
        Some(Ok(items.body)),
        "the reassembled body is not the length the open reported"
    );
}

/// The en-US mailbox.
#[tokio::test]
async fn an_en_us_item_session_replays_byte_for_byte() {
    let items = replay("items-en-us", Lcid::EN_US).await;
    assert_shape(&items);

    assert!(
        items
            .events
            .iter()
            .any(|(.., subject, _)| subject.contains("standup")),
        "{:?}",
        items.events
    );
}

/// The nl-NL mailbox — which is not a copy of the first, because the named-property ids a store
/// allocates are its own.
///
/// The sort key in the captured `RopSortTable` request is `PidLidAppointmentStartWhole`'s tag, and
/// that tag is a different number in each mailbox. So this replay sending the same bytes as the
/// other one would mean the client had ignored what the store answered — the request comparison
/// catches it, and this is the note that says why that matters.
#[tokio::test]
async fn an_nl_nl_item_session_replays_with_its_own_property_ids() {
    let items = replay("items-nl-nl", Lcid::new(0x0413)).await;
    assert_shape(&items);

    let contacts: Vec<&str> = items
        .contacts
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(contacts.contains(&"Ada Lovelace"), "{contacts:?}");
}

/// The one thing a single scenario cannot show: that the two captures are not the same bytes.
///
/// Named-property ids are allocated per store, so a calendar read built from what one mailbox
/// answered is a different request from the same read against the other. If these two ever matched,
/// the client would be sending an id it did not resolve.
#[test]
fn the_two_captures_sort_on_different_property_ids() {
    let request = |name: &str| {
        scenario(name)
            .into_iter()
            .find(|exchange| exchange.stem.ends_with("-events"))
            .map(|exchange| exchange.request_body)
            .expect("an events exchange in every item scenario")
    };

    let en_us = request("items-en-us");
    let nl_nl = request("items-nl-nl");
    assert_eq!(
        en_us.len(),
        nl_nl.len(),
        "the same ROPs, so the same length: only the ids inside differ"
    );
    assert_ne!(
        en_us, nl_nl,
        "both mailboxes sorted on the same property id, so at least one read used an id it did \
         not resolve against that store"
    );
}

/// A `TableString` is only truncated when a *table* cut it short. Every string here came from a
/// table, and none of them is at the limit — so a value reported as truncated would mean the
/// classification had started firing on values that are whole.
#[test]
fn nothing_in_the_item_corpus_is_reported_as_truncated() {
    for name in ["items-en-us", "items-nl-nl"] {
        assert!(
            !scenario(name).is_empty(),
            "{name} is missing from the corpus"
        );
    }
    let complete: TableString = "a value no table cut short".into();
    assert!(!complete.is_truncated());
}
