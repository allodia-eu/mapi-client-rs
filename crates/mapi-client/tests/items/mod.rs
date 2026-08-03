//! Items against a real store: calendar events, contacts, a body larger than a response buffer,
//! and both kinds of attachment.
//!
//! Its own file because it is its own question, and because `live.rs` is at the workspace's
//! 500-line limit.
//!
//! **These need a seeded mailbox.** `scripts\Add-LabItems.ps1` puts the events, the contacts and
//! the one message with a 60 KB body and two attachments in place. The tests say so by name when
//! they find nothing, because "the calendar is empty" and "the calendar read is broken" produce the
//! same zero rows and only one of them is worth debugging.
//!
//! Four things here cannot be proved offline, which is what makes them worth the round trips:
//!
//! * A body over the response-buffer limit reads whole. A fixture proves one capture decoded; only
//!   a live read proves the paging loop reaches the end of a stream the server is bounding.
//! * `RopSortTable` and `RopRestrict` actually change the answer. Both are ROPs whose whole effect
//!   is on rows the server chooses not to send, so a replay of a capture cannot tell a working sort
//!   from a folder that happened to be in order.
//! * An `afEmbeddedMessage` attachment reports the *inner* message. Reaching it opens the outer one
//!   first, and the failure — the parent's subject reported as the child's — looks entirely
//!   plausible.
//! * The named-property ids differ between mailboxes, so a calendar read has to be built from what
//!   *this* store answered. Running against two mailboxes is what proves it was.

use mapi_client::{
    APPOINTMENT_COLUMNS, AttachMethod, AttachmentNumber, CONTACT_COLUMNS, CONTACT_PROPERTIES,
    FuzzyLevel, Logon, MESSAGE_PROPERTIES, MessageId, NamedProperty, PropertyRow, PropertyTag,
    PropertyValue, Restriction, SortOrder, SortOrderSet, SpecialFolder, TableString, TaggedValue,
    WellKnownFolder,
};

use crate::client;

/// The subject `scripts\Add-LabItems.ps1` gives the message these tests read.
const SEEDED_SUBJECT: &str = "Seeded message with a large body and two attachments";

/// The stream chunk `mapi-client` reads with. A body has to clear this for the paging loop to be
/// exercised at all, and the seeded body is several times it.
const CHUNK: usize = 16 * 1024;

async fn logon() -> Logon {
    client()
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon")
}

/// Finds the seeded message by asking the *server* to filter, which proves the restriction works
/// and finds the message in one go.
async fn seeded_message(logon: &mut Logon) -> MessageId {
    let inbox = logon
        .folder_id(WellKnownFolder::Inbox)
        .expect("the logon names an Inbox");

    let rows = logon
        .folder(inbox)
        .contents()
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
        .collect()
        .await
        .expect("a filtered contents read");

    assert_eq!(
        rows.len(),
        1,
        "expected exactly one message subjected {SEEDED_SUBJECT:?}; run \
         scripts\\Add-LabItems.ps1 against this mailbox, and remove any duplicates first"
    );
    rows.first()
        .and_then(PropertyRow::message_id)
        .expect("the row carries PidTagMid")
}

/// *"List calendar events"*, with the start, end and location that make the answer worth having.
///
/// Every one of those is a named property, so this is also the end-to-end proof that the ids this
/// store allocated are the ids the read used.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_calendar_reads_with_real_start_times_and_locations() {
    let mut logon = logon().await;
    let calendar = logon
        .special_folder(SpecialFolder::Calendar)
        .await
        .expect("the entry-id chain reaches the Calendar");

    let named = logon
        .resolve_names(mapi_client::APPOINTMENT_PROPERTIES)
        .await
        .expect("the appointment properties resolve");
    let start = named
        .tag_of(NamedProperty::AppointmentStartWhole)
        .expect("this store maps PidLidAppointmentStartWhole");
    let end = named
        .tag_of(NamedProperty::AppointmentEndWhole)
        .expect("this store maps PidLidAppointmentEndWhole");
    let location = named
        .tag_of(NamedProperty::Location)
        .expect("this store maps PidLidLocation");
    let recurring = named
        .tag_of(NamedProperty::Recurring)
        .expect("this store maps PidLidRecurring");

    let mut columns = APPOINTMENT_COLUMNS.to_vec();
    columns.extend([start, end, location, recurring]);

    let rows = logon
        .folder(calendar)
        .contents()
        .columns(&columns)
        .sort(SortOrderSet::new([SortOrder::ascending(start)]))
        .collect()
        .await
        .expect("a sorted calendar read");

    assert!(
        !rows.is_empty(),
        "this calendar is empty, so the read proves nothing. Run scripts\\Add-LabItems.ps1."
    );

    let mut previous = 0_u64;
    let mut located = 0_usize;
    let mut recurrences = 0_usize;
    for row in &rows {
        let from = row
            .get(start)
            .and_then(PropertyValue::as_time)
            .expect("every appointment has a start")
            .as_u64();
        let to = row
            .get(end)
            .and_then(PropertyValue::as_time)
            .expect("every appointment has an end")
            .as_u64();
        println!(
            "  {:<40} {from} -> {to}",
            row.string(PropertyTag::SUBJECT)
                .map_or("(no subject)", TableString::as_str)
        );

        assert!(to >= from, "an event that ends before it starts");
        assert!(from >= previous, "RopSortTable did not order by start time");
        previous = from;

        if row
            .string(location)
            .is_some_and(|value| !value.as_str().is_empty())
        {
            located = located.saturating_add(1);
        }
        if row.get(recurring).and_then(PropertyValue::as_bool) == Some(true) {
            recurrences = recurrences.saturating_add(1);
        }
    }

    assert!(located > 0, "no event reported a location");
    assert!(
        recurrences > 0,
        "no event reported PidLidRecurring, so the property was never exercised"
    );

    logon.disconnect().await.expect("Disconnect");
}

/// *"List contacts"*, with the email addresses that are the point of listing them.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn contacts_read_with_their_email_addresses() {
    let mut logon = logon().await;
    let folder = logon
        .special_folder(SpecialFolder::Contacts)
        .await
        .expect("the entry-id chain reaches the Contacts folder");

    let named = logon
        .resolve_names(CONTACT_PROPERTIES)
        .await
        .expect("the contact properties resolve");
    let address = named
        .tag_of(NamedProperty::Email1EmailAddress)
        .expect("this store maps PidLidEmail1EmailAddress");

    let mut columns = CONTACT_COLUMNS.to_vec();
    columns.push(address);

    let rows = logon
        .folder(folder)
        .contents()
        .columns(&columns)
        .collect()
        .await
        .expect("a contacts read");

    assert!(
        !rows.is_empty(),
        "this contacts folder is empty. Run scripts\\Add-LabItems.ps1."
    );

    let with_addresses = rows
        .iter()
        .filter(|row| {
            row.string(address)
                .is_some_and(|value| value.as_str().contains('@'))
        })
        .count();
    for row in &rows {
        println!(
            "  {:<28} {}",
            row.string(PropertyTag::DISPLAY_NAME)
                .map_or("(no name)", TableString::as_str),
            row.string(address).map_or("(none)", TableString::as_str)
        );
    }
    assert_eq!(
        with_addresses,
        rows.len(),
        "a contact came back with no email address, which is the one column this read is for"
    );

    logon.disconnect().await.expect("Disconnect");
}

/// A body larger than one `RopReadStream` can carry, read to its end.
///
/// The assertion that matters is not the length but that the paging loop *stopped in the right
/// place*: the server reported a size when the stream was opened, and the bytes that arrived match
/// it. A loop that stopped one chunk early would still return a plausible-looking body.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_body_larger_than_a_response_buffer_reads_whole() {
    let mut logon = logon().await;
    let inbox = logon.folder_id(WellKnownFolder::Inbox).expect("an Inbox");
    let id = seeded_message(&mut logon).await;

    let body = logon
        .message(inbox, id)
        .stream(PropertyTag::BODY)
        .read()
        .await
        .expect("a streamed body");

    println!(
        "  PidTagBody: {} bytes read, {:?} reported, complete = {}",
        body.len(),
        body.reported_size(),
        body.is_complete()
    );
    assert!(
        body.len() > CHUNK,
        "the seeded body is {} bytes, which fits one read — the paging loop was never exercised",
        body.len()
    );
    assert!(body.is_complete(), "the read stopped at its own limit");
    assert_eq!(
        body.reported_size().map(usize::try_from),
        Some(Ok(body.len())),
        "the bytes that arrived do not match the size the open reported"
    );

    let text = body.text().expect("PidTagBody is PtypString");
    assert!(
        text.contains("Line 0001") && text.contains("Line 0900"),
        "the body is missing its first or last line, so the read lost a chunk"
    );

    // The same property fetched rather than streamed: the server refuses it, which is the whole
    // reason the stream path exists.
    let fetched = logon
        .message(inbox, id)
        .properties()
        .read([PropertyTag::BODY])
        .await
        .expect("the fetch itself succeeds");
    println!(
        "  the same property fetched: {:?}",
        fetched.get(PropertyTag::BODY)
    );
    assert!(
        fetched.error(PropertyTag::BODY).is_some(),
        "this server returned a {} byte body through a property fetch, so the claim in \
         PropertyTag::BODY's documentation needs re-measuring rather than repeating",
        body.len()
    );

    logon.disconnect().await.expect("Disconnect");
}

/// Both kinds of attachment, read the way each one's `PidTagAttachMethod` says to.
///
/// The embedded case is the one worth the round trips: it has no `PidTagAttachDataBinary` at all,
/// so a client that only ever streamed that property would report a forwarded mail as an empty
/// file — and reaching the real content opens the *parent* message first, which is how the inner
/// subject comes back as the outer one.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn both_kinds_of_attachment_read_the_way_their_method_says() {
    let mut logon = logon().await;
    let inbox = logon.folder_id(WellKnownFolder::Inbox).expect("an Inbox");
    let id = seeded_message(&mut logon).await;

    let opened = logon
        .message(inbox, id)
        .open()
        .await
        .expect("RopOpenMessage");
    println!(
        "  opened: prefix {:?}, subject {:?}, {} recipient(s)",
        opened.subject_prefix(),
        opened.normalized_subject(),
        opened.recipient_count()
    );
    assert_eq!(
        opened.normalized_subject(),
        Some(SEEDED_SUBJECT),
        "the open reported a different subject than the contents table did"
    );

    let properties = logon
        .message(inbox, id)
        .properties()
        .read(MESSAGE_PROPERTIES)
        .await
        .expect("the message's properties");
    assert_eq!(
        properties
            .get(PropertyTag::HAS_ATTACHMENTS)
            .and_then(PropertyValue::as_bool),
        Some(true),
        "PidTagHasAttachments says this message has none"
    );

    let rows = logon
        .message(inbox, id)
        .attachments()
        .collect()
        .await
        .expect("the attachment table");
    assert_eq!(rows.len(), 2, "the seeded message has one of each kind");

    let counts = read_each_attachment(&mut logon, inbox, id, &rows).await;
    assert_eq!(counts, (1, 1), "one attachment of each kind");
    logon.disconnect().await.expect("Disconnect");
}

/// Reads every attachment the way its own `PidTagAttachMethod` says to, and counts each kind.
async fn read_each_attachment(
    logon: &mut Logon,
    inbox: mapi_client::FolderId,
    id: MessageId,
    rows: &[PropertyRow],
) -> (usize, usize) {
    let mut by_value = 0_usize;
    let mut embedded = 0_usize;

    for row in rows {
        let number = row
            .get(PropertyTag::ATTACH_NUMBER)
            .and_then(PropertyValue::as_u32)
            .map(AttachmentNumber::new)
            .expect("every attachment row carries PidTagAttachNumber");
        let method = row
            .get(PropertyTag::ATTACH_METHOD)
            .and_then(PropertyValue::as_u32)
            .map(AttachMethod::new)
            .expect("every attachment row carries PidTagAttachMethod");
        println!(
            "  #{number} {:<24} {method}",
            row.string(PropertyTag::ATTACH_LONG_FILENAME)
                .map_or("(no name)", TableString::as_str)
        );

        if method.has_binary_content() {
            let content = logon
                .message(inbox, id)
                .attachment(number)
                .content()
                .read()
                .await
                .expect("an afByValue attachment has bytes");
            assert!(!content.is_empty(), "an afByValue attachment read as empty");
            by_value = by_value.saturating_add(1);
        } else if method.is_embedded_message() {
            let inner = logon
                .message(inbox, id)
                .attachment(number)
                .embedded()
                .open()
                .await
                .expect("RopOpenEmbeddedMessage");
            println!(
                "      embedded: id {:?}, subject {:?}",
                inner.embedded_id(),
                inner.normalized_subject()
            );
            assert_ne!(
                inner.normalized_subject(),
                Some(SEEDED_SUBJECT),
                "the embedded open reported the parent message's subject, which is what happens \
                 when the first RopOpenMessage response in the batch is taken instead of the \
                 RopOpenEmbeddedMessage one"
            );
            assert_eq!(
                inner.normalized_subject(),
                Some("The message inside the attachment"),
                "the embedded message is not the one scripts\\Add-LabItems.ps1 puts there"
            );

            // It has no bytes at all, which is the fact that makes the branch necessary.
            let refused = logon
                .message(inbox, id)
                .attachment(number)
                .content()
                .read()
                .await;
            println!("      its PidTagAttachDataBinary: {refused:?}");
            assert!(
                refused.is_err(),
                "an afEmbeddedMessage attachment answered with binary content, so the two methods \
                 are not as distinct as [MS-OXCMSG] §2.2.2.9 says"
            );
            embedded = embedded.saturating_add(1);
        }
    }

    (by_value, embedded)
}

/// `RopSortTable` and `RopRestrict`, each proved by the answer being different from the unsorted,
/// unfiltered one.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn the_server_sorts_and_filters_rather_than_the_client() {
    let mut logon = logon().await;
    let inbox = logon.folder_id(WellKnownFolder::Inbox).expect("an Inbox");

    let newest_first = logon
        .folder(inbox)
        .contents()
        .sort(SortOrderSet::new([SortOrder::descending(
            PropertyTag::MESSAGE_DELIVERY_TIME,
        )]))
        .collect()
        .await
        .expect("a sorted contents read");
    assert!(
        newest_first.len() > 1,
        "one row cannot show an ordering. Run scripts\\Initialize-ExchangeLab.ps1 -Seed."
    );

    let times: Vec<u64> = newest_first
        .iter()
        .filter_map(|row| {
            row.get(PropertyTag::MESSAGE_DELIVERY_TIME)
                .and_then(PropertyValue::as_time)
                .map(mapi_client::FileTime::as_u64)
        })
        .collect();
    assert_eq!(
        times.len(),
        newest_first.len(),
        "a row with no delivery time"
    );
    assert!(
        times.windows(2).all(|pair| pair.first() >= pair.get(1)),
        "RopSortTable did not order the rows: {times:?}"
    );

    // The same table filtered. The count the server reports when a table opens is the *unfiltered*
    // one — RopRestrict answers with a status and nothing else — so the rows are what to count.
    let mut filtered = logon
        .folder(inbox)
        .contents()
        .filter(Restriction::all([
            Restriction::exists(PropertyTag::SUBJECT),
            Restriction::content(
                FuzzyLevel::substring().ignoring_case(),
                TaggedValue::new(
                    PropertyTag::SUBJECT,
                    PropertyValue::String("attachments".into()),
                )
                .expect("a string value for a string tag"),
            ),
        ]))
        .rows();

    let mut matched = 0_usize;
    while let Some(row) = filtered.try_next().await.expect("a filtered page") {
        assert!(
            row.string(PropertyTag::SUBJECT)
                .is_some_and(|subject| subject.as_str().to_lowercase().contains("attachments")),
            "a row survived the restriction that does not match it"
        );
        matched = matched.saturating_add(1);
    }
    let reported = filtered.row_count();
    let status = filtered.table_status();
    filtered.close().await.expect("releasing the table");

    println!("  {matched} matched, table reported {reported:?}, status {status:?}");
    assert!(matched > 0, "the restriction matched nothing at all");
    assert!(
        matched < newest_first.len(),
        "the restriction did not narrow the table, so it proves nothing"
    );
    assert_eq!(
        reported.map(usize::try_from),
        Some(Ok(newest_first.len())),
        "the row count changed under a restriction, which [MS-OXCROPS] §2.2.5.3.2 gives the server \
         no way to report"
    );

    logon.disconnect().await.expect("Disconnect");
}
