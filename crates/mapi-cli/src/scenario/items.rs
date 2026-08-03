//! The item conversation: a calendar, a contacts folder, and one message read to the bottom.
//!
//! Its own scenario rather than more exchanges on the end of the `session` one, for two
//! reasons. It needs a mailbox seeded by `scripts\Add-LabItems.ps1` and the other does not, so
//! failing them separately says which; and a message body several times the size of one
//! `RopReadStream` would otherwise be the largest thing in a corpus that is mostly a few hundred
//! bytes per exchange.
//!
//! What this is evidence *for*, none of which the other scenario carries:
//!
//! * `RopOpenMessage`'s response, whose subject arrives as two `TypedString`s and whose tail is a
//!   recipient table that has to be consumed exactly.
//! * `RopSortTable` and `RopRestrict` — the two ROPs whose whole effect is on rows the server
//!   chooses not to send.
//! * An attachment table, whose response carries **no row count** where a folder's does.
//! * `RopOpenEmbeddedMessage`, whose response is `RopOpenMessage`'s with a reserved byte and a
//!   message id in front — and whose batch therefore holds two responses of that shape, only one of
//!   which is the message that was asked for.
//! * A stream read that takes more than one round trip, which is the only evidence that the loop
//!   ends where the stream does rather than where the first short answer is.

use mapi_client::{
    APPOINTMENT_COLUMNS, ATTACHMENT_COLUMNS, AttachMethod, AttachmentNumber, CONTACT_COLUMNS,
    CONTACT_PROPERTIES, FolderId, FuzzyLevel, Logon, MESSAGE_PROPERTIES, MapiClient, MessageId,
    NamedProperty, PropertyRow, PropertyTag, PropertyValue, Restriction, SortOrder, SortOrderSet,
    SpecialFolder, TaggedValue, WellKnownFolder,
};

use crate::Failure;
use crate::capture::Recorder;

/// The subject `scripts\Add-LabItems.ps1` gives the message this scenario reads.
///
/// Matched with a full-string content restriction, so the capture is also the corpus's only
/// `RopRestrict` request — and the reason the scenario can name one message without a folder-wide
/// read in front of it.
pub(super) const SEEDED_SUBJECT: &str = "Seeded message with a large body and two attachments";

/// The body streamed here, which is the HTML one rather than the plain text.
///
/// Both are several times one read; the HTML is roughly half the size, and one multi-round-trip
/// read is as much evidence as two. [MS-OXCMSG] §2.2.1.56.4 makes it `PtypBinary`, which is the
/// half of [`StreamValue`](mapi_client::StreamValue) the other scenarios never exercise.
const STREAMED_BODY: PropertyTag = PropertyTag::BODY_HTML;

/// The whole item conversation, in one Session Context.
pub(super) async fn items(client: &MapiClient, recorder: &Recorder) -> Result<(), Failure> {
    recorder.label("");
    let connection = client.connect().await?;

    recorder.label("logon");
    let mut logon = connection.logon().await?;
    let inbox = logon.folder_id(WellKnownFolder::Inbox)?;

    calendar(&mut logon, recorder).await?;
    contacts(&mut logon, recorder).await?;
    let id = find_message(&mut logon, recorder, inbox).await?;
    message(&mut logon, recorder, inbox, id).await?;
    attachments(&mut logon, recorder, inbox, id).await?;
    body(&mut logon, recorder, inbox, id).await?;

    recorder.label("");
    logon.disconnect().await?;
    Ok(())
}

/// *"List calendar events"*: the named-property lookup, then a contents read sorted on an id this
/// store allocated.
///
/// The sort is the point of capturing the calendar rather than any other folder. `RopSortTable`
/// requires its key to be among the columns already set ([MS-OXCTABL] §2.2.2.3), and here the key
/// is a named-property tag — so the capture is evidence that the two round trips fit together.
async fn calendar(logon: &mut Logon, recorder: &Recorder) -> Result<(), Failure> {
    recorder.label("calendar-folder");
    let calendar = logon.special_folder(SpecialFolder::Calendar).await?;

    recorder.label("appointment-names");
    let named = logon
        .resolve_names(mapi_client::APPOINTMENT_PROPERTIES)
        .await?;
    let start = named.tag_of(NamedProperty::AppointmentStartWhole);
    let end = named.tag_of(NamedProperty::AppointmentEndWhole);
    let location = named.tag_of(NamedProperty::Location);
    let recurring = named.tag_of(NamedProperty::Recurring);

    let (Some(start), Some(end), Some(location), Some(recurring)) =
        (start, end, location, recurring)
    else {
        return Err(Failure::from(
            "this store does not map all four appointment properties, so the capture would carry \
             a calendar read with nothing in it worth reading. Open the mailbox in Outlook or OWA \
             once and re-run."
                .to_owned(),
        ));
    };

    let mut columns = APPOINTMENT_COLUMNS.to_vec();
    columns.extend([start, end, location, recurring]);

    recorder.label("events");
    let mut rows = logon
        .folder(calendar)
        .contents()
        .columns(&columns)
        .sort(SortOrderSet::new([SortOrder::ascending(start)]))
        .rows();
    let mut events = 0_usize;
    while rows.try_next().await?.is_some() {
        events = events.saturating_add(1);
    }
    recorder.label("events-release");
    rows.close().await?;

    println!("  {events} calendar event(s), ordered by start time");
    if events == 0 {
        return Err(Failure::from(
            "this calendar is empty, so the capture would prove nothing about reading one. Run \
             scripts\\Add-LabItems.ps1 against this mailbox."
                .to_owned(),
        ));
    }
    Ok(())
}

/// *"List contacts"*: the same shape without the sort, against `PSETID_Address` rather than
/// `PSETID_Appointment`.
async fn contacts(logon: &mut Logon, recorder: &Recorder) -> Result<(), Failure> {
    recorder.label("contacts-folder");
    let folder = logon.special_folder(SpecialFolder::Contacts).await?;

    recorder.label("contact-names");
    let named = logon.resolve_names(CONTACT_PROPERTIES).await?;
    let Some(address) = named.tag_of(NamedProperty::Email1EmailAddress) else {
        return Err(Failure::from(
            "this store does not map PidLidEmail1EmailAddress, which is the one column a contacts \
             listing is for."
                .to_owned(),
        ));
    };

    let mut columns = CONTACT_COLUMNS.to_vec();
    columns.push(address);

    recorder.label("contacts");
    let mut rows = logon.folder(folder).contents().columns(&columns).rows();
    let mut found = 0_usize;
    while let Some(row) = rows.try_next().await? {
        if row
            .string(address)
            .is_some_and(|value| !value.as_str().is_empty())
        {
            found = found.saturating_add(1);
        }
    }
    recorder.label("contacts-release");
    rows.close().await?;

    println!("  {found} contact(s) with an email address");
    if found == 0 {
        return Err(Failure::from(
            "no contact in this folder has an email address. Run scripts\\Add-LabItems.ps1."
                .to_owned(),
        ));
    }
    Ok(())
}

/// Finds the seeded message by asking the server to filter, which is what puts a `RopRestrict` in
/// the corpus.
async fn find_message(
    logon: &mut Logon,
    recorder: &Recorder,
    inbox: FolderId,
) -> Result<MessageId, Failure> {
    recorder.label("filtered-contents");
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
                )?,
            ),
        ]))
        .rows();

    let mut matched = Vec::new();
    while let Some(row) = rows.try_next().await? {
        matched.push(row);
    }
    recorder.label("filtered-contents-release");
    rows.close().await?;

    println!("  {} message(s) matched the restriction", matched.len());
    match matched.as_slice() {
        [only] => PropertyRow::message_id(only)
            .ok_or_else(|| Failure::from("the matched row carried no PidTagMid".to_owned())),
        rows => Err(Failure::from(format!(
            "{} message(s) match {SEEDED_SUBJECT:?} rather than exactly one. The capture names a \
             message by its subject, so a duplicate makes it ambiguous — remove the extras and \
             re-run.",
            rows.len()
        ))),
    }
}

/// `RopOpenMessage` on its own, then the message's properties.
async fn message(
    logon: &mut Logon,
    recorder: &Recorder,
    inbox: FolderId,
    id: MessageId,
) -> Result<(), Failure> {
    recorder.label("open-message");
    let opened = logon.message(inbox, id).open().await?;
    println!(
        "  opened {:#018x}: {:?}, {} recipient(s)",
        id.as_u64(),
        opened.normalized_subject().unwrap_or_default(),
        opened.recipient_count()
    );

    recorder.label("message-properties");
    let properties = logon
        .message(inbox, id)
        .properties()
        .read(MESSAGE_PROPERTIES)
        .await?;
    println!(
        "  {} propert(y/ies) on the Message object",
        properties.len()
    );
    Ok(())
}

/// The attachment table, then one attachment of each kind read the way its method says to.
async fn attachments(
    logon: &mut Logon,
    recorder: &Recorder,
    inbox: FolderId,
    id: MessageId,
) -> Result<(), Failure> {
    recorder.label("attachment-table");
    let mut rows = logon
        .message(inbox, id)
        .attachments()
        .columns(ATTACHMENT_COLUMNS)
        .rows();
    let mut found = Vec::new();
    while let Some(row) = rows.try_next().await? {
        let number = row
            .get(PropertyTag::ATTACH_NUMBER)
            .and_then(PropertyValue::as_u32)
            .map(AttachmentNumber::new);
        let method = row
            .get(PropertyTag::ATTACH_METHOD)
            .and_then(PropertyValue::as_u32)
            .map(AttachMethod::new);
        if let (Some(number), Some(method)) = (number, method) {
            found.push((number, method));
        }
    }
    recorder.label("attachment-table-release");
    rows.close().await?;

    let by_value = found.iter().find(|(_, method)| method.has_binary_content());
    let embedded = found
        .iter()
        .find(|(_, method)| method.is_embedded_message());
    let (Some((by_value, _)), Some((embedded, _))) = (by_value, embedded) else {
        return Err(Failure::from(format!(
            "this message has {} attachment(s) and the capture needs one afByValue and one \
             afEmbeddedMessage. Run scripts\\Add-LabItems.ps1 against a mailbox that does not \
             already hold the seeded message.",
            found.len()
        )));
    };

    recorder.label("attachment-content");
    let content = logon
        .message(inbox, id)
        .attachment(*by_value)
        .content()
        .read()
        .await?;
    println!("  attachment #{by_value}: {} byte(s)", content.len());

    recorder.label("embedded-message");
    let inner = logon
        .message(inbox, id)
        .attachment(*embedded)
        .embedded()
        .open()
        .await?;
    println!(
        "  attachment #{embedded} is a message: {:?}",
        inner.normalized_subject().unwrap_or_default()
    );
    if inner.normalized_subject() == Some(SEEDED_SUBJECT) {
        return Err(Failure::from(
            "the embedded open reported the parent message's subject, which is what taking the \
             first RopOpenMessage response in the batch produces. Do not commit this capture."
                .to_owned(),
        ));
    }
    Ok(())
}

/// The body, read through as many round trips as it takes.
///
/// The one capture in the corpus that spans more than one `Execute` for a single value, and the
/// only evidence that the loop stops where the stream does. Nothing here says how many exchanges
/// that will be: it depends on the body the lab holds, which is what the count printed at the end
/// is for.
async fn body(
    logon: &mut Logon,
    recorder: &Recorder,
    inbox: FolderId,
    id: MessageId,
) -> Result<(), Failure> {
    recorder.label("body-stream");
    let value = logon
        .message(inbox, id)
        .stream(STREAMED_BODY)
        .read()
        .await?;

    println!(
        "  {STREAMED_BODY}: {} byte(s) read, {:?} reported",
        value.len(),
        value.reported_size()
    );
    if !value.is_complete() {
        return Err(Failure::from(
            "the body read stopped at its own limit rather than at the end of the stream, so the \
             capture would carry a truncated value."
                .to_owned(),
        ));
    }
    if value.len() <= 32 * 1024 {
        return Err(Failure::from(format!(
            "this body is {} bytes, which one or two reads cover — the capture would carry no \
             evidence that a stream spanning several round trips is reassembled correctly. Seed a \
             larger one.",
            value.len()
        )));
    }
    Ok(())
}
