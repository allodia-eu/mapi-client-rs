//! The commands that read *items* rather than folders: calendar events, contacts, and one message
//! with its body and its attachments.
//!
//! Each of these is where a phase's work becomes something a person can look at. What they have in
//! common is that none of them can be written against `PidTag` constants alone — an event's start
//! time and a contact's email address are named properties whose ids this store allocated, so every
//! one of these resolves names first and builds its column set from the answer.

use std::collections::HashMap;

use mapi_client::{
    APPOINTMENT_COLUMNS, ATTACHMENT_COLUMNS, AttachMethod, AttachmentNumber, CONTACT_COLUMNS,
    CONTACT_PROPERTIES, FolderId, FuzzyLevel, Logon, MESSAGE_PROPERTIES, MessageId, NamedProperty,
    PropertyRow, PropertyTag, PropertyValue, Restriction, SortOrder, SortOrderSet, SpecialFolder,
    TableString, TaggedValue,
};

use crate::settings::Connection;
use crate::{Failure, report};

/// The appointment properties a listing shows, in the order they are printed.
const EVENT_COLUMNS: [NamedProperty; 5] = [
    NamedProperty::AppointmentStartWhole,
    NamedProperty::AppointmentEndWhole,
    NamedProperty::Location,
    NamedProperty::BusyStatus,
    NamedProperty::Recurring,
];

/// The contact properties a listing shows.
const CONTACT_EMAIL: [NamedProperty; 3] = [
    NamedProperty::Email1DisplayName,
    NamedProperty::Email1AddressType,
    NamedProperty::Email1EmailAddress,
];

/// Read a folder's contents table, optionally ordered and filtered by the server.
///
/// The two options are what `RopSortTable` and `RopRestrict` are for, and both are worth reaching
/// for rather than sorting locally: a filter applied here means the server never sends the rows
/// nobody asked for, which for a folder of any size is the difference between one round trip and
/// all of them.
pub(crate) async fn messages(
    connection: &Connection,
    folder: &str,
    page_size: u16,
    limit: usize,
    newest_first: bool,
    subject: Option<&str>,
) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let id = super::resolve(&mut logon, folder).await?;

    println!("contents of {folder} ({:#018x})", id.as_u64());
    let mut table = logon.folder(id).contents().page_size(page_size);
    if newest_first {
        table = table.sort(SortOrderSet::new([SortOrder::descending(
            PropertyTag::MESSAGE_DELIVERY_TIME,
        )]));
        println!("  ordered by delivery time, newest first (RopSortTable)");
    }
    if let Some(wanted) = subject {
        // The existence test is not decoration: [MS-OXCDATA] 2.12.9.1 says the result of a content
        // restriction on an item with no such property is *undefined*, not false.
        table = table.filter(Restriction::all([
            Restriction::exists(PropertyTag::SUBJECT),
            Restriction::content(
                FuzzyLevel::substring().ignoring_case(),
                TaggedValue::new(PropertyTag::SUBJECT, PropertyValue::String(wanted.into()))?,
            ),
        ]));
        println!("  filtered to subjects containing {wanted:?} (RopRestrict)");
    }

    let mut rows = table.rows();
    let mut seen = 0_usize;
    let mut truncated = 0_usize;
    while let Some(row) = rows.try_next().await? {
        if seen < limit {
            println!("{}", report::message_line(&row));
        }
        if row
            .string(PropertyTag::SUBJECT)
            .is_some_and(TableString::is_truncated)
        {
            truncated = truncated.saturating_add(1);
        }
        seen = seen.saturating_add(1);
    }
    let reported = rows.row_count();
    let status = rows.table_status();
    rows.close().await?;

    if seen > limit {
        println!(
            "  ... {} more row(s) read but not shown",
            seen.saturating_sub(limit)
        );
    }
    if subject.is_some() {
        // RopRestrict answers with a status and no count, so the number the table reported when it
        // opened is the unfiltered one and stays that way.
        println!("  {seen} row(s) matched; the count below is the folder's, before the filter");
    }
    super::summarise(seen, reported);
    if let Some(status) = status.filter(|status| !status.is_complete()) {
        println!(
            "  the server reported table status 0x{:02X} rather than TBLSTAT_COMPLETE, so the \
             rows read may predate the sort or the filter",
            status.as_u8()
        );
    }
    if truncated > 0 {
        println!(
            "  {truncated} subject(s) were truncated by the table at 255 characters — the full \
             value is only available by opening the message"
        );
    }

    logon.disconnect().await?;
    Ok(())
}

/// List a calendar's events, with real start times, end times and locations.
///
/// Three round trips before the first row and one per page after it: the entry-id chain that finds
/// the Calendar folder is two, resolving the named properties is one, and the read itself opens the
/// folder, opens its table, sets the columns and reads a page in a single `Execute`.
pub(crate) async fn events(
    connection: &Connection,
    folder: Option<&str>,
    limit: usize,
) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let id = match folder {
        Some(folder) => super::parse_folder_id(folder)?,
        None => logon.special_folder(SpecialFolder::Calendar).await?,
    };

    let named = logon.resolve_names(EVENT_COLUMNS).await?;
    let tags: HashMap<NamedProperty, PropertyTag> = EVENT_COLUMNS
        .into_iter()
        .filter_map(|property| Some((property, named.tag_of(property)?)))
        .collect();
    if tags.len() < EVENT_COLUMNS.len() {
        println!(
            "  note: this store maps only {} of the {} appointment properties; the rest are shown \
             as (unmapped)",
            tags.len(),
            EVENT_COLUMNS.len()
        );
    }

    let mut columns = APPOINTMENT_COLUMNS.to_vec();
    columns.extend(
        EVENT_COLUMNS
            .into_iter()
            .filter_map(|p| tags.get(&p).copied()),
    );

    println!("events in {:#018x}", id.as_u64());
    let start = tags.get(&NamedProperty::AppointmentStartWhole).copied();
    let table = logon.folder(id).contents().columns(&columns);
    // Sorting on the start time is the whole reason a calendar listing is useful, and it is only
    // possible because the tag was resolved above — the server has no fixed id for it either.
    let table = match start {
        Some(tag) => table.sort(SortOrderSet::new([SortOrder::ascending(tag)])),
        None => table,
    };

    let mut rows = table.rows();
    let mut seen = 0_usize;
    while let Some(row) = rows.try_next().await? {
        if seen < limit {
            print_event(&row, &tags);
        }
        seen = seen.saturating_add(1);
    }
    let reported = rows.row_count();
    rows.close().await?;
    super::summarise(seen, reported);
    if seen > limit {
        println!("  ... {} more not shown", seen.saturating_sub(limit));
    }

    logon.disconnect().await?;
    Ok(())
}

fn print_event(row: &PropertyRow, tags: &HashMap<NamedProperty, PropertyTag>) {
    let named = |property: NamedProperty| tags.get(&property).and_then(|tag| row.get(*tag));
    let when = |property| {
        named(property)
            .and_then(PropertyValue::as_time)
            .map_or_else(|| "(unmapped)".to_owned(), report::timestamp)
    };

    println!(
        "  {}  {} -> {}",
        report::string_cell(row, PropertyTag::SUBJECT),
        when(NamedProperty::AppointmentStartWhole),
        when(NamedProperty::AppointmentEndWhole)
    );
    println!(
        "      location {:<24} busy {:<12} recurring {}",
        named(NamedProperty::Location)
            .and_then(PropertyValue::as_string)
            .map_or("(none)", TableString::as_str),
        busy_status(named(NamedProperty::BusyStatus)),
        named(NamedProperty::Recurring)
            .and_then(PropertyValue::as_bool)
            .map_or_else(|| "(unmapped)".to_owned(), |value| value.to_string())
    );
}

/// `PidLidBusyStatus`, whose values are an enumeration rather than a scale.
///
/// [MS-OXOCAL] §2.2.1.2 — `olFree` (0), `olTentative` (1), `olBusy` (2), `olOof` (3),
/// `olWorkingElsewhere` (4)
fn busy_status(value: Option<&PropertyValue>) -> String {
    match value.and_then(PropertyValue::as_u32) {
        Some(0) => "free".to_owned(),
        Some(1) => "tentative".to_owned(),
        Some(2) => "busy".to_owned(),
        Some(3) => "out of office".to_owned(),
        Some(4) => "elsewhere".to_owned(),
        Some(other) => format!("status {other}"),
        None => "(unmapped)".to_owned(),
    }
}

/// List a contacts folder, with the email addresses that make it worth listing.
pub(crate) async fn contacts(
    connection: &Connection,
    folder: Option<&str>,
    limit: usize,
) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let id = match folder {
        Some(folder) => super::parse_folder_id(folder)?,
        None => logon.special_folder(SpecialFolder::Contacts).await?,
    };

    let named = logon.resolve_names(CONTACT_PROPERTIES).await?;
    let tags: Vec<Option<PropertyTag>> = CONTACT_EMAIL.map(|p| named.tag_of(p)).to_vec();

    let mut columns = CONTACT_COLUMNS.to_vec();
    columns.extend(tags.iter().flatten().copied());

    println!("contacts in {:#018x}", id.as_u64());
    let mut rows = logon.folder(id).contents().columns(&columns).rows();
    let mut seen = 0_usize;
    while let Some(row) = rows.try_next().await? {
        if seen < limit {
            let text = |tag: Option<PropertyTag>| {
                tag.and_then(|tag| row.string(tag))
                    .map_or("(none)", TableString::as_str)
                    .to_owned()
            };
            println!(
                "  {:<28} {:<32} {}",
                report::string_cell(&row, PropertyTag::DISPLAY_NAME),
                text(tags.get(2).copied().flatten()),
                report::string_cell(&row, PropertyTag::COMPANY_NAME)
            );
        }
        seen = seen.saturating_add(1);
    }
    let reported = rows.row_count();
    rows.close().await?;
    super::summarise(seen, reported);
    if seen > limit {
        println!("  ... {} more not shown", seen.saturating_sub(limit));
    }

    logon.disconnect().await?;
    Ok(())
}

/// Open one message and report everything about it: its properties, its body, its attachments.
///
/// The body goes through `RopOpenStream` rather than a property fetch, which is the only reading
/// that works for a message of any size — see [`PidTagBody`](PropertyTag::BODY).
pub(crate) async fn message(
    connection: &Connection,
    folder: &str,
    id: &str,
    body: bool,
) -> Result<(), Failure> {
    let message_id = MessageId::new(super::parse_hexadecimal(id, "a message id")?);
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let folder_id = super::resolve(&mut logon, folder).await?;

    let opened = logon.message(folder_id, message_id).open().await?;
    println!(
        "message {:#018x} in {:#018x}",
        message_id.as_u64(),
        folder_id.as_u64()
    );
    println!(
        "  subject          {:?} + {:?}",
        opened.subject_prefix().unwrap_or_default(),
        opened.normalized_subject().unwrap_or_default()
    );
    println!(
        "  recipients       {} ({} row(s) returned{})",
        opened.recipient_count(),
        opened.recipients().len(),
        if opened.is_truncated() {
            ", the rest did not fit"
        } else {
            ""
        }
    );
    for recipient in opened.recipients() {
        println!(
            "    {:<4} {} byte(s) of RecipientRow, undecoded",
            recipient.recipient_type(),
            recipient.row_bytes().len()
        );
    }
    println!(
        "  named properties {}",
        if opened.has_named_properties() {
            "yes — this message carries per-store ids"
        } else {
            "no"
        }
    );

    let properties = logon
        .message(folder_id, message_id)
        .properties()
        .read(MESSAGE_PROPERTIES)
        .await?;
    println!();
    println!("{} propert(y/ies) on the Message object", properties.len());
    for cell in &properties {
        println!("{}", report::property_line(cell));
    }
    if let Some(delivered) = properties
        .get(PropertyTag::MESSAGE_DELIVERY_TIME)
        .and_then(PropertyValue::as_time)
    {
        println!("  delivered {}", report::timestamp(delivered));
    }

    if body {
        read_body(&mut logon, folder_id, message_id).await?;
    }
    attachments(&mut logon, folder_id, message_id).await?;

    logon.disconnect().await?;
    Ok(())
}

/// Streams the plain-text body and the HTML body, and says how big each turned out to be.
///
/// Both are asked for because which one a message actually holds is the server's business:
/// `PidTagNativeBody` says which is the original and the other is converted on demand, and a
/// conversion that is not possible answers `NotFound` rather than empty text.
async fn read_body(logon: &mut Logon, folder: FolderId, message: MessageId) -> Result<(), Failure> {
    println!();
    for tag in [PropertyTag::BODY, PropertyTag::BODY_HTML] {
        match logon.message(folder, message).stream(tag).read().await {
            Ok(value) => {
                let reported = value
                    .reported_size()
                    .map_or_else(|| "(none)".to_owned(), |size| size.to_string());
                println!(
                    "  {tag}: {} read, {reported} reported{}",
                    report::bytes(value.len()),
                    if value.is_complete() {
                        ""
                    } else {
                        " — the read limit was reached first, so this is a prefix"
                    }
                );
                if let Ok(text) = value.text() {
                    println!(
                        "    {} character(s): {:?}",
                        text.chars().count(),
                        preview(&text)
                    );
                }
            }
            Err(error) => println!("  {tag}: {error}"),
        }
    }
    Ok(())
}

/// Lists the attachments and reads each one the way its own method says to.
///
/// The `PidTagAttachMethod` branch is the point of the whole command: an `afEmbeddedMessage`
/// attachment has no bytes at all, and a client that only ever streamed
/// `PidTagAttachDataBinary` would report a forwarded mail as an empty file.
async fn attachments(
    logon: &mut Logon,
    folder: FolderId,
    message: MessageId,
) -> Result<(), Failure> {
    let rows = logon
        .message(folder, message)
        .attachments()
        .columns(ATTACHMENT_COLUMNS)
        .collect()
        .await?;

    println!();
    println!("{} attachment(s)", rows.len());
    for row in &rows {
        let Some(number) = row
            .get(PropertyTag::ATTACH_NUMBER)
            .and_then(PropertyValue::as_u32)
            .map(AttachmentNumber::new)
        else {
            println!("  a row with no PidTagAttachNumber, which cannot be opened");
            continue;
        };
        let method = row
            .get(PropertyTag::ATTACH_METHOD)
            .and_then(PropertyValue::as_u32)
            .map_or(AttachMethod::None, AttachMethod::new);

        println!(
            "  #{number} {:<32} {:<20} {}",
            report::string_cell(row, PropertyTag::ATTACH_LONG_FILENAME),
            method.to_string(),
            row.get(PropertyTag::ATTACH_SIZE)
                .and_then(PropertyValue::as_u32)
                .map_or_else(|| "(no size)".to_owned(), |size| format!("{size} bytes"))
        );

        if method.has_binary_content() {
            let value = logon
                .message(folder, message)
                .attachment(number)
                .content()
                .read()
                .await?;
            println!("      {} of content read", report::bytes(value.len()));
        } else if method.is_embedded_message() {
            let embedded = logon
                .message(folder, message)
                .attachment(number)
                .embedded()
                .open()
                .await?;
            println!(
                "      an embedded message, id {}: {:?}",
                embedded
                    .embedded_id()
                    .map_or_else(|| "(none)".to_owned(), |id| id.to_string()),
                embedded.normalized_subject().unwrap_or_default()
            );
            let inner = logon
                .message(folder, message)
                .attachment(number)
                .embedded()
                .attachments()
                .collect()
                .await?;
            println!("      and {} attachment(s) of its own", inner.len());
        } else {
            println!("      no content this client reads: see [MS-OXCMSG] §2.2.2.9");
        }
    }
    Ok(())
}

/// The first line of a body, for a listing that is not meant to print the whole thing.
fn preview(text: &str) -> String {
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default();
    line.chars().take(72).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [MS-OXOCAL] §2.2.1.2's own table, which is an enumeration and not a scale — printing the
    /// number would say nothing.
    #[test]
    fn every_busy_status_the_document_lists_has_a_name() {
        for (raw, expected) in [
            (0, "free"),
            (1, "tentative"),
            (2, "busy"),
            (3, "out of office"),
            (4, "elsewhere"),
        ] {
            assert_eq!(busy_status(Some(&PropertyValue::Integer32(raw))), expected);
        }
        assert_eq!(busy_status(Some(&PropertyValue::Integer32(9))), "status 9");
        assert_eq!(busy_status(None), "(unmapped)");
    }

    #[test]
    fn a_body_preview_is_the_first_non_empty_line() {
        assert_eq!(preview("\n\n  hello \nworld"), "  hello ");
        assert_eq!(preview(""), "");
        assert_eq!(preview(&"x".repeat(200)).chars().count(), 72);
    }

    /// The two catalogues these commands read with have to be subsets of what the crate knows, or
    /// resolving them would silently ask for nothing.
    #[test]
    fn the_listed_properties_are_all_catalogued() {
        for property in EVENT_COLUMNS.into_iter().chain(CONTACT_EMAIL) {
            assert!(NamedProperty::ALL.contains(&property), "{property}");
        }
    }
}
