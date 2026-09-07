//! The commands that put an item into a mailbox, change one, and take one out again.
//!
//! Each of these is a property list, and the list is the whole of the work: `mapi-client` will
//! create a Message object in any folder with any properties on it, and what makes the result a
//! contact rather than a mail is which properties it carries. So this file is a transcription of
//! [MS-OXOCAL] §2.2.1 and [MS-OXOCNTC] §2.2.1 into `TaggedValue`s, and everything else is the
//! library's.
//!
//! That division is deliberate and is the same one the read commands make. A crate that shipped
//! `create_contact(name, email)` would have to take a position on `PidLidFileUnder`, on which of
//! three display names to use and on what to do about the ten other electronic-address properties —
//! positions [MS-OXOCNTC] leaves to the client. Here they are visible, in one place, with the
//! section that justifies each.
//!
//! **Nothing here writes to a mailbox without being asked to by name.** Every command in this file
//! is a create, an update or a delete, and `mapi-cli` has no dry-run mode: the flag is the consent.

use mapi_client::{
    FileTime, FolderId, MessageClass, MessageId, NEW_APPOINTMENT_PROPERTIES,
    NEW_CONTACT_PROPERTIES, NamedProperty, NewAttachment, OneOffEntryId, PropertyTag,
    PropertyValue, Recipient, SavedMessage, SpecialFolder, TaggedValue,
};

use crate::settings::Connection;
use crate::{Failure, report};

/// `PidLidBusyStatus`: `olBusy`. [MS-OXOCAL] §2.2.1.2
const BUSY: u32 = 0x0000_0002;

/// `PidLidResponseStatus`: `respNone`, which is what an Appointment object rather than a Meeting
/// object carries. [MS-OXOCAL] §2.2.1.11
const RESPONSE_NONE: u32 = 0x0000_0000;

/// `PidLidAppointmentStateFlags`: none of `asfMeeting`, `asfReceived` or `asfCanceled`.
/// [MS-OXOCAL] §2.2.1.10
const NOT_A_MEETING: u32 = 0x0000_0000;

/// `PidLidSideEffects`: the five flags [MS-OXOCAL] §2.2.2.2 has every Calendar object set.
///
/// `seOpenToDelete` (`0x0001`), `seOpenToCopy` (`0x0020`), `seOpenToMove` (`0x0040`),
/// `seCoerceToInbox` (`0x0100`) and `seOpenForCtxMenu` (`0x0400`).
///
/// [MS-OXCMSG] §2.2.1.16 — the flag values
const CALENDAR_SIDE_EFFECTS: u32 = 0x0001 | 0x0020 | 0x0040 | 0x0100 | 0x0400;

/// Draft a message, with recipients and an attachment.
pub(crate) async fn draft(
    connection: &Connection,
    subject: &str,
    body: &str,
    to: &[String],
    attach: Option<&std::path::Path>,
) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let drafts = logon.special_folder(SpecialFolder::Drafts).await?;

    let mut recipients = Vec::with_capacity(to.len());
    for address in to {
        recipients.push(Recipient::to(address.as_str(), address.as_str())?);
    }

    let mut attachments = Vec::new();
    if let Some(path) = attach {
        let bytes = std::fs::read(path)
            .map_err(|error| Failure::from(format!("{}: {error}", path.display())))?;
        let name = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| Failure::from(format!("{} has no file name", path.display())))?;
        println!("attaching {name} ({})", report::bytes(bytes.len()));
        attachments.push(NewAttachment::by_value(name, bytes)?);
    }

    let saved = logon
        .folder(drafts)
        .create_message(MessageClass::Note)
        .set([
            TaggedValue::new(PropertyTag::SUBJECT, string(subject))?,
            TaggedValue::new(PropertyTag::BODY, string(body))?,
        ])
        .to(recipients)
        .attach(attachments)
        .save()
        .await?;

    report_saved("a draft", drafts, &saved);
    logon.disconnect().await?;
    Ok(())
}

/// Create a contact.
///
/// The three electronic-address properties beyond the address itself are what separate a contact a
/// client can act on from one it can only display: `PidLidEmail1OriginalEntryId` is a one-off entry
/// id, and without it Outlook shows the address and will not send to it.
///
/// [MS-OXOCNTC] §2.2.1.2 — the electronic address properties
pub(crate) async fn contact(
    connection: &Connection,
    name: &str,
    email: &str,
    company: Option<&str>,
    phone: Option<&str>,
) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let folder = logon.special_folder(SpecialFolder::Contacts).await?;

    let (given, surname) = split_name(name);
    let one_off = OneOffEntryId::smtp(email, email)?;

    let named = logon.register_names(NEW_CONTACT_PROPERTIES).await?.clone();
    let tag = |property| tag_of(&named, property);

    let mut values = vec![
        TaggedValue::new(PropertyTag::DISPLAY_NAME, string(name))?,
        TaggedValue::new(PropertyTag::GIVEN_NAME, string(given))?,
        TaggedValue::new(PropertyTag::SURNAME, string(surname))?,
        TaggedValue::new(tag(NamedProperty::Email1DisplayName)?, string(name))?,
        TaggedValue::new(tag(NamedProperty::Email1AddressType)?, string("SMTP"))?,
        TaggedValue::new(tag(NamedProperty::Email1EmailAddress)?, string(email))?,
        TaggedValue::new(
            tag(NamedProperty::Email1OriginalDisplayName)?,
            string(email),
        )?,
        TaggedValue::new(
            tag(NamedProperty::Email1OriginalEntryId)?,
            PropertyValue::Binary(one_off.to_bytes()),
        )?,
        TaggedValue::new(
            tag(NamedProperty::FileUnder)?,
            string(&file_under(given, surname, name)),
        )?,
    ];
    if let Some(company) = company {
        values.push(TaggedValue::new(
            PropertyTag::COMPANY_NAME,
            string(company),
        )?);
    }
    if let Some(phone) = phone {
        values.push(TaggedValue::new(
            PropertyTag::BUSINESS_TELEPHONE_NUMBER,
            string(phone),
        )?);
    }

    let saved = logon
        .folder(folder)
        .create_message(MessageClass::Contact)
        .set(values)
        .save()
        .await?;

    println!("  {one_off}");
    report_saved("a contact", folder, &saved);
    logon.disconnect().await?;
    Ok(())
}

/// Create a single-instance appointment.
///
/// `PidTagStartDate` and `PidTagEndDate` are written alongside their named twins because
/// [MS-OXOCAL] §2.2.1.30 requires them to be equal when set, and they are what a client that has
/// not resolved the named properties reads.
pub(crate) async fn event(
    connection: &Connection,
    subject: &str,
    start: &str,
    end: &str,
    location: Option<&str>,
) -> Result<(), Failure> {
    let start = parse_instant(start)?;
    let end = parse_instant(end)?;
    if end.as_u64() < start.as_u64() {
        return Err(Failure::from(
            "the end is before the start, which [MS-OXOCAL] §2.2.1.6 forbids".to_owned(),
        ));
    }

    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let calendar = logon.special_folder(SpecialFolder::Calendar).await?;

    let named = logon
        .register_names(NEW_APPOINTMENT_PROPERTIES)
        .await?
        .clone();
    let tag = |property| tag_of(&named, property);

    let values = vec![
        TaggedValue::new(PropertyTag::SUBJECT, string(subject))?,
        TaggedValue::new(PropertyTag::START_DATE, PropertyValue::Time(start))?,
        TaggedValue::new(PropertyTag::END_DATE, PropertyValue::Time(end))?,
        TaggedValue::new(
            tag(NamedProperty::AppointmentStartWhole)?,
            PropertyValue::Time(start),
        )?,
        TaggedValue::new(
            tag(NamedProperty::AppointmentEndWhole)?,
            PropertyValue::Time(end),
        )?,
        TaggedValue::new(
            tag(NamedProperty::Location)?,
            string(location.unwrap_or_default()),
        )?,
        TaggedValue::new(
            tag(NamedProperty::BusyStatus)?,
            PropertyValue::Integer32(BUSY),
        )?,
        TaggedValue::new(
            tag(NamedProperty::AppointmentSubType)?,
            PropertyValue::Boolean(false),
        )?,
        TaggedValue::new(
            tag(NamedProperty::Recurring)?,
            PropertyValue::Boolean(false),
        )?,
        TaggedValue::new(
            tag(NamedProperty::ResponseStatus)?,
            PropertyValue::Integer32(RESPONSE_NONE),
        )?,
        TaggedValue::new(
            tag(NamedProperty::AppointmentStateFlags)?,
            PropertyValue::Integer32(NOT_A_MEETING),
        )?,
        TaggedValue::new(
            tag(NamedProperty::SideEffects)?,
            PropertyValue::Integer32(CALENDAR_SIDE_EFFECTS),
        )?,
    ];

    let saved = logon
        .folder(calendar)
        .create_message(MessageClass::Appointment)
        .set(values)
        .save()
        .await?;

    report_saved("an appointment", calendar, &saved);
    logon.disconnect().await?;
    Ok(())
}

/// Delete messages from a folder, by id.
pub(crate) async fn delete(
    connection: &Connection,
    folder: &str,
    ids: &[String],
) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let id = super::resolve(&mut logon, folder).await?;

    let mut messages = Vec::with_capacity(ids.len());
    for value in ids {
        messages.push(MessageId::new(super::parse_hexadecimal(
            value,
            "a message id",
        )?));
    }

    let complete = logon.folder(id).delete_messages(&messages).await?;
    // Reported only once the flag has been looked at. `RopDeleteMessages` succeeds whether or not
    // it deleted anything, so printing the count first would say "deleted 3 message(s)" on the
    // very run whose next line is that some of them are still there.
    if !complete {
        return Err(Failure::from(format!(
            "the server reported partial completion on {folder} ({:#018x}), so at least one of \
             those {} message(s) is still there. RopDeleteMessages succeeds either way; the flag \
             is the only thing that says so.",
            id.as_u64(),
            messages.len(),
        )));
    }
    println!(
        "deleted {} message(s) from {folder} ({:#018x})",
        messages.len(),
        id.as_u64()
    );

    logon.disconnect().await?;
    Ok(())
}

/// Prints what a create came to, refused properties included.
fn report_saved(kind: &str, folder: FolderId, saved: &SavedMessage) {
    println!(
        "created {kind} in {:#018x}: {:#018x}",
        folder.as_u64(),
        saved.id().as_u64()
    );
    for number in saved.attachments() {
        println!("  attachment #{number}");
    }
    for problem in saved.problems() {
        println!("  the server refused {problem}");
    }
    if saved.is_clean() {
        println!("  every property was accepted");
    }
}

/// The tag this store uses for a named property, or a failure that says which one is missing.
pub(super) fn tag_of(
    named: &mapi_client::NamedProperties,
    property: NamedProperty,
) -> Result<PropertyTag, Failure> {
    named.tag_of(property).ok_or_else(|| {
        Failure::from(format!(
            "this store does not map {property}, so the item cannot be written without it. Open \
             the mailbox in Outlook or OWA once and re-run."
        ))
    })
}

pub(super) fn string(value: &str) -> PropertyValue {
    PropertyValue::String(value.into())
}

/// Splits a display name into a given name and a surname, on the last space.
///
/// A crude rule, and deliberately visible rather than hidden in the library: names do not split
/// this way in general, and a client that cares should set the three properties itself.
fn split_name(name: &str) -> (&str, &str) {
    match name.rsplit_once(' ') {
        Some((given, surname)) => (given, surname),
        None => (name, ""),
    }
}

/// `PidLidFileUnder`, as "surname, given name" where there is a surname.
///
/// [MS-OXOCNTC] §2.2.1.1.11 leaves the format to the client, and `PidLidFileUnderId` is
/// deliberately not written: it names the formula that produced this string, and an unset id means
/// the value is the client's own — which it is.
fn file_under(given: &str, surname: &str, name: &str) -> String {
    if surname.is_empty() {
        name.to_owned()
    } else {
        format!("{surname}, {given}")
    }
}

/// Reads `YYYY-MM-DDTHH:MM:SSZ` into a `FILETIME`.
///
/// A deliberately narrow parser rather than a date library. This crate has none — and the one thing
/// a calendar write must not do is guess a time zone, so the trailing `Z` is required rather than
/// assumed: [MS-OXOCAL] §2.2.1.5 specifies `PidLidAppointmentStartWhole` in UTC.
fn parse_instant(value: &str) -> Result<FileTime, Failure> {
    let refused = || {
        Failure::from(format!(
            "`{value}` is not an instant. Write it as 2026-09-10T09:00:00Z — UTC, with the Z, \
             because a calendar entry's start is specified in UTC and this tool will not guess a \
             time zone."
        ))
    };

    let body = value.strip_suffix('Z').ok_or_else(refused)?;
    let (date, time) = body.split_once('T').ok_or_else(refused)?;
    let mut date = date.split('-');
    let mut time = time.split(':');

    let next = |part: Option<&str>| -> Result<i64, Failure> {
        part.and_then(|part| part.parse::<i64>().ok())
            .ok_or_else(refused)
    };
    let (year, month, day) = (next(date.next())?, next(date.next())?, next(date.next())?);
    let (hour, minute, second) = (next(time.next())?, next(time.next())?, next(time.next())?);
    if date.next().is_some() || time.next().is_some() {
        return Err(refused());
    }

    let seconds = seconds_from_civil(year, month, day, hour, minute, second).ok_or_else(refused)?;
    FileTime::from_unix_seconds(seconds).ok_or_else(refused)
}

/// The earliest year a `FILETIME` can express, and the latest a four-digit field can name.
const YEARS: core::ops::RangeInclusive<i64> = 1601..=9999;

/// The length of each month in a common year. February is corrected for a leap year.
const MONTH_LENGTHS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Unix seconds for a UTC calendar instant, or `None` for anything that is not one.
///
/// Every step is checked. Not defensiveness: the workspace forbids plain arithmetic in a code path
/// that reads a number somebody typed, and this is exactly that path.
fn seconds_from_civil(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> Option<i64> {
    // A leap second is 60, which a calendar entry will never carry and a parser should not refuse.
    if !(0..24).contains(&hour) || !(0..60).contains(&minute) || !(0..=60).contains(&second) {
        return None;
    }

    days_from_civil(year, month, day)?
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)
}

/// Days since 1970-01-01 for a proleptic Gregorian date, counted rather than computed.
///
/// The closed form is shorter and this is clearer, which matters more here: a calendar client that
/// is one day out on a leap year is worse than one that refuses the date, and the loop is over at
/// most the 8,398 years a `FILETIME` and a four-digit year between them allow.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !YEARS.contains(&year) {
        return None;
    }
    let index = usize::try_from(month.checked_sub(1)?).ok()?;
    if day < 1 || day > month_length(year, index)? {
        return None;
    }

    let mut days: i64 = 0;
    let mut counted = 1970_i64;
    while counted < year {
        days = days.checked_add(year_length(counted))?;
        counted = counted.checked_add(1)?;
    }
    while counted > year {
        counted = counted.checked_sub(1)?;
        days = days.checked_sub(year_length(counted))?;
    }
    for earlier in 0..index {
        days = days.checked_add(month_length(year, earlier)?)?;
    }
    days.checked_add(day.checked_sub(1)?)
}

/// 366 in a leap year, 365 otherwise.
fn year_length(year: i64) -> i64 {
    if is_leap(year) { 366 } else { 365 }
}

/// The length of the month at `index`, `0` being January, or `None` for an index past December.
fn month_length(year: i64, index: usize) -> Option<i64> {
    let length = *MONTH_LENGTHS.get(index)?;
    Some(if index == 1 && is_leap(year) {
        29
    } else {
        length
    })
}

/// The Gregorian rule, written out: every fourth year, except every hundredth, except every four
/// hundredth.
fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against instants computed independently: the Unix epoch, a leap day, and the two the live
    /// suite uses.
    #[test]
    fn an_instant_parses_to_the_seconds_it_names() {
        for (text, unix) in [
            ("1970-01-01T00:00:00Z", 0_i64),
            ("2000-02-29T12:00:00Z", 951_825_600),
            ("2026-09-10T09:00:00Z", 1_789_030_800),
            ("2026-09-10T10:00:00Z", 1_789_034_400),
        ] {
            let parsed = parse_instant(text).expect(text);
            assert_eq!(parsed.to_unix_seconds(), Some(unix), "{text}");
        }
    }

    /// The `Z` is required. A calendar entry's start is UTC, and a client that quietly read a local
    /// time as UTC would put every appointment at the wrong hour with no error anywhere.
    #[test]
    fn an_instant_without_a_zone_is_refused_rather_than_assumed() {
        for bad in [
            "2026-09-10T09:00:00",
            "2026-09-10 09:00:00Z",
            "2026-09-10T09:00Z",
            "2026-13-01T00:00:00Z",
            "2026-09-32T00:00:00Z",
            "yesterdayZ",
            "",
        ] {
            assert!(parse_instant(bad).is_err(), "{bad:?}");
        }
    }

    /// The three centuries the hundred-year rule and the four-hundred-year rule disagree about,
    /// which is where a hand-written calendar goes wrong.
    #[test]
    fn the_gregorian_leap_rule_is_the_whole_rule() {
        for (year, leap) in [
            (1900, false),
            (2000, true),
            (2024, true),
            (2100, false),
            (2200, false),
            (2400, true),
        ] {
            assert_eq!(is_leap(year), leap, "{year}");
            assert_eq!(year_length(year), if leap { 366 } else { 365 }, "{year}");
        }
        assert_eq!(month_length(2024, 1), Some(29));
        assert_eq!(month_length(2023, 1), Some(28));
        assert_eq!(month_length(2023, 12), None);
    }

    #[test]
    fn a_name_splits_on_its_last_space_and_says_so_when_it_cannot() {
        assert_eq!(split_name("Ada Lovelace"), ("Ada", "Lovelace"));
        assert_eq!(split_name("Ada King Lovelace"), ("Ada King", "Lovelace"));
        assert_eq!(split_name("Prince"), ("Prince", ""));

        assert_eq!(
            file_under("Ada", "Lovelace", "Ada Lovelace"),
            "Lovelace, Ada"
        );
        assert_eq!(file_under("Prince", "", "Prince"), "Prince");
    }

    /// The five flags [MS-OXOCAL] §2.2.2.2 names, spelled out against [MS-OXCMSG] §2.2.1.16's
    /// values rather than against the constant that combines them.
    #[test]
    fn the_calendar_side_effects_are_the_five_the_document_lists() {
        for (name, flag) in [
            ("seOpenToDelete", 0x0001),
            ("seOpenToCopy", 0x0020),
            ("seOpenToMove", 0x0040),
            ("seCoerceToInbox", 0x0100),
            ("seOpenForCtxMenu", 0x0400),
        ] {
            assert_eq!(CALENDAR_SIDE_EFFECTS & flag, flag, "{name}");
        }
        assert_eq!(CALENDAR_SIDE_EFFECTS, 0x0561);
    }
}
