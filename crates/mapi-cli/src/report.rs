//! Putting bytes and rows on a terminal.
//!
//! The hex dump is the reason this crate exists at all: when a deployment misbehaves, the useful
//! question is what the buffer actually contains, and no amount of decoded output answers it.

use core::fmt::Write as _;

use mapi_client::{
    Cell, Exchange, FileTime, Observer, PropertyRow, PropertySet, PropertyTag, PropertyValue,
    TableString,
};

/// Bytes per line of a hex dump, which is what fits an eighty-column terminal alongside the ASCII.
const PER_LINE: usize = 16;

/// A classic offset / hex / ASCII dump, stopping after `limit` bytes.
///
/// The tail is summarised rather than dropped silently: a dump that quietly stopped would be a
/// dump you could draw the wrong conclusion from.
pub(crate) fn hex_dump(bytes: &[u8], limit: usize) -> String {
    let shown = bytes.get(..limit.min(bytes.len())).unwrap_or_default();
    let mut lines: Vec<String> = shown
        .chunks(PER_LINE)
        .enumerate()
        .map(|(index, chunk)| {
            let offset = index.saturating_mul(PER_LINE);
            let hex = chunk.iter().fold(String::new(), |mut out, byte| {
                // Writing into a `String` cannot fail; the result is discarded deliberately.
                let _ = write!(out, "{byte:02x} ");
                out
            });
            let text: String = chunk
                .iter()
                .map(|byte| {
                    if byte.is_ascii_graphic() || *byte == b' ' {
                        char::from(*byte)
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("  {offset:08x}  {hex:<48} |{text}|\n")
        })
        .collect();

    if let Some(rest) = bytes
        .len()
        .checked_sub(shown.len())
        .filter(|rest| *rest > 0)
    {
        lines.push(format!("  ... {rest} more byte(s)\n"));
    }
    lines.concat()
}

/// A row's string value, with the truncation the table performed made visible.
///
/// A table silently cuts a string value at 255 characters and says so nowhere except in the
/// value's own length, so a diagnostic that printed the value alone would be the very data-loss
/// bug this crate exists to make impossible.
///
/// [MS-OXCDATA] §2.11.1
pub(crate) fn string_cell(row: &PropertyRow, tag: PropertyTag) -> String {
    match row.string(tag) {
        None => "(absent)".to_owned(),
        Some(value) if value.is_truncated() => {
            format!("{} [truncated by the table]", value.as_str())
        }
        Some(value) => value.as_str().to_owned(),
    }
}

/// A one-line summary of a hierarchy-table row, indented by how deep the folder sits.
///
/// The class is shown because it is the whole of what makes a folder a calendar rather than a mail
/// folder, and because a recursive listing without it is a list of names in a language the reader
/// may not have.
pub(crate) fn folder_line(row: &PropertyRow, depth: usize) -> String {
    let name = string_cell(row, PropertyTag::DISPLAY_NAME);
    let class = row
        .string(PropertyTag::CONTAINER_CLASS)
        .map(TableString::as_str)
        .filter(|value| !value.is_empty())
        .map_or_else(String::new, |value| format!("  [{value}]"));
    let indent = "  ".repeat(depth);

    match row.folder_id() {
        Some(id) => format!("  {:#018x}  {indent}{name}{class}", id.as_u64()),
        None => format!("  {:18}  {indent}{name}{class}", "(no id)"),
    }
}

/// A one-line summary of a folder's own properties.
///
/// `PidTagFolderType` is called out because a search folder answers every other property exactly
/// as a real folder does: the To-Do list reports a container class and a message count and holds
/// none of them.
///
/// [MS-OXCFOLD] §2.2.2.2.2.7 — Root (0), Generic (1), Search (2)
pub(crate) fn folder_summary(properties: &PropertySet) -> String {
    let text = |tag| {
        properties
            .string(tag)
            .map_or_else(|| "(absent)".to_owned(), |value| value.as_str().to_owned())
    };
    let number = |tag| {
        properties
            .get(tag)
            .and_then(PropertyValue::as_u32)
            .map_or_else(|| "(absent)".to_owned(), |value| value.to_string())
    };

    let kind = match properties
        .get(PropertyTag::FOLDER_TYPE)
        .and_then(PropertyValue::as_u32)
    {
        Some(0) => "root".to_owned(),
        Some(1) => "generic".to_owned(),
        Some(2) => "search folder — its contents are a query, not items it holds".to_owned(),
        Some(other) => format!("type {other}, which [MS-OXCFOLD] §2.2.2.2.2.7 does not list"),
        None => "(absent)".to_owned(),
    };

    let size = properties
        .get(PropertyTag::MESSAGE_SIZE_EXTENDED)
        .and_then(PropertyValue::as_u64)
        .map_or_else(|| "(absent)".to_owned(), |value| format!("{value} bytes"));

    [
        format!("  display name     {}", text(PropertyTag::DISPLAY_NAME)),
        format!("  container class  {}", text(PropertyTag::CONTAINER_CLASS)),
        format!(
            "  content          {} item(s), {} unread, {size}",
            number(PropertyTag::CONTENT_COUNT),
            number(PropertyTag::CONTENT_UNREAD_COUNT)
        ),
        format!("  kind             {kind}"),
    ]
    .join("\n")
}

/// A one-line summary of a contents-table row.
pub(crate) fn message_line(row: &PropertyRow) -> String {
    let subject = string_cell(row, PropertyTag::SUBJECT);
    match row.message_id() {
        Some(id) => format!("  {:#018x}  {subject}", id.as_u64()),
        None => format!("  {:18}  {subject}", "(no id)"),
    }
}

/// One property, as the tag it arrived under, the type that tag declares, and the value.
///
/// Two things are called out rather than printed flat, because both are the kind of number that
/// reads as a fact and is not one:
///
/// * **A named-property id.** Ids from `0x8000` up are allocated per store, so the same number
///   means a different property in a different mailbox.
/// * **An error in place of a value.** A property too large for the response buffer comes back
///   under its own id with the type changed to `PtypErrorCode`, which is a different statement from
///   "not set".
pub(crate) fn property_line(cell: &Cell) -> String {
    let tag = cell.tag().to_string();
    let property_type = cell.tag().property_type().to_string();
    let note = if cell.tag().is_named() {
        "   <- named property; this id means nothing in another mailbox"
    } else if cell.value().as_error().is_some() {
        "   <- the server declined to return the value, not an empty value"
    } else {
        ""
    };

    format!("  {tag:<40} {property_type:<22} {}{note}", cell.value())
}

/// The half-dozen properties that answer "tell me about this mailbox".
///
/// [MS-OXCSTOR] §2.2.2.1 — private mailbox logon properties
pub(crate) fn mailbox_summary(properties: &PropertySet) -> String {
    let text = |tag| {
        properties
            .string(tag)
            .map_or_else(|| "(absent)".to_owned(), |value| value.as_str().to_owned())
    };

    let count = properties
        .get(PropertyTag::CONTENT_COUNT)
        .and_then(PropertyValue::as_u32)
        .map_or_else(|| "(absent)".to_owned(), |count| count.to_string());

    let size = properties
        .get(PropertyTag::MESSAGE_SIZE_EXTENDED)
        .and_then(PropertyValue::as_u64)
        .map_or_else(|| "(absent)".to_owned(), |bytes| format!("{bytes} bytes"));

    [
        format!("  display name     {}", text(PropertyTag::DISPLAY_NAME)),
        format!(
            "  owner            {}",
            text(PropertyTag::MAILBOX_OWNER_NAME)
        ),
        format!("  content          {count} message(s), {size}"),
        format!(
            "  send quota       {}",
            quota(properties, PropertyTag::PROHIBIT_SEND_QUOTA)
        ),
        format!(
            "  receive quota    {}",
            quota(properties, PropertyTag::PROHIBIT_RECEIVE_QUOTA)
        ),
        format!(
            "  submit limit     {}",
            quota(properties, PropertyTag::MAXIMUM_SUBMIT_MESSAGE_SIZE)
        ),
    ]
    .join("\n")
}

/// A quota in kilobytes, where an unset value **and** `-1` both mean "no limit".
///
/// The sentinel is why this is not a plain integer: the field is `PtypInteger32`, so `-1` arrives
/// as `0xFFFFFFFF` and printing it unsigned would report a four-terabyte quota.
///
/// [MS-OXCSTOR] §2.2.2.1.1.3 — "An unset value or a value of -1 indicates that there is no limit"
fn quota(properties: &PropertySet, tag: PropertyTag) -> String {
    match properties.get(tag).and_then(PropertyValue::as_i32) {
        None => "(absent, so no limit)".to_owned(),
        Some(-1) => "no limit".to_owned(),
        Some(kilobytes) => format!("{kilobytes} KB"),
    }
}

/// Prints every exchange as a hex dump, which is what `--dump` is for.
///
/// The reason to reach for this: a wrong `RopBuffer` is not readable by inspection and a decoded
/// view of it is a view through the very code you are doubting. Bytes are the only thing that
/// settles an argument with a server.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Dump {
    /// How much of each body to show. The rest is counted rather than dropped silently.
    pub(crate) limit: usize,
}

impl Observer for Dump {
    fn observe(&self, exchange: &Exchange<'_>) {
        println!(
            "\n--> {} request, {}",
            exchange.request_type(),
            bytes(exchange.request_body().len())
        );
        for (name, value) in exchange.request_headers() {
            println!("  {name}: {value}");
        }
        print!("{}", hex_dump(exchange.request_body(), self.limit));

        println!(
            "\n<-- HTTP {}, {}",
            exchange.status(),
            bytes(exchange.response_body().len())
        );
        for (name, value) in exchange.response_headers() {
            println!("  {name}: {value}");
        }
        print!("{}", hex_dump(exchange.response_body(), self.limit));
    }
}

/// A `PtypTime` as an ISO-8601 instant in UTC.
///
/// Written out rather than pulled from a date library because the workspace has no dependency that
/// would supply one and this is the only place a calendar is needed. The conversion is Howard
/// Hinnant's `civil_from_days`, which is exact for the whole range a `FILETIME` can express.
///
/// **Everything MAPI stores is UTC.** [MS-OXOCAL] §2.2.1.5 has `PidLidAppointmentStartWhole` in
/// UTC, and the timezone an event was *created* in is a separate property this crate does not
/// read — so a start time printed here is the right instant and not necessarily the wall clock the
/// organiser saw.
pub(crate) fn timestamp(time: FileTime) -> String {
    let Some((year, month, day, hour, minute, second)) =
        time.to_unix_seconds().and_then(civil_from_unix)
    else {
        return format!("FILETIME({})", time.as_u64());
    };

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}Z")
}

/// Unix seconds to year, month, day, hour, minute, second — Howard Hinnant's `civil_from_days`.
///
/// Every step is checked rather than plain arithmetic, which the workspace's
/// `arithmetic_side_effects` lint requires and which is not merely ceremony here: the input is a
/// `FILETIME` from a server, so the range is whatever that server chose to send.
fn civil_from_unix(seconds: i64) -> Option<(i64, i64, i64, i64, i64, i64)> {
    let time_of_day = seconds.checked_rem_euclid(86_400)?;
    let hour = time_of_day.checked_div(3_600)?;
    let minute = time_of_day.checked_rem(3_600)?.checked_div(60)?;
    let second = time_of_day.checked_rem(60)?;

    // Shift the epoch to 0000-03-01 so that a leap day is always the last day of a year.
    let shifted = seconds.checked_div_euclid(86_400)?.checked_add(719_468)?;
    let era = shifted.checked_div_euclid(146_097)?;
    let day_of_era = shifted.checked_rem_euclid(146_097)?;
    let year_of_era = day_of_era
        .checked_sub(day_of_era.checked_div(1_460)?)?
        .checked_add(day_of_era.checked_div(36_524)?)?
        .checked_sub(day_of_era.checked_div(146_096)?)?
        .checked_div(365)?;
    let day_of_year = day_of_era.checked_sub(
        year_of_era
            .checked_mul(365)?
            .checked_add(year_of_era.checked_div(4)?)?
            .checked_sub(year_of_era.checked_div(100)?)?,
    )?;

    let shifted_month = day_of_year
        .checked_mul(5)?
        .checked_add(2)?
        .checked_div(153)?;
    let day = day_of_year
        .checked_sub(
            shifted_month
                .checked_mul(153)?
                .checked_add(2)?
                .checked_div(5)?,
        )?
        .checked_add(1)?;
    let month = if shifted_month < 10 {
        shifted_month.checked_add(3)?
    } else {
        shifted_month.checked_sub(9)?
    };

    let year = year_of_era.checked_add(era.checked_mul(400)?)?;
    let year = if month <= 2 {
        year.checked_add(1)?
    } else {
        year
    };
    Some((year, month, day, hour, minute, second))
}

/// A byte count, for the summaries.
pub(crate) fn bytes(count: usize) -> String {
    if count == 1 {
        "1 byte".to_owned()
    } else {
        format!("{count} bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hex_dump_shows_offsets_hex_and_printable_text() {
        let dump = hex_dump(b"MAPI\x00\xffok", 64);
        assert!(dump.contains("00000000"), "{dump}");
        assert!(dump.contains("4d 41 50 49 00 ff 6f 6b"), "{dump}");
        assert!(dump.contains("|MAPI..ok|"), "{dump}");
        assert_eq!(dump.lines().count(), 1);
    }

    #[test]
    fn a_long_dump_says_how_much_it_did_not_show() {
        let dump = hex_dump(&[0x41; 40], 16);
        assert!(dump.contains("... 24 more byte(s)"), "{dump}");
        assert_eq!(dump.lines().count(), 2);
    }

    #[test]
    fn an_empty_dump_is_empty_rather_than_a_blank_line() {
        assert_eq!(hex_dump(b"", 16), "");
    }

    /// Two instants whose calendar arithmetic is easy to get wrong: the Unix epoch itself, and a
    /// leap day in a century year that *is* a leap year.
    #[test]
    fn a_filetime_prints_as_a_readable_instant() {
        // 1970-01-01T00:00:00Z, which is 11644473600 seconds after the FILETIME epoch.
        assert_eq!(
            timestamp(FileTime::new(116_444_736_000_000_000)),
            "1970-01-01 00:00:00Z"
        );
        // 2000-02-29T12:34:56Z. 2000 is a leap year despite being a century year.
        assert_eq!(
            timestamp(FileTime::new(125_963_012_960_000_000)),
            "2000-02-29 12:34:56Z"
        );
        // The FILETIME epoch itself, which is before the Unix one.
        assert_eq!(timestamp(FileTime::new(0)), "1601-01-01 00:00:00Z");
    }

    #[test]
    fn byte_counts_read_as_english() {
        assert_eq!(bytes(0), "0 bytes");
        assert_eq!(bytes(1), "1 byte");
        assert_eq!(bytes(2), "2 bytes");
    }
}
