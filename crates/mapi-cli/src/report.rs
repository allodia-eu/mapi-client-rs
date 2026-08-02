//! Putting bytes and rows on a terminal.
//!
//! The hex dump is the reason this crate exists at all: when a deployment misbehaves, the useful
//! question is what the buffer actually contains, and no amount of decoded output answers it.

use core::fmt::Write as _;

use mapi_client::{Exchange, Observer, PropertyRow, PropertyTag};

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

/// A one-line summary of a hierarchy-table row.
pub(crate) fn folder_line(row: &PropertyRow) -> String {
    let name = string_cell(row, PropertyTag::DISPLAY_NAME);
    match row.folder_id() {
        Some(id) => format!("  {:#018x}  {name}", id.as_u64()),
        None => format!("  {:18}  {name}", "(no id)"),
    }
}

/// A one-line summary of a contents-table row.
pub(crate) fn message_line(row: &PropertyRow) -> String {
    let subject = string_cell(row, PropertyTag::SUBJECT);
    match row.message_id() {
        Some(id) => format!("  {:#018x}  {subject}", id.as_u64()),
        None => format!("  {:18}  {subject}", "(no id)"),
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

    #[test]
    fn byte_counts_read_as_english() {
        assert_eq!(bytes(0), "0 bytes");
        assert_eq!(bytes(1), "1 byte");
        assert_eq!(bytes(2), "2 bytes");
    }
}
