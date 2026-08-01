//! Property values, and the truncation a table quietly applies to strings.

use crate::error::{Error, ErrorCode, Result};
use crate::oxcdata::{FileTime, PropertyType};
use crate::wire::Reader;

/// The length at which a table string stops being trustworthy.
///
/// [MS-OXCDATA] §2.8.2 — "column values larger than 255 bytes (for binary types) or 255
/// characters (for string types) can be truncated by the server for performance reasons.
/// Clients analyzing data returned from table operations can assume that if the length of such a
/// value is exactly 255 bytes or characters, then the value of the same property obtained by
/// opening the message [...] is likely to be larger."
const TABLE_STRING_LIMIT: usize = 255;

/// A string read out of a table row, carrying whether it is the whole value.
///
/// A table does not report truncation: there is no error code and no flag, the value simply comes
/// back shorter than it is. Handing back a bare `&str` would put a silently corrupted subject line
/// into a caller's search index, so the two cases are different variants and the caller has to
/// look at which one it got.
///
/// Observed on Exchange Server SE `15.02.2562.000`: a truncated value is exactly 255 characters
/// and ends in a literal `...` that the server appended. The specification documents the length
/// rule but not the ellipsis, so detection here uses the length.
///
/// [MS-OXCDATA] §2.8.2 — `PropertyRowSet` structures
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TableString {
    /// Shorter than the table limit, so this is the whole value.
    Complete(String),
    /// Exactly at the table limit. The real value is likely longer; read the property from the
    /// message itself to get all of it.
    Truncated(String),
}

impl TableString {
    /// Classifies a string that came out of a table row.
    #[must_use]
    pub fn from_table(text: String) -> Self {
        if text.chars().count() >= TABLE_STRING_LIMIT {
            Self::Truncated(text)
        } else {
            Self::Complete(text)
        }
    }

    /// The text as received — truncated or not.
    ///
    /// Deliberately explicit: reaching for this is how a caller says it does not mind either way.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Complete(text) | Self::Truncated(text) => text,
        }
    }

    /// The text, but only when it is known to be whole.
    #[must_use]
    pub fn complete(&self) -> Option<&str> {
        match self {
            Self::Complete(text) => Some(text),
            Self::Truncated(_) => None,
        }
    }

    /// Whether the server may have cut this value short.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated(_))
    }

    /// Takes the text out, truncated or not.
    #[must_use]
    pub fn into_string(self) -> String {
        match self {
            Self::Complete(text) | Self::Truncated(text) => text,
        }
    }
}

/// One value from a row, of the type its column declared.
///
/// [MS-OXCDATA] §2.11.2 — `PropertyValue` structure
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PropertyValue {
    /// A `PtypInteger32` value.
    Integer32(u32),
    /// A `PtypInteger64` value.
    Integer64(u64),
    /// A `PtypBoolean` value.
    Boolean(bool),
    /// A `PtypString` value, with the table's truncation made visible.
    String(TableString),
    /// A `PtypTime` value.
    Time(FileTime),
    /// The server returned an error code where a value was asked for.
    ///
    /// Routine rather than exceptional in a table: it is how a value too large for a row comes
    /// back. [MS-OXCDATA] §2.11.5 — `FlaggedPropertyValue` flag `0x0A`
    Error(ErrorCode),
    /// The property is not set on this row, and no value bytes were present.
    ///
    /// [MS-OXCDATA] §2.11.5 — `FlaggedPropertyValue` flag `0x01`
    Absent,
}

impl PropertyValue {
    /// The value if it is a `PtypInteger32`.
    #[must_use]
    pub const fn as_u32(&self) -> Option<u32> {
        match self {
            Self::Integer32(value) => Some(*value),
            _ => None,
        }
    }

    /// The value if it is a `PtypInteger64`.
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Integer64(value) => Some(*value),
            _ => None,
        }
    }

    /// The value if it is a `PtypBoolean`.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    /// The value if it is a `PtypString`.
    #[must_use]
    pub const fn as_string(&self) -> Option<&TableString> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// The value if it is a `PtypTime`.
    #[must_use]
    pub const fn as_time(&self) -> Option<FileTime> {
        match self {
            Self::Time(value) => Some(*value),
            _ => None,
        }
    }

    /// The error code, if the server sent one in place of a value.
    #[must_use]
    pub const fn as_error(&self) -> Option<ErrorCode> {
        match self {
            Self::Error(code) => Some(*code),
            _ => None,
        }
    }

    /// Reads one value of the type its column declared.
    ///
    /// Values are not self-describing — the type comes from the column set, never from the bytes.
    pub(crate) fn read(r: &mut Reader<'_>, property_type: PropertyType) -> Result<Self> {
        Ok(match property_type {
            PropertyType::Integer32 => Self::Integer32(r.u32()?),
            PropertyType::ErrorCode => Self::Error(ErrorCode::new(r.u32()?)),
            PropertyType::Boolean => Self::Boolean(r.u8()? != 0),
            PropertyType::Integer64 => Self::Integer64(r.u64()?),
            PropertyType::String => Self::String(TableString::from_table(r.utf16_z()?)),
            PropertyType::Time => Self::Time(FileTime::new(r.u64()?)),
            PropertyType::Unsupported(raw) => {
                return Err(Error::UnsupportedPropertyType {
                    property_type: raw,
                    at: r.position(),
                });
            }
        })
    }
}

impl core::fmt::Display for PropertyValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Integer32(value) => write!(f, "{value}"),
            Self::Integer64(value) => write!(f, "0x{value:016X}"),
            Self::Boolean(value) => write!(f, "{value}"),
            Self::String(TableString::Complete(text)) => write!(f, "{text:?}"),
            Self::String(TableString::Truncated(text)) => write!(f, "{text:?} (truncated)"),
            Self::Time(value) => write!(f, "FILETIME({})", value.as_u64()),
            Self::Error(code) => write!(f, "<{code}>"),
            Self::Absent => f.write_str("<absent>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_z(text: &str) -> Vec<u8> {
        let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.extend_from_slice(&[0x00, 0x00]);
        out
    }

    #[test]
    fn each_modelled_type_reads_its_own_width() {
        let cases: [(PropertyType, &[u8], PropertyValue); 5] = [
            (
                PropertyType::Integer32,
                &[0x07, 0x00, 0x00, 0x00],
                PropertyValue::Integer32(7),
            ),
            (
                PropertyType::Integer64,
                &[0x01, 0, 0, 0, 0, 0, 0, 0x0D],
                PropertyValue::Integer64(0x0D00_0000_0000_0001),
            ),
            (PropertyType::Boolean, &[0x01], PropertyValue::Boolean(true)),
            (
                PropertyType::Time,
                &[0x9E, 0x71, 0x1A, 0x36, 0x5E, 0xD8, 0xDD, 0x01],
                PropertyValue::Time(FileTime::new(0x01DD_D85E_361A_719E)),
            ),
            (
                PropertyType::ErrorCode,
                &[0x05, 0x03, 0x04, 0x80],
                PropertyValue::Error(ErrorCode::TOO_BIG),
            ),
        ];

        for (property_type, bytes, expected) in cases {
            let mut r = Reader::new(bytes);
            assert_eq!(
                PropertyValue::read(&mut r, property_type).unwrap(),
                expected
            );
            assert!(r.is_empty(), "{property_type} left bytes behind");
        }
    }

    #[test]
    fn accessors_answer_only_for_their_own_type() {
        let value = PropertyValue::Integer32(7);
        assert_eq!(value.as_u32(), Some(7));
        assert_eq!(value.as_u64(), None);
        assert_eq!(value.as_bool(), None);
        assert_eq!(value.as_string(), None);
        assert_eq!(value.as_time(), None);
        assert_eq!(value.as_error(), None);

        assert_eq!(PropertyValue::Boolean(true).as_bool(), Some(true));
        assert_eq!(PropertyValue::Integer64(9).as_u64(), Some(9));
        assert_eq!(
            PropertyValue::Time(FileTime::new(4)).as_time(),
            Some(FileTime::new(4))
        );
        assert_eq!(
            PropertyValue::Error(ErrorCode::NOT_FOUND).as_error(),
            Some(ErrorCode::NOT_FOUND)
        );
        assert_eq!(PropertyValue::Absent.as_u32(), None);
    }

    #[test]
    fn a_short_string_is_complete() {
        let bytes = utf16_z("Inbox");
        let value = PropertyValue::read(&mut Reader::new(&bytes), PropertyType::String).unwrap();
        let text = value.as_string().unwrap();
        assert!(!text.is_truncated());
        assert_eq!(text.complete(), Some("Inbox"));
        assert_eq!(text.as_str(), "Inbox");
        assert_eq!(value.to_string(), "\"Inbox\"");
    }

    /// Exchange truncates a table string at 255 characters and appends a literal `...`, with no
    /// error code and no flag. The only signal is the length, so the decoder has to act on it.
    #[test]
    fn a_string_at_the_table_limit_is_reported_as_truncated() {
        let long = format!("{}...", "x".repeat(252));
        assert_eq!(long.chars().count(), 255);

        let bytes = utf16_z(&long);
        let value = PropertyValue::read(&mut Reader::new(&bytes), PropertyType::String).unwrap();
        let text = value.as_string().unwrap();

        assert!(text.is_truncated());
        assert_eq!(text.complete(), None, "a truncated value is not the value");
        assert_eq!(
            text.as_str(),
            long,
            "the bytes received are still available"
        );
        assert!(value.to_string().ends_with("(truncated)"));
    }

    #[test]
    fn one_character_short_of_the_limit_is_still_complete() {
        let text = TableString::from_table("y".repeat(254));
        assert!(!text.is_truncated());
        assert_eq!(text.into_string().chars().count(), 254);
    }

    /// Counted in characters, not bytes: 255 emoji are four bytes each in UTF-8 and two units
    /// each in UTF-16, and none of those numbers is the one the specification talks about.
    #[test]
    fn the_limit_counts_characters_not_bytes() {
        assert!(TableString::from_table("é".repeat(255)).is_truncated());
        assert!(!TableString::from_table("é".repeat(200)).is_truncated());
    }

    #[test]
    fn an_unmodelled_type_stops_rather_than_guessing_a_length() {
        let mut r = Reader::new(&[0u8; 8]);
        assert_eq!(
            PropertyValue::read(&mut r, PropertyType::new(0x0102)),
            Err(Error::UnsupportedPropertyType {
                property_type: 0x0102,
                at: 0
            })
        );
    }

    #[test]
    fn truncated_buffers_never_panic() {
        for property_type in [
            PropertyType::Integer32,
            PropertyType::Integer64,
            PropertyType::Boolean,
            PropertyType::String,
            PropertyType::Time,
            PropertyType::ErrorCode,
        ] {
            for bytes in [&b""[..], &[0x01][..], &[0xFF, 0xFF, 0xFF][..]] {
                let _ = PropertyValue::read(&mut Reader::new(bytes), property_type);
            }
        }
    }

    #[test]
    fn values_render_for_humans() {
        assert_eq!(PropertyValue::Integer32(42).to_string(), "42");
        assert_eq!(
            PropertyValue::Integer64(0x0D00_0000_0000_0001).to_string(),
            "0x0D00000000000001"
        );
        assert_eq!(PropertyValue::Boolean(false).to_string(), "false");
        assert_eq!(
            PropertyValue::Time(FileTime::new(5)).to_string(),
            "FILETIME(5)"
        );
        assert_eq!(
            PropertyValue::Error(ErrorCode::TOO_BIG).to_string(),
            "<TooBig (0x80040305)>"
        );
        assert_eq!(PropertyValue::Absent.to_string(), "<absent>");
    }
}
