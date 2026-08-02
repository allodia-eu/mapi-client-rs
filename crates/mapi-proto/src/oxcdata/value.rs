//! Property values, and the truncation a table quietly applies to strings.

use crate::error::ErrorCode;
use crate::oxcdata::{FileTime, Guid, PropertyType};

mod codec;

#[cfg(test)]
mod tests;

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
/// Observed on Exchange Server SE `15.02.2562.045`: a 300-character subject came back as exactly
/// 255 characters, the last three a literal `...` the server appended — the sent subject was
/// digits alone, so the ellipsis is the server's and not the sender's. The specification documents
/// the length rule but not the ellipsis, so detection here uses the length.
///
/// **Only a table truncates.** The same property read from the object itself comes back whole, or
/// as `NotEnoughMemory` if it does not fit ([MS-OXCPRPT] §2.2.3.2), so a string that arrived that
/// way is always [`Complete`](Self::Complete) however long it is.
///
/// [MS-OXCDATA] §2.8.2 — `PropertyRowSet` structures
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TableString {
    /// Shorter than the table limit, or not read from a table at all. This is the whole value.
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

impl From<&str> for TableString {
    /// A string a caller built, which no server has had the chance to truncate.
    fn from(text: &str) -> Self {
        Self::Complete(text.to_owned())
    }
}

impl From<String> for TableString {
    /// A string a caller built, which no server has had the chance to truncate.
    fn from(text: String) -> Self {
        Self::Complete(text)
    }
}

/// A `PtypFloating64` value, held as the eight bytes the wire carried.
///
/// The bits rather than an `f64` so that a [`PropertyValue`] can stay `Eq`, `Ord` and `Hash` —
/// which the response types are compared and hashed by throughout this workspace, and which no
/// type containing a bare `f64` can be. Two of these are equal when the server sent the same eight
/// bytes, which is the question a wire codec is actually asked; [`as_f64`](Self::as_f64) hands back
/// the number for arithmetic.
///
/// [MS-OXCDATA] §2.11.1 — `PtypFloating64`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Floating64(u64);

impl Floating64 {
    /// Wraps the raw bit pattern as the wire carries it.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Wraps a number.
    #[must_use]
    pub const fn new(value: f64) -> Self {
        Self(value.to_bits())
    }

    /// The bit pattern, which little-endian encoded is the wire form.
    #[must_use]
    pub const fn to_bits(self) -> u64 {
        self.0
    }

    /// The number.
    #[must_use]
    pub const fn as_f64(self) -> f64 {
        f64::from_bits(self.0)
    }
}

impl core::fmt::Display for Floating64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_f64())
    }
}

/// One value, of the type its tag or its column declared.
///
/// [MS-OXCDATA] §2.11.2 — `PropertyValue` structure
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PropertyValue {
    /// A `PtypInteger16` value.
    Integer16(u16),
    /// A `PtypInteger32` value.
    Integer32(u32),
    /// A `PtypInteger64` value.
    Integer64(u64),
    /// A `PtypFloating64` value.
    Floating64(Floating64),
    /// A `PtypBoolean` value.
    Boolean(bool),
    /// A `PtypString` value, with the table's truncation made visible.
    String(TableString),
    /// A `PtypString8` value, decoded from the session's code page.
    ///
    /// Kept apart from [`String`](Self::String) because which one arrived is a fact about the
    /// server's answer, and because an 8-bit value that failed to decode cleanly is worth being
    /// able to see. [`as_string`](Self::as_string) answers for both, since a caller after a display
    /// name has no reason to care.
    ///
    /// [MS-OXCDATA] §2.11.1.2 — string property values
    String8(TableString),
    /// A `PtypTime` value.
    Time(FileTime),
    /// A `PtypGuid` value.
    Guid(Guid),
    /// A `PtypBinary` value.
    Binary(Vec<u8>),
    /// A `PtypMultipleInteger32` value.
    MultipleInteger32(Vec<u32>),
    /// A `PtypMultipleString` value.
    MultipleString(Vec<TableString>),
    /// A `PtypMultipleBinary` value.
    MultipleBinary(Vec<Vec<u8>>),
    /// The server returned an error code where a value was asked for.
    ///
    /// Routine rather than exceptional: it is how a value too large for a row or for the response
    /// buffer comes back. [MS-OXCDATA] §2.11.5 — `FlaggedPropertyValue` flag `0x0A`
    Error(ErrorCode),
    /// The property is not set on this row, and no value bytes were present.
    ///
    /// [MS-OXCDATA] §2.11.5 — `FlaggedPropertyValue` flag `0x01`
    Absent,
}

impl PropertyValue {
    /// The type a tag would have to declare to carry this value, or `None` for
    /// [`Absent`](Self::Absent), which is the absence of one.
    #[must_use]
    pub const fn property_type(&self) -> Option<PropertyType> {
        Some(match self {
            Self::Integer16(_) => PropertyType::Integer16,
            Self::Integer32(_) => PropertyType::Integer32,
            Self::Integer64(_) => PropertyType::Integer64,
            Self::Floating64(_) => PropertyType::Floating64,
            Self::Boolean(_) => PropertyType::Boolean,
            Self::String(_) => PropertyType::String,
            Self::String8(_) => PropertyType::String8,
            Self::Time(_) => PropertyType::Time,
            Self::Guid(_) => PropertyType::Guid,
            Self::Binary(_) => PropertyType::Binary,
            Self::MultipleInteger32(_) => PropertyType::MultipleInteger32,
            Self::MultipleString(_) => PropertyType::MultipleString,
            Self::MultipleBinary(_) => PropertyType::MultipleBinary,
            Self::Error(_) => PropertyType::ErrorCode,
            Self::Absent => return None,
        })
    }

    /// The value if it is a `PtypInteger16`.
    #[must_use]
    pub const fn as_u16(&self) -> Option<u16> {
        match self {
            Self::Integer16(value) => Some(*value),
            _ => None,
        }
    }

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

    /// The value if it is a `PtypInteger32`, read as the signed integer it sometimes is.
    ///
    /// [MS-OXCSTOR] documents a quota of `-1` as "no limit" in a field whose type is
    /// `PtypInteger32`, so the same four bytes are a count in one property and a sentinel in
    /// another. Both readings are offered rather than one being chosen for the caller.
    #[must_use]
    pub const fn as_i32(&self) -> Option<i32> {
        match self {
            Self::Integer32(value) => Some(value.cast_signed()),
            _ => None,
        }
    }

    /// The value if it is a `PtypFloating64`.
    #[must_use]
    pub const fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Floating64(value) => Some(value.as_f64()),
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

    /// The value if it is a string of either width.
    #[must_use]
    pub const fn as_string(&self) -> Option<&TableString> {
        match self {
            Self::String(value) | Self::String8(value) => Some(value),
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

    /// The value if it is a `PtypGuid`.
    #[must_use]
    pub const fn as_guid(&self) -> Option<Guid> {
        match self {
            Self::Guid(value) => Some(*value),
            _ => None,
        }
    }

    /// The value if it is a `PtypBinary`.
    #[must_use]
    pub fn as_binary(&self) -> Option<&[u8]> {
        match self {
            Self::Binary(value) => Some(value),
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
}

impl core::fmt::Display for PropertyValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Integer16(value) => write!(f, "{value}"),
            Self::Integer32(value) => write!(f, "{value}"),
            Self::Integer64(value) => write!(f, "0x{value:016X}"),
            Self::Floating64(value) => write!(f, "{value}"),
            Self::Boolean(value) => write!(f, "{value}"),
            Self::String(text) | Self::String8(text) => show_string(f, text),
            Self::Time(value) => write!(f, "FILETIME({})", value.as_u64()),
            Self::Guid(value) => write!(f, "{value}"),
            Self::Binary(bytes) => write!(f, "{} byte(s)", bytes.len()),
            Self::MultipleInteger32(values) => write!(f, "{values:?}"),
            Self::MultipleString(values) => {
                f.write_str("[")?;
                for (index, text) in values.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    show_string(f, text)?;
                }
                f.write_str("]")
            }
            Self::MultipleBinary(values) => {
                let total: usize = values.iter().map(Vec::len).sum();
                write!(f, "{} value(s), {total} byte(s)", values.len())
            }
            Self::Error(code) => write!(f, "<{code}>"),
            Self::Absent => f.write_str("<absent>"),
        }
    }
}

/// A string value, saying so when the table cut it short.
fn show_string(f: &mut core::fmt::Formatter<'_>, text: &TableString) -> core::fmt::Result {
    match text {
        TableString::Complete(text) => write!(f, "{text:?}"),
        TableString::Truncated(text) => write!(f, "{text:?} (truncated)"),
    }
}
