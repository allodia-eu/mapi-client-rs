//! Reading a property value off the wire, and putting one back on it.
//!
//! Values are **not self-describing**: the type comes from the column set or from the tag beside
//! them, never from the bytes. That is why every function here takes the type, and why an
//! unmodelled type stops the decode rather than skipping a length it would have to guess.
//!
//! [MS-OXCDATA] §2.11.2.1 — `PropertyValue` structure

use crate::error::{Error, ErrorCode, Result};
use crate::oxcdata::kind::{CountWidth, ValueContext};
use crate::oxcdata::{
    FileTime, Floating64, Guid, PropertyType, PropertyValue, ServerEntryId, TableString,
};
use crate::wire::{Reader, Writer};

impl PropertyValue {
    /// Reads one value of the type its tag or its column declared.
    pub(crate) fn read(
        r: &mut Reader<'_>,
        property_type: PropertyType,
        context: ValueContext,
    ) -> Result<Self> {
        Ok(match property_type {
            PropertyType::Integer16 => Self::Integer16(r.u16()?),
            PropertyType::Integer32 => Self::Integer32(r.u32()?),
            PropertyType::Integer64 => Self::Integer64(r.u64()?),
            PropertyType::Floating64 => Self::Floating64(Floating64::from_bits(r.u64()?)),
            PropertyType::ErrorCode => Self::Error(ErrorCode::new(r.u32()?)),
            PropertyType::Boolean => Self::Boolean(r.u8()? != 0),
            PropertyType::String => Self::String(string(r.utf16_z()?, context)),
            PropertyType::String8 => Self::String8(string(r.ascii_z()?, context)),
            PropertyType::Time => Self::Time(FileTime::new(r.u64()?)),
            PropertyType::Guid => Self::Guid(Guid::from_bytes(r.array::<16>()?)),
            PropertyType::Binary => Self::Binary(read_binary(r, context)?),
            // Counted exactly as a PtypBinary is, and then interpreted. The COUNT is not part of
            // [MS-OXCDATA] §2.11.1.4's diagram — §2.11.1's type table is where it comes from,
            // "Variable size; a 16-bit COUNT field followed by a structure".
            PropertyType::ServerId => {
                Self::ServerId(ServerEntryId::from_bytes(&read_binary(r, context)?))
            }
            PropertyType::MultipleInteger32 => {
                Self::MultipleInteger32(read_each(r, context, Reader::u32)?)
            }
            PropertyType::MultipleString => Self::MultipleString(read_each(r, context, |r| {
                Ok(string(r.utf16_z()?, context))
            })?),
            PropertyType::MultipleBinary => {
                Self::MultipleBinary(read_each(r, context, |r| read_binary(r, context))?)
            }
            // A store server MUST NOT answer a property fetch with one of these, and if one
            // arrives anyway its length is not something this layer can invent.
            PropertyType::Object => {
                return Err(Error::ObjectPropertyValue { at: r.position() });
            }
            PropertyType::Unsupported(raw) => {
                return Err(Error::UnsupportedPropertyType {
                    property_type: raw,
                    at: r.position(),
                });
            }
        })
    }

    /// Writes this value in the form a `TaggedPropertyValue` carries it.
    ///
    /// # Errors
    ///
    /// [`Error::UnencodableValue`] for a value this crate will not put on the wire, and
    /// [`Error::ValueTooLarge`] for one longer than its own COUNT field can describe. Both are
    /// refusals rather than approximations: a buffer the server reads as something else sets a
    /// silently wrong property, which is worse than a failed request.
    pub(crate) fn write(&self, w: &mut Writer, context: ValueContext) -> Result<()> {
        match self {
            Self::Integer16(value) => {
                w.u16(*value);
            }
            Self::Integer32(value) => {
                w.u32(*value);
            }
            Self::Integer64(value) => {
                w.u64(*value);
            }
            Self::Floating64(value) => {
                w.u64(value.to_bits());
            }
            Self::Boolean(value) => {
                w.u8(u8::from(*value));
            }
            Self::Time(value) => {
                w.u64(value.as_u64());
            }
            Self::Guid(value) => {
                w.bytes(value.as_bytes());
            }
            Self::String(text) => write_string(w, text)?,
            Self::Binary(bytes) => write_binary(w, bytes, context)?,
            Self::ServerId(value) => write_binary(w, &value.to_bytes(), context)?,
            Self::MultipleInteger32(values) => {
                write_count(w, values.len(), PropertyType::MultipleInteger32, context)?;
                for value in values {
                    w.u32(*value);
                }
            }
            Self::MultipleString(values) => {
                write_count(w, values.len(), PropertyType::MultipleString, context)?;
                for text in values {
                    write_string(w, text)?;
                }
            }
            Self::MultipleBinary(values) => {
                write_count(w, values.len(), PropertyType::MultipleBinary, context)?;
                for bytes in values {
                    write_binary(w, bytes, context)?;
                }
            }
            // Everything below is a value that exists as a decoding outcome and not as something
            // a client may send.
            Self::String8(_) => {
                return Err(Error::UnencodableValue {
                    value: "a PtypString8 value",
                    reason: "its code page is the one negotiated for the session, which this \
                             crate never sets — send PtypString, which is UTF-16LE and what \
                             [MS-OXCDATA] §2.11.1.2 says clients SHOULD use",
                });
            }
            Self::Error(_) => {
                return Err(Error::UnencodableValue {
                    value: "an error code",
                    reason: "PtypErrorCode is how a server declines to return a value, not a \
                             value a client can set",
                });
            }
            Self::Absent => {
                return Err(Error::UnencodableValue {
                    value: "an absent value",
                    reason: "a property being set has to have a value; delete it with \
                             RopDeleteProperties instead",
                });
            }
        }
        Ok(())
    }
}

/// Classifies a decoded string according to where it came from.
///
/// A table cuts a value at 255 characters and reports it nowhere; a property fetch on an object
/// does not truncate at all. Applying the table's rule to an object's answer would report a whole
/// 255-character display name as damaged.
fn string(text: String, context: ValueContext) -> TableString {
    if context.truncates_strings() {
        TableString::from_table(text)
    } else {
        TableString::Complete(text)
    }
}

/// A COUNT of bytes, then that many bytes.
fn read_binary(r: &mut Reader<'_>, context: ValueContext) -> Result<Vec<u8>> {
    let count = read_count(r, context.binary_count())?;
    Ok(r.bytes(count)?.to_vec())
}

/// A COUNT of values, then that many of whatever `each` reads.
///
/// The count is a number from a server nobody here controls, so nothing is pre-allocated from it:
/// a claimed four billion entries has to cost one failed read, not four billion elements of
/// capacity.
fn read_each<'a, T>(
    r: &mut Reader<'a>,
    context: ValueContext,
    each: impl Fn(&mut Reader<'a>) -> Result<T>,
) -> Result<Vec<T>> {
    let count = read_count(r, context.multiple_count())?;
    let mut values = Vec::new();
    for _ in 0..count {
        values.push(each(r)?);
    }
    Ok(values)
}

/// Reads a COUNT field of the width its context gives it.
fn read_count(r: &mut Reader<'_>, width: CountWidth) -> Result<usize> {
    Ok(match width {
        CountWidth::Short => usize::from(r.u16()?),
        // Infallible on every target this crate builds for; `usize::MAX` rather than a panic keeps
        // the "no read may panic on hostile input" property true even where it cannot happen.
        CountWidth::Long => usize::try_from(r.u32()?).unwrap_or(usize::MAX),
    })
}

/// Writes a null-terminated UTF-16LE string, refusing one that would end its own field early.
fn write_string(w: &mut Writer, text: &TableString) -> Result<()> {
    let text = text.as_str();
    if text.contains('\0') {
        return Err(Error::UnencodableValue {
            value: "a string with an interior NUL",
            reason: "the NUL would terminate the field early and shift every field after it, \
                     which the server reads as a different property rather than as an error",
        });
    }
    w.utf16_z(text);
    Ok(())
}

/// Writes a COUNT of bytes, then those bytes.
fn write_binary(w: &mut Writer, bytes: &[u8], context: ValueContext) -> Result<()> {
    write_count(w, bytes.len(), PropertyType::Binary, context)?;
    w.bytes(bytes);
    Ok(())
}

/// Writes a COUNT field, refusing a count the field cannot express.
fn write_count(
    w: &mut Writer,
    count: usize,
    property_type: PropertyType,
    context: ValueContext,
) -> Result<()> {
    let width = if property_type.is_multivalued() {
        context.multiple_count()
    } else {
        context.binary_count()
    };

    if count > width.limit() {
        return Err(Error::ValueTooLarge {
            property_type,
            count,
            limit: width.limit(),
        });
    }

    match width {
        CountWidth::Short => {
            w.u16(u16::try_from(count).unwrap_or(u16::MAX));
        }
        CountWidth::Long => {
            w.u32(u32::try_from(count).unwrap_or(u32::MAX));
        }
    }
    Ok(())
}
