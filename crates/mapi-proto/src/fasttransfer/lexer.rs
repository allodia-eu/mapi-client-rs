//! Splitting a `FastTransfer` stream into elements, across however many buffers it arrives in.
//!
//! **A stream is not split where a reader would like.** [MS-OXCFXICS] §2.2.4.1 lets the server
//! break it "between two atoms or at any point inside a `varSizeValue`", so a property's value can
//! begin in one `RopFastTransferSourceGetBuffer` response and end three later. The lexer therefore
//! keeps the bytes it has not yet been able to make an element of, and answers "not yet" rather
//! than failing when an element is incomplete. Memory is bounded by the largest single element,
//! never by the stream.
//!
//! Re-reading a half-arrived value from its start on every buffer would cost the square of its
//! size, so a short read remembers how many bytes it needs and the lexer does not try again until
//! it has them.
//!
//! **The encoding is not a ROP buffer's.** [MS-OXCFXICS] §2.2.4.1.3: a `PtypBoolean` is two bytes,
//! every variable-length value and every list carries a 32-bit length, a named property brings its
//! property set and LID or name inline, and a string may arrive under a code-page type,
//! `0x8000 | cpid`. So values are decoded here rather than by the row codec.
//!
//! [MS-OXCFXICS] §2.2.4.1 — lexical structure
//! [MS-OXCFXICS] §2.2.4.1.3 — serialization of simple types

use crate::error::{Error, Result};
use crate::fasttransfer::Marker;
use crate::oxcdata::{
    Currency, FileTime, Floating32, Floating64, Guid, PropertyName, PropertySetId, PropertyTag,
    PropertyType, PropertyValue, ServerEntryId, TableString,
};
use crate::wire::Reader;

/// The code page whose strings are UTF-16LE, `1200`. [MS-OXCFXICS] §2.2.4.1.1.1
const UNICODE_CODE_PAGE: u16 = 1200;

/// The bit that marks a code-page string type. [MS-OXCFXICS] §2.2.4.1.1.1
const CODE_PAGE_BIT: u16 = 0x8000;

/// One element of a stream: a marker, or a property with its value.
///
/// [MS-OXCFXICS] §2.2.4.1 — `element = marker / propValue`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Element {
    /// A marker, which has no value.
    Marker(Marker),
    /// A property, or a meta-property, with its value.
    Property(StreamProperty),
}

/// A property as a `FastTransfer` stream carries it: its tag, its name if it is a named property,
/// and its value.
///
/// **A named property's id is the store's**, as everywhere — but here the stream also says which
/// property it is, so [`name`](Self::name) is the portable half and the one to match on.
///
/// **A string that arrived under a code-page type is reported under its ordinary one.** The tag
/// says `PtypString` for code page 1200 and `PtypString8` for any other, so that matching on
/// [`PropertyTag::SUBJECT`] works whatever the server chose, and [`code_page`](Self::code_page)
/// keeps what it said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamProperty {
    tag: PropertyTag,
    name: Option<PropertyName>,
    code_page: Option<u16>,
    value: PropertyValue,
}

impl StreamProperty {
    /// The tag, with a code-page type reported as the ordinary string type.
    #[must_use]
    pub const fn tag(&self) -> PropertyTag {
        self.tag
    }

    /// The property set and LID or name, for a named property.
    #[must_use]
    pub const fn name(&self) -> Option<&PropertyName> {
        self.name.as_ref()
    }

    /// The code page the stream named, for a string that arrived under a code-page type.
    #[must_use]
    pub const fn code_page(&self) -> Option<u16> {
        self.code_page
    }

    /// The value.
    #[must_use]
    pub const fn value(&self) -> &PropertyValue {
        &self.value
    }

    /// Takes the value out.
    #[must_use]
    pub fn into_value(self) -> PropertyValue {
        self.value
    }
}

/// Turns the bytes of a stream into [`Element`]s, as they arrive.
#[derive(Clone, Debug, Default)]
pub struct Lexer {
    buffer: Vec<u8>,
    /// Where the next element starts in `buffer`.
    start: usize,
    /// The buffer length the last short read needed before it is worth trying again.
    wanted: usize,
}

impl Lexer {
    /// A lexer that has seen nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffer: Vec::new(),
            start: 0,
            wanted: 0,
        }
    }

    /// Hands the lexer the next portion of the stream.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.start > 0 {
            self.buffer.drain(..self.start);
            self.wanted = self.wanted.saturating_sub(self.start);
            self.start = 0;
        }
        self.buffer.extend_from_slice(bytes);
    }

    /// How many bytes have arrived that are not yet part of an element.
    ///
    /// Zero once a stream has ended cleanly; anything else at the end means it ended inside an
    /// element.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffer.len().saturating_sub(self.start)
    }

    /// The next element, or `None` until enough of it has arrived.
    ///
    /// # Errors
    ///
    /// A decoding error for an element whose bytes cannot be one: an unsupported property type, a
    /// named property of an unknown kind, a string that is not UTF-16. A short read is never one.
    pub fn next_element(&mut self) -> Result<Option<Element>> {
        if self.buffer.len() < self.wanted {
            return Ok(None);
        }
        let rest = self.buffer.get(self.start..).unwrap_or_default();
        if rest.is_empty() {
            return Ok(None);
        }
        let mut r = Reader::new(rest);
        match read_element(&mut r) {
            Ok(element) => {
                self.start = self.start.saturating_add(r.position());
                self.wanted = 0;
                Ok(Some(element))
            }
            Err(Error::Truncated { at, need, .. }) => {
                self.wanted = self.start.saturating_add(at).saturating_add(need);
                Ok(None)
            }
            // Only a named property's name is terminated rather than counted, so this is a name
            // whose terminator has not arrived yet. The atom rule forbids the split, but waiting
            // costs nothing and refusing would end the download over a server's choice of buffer.
            Err(Error::Unterminated { .. }) => {
                self.wanted = self.buffer.len().saturating_add(1);
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

/// Reads one element: a marker, or a property's tag, name and value.
fn read_element(r: &mut Reader<'_>) -> Result<Element> {
    let raw = r.u32()?;
    if let Some(marker) = Marker::from_u32(raw) {
        return Ok(Element::Marker(marker));
    }
    let tag = PropertyTag::new(raw);
    let name = if tag.id() >= 0x8000 {
        Some(read_name(r)?)
    } else {
        None
    };
    let (tag, code_page, value) = read_value(r, tag)?;
    Ok(Element::Property(StreamProperty {
        tag,
        name,
        code_page,
        value,
    }))
}

/// A named property's identity, as the stream carries it after the tag.
///
/// [MS-OXCFXICS] §2.2.4.1 — `namedPropInfo = propertySet ((%x00 dispid) / (%x01 name))`, the name
/// a null-terminated `PtypString`
fn read_name(r: &mut Reader<'_>) -> Result<PropertyName> {
    let set = PropertySetId::from_guid(Guid::from_bytes(r.array::<16>()?));
    let at = r.position();
    match r.u8()? {
        0x00 => Ok(PropertyName::lid(set, r.u32()?)),
        0x01 => Ok(PropertyName::from_stream(set, r.utf16_z()?)),
        kind => Err(Error::InvalidPropertyNameKind { kind, at }),
    }
}

/// One property's value, and the tag to report it under.
fn read_value(
    r: &mut Reader<'_>,
    tag: PropertyTag,
) -> Result<(PropertyTag, Option<u16>, PropertyValue)> {
    // [MS-OXCFXICS] §3.2.5.2.1: tagged PtypInteger32, carried and handled as PtypBinary.
    if tag == PropertyTag::META_TAG_IDSET_GIVEN {
        return Ok((tag, None, PropertyValue::Binary(var(r)?.to_vec())));
    }

    let raw = tag.property_type().as_u16();
    if raw & CODE_PAGE_BIT != 0 {
        let code_page = raw & !CODE_PAGE_BIT;
        let bytes = var(r)?;
        let (property_type, value) = if code_page == UNICODE_CODE_PAGE {
            (
                PropertyType::String,
                PropertyValue::String(utf16(bytes, r)?),
            )
        } else {
            (
                PropertyType::String8,
                PropertyValue::String8(eight_bit(bytes)),
            )
        };
        let tag = PropertyTag::from_parts(tag.id(), property_type);
        return Ok((tag, Some(code_page), value));
    }

    Ok((tag, None, read_typed(r, tag.property_type())?))
}

/// A value of one of the types [MS-OXCDATA] §2.11.1 names, in the stream's encoding.
fn read_typed(r: &mut Reader<'_>, property_type: PropertyType) -> Result<PropertyValue> {
    Ok(match property_type {
        PropertyType::Integer16 => PropertyValue::Integer16(r.u16()?),
        PropertyType::Integer32 => PropertyValue::Integer32(r.u32()?),
        PropertyType::Integer64 => PropertyValue::Integer64(r.u64()?),
        PropertyType::Floating32 => PropertyValue::Floating32(Floating32::from_bits(r.u32()?)),
        PropertyType::Floating64 => PropertyValue::Floating64(Floating64::from_bits(r.u64()?)),
        PropertyType::FloatingTime => PropertyValue::FloatingTime(Floating64::from_bits(r.u64()?)),
        PropertyType::Currency => PropertyValue::Currency(currency(r)?),
        PropertyType::ErrorCode => PropertyValue::Error(crate::ErrorCode::new(r.u32()?)),
        // Two bytes in a stream, against one in a ROP buffer. [MS-OXCFXICS] §2.2.4.1.3
        PropertyType::Boolean => PropertyValue::Boolean(r.u16()? != 0),
        PropertyType::Time => PropertyValue::Time(FileTime::new(r.u64()?)),
        PropertyType::Guid => PropertyValue::Guid(Guid::from_bytes(r.array::<16>()?)),
        PropertyType::String => PropertyValue::String(utf16(var(r)?, r)?),
        PropertyType::String8 => PropertyValue::String8(eight_bit(var(r)?)),
        PropertyType::Binary => PropertyValue::Binary(var(r)?.to_vec()),
        PropertyType::Object => PropertyValue::Object(var(r)?.to_vec()),
        PropertyType::ServerId => PropertyValue::ServerId(ServerEntryId::from_bytes(var(r)?)),
        PropertyType::MultipleInteger16 => PropertyValue::MultipleInteger16(list(r, Reader::u16)?),
        PropertyType::MultipleInteger32 => PropertyValue::MultipleInteger32(list(r, Reader::u32)?),
        PropertyType::MultipleInteger64 => PropertyValue::MultipleInteger64(list(r, Reader::u64)?),
        PropertyType::MultipleFloating32 => {
            PropertyValue::MultipleFloating32(list(r, |r| Ok(Floating32::from_bits(r.u32()?)))?)
        }
        PropertyType::MultipleFloating64 => {
            PropertyValue::MultipleFloating64(list(r, |r| Ok(Floating64::from_bits(r.u64()?)))?)
        }
        PropertyType::MultipleFloatingTime => {
            PropertyValue::MultipleFloatingTime(list(r, |r| Ok(Floating64::from_bits(r.u64()?)))?)
        }
        PropertyType::MultipleCurrency => PropertyValue::MultipleCurrency(list(r, currency)?),
        PropertyType::MultipleTime => {
            PropertyValue::MultipleTime(list(r, |r| Ok(FileTime::new(r.u64()?)))?)
        }
        PropertyType::MultipleGuid => {
            PropertyValue::MultipleGuid(list(r, |r| Ok(Guid::from_bytes(r.array::<16>()?)))?)
        }
        PropertyType::MultipleString => {
            PropertyValue::MultipleString(list(r, |r| utf16(var(r)?, r))?)
        }
        PropertyType::MultipleString8 => {
            PropertyValue::MultipleString8(list(r, |r| Ok(eight_bit(var(r)?)))?)
        }
        PropertyType::MultipleBinary => {
            PropertyValue::MultipleBinary(list(r, |r| Ok(var(r)?.to_vec()))?)
        }
        // A type whose length is unknown cannot be stepped over, and stepping over it wrongly would
        // read every element after it from the middle of a value.
        PropertyType::Unsupported(raw) => {
            return Err(Error::UnsupportedPropertyType {
                property_type: raw,
                at: r.position(),
            });
        }
    })
}

/// A 32-bit length, then that many bytes. [MS-OXCFXICS] §2.2.4.1 — `length varSizeValue`
fn var<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    let length = usize::try_from(r.u32()?).unwrap_or(usize::MAX);
    r.bytes(length)
}

/// A 32-bit count, then that many values. Nothing is pre-allocated from the count, which comes
/// from a server nobody here controls.
fn list<'a, T>(r: &mut Reader<'a>, each: impl Fn(&mut Reader<'a>) -> Result<T>) -> Result<Vec<T>> {
    let count = r.u32()?;
    let mut values = Vec::new();
    for _ in 0..count {
        values.push(each(r)?);
    }
    Ok(values)
}

/// A `PtypCurrency`: eight bytes, a signed count of ten-thousandths.
fn currency(r: &mut Reader<'_>) -> Result<Currency> {
    Ok(Currency::from_scaled(r.u64()?.cast_signed()))
}

/// A UTF-16LE string with its length given, its terminator optional.
///
/// [MS-OXCFXICS] §2.2.4.1.3: the server SHOULD send the terminator, and readers "MUST check that
/// the last 1 (for `PtypString8`) or 2 (for `PtypString`) bytes of a stream are indeed zeros before
/// truncating them".
fn utf16(bytes: &[u8], r: &Reader<'_>) -> Result<TableString> {
    utf16_text(bytes)
        .map(TableString::Complete)
        .ok_or(Error::InvalidUtf16 { at: r.position() })
}

/// Counted UTF-16LE text, a trailing terminator dropped: the shape both a stream value and a
/// property group mapping's name take. `None` for text that is not UTF-16.
pub(crate) fn utf16_text(bytes: &[u8]) -> Option<String> {
    let mut units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| match pair {
            [low, high] => u16::from_le_bytes([*low, *high]),
            _ => 0,
        })
        .collect();
    if units.last() == Some(&0) {
        units.pop();
    }
    String::from_utf16(&units).ok()
}

/// An 8-bit string with its length given, its terminator optional, decoded as the row codec decodes
/// one.
///
/// Not by its code page, which a code-page type names and [`StreamProperty::code_page`] keeps:
/// decoding 8-bit strings by code page is a separate piece of work, for the row codec and the
/// stream alike. A download configured with `ForceUnicode` is answered in `PtypString` throughout
/// ([MS-OXCFXICS] §3.2.5.8.1.1), so one that is configured that way never reaches this.
fn eight_bit(bytes: &[u8]) -> TableString {
    let text = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    TableString::Complete(String::from_utf8_lossy(text).into_owned())
}

#[cfg(test)]
mod tests;
