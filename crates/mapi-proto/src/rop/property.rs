//! The property ROPs: reading an object's properties, writing them, and deleting them.
//!
//! These are the first ROPs here that operate on an object rather than on a table, and the first
//! that *write*. Three things about them are load-bearing:
//!
//! * `RopGetPropertiesSpecific` answers with a `PropertyRow` — the same structure a table row is —
//!   decoded against the tags in the **request**. Nothing in the response says what they were, so
//!   the batch remembers them and hands them to the decoder.
//! * `RopGetPropertiesAll` answers with `TaggedPropertyValue`s instead, so the tags come off the
//!   wire and no request-side memory is needed.
//! * `RopSetProperties` and `RopDeleteProperties` report per-property failures **alongside a
//!   successful `ReturnValue`**. A caller that only checked the return value would report a write
//!   that did not happen as done.
//!
//! [MS-OXCROPS] §2.2.8.3 — `RopGetPropertiesSpecific`
//! [MS-OXCROPS] §2.2.8.4 — `RopGetPropertiesAll`
//! [MS-OXCROPS] §2.2.8.6 — `RopSetProperties`
//! [MS-OXCROPS] §2.2.8.8 — `RopDeleteProperties`
//! [MS-OXCPRPT] §2.2.2 — semantics

use crate::error::{Error, Result};
use crate::oxcdata::{
    PropertyProblem, PropertyRow, PropertySet, PropertyTag, TaggedValue, ValueContext,
};
use crate::rop::RopId;
use crate::rop::batch::LOGON_ID;
use crate::wire::{Reader, Writer};

/// `PropertySizeLimit`: no limit beyond the response buffer's own.
///
/// Exchange is documented as ignoring this field anyway ([MS-OXCPRPT] §3.2.5.1), and a non-zero
/// value would only turn a large property into `NotEnoughMemory` sooner than the buffer does.
///
/// [MS-OXCPRPT] §2.2.2.1 — `PropertySizeLimit`
const NO_SIZE_LIMIT: u16 = 0x0000;

/// `WantUnicode`: return strings as `PtypString` rather than in a code page.
///
/// This only governs properties asked for as `PtypUnspecified` — a tag naming a string type gets
/// that type back regardless ([MS-OXCPRPT] §3.2.5.1). It is set anyway because
/// `RopGetPropertiesAll` names no tags at all, so it is the only say this crate gets over how that
/// ROP's strings arrive, and because [MS-OXCDATA] §2.11.1.2 says clients SHOULD use Unicode.
///
/// [MS-OXCPRPT] §2.2.2.1 — `WantUnicode`
const WANT_UNICODE: u16 = 0x0001;

/// The `PropertyValueSize` field counts itself plus `PropertyValueCount`, which is two bytes.
///
/// [MS-OXCROPS] §2.2.8.6.1 — `PropertyValueSize`
const PROPERTY_VALUE_COUNT_BYTES: usize = 2;

/// The properties one object answered with.
///
/// [MS-OXCROPS] §2.2.8.3.2 — `RopGetPropertiesSpecific` success response buffer
/// [MS-OXCROPS] §2.2.8.4.2 — `RopGetPropertiesAll` success response buffer
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetPropertiesResponse {
    rop: RopId,
    properties: PropertySet,
}

impl GetPropertiesResponse {
    /// Which ROP produced this — the two answer in different wire forms and are worth telling
    /// apart when a batch issued both.
    #[must_use]
    pub const fn rop(&self) -> RopId {
        self.rop
    }

    /// What came back.
    #[must_use]
    pub const fn properties(&self) -> &PropertySet {
        &self.properties
    }

    /// Takes the properties out.
    #[must_use]
    pub fn into_properties(self) -> PropertySet {
        self.properties
    }

    /// Reads a `RopGetPropertiesSpecific` body: one row, against the tags that were requested.
    pub(crate) fn read_row(r: &mut Reader<'_>, rop: RopId, tags: &[PropertyTag]) -> Result<Self> {
        let row = PropertyRow::read(r, tags, ValueContext::Object)?;
        Ok(Self {
            rop,
            properties: row.into_property_set(),
        })
    }

    /// Reads a `RopGetPropertiesAll` body: a count, then that many tag/value pairs.
    pub(crate) fn read_all(r: &mut Reader<'_>, rop: RopId) -> Result<Self> {
        let count = usize::from(r.u16()?);
        Ok(Self {
            rop,
            properties: PropertySet::read_tagged(r, count)?,
        })
    }
}

/// What a property write reported, property by property.
///
/// An empty list is the success case, and is what both ROPs answer with when everything applied.
///
/// [MS-OXCROPS] §2.2.8.6.2 — `RopSetProperties` success response buffer
/// [MS-OXCROPS] §2.2.8.8.2 — `RopDeleteProperties` success response buffer
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyProblemsResponse {
    rop: RopId,
    problems: Vec<PropertyProblem>,
}

impl PropertyProblemsResponse {
    /// Which ROP reported these — a batch that sets some properties and deletes others gets two
    /// of these responses, and attributing one to the wrong ROP is a wrong answer.
    #[must_use]
    pub const fn rop(&self) -> RopId {
        self.rop
    }

    /// The properties that were not written, and why.
    ///
    /// **Empty does not mean every property was written.** A server is permitted to disregard a
    /// property that is read-only for the client and say nothing at all about it
    /// ([MS-OXCPRPT] §3.2.5.4), so this reports the failures a server chose to report and not the
    /// absence of failure.
    #[must_use]
    pub fn problems(&self) -> &[PropertyProblem] {
        &self.problems
    }

    /// Whether the server reported a problem with any property.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty()
    }

    /// Reads the count and that many `PropertyProblem` structures.
    pub(crate) fn read(r: &mut Reader<'_>, rop: RopId) -> Result<Self> {
        let count = usize::from(r.u16()?);
        let mut problems = Vec::new();
        for _ in 0..count {
            problems.push(PropertyProblem::read(r)?);
        }
        Ok(Self { rop, problems })
    }
}

/// Encodes a `RopGetPropertiesSpecific` request.
///
/// [MS-OXCROPS] §2.2.8.3.1 — request buffer
pub(crate) fn encode_get_properties_specific(w: &mut Writer, input: u8, tags: &[PropertyTag]) {
    w.u8(RopId::GET_PROPERTIES_SPECIFIC.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u16(NO_SIZE_LIMIT)
        .u16(WANT_UNICODE)
        .u16(u16::try_from(tags.len()).unwrap_or(u16::MAX));
    for tag in tags {
        w.u32(tag.as_u32());
    }
}

/// Encodes a `RopGetPropertiesAll` request.
///
/// [MS-OXCROPS] §2.2.8.4.1 — request buffer
pub(crate) fn encode_get_properties_all(w: &mut Writer, input: u8) {
    w.u8(RopId::GET_PROPERTIES_ALL.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u16(NO_SIZE_LIMIT)
        .u16(WANT_UNICODE);
}

/// Encodes a `RopSetProperties` request.
///
/// `PropertyValueSize` counts the `PropertyValueCount` field as well as the values, so the values
/// are encoded first and measured — the length cannot be predicted from the value list, because
/// every string and every binary is variable-length.
///
/// # Errors
///
/// Whatever the values themselves refused — a string with an interior NUL, a binary past what its
/// COUNT can express — plus [`Error::RopBufferTooLarge`] if the encoded values do not fit the
/// 16-bit `PropertyValueSize` field.
///
/// [MS-OXCROPS] §2.2.8.6.1 — request buffer
pub(crate) fn encode_set_properties(
    w: &mut Writer,
    input: u8,
    values: &[TaggedValue],
) -> Result<()> {
    let mut encoded = Writer::new();
    for value in values {
        value.write(&mut encoded, ValueContext::Object)?;
    }
    let encoded = encoded.finish();

    let size = encoded
        .len()
        .checked_add(PROPERTY_VALUE_COUNT_BYTES)
        .and_then(|size| u16::try_from(size).ok())
        .ok_or(Error::RopBufferTooLarge {
            bytes: encoded.len(),
            limit: usize::from(u16::MAX).saturating_sub(PROPERTY_VALUE_COUNT_BYTES),
        })?;

    w.u8(RopId::SET_PROPERTIES.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u16(size)
        .u16(u16::try_from(values.len()).unwrap_or(u16::MAX))
        .bytes(&encoded);
    Ok(())
}

/// Encodes a `RopDeleteProperties` request.
///
/// [MS-OXCROPS] §2.2.8.8.1 — request buffer
pub(crate) fn encode_delete_properties(w: &mut Writer, input: u8, tags: &[PropertyTag]) {
    w.u8(RopId::DELETE_PROPERTIES.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u16(u16::try_from(tags.len()).unwrap_or(u16::MAX));
    for tag in tags {
        w.u32(tag.as_u32());
    }
}

#[cfg(test)]
mod tests;
