//! Properties that travel with their tags: what a property fetch answers, and what a property
//! write is made of.
//!
//! A table row carries values alone and takes its meaning from a column set held elsewhere. These
//! do not — each value arrives beside the tag it belongs to — which is what makes
//! `RopGetPropertiesAll` able to answer "everything this object has" without the client knowing
//! the list in advance.
//!
//! [MS-OXCDATA] §2.11.4 — `TaggedPropertyValue` structure
//! [MS-OXCDATA] §2.7 — `PropertyProblem` structure

use crate::error::{Error, ErrorCode, Result};
use crate::oxcdata::kind::ValueContext;
use crate::oxcdata::{Cell, PropertyTag, PropertyValue, TableString};
use crate::wire::{Reader, Writer};

#[cfg(test)]
mod tests;

/// The properties one object answered with.
///
/// Both property ROPs produce one of these: `RopGetPropertiesSpecific` decodes its row against the
/// tags that were asked for, and `RopGetPropertiesAll` reads the tags off the wire. What a caller
/// does with the result is the same either way.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PropertySet {
    cells: Vec<Cell>,
}

impl PropertySet {
    /// Every property, in the order the server sent them.
    #[must_use]
    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }

    /// How many properties came back.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    /// Whether the object answered with nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// Every property, in the order the server sent them.
    #[must_use]
    pub fn iter(&self) -> PropertySetIter<'_> {
        PropertySetIter {
            inner: self.cells.iter(),
        }
    }

    /// The value recorded for one tag.
    ///
    /// Matched on both halves of the tag, then — and only then — on the property id alone for a
    /// cell holding an error. **A value too large for the response buffer comes back under the
    /// same id with its type changed to `PtypErrorCode`** ([MS-OXCPRPT] §2.2.3.2), so a strict
    /// match alone would report "the server could not fit this" as "the property is not set",
    /// which is a different fact and the one a caller would act on wrongly.
    ///
    /// The fallback is deliberately confined to errors: one property id can carry two real
    /// properties of different types — `PidTagMessageSize` and `PidTagMessageSizeExtended` share
    /// `0x0E08` — and matching on the id alone would hand back the wrong one of those.
    #[must_use]
    pub fn get(&self, tag: PropertyTag) -> Option<&PropertyValue> {
        self.cells
            .iter()
            .find(|cell| cell.tag() == tag)
            .or_else(|| {
                self.cells
                    .iter()
                    .find(|cell| cell.tag().id() == tag.id() && cell.value().as_error().is_some())
            })
            .map(Cell::value)
    }

    /// A string property, of either width, or `None` if it is absent or came back as an error.
    #[must_use]
    pub fn string(&self, tag: PropertyTag) -> Option<&TableString> {
        self.get(tag).and_then(PropertyValue::as_string)
    }

    /// Why the server would not return a property, if that is what it said.
    ///
    /// Distinguishes "not set on this object" — [`get`](Self::get) answering
    /// [`PropertyValue::Absent`] or nothing at all — from "set, and here is why you cannot have
    /// it", which `NotEnoughMemory` and `AccessDenied` both are.
    #[must_use]
    pub fn error(&self, tag: PropertyTag) -> Option<ErrorCode> {
        self.get(tag).and_then(PropertyValue::as_error)
    }

    /// Builds a set from tag/value pairs that have already been decoded.
    pub(crate) fn from_cells(cells: Vec<Cell>) -> Self {
        Self { cells }
    }

    /// Reads `count` `TaggedPropertyValue` structures, as `RopGetPropertiesAll` answers with.
    ///
    /// Nothing is pre-allocated from `count`: it is a number from a server nobody here controls.
    ///
    /// [MS-OXCDATA] §2.11.4 — `TaggedPropertyValue` structure
    pub(crate) fn read_tagged(r: &mut Reader<'_>, count: usize) -> Result<Self> {
        let mut cells = Vec::new();
        for _ in 0..count {
            let tag = PropertyTag::new(r.u32()?);
            let value = PropertyValue::read(r, tag.property_type(), ValueContext::Object)?;
            cells.push(Cell::new(tag, value));
        }
        Ok(Self { cells })
    }
}

impl<'a> IntoIterator for &'a PropertySet {
    type IntoIter = PropertySetIter<'a>;
    type Item = &'a Cell;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Every property in a [`PropertySet`], in the order the server sent them.
///
/// A named type rather than `impl Iterator`, so a caller can store one in a struct.
#[derive(Clone, Debug)]
pub struct PropertySetIter<'a> {
    inner: core::slice::Iter<'a, Cell>,
}

impl<'a> Iterator for PropertySetIter<'a> {
    type Item = &'a Cell;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for PropertySetIter<'_> {}

impl DoubleEndedIterator for PropertySetIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

/// A property to set, checked against the tag that names it.
///
/// The check is the point. A tag is an id **and** a type, and the type half is what tells the
/// server how to parse the bytes that follow — so `PidTagSubject` paired with an integer does not
/// set a wrong subject, it makes the server read the rest of the buffer as a different shape.
/// There is no way to build one of these that says something the wire cannot carry.
///
/// [MS-OXCDATA] §2.11.4 — `TaggedPropertyValue` structure
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaggedValue {
    tag: PropertyTag,
    value: PropertyValue,
}

impl TaggedValue {
    /// Pairs a value with the property it is to be set on.
    ///
    /// # Errors
    ///
    /// [`Error::PropertyTypeMismatch`] if the tag's type half is not the value's own type.
    pub fn new(tag: PropertyTag, value: PropertyValue) -> Result<Self> {
        let value_type = value.property_type();
        if value_type != Some(tag.property_type()) {
            return Err(Error::PropertyTypeMismatch { tag, value_type });
        }
        Ok(Self { tag, value })
    }

    /// The property being set.
    #[must_use]
    pub const fn tag(&self) -> PropertyTag {
        self.tag
    }

    /// The value it is being set to.
    #[must_use]
    pub const fn value(&self) -> &PropertyValue {
        &self.value
    }

    /// Writes the tag and then the value, which is the `TaggedPropertyValue` layout.
    pub(crate) fn write(&self, w: &mut Writer, context: ValueContext) -> Result<()> {
        w.u32(self.tag.as_u32());
        self.value.write(w, context)
    }
}

/// One property a write did not apply, and why.
///
/// Returned by `RopSetProperties` and `RopDeleteProperties`, **alongside a successful
/// `ReturnValue`**: the ROP as a whole succeeded and individual properties did not, so a caller
/// that only looked at the return value would report a write that did not happen as done.
///
/// [MS-OXCDATA] §2.7 — `PropertyProblem` structure
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PropertyProblem {
    index: u16,
    tag: PropertyTag,
    code: ErrorCode,
}

impl PropertyProblem {
    /// Which entry of the request this refers to.
    #[must_use]
    pub const fn index(self) -> u16 {
        self.index
    }

    /// The property that was not written.
    #[must_use]
    pub const fn tag(self) -> PropertyTag {
        self.tag
    }

    /// Why it was not.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        self.code
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            index: r.u16()?,
            tag: PropertyTag::new(r.u32()?),
            code: ErrorCode::new(r.u32()?),
        })
    }
}

impl core::fmt::Display for PropertyProblem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} (entry {}): {}", self.tag, self.index, self.code)
    }
}
