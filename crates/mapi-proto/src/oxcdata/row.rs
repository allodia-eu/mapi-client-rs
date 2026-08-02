//! Rows, and why they cannot be decoded on their own.
//!
//! **A row is not self-describing.** It carries values and nothing else — no tags, no types, no
//! lengths. The types come entirely from the column set the client last sent in `RopSetColumns`,
//! so the same bytes decode into different values under a different column set. That is why
//! [`PropertyRow::read`] takes the columns rather than discovering them, and why the session keeps
//! the column set alive for as long as the table handle is.
//!
//! [MS-OXCDATA] §2.8 — `PropertyRow` structures

use crate::error::{Error, Result};
use crate::oxcdata::kind::ValueContext;
use crate::oxcdata::{FolderId, MessageId, PropertySet, PropertyTag, PropertyValue, TableString};
use crate::wire::Reader;

/// Which of the two row encodings the server chose.
///
/// The choice is the server's, per row, and a client MUST handle both. Recorded rather than
/// normalised away because "which form does this server actually send?" is a question about a
/// deployment, and answering it from a capture beats guessing from the specification.
///
/// [MS-OXCDATA] §2.8.1 — `PropertyRow` structures
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RowForm {
    /// `0x00`: values in column order, with no per-value flag.
    ///
    /// [MS-OXCDATA] §2.8.1.1 — `StandardPropertyRow`
    Standard,
    /// `0x01`: every value is preceded by a flag saying whether it is present, absent or an error.
    ///
    /// [MS-OXCDATA] §2.8.1.2 — `FlaggedPropertyRow`
    Flagged,
}

/// One column of one row: the tag it was asked for, and what came back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    tag: PropertyTag,
    value: PropertyValue,
}

impl Cell {
    /// The column this value belongs to.
    #[must_use]
    pub const fn tag(&self) -> PropertyTag {
        self.tag
    }

    /// The value.
    #[must_use]
    pub const fn value(&self) -> &PropertyValue {
        &self.value
    }

    pub(crate) const fn new(tag: PropertyTag, value: PropertyValue) -> Self {
        Self { tag, value }
    }
}

impl core::fmt::Display for Cell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} = {}", self.tag, self.value)
    }
}

/// One decoded row, with each value paired to the column it was requested under.
///
/// [MS-OXCDATA] §2.8.1 — `PropertyRow` structures
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyRow {
    form: RowForm,
    cells: Vec<Cell>,
}

impl PropertyRow {
    /// Which encoding the server used for this row.
    #[must_use]
    pub const fn form(&self) -> RowForm {
        self.form
    }

    /// Every column of the row, in the order they were requested.
    #[must_use]
    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }

    /// The value for one column, if it was among the columns requested.
    #[must_use]
    pub fn get(&self, tag: PropertyTag) -> Option<&PropertyValue> {
        self.cells
            .iter()
            .find(|cell| cell.tag == tag)
            .map(Cell::value)
    }

    /// A string column, still carrying whether the table truncated it.
    #[must_use]
    pub fn string(&self, tag: PropertyTag) -> Option<&TableString> {
        self.get(tag).and_then(PropertyValue::as_string)
    }

    /// The row's `PidTagFolderId`, for a row read from a hierarchy table.
    #[must_use]
    pub fn folder_id(&self) -> Option<FolderId> {
        self.get(PropertyTag::FOLDER_ID)
            .and_then(PropertyValue::as_u64)
            .map(FolderId::new)
    }

    /// The row's `PidTagMid`, for a row read from a contents table.
    #[must_use]
    pub fn message_id(&self) -> Option<MessageId> {
        self.get(PropertyTag::MID)
            .and_then(PropertyValue::as_u64)
            .map(MessageId::new)
    }

    /// The row as a bag of tag/value pairs.
    ///
    /// What `RopGetPropertiesSpecific` answers with is a row like any other; a caller reading one
    /// object's properties wants it in the same shape `RopGetPropertiesAll` produces, so that the
    /// two ROPs are interchangeable at the call site.
    #[must_use]
    pub fn into_property_set(self) -> PropertySet {
        PropertySet::from_cells(self.cells)
    }

    /// Reads one row against the column set it was requested with.
    ///
    /// The leading byte picks the form. In a flagged row each value carries `0x00` (the value
    /// follows), `0x01` (absent, and **no bytes are consumed** — the mistake that desynchronises
    /// every later column) or `0x0A` (a 4-byte error code follows).
    ///
    /// `context` is not discoverable from the bytes and decides two things: how wide the COUNT
    /// fields inside a variable-length value are, and whether a 255-character string is to be
    /// reported as truncated. A `RopGetPropertiesSpecific` response is this same structure read
    /// from an object rather than from a table, which is why it is a parameter.
    ///
    /// [MS-OXCDATA] §2.8.1.1 — `StandardPropertyRow`
    /// [MS-OXCDATA] §2.8.1.2 — `FlaggedPropertyRow`
    pub(crate) fn read(
        r: &mut Reader<'_>,
        columns: &[PropertyTag],
        context: ValueContext,
    ) -> Result<Self> {
        let form = match r.u8()? {
            0x00 => RowForm::Standard,
            _ => RowForm::Flagged,
        };

        let mut cells = Vec::with_capacity(columns.len());
        for &tag in columns {
            let value = match form {
                RowForm::Standard => PropertyValue::read(r, tag.property_type(), context)?,
                RowForm::Flagged => Self::read_flagged_value(r, tag, context)?,
            };
            cells.push(Cell { tag, value });
        }
        Ok(Self { form, cells })
    }

    fn read_flagged_value(
        r: &mut Reader<'_>,
        tag: PropertyTag,
        context: ValueContext,
    ) -> Result<PropertyValue> {
        let at = r.position();
        match r.u8()? {
            0x00 => PropertyValue::read(r, tag.property_type(), context),
            0x01 => Ok(PropertyValue::Absent),
            0x0A => Ok(PropertyValue::Error(r.u32()?.into())),
            flag => Err(Error::InvalidValueFlag { flag, at }),
        }
    }
}

#[cfg(test)]
mod tests;
