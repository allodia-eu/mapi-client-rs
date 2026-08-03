//! Sort keys for a table.
//!
//! A `SortOrderSet` is what turns "the messages in this folder" into "the messages in this folder,
//! newest first" without reading them all and sorting locally — which for a folder of any size is
//! the difference between one round trip and every round trip.
//!
//! **The sort key must be a column the table has been given.** [MS-OXCTABL] §2.2.2.3 requires
//! `RopSetColumns` to have named every property sorted on, and a server that has not been told
//! about the column answers `ecInvalidParam` rather than sorting on something else. That is a rule
//! the type system can enforce, so [`SortOrderSet::covered_by`] exists and the batch checks it.
//!
//! [MS-OXCDATA] §2.13.1 — `SortOrder` structure
//! [MS-OXCDATA] §2.13.2 — `SortOrderSet` structure

use crate::oxcdata::PropertyTag;
use crate::wire::Writer;

/// Which way one column sorts.
///
/// [MS-OXCDATA] §2.13.1 — `Order`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SortDirection {
    /// `0x00` — smallest first, which for a time column is oldest first.
    Ascending,
    /// `0x01` — largest first, which for a time column is newest first.
    Descending,
}

impl SortDirection {
    /// The `Order` byte as the wire carries it.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Ascending => 0x00,
            Self::Descending => 0x01,
        }
    }
}

/// One column of a sort key, and the direction it sorts in.
///
/// [MS-OXCDATA] §2.13.1 — `SortOrder` structure
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SortOrder {
    tag: PropertyTag,
    direction: SortDirection,
}

impl SortOrder {
    /// Sorts on this column, smallest first.
    #[must_use]
    pub const fn ascending(tag: PropertyTag) -> Self {
        Self {
            tag,
            direction: SortDirection::Ascending,
        }
    }

    /// Sorts on this column, largest first.
    #[must_use]
    pub const fn descending(tag: PropertyTag) -> Self {
        Self {
            tag,
            direction: SortDirection::Descending,
        }
    }

    /// The column sorted on.
    #[must_use]
    pub const fn tag(self) -> PropertyTag {
        self.tag
    }

    /// Which way it sorts.
    #[must_use]
    pub const fn direction(self) -> SortDirection {
        self.direction
    }

    /// Writes the structure: the tag, then the order byte.
    ///
    /// The tag is written whole rather than as its two halves, which is the same four bytes:
    /// [MS-OXCDATA] §2.13.1 names them `PropertyType (bits 0-15)` and `PropertyId (bits 16-31)`,
    /// which is a `PropertyTag` under another name.
    fn write(self, w: &mut Writer) {
        w.u32(self.tag.as_u32()).u8(self.direction.as_u8());
    }
}

/// A whole sort key — the columns, in the order they break ties.
///
/// Categorisation is deliberately not modelled. A categorised sort makes the table answer with
/// header rows a caller has to know to expect, and nothing in the requested operations needs one;
/// both counts are therefore sent as zero, which is what makes every row of the answer an item.
///
/// ```
/// use mapi_proto::{PropertyTag, SortOrder, SortOrderSet};
///
/// let newest_first =
///     SortOrderSet::new([SortOrder::descending(PropertyTag::MESSAGE_DELIVERY_TIME)]);
/// assert!(
///     newest_first.covered_by(&[PropertyTag::MID, PropertyTag::MESSAGE_DELIVERY_TIME])
/// );
/// assert!(!newest_first.covered_by(&[PropertyTag::MID]));
/// ```
///
/// [MS-OXCDATA] §2.13.2 — `SortOrderSet` structure
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SortOrderSet {
    orders: Vec<SortOrder>,
}

impl SortOrderSet {
    /// A sort key made of these columns, in this order.
    #[must_use]
    pub fn new<I>(orders: I) -> Self
    where
        I: IntoIterator<Item = SortOrder>,
    {
        Self {
            orders: orders.into_iter().collect(),
        }
    }

    /// The columns, in the order they break ties.
    #[must_use]
    pub fn orders(&self) -> &[SortOrder] {
        &self.orders
    }

    /// Whether nothing is sorted on, in which case there is nothing to send.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.orders.is_empty()
    }

    /// Whether every column sorted on is among `columns`.
    ///
    /// [MS-OXCTABL] §2.2.2.3 requires it, and a server that has not been given the column refuses
    /// the sort rather than sorting on something else — so this is a check worth making before the
    /// round trip, where the answer names the column.
    #[must_use]
    pub fn covered_by(&self, columns: &[PropertyTag]) -> bool {
        self.orders
            .iter()
            .all(|order| columns.contains(&order.tag()))
    }

    /// The first column sorted on that `columns` does not carry.
    #[must_use]
    pub fn uncovered(&self, columns: &[PropertyTag]) -> Option<PropertyTag> {
        self.orders
            .iter()
            .map(|order| order.tag())
            .find(|tag| !columns.contains(tag))
    }

    /// Writes the `SortOrderCount`, `CategorizedCount` and `ExpandedCount` fields, then the orders.
    ///
    /// Shared by the `SortOrderSet` structure and by `RopSortTable`'s request buffer, which is the
    /// same three counts followed by the same array — [MS-OXCROPS] §2.2.5.2.1 inlines the structure
    /// rather than nesting it.
    ///
    /// `CategorizedCount` and `ExpandedCount` are both zero, which is what makes every row of the
    /// answer an item: a categorised sort inserts header rows a caller has to know to expect, and
    /// nothing in the requested operations wants one.
    pub(crate) fn write(&self, w: &mut Writer) {
        let count = u16::try_from(self.orders.len()).unwrap_or(u16::MAX);
        w.u16(count).u16(0).u16(0);
        for order in &self.orders {
            order.write(w);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes [MS-OXCDATA] §2.13.1 describes: the tag little-endian, then the order.
    #[test]
    fn a_sort_order_set_encodes_as_counts_then_orders() {
        let mut w = Writer::new();
        SortOrderSet::new([
            SortOrder::descending(PropertyTag::MESSAGE_DELIVERY_TIME),
            SortOrder::ascending(PropertyTag::SUBJECT),
        ])
        .write(&mut w);

        #[rustfmt::skip]
        let expected = vec![
            0x02, 0x00,             // SortOrderCount
            0x00, 0x00,             // CategorizedCount
            0x00, 0x00,             // ExpandedCount
            0x40, 0x00, 0x06, 0x0E, // PidTagMessageDeliveryTime
            0x01,                   // Descending
            0x1F, 0x00, 0x37, 0x00, // PidTagSubject
            0x00,                   // Ascending
        ];
        assert_eq!(w.finish(), expected);
    }

    #[test]
    fn an_empty_set_is_three_zero_counts() {
        let mut w = Writer::new();
        SortOrderSet::default().write(&mut w);
        assert_eq!(w.finish(), vec![0x00; 6]);
        assert!(SortOrderSet::default().is_empty());
        assert!(SortOrderSet::default().covered_by(&[]));
    }

    /// The check that saves a round trip: a sort on a column the table was never given is refused
    /// by the server, and the refusal does not say which column.
    #[test]
    fn a_sort_key_knows_which_column_the_table_is_missing() {
        let set = SortOrderSet::new([
            SortOrder::descending(PropertyTag::MESSAGE_DELIVERY_TIME),
            SortOrder::ascending(PropertyTag::SUBJECT),
        ]);

        assert!(set.covered_by(&[
            PropertyTag::SUBJECT,
            PropertyTag::MESSAGE_DELIVERY_TIME,
            PropertyTag::MID,
        ]));
        assert_eq!(
            set.uncovered(&[PropertyTag::MESSAGE_DELIVERY_TIME]),
            Some(PropertyTag::SUBJECT)
        );
        assert_eq!(
            set.uncovered(&[PropertyTag::SUBJECT, PropertyTag::MESSAGE_DELIVERY_TIME]),
            None
        );
        assert_eq!(set.orders().len(), 2);
        let first = set.orders().first().copied().expect("a first order");
        assert_eq!(first.tag(), PropertyTag::MESSAGE_DELIVERY_TIME);
        assert_eq!(first.direction(), SortDirection::Descending);
    }
}
