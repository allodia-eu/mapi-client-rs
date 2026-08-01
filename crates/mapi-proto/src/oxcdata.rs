//! Property tags, values, rows and the identities they carry.
//!
//! This is the layer that decides what a sequence of bytes *means*, given a column set. It is
//! deliberately separate from the ROP layer: the same structures appear in table rows, in property
//! fetches and in `FastTransfer` streams, and only the framing around them differs.
//!
//! [MS-OXCDATA] — data structures

mod ids;
mod row;
mod tag;
mod value;

pub use ids::{FileTime, FolderId, Guid, LegacyDn, MessageId, ReplicaId};
pub use row::{Cell, PropertyRow, RowForm};
pub use tag::{CONTENTS_COLUMNS, HIERARCHY_COLUMNS, PropertyTag, PropertyType};
pub use value::{PropertyValue, TableString};
