//! Property tags, values, rows and the identities they carry.
//!
//! This is the layer that decides what a sequence of bytes *means*, given a column set. It is
//! deliberately separate from the ROP layer: the same structures appear in table rows, in property
//! fetches and in `FastTransfer` streams, and only the framing around them differs.
//!
//! [MS-OXCDATA] — data structures

mod class;
mod entryid;
mod ids;
mod kind;
mod named;
mod properties;
mod propname;
mod propset;
mod row;
mod special;
mod tag;
mod value;

pub use class::ContainerClass;
pub use entryid::{FolderEntryId, LongTermId, ShortTermId, StoreObjectType};
pub use ids::{FileTime, FolderId, Guid, LegacyDn, MessageId, ReplicaId};
pub use kind::PropertyType;
pub(crate) use kind::ValueContext;
pub use named::{APPOINTMENT_PROPERTIES, CONTACT_PROPERTIES, NamedProperty};
pub use properties::{PropertyProblem, PropertySet, PropertySetIter, TaggedValue};
pub use propname::{NamedPropertyId, PropertyName, PropertyNameKind};
pub use propset::PropertySetId;
pub use row::{Cell, PropertyRow, RowForm};
pub use special::{SPECIAL_FOLDER_PROPERTIES, SpecialFolder};
pub use tag::{
    CONTENTS_COLUMNS, FOLDER_PROPERTIES, HIERARCHY_COLUMNS, MAILBOX_PROPERTIES, PropertyTag,
};
pub use value::{Floating64, PropertyValue, TableString};
