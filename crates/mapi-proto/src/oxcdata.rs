//! Property tags, values, rows and the identities they carry.
//!
//! This is the layer that decides what a sequence of bytes *means*, given a column set. It is
//! deliberately separate from the ROP layer: the same structures appear in table rows, in property
//! fetches and in `FastTransfer` streams, and only the framing around them differs.
//!
//! [MS-OXCDATA] — data structures

mod attach;
mod class;
mod columns;
mod entryid;
mod ids;
mod kind;
mod named;
mod properties;
mod propname;
mod propset;
mod restrict;
mod row;
mod sort;
mod special;
mod tag;
mod value;

pub use attach::AttachMethod;
pub use class::ContainerClass;
pub use columns::{
    APPOINTMENT_COLUMNS, ATTACHMENT_COLUMNS, ATTACHMENT_PROPERTIES, CONTACT_COLUMNS,
    CONTENTS_COLUMNS, FOLDER_PROPERTIES, HIERARCHY_COLUMNS, MAILBOX_PROPERTIES, MESSAGE_PROPERTIES,
};
pub use entryid::{FolderEntryId, LongTermId, ShortTermId, StoreObjectType};
pub use ids::{AttachmentNumber, FileTime, FolderId, Guid, LegacyDn, MessageId, ReplicaId};
pub use kind::PropertyType;
pub(crate) use kind::ValueContext;
pub use named::{APPOINTMENT_PROPERTIES, CONTACT_PROPERTIES, NamedProperty};
pub use properties::{PropertyProblem, PropertySet, PropertySetIter, TaggedValue};
pub use propname::{NamedPropertyId, PropertyName, PropertyNameKind};
pub use propset::PropertySetId;
pub use restrict::{FuzzyLevel, RelationalOperator, Restriction};
pub use row::{Cell, PropertyRow, RowForm};
pub use sort::{SortDirection, SortOrder, SortOrderSet};
pub use special::{SPECIAL_FOLDER_PROPERTIES, SpecialFolder};
pub use tag::PropertyTag;
pub use value::{Floating64, PropertyValue, TableString};
