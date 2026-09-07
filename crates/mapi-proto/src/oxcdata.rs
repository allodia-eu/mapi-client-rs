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
mod flag;
mod ids;
mod kind;
mod msgclass;
mod named;
mod oneoff;
mod properties;
mod propname;
mod propset;
mod recipient;
mod restrict;
mod row;
mod serverid;
mod sort;
mod special;
mod tag;
mod value;

pub use attach::AttachMethod;
pub use class::ContainerClass;
pub use columns::{
    APPOINTMENT_COLUMNS, ATTACHMENT_COLUMNS, ATTACHMENT_PROPERTIES, CONTACT_COLUMNS,
    CONTENTS_COLUMNS, FOLDER_PROPERTIES, HIERARCHY_COLUMNS, MAILBOX_PROPERTIES, MESSAGE_PROPERTIES,
    STATE_PROPERTIES,
};
pub use entryid::{FolderEntryId, LongTermId, ShortTermId, StoreObjectType};
pub use flag::{FlagStatus, FollowupIcon, MessageFlags};
pub use ids::{AttachmentNumber, FileTime, FolderId, Guid, LegacyDn, MessageId, ReplicaId};
pub use kind::PropertyType;
pub(crate) use kind::ValueContext;
pub use msgclass::MessageClass;
pub use named::{
    APPOINTMENT_PROPERTIES, COMPLETE_FLAG_PROPERTIES, CONTACT_PROPERTIES, FOLLOW_UP_PROPERTIES,
    NEW_APPOINTMENT_PROPERTIES, NEW_CONTACT_PROPERTIES, NamedProperty,
};
pub use oneoff::{OneOffEntryId, SMTP_ADDRESS_TYPE, one_off_provider};
pub use properties::{PropertyProblem, PropertySet, PropertySetIter, TaggedValue};
pub use propname::{NamedPropertyId, PropertyName, PropertyNameKind};
pub use propset::PropertySetId;
pub use recipient::{Recipient, RecipientType};
pub use restrict::{FuzzyLevel, RelationalOperator, Restriction};
pub use row::{Cell, PropertyRow, RowForm};
pub use serverid::ServerEntryId;
pub use sort::{SortDirection, SortOrder, SortOrderSet};
pub use special::{SPECIAL_FOLDER_PROPERTIES, SpecialFolder};
pub use tag::PropertyTag;
pub use value::{Floating64, PropertyValue, TableString};
