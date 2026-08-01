//! Remote operations: building a batch of them, and reading the responses back.
//!
//! The layer's one structural idea is that ROPs in a single buffer chain through the handle table,
//! so a folder walk that would be three round trips is one. [`RopBatch`] is where that happens
//! without anyone writing a handle index by hand.
//!
//! [MS-OXCROPS] — remote operations list and encoding

mod batch;
mod buffer;
mod folder;
mod id;
mod logon;
mod response;
mod table;

pub use batch::{HandleSlot, ObjectHandle, RopBatch};
pub(crate) use buffer::RopBuffer;
pub use folder::OpenFolderResponse;
pub use id::RopId;
pub use logon::{LogonResponse, WellKnownFolder};
pub use response::RopResponse;
pub(crate) use response::decode_all;
pub use table::{Bookmark, GetTableResponse, QueryRowsResponse, SetColumnsResponse, TableStatus};
