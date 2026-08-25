//! Remote operations: building a batch of them, and reading the responses back.
//!
//! The layer's one structural idea is that ROPs in a single buffer chain through the handle table,
//! so a folder walk that would be three round trips is one. [`RopBatch`] is where that happens
//! without anyone writing a handle index by hand.
//!
//! [MS-OXCROPS] — remote operations list and encoding

mod batch;
mod buffer;
mod create;
mod folder;
mod id;
mod logon;
mod longterm;
mod message;
mod named;
mod property;
mod response;
mod stream;
mod table;

pub use batch::{HandleSlot, ObjectHandle, RopBatch};
pub(crate) use buffer::RopBuffer;
pub use create::{
    CreateAttachmentResponse, CreateMessageResponse, DeleteMessagesResponse, SaveChangesResponse,
};
pub use folder::OpenFolderResponse;
pub use id::RopId;
pub use logon::{LogonResponse, WellKnownFolder};
pub use longterm::{IdFromLongTermIdResponse, LongTermIdFromIdResponse};
pub use message::{MessageMode, OpenMessageResponse, OpenRecipient};
pub use named::{NameRegistration, PropertyIdsResponse, PropertyNamesResponse};
pub use property::{GetPropertiesResponse, PropertyProblemsResponse};
pub use response::RopResponse;
pub(crate) use response::{Decoding, decode_all};
pub use stream::{ReadStreamResponse, StreamMode, StreamSizeResponse, WriteStreamResponse};
pub use table::{
    Bookmark, FolderDepth, GetTableResponse, QueryRowsResponse, SetColumnsResponse, TableStatus,
    TableStatusResponse,
};
