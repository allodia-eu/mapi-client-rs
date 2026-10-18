//! `FastTransfer` streams: the encoding bulk downloads and incremental synchronization arrive in.
//!
//! A stream is one long sequence of markers and properties, split across as many
//! `RopFastTransferSourceGetBuffer` responses as it takes. [`Lexer`] turns the bytes into elements
//! however they were split; [`ContentsSync`] reads the elements of a content synchronization
//! download as events.
//!
//! [MS-OXCFXICS] §2.2.4 — `FastTransfer` stream

mod content;
mod group;
mod lexer;
mod marker;
mod sync;

pub use content::{Attachment, MessageContent};
pub use group::{GroupProperty, PropertyGroupInfo};
pub use lexer::{Element, Lexer, StreamProperty};
pub use marker::Marker;
pub use sync::{
    ChangeHeader, ContentsSync, Deletions, ErrorInfo, FinalState, MessageChange, PartialGroup,
    Progress, ReadStates, SyncEvent,
};
