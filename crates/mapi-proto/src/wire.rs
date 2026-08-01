//! Little-endian primitives — the layer that is not allowed to panic.
//!
//! Every MAPI structure is little-endian and length-prefixed, which makes the read side a parser
//! over bytes from a server nobody here controls: a truncated buffer or a lying length prefix has
//! to produce an error, never a panic and never an out-of-bounds read. So [`Reader`] returns
//! [`Result`](crate::Result) from every method, reaches the buffer only through `get`, and
//! every offset it computes is a `checked_` or `saturating_` operation.
//!
//! [MS-OXCROPS] §2 — "buffers and fields in this section are depicted in little-endian byte
//! order"

mod reader;
mod writer;

pub(crate) use reader::Reader;
pub(crate) use writer::Writer;
