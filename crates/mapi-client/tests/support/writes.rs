//! The responses a server sends back to the ROPs that change a mailbox.
//!
//! Split from the rest of the harness because the read side was already at the workspace's file
//! limit, and because these are the half a test has to be able to make *wrong*: a short write, a
//! create that reports no handle, a save that refuses. Every one of those succeeds as a ROP, so
//! nothing but a scripted server can produce one.
//!
//! [MS-OXCROPS] §2.2.6 — Message ROPs
//! [MS-OXCROPS] §2.2.9 — Stream ROPs

use super::Bytes;

/// The handle a created message, attachment or stream is given.
pub(crate) const MESSAGE_HANDLE: u32 = 0x0000_0010;
pub(crate) const ATTACHMENT_HANDLE: u32 = 0x0000_0011;
pub(crate) const STREAM_HANDLE: u32 = 0x0000_0012;

/// The id a save reports, in the shape a real one has: replica id, then the global counter.
pub(crate) const NEW_MESSAGE_ID: u64 = 0x0D01_0000_0000_0042;

/// A `RopCreateMessage` success response.
///
/// `HasMessageId` is zero, which is what Exchange sends: the id arrives with the save.
///
/// [MS-OXCROPS] §2.2.6.2.2
pub(crate) fn create_message_response(slot: u8) -> Vec<u8> {
    Bytes::new().u8(0x06).u8(slot).u32(0).u8(0x00).done()
}

/// A `RopSaveChangesMessage` success response, whose body begins with a *second* handle index.
///
/// [MS-OXCROPS] §2.2.6.3.2
pub(crate) fn save_changes_response(slot: u8, id: u64) -> Vec<u8> {
    Bytes::new()
        .u8(0x0C)
        .u8(slot)
        .u32(0)
        .u8(slot)
        .u64(id)
        .done()
}

/// A `RopModifyRecipients` success response, which has no body at all.
///
/// [MS-OXCROPS] §2.2.6.5.2
pub(crate) fn modify_recipients_response(slot: u8) -> Vec<u8> {
    Bytes::new().u8(0x0E).u8(slot).u32(0).done()
}

/// A `RopCreateAttachment` success response, reporting the number that names the attachment.
///
/// [MS-OXCROPS] §2.2.6.13.2
pub(crate) fn create_attachment_response(slot: u8, number: u32) -> Vec<u8> {
    Bytes::new().u8(0x23).u8(slot).u32(0).u32(number).done()
}

/// A `RopSaveChangesAttachment` success response, which has no body either.
///
/// [MS-OXCROPS] §2.2.6.15.2
pub(crate) fn save_changes_attachment_response(slot: u8) -> Vec<u8> {
    Bytes::new().u8(0x25).u8(slot).u32(0).done()
}

/// A `RopWriteStream` success response.
///
/// **`written` is the field a test makes wrong.** A server that accepted fewer bytes than it was
/// sent still succeeds here, so this is the only way to produce the truncated attachment the
/// client is meant to refuse.
///
/// [MS-OXCROPS] §2.2.9.3.2
pub(crate) fn write_stream_response(slot: u8, written: u16) -> Vec<u8> {
    Bytes::new().u8(0x2D).u8(slot).u32(0).u16(written).done()
}

/// A `RopCommitStream` success response, which has no body.
///
/// [MS-OXCROPS] §2.2.9.5.2
pub(crate) fn commit_stream_response(slot: u8) -> Vec<u8> {
    Bytes::new().u8(0x5D).u8(slot).u32(0).done()
}

/// A `RopDeleteMessages` success response, whose one byte says whether it deleted everything.
///
/// [MS-OXCROPS] §2.2.4.11.2
pub(crate) fn delete_messages_response(slot: u8, partial: bool) -> Vec<u8> {
    Bytes::new()
        .u8(0x1E)
        .u8(slot)
        .u32(0)
        .u8(u8::from(partial))
        .done()
}

/// A `RopSetProperties` success response, listing the properties the server refused.
///
/// A `RopSetProperties` that refused every property still succeeds, which is why the list travels
/// alongside a zero `ReturnValue` rather than instead of one.
///
/// [MS-OXCROPS] §2.2.8.6.2
/// [MS-OXCDATA] §2.7 — `PropertyProblem`
pub(crate) fn set_properties_response(slot: u8, problems: &[(u16, u32, u32)]) -> Vec<u8> {
    let mut out = Bytes::new()
        .u8(0x0A)
        .u8(slot)
        .u32(0)
        .u16(u16::try_from(problems.len()).unwrap());
    for (index, tag, code) in problems {
        out = out.u16(*index).u32(*tag).u32(*code);
    }
    out.done()
}

/// A `RopOpenMessage` success response for a message with no recipients and no subject.
///
/// The empty tail is deliberate: these tests are about the write that follows the open, and a
/// recipient table in front of it would only be asserting the read path a second time.
///
/// [MS-OXCROPS] §2.2.6.1.2
#[rustfmt::skip]
pub(crate) fn open_message_response(slot: u8) -> Vec<u8> {
    Bytes::new()
        .u8(0x03)
        .u8(slot)
        .u32(0)
        .u8(0x00) // HasNamedProperties
        .u8(0x00) // SubjectPrefix: StringType 0x00, no string at all
        .u8(0x00) // NormalizedSubject, the same
        .u16(0)   // RecipientCount
        .u16(0)   // RecipientColumnCount
        .u8(0)    // RowCount
        .done()
}
