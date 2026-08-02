//! Builders for the byte sequences the tests decode.
//!
//! Every one of these produces bytes in the shape a real server sends, so a test that decodes them
//! is making a statement about the protocol rather than about a mock.

use crate::rop::{ObjectHandle, RopId};
use crate::wire::Writer;

/// A `RopLogon` success response for a private mailbox, from `LogonFlags` onwards.
///
/// [MS-OXCSTOR] §2.2.1.1.3
pub(crate) fn logon_response_body() -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(0x01); // LogonFlags = Private
    for i in 0..13_u64 {
        w.u64(0x0100_0000_0000_0000 | i);
    }
    w.u8(0x01); // ResponseFlags: the Reserved bit, which MUST be set
    w.bytes(&[0xAB; 16]); // MailboxGuid
    w.u16(1); // ReplId
    w.bytes(&[0xCD; 16]); // ReplGuid
    w.bytes(&[0; 8]); // LogonTime
    w.bytes(&[0; 8]); // GwartTime
    w.u32(0); // StoreState
    w.finish()
}

/// A complete `RopLogon` response, including its header fields.
pub(crate) fn logon_response(handle_index: u8) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(RopId::LOGON.as_u8()).u8(handle_index).u32(0);
    w.bytes(&logon_response_body());
    w.finish()
}

/// A `RopQueryRows` response carrying `rows` hierarchy-table rows.
pub(crate) fn query_rows_response(handle_index: u8, rows: &[(u64, &str)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(RopId::QUERY_ROWS.as_u8()).u8(handle_index).u32(0);
    // Origin = BOOKMARK_BEGINNING, then the row count.
    w.u8(0x00)
        .u16(u16::try_from(rows.len()).unwrap_or(u16::MAX));
    for (folder_id, name) in rows {
        w.u8(0x00).u64(*folder_id);
        for unit in name.encode_utf16() {
            w.u16(unit);
        }
        w.u16(0);
        w.u32(1).u8(0);
    }
    w.finish()
}

/// Frames a ROP list and handle table the way a server does.
///
/// [MS-OXCROPS] §2.2.1
pub(crate) fn rop_buffer(rops: &[u8], handles: &[ObjectHandle]) -> Vec<u8> {
    let mut payload = Writer::new();
    payload
        .u16(u16::try_from(rops.len().saturating_add(2)).unwrap_or(u16::MAX))
        .bytes(rops);
    for handle in handles {
        payload.u32(handle.as_u32());
    }
    let payload = payload.finish();

    let mut w = Writer::new();
    let size = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    w.u16(0).u16(0x0004).u16(size).u16(size).bytes(&payload);
    w.finish()
}

/// A whole `Execute` response payload: meta-tag preamble, then the response body.
///
/// [MS-OXCMAPIHTTP] §2.2.4.2.2
pub(crate) fn execute_payload(rops: &[u8], handles: &[ObjectHandle]) -> Vec<u8> {
    let buffer = rop_buffer(rops, handles);

    // StatusCode, ErrorCode, Flags, RopBufferSize, RopBuffer, AuxiliaryBufferSize.
    let mut body = Writer::new();
    body.u32(0)
        .u32(0)
        .u32(0)
        .u32(u32::try_from(buffer.len()).unwrap_or(u32::MAX))
        .bytes(&buffer)
        .u32(0);

    with_preamble(&body.finish())
}

/// A whole `Connect` success response payload.
///
/// [MS-OXCMAPIHTTP] §2.2.4.1.2
pub(crate) fn connect_payload(display_name: &str) -> Vec<u8> {
    // StatusCode, ErrorCode, PollsMax, RetryCount, RetryDelay, DnPrefix.
    let mut body = Writer::new();
    body.u32(0)
        .u32(0)
        .u32(60_000)
        .u32(3)
        .u32(1_000)
        .ascii_z("/o=First Organization/ou=Exchange Administrative Group");
    for unit in display_name.encode_utf16() {
        body.u16(unit);
    }
    body.u16(0).u32(0);

    with_preamble(&body.finish())
}

/// A `Connect` failure payload carrying one error code.
pub(crate) fn connect_failure_payload(error_code: u32) -> Vec<u8> {
    let mut body = Writer::new();
    body.u32(0).u32(error_code).u32(0).u32(0).u32(0);
    body.ascii_z("").u16(0).u32(0);
    with_preamble(&body.finish())
}

/// Wraps a response body in the meta-tag preamble a server sends.
///
/// [MS-OXCMAPIHTTP] §2.2.7
pub(crate) fn with_preamble(body: &[u8]) -> Vec<u8> {
    let mut payload = b"PROCESSING\r\nDONE\r\nX-ElapsedTime: 5\r\n\r\n".to_vec();
    payload.extend_from_slice(body);
    payload
}

/// The response headers a successful exchange carries.
pub(crate) fn ok_headers() -> crate::Headers {
    let mut headers = crate::Headers::new();
    headers
        .append("X-ResponseCode", "0")
        .append("X-ServerApplication", "Exchange/15.02.2562.045");
    headers
}
