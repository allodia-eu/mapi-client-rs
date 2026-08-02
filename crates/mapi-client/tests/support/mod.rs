//! A fake MAPI/HTTP server, and the byte sequences it answers with.
//!
//! Every builder here writes the layout the specification defines, field by field, so a test that
//! passes is a statement about the protocol rather than about a mock that agrees with the code.
//! The one thing this cannot prove is that a real Exchange sends these bytes; `tests/live.rs`
//! answers that, against a server CI never sees.
//!
//! [MS-OXCMAPIHTTP] §2.2.4 — request types and their response bodies
//! [MS-OXCROPS] §2.2.1 — ROP output buffers

#![allow(
    dead_code,
    reason = "shared by several test binaries; each one uses a different part"
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    reason = "a test that walks a known layout by offset is asserting something true about it"
)]
#![allow(
    clippy::needless_pass_by_value,
    reason = "these builders hand their bytes onward to wiremock, which wants them owned"
)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use mapi_client::{Credentials, LegacyDn, MapiClient, PropertyTag};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The distinguished name every test logs on with.
pub(crate) const USER_DN: &str =
    "/o=Example/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=alice";

/// A plausible server version, so a test reading the header sees the shape of a real one.
pub(crate) const SERVER_VERSION: &str = "Exchange/15.02.2562.045";

/// The handle a logon is given, and the handles the folder and table reads produce.
pub(crate) const LOGON_HANDLE: u32 = 0x0000_0000;
pub(crate) const FOLDER_HANDLE: u32 = 0x0000_0001;
pub(crate) const TABLE_HANDLE: u32 = 0x0000_0002;

/// The handle-table slots the opening batch allocates: the bound logon, then the folder it opens,
/// then the table it takes from that folder.
pub(crate) const LOGON_SLOT: u8 = 0;
pub(crate) const OPEN_FOLDER_SLOT: u8 = 1;
pub(crate) const TABLE_SLOT: u8 = 2;

// ---------------------------------------------------------------------------
// Little-endian writing, which is all the wire format is.
// ---------------------------------------------------------------------------

/// Builds a byte string in the order the wire carries it.
#[derive(Debug, Default)]
pub(crate) struct Bytes(Vec<u8>);

impl Bytes {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn u8(mut self, value: u8) -> Self {
        self.0.push(value);
        self
    }

    pub(crate) fn u16(mut self, value: u16) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub(crate) fn u32(mut self, value: u32) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub(crate) fn u64(mut self, value: u64) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub(crate) fn raw(mut self, value: &[u8]) -> Self {
        self.0.extend_from_slice(value);
        self
    }

    /// A null-terminated 8-bit string.
    pub(crate) fn ascii_z(mut self, value: &str) -> Self {
        self.0.extend_from_slice(value.as_bytes());
        self.0.push(0);
        self
    }

    /// A null-terminated UTF-16LE string, which is what `PtypString` is.
    ///
    /// [MS-OXCDATA] §2.11.1
    pub(crate) fn utf16_z(mut self, value: &str) -> Self {
        for unit in value.encode_utf16() {
            self.0.extend_from_slice(&unit.to_le_bytes());
        }
        self.0.extend_from_slice(&[0, 0]);
        self
    }

    pub(crate) fn done(self) -> Vec<u8> {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Response bodies.
// ---------------------------------------------------------------------------

/// A `Connect` success body. [MS-OXCMAPIHTTP] §2.2.4.1.2
#[rustfmt::skip]
pub(crate) fn connect_body(display_name: &str) -> Vec<u8> {
    Bytes::new()
        .u32(0) // StatusCode
        .u32(0) // ErrorCode
        .u32(60_000) // PollsMax
        .u32(6) // RetryCount
        .u32(18_409) // RetryDelay
        .ascii_z("/o=Example/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)")
        .utf16_z(display_name)
        .u32(0) // AuxiliaryBufferSize
        .done()
}

/// A `Connect` failure body, which stops right after `StatusCode` unless the status is zero.
///
/// [MS-OXCMAPIHTTP] §2.2.4.1.3
#[rustfmt::skip]
pub(crate) fn connect_refused(error_code: u32) -> Vec<u8> {
    Bytes::new()
        .u32(0) // StatusCode: the request itself was fine
        .u32(error_code) // ErrorCode: what the server thought of the distinguished name
        .u32(0)
        .u32(0)
        .u32(0)
        .ascii_z("")
        .utf16_z("")
        .u32(0)
        .done()
}

/// An `Execute` success body wrapping a ROP output buffer. [MS-OXCMAPIHTTP] §2.2.4.2.2
#[rustfmt::skip]
pub(crate) fn execute_body(rops: &[u8], handles: &[u32]) -> Vec<u8> {
    let buffer = rop_buffer(rops, handles);
    Bytes::new()
        .u32(0) // StatusCode
        .u32(0) // ErrorCode
        .u32(0) // Flags
        .u32(u32::try_from(buffer.len()).unwrap())
        .raw(&buffer)
        .u32(0) // AuxiliaryBufferSize
        .done()
}

/// A `Disconnect` success body. [MS-OXCMAPIHTTP] §2.2.4.3.2
pub(crate) fn disconnect_body() -> Vec<u8> {
    Bytes::new().u32(0).u32(0).u32(0).done()
}

/// Frames a ROP list and its handle table.
///
/// `RopSize` counts itself and the ROP list but **not** the handle table, which is the rule an
/// implementation gets wrong by exactly two bytes.
///
/// [MS-OXCROPS] §2.2.1
#[rustfmt::skip]
pub(crate) fn rop_buffer(rops: &[u8], handles: &[u32]) -> Vec<u8> {
    let mut payload = Bytes::new()
        .u16(u16::try_from(rops.len() + 2).unwrap())
        .raw(rops);
    for handle in handles {
        payload = payload.u32(*handle);
    }
    let payload = payload.done();
    let size = u16::try_from(payload.len()).unwrap();

    Bytes::new()
        .u16(0x0000) // Version
        .u16(0x0004) // Flags = Last
        .u16(size)
        .u16(size) // SizeActual, equal because nothing is compressed
        .raw(&payload)
        .done()
}

// ---------------------------------------------------------------------------
// ROP responses.
// ---------------------------------------------------------------------------

/// A `RopLogon` success response for a private mailbox.
///
/// The thirteen folder ids are `0x0100000000000000 + index`, so a test can name the one it means.
///
/// [MS-OXCSTOR] §2.2.1.1.3
#[rustfmt::skip]
pub(crate) fn logon_response(slot: u8) -> Vec<u8> {
    let mut out = Bytes::new()
        .u8(0xFE) // RopLogon
        .u8(slot)
        .u32(0) // ReturnValue
        .u8(0x01); // LogonFlags = Private
    for index in 0..13_u64 {
        out = out.u64(0x0100_0000_0000_0000 | index);
    }
    out.u8(0x01) // ResponseFlags: the Reserved bit, which MUST be set
        .raw(&[0xAB; 16]) // MailboxGuid
        .u16(1) // ReplId
        .raw(&[0xCD; 16]) // ReplGuid
        .raw(&[0; 8]) // LogonTime: 8 bytes, not 13
        .raw(&[0; 8]) // GwartTime
        .u32(0) // StoreState
        .done()
}

/// The folder id a [`logon_response`] reports for a given well-known folder index.
pub(crate) fn well_known_folder_id(index: u64) -> u64 {
    0x0100_0000_0000_0000 | index
}

/// A ROP that failed, whose response stops right after `ReturnValue`.
pub(crate) fn rop_failed(rop: u8, slot: u8, code: u32) -> Vec<u8> {
    Bytes::new().u8(rop).u8(slot).u32(code).done()
}

/// A `RopLogon` refused with `ecWrongServer`, which alone among refusals carries a body.
///
/// [MS-OXCSTOR] §2.2.1.1.2
#[rustfmt::skip]
pub(crate) fn logon_redirect(slot: u8, server: &str) -> Vec<u8> {
    let name = Bytes::new().ascii_z(server).done();
    Bytes::new()
        .u8(0xFE)
        .u8(slot)
        .u32(0x0000_0478) // ecWrongServer
        .u8(0x01) // LogonFlags
        .u8(u8::try_from(name.len()).unwrap()) // ServerNameSize, counting the NUL
        .raw(&name)
        .done()
}

/// A `RopOpenFolder` success response. [MS-OXCROPS] §2.2.4.1.2
#[rustfmt::skip]
pub(crate) fn open_folder_response(slot: u8) -> Vec<u8> {
    Bytes::new()
        .u8(0x02)
        .u8(slot)
        .u32(0)
        .u8(0) // HasRules
        .u8(0) // IsGhosted
        .done()
}

/// A `RopGetContentsTable` or `RopGetHierarchyTable` success response.
///
/// [MS-OXCROPS] §2.2.4.13.2
pub(crate) fn get_table_response(rop: u8, slot: u8, row_count: u32) -> Vec<u8> {
    Bytes::new().u8(rop).u8(slot).u32(0).u32(row_count).done()
}

/// A `RopSetColumns` success response. [MS-OXCROPS] §2.2.5.1.2
#[rustfmt::skip]
pub(crate) fn set_columns_response(slot: u8) -> Vec<u8> {
    Bytes::new()
        .u8(0x12)
        .u8(slot)
        .u32(0)
        .u8(0x00) // TableStatus = TBLSTAT_COMPLETE
        .done()
}

/// A `RopRelease` success response, which a real server does not send at all.
pub(crate) fn release_response(slot: u8) -> Vec<u8> {
    Bytes::new().u8(0x01).u8(slot).u32(0).done()
}

/// Where the cursor sits after a read. [MS-OXCTABL] §2.2.2.1.1
pub(crate) const BOOKMARK_CURRENT: u8 = 0x01;
pub(crate) const BOOKMARK_END: u8 = 0x02;

/// A `RopQueryRows` response carrying rows in the standard form, which is what Exchange sends.
///
/// `rows` are encoded against the column set the caller last set on the table — that is the whole
/// point of a row: it carries values and nothing else.
///
/// [MS-OXCROPS] §2.2.5.4.2
/// [MS-OXCDATA] §2.8.1.1 — `StandardPropertyRow`
pub(crate) fn query_rows_response(slot: u8, bookmark: u8, rows: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Bytes::new()
        .u8(0x15)
        .u8(slot)
        .u32(0)
        .u8(bookmark)
        .u16(u16::try_from(rows.len()).unwrap());
    for row in rows {
        out = out.u8(0x00).raw(row); // RowFlag = StandardPropertyRow
    }
    out.done()
}

/// One row of a hierarchy table read with [`mapi_client::HIERARCHY_COLUMNS`]: folder id, parent
/// folder id, display name, container class, message count, has-children.
///
/// The parent is a constant here because nothing in this file tests nesting — the recursive read
/// is exercised against the captured corpus, where the ids are a real mailbox's rather than made
/// up.
pub(crate) fn hierarchy_row(
    folder_id: u64,
    name: &str,
    content_count: u32,
    subfolders: bool,
) -> Vec<u8> {
    Bytes::new()
        .u64(folder_id)
        .u64(0x0D00_0000_0000_0001)
        .utf16_z(name)
        .utf16_z("IPF.Note")
        .u32(content_count)
        .u8(u8::from(subfolders))
        .done()
}

/// One row of a contents table read with [`mapi_client::CONTENTS_COLUMNS`]: message id, subject,
/// delivery time, flags.
pub(crate) fn contents_row(
    message_id: u64,
    subject: &str,
    delivery_time: u64,
    flags: u32,
) -> Vec<u8> {
    Bytes::new()
        .u64(message_id)
        .utf16_z(subject)
        .u64(delivery_time)
        .u32(flags)
        .done()
}

// ---------------------------------------------------------------------------
// The server itself.
// ---------------------------------------------------------------------------

/// A response the fake server will give, in turn.
type Queue = Arc<Mutex<VecDeque<ResponseTemplate>>>;

/// Answers each request with the next queued response.
///
/// A scripted queue rather than per-request matchers, because MAPI/HTTP is a conversation: two
/// `Execute` requests differ only in the bytes of their ROP buffers, and a test that matched on
/// those would be asserting the request shape twice — once to route, once to check.
struct Script(Queue);

impl Respond for Script {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.0.lock().unwrap().pop_front().unwrap_or_else(|| {
            ResponseTemplate::new(500).set_body_string("the test queued no further response")
        })
    }
}

/// A fake MAPI/HTTP endpoint.
pub(crate) struct MapiServer {
    server: MockServer,
    queue: Queue,
}

impl MapiServer {
    /// Starts one, answering on a loopback port.
    pub(crate) async fn start() -> Self {
        let server = MockServer::start().await;
        let queue: Queue = Arc::new(Mutex::new(VecDeque::new()));
        Mock::given(method("POST"))
            .respond_with(Script(Arc::clone(&queue)))
            .mount(&server)
            .await;
        Self { server, queue }
    }

    /// Queues one response.
    pub(crate) fn reply(&self, response: ResponseTemplate) -> &Self {
        self.queue.lock().unwrap().push_back(response);
        self
    }

    /// Queues a successful MAPI response carrying `body`.
    pub(crate) fn reply_ok(&self, body: Vec<u8>) -> &Self {
        self.reply(mapi_ok(body))
    }

    /// The endpoint URL, in the shape Autodiscover hands over.
    pub(crate) fn endpoint(&self) -> String {
        format!(
            "{}/mapi/emsmdb/?MailboxId=00000000-0000-0000-0000-000000000000@example.test",
            self.server.uri()
        )
    }

    /// The server's base URL, for the paths that are not the MAPI endpoint.
    pub(crate) fn uri(&self) -> String {
        self.server.uri()
    }

    /// A client pointed at this server. Plaintext, because a fake server has no certificate.
    pub(crate) fn client(&self) -> MapiClient {
        self.builder().build().unwrap()
    }

    /// The same, before `build`, for a test that needs to change something first.
    pub(crate) fn builder(&self) -> mapi_client::MapiClientBuilder {
        Self::builder_for(self.endpoint())
    }

    /// A builder pointed at any URL, for the tests whose endpoint is not a running fake.
    pub(crate) fn builder_for(url: impl Into<String>) -> mapi_client::MapiClientBuilder {
        MapiClient::builder()
            .endpoint(url)
            .user_dn(LegacyDn::new(USER_DN).unwrap())
            .credentials(Credentials::basic("alice@example.test", "hunter2"))
            .danger_allow_plaintext_http()
    }

    /// Every request received, in order.
    pub(crate) async fn requests(&self) -> Vec<Request> {
        self.server.received_requests().await.unwrap_or_default()
    }

    /// The ROP list from the nth request's `Execute` body, without any of its framing.
    ///
    /// An `Execute` body is `Flags || RopBufferSize || RopBuffer || MaxRopOut ||
    /// AuxiliaryBufferSize`, and the buffer inside it is `RPC_HEADER_EXT (8) || RopSize (2) ||
    /// RopsList || ServerObjectHandleTable`. `RopSize` counts itself, hence the two.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.2.1 — `Execute` request body
    /// [MS-OXCROPS] §2.2.1 — ROP input buffer
    pub(crate) async fn rops(&self, index: usize) -> Vec<u8> {
        let requests = self.requests().await;
        let body = &requests[index].body;
        let rop_size = usize::from(u16::from_le_bytes([body[16], body[17]]));
        body[18..18 + rop_size - 2].to_vec()
    }
}

/// Splits a ROP list into one entry per ROP: its opcode, and the whole ROP including its header.
///
/// ROPs are variable-length and not self-describing, so this walks them with the layouts of the
/// ones this crate actually sends. A test can then say "the batch was open, table, columns, rows,
/// release" instead of counting bytes, and an accidental change to any encoding shows up here as a
/// wrong opcode rather than as a silently shifted offset.
///
/// # Panics
///
/// On a ROP this crate does not send, which in a test means the batch builder has changed and this
/// walker has not.
pub(crate) fn rop_list(rops: &[u8]) -> Vec<(u8, &[u8])> {
    let u16_at = |at: usize| usize::from(u16::from_le_bytes([rops[at], rops[at + 1]]));

    let mut out = Vec::new();
    let mut at = 0;
    while at < rops.len() {
        let opcode = rops[at];
        let length = match opcode {
            0x01 => 3,                      // RopRelease
            0x02 => 13,                     // RopOpenFolder: FolderId is 8 of them
            0x04 | 0x05 => 5,               // RopGetHierarchyTable / RopGetContentsTable
            0x07 => 9 + 4 * u16_at(at + 7), // RopGetPropertiesSpecific: limit, unicode, then tags
            0x0B => 5 + 4 * u16_at(at + 3), // RopDeleteProperties: PropertyTagCount, then the tags
            0x12 => 6 + 4 * u16_at(at + 4), // RopSetColumns: PropertyTagCount, then the tags
            // RopGetPropertiesAll (limit and unicode) and RopQueryRows (flags, direction, count)
            // are the same length by coincidence rather than by kinship.
            0x08 | 0x15 => 7,
            0x43 => 11,                   // RopLongTermIdFromId: an 8-byte ObjectId
            0x44 => 27,                   // RopIdFromLongTermId: a 24-byte LongTermID
            0xFE => 14 + u16_at(at + 12), // RopLogon: EssdnSize counts the NUL
            other => panic!("ROP 0x{other:02X} is not one this crate sends"),
        };
        out.push((opcode, &rops[at..at + length]));
        at += length;
    }
    out
}

/// The opcodes of a ROP list, in order.
pub(crate) fn opcodes(rops: &[u8]) -> Vec<u8> {
    rop_list(rops)
        .into_iter()
        .map(|(opcode, _)| opcode)
        .collect()
}

/// A successful MAPI response: `X-ResponseCode: 0` and the meta-tag preamble a server sends.
///
/// [MS-OXCMAPIHTTP] §2.2.7 — response meta-tags
pub(crate) fn mapi_ok(body: Vec<u8>) -> ResponseTemplate {
    mapi_response(0, body)
}

/// A MAPI response carrying an arbitrary `X-ResponseCode`.
pub(crate) fn mapi_response(response_code: u32, body: Vec<u8>) -> ResponseTemplate {
    let mut payload = b"PROCESSING\r\nDONE\r\nX-ElapsedTime: 5\r\n\r\n".to_vec();
    payload.extend_from_slice(&body);

    ResponseTemplate::new(200)
        .append_header("X-ResponseCode", response_code.to_string().as_str())
        .append_header("X-ServerApplication", SERVER_VERSION)
        .append_header("Content-Type", "application/mapi-http")
        .set_body_bytes(payload)
}

/// A successful `Connect` response, with the cookies that identify the Session Context.
///
/// [MS-OXCMAPIHTTP] §2.2.3.2.3 — `Set-Cookie`
pub(crate) fn connect_ok(display_name: &str) -> ResponseTemplate {
    mapi_ok(connect_body(display_name))
        .append_header("Set-Cookie", "MapiContext=ctx-0001; Path=/mapi; HttpOnly")
        .append_header("Set-Cookie", "MapiSequence=seq-0001; Path=/mapi; HttpOnly")
}

/// The tags in a `RopSetColumns` request's `PropertyTags` field, for asserting what was asked for.
pub(crate) fn columns_of(set_columns: &[u8]) -> Vec<PropertyTag> {
    // RopId, LogonId, InputHandleIndex, SetColumnsFlags, PropertyTagCount, then the tags.
    let count = usize::from(u16::from_le_bytes([set_columns[4], set_columns[5]]));
    (0..count)
        .map(|index| {
            let at = 6 + index * 4;
            PropertyTag::new(u32::from_le_bytes([
                set_columns[at],
                set_columns[at + 1],
                set_columns[at + 2],
                set_columns[at + 3],
            ]))
        })
        .collect()
}
