//! The transport boundary, against a fake MAPI/HTTP server.
//!
//! What these tests are for: everything between "the codec produced these bytes" and "the server
//! saw this request" — the headers, the cookies, the sequencing, and the shape of the ROP batches
//! this crate builds. The bytes themselves are the codec's business and are tested there; the live
//! server's agreement with all of it is `tests/live.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use mapi_client::{CONTENTS_COLUMNS, HIERARCHY_COLUMNS, PropertyTag, WellKnownFolder};
use support::{
    BOOKMARK_CURRENT, BOOKMARK_END, FOLDER_HANDLE, LOGON_HANDLE, MapiServer, SERVER_VERSION,
    TABLE_HANDLE, columns_of, connect_ok, contents_row, disconnect_body, execute_body,
    get_table_response, hierarchy_row, logon_response, opcodes, open_folder_response,
    query_rows_response, rop_list, set_columns_response, well_known_folder_id,
};

/// The handle table an opened table read leaves behind: logon in slot 0, folder in 1, table in 2.
const OPENED: [u32; 3] = [LOGON_HANDLE, FOLDER_HANDLE, TABLE_HANDLE];

/// Queues the two round trips every read starts with: `Connect`, then the logon.
fn ready(server: &MapiServer) {
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
}

/// The whole path, from an endpoint URL to rows, across the round trips it really takes.
#[tokio::test]
async fn a_table_is_read_a_page_at_a_time() {
    let server = MapiServer::start().await;
    ready(&server);

    // Opening: folder, table, columns and the first page, all in one Execute.
    let mut first = open_folder_response(1);
    first.extend(get_table_response(0x05, 2, 3));
    first.extend(set_columns_response(2));
    first.extend(query_rows_response(
        2,
        BOOKMARK_CURRENT,
        &[
            contents_row(0x1000, "First", 0x01D9_0000_0000_0000, 1),
            contents_row(0x1001, "Second", 0x01D9_0000_0000_0001, 1),
        ],
    ));
    server.reply_ok(execute_body(&first, &OPENED));

    // Paging: one `RopQueryRows` against the bound table handle, and the last page carries a row.
    server.reply_ok(execute_body(
        &query_rows_response(
            0,
            BOOKMARK_END,
            &[contents_row(0x1002, "Third", 0x01D9_0000_0000_0002, 0)],
        ),
        &[TABLE_HANDLE],
    ));

    let client = server.client();
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();
    let mut rows = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .page_size(2)
        .rows();

    let mut subjects = Vec::new();
    while let Some(row) = rows.try_next().await.unwrap() {
        subjects.push(
            row.string(PropertyTag::SUBJECT)
                .unwrap()
                .as_str()
                .to_owned(),
        );
    }

    assert_eq!(subjects, ["First", "Second", "Third"]);
    assert_eq!(rows.row_count(), Some(3), "reported when the table opened");
    assert_eq!(server.requests().await.len(), 4);
}

/// The first batch chains four ROPs and throws the folder handle away in the same round trip: the
/// table is a Server object in its own right and does not need it.
#[tokio::test]
async fn the_opening_batch_chains_four_rops_and_releases_the_folder() {
    let server = MapiServer::start().await;
    ready(&server);

    let mut opened = open_folder_response(1);
    opened.extend(get_table_response(0x04, 2, 0));
    opened.extend(set_columns_response(2));
    opened.extend(query_rows_response(2, BOOKMARK_END, &[]));
    server.reply_ok(execute_body(&opened, &OPENED));
    server.reply_ok(execute_body(&[], &[TABLE_HANDLE]));

    let client = server.client();
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();
    let rows = logon
        .well_known(WellKnownFolder::IpmSubtree)
        .unwrap()
        .subfolders()
        .collect()
        .await
        .unwrap();
    assert!(rows.is_empty());

    let sent = server.rops(2).await;
    assert_eq!(
        opcodes(&sent),
        [
            0x02, // RopOpenFolder
            0x04, // RopGetHierarchyTable, because this read asked for subfolders
            0x12, // RopSetColumns
            0x15, // RopQueryRows
            0x01, // RopRelease, of the folder handle
        ],
        "unexpected ROP chain: {sent:02X?}"
    );

    // Each ROP names the slot it works on: the folder is slot 1, the table slot 2, and the
    // release is of the folder. Getting one of these wrong yields a plausible wrong answer
    // rather than an error, which is why they are pinned.
    let batch = rop_list(&sent);
    assert_eq!(
        batch[0].1[3], 1,
        "RopOpenFolder writes its handle to slot 1"
    );
    assert_eq!(batch[1].1[3], 2, "the table lands in slot 2");
    assert_eq!(batch[3].1[2], 2, "RopQueryRows reads from the table's slot");
    assert_eq!(
        batch[4].1[2], 1,
        "RopRelease frees the folder, not the table"
    );
}

/// Each table gets the column set that suits it unless the caller says otherwise, and the columns
/// are sent once however many pages are read.
#[tokio::test]
async fn columns_are_sent_once_and_default_to_the_table_kind() {
    let server = MapiServer::start().await;
    ready(&server);

    let mut opened = open_folder_response(1);
    opened.extend(get_table_response(0x04, 2, 2));
    opened.extend(set_columns_response(2));
    opened.extend(query_rows_response(
        2,
        BOOKMARK_CURRENT,
        &[hierarchy_row(well_known_folder_id(4), "Inbox", 12, false)],
    ));
    server.reply_ok(execute_body(&opened, &OPENED));
    server.reply_ok(execute_body(
        &query_rows_response(
            0,
            BOOKMARK_END,
            &[hierarchy_row(
                well_known_folder_id(6),
                "Sent Items",
                3,
                false,
            )],
        ),
        &[TABLE_HANDLE],
    ));
    server.reply_ok(execute_body(&[], &[TABLE_HANDLE]));

    let client = server.client();
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();
    let rows = logon
        .well_known(WellKnownFolder::IpmSubtree)
        .unwrap()
        .subfolders()
        .page_size(1)
        .collect()
        .await
        .unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0].string(PropertyTag::DISPLAY_NAME).unwrap().as_str(),
        "Inbox"
    );
    assert_eq!(
        rows[0].folder_id().unwrap().as_u64(),
        well_known_folder_id(4)
    );
    assert_eq!(
        rows[1].get(PropertyTag::CONTENT_COUNT).unwrap().as_u32(),
        Some(3)
    );

    // The opening batch asked for the hierarchy columns...
    let opening = server.rops(2).await;
    assert_eq!(columns_of(rop_list(&opening)[2].1), HIERARCHY_COLUMNS);

    // ...and the second page asked for rows and nothing else. The session remembers the column
    // set for the table's handle, which is what makes paging one ROP rather than two.
    let paging = server.rops(3).await;
    assert_eq!(opcodes(&paging), [0x15], "a page is a RopQueryRows alone");
}

/// A caller's column set reaches the wire in the order given, and the rows decode against it.
#[tokio::test]
async fn a_chosen_column_set_is_what_the_rows_decode_against() {
    let server = MapiServer::start().await;
    ready(&server);

    // Two columns, in an order that is not the default's.
    let row = support::Bytes::new()
        .utf16_z("Lunch")
        .u64(0x0000_0000_0000_002A)
        .done();
    let mut opened = open_folder_response(1);
    opened.extend(get_table_response(0x05, 2, 1));
    opened.extend(set_columns_response(2));
    opened.extend(query_rows_response(2, BOOKMARK_END, &[row]));
    server.reply_ok(execute_body(&opened, &OPENED));
    server.reply_ok(execute_body(&[], &[TABLE_HANDLE]));

    let client = server.client();
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();
    let rows = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .columns([PropertyTag::SUBJECT, PropertyTag::MID])
        .collect()
        .await
        .unwrap();

    assert_eq!(
        rows[0].string(PropertyTag::SUBJECT).unwrap().as_str(),
        "Lunch"
    );
    assert_eq!(rows[0].message_id().unwrap().as_u64(), 0x2A);

    let opening = server.rops(2).await;
    assert_eq!(
        columns_of(rop_list(&opening)[2].1),
        [PropertyTag::SUBJECT, PropertyTag::MID]
    );
    // A borrowed constant works as well as an array literal.
    assert_eq!(CONTENTS_COLUMNS.len(), 4);
}

/// The headers the protocol requires, and the two whose uniqueness rules differ.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.2 — `X-RequestId`: the counter increases with every request
/// [MS-OXCMAPIHTTP] §2.2.3.3.4 — `X-ClientInfo`: constant for the life of a client instance
#[tokio::test]
async fn every_request_carries_the_headers_the_protocol_requires() {
    let server = MapiServer::start().await;
    ready(&server);
    server.reply_ok(disconnect_body());

    let client = server.client();
    let logon = client.connect().await.unwrap().logon().await.unwrap();
    logon.disconnect().await.unwrap();

    let requests = server.requests().await;
    let header = |index: usize, name: &str| {
        requests[index]
            .headers
            .get(name)
            .map(|value| value.to_str().unwrap().to_owned())
    };

    assert_eq!(header(0, "X-RequestType").as_deref(), Some("Connect"));
    assert_eq!(header(1, "X-RequestType").as_deref(), Some("Execute"));
    assert_eq!(header(2, "X-RequestType").as_deref(), Some("Disconnect"));

    for index in 0..3 {
        assert_eq!(
            header(index, "Content-Type").as_deref(),
            Some("application/mapi-http")
        );
        assert!(
            header(index, "Authorization").is_some_and(|value| value.starts_with("Basic ")),
            "request {index} carried no Basic credentials"
        );
        assert!(header(index, "X-ClientApplication").is_some());
    }

    // The GUID is the client instance's and does not move; the counter after it does.
    let client_info: Vec<_> = (0..3).map(|index| header(index, "X-ClientInfo")).collect();
    assert_eq!(client_info[0], client_info[1]);
    assert_eq!(client_info[1], client_info[2]);

    let request_ids: Vec<_> = (0..3)
        .map(|index| header(index, "X-RequestId").unwrap())
        .collect();
    let counter = |value: &str| value.rsplit_once(':').unwrap().1.parse::<u64>().unwrap();
    assert!(counter(&request_ids[0]) < counter(&request_ids[1]));
    assert!(counter(&request_ids[1]) < counter(&request_ids[2]));
    assert_eq!(
        request_ids[0].rsplit_once(':').unwrap().0,
        request_ids[2].rsplit_once(':').unwrap().0,
        "the GUID must not change for the life of the Session Context"
    );
}

/// Losing the Session Context's cookies is reported several requests later as `X-ResponseCode` 13,
/// pointing nowhere near the cause — so this is worth pinning.
///
/// [MS-OXCMAPIHTTP] §2.2.3.2.4 — `Cookie`
#[tokio::test]
async fn the_session_cookies_are_echoed_on_every_later_request() {
    let server = MapiServer::start().await;
    ready(&server);

    let client = server.client();
    let connection = client.connect().await.unwrap();
    assert_eq!(connection.server().display_name(), "Alice Example");
    assert_eq!(connection.server().retry_count(), 6);
    let _logon = connection.logon().await.unwrap();

    let requests = server.requests().await;
    assert!(
        requests[0].headers.get("Cookie").is_none(),
        "there is nothing to echo before the first response"
    );

    let cookie = requests[1].headers.get("Cookie").unwrap().to_str().unwrap();
    assert!(cookie.contains("MapiContext=ctx-0001"), "{cookie}");
    assert!(cookie.contains("MapiSequence=seq-0001"), "{cookie}");
}

/// `PING` needs no Session Context. The specification describes it as validating an existing one;
/// Exchange Server SE `15.02.2562.045` answers `X-ResponseCode: 0` without one, which is what
/// makes it useful as a reachability check.
///
/// [MS-OXCMAPIHTTP] §2.2.6 — `PING`
#[tokio::test]
async fn ping_asks_nothing_of_the_server_but_an_answer() {
    let server = MapiServer::start().await;
    server.reply_ok(Vec::new());

    server.client().ping().await.unwrap();

    let requests = server.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].headers.get("X-RequestType").unwrap(),
        &"PING".to_owned()
    );
    assert!(requests[0].body.is_empty());
}

/// Reading everything releases the table handle; the server would otherwise hold it until the
/// Session Context ends.
#[tokio::test]
async fn collecting_every_row_releases_the_table() {
    let server = MapiServer::start().await;
    ready(&server);

    let mut opened = open_folder_response(1);
    opened.extend(get_table_response(0x05, 2, 1));
    opened.extend(set_columns_response(2));
    opened.extend(query_rows_response(
        2,
        BOOKMARK_END,
        &[contents_row(0x1000, "Only", 0, 0)],
    ));
    server.reply_ok(execute_body(&opened, &OPENED));
    server.reply_ok(execute_body(&[], &[TABLE_HANDLE]));

    let client = server.client();
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();
    let rows = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .collect()
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    let closing = server.rops(3).await;
    assert_eq!(opcodes(&closing), [0x01], "RopRelease and nothing else");
    assert_eq!(
        rop_list(&closing)[0].1[2],
        0,
        "the table was bound into slot 0 of a fresh batch"
    );
}

/// The server's version is not something this crate acts on, but a response that carries one is
/// the shape every real answer has, and the codec has to survive the whole header set.
#[tokio::test]
async fn a_response_carrying_the_servers_own_headers_is_read_normally() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example").append_header("X-ExpirationInfo", "600000"));

    let connection = server.client().connect().await.unwrap();
    assert_eq!(connection.server().polls_max(), 60_000);
    assert!(SERVER_VERSION.starts_with("Exchange/"));
}
