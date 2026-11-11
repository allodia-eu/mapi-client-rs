//! Handles given back when the object holding them is dropped rather than closed.
//!
//! Exchange holds at most 500 objects per Session Context — measured against Exchange Server SE
//! `15.02.2562.056`, which refused the next with `ecMaxObjsExceeded` — so a session that lasts
//! cannot leave a table open for every read it gave up on. A dropped object queues its release, and
//! the connection's next request carries it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use mapi_client::WellKnownFolder;
use support::{
    BOOKMARK_CURRENT, BOOKMARK_END, LOGON_HANDLE, MapiServer, OPEN_FOLDER_SLOT, TABLE_HANDLE,
    connect_body, connect_ok, contents_row, execute_body, get_table_response, logon_response,
    mapi_ok, mapi_response, opcodes, open_folder_response, query_rows_response,
    set_columns_response,
};
use wiremock::ResponseTemplate;

/// `RopRelease`.
const RELEASE: u8 = 0x01;

/// Opening the Inbox's contents table: one row, then either more to come or the end.
fn opened(bookmark: u8) -> ResponseTemplate {
    let mut rops = open_folder_response(OPEN_FOLDER_SLOT);
    rops.extend(get_table_response(0x05, 2, 2));
    rops.extend(set_columns_response(2));
    rops.extend(query_rows_response(
        2,
        bookmark,
        &[contents_row(0x0100_0000_0000_0042, "first", 0, 0)],
    ));
    mapi_ok(execute_body(
        &rops,
        &[LOGON_HANDLE, 0x0000_0001, TABLE_HANDLE],
    ))
}

/// The handle table an `Execute` request carried.
///
/// The body is `Flags`, `RopBufferSize`, then the buffer: `RPC_HEADER_EXT` (8), `RopSize` (2,
/// counting itself), the ROPs, and the handles to the end of the buffer.
fn handles(body: &[u8]) -> Vec<u32> {
    let buffer_size = usize::try_from(u32::from_le_bytes(body[4..8].try_into().unwrap())).unwrap();
    let rop_size = usize::from(u16::from_le_bytes([body[16], body[17]]));
    body[16 + rop_size..8 + buffer_size]
        .chunks_exact(4)
        .map(|handle| u32::from_le_bytes(handle.try_into().unwrap()))
        .collect()
}

/// Reads the Inbox's first row and drops what is left, in a scope of its own.
async fn read_one_and_drop(logon: &mut mapi_client::Logon) {
    let mut rows = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .page_size(1)
        .rows();
    assert!(rows.try_next().await.unwrap().is_some());
}

/// A table dropped part way, or read to its end and never closed, is released by the next request
/// — at its end, after the caller's own ROPs — and by that one only.
#[tokio::test]
async fn a_dropped_table_is_released_by_the_next_request() {
    for bookmark in [BOOKMARK_CURRENT, BOOKMARK_END] {
        let server = MapiServer::start().await;
        server.reply(connect_ok("Alice Example"));
        server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
        server.reply(opened(bookmark));
        server.reply(opened(BOOKMARK_END));
        server.reply(opened(BOOKMARK_END));

        let mut logon = server
            .client()
            .connect()
            .await
            .unwrap()
            .logon()
            .await
            .unwrap();
        read_one_and_drop(&mut logon).await;
        read_one_and_drop(&mut logon).await;
        read_one_and_drop(&mut logon).await;

        let carried = server.rops(3).await;
        let ops = opcodes(&carried);
        assert_eq!(ops.last(), Some(&RELEASE), "{bookmark}: {ops:02X?}");
        let requests = server.requests().await;
        let table = handles(&requests[3].body);
        assert_eq!(
            table.last(),
            Some(&TABLE_HANDLE),
            "{bookmark}: the release names the dropped table: {table:08X?}"
        );
        let next = handles(&requests[4].body);
        assert_eq!(
            next.iter()
                .filter(|handle| **handle == TABLE_HANDLE)
                .count(),
            1,
            "the second table, released once, and the first not again: {next:08X?}"
        );
    }
}

/// A request the server refused unread released nothing, so the release stays queued for the one
/// after it.
#[tokio::test]
async fn a_release_on_a_refused_request_is_carried_by_the_next() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(opened(BOOKMARK_CURRENT));
    server.reply(ResponseTemplate::new(401).append_header("WWW-Authenticate", "Basic"));
    server.reply(opened(BOOKMARK_END));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    read_one_and_drop(&mut logon).await;
    let refused = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await;
    assert!(refused.is_err());
    read_one_and_drop(&mut logon).await;

    let requests = server.requests().await;
    assert_eq!(handles(&requests[3].body).last(), Some(&TABLE_HANDLE));
    assert_eq!(
        handles(&requests[4].body).last(),
        Some(&TABLE_HANDLE),
        "carried again, because the server never saw the first"
    );
}

/// A Session Context replaced since the table was dropped took the table along: the release is
/// not sent into the new one, where the same value may name something else.
#[tokio::test]
async fn a_release_does_not_outlive_its_session_context() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(opened(BOOKMARK_CURRENT));
    server.reply(mapi_response(10, Vec::new()));
    server.reply(mapi_ok(connect_body("Alice Example")));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(opened(BOOKMARK_END));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    read_one_and_drop(&mut logon).await;
    read_one_and_drop(&mut logon).await;
    assert_eq!(logon.reconnects(), 1);

    let requests = server.requests().await;
    assert_eq!(
        handles(&requests[3].body).last(),
        Some(&TABLE_HANDLE),
        "sent to the old context"
    );
    assert!(
        !handles(&requests[6].body).contains(&TABLE_HANDLE),
        "and not to the new one: {:08X?}",
        handles(&requests[6].body)
    );
}

/// A close that never reached the server keeps hold of its table, so the table is still released —
/// by the next request — rather than lost along with the failed close.
#[tokio::test]
async fn a_close_that_never_reached_the_server_still_gets_its_table_released() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(opened(BOOKMARK_CURRENT));
    server.reply(ResponseTemplate::new(401).append_header("WWW-Authenticate", "Basic"));
    server.reply(opened(BOOKMARK_END));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let mut rows = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .page_size(1)
        .rows();
    assert!(rows.try_next().await.unwrap().is_some());
    assert!(rows.close().await.is_err(), "the close was refused unread");
    read_one_and_drop(&mut logon).await;

    let requests = server.requests().await;
    assert_eq!(
        handles(&requests[4].body).last(),
        Some(&TABLE_HANDLE),
        "released by the next request after all"
    );
}

/// A table whose Session Context the server has lost went with it: closing it then has nothing left
/// to do, which is success — so a `collect` whose last page beat the expiry keeps its rows.
#[tokio::test]
async fn closing_a_table_whose_context_was_lost_succeeds() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(opened(BOOKMARK_END));
    server.reply(mapi_response(10, Vec::new()));
    server.reply(mapi_ok(connect_body("Alice Example")));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let rows = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .collect()
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(logon.reconnects(), 1);
}
