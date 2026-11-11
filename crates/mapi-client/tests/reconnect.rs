//! A Session Context the server has lost, and the new one that replaces it.
//!
//! [MS-OXCMAPIHTTP] §3.2.5.6 has the client "reconnect and establish a new Session Context" when
//! the server answers `X-ResponseCode` 10, and these are the fake-server half of what that means:
//! which request is sent again, which object refuses to go on, and which cookies go where. What
//! Exchange itself answers is measured by the live suite's `lifetime` tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use core::time::Duration;

use mapi_client::{Error, NamedProperty, ResponseCode, WellKnownFolder};
use support::{
    BOOKMARK_CURRENT, BOOKMARK_END, Bytes, LOGON_HANDLE, MapiServer, OPEN_FOLDER_SLOT,
    TABLE_HANDLE, connect_body, connect_ok, contents_row, disconnect_body, execute_body,
    get_table_response, logon_response, mapi_ok, mapi_response, open_folder_response,
    query_rows_response, set_columns_response,
};
use wiremock::ResponseTemplate;

/// The logon handle the replacement Session Context hands out, different from the first one's so
/// that a request still carrying the old value would show.
const NEW_LOGON_HANDLE: u32 = 0x0000_0007;

/// A `Connect` that creates a second Session Context, with cookies of its own.
fn reconnected() -> ResponseTemplate {
    mapi_ok(connect_body("Alice Example"))
        .append_header("Set-Cookie", "MapiContext=ctx-0002; Path=/mapi; HttpOnly")
        .append_header("Set-Cookie", "MapiSequence=seq-0002; Path=/mapi; HttpOnly")
}

/// The answer Exchange gives a request naming a Session Context it does not have.
fn lost(code: u32) -> ResponseTemplate {
    mapi_response(
        code,
        b"Microsoft.Exchange.MapiHttp.ContextNotFoundException: Unable to create session context"
            .to_vec(),
    )
}

/// Opening the Inbox's contents table: one row, and the end of the table.
fn opened(logon: u32, bookmark: u8) -> ResponseTemplate {
    let mut rops = open_folder_response(OPEN_FOLDER_SLOT);
    rops.extend(get_table_response(0x05, 2, 2));
    rops.extend(set_columns_response(2));
    rops.extend(query_rows_response(
        2,
        bookmark,
        &[contents_row(0x0100_0000_0000_0042, "first", 0, 0)],
    ));
    mapi_ok(execute_body(&rops, &[logon, 0x0000_0001, TABLE_HANDLE]))
}

/// The first handle in an `Execute` request's handle table, which is where the logon goes.
fn first_handle(body: &[u8]) -> u32 {
    let rop_size = usize::from(u16::from_le_bytes([body[16], body[17]]));
    let at = 16 + rop_size;
    u32::from_le_bytes(body[at..at + 4].try_into().unwrap())
}

fn cookie(request: &wiremock::Request) -> String {
    request
        .headers
        .get("Cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

/// Every code that means "no such Session Context" is answered the same way: a `Connect` carrying
/// the old cookies, the logon again, and the request again — aimed at the new logon, and otherwise
/// the same bytes.
#[tokio::test]
async fn a_request_the_server_had_no_context_for_is_sent_again_on_a_new_one() {
    for code in [10, 6, 13] {
        let server = MapiServer::start().await;
        server.reply(connect_ok("Alice Example"));
        server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
        server.reply(lost(code));
        server.reply(reconnected());
        server.reply_ok(execute_body(&logon_response(0), &[NEW_LOGON_HANDLE]));
        server.reply(opened(NEW_LOGON_HANDLE, BOOKMARK_END));

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
            .page_size(5)
            .rows();
        let mut rows = rows;
        let row = rows.try_next().await.unwrap().expect("a row");
        assert_eq!(
            row.message_id().map(mapi_client::MessageId::as_u64),
            Some(0x0100_0000_0000_0042)
        );
        drop(rows);
        assert_eq!(logon.reconnects(), 1, "code {code}");

        let requests = server.requests().await;
        assert_eq!(requests.len(), 6, "code {code}");
        assert_eq!(requests[3].headers.get("X-RequestType").unwrap(), "Connect");
        let passed = cookie(&requests[3]);
        assert!(
            passed.contains("MapiContext=ctx-0001") && passed.contains("MapiSequence=seq-0001"),
            "the reconnect passes the old context's cookies: {passed}"
        );
        assert!(
            cookie(&requests[5]).contains("MapiContext=ctx-0002")
                && !cookie(&requests[5]).contains("ctx-0001"),
            "and the new context's cookies replace them"
        );

        assert_eq!(server.rops(2).await, server.rops(5).await, "the same ROPs");
        assert_eq!(first_handle(&requests[2].body), LOGON_HANDLE);
        assert_eq!(
            first_handle(&requests[5].body),
            NEW_LOGON_HANDLE,
            "aimed at the new context's logon"
        );
    }
}

/// [MS-OXCMAPIHTTP] §3.2.5.2 lets a server fail a request after `DONE`, with a second
/// `X-ResponseCode` among the headers that follow it. That verdict stands, and the context is lost
/// all the same — but the request had been accepted, so it is not sent again: what ran of it is not
/// known. The next request re-establishes the context.
#[tokio::test]
async fn a_context_lost_after_done_is_not_sent_again_but_is_reconnected() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(
        ResponseTemplate::new(200)
            .append_header("X-ResponseCode", "0")
            .append_header("Content-Type", "application/mapi-http")
            .set_body_bytes(b"PROCESSING\r\nDONE\r\nX-ResponseCode: 10\r\n\r\n".to_vec()),
    );
    server.reply(reconnected());
    server.reply_ok(execute_body(&logon_response(0), &[NEW_LOGON_HANDLE]));
    server.reply(opened(NEW_LOGON_HANDLE, BOOKMARK_END));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let failed = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap_err();
    assert!(
        matches!(
            failed,
            Error::Protocol(mapi_proto::Error::FailedAfterDone {
                code: ResponseCode::CONTEXT_NOT_FOUND,
                ..
            })
        ),
        "{failed:?}"
    );
    assert_eq!(logon.reconnects(), 0, "nothing sent again");

    let row = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap();
    assert!(row.is_some());
    assert_eq!(logon.reconnects(), 1);
    assert_eq!(server.requests().await.len(), 6);
}

/// A page read binds the table, which the new Session Context never issued, so it is not sent
/// again: the read fails as `SessionLost`, the `Rows` refuses to go on, and the logon — already
/// re-established — reads the folder afresh without another `Connect`.
#[tokio::test]
async fn a_table_part_way_through_does_not_carry_over() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(opened(LOGON_HANDLE, BOOKMARK_CURRENT));
    server.reply(lost(10));
    server.reply(reconnected());
    server.reply_ok(execute_body(&logon_response(0), &[NEW_LOGON_HANDLE]));
    server.reply(opened(NEW_LOGON_HANDLE, BOOKMARK_END));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    {
        let mut rows = logon
            .well_known(WellKnownFolder::Inbox)
            .unwrap()
            .contents()
            .page_size(1)
            .rows();
        assert!(rows.try_next().await.unwrap().is_some());

        let error = rows.try_next().await.unwrap_err();
        assert!(
            matches!(
                error,
                Error::SessionLost {
                    code: ResponseCode::CONTEXT_NOT_FOUND,
                    ..
                }
            ),
            "{error:?}"
        );
        let refused = rows.try_next().await.unwrap_err();
        assert!(
            matches!(refused, Error::SessionReplaced { .. }),
            "{refused:?}"
        );
        rows.close().await.unwrap();
    }
    assert_eq!(logon.reconnects(), 1);

    let again = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap();
    assert!(again.is_some());

    let requests = server.requests().await;
    assert_eq!(
        requests.len(),
        7,
        "the stale table is neither read nor released, and no second reconnect happens"
    );
    assert_eq!(first_handle(&requests[6].body), NEW_LOGON_HANDLE);
}

/// A `PING` for a context that is gone is answered 10 — measured against Exchange Server SE
/// `15.02.2562.056` — and keeping it alive then means replacing it, which starts a timer of its
/// own.
#[tokio::test]
async fn keeping_a_lost_context_alive_replaces_it() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(lost(10));
    server.reply(reconnected().append_header("X-ExpirationInfo", "300000"));
    server.reply(
        mapi_ok(execute_body(&logon_response(0), &[NEW_LOGON_HANDLE]))
            .append_header("X-ExpirationInfo", "900000"),
    );

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let before = std::time::Instant::now();
    let deadline = logon.keep_alive().await.unwrap();
    assert!(deadline >= before + Duration::from_mins(15), "{deadline:?}");
    assert_eq!(logon.reconnects(), 1);
}

/// Disconnecting a context the server no longer has has nothing left to do, which is success.
#[tokio::test]
async fn disconnecting_a_lost_context_succeeds() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply(lost(10));

    let connection = server.client().connect().await.unwrap();
    connection.disconnect().await.unwrap();
    assert_eq!(server.requests().await.len(), 2);
}

/// A reconnect the server refuses leaves the connection to try again on its next request, still
/// passing the cookies of the context it is replacing.
#[tokio::test]
async fn a_reconnect_that_fails_is_tried_again_next_time() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(lost(10));
    server.reply(ResponseTemplate::new(503));
    server.reply(reconnected());
    server.reply_ok(execute_body(&logon_response(0), &[NEW_LOGON_HANDLE]));
    server.reply(opened(NEW_LOGON_HANDLE, BOOKMARK_END));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let first = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await;
    assert!(
        matches!(first, Err(Error::Http { status: 503, .. })),
        "{first:?}"
    );

    let second = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap();
    assert!(second.is_some());
    let requests = server.requests().await;
    assert_eq!(requests.len(), 7);
    assert!(
        cookie(&requests[4]).contains("ctx-0001"),
        "the second attempt still names it"
    );
}

/// A dropped request poisons the connection, and an explicit reconnect is the remedy
/// [MS-OXCMAPIHTTP] §3.1.7.2 gives for a response that never arrived: afterwards it is usable.
#[tokio::test]
async fn reconnecting_makes_a_poisoned_connection_usable() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(mapi_ok(Vec::new()).set_delay(Duration::from_millis(500)));
    server.reply(reconnected());
    server.reply_ok(execute_body(&logon_response(0), &[NEW_LOGON_HANDLE]));
    server.reply(opened(NEW_LOGON_HANDLE, BOOKMARK_END));
    server.reply_ok(disconnect_body());

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    {
        let mut rows = logon
            .well_known(WellKnownFolder::Inbox)
            .unwrap()
            .contents()
            .rows();
        let dropped = tokio::time::timeout(Duration::from_millis(100), rows.try_next()).await;
        assert!(dropped.is_err());
    }
    logon.reconnect().await.unwrap();
    let row = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap();
    assert!(row.is_some());
    logon.disconnect().await.unwrap();
}

/// `RopGetPropertyIdsFromNames` answering one id.
fn property_ids(id: u16) -> Vec<u8> {
    Bytes::new().u8(0x56).u8(0).u32(0).u16(1).u16(id).done()
}

/// A logon response naming another mailbox instance: the GUID at its fixed offset changed.
fn logon_of_another_mailbox() -> Vec<u8> {
    let mut response = logon_response(0);
    // RopId, slot, ReturnValue, LogonFlags, thirteen folder ids, ResponseFlags.
    let at = 1 + 1 + 4 + 1 + 13 * 8 + 1;
    response[at..at + 16].copy_from_slice(&[0xEE; 16]);
    response
}

/// Named-property ids belong to the store ([MS-OXCPRPT] §3.1.2), so a reconnect to the same mailbox
/// keeps them — and one that logs on to another instance of it asks again rather than reuse ids
/// that store never issued.
#[tokio::test]
async fn named_properties_survive_a_reconnect_only_to_the_same_mailbox() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply_ok(execute_body(&property_ids(0x8001), &[LOGON_HANDLE]));
    server.reply(reconnected());
    server.reply_ok(execute_body(&logon_response(0), &[NEW_LOGON_HANDLE]));
    server.reply(reconnected());
    server.reply_ok(execute_body(
        &logon_of_another_mailbox(),
        &[NEW_LOGON_HANDLE],
    ));
    server.reply_ok(execute_body(&property_ids(0x8123), &[NEW_LOGON_HANDLE]));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let wanted = [NamedProperty::AppointmentStartWhole];
    let first = logon
        .resolve_names(wanted)
        .await
        .unwrap()
        .tag_of(NamedProperty::AppointmentStartWhole);

    logon.reconnect().await.unwrap();
    let same = logon
        .resolve_names(wanted)
        .await
        .unwrap()
        .tag_of(NamedProperty::AppointmentStartWhole);
    assert_eq!(same, first, "answered from the cache");
    assert_eq!(
        server.requests().await.len(),
        5,
        "nothing asked after the first reconnect"
    );

    logon.reconnect().await.unwrap();
    let moved = logon.resolve_names(wanted).await.unwrap();
    assert_eq!(moved.store().as_bytes(), &[0xEE; 16]);
    assert_ne!(moved.tag_of(NamedProperty::AppointmentStartWhole), first);
    assert_eq!(
        server.requests().await.len(),
        8,
        "asked again of the new store"
    );
}
