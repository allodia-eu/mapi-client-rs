//! The two failure phases of [MS-OXCMAPIHTTP] §3.1.7, against a server that produces each.
//!
//! §3.1.7.1: a failure "before streaming the request body or while streaming the request body" is
//! answered by resubmitting "the request as-is" on a new HTTP connection, with the same cookies and
//! no new Session Context. §3.1.7.2: a failure "after the entire request ... is streamed" is
//! answered with a new Session Context, because whether the server acted cannot be known.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]

mod support;

use mapi_client::{Delivery, Error, MapiClient, WellKnownFolder};
use support::fault::{Act, FaultServer, Received, mapi_reply};
use support::{
    BOOKMARK_END, LOGON_HANDLE, MapiServer, OPEN_FOLDER_SLOT, TABLE_HANDLE, connect_body,
    connect_ok, contents_row, execute_body, get_table_response, logon_response, mapi_ok,
    open_folder_response, query_rows_response, set_columns_response,
};
use wiremock::ResponseTemplate;

const COOKIES: [&str; 2] = [
    "Set-Cookie: MapiContext=ctx-0001; Path=/mapi",
    "Set-Cookie: MapiSequence=seq-0001; Path=/mapi",
];

/// Opening the Inbox's contents table: one row, and the end of the table.
fn opened() -> Vec<u8> {
    let mut rops = open_folder_response(OPEN_FOLDER_SLOT);
    rops.extend(get_table_response(0x05, 2, 1));
    rops.extend(set_columns_response(2));
    rops.extend(query_rows_response(
        2,
        BOOKMARK_END,
        &[contents_row(0x0100_0000_0000_0042, "first", 0, 0)],
    ));
    execute_body(&rops, &[LOGON_HANDLE, 0x0000_0001, TABLE_HANDLE])
}

/// A server that has a Session Context and a logon for the client that comes next.
fn logged_on(server: &FaultServer) -> MapiClient {
    server.then(Act::Reply(mapi_reply(
        &connect_body("Alice Example"),
        &COOKIES,
    )));
    server.then(Act::Reply(mapi_reply(
        &execute_body(&logon_response(0), &[LOGON_HANDLE]),
        &[],
    )));
    MapiServer::builder_for(server.endpoint()).build().unwrap()
}

/// The counter half of `X-RequestId`, which goes up by one per request.
fn counter(request: &Received) -> u64 {
    let id = request.header("X-RequestId").unwrap();
    id.rsplit_once(':').unwrap().1.parse().unwrap()
}

/// §3.1.7.1. With the endpoint gone, the request cannot be sent at all; the client tries it once
/// more on a fresh connection, as the section has it, and reports that nothing left. The
/// connection is untouched: once the endpoint is back, the same request goes out — the next
/// counter value, the same cookies — with no new Session Context in between.
#[tokio::test]
async fn a_request_that_never_left_is_sent_as_it_was_once_the_server_is_back() {
    let mut server = FaultServer::start().await;
    let client = logged_on(&server);
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();

    server.stop().await;
    let error = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Connect { .. }), "{error:?}");
    assert_eq!(error.delivery(), Delivery::NotSent);

    server.restart().await;
    server.then(Act::Reply(mapi_reply(&opened(), &[])));
    let row = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap();
    assert!(row.is_some(), "the connection is as usable as it was");
    assert_eq!(logon.reconnects(), 0, "no new Session Context");

    let received = server.received();
    assert_eq!(
        received.len(),
        3,
        "Connect, logon, and the read once it could be sent"
    );
    assert_eq!(counter(&received[2]), counter(&received[1]) + 1, "as-is");
    let cookie = received[2].header("Cookie").unwrap();
    assert!(cookie.contains("MapiContext=ctx-0001"), "{cookie}");
}

/// §3.1.7.2. The server reads the whole request and hangs up, so whether it acted is unknowable:
/// the connection refuses to send anything else into that Session Context, and a reconnect —
/// passing its cookies — is what makes it usable again.
#[tokio::test]
async fn a_request_sent_whole_and_never_answered_leaves_the_outcome_unknown() {
    for cut in [
        Act::HangUp,
        Act::Partial(b"HTTP/1.1 200 OK\r\nContent-Length: 400\r\n\r\nPROCESSING\r\n".to_vec()),
    ] {
        let server = FaultServer::start().await;
        let client = logged_on(&server);
        let mut logon = client.connect().await.unwrap().logon().await.unwrap();

        server.then(cut.clone());
        let error = logon
            .well_known(WellKnownFolder::Inbox)
            .unwrap()
            .contents()
            .rows()
            .try_next()
            .await
            .unwrap_err();
        assert_eq!(error.delivery(), Delivery::Unknown, "{cut:?}: {error:?}");

        let refused = logon
            .well_known(WellKnownFolder::Inbox)
            .unwrap()
            .contents()
            .rows()
            .try_next()
            .await
            .unwrap_err();
        assert!(matches!(refused, Error::Poisoned { .. }), "{refused:?}");
        assert_eq!(
            server.received().len(),
            3,
            "nothing more was sent into that context"
        );

        server.then(Act::Reply(mapi_reply(
            &connect_body("Alice Example"),
            &[
                "Set-Cookie: MapiContext=ctx-0002; Path=/mapi",
                "Set-Cookie: MapiSequence=seq-0002; Path=/mapi",
            ],
        )));
        server.then(Act::Reply(mapi_reply(
            &execute_body(&logon_response(0), &[LOGON_HANDLE]),
            &[],
        )));
        server.then(Act::Reply(mapi_reply(&opened(), &[])));
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

        let received = server.received();
        assert_eq!(
            received[3].header("X-RequestType").as_deref(),
            Some("Connect")
        );
        assert!(
            received[3].header("Cookie").unwrap().contains("ctx-0001"),
            "the reconnect names the context it replaces"
        );
    }
}

/// A 401 is the server refusing the request before the protocol saw it, so nothing about the
/// Session Context moved: the connection stays usable, and the request goes out again as the same
/// request rather than the next one.
#[tokio::test]
async fn a_request_refused_before_the_protocol_leaves_the_connection_usable() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(ResponseTemplate::new(401).append_header("WWW-Authenticate", "Basic"));
    server.reply(mapi_ok(opened()));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let error = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Unauthorized { .. }), "{error:?}");
    assert_eq!(error.delivery(), Delivery::Refused);

    let row = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap();
    assert!(row.is_some());

    let requests = server.requests().await;
    assert_eq!(
        requests[2].headers.get("X-RequestId"),
        requests[3].headers.get("X-RequestId"),
        "the refused request, sent again, is the same request"
    );
}

/// A request the server accepted and then failed after `DONE` — [MS-OXCMAPIHTTP] §3.2.5.2 — may
/// have run any of its ROPs: its outcome is unknown, and nothing more is sent into that Session
/// Context until a reconnect replaces it.
#[tokio::test]
async fn a_request_failed_after_it_was_accepted_poisons_the_connection() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(
        ResponseTemplate::new(200)
            .append_header("X-ResponseCode", "0")
            .set_body_bytes(b"PROCESSING\r\nDONE\r\nX-ResponseCode: 1\r\n\r\n".to_vec()),
    );

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let error = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap_err();
    assert_eq!(error.delivery(), Delivery::Unknown, "{error:?}");
    let refused = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap_err();
    assert!(matches!(refused, Error::Poisoned { .. }), "{refused:?}");
    assert_eq!(server.requests().await.len(), 3);
}
