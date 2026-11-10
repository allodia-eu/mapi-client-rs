//! A response read as it arrives: the keep-alives a long request sends, and the bound on silence
//! they keep from tripping.
//!
//! [MS-OXCMAPIHTTP] §3.1.5.6: the client "can abandon a request if no periodic keep-alive response
//! is received within a reasonable amount of time". The fault server sends a response a piece at a
//! time, with waits between, which is what Exchange does with a request it holds open.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]

mod support;

use core::time::Duration;
use std::sync::{Arc, Mutex};

use mapi_client::{Delivery, Error, Exchange, MetaTag, Observer, RequestType, WellKnownFolder};
use support::fault::{Act, FaultServer, mapi_reply};
use support::{
    BOOKMARK_END, LOGON_HANDLE, MapiServer, OPEN_FOLDER_SLOT, TABLE_HANDLE, connect_body,
    contents_row, execute_body, get_table_response, logon_response, open_folder_response,
    query_rows_response, set_columns_response,
};

/// Every meta-tag the client was told of, as it was told.
#[derive(Debug, Default)]
struct Tags(Mutex<Vec<(RequestType, MetaTag)>>);

impl Observer for Tags {
    fn observe(&self, _: &Exchange<'_>) {}

    fn meta_tag(&self, request: RequestType, tag: MetaTag) {
        self.0.lock().unwrap().push((request, tag));
    }
}

const COOKIES: [&str; 2] = [
    "Set-Cookie: MapiContext=ctx-0001; Path=/mapi",
    "Set-Cookie: MapiSequence=seq-0001; Path=/mapi",
];

/// The opening of the Inbox's contents table, as a body.
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

/// That opening, sent the way a long request is: `PROCESSING` at once, then `PENDING` after each
/// wait, then `DONE` and the body.
fn slowly(waits: &[u64]) -> Act {
    let mut pieces = vec![(Duration::ZERO, b"PROCESSING\r\n".to_vec())];
    let (last, keep_alives) = waits.split_last().unwrap();
    for wait in keep_alives {
        pieces.push((Duration::from_millis(*wait), b"PENDING\r\n".to_vec()));
    }
    let mut done = b"DONE\r\nX-ElapsedTime: 1\r\n\r\n".to_vec();
    done.extend(opened());
    pieces.push((Duration::from_millis(*last), done));
    Act::Stream(pieces)
}

/// A server with a Session Context and a logon for the next client, and that client.
fn logged_on(
    server: &FaultServer,
    configure: impl FnOnce(mapi_client::MapiClientBuilder) -> mapi_client::MapiClientBuilder,
) -> mapi_client::MapiClient {
    server.then(Act::Reply(mapi_reply(
        &connect_body("Alice Example"),
        &COOKIES,
    )));
    server.then(Act::Reply(mapi_reply(
        &execute_body(&logon_response(0), &[LOGON_HANDLE]),
        &[],
    )));
    configure(MapiServer::builder_for(server.endpoint()))
        .build()
        .unwrap()
}

/// Five keep-alives, each inside the bound on silence, carry a request well past it — with no
/// bound on the whole exchange at all — and each one is told to the observer as it arrives.
#[tokio::test]
async fn keep_alives_carry_a_slow_request_past_the_bound_on_silence() {
    let tags = Arc::new(Tags::default());
    let server = FaultServer::start().await;
    let client = logged_on(&server, |builder| {
        builder
            .stall_timeout(Duration::from_millis(500))
            .no_timeout()
            .observer(Arc::clone(&tags))
    });
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();
    tags.0.lock().unwrap().clear();

    server.then(slowly(&[250, 250, 250, 250, 250, 250]));
    let row = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap();
    assert!(
        row.is_some(),
        "a request three times the bound on silence, alive throughout"
    );

    let seen: Vec<MetaTag> = tags.0.lock().unwrap().iter().map(|(_, tag)| *tag).collect();
    let mut expected = vec![MetaTag::Processing];
    expected.extend([MetaTag::Pending; 5]);
    expected.push(MetaTag::Done);
    assert_eq!(seen, expected);
    assert!(
        tags.0
            .lock()
            .unwrap()
            .iter()
            .all(|(request, _)| *request == RequestType::Execute)
    );
}

/// A response that goes quiet for longer than the bound is called dead, however recently it last
/// spoke: it was sent and never answered, so the outcome is unknown and the connection poisoned.
#[tokio::test]
async fn a_response_that_goes_quiet_is_abandoned() {
    let server = FaultServer::start().await;
    let client = logged_on(&server, |builder| {
        builder.stall_timeout(Duration::from_millis(300))
    });
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();

    server.then(slowly(&[100, 100, 1_000]));
    let error = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::Timeout { after, .. } if after == Duration::from_millis(300)),
        "the bound that elapsed is the one on silence: {error:?}"
    );
    assert_eq!(error.delivery(), Delivery::Unknown);
    let refused = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap_err();
    assert!(matches!(refused, Error::Poisoned { .. }), "{refused:?}");
}

/// The bound on the whole exchange still holds when one is set: keep-alives restart the clock on
/// silence, not the one on time.
#[tokio::test]
async fn keep_alives_do_not_extend_the_bound_on_the_whole_exchange() {
    let server = FaultServer::start().await;
    let client = logged_on(&server, |builder| {
        builder
            .stall_timeout(Duration::from_millis(500))
            .timeout(Duration::from_millis(800))
    });
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();

    server.then(slowly(&[200, 200, 200, 200, 200, 200, 200]));
    let error = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows()
        .try_next()
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::Timeout { after, .. } if after == Duration::from_millis(800)),
        "the bound that elapsed is the whole exchange's: {error:?}"
    );
}
