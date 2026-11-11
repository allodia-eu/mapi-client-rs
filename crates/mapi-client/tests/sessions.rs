//! A Session Context over time: when it expires, and keeping it alive.
//!
//! The fake server stands in for Exchange; what Exchange itself does with an idle context is
//! measured by `tests/sessions/` in the live suite.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

mod support;

use core::time::Duration;
use std::time::Instant;

use mapi_client::Error;
use support::{MapiServer, connect_ok, mapi_ok, mapi_response};

/// A response carrying `X-ExpirationInfo`, as Exchange sends on everything that names a context.
fn lasting(response: wiremock::ResponseTemplate, milliseconds: u64) -> wiremock::ResponseTemplate {
    response.append_header("X-ExpirationInfo", milliseconds.to_string().as_str())
}

/// The deadline is counted from when the request went out, so it is never later than the server's.
#[tokio::test]
async fn the_deadline_is_the_last_reported_lifetime_from_when_the_request_left() {
    let server = MapiServer::start().await;
    server.reply(lasting(connect_ok("Alice Example"), 300_000));

    let before = Instant::now();
    let connection = server.client().connect().await.unwrap();
    let after = Instant::now();

    let deadline = connection.expires_at().expect("the Connect response said");
    assert!(deadline >= before + Duration::from_mins(5), "{deadline:?}");
    assert!(deadline <= after + Duration::from_mins(5), "{deadline:?}");
}

/// No `X-ExpirationInfo`, no deadline: nothing is invented.
#[tokio::test]
async fn a_server_that_never_says_leaves_no_deadline() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));

    let connection = server.client().connect().await.unwrap();
    assert_eq!(connection.expires_at(), None);
}

/// A `PING` that carries the session's cookies and comes back with `X-ExpirationInfo` moves the
/// deadline — to the lifetime that response gave, not the first one.
///
/// [MS-OXCMAPIHTTP] §3.1.5.3
#[tokio::test]
async fn keeping_alive_pings_with_the_sessions_cookies_and_moves_the_deadline() {
    let server = MapiServer::start().await;
    server.reply(lasting(connect_ok("Alice Example"), 300_000));
    server.reply(lasting(mapi_ok(Vec::new()), 900_000));

    let mut connection = server.client().connect().await.unwrap();
    let first = connection.expires_at().unwrap();
    let before = Instant::now();
    let refreshed = connection.keep_alive().await.unwrap();

    assert_eq!(connection.expires_at(), Some(refreshed));
    assert!(
        refreshed >= before + Duration::from_mins(15),
        "{refreshed:?}"
    );
    assert!(refreshed > first + Duration::from_secs(500));

    let requests = server.requests().await;
    let ping = &requests[1];
    assert_eq!(ping.headers.get("X-RequestType").unwrap(), "PING");
    let cookie = ping.headers.get("Cookie").unwrap().to_str().unwrap();
    assert!(
        cookie.contains("MapiContext=ctx-0001") && cookie.contains("MapiSequence=seq-0001"),
        "{cookie}"
    );
}

/// A successful `PING` without the header is what the endpoint answers when it has no Session
/// Context for those cookies, so it is not a refresh — and the deadline stays where it was.
#[tokio::test]
async fn a_ping_that_does_not_say_it_refreshed_is_not_a_refresh() {
    let server = MapiServer::start().await;
    server.reply(lasting(connect_ok("Alice Example"), 300_000));
    server.reply(mapi_ok(Vec::new()));

    let mut connection = server.client().connect().await.unwrap();
    let deadline = connection.expires_at();
    let error = connection.keep_alive().await.unwrap_err();
    assert!(matches!(error, Error::NotRefreshed), "{error:?}");
    assert_eq!(connection.expires_at(), deadline);
}

/// A refused request carries no expiration and says nothing about the deadline it lacks, so the
/// last one stands.
#[tokio::test]
async fn a_refusal_leaves_the_last_deadline_standing() {
    let server = MapiServer::start().await;
    server.reply(lasting(connect_ok("Alice Example"), 300_000));
    server.reply(mapi_response(7, Vec::new()));

    let mut connection = server.client().connect().await.unwrap();
    let deadline = connection.expires_at();
    assert!(connection.keep_alive().await.is_err());
    assert_eq!(connection.expires_at(), deadline);
}

/// A 200 with no `X-ResponseCode` — a proxy answering for the endpoint — says nothing about the
/// Session Context, so the deadline stays where the last response that did say put it.
#[tokio::test]
async fn a_response_without_a_verdict_does_not_move_the_deadline() {
    let server = MapiServer::start().await;
    server.reply(lasting(connect_ok("Alice Example"), 300_000));
    server.reply(wiremock::ResponseTemplate::new(200).set_body_bytes(Vec::new()));

    let mut connection = server.client().connect().await.unwrap();
    let deadline = connection.expires_at();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(connection.keep_alive().await.is_err());
    assert_eq!(connection.expires_at(), deadline);
}
