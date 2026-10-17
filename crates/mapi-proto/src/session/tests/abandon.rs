//! Giving up on a request: what the session still allows, and what it refuses.

use super::*;

/// The case cancellation produces: a caller drops the future driving a request, so its response
/// never reaches `on_response`. Without `abandon` the session waits for it forever and refuses
/// even the `Disconnect` that would free the server's context.
#[test]
fn an_abandoned_execute_leaves_only_disconnect() {
    let mut session = connected();
    session.execute(RopBatch::new()).unwrap();
    assert!(session.is_awaiting_response());

    assert!(session.abandon(), "a request was in flight");
    assert!(!session.is_awaiting_response());
    assert!(session.is_abandoned());

    for refused in [
        session.execute(RopBatch::new()).unwrap_err(),
        session.begin_ping().unwrap_err(),
    ] {
        assert!(matches!(refused, Error::InvalidState { .. }), "{refused:?}");
        assert!(refused.to_string().contains("abandoned"), "{refused}");
    }

    let request = session.begin_disconnect().unwrap();
    assert_eq!(request.request_type(), RequestType::Disconnect);
    assert_eq!(
        request.headers().get("Cookie"),
        Some("MapiContext=abc"),
        "the Disconnect names the context the abandoned request belonged to"
    );
    session
        .on_response(&ok_headers(), &with_preamble(&[]))
        .unwrap();
    assert!(!session.is_abandoned());
    assert!(!session.is_connected());
}

/// An abandoned `Execute` may have released a table whose columns the session remembers, and the
/// server is free to hand that handle value to the next table it opens. Forgetting every column
/// set is what keeps a session that somehow carried on from decoding rows against the wrong one.
#[test]
fn abandoning_forgets_every_table_the_session_knew() {
    let mut session = connected();
    session
        .table_columns
        .push((ObjectHandle::new(7), vec![PropertyTag::SUBJECT]));
    session.execute(RopBatch::new()).unwrap();

    session.abandon();
    assert!(session.table_columns.is_empty());
}

/// Before a Session Context exists there is no server state to be unsure about, so nothing is
/// lost: the session can try again.
#[test]
fn an_abandoned_connect_or_ping_costs_nothing() {
    let mut session = Session::new();
    session.begin_connect(&dn()).unwrap();
    assert!(session.abandon());
    assert!(!session.is_abandoned());
    session.begin_connect(&dn()).unwrap();
    assert!(session.abandon());

    session.begin_ping().unwrap();
    assert!(session.abandon());
    assert!(!session.is_abandoned());
    session.begin_ping().unwrap();
}

#[test]
fn abandoning_with_nothing_in_flight_changes_nothing() {
    let mut session = connected();
    assert!(!session.abandon());
    assert!(!session.is_abandoned());
    session.execute(RopBatch::new()).unwrap();
}

/// A late response to an abandoned request has nothing to answer, and is refused rather than read
/// as the answer to whatever is sent next.
#[test]
fn a_response_to_an_abandoned_request_is_refused() {
    let mut session = connected();
    session.execute(RopBatch::new()).unwrap();
    session.abandon();

    assert_eq!(
        session.on_response(&ok_headers(), &with_preamble(&[])),
        Err(Error::NoRequestInFlight)
    );
}

/// [MS-OXCMAPIHTTP] §3.1.5.7's reconnect: a `Connect` that carries the old context's cookies, so
/// the server can clean it up. It is how an abandoned context is freed when its `Disconnect` is
/// refused, and a successful one starts over: no abandonment, and no table this session knew.
#[test]
fn a_reconnect_carries_the_old_cookies_and_starts_over() {
    let mut session = connected();
    session
        .table_columns
        .push((ObjectHandle::new(7), vec![PropertyTag::SUBJECT]));
    session.execute(RopBatch::new()).unwrap();
    session.abandon();

    let request = session.begin_reconnect(&dn()).unwrap();
    assert_eq!(request.request_type(), RequestType::Connect);
    assert_eq!(request.headers().get("Cookie"), Some("MapiContext=abc"));

    let mut headers = ok_headers();
    headers.append("Set-Cookie", "MapiContext=def; Path=/; HttpOnly");
    session
        .on_response(&headers, &connect_payload("Spike Test Usr"))
        .unwrap();
    assert!(!session.is_abandoned());
    assert!(session.is_connected());
    assert!(session.table_columns.is_empty());
    assert_eq!(
        session.cookies().header_value().as_deref(),
        Some("MapiContext=def")
    );
    session.execute(RopBatch::new()).unwrap();
}

/// There is nothing to re-establish before the first `Connect`, and two requests at once are
/// refused here as everywhere.
#[test]
fn a_reconnect_needs_a_context_and_an_idle_session() {
    let mut session = Session::new();
    assert!(matches!(
        session.begin_reconnect(&dn()),
        Err(Error::InvalidState { .. })
    ));

    let mut session = connected();
    session.execute(RopBatch::new()).unwrap();
    assert!(matches!(
        session.begin_reconnect(&dn()),
        Err(Error::InvalidState { .. })
    ));
}
