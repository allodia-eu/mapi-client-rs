use super::*;
use crate::oxcdata::{FolderId, HIERARCHY_COLUMNS, PropertyTag, TableString};
use crate::rop::{FolderDepth, WellKnownFolder};
use crate::testing::{
    connect_failure_payload, connect_payload, execute_payload, logon_response, ok_headers,
    query_rows_response, with_preamble,
};
use crate::wire::Writer;
use crate::{ErrorCode, Headers, RopId};

fn dn() -> LegacyDn {
    LegacyDn::new("/o=First/ou=Exchange Administrative Group/cn=alice").unwrap()
}

/// Drives a session to the point where a Session Context exists.
fn connected() -> Session {
    let mut session = Session::new();
    session.begin_connect(&dn()).unwrap();

    let mut headers = ok_headers();
    headers.append("Set-Cookie", "MapiContext=abc; Path=/; HttpOnly");
    session
        .on_response(&headers, &connect_payload("Spike Test Usr"))
        .unwrap();
    session
}

#[test]
fn a_connect_request_carries_the_headers_the_protocol_requires() {
    let mut session = Session::new();
    let request = session.begin_connect(&dn()).unwrap();

    assert_eq!(request.request_type(), RequestType::Connect);
    assert_eq!(
        request.headers().get("Content-Type"),
        Some("application/mapi-http")
    );
    assert_eq!(request.headers().get("X-RequestType"), Some("Connect"));
    assert!(request.headers().get("X-ClientApplication").is_some());
    assert!(request.headers().get("X-ClientInfo").is_some());
    assert_eq!(request.headers().get("Cookie"), None, "no context yet");
    assert!(request.body().starts_with(b"/o=First"));
    assert!(session.is_awaiting_response());
    assert!(!session.is_connected());
}

/// The `X-RequestId` counter increases on every request while its GUID stays put.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.2
#[test]
fn the_request_id_counter_advances_and_its_guid_does_not() {
    let mut session = Session::builder()
        .request_guid("{11111111-2222-3333-4444-555555555555}")
        .client_application("Outlook/15.00.0847.4040")
        .client_info("{11111111-2222-3333-4444-555555555555}:7")
        .build();

    let first = session.begin_ping().unwrap();
    session.on_response(&ok_headers(), b"").unwrap();
    let second = session.begin_ping().unwrap();

    assert_eq!(
        first.headers().get("X-RequestId"),
        Some("{11111111-2222-3333-4444-555555555555}:1")
    );
    assert_eq!(
        second.headers().get("X-RequestId"),
        Some("{11111111-2222-3333-4444-555555555555}:2")
    );
    assert_eq!(
        second.headers().get("X-ClientInfo"),
        Some("{11111111-2222-3333-4444-555555555555}:7")
    );
}

#[test]
fn connecting_records_the_session_context_and_echoes_its_cookies() {
    let mut session = connected();
    assert!(session.is_connected());
    assert!(!session.is_awaiting_response());
    assert_eq!(session.cookies().cookies().len(), 1);

    let request = session.execute(RopBatch::new()).unwrap();
    assert_eq!(request.headers().get("Cookie"), Some("MapiContext=abc"));
}

#[test]
fn a_connect_outcome_reports_what_the_server_said() {
    let mut session = Session::new();
    session.begin_connect(&dn()).unwrap();
    let outcome = session
        .on_response(&ok_headers(), &connect_payload("Spike Test Usr"))
        .unwrap();

    let Outcome::Connected(connected) = outcome else {
        panic!("expected Connected, got {outcome:?}");
    };
    assert_eq!(connected.display_name(), "Spike Test Usr");
    assert!(connected.dn_prefix().starts_with("/o="));
    assert_eq!(connected.polls_max(), 60_000);
    assert_eq!(connected.retry_count(), 3);
    assert_eq!(connected.retry_delay(), 1_000);
}

/// `UnknownUser` reads like an authentication failure, so the error names the distinguished name
/// that failed to map — the exact omission that cost an afternoon during the spike.
#[test]
fn a_refused_connect_names_the_distinguished_name() {
    let mut session = Session::new();
    session.begin_connect(&dn()).unwrap();

    let error = session
        .on_response(
            &ok_headers(),
            &connect_failure_payload(ErrorCode::UNKNOWN_USER.as_u32()),
        )
        .unwrap_err();

    assert_eq!(
        error,
        Error::ConnectFailed {
            status: 0,
            code: ErrorCode::UNKNOWN_USER,
            user_dn: dn()
        }
    );
    assert!(error.to_string().contains("/o=First"));
    assert!(!session.is_connected());
}

/// A non-zero `StatusCode` means the body stops before `ErrorCode`, so the code is `Success` for
/// want of anything else. Reporting only that would say "Connect refused: Success", which is the
/// least useful sentence available — the status has to come along.
///
/// [MS-OXCMAPIHTTP] §2.2.4.1.3 — `Connect` failure response body
#[test]
fn a_connect_refused_before_its_body_reports_the_status_not_a_bare_success() {
    let mut session = Session::new();
    session.begin_connect(&dn()).unwrap();

    let mut body = Writer::new();
    body.u32(0x0000_000A);
    let error = session
        .on_response(&ok_headers(), &with_preamble(&body.finish()))
        .unwrap_err();

    assert_eq!(
        error,
        Error::ConnectFailed {
            status: 0x0000_000A,
            code: ErrorCode::SUCCESS,
            user_dn: dn()
        }
    );
    assert!(error.to_string().contains("0x0000000A"));
}

#[test]
fn a_logon_round_trip_yields_folder_ids_and_a_handle() {
    let mut session = connected();

    let mut batch = RopBatch::new();
    let logon_slot = batch.logon(&dn());
    session.execute(batch).unwrap();

    let payload = execute_payload(&logon_response(0), &[ObjectHandle::new(0x2A)]);
    let outcome = session.on_response(&ok_headers(), &payload).unwrap();

    let Outcome::Executed(execution) = outcome else {
        panic!("expected Executed, got {outcome:?}");
    };
    assert_eq!(execution.handle(logon_slot), Some(ObjectHandle::new(0x2A)));
    assert_eq!(execution.responses().len(), 1);
    assert!(execution.failure().is_none());
    assert_eq!(
        execution
            .logon()
            .and_then(|logon| logon.folder(WellKnownFolder::Inbox)),
        Some(FolderId::new(0x0100_0000_0000_0004))
    );
}

/// The four-ROP chain in one `Execute`, with the rows decoded against the columns the same batch
/// set — the caller never handles a column set or a handle index.
#[test]
fn a_folder_walk_is_one_round_trip() {
    let mut session = connected();

    let mut batch = RopBatch::new();
    let logon = batch.bind(ObjectHandle::new(0x2A));
    let folder = batch.open_folder(logon, FolderId::new(0x0D00_0000_0000_0001));
    let table = batch.hierarchy_table(folder, FolderDepth::Immediate);
    batch
        .set_columns(table, &HIERARCHY_COLUMNS)
        .query_rows(table, 50);
    let request = session.execute(batch).unwrap();
    assert_eq!(request.request_type(), RequestType::Execute);

    let mut rops = Writer::new();
    rops.u8(RopId::OPEN_FOLDER.as_u8()).u8(1).u32(0).u8(0).u8(0);
    rops.u8(RopId::GET_HIERARCHY_TABLE.as_u8())
        .u8(2)
        .u32(0)
        .u32(2);
    rops.u8(RopId::SET_COLUMNS.as_u8()).u8(2).u32(0).u8(0);
    rops.bytes(&query_rows_response(
        2,
        &[
            (0x0D00_0000_0000_0011, "Inbox"),
            (0x0D00_0000_0000_0022, "Sent Items"),
        ],
    ));
    let payload = execute_payload(
        &rops.finish(),
        &[
            ObjectHandle::new(0x2A),
            ObjectHandle::new(0x2B),
            ObjectHandle::new(0x2C),
        ],
    );

    let Outcome::Executed(execution) = session.on_response(&ok_headers(), &payload).unwrap() else {
        panic!("expected Executed");
    };
    let page = execution.rows().unwrap();
    assert_eq!(page.rows().len(), 2);
    assert_eq!(
        page.rows()
            .first()
            .and_then(|row| row.string(PropertyTag::DISPLAY_NAME))
            .map(TableString::as_str),
        Some("Inbox")
    );
    assert_eq!(execution.handle(table), Some(ObjectHandle::new(0x2C)));
}

/// Paging: the second `Execute` sends only `RopQueryRows`, and the rows still decode because the
/// session remembers which column set belongs to that table handle.
#[test]
fn a_tables_column_set_survives_into_the_next_round_trip() {
    let mut session = connected();

    let mut batch = RopBatch::new();
    let table = batch.bind(ObjectHandle::new(0x2C));
    batch
        .set_columns(table, &HIERARCHY_COLUMNS)
        .query_rows(table, 1);
    session.execute(batch).unwrap();

    let mut rops = Writer::new();
    rops.u8(RopId::SET_COLUMNS.as_u8()).u8(0).u32(0).u8(0);
    rops.bytes(&query_rows_response(0, &[(0x11, "Inbox")]));
    session
        .on_response(
            &ok_headers(),
            &execute_payload(&rops.finish(), &[ObjectHandle::new(0x2C)]),
        )
        .unwrap();

    // Second round trip: no RopSetColumns at all.
    let mut batch = RopBatch::new();
    let table = batch.bind(ObjectHandle::new(0x2C));
    batch.query_rows(table, 1);
    session.execute(batch).unwrap();

    let payload = execute_payload(
        &query_rows_response(0, &[(0x22, "Sent Items")]),
        &[ObjectHandle::new(0x2C)],
    );
    let Outcome::Executed(execution) = session.on_response(&ok_headers(), &payload).unwrap() else {
        panic!("expected Executed");
    };
    assert_eq!(
        execution
            .rows()
            .and_then(|page| page.rows().first())
            .and_then(|row| row.string(PropertyTag::DISPLAY_NAME))
            .map(TableString::as_str),
        Some("Sent Items")
    );
}

/// A released handle value is the server's to hand out again. If the session kept its column set,
/// the next table given that same value would decode its rows against the previous table's
/// columns — silently, as plausible-looking wrong values rather than as an error.
#[test]
fn releasing_a_table_forgets_the_columns_that_belonged_to_it() {
    let mut session = connected();

    // One: a table on handle 0x2C is given a column set, which the session records.
    let mut batch = RopBatch::new();
    let table = batch.bind(ObjectHandle::new(0x2C));
    batch.set_columns(table, &HIERARCHY_COLUMNS);
    session.execute(batch).unwrap();

    let mut rops = Writer::new();
    rops.u8(RopId::SET_COLUMNS.as_u8()).u8(0).u32(0).u8(0);
    session
        .on_response(
            &ok_headers(),
            &execute_payload(&rops.finish(), &[ObjectHandle::new(0x2C)]),
        )
        .unwrap();

    // Two: the table is released. RopRelease has no response buffer, and the server empties the
    // slot it held. [MS-OXCROPS] §2.2.15.3
    let mut batch = RopBatch::new();
    let table = batch.bind(ObjectHandle::new(0x2C));
    batch.release(table);
    session.execute(batch).unwrap();
    session
        .on_response(&ok_headers(), &execute_payload(&[], &[ObjectHandle::NONE]))
        .unwrap();

    // Three: the server hands 0x2C back out for a different table, and no RopSetColumns has been
    // sent for it.
    let mut batch = RopBatch::new();
    let recycled = batch.bind(ObjectHandle::new(0x2C));
    batch.query_rows(recycled, 1);
    session.execute(batch).unwrap();

    assert_eq!(
        session.on_response(
            &ok_headers(),
            &execute_payload(
                &query_rows_response(0, &[(0x11, "Inbox")]),
                &[ObjectHandle::new(0x2C)],
            ),
        ),
        Err(Error::UnknownColumns { handle_index: 0 }),
        "a stale column set must not be reused for a recycled handle"
    );
}

#[test]
fn a_failing_rop_does_not_fail_the_execute() {
    let mut session = connected();
    let mut batch = RopBatch::new();
    let logon = batch.bind(ObjectHandle::new(0x2A));
    batch.open_folder(logon, FolderId::new(1));
    session.execute(batch).unwrap();

    let mut rops = Writer::new();
    rops.u8(RopId::OPEN_FOLDER.as_u8())
        .u8(1)
        .u32(ErrorCode::NOT_FOUND.as_u32());
    let payload = execute_payload(
        &rops.finish(),
        &[ObjectHandle::new(0x2A), ObjectHandle::NONE],
    );

    let Outcome::Executed(execution) = session.on_response(&ok_headers(), &payload).unwrap() else {
        panic!("expected Executed");
    };
    assert_eq!(execution.failure(), Some(ErrorCode::NOT_FOUND));
    assert_eq!(execution.rows(), None);
    assert_eq!(execution.handles().len(), 2);
}

#[test]
fn disconnecting_ends_the_session_context() {
    let mut session = connected();
    let request = session.begin_disconnect().unwrap();
    assert_eq!(request.body(), &[0, 0, 0, 0]);

    let outcome = session
        .on_response(&ok_headers(), &with_preamble(&[]))
        .unwrap();
    assert_eq!(outcome, Outcome::Disconnected);
    assert!(!session.is_connected());
    assert!(session.cookies().is_empty());
}

/// `PING` is an endpoint reachability check, not a session one: [MS-OXCMAPIHTTP] §2.2.6 gives it
/// no request body, no response body and no reference to a Session Context. Exchange Server SE
/// `15.02.2562.045` answers `X-ResponseCode: 0` to a `PING` on a session that has never connected,
/// and to one whose context has already been torn down.
#[test]
fn ping_works_without_a_session_context() {
    let mut session = Session::new();
    let request = session.begin_ping().unwrap();
    assert_eq!(request.request_type(), RequestType::Ping);
    assert!(request.body().is_empty());

    assert_eq!(
        session.on_response(&ok_headers(), b"").unwrap(),
        Outcome::Pong
    );
}

/// One request at a time per Session Context; the server reports a violation as `X-ResponseCode`
/// 15, which points nowhere near the cause.
#[test]
fn a_second_request_while_one_is_in_flight_is_refused() {
    let mut session = Session::new();
    session.begin_connect(&dn()).unwrap();

    let error = session.begin_connect(&dn()).unwrap_err();
    assert!(matches!(error, Error::InvalidState { .. }));
    assert!(error.to_string().contains("already in flight"));
    assert!(session.begin_ping().is_err());
    assert!(session.begin_disconnect().is_err());
}

#[test]
fn requests_that_need_a_session_context_say_so() {
    let mut session = Session::new();
    assert!(matches!(
        session.execute(RopBatch::new()),
        Err(Error::InvalidState { .. })
    ));
    assert!(matches!(
        session.begin_disconnect(),
        Err(Error::InvalidState { .. })
    ));

    let mut session = connected();
    assert!(matches!(
        session.begin_connect(&dn()),
        Err(Error::InvalidState { .. })
    ));
}

#[test]
fn a_response_nobody_asked_for_is_refused() {
    let mut session = Session::new();
    assert_eq!(
        session.on_response(&ok_headers(), b""),
        Err(Error::NoRequestInFlight)
    );
}

/// An endpoint URL missing its `MailboxId` parameter answers HTTP 400 with no `X-ResponseCode` at
/// all, which reads like "MAPI is not enabled" rather than "your URL is incomplete".
#[test]
fn a_response_without_the_response_code_header_is_reported_as_such() {
    let mut session = Session::new();
    session.begin_ping().unwrap();
    assert_eq!(
        session.on_response(&Headers::new(), b""),
        Err(Error::MissingResponseCode)
    );
    assert!(
        !session.is_awaiting_response(),
        "a failed response still ends the request"
    );
}

#[test]
fn a_transport_refusal_carries_the_code_and_the_servers_own_words() {
    let mut session = Session::new();
    session.begin_ping().unwrap();

    let mut headers = Headers::new();
    headers.append("X-ResponseCode", "10");
    let error = session
        .on_response(&headers, b"<html><p>Context Not Found</p></html>")
        .unwrap_err();

    assert_eq!(
        error,
        Error::Transport {
            code: ResponseCode::CONTEXT_NOT_FOUND,
            diagnostic: Some("Context Not Found".to_owned())
        }
    );
    assert!(error.to_string().contains("Context Not Found"));
}

#[test]
fn a_transport_refusal_without_a_diagnostic_still_reports_the_code() {
    let mut session = Session::new();
    session.begin_ping().unwrap();

    let mut headers = Headers::new();
    headers.append("X-ResponseCode", "not a number");
    assert_eq!(
        session.on_response(&headers, b""),
        Err(Error::MissingResponseCode)
    );

    session.begin_ping().unwrap();
    let mut headers = Headers::new();
    headers.append("X-ResponseCode", " 7 ");
    assert_eq!(
        session.on_response(&headers, &[0xFF, 0xFE]),
        Err(Error::Transport {
            code: ResponseCode::MISSING_HEADER,
            diagnostic: None
        })
    );
}

#[test]
fn an_execute_the_server_refuses_reports_its_status() {
    let mut session = connected();
    session.execute(RopBatch::new()).unwrap();

    let mut body = Writer::new();
    body.u32(0x0000_000A);
    let error = session
        .on_response(&ok_headers(), &with_preamble(&body.finish()))
        .unwrap_err();

    assert_eq!(
        error,
        Error::ExecuteFailed {
            status: 0x0000_000A,
            code: ErrorCode::SUCCESS
        }
    );
}

#[test]
fn a_batch_built_with_a_foreign_slot_never_reaches_the_wire() {
    let mut other = RopBatch::new();
    let stranger = other.bind(ObjectHandle::NONE);

    let mut session = connected();
    let mut batch = RopBatch::new();
    batch.query_rows(stranger, 10);

    assert_eq!(
        session.execute(batch),
        Err(Error::UnknownHandleSlot { index: 0 })
    );
    assert!(
        !session.is_awaiting_response(),
        "a request that was never built cannot be in flight"
    );
}

#[test]
fn a_session_can_be_built_with_its_own_identity() {
    let session = SessionBuilder::default()
        .client_application("Outlook/15.00.0847.4040")
        .client_info("{00000000-0000-0000-0000-000000000000}:1")
        .request_guid("{00000000-0000-0000-0000-000000000000}")
        .build();
    assert!(!session.is_connected());
    assert!(Session::default().cookies().is_empty());
}
