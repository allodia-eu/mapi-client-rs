//! How long the Session Context has left, as each response reports it.

use super::*;

fn reporting(milliseconds: &str) -> Headers {
    let mut headers = ok_headers();
    headers.append("X-ExpirationInfo", milliseconds);
    headers
}

/// The sequence measured against Exchange Server SE `15.02.2562.056`: five minutes in the
/// `Connect` response, fifteen once a logon has run, and nothing at all from a `PING` that named
/// no Session Context.
#[test]
fn every_response_replaces_what_the_last_one_said() {
    let mut session = Session::new();
    assert_eq!(session.expiration(), None, "nothing has been said yet");

    session.begin_connect(&dn()).unwrap();
    session
        .on_response(&reporting("300000"), &connect_payload("Spike Test Usr"))
        .unwrap();
    assert_eq!(session.expiration(), Some(Duration::from_mins(5)));

    let mut batch = RopBatch::new();
    let _ = batch.logon(&dn());
    session.execute(batch).unwrap();
    session
        .on_response(
            &reporting("900000"),
            &execute_payload(&logon_response(0), &[ObjectHandle::new(1)]),
        )
        .unwrap();
    assert_eq!(session.expiration(), Some(Duration::from_mins(15)));

    session.begin_ping().unwrap();
    session.on_response(&ok_headers(), b"").unwrap();
    assert_eq!(
        session.expiration(),
        None,
        "a response that does not say is not a refresh, and not the last value either"
    );
}

/// A refused request says nothing about the context's lifetime either — Exchange sends no
/// `X-ExpirationInfo` with a failing `X-ResponseCode` — and the expiration says so rather than
/// carrying the previous response's value forward.
#[test]
fn a_refusal_reports_no_expiration() {
    let mut session = connected();
    session.begin_ping().unwrap();
    session.on_response(&reporting("900000"), b"").unwrap();
    assert!(session.expiration().is_some());

    session.execute(RopBatch::new()).unwrap();
    let mut refused = Headers::new();
    refused.append("X-ResponseCode", "10");
    let error = session.on_response(&refused, b"").unwrap_err();
    assert!(matches!(error, Error::Transport { .. }), "{error:?}");
    assert_eq!(session.expiration(), None);
}

/// A response with no `X-ResponseCode` — a proxy's 200, say — is not the endpoint speaking, and
/// says nothing about the context's lifetime either: the last response's value is not carried
/// forward as though it had.
#[test]
fn a_response_without_a_verdict_reports_no_expiration() {
    let mut session = connected();
    session.begin_ping().unwrap();
    session.on_response(&reporting("900000"), b"").unwrap();
    assert!(session.expiration().is_some());

    session.begin_ping().unwrap();
    let error = session.on_response(&Headers::new(), b"").unwrap_err();
    assert_eq!(error, Error::MissingResponseCode);
    assert_eq!(session.expiration(), None);
}
