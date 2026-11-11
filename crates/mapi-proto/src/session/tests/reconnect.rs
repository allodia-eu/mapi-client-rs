//! Re-establishing a Session Context: which cookies go out, and which are kept.

use super::*;

fn setting(cookies: &[&str]) -> Headers {
    let mut headers = ok_headers();
    for cookie in cookies {
        headers.append("Set-Cookie", *cookie);
    }
    headers
}

/// [MS-OXCMAPIHTTP] §3.2.5.6: the client "MUST NOT comingle the new cookies with cookies from
/// the previous Session Context". The reconnect carries every old cookie; the jar afterwards holds
/// only what its response set.
#[test]
fn a_reconnect_passes_the_old_cookies_and_keeps_only_the_new_ones() {
    let mut session = connected();
    session.begin_ping().unwrap();
    session
        .on_response(&setting(&["Leftover=1; Path=/"]), b"")
        .unwrap();

    let request = session.begin_reconnect(&dn()).unwrap();
    let sent = request.headers().get("Cookie").unwrap();
    assert!(
        sent.contains("MapiContext=abc") && sent.contains("Leftover=1"),
        "{sent}"
    );

    session
        .on_response(
            &setting(&["MapiContext=new; Path=/", "MapiSequence=1; Path=/"]),
            &connect_payload("Spike Test Usr"),
        )
        .unwrap();
    let names: Vec<_> = session
        .cookies()
        .cookies()
        .iter()
        .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
        .collect();
    assert_eq!(names, ["MapiContext=new", "MapiSequence=1"]);
}

/// A reconnect the server refused leaves the old cookies in place, so the next attempt still names
/// the context the server has to clean up.
#[test]
fn a_refused_reconnect_keeps_the_old_cookies_for_the_next_attempt() {
    let mut session = connected();
    session.begin_reconnect(&dn()).unwrap();
    let mut refused = Headers::new();
    refused.append("X-ResponseCode", "1");
    refused.append("Set-Cookie", "MapiRouting=r; Path=/");
    assert!(session.on_response(&refused, b"").is_err());

    let request = session.begin_reconnect(&dn()).unwrap();
    let sent = request.headers().get("Cookie").unwrap();
    assert!(
        sent.contains("MapiContext=abc") && sent.contains("MapiRouting=r"),
        "{sent}"
    );
}

/// [MS-OXCMAPIHTTP] §3.2.5.2: a failure the server settles only after `DONE` is the verdict, even
/// though the first `X-ResponseCode` said 0 — and it says it came late, because by then the
/// request was being worked on.
#[test]
fn a_failure_reported_after_done_fails_the_request() {
    let mut session = connected();
    session.execute(RopBatch::new()).unwrap();
    let payload = b"PROCESSING\r\nDONE\r\nX-ResponseCode: 10\r\nX-ElapsedTime: 3\r\n\r\n";
    let error = session.on_response(&ok_headers(), payload).unwrap_err();
    assert!(
        matches!(
            error,
            Error::FailedAfterDone {
                code: ResponseCode::CONTEXT_NOT_FOUND,
                ..
            }
        ),
        "{error:?}"
    );
}
