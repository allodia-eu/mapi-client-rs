//! What each kind of failure is reported as.
//!
//! A protocol whose failures are numbers is only debuggable if the client turns them back into
//! sentences, so these tests are about the diagnosis rather than about the plumbing: which error
//! variant, carrying which context, for which answer from the server.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use core::time::Duration;

use mapi_client::{Error, ErrorCode, WellKnownFolder, mapi_proto};
use support::{
    BOOKMARK_CURRENT, LOGON_HANDLE, MapiServer, OPEN_FOLDER_SLOT, TABLE_HANDLE, connect_ok,
    connect_refused, contents_row, execute_body, get_table_response, logon_redirect,
    logon_response, mapi_ok, mapi_response, open_folder_response, query_rows_response, rop_failed,
    set_columns_response,
};
use wiremock::ResponseTemplate;

/// The one failure that a bare status code makes unactionable: whether the password is wrong or
/// the *scheme* is unsupported is the difference between retrying and giving up, and only the
/// `WWW-Authenticate` list says which.
#[tokio::test]
async fn a_401_names_the_schemes_the_server_offers_and_the_one_that_was_sent() {
    let server = MapiServer::start().await;
    server.reply(
        ResponseTemplate::new(401)
            .append_header("WWW-Authenticate", "Negotiate")
            .append_header("WWW-Authenticate", "NTLM")
            .append_header("WWW-Authenticate", "Basic realm=\"mail.example.test\""),
    );

    let error = server.client().connect().await.unwrap_err();
    let Error::Unauthorized { offered, sent, .. } = &error else {
        panic!("expected Unauthorized, got {error:?}");
    };

    assert_eq!(offered, &["Negotiate", "NTLM", "Basic"]);
    assert_eq!(*sent, "Basic credentials");

    let message = error.to_string();
    assert!(message.contains("Negotiate, NTLM, Basic"), "{message}");
    assert!(message.contains("sent Basic credentials"), "{message}");
}

/// An endpoint URL without its `MailboxId` parameter is answered by Exchange with an empty HTTP
/// 400 and no `X-ResponseCode` at all, so the status is the entire diagnostic and has to survive.
#[tokio::test]
async fn a_non_mapi_http_status_is_reported_with_its_status_code() {
    let server = MapiServer::start().await;
    server.reply(ResponseTemplate::new(400));

    let error = server.client().ping().await.unwrap_err();
    assert!(
        matches!(&error, Error::Http { status: 400, detail: None, url } if url.contains("MailboxId")),
        "{error:?}"
    );
    assert!(error.to_string().contains("HTTP 400"));
}

/// A proxy in the way says so in HTML, and the one sentence in it is worth keeping.
#[tokio::test]
async fn a_legible_error_body_is_quoted_back() {
    let server = MapiServer::start().await;
    server.reply(
        ResponseTemplate::new(502)
            .set_body_string("<html><body><p>No upstream server available</p></body></html>"),
    );

    let error = server.client().ping().await.unwrap_err();
    assert!(
        matches!(&error, Error::Http { status: 502, detail: Some(text), .. }
            if text == "No upstream server available"),
        "{error:?}"
    );
}

/// The transport's own verdict arrives as HTTP 200 with a non-zero `X-ResponseCode`, which is the
/// reason this crate never treats a 200 as success on its own.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.3
#[tokio::test]
async fn a_non_zero_response_code_is_a_refusal_however_healthy_the_status_line() {
    let server = MapiServer::start().await;
    server.reply(mapi_response(15, Vec::new()));

    let error = server.client().ping().await.unwrap_err();
    let Error::Protocol(mapi_proto::Error::Transport { code, .. }) = &error else {
        panic!("expected a transport refusal, got {error:?}");
    };
    assert_eq!(code.as_u32(), 15);
    assert!(error.to_string().contains("Invalid Sequence"), "{error}");
}

/// No `X-ResponseCode` on a 200 is its own diagnosis, and the codec's message names the usual
/// cause rather than leaving the reader to guess.
#[tokio::test]
async fn a_missing_response_code_header_is_not_read_as_success() {
    let server = MapiServer::start().await;
    server.reply(ResponseTemplate::new(200).set_body_bytes(b"DONE\r\n\r\n".to_vec()));

    let error = server.client().ping().await.unwrap_err();
    assert!(
        matches!(
            error,
            Error::Protocol(mapi_proto::Error::MissingResponseCode)
        ),
        "{error:?}"
    );
}

/// `Connect` failing names the distinguished name that was refused. Without it, `UnknownUser`
/// reads like a credential problem, which is the wrong thing to go and investigate.
#[tokio::test]
async fn a_refused_connect_names_the_distinguished_name() {
    let server = MapiServer::start().await;
    server.reply_ok(connect_refused(ErrorCode::UNKNOWN_USER.as_u32()));

    let error = server.client().connect().await.unwrap_err();
    let Error::Protocol(mapi_proto::Error::ConnectFailed { code, user_dn, .. }) = &error else {
        panic!("expected ConnectFailed, got {error:?}");
    };
    assert_eq!(*code, ErrorCode::UNKNOWN_USER);
    assert!(user_dn.as_str().contains("cn=alice"));
}

/// A ROP the server refuses does not fail the `Execute` that carried it: the batch runs, each ROP
/// reports its own result, and a client that only checked the transport would read an empty answer
/// as an empty mailbox.
#[tokio::test]
async fn a_refused_rop_is_an_error_even_though_the_execute_succeeded() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(
        &rop_failed(0xFE, 0, ErrorCode::LOGIN_PERMISSION.as_u32()),
        &[LOGON_HANDLE],
    ));
    server.reply_ok(support::disconnect_body());

    let error = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            Error::Rop {
                during: "the logon",
                code: ErrorCode::LOGIN_PERMISSION
            }
        ),
        "{error:?}"
    );

    // The Session Context that the failed logon left behind is torn down rather than abandoned
    // for the server to time out.
    let requests = server.requests().await;
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[2].headers.get("X-RequestType").unwrap(),
        &"Disconnect".to_owned()
    );
}

/// The one refusal whose response body does not stop after `ReturnValue`, and the only one that
/// says where to go instead.
///
/// [MS-OXCSTOR] §2.2.1.1.2
#[tokio::test]
async fn a_moved_mailbox_reports_the_server_to_log_on_to_instead() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(
        &logon_redirect(
            0,
            "/o=Example/ou=Exchange Administrative Group/cn=Configuration/cn=other",
        ),
        &[LOGON_HANDLE],
    ));
    server.reply_ok(support::disconnect_body());

    let error = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap_err();

    let Error::WrongServer { server_name } = &error else {
        panic!("expected WrongServer, got {error:?}");
    };
    assert!(server_name.ends_with("cn=other"), "{server_name}");
}

/// A page too big for the output buffer is a request to make, not a server fault, so the error
/// names the remedy.
///
/// [MS-OXCROPS] §2.2.15.1
#[tokio::test]
async fn a_page_that_does_not_fit_says_to_ask_for_less() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    // RopBufferTooSmall: the opcode, the size needed, then the requests that were not executed.
    server.reply_ok(execute_body(&[0xFF, 0x00, 0x40, 0x00], &[LOGON_HANDLE]));

    let client = server.client();
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();
    let error = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .page_size(5000)
        .collect()
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            Error::ResponseTooLarge {
                size_needed: 0x4000
            }
        ),
        "{error:?}"
    );
    // The advice has to be "ask for less", never "ask for a bigger buffer": measurement showed
    // that raising the buffer to what the server reports does not help, and can be impossible.
    let message = error.to_string();
    assert!(message.contains("smaller page"), "{message}");
    assert!(!message.contains("64 KiB"), "{message}");
}

/// A busy server asks to be left alone for a while, and says how long.
///
/// [MS-OXCROPS] §2.2.15.2
#[tokio::test]
async fn a_backoff_carries_the_delay_the_server_asked_for() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    // RopBackoff: opcode, LogonId, Duration, RopCount, AdditionalDataSize.
    server.reply_ok(execute_body(
        &[0xF9, 0x00, 0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[LOGON_HANDLE],
    ));
    server.reply_ok(support::disconnect_body());

    let error = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap_err();

    assert!(
        matches!(error, Error::Backoff { duration_ms: 5000 }),
        "{error:?}"
    );
}

/// When a request fails in transit there is no way to know whether the server acted on it, so the
/// connection refuses to send another rather than reading the previous answer as this one's.
#[tokio::test]
async fn a_connection_that_lost_a_request_will_not_send_another() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server.reply(mapi_ok(Vec::new()).set_delay(Duration::from_secs(30)));

    let client = server
        .builder()
        .timeout(Duration::from_millis(150))
        .build()
        .unwrap();
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();
    let mut rows = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .rows();

    let timed_out = rows.try_next().await.unwrap_err();
    assert!(matches!(timed_out, Error::Timeout { .. }), "{timed_out:?}");

    let poisoned = rows.try_next().await.unwrap_err();
    let Error::Poisoned { cause } = &poisoned else {
        panic!("expected Poisoned, got {poisoned:?}");
    };
    assert!(cause.contains("did not answer within"), "{cause}");
    assert!(
        poisoned.to_string().contains("re-established"),
        "the message has to say what to do: {poisoned}"
    );
}

/// A host that is not listening is not a protocol failure, and the error says so.
#[tokio::test]
async fn an_unreachable_endpoint_is_a_connection_failure() {
    let client =
        MapiServer::builder_for("http://127.0.0.1:1/mapi/emsmdb/?MailboxId=x@example.test")
            .connect_timeout(Duration::from_secs(2))
            .build()
            .unwrap();

    let error = client.ping().await.unwrap_err();
    assert!(matches!(error, Error::Connect { .. }), "{error:?}");
    assert!(
        core::error::Error::source(&error).is_some(),
        "the underlying failure is kept for whoever wants to downcast"
    );
}

/// Rows that arrive for a table whose columns are unknown cannot be decoded, and guessing would
/// hand back plausible wrong values.
#[tokio::test]
async fn rows_for_a_table_with_no_known_columns_are_refused_rather_than_guessed() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));

    // The server answers the opening batch with rows on a handle index the batch never set
    // columns on.
    let mut opened = open_folder_response(OPEN_FOLDER_SLOT);
    opened.extend(get_table_response(0x05, 2, 1));
    opened.extend(set_columns_response(2));
    opened.extend(query_rows_response(
        7,
        BOOKMARK_CURRENT,
        &[contents_row(1, "x", 0, 0)],
    ));
    server.reply_ok(execute_body(&opened, &[LOGON_HANDLE, 1, TABLE_HANDLE]));

    let client = server.client();
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();
    let error = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .collect()
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            Error::Protocol(mapi_proto::Error::UnknownColumns { handle_index: 7 })
        ),
        "{error:?}"
    );
}
