//! What an [`Observer`](mapi_client::Observer) is handed, against a server that answers.
//!
//! These are the assertions the fixture pipeline rests on: if what an observer sees is not
//! byte-for-byte what went over the wire, every capture in `fixtures/` is a well-formatted fiction.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use std::sync::{Arc, Mutex};

use mapi_client::{Credentials, Exchange, Observer, RequestType};
use support::{LOGON_HANDLE, MapiServer, connect_ok, execute_body, logon_response, mapi_response};
use wiremock::ResponseTemplate;

/// Everything one exchange carried, owned so it outlives the borrow.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    request_type: RequestType,
    request_body: Vec<u8>,
    request_headers: Vec<(String, String)>,
    status: u16,
    response_body: Vec<u8>,
    response_code: Option<String>,
}

#[derive(Debug, Default)]
struct Transcript(Mutex<Vec<Seen>>);

impl Transcript {
    fn entries(&self) -> Vec<Seen> {
        self.0.lock().unwrap().clone()
    }
}

impl Observer for Transcript {
    fn observe(&self, exchange: &Exchange<'_>) {
        self.0.lock().unwrap().push(Seen {
            request_type: exchange.request_type(),
            request_body: exchange.request_body().to_vec(),
            request_headers: exchange
                .request_headers()
                .iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            status: exchange.status(),
            response_body: exchange.response_body().to_vec(),
            response_code: exchange
                .response_headers()
                .get("X-ResponseCode")
                .map(str::to_owned),
        });
    }
}

/// The whole point: what the observer reports is what the transport sent and received, with the
/// meta-tag preamble still on the front of the response because nothing has parsed it yet.
#[tokio::test]
async fn an_observer_sees_the_bytes_that_actually_crossed_the_wire() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));

    let transcript = Arc::new(Transcript::default());
    let client = server
        .builder()
        .observer(Arc::clone(&transcript))
        .build()
        .unwrap();

    let logon = client.connect().await.unwrap().logon().await.unwrap();
    assert_eq!(logon.mailbox().folder_ids().len(), 13);

    let seen = transcript.entries();
    assert_eq!(seen.len(), 2);

    // Request bodies, byte for byte against what the server received.
    let sent = server.requests().await;
    assert_eq!(seen[0].request_body, sent[0].body);
    assert_eq!(seen[1].request_body, sent[1].body);

    assert_eq!(seen[0].request_type, RequestType::Connect);
    assert_eq!(seen[1].request_type, RequestType::Execute);
    assert_eq!(seen[0].status, 200);
    assert_eq!(seen[0].response_code.as_deref(), Some("0"));

    // The response is handed over whole, preamble included — which is what makes a capture
    // replayable through `Session::on_response` with nothing put back.
    assert!(seen[0].response_body.starts_with(b"PROCESSING\r\nDONE\r\n"));

    let names: Vec<&str> = seen[0]
        .request_headers
        .iter()
        .map(|(name, _)| &**name)
        .collect();
    assert!(names.contains(&"X-RequestType"));
    // Basic credentials were configured, and none of them are here: the `Authorization` header is
    // the HTTP client's, below the layer an observer watches.
    assert!(
        !names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("Authorization")),
        "{names:?}"
    );
    let serialised = format!("{:?}", seen[0].request_headers);
    assert!(!serialised.contains("hunter2"), "{serialised}");
}

/// A refusal is an exchange too. The 401 that means "wrong password" and the 400 that means "your
/// endpoint URL is missing its `MailboxId`" are exactly the two answers somebody reaches for a
/// transcript to explain, so an observer that only saw successes would be silent when it mattered.
#[tokio::test]
async fn a_refusal_is_reported_rather_than_swallowed() {
    let server = MapiServer::start().await;
    server.reply(
        ResponseTemplate::new(401)
            .append_header("WWW-Authenticate", "Negotiate")
            .set_body_string("denied"),
    );
    server.reply(ResponseTemplate::new(400).set_body_string("no MailboxId"));

    let transcript = Arc::new(Transcript::default());
    let client = server
        .builder()
        .credentials(Credentials::basic("alice@example.test", "wrong"))
        .observer(Arc::clone(&transcript))
        .build()
        .unwrap();

    let refused = client.ping().await.expect_err("401");
    assert!(matches!(refused, mapi_client::Error::Unauthorized { .. }));
    let rejected = client.ping().await.expect_err("400");
    assert!(matches!(
        rejected,
        mapi_client::Error::Http { status: 400, .. }
    ));

    let seen = transcript.entries();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].status, 401);
    assert_eq!(seen[0].response_body, b"denied");
    assert_eq!(seen[1].status, 400);
    assert_eq!(seen[1].response_body, b"no MailboxId");
}

/// A request that never reached a server produced no exchange, so there is nothing to report and
/// the error the caller gets is the whole story.
#[tokio::test]
async fn a_request_that_got_no_answer_is_not_an_exchange() {
    let transcript = Arc::new(Transcript::default());
    // A port nothing is listening on, so the connection is refused before anything is sent.
    let client =
        MapiServer::builder_for("http://127.0.0.1:1/mapi/emsmdb/?MailboxId=x@example.test")
            .observer(Arc::clone(&transcript))
            .build()
            .unwrap();

    let error = client.ping().await.expect_err("nothing is listening");
    assert!(
        matches!(error, mapi_client::Error::Connect { .. }),
        "{error:?}"
    );
    assert!(transcript.entries().is_empty());
}

/// Observing does not change what the client does, which is the property that makes it safe to
/// leave on. Also the documented replacement rule: the last observer set is the one that runs.
#[tokio::test]
async fn observing_changes_nothing_about_the_exchange() {
    let server = MapiServer::start().await;
    server.reply(mapi_response(0, support::connect_body("Alice Example")));

    let first = Arc::new(Transcript::default());
    let second = Arc::new(Transcript::default());
    let client = server
        .builder()
        .observer(Arc::clone(&first))
        .observer(Arc::clone(&second))
        .build()
        .unwrap();

    let connection = client.connect().await.unwrap();
    assert_eq!(connection.server().display_name(), "Alice Example");

    assert!(first.entries().is_empty(), "replaced, so never called");
    assert_eq!(second.entries().len(), 1);
}
