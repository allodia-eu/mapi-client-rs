//! Concurrency under NTLM, against a server that authenticates connections the way IIS does.
//!
//! The fake in `support` answers requests in order, whatever connection they arrive on, which is
//! exactly the property these tests cannot use: the question here is which connection each leg
//! travelled on. So this server is a socket of its own. It challenges each TCP connection, counts
//! it authenticated once the third message arrives on it, refuses a third message on a connection
//! it never challenged, answers an unauthenticated request with a 401, and can hold every response
//! until a given number of requests are in flight at once — so a client that ran them one after
//! another would never be answered at all.
//!
//! The challenge it sends is [MS-NLMP] §4.2.4.3's own `CHALLENGE_MESSAGE`, as in `tests/auth.rs`.

#![cfg(feature = "ntlm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

use core::num::NonZeroUsize;
use core::time::Duration;
use std::sync::{Arc, Mutex};

use mapi_client::{Credentials, Error, LegacyDn, MapiClient};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Barrier;

/// [MS-NLMP] §4.2.4.3's `CHALLENGE_MESSAGE`, base64 as a `WWW-Authenticate` value carries it.
const CHALLENGE: &str = concat!(
    "TlRMTVNTUAACAAAADAAMADgAAAAzgoriASNFZ4mrze8AAAAAAAAAACQAJABEAAAA",
    "BgBwFwAAAA9TAGUAcgB2AGUAcgACAAwARABvAG0AYQBpAG4AAQAMAFMAZQByAHYAZQByAAAAAAA="
);

/// The endpoint's `MailboxId`, whose value this server never reads.
const MAILBOX: &str = "00000000-0000-0000-0000-000000000000@example.test";

/// Long enough for anything a test waits for to have happened, short enough to fail quickly.
const PATIENCE: Duration = Duration::from_secs(10);

/// What the server saw, connection by connection.
#[derive(Debug, Default)]
struct Seen {
    connections: usize,
    /// Handshakes completed, and refused.
    authenticated: usize,
    refused: usize,
    /// Requests sent as though their connection were authenticated, to one that was not.
    misdirected: usize,
    /// Third messages that arrived on a connection that was never challenged.
    unchallenged: usize,
    /// `challenged` and `authenticated`, in the order they happened, across every connection.
    log: Vec<&'static str>,
}

/// A server that authenticates connections.
#[derive(Clone)]
struct Server {
    url: String,
    seen: Arc<Mutex<Seen>>,
    /// When set, every MAPI response waits until this many are waiting.
    hold: Arc<Mutex<Option<Arc<Barrier>>>>,
    /// How many more challenges close their connection once sent.
    closing: Arc<Mutex<usize>>,
    /// Whether the password has changed since the server started: every connection it had
    /// authenticated is unauthenticated from then on, and the old password refused.
    changed: Arc<core::sync::atomic::AtomicBool>,
}

impl Server {
    /// Accepts the password when `accept`, after taking `think` over the third message.
    async fn start(accept: bool, think: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = Self {
            url: format!(
                "http://{}/mapi/emsmdb/?MailboxId={MAILBOX}",
                listener.local_addr().unwrap()
            ),
            seen: Arc::default(),
            hold: Arc::default(),
            closing: Arc::default(),
            changed: Arc::default(),
        };
        let shared = server.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                shared.seen.lock().unwrap().connections += 1;
                tokio::spawn(shared.clone().serve(stream, accept, think));
            }
        });
        server
    }

    /// Answers one connection's requests until the client closes it.
    async fn serve(self, stream: tokio::net::TcpStream, accept: bool, think: Duration) {
        let mut stream = BufReader::new(stream);
        let (mut challenged, mut authenticated, mut close) = (false, false, false);
        loop {
            let mut authorization = None;
            let mut length = 0;
            let mut line = String::new();
            if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let autodiscover = line.contains("/Autodiscover/");
            loop {
                line.clear();
                stream.read_line(&mut line).await.unwrap();
                let header = line.trim_end();
                if header.is_empty() {
                    break;
                }
                let (name, value) = header.split_once(':').unwrap();
                match name.to_ascii_lowercase().as_str() {
                    "authorization" => authorization = Some(value.trim().to_owned()),
                    "content-length" => length = value.trim().parse().unwrap(),
                    _ => {}
                }
            }
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();

            let changed = self.changed.load(core::sync::atomic::Ordering::SeqCst);
            authenticated &= !changed;
            let accept = accept && !changed;

            // [MS-NLMP] §2.2.1: the signature, then the message type — 1 opens, 3 authenticates —
            // which in base64 is the twelfth character.
            let response = match (authorization, authenticated) {
                (None, true) if autodiscover => settings(),
                (None, true) => self.mapi().await,
                (Some(token), _) if token.starts_with("NTLM TlRMTVNTUAAB") => {
                    challenged = true;
                    self.seen.lock().unwrap().log.push("challenged");
                    let mut closing = self.closing.lock().unwrap();
                    close = *closing > 0;
                    *closing = closing.saturating_sub(1);
                    drop(closing);
                    let mut response = unauthorized(Some(CHALLENGE));
                    if close {
                        let at = response.len().saturating_sub(2);
                        response.splice(at..at, *b"Connection: close\r\n");
                    }
                    response
                }
                (Some(_), _) if !challenged => {
                    self.seen.lock().unwrap().unchallenged += 1;
                    unauthorized(None)
                }
                (Some(_), _) => {
                    challenged = false;
                    tokio::time::sleep(think).await;
                    if accept {
                        authenticated = true;
                        {
                            let mut seen = self.seen.lock().unwrap();
                            seen.authenticated += 1;
                            seen.log.push("authenticated");
                        }
                        if autodiscover {
                            settings()
                        } else {
                            self.mapi().await
                        }
                    } else {
                        self.seen.lock().unwrap().refused += 1;
                        unauthorized(None)
                    }
                }
                (None, false) => {
                    self.seen.lock().unwrap().misdirected += 1;
                    unauthorized(None)
                }
            };
            stream.get_mut().write_all(&response).await.unwrap();
            if close {
                // The client hangs up, not the server. A connection the server closes first leaves
                // the client's port free at once, and Windows hands it to the very next connection
                // — whose 401 then reads as the same connection's, which is the one case `moved`
                // cannot see. The side that closes first keeps its port in TIME_WAIT, so it closes.
                let _ = stream.read_to_end(&mut Vec::new()).await;
                return;
            }
        }
    }

    /// A PING's answer, once enough others are waiting for theirs.
    async fn mapi(&self) -> Vec<u8> {
        let hold = self.hold.lock().unwrap().clone();
        if let Some(barrier) = hold {
            barrier.wait().await;
        }
        let body = b"PROCESSING\r\nDONE\r\nX-ElapsedTime: 5\r\n\r\n";
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nX-ResponseCode: 0\r\nContent-Type: application/mapi-http\r\n\
             Persistent-Auth: true\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    /// From now on, answer nothing until `parties` requests are waiting together.
    fn hold(&self, parties: usize) {
        *self.hold.lock().unwrap() = Some(Arc::new(Barrier::new(parties)));
    }

    /// From now on, answer at once.
    fn release(&self) {
        *self.hold.lock().unwrap() = None;
    }

    /// Changes the password, as an administrator resetting it would.
    fn change_password(&self) {
        self.changed
            .store(true, core::sync::atomic::Ordering::SeqCst);
    }

    /// Closes the connection after each of the next `count` challenges — `Connection: close`, so
    /// the client does the closing — as though the pool had handed the next leg another one.
    fn close_after_challenges(&self, count: usize) {
        *self.closing.lock().unwrap() = count;
    }

    fn client(&self, connections: usize, password: &str) -> MapiClient {
        MapiClient::builder()
            .endpoint(&self.url)
            .user_dn(LegacyDn::new("/o=Example/ou=Exchange/cn=Recipients/cn=alice").unwrap())
            .credentials(Credentials::ntlm("EXAMPLE\\alice", password))
            .max_authenticated_connections(NonZeroUsize::new(connections).unwrap())
            .danger_allow_plaintext_http()
            .timeout(PATIENCE)
            .build()
            .unwrap()
    }

    /// Connections opened, handshakes completed, handshakes refused.
    fn seen(&self) -> (usize, usize, usize) {
        let seen = self.seen.lock().unwrap();
        (seen.connections, seen.authenticated, seen.refused)
    }
}

/// An Autodiscover answer naming a mailbox.
fn settings() -> Vec<u8> {
    let body = include_str!("autodiscover-settings.xml");
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body.as_bytes());
    response
}

/// A 401 offering NTLM, with `token` when there is a challenge to send.
fn unauthorized(token: Option<&str>) -> Vec<u8> {
    let offer = token.map_or_else(|| "NTLM".to_owned(), |token| format!("NTLM {token}"));
    format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: {offer}\r\nContent-Length: 0\r\n\r\n")
        .into_bytes()
}

/// `count` PINGs at once, on clones of `client`.
async fn at_once(client: &MapiClient, count: usize) -> Vec<Result<(), Error>> {
    let pings = (0..count).map(|_| {
        let client = client.clone();
        tokio::spawn(async move { client.ping().await })
    });
    let mut results = Vec::new();
    for ping in pings.collect::<Vec<_>>() {
        results.push(tokio::time::timeout(PATIENCE, ping).await.unwrap().unwrap());
    }
    results
}

/// Four requests at once are four connections, each authenticated by a handshake of its own — and
/// the server answers none of them until all four are in flight, so a client that ran them one
/// after another would wait forever. After that every connection is reused, and nothing is
/// authenticated again.
#[tokio::test]
async fn concurrent_requests_each_authenticate_a_connection_of_their_own() {
    let server = Server::start(true, Duration::ZERO).await;
    let client = server.client(4, "hunter2");
    client.ping().await.unwrap();
    assert_eq!(server.seen(), (1, 1, 0));

    server.hold(4);
    for result in at_once(&client, 4).await {
        result.unwrap();
    }
    assert_eq!(server.seen(), (4, 4, 0), "one new connection per request");

    // Answered two at a time now: eight requests on the four connections there are.
    server.hold(2);
    for result in at_once(&client, 8).await {
        result.unwrap();
    }
    assert_eq!(server.seen(), (4, 4, 0), "every connection reused");
}

/// Past the limit a request waits for a connection rather than opening one.
#[tokio::test]
async fn no_more_connections_are_authenticated_than_the_limit() {
    let server = Server::start(true, Duration::ZERO).await;
    let client = server.client(2, "hunter2");
    client.ping().await.unwrap();

    server.hold(2);
    for result in at_once(&client, 6).await {
        result.unwrap();
    }
    assert_eq!(server.seen(), (2, 2, 0));
}

/// A wrong password is sent once, not once per request: the others were waiting for their turn,
/// and are refused with the first. A domain controller counts every refused handshake towards
/// locking the account.
#[tokio::test]
async fn a_wrong_password_is_tried_once_not_once_per_request() {
    let server = Server::start(false, Duration::from_millis(200)).await;
    let client = server.client(4, "not-the-password");
    for result in at_once(&client, 4).await {
        assert!(
            matches!(result, Err(Error::Unauthorized { .. })),
            "{result:?}"
        );
    }
    assert_eq!(server.seen().2, 1, "one refused handshake");

    // Asking again is the caller's decision, and it is honoured.
    let again = client.ping().await;
    assert!(
        matches!(again, Err(Error::Unauthorized { .. })),
        "{again:?}"
    );
    assert_eq!(server.seen().2, 2);
}

/// Until one handshake has worked, the others wait for it rather than run their own — and once it
/// has, the first of them is lent the connection it authenticated, and the rest run theirs at once.
#[tokio::test]
async fn the_first_handshake_is_run_alone() {
    let server = Server::start(true, Duration::from_millis(200)).await;
    let client = server.client(4, "hunter2");
    for result in at_once(&client, 4).await {
        result.unwrap();
    }
    assert_eq!(server.seen(), (3, 3, 0), "one handshake saved");
    let log = server.seen.lock().unwrap().log.clone();
    assert_eq!(
        log,
        [
            "challenged",
            "authenticated",
            "challenged",
            "challenged",
            "authenticated",
            "authenticated",
        ]
    );
}

/// A password changed under connections already authenticated is sent once, not once per
/// connection: the first refusal of a connection believed authenticated makes the handshakes that
/// follow take turns, and the one refused refuses those waiting.
#[tokio::test]
async fn a_changed_password_is_tried_once_not_once_per_connection() {
    let server = Server::start(true, Duration::from_millis(200)).await;
    let client = server.client(4, "hunter2");
    client.ping().await.unwrap();
    server.hold(4);
    for result in at_once(&client, 4).await {
        result.unwrap();
    }
    server.release();
    assert_eq!(server.seen(), (4, 4, 0));

    server.change_password();
    for result in at_once(&client, 4).await {
        assert!(
            matches!(result, Err(Error::Unauthorized { .. })),
            "{result:?}"
        );
    }
    assert_eq!(server.seen().2, 1, "one refused handshake");
}

/// A request abandoned in flight takes its connection with it, so the next request on that lane
/// authenticates a new one first, rather than sending its body to a connection the server has never
/// seen and being refused.
#[tokio::test]
async fn a_connection_lost_in_flight_is_not_believed_authenticated() {
    let server = Server::start(true, Duration::ZERO).await;
    let client = server.client(1, "hunter2");
    client.ping().await.unwrap();

    server.hold(2);
    let abandoned = tokio::time::timeout(Duration::from_millis(200), client.ping()).await;
    assert!(abandoned.is_err(), "the server never answered it");
    server.release();

    client.ping().await.unwrap();
    assert_eq!(
        server.seen(),
        (2, 2, 0),
        "a second connection, authenticated"
    );
    assert_eq!(server.seen.lock().unwrap().misdirected, 0);
}

/// A leg the pool moves to another connection is refused there, as a wrong password would be — but
/// on a different connection from the challenge it answered, which a wrong password never is. So
/// the handshake starts again, and the request succeeds.
#[tokio::test]
async fn a_handshake_moved_to_another_connection_is_started_again() {
    let server = Server::start(true, Duration::ZERO).await;
    server.close_after_challenges(1);
    let client = server.client(1, "hunter2");
    client.ping().await.unwrap();
    assert_eq!(
        server.seen(),
        (2, 1, 0),
        "one connection lost, one authenticated"
    );
    assert_eq!(server.seen.lock().unwrap().unchallenged, 1);
}

/// It starts again a bounded number of times: a server that loses every challenge's connection
/// gets the refusal reported, not a client that never stops.
#[tokio::test]
async fn a_handshake_that_keeps_moving_is_given_up() {
    let server = Server::start(true, Duration::ZERO).await;
    server.close_after_challenges(usize::MAX);
    let client = server.client(1, "hunter2");
    let error = client.ping().await.unwrap_err();
    assert!(matches!(error, Error::Unauthorized { .. }), "{error:?}");
    assert_eq!(
        server.seen.lock().unwrap().unchallenged,
        3,
        "three attempts"
    );
}

/// Autodiscover's handshake, moved the same way, starts again the same way.
#[cfg(feature = "autodiscover")]
#[tokio::test]
async fn an_autodiscover_handshake_moved_to_another_connection_is_started_again() {
    use mapi_client::EmailAddress;

    let server = Server::start(true, Duration::ZERO).await;
    server.close_after_challenges(1);
    let url = server
        .url
        .replace("/mapi/emsmdb/", "/Autodiscover/Autodiscover.xml");
    let found = MapiClient::builder()
        .credentials(Credentials::ntlm("EXAMPLE\\alice", "hunter2"))
        .danger_allow_plaintext_http()
        .timeout(PATIENCE)
        .lookup_at(url, &EmailAddress::new("alice@example.test").unwrap())
        .await
        .expect("the settings, on the second handshake");
    assert!(found.mail_store_url().is_some());
    assert_eq!(server.seen(), (2, 1, 0));
    assert_eq!(server.seen.lock().unwrap().unchallenged, 1);
}
