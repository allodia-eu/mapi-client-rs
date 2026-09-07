//! The connection-oriented schemes, against a fake server that answers like IIS does.
//!
//! What these tests are for is the *arrangement*, not the cryptography: how many round trips a
//! handshake costs, which requests carry an `Authorization` header and which do not, what happens
//! when the connection stops being authenticated part way through a session, and how each way of
//! failing is reported. The messages themselves are `mapi-auth`'s business and are checked there
//! against [MS-NLMP]'s published values; a real Exchange's agreement with all of it is
//! `tests/live.rs`.
//!
//! The challenge every test here replies with is [MS-NLMP] §4.2.4.3's own `CHALLENGE_MESSAGE`,
//! which is the only one that can be written down without a server to get it from.

#![cfg(feature = "ntlm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use mapi_client::Credentials;
use support::{LOGON_HANDLE, MapiServer, connect_ok, execute_body, logon_response};
use wiremock::ResponseTemplate;

/// [MS-NLMP] §4.2.4.3's `CHALLENGE_MESSAGE`, base64 as a `WWW-Authenticate` value carries it.
const CHALLENGE: &str = concat!(
    "TlRMTVNTUAACAAAADAAMADgAAAAzgoriASNFZ4mrze8AAAAAAAAAACQAJABEAAAA",
    "BgBwFwAAAA9TAGUAcgB2AGUAcgACAAwARABvAG0AYQBpAG4AAQAMAFMAZQByAHYAZQByAAAAAAA="
);

/// The same challenge inside the `NegTokenResp` a `Negotiate` server answers with: `negState`
/// accept-incomplete, `supportedMech` 1.3.6.1.4.1.311.2.2.10, and the NTLM message as the
/// `responseToken`.
///
/// [RFC 4178] §4.2.2 — `NegTokenResp`
const SPNEGO_CHALLENGE: &str = concat!(
    "oYGBMH+gAwoBAaEMBgorBgEEAYI3AgIKomoEaE5UTE1TU1AAAgAAAAwADAA4AAAA",
    "M4KK4gEjRWeJq83vAAAAAAAAAAAkACQARAAAAAYAcBcAAAAPUwBlAHIAdgBlAHIA",
    "AgAMAEQAbwBtAGEAaQBuAAEADABTAGUAcgB2AGUAcgAAAAAA",
);

/// A 401 offering all three schemes, with a real challenge on the one named.
///
/// The other two are offered bare, exactly as IIS does: a server lists what it would accept
/// alongside the handshake it is part-way through.
fn challenge(scheme: &str) -> ResponseTemplate {
    let token = if scheme == "Negotiate" {
        SPNEGO_CHALLENGE
    } else {
        CHALLENGE
    };
    let mut response = ResponseTemplate::new(401);
    for offered in ["Negotiate", "NTLM"] {
        response = if offered == scheme {
            response.append_header("WWW-Authenticate", format!("{scheme} {token}").as_str())
        } else {
            response.append_header("WWW-Authenticate", offered)
        };
    }
    response.append_header("WWW-Authenticate", "Basic realm=\"exchange-lab-01\"")
}

/// The 401 IIS sends when it has *rejected* a credential: the same schemes, none of them carrying
/// a token. Indistinguishable from the opening 401 except that no challenge is attached.
fn restart() -> ResponseTemplate {
    ResponseTemplate::new(401)
        .append_header("WWW-Authenticate", "Negotiate")
        .append_header("WWW-Authenticate", "NTLM")
}

/// The `Authorization` header of each request the server received, in order.
async fn authorizations(server: &MapiServer) -> Vec<String> {
    server
        .requests()
        .await
        .iter()
        .map(|request| {
            request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("(none)")
                .split_whitespace()
                .next()
                .unwrap_or("(none)")
                .to_owned()
        })
        .collect()
}

/// The whole shape of the thing: one extra round trip for the handshake, then none.
///
/// The opening leg carries no MAPI request — its body is empty and it has no `X-RequestType` —
/// because a `NEGOTIATE_MESSAGE` proves nothing and the answer is a 401 whatever was sent. Sending
/// the ROP buffer with it would upload it an extra time for no gain.
#[tokio::test]
async fn an_ntlm_handshake_costs_one_extra_round_trip_and_then_none() {
    let server = MapiServer::start().await;
    server.reply(challenge("NTLM"));
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));

    let client = server
        .builder()
        .credentials(Credentials::ntlm("DEV\\alice", "hunter2"))
        .build()
        .unwrap();

    let logon = client.connect().await.unwrap().logon().await.unwrap();
    drop(logon);

    // Three requests for two MAPI ones: the handshake's opening leg, then Connect on the last leg
    // of the handshake, then the logon with no `Authorization` at all — because the connection is
    // authenticated and IIS says so with `Persistent-Auth: true`.
    assert_eq!(authorizations(&server).await, ["NTLM", "NTLM", "(none)"]);

    let requests = server.requests().await;
    assert_eq!(requests.len(), 3);
    assert!(
        requests[0].body.is_empty(),
        "the opening leg carries no body"
    );
    assert!(requests[0].headers.get("x-requesttype").is_none());
    // …and it says so explicitly, because `http.sys` answers a POST with no `Content-Length` with
    // 411 before it authenticates anything.
    assert_eq!(
        requests[0].headers.get("content-length").unwrap(),
        "0",
        "an empty leg must still declare its length"
    );
    assert!(
        !requests[1].body.is_empty(),
        "the real request rides leg two"
    );
    assert_eq!(requests[1].headers.get("x-requesttype").unwrap(), "Connect");
}

/// Negotiate carries the same NTLM messages inside a SPNEGO token, which is visible in the wire
/// bytes: the first is a GSS-API `InitialContextToken`, the second a bare `NegTokenResp`.
#[tokio::test]
async fn a_negotiate_handshake_wraps_the_messages_in_spnego() {
    let server = MapiServer::start().await;
    server.reply(challenge("Negotiate"));
    server.reply(connect_ok("Alice Example"));

    let client = server
        .builder()
        .credentials(Credentials::negotiate("alice@example.test", "hunter2"))
        .build()
        .unwrap();
    client.connect().await.unwrap();

    assert_eq!(authorizations(&server).await, ["Negotiate", "Negotiate"]);

    let requests = server.requests().await;
    let token = |index: usize| {
        let value = requests[index]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned();
        // base64, decoded the long way so that this test depends on nothing but std.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut bits = 0_u32;
        let mut count = 0_u8;
        for byte in value.bytes().filter(|byte| *byte != b'=') {
            let index = alphabet.iter().position(|c| *c == byte).unwrap();
            bits = (bits << 6) | u32::try_from(index).unwrap();
            count += 6;
            if count >= 8 {
                count -= 8;
                out.push(u8::try_from((bits >> count) & 0xFF).unwrap());
            }
        }
        out
    };

    // [APPLICATION 0] on the first, per [RFC 2743] §3.1, and the SPNEGO OID 1.3.6.1.5.5.2 inside.
    let first = token(0);
    assert_eq!(first[0], 0x60);
    assert!(
        first
            .windows(6)
            .any(|w| w == [0x2B, 0x06, 0x01, 0x05, 0x05, 0x02])
    );
    // A continuation token is a bare NegTokenResp, `[1]`, with no wrapper and no OID.
    let second = token(1);
    assert_eq!(second[0], 0xA1);
    assert!(
        !second
            .windows(6)
            .any(|w| w == [0x2B, 0x06, 0x01, 0x05, 0x05, 0x02])
    );
    // Both still carry an NTLM message, which is the whole point of the arrangement.
    for token in [&first, &second] {
        assert!(token.windows(8).any(|w| w == b"NTLMSSP\0"));
    }
}

/// A connection that stops being authenticated part way through a session.
///
/// The pool can hand over a connection the server has never authenticated — a new one, or one that
/// timed out — and the request on it comes back 401. That is not a failure: it is the signal to run
/// the handshake again, which is why the "already authenticated" flag in the transport is a hint
/// rather than a fact.
#[tokio::test]
async fn a_401_part_way_through_a_session_authenticates_again() {
    let server = MapiServer::start().await;
    server.reply(challenge("NTLM"));
    server.reply(connect_ok("Alice Example"));
    // The logon lands on a connection the server does not recognise.
    server.reply(restart());
    server.reply(challenge("NTLM"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));

    let client = server
        .builder()
        .credentials(Credentials::ntlm("DEV\\alice", "hunter2"))
        .build()
        .unwrap();

    let logon = client.connect().await.unwrap().logon().await.unwrap();
    drop(logon);

    assert_eq!(
        authorizations(&server).await,
        ["NTLM", "NTLM", "(none)", "NTLM", "NTLM"],
        "the unauthenticated attempt is retried behind a fresh handshake"
    );
}

/// A rejected credential, which IIS reports by starting the handshake over rather than by saying
/// anything about the password.
///
/// The distinction matters: read as a protocol error it sends the reader looking at the message
/// encoding, when the answer is that the password is wrong.
#[tokio::test]
async fn a_restarted_handshake_is_reported_as_a_refused_credential() {
    let server = MapiServer::start().await;
    server.reply(challenge("NTLM"));
    server.reply(restart());

    let client = server
        .builder()
        .credentials(Credentials::ntlm("DEV\\alice", "wrong-password"))
        .build()
        .unwrap();

    let error = client.connect().await.expect_err("a refusal");
    assert!(
        matches!(&error, mapi_client::Error::Unauthorized { sent, .. } if *sent == "NTLM credentials"),
        "{error:?}"
    );
    // The message names the schemes the server was still offering, which is the diagnosis.
    let rendered = error.to_string();
    assert!(rendered.contains("Negotiate"), "{rendered}");
}

/// A server whose 401 offers nothing this scheme speaks, which is a different failure and reads as
/// one: the credentials may be perfect and still unusable here.
#[tokio::test]
async fn a_server_that_offers_no_matching_scheme_says_what_it_does_offer() {
    let server = MapiServer::start().await;
    server.reply(
        ResponseTemplate::new(401)
            .append_header("WWW-Authenticate", "Basic realm=\"exchange-lab-01\"")
            .append_header("WWW-Authenticate", "Bearer"),
    );

    let client = server
        .builder()
        .credentials(Credentials::negotiate("alice@example.test", "hunter2"))
        .build()
        .unwrap();

    let error = client.connect().await.expect_err("nothing to answer");
    assert!(
        matches!(&error, mapi_client::Error::Unauthorized { offered, .. }
            if offered == &["Basic", "Bearer"]),
        "{error:?}"
    );
}

/// A challenge that will not parse is the server's fault, not the credential's — but it still has
/// to arrive as something a person can act on rather than as a panic or a hang.
#[tokio::test]
async fn a_challenge_that_will_not_parse_is_reported_rather_than_trusted() {
    for offered in ["NTLM !!!not-base64!!!", "NTLM aGVsbG8gd29ybGQ="] {
        let server = MapiServer::start().await;
        server.reply(ResponseTemplate::new(401).append_header("WWW-Authenticate", offered));

        let client = server
            .builder()
            .credentials(Credentials::ntlm("DEV\\alice", "hunter2"))
            .build()
            .unwrap();

        let error = client.connect().await.expect_err("an unusable challenge");
        assert!(
            matches!(error, mapi_client::Error::Unauthorized { .. }),
            "{offered}: {error:?}"
        );
    }
}

/// Basic credentials are unaffected: one request per request, and the header on every one.
///
/// Worth asserting rather than assuming, because the handshake path is chosen by a branch on the
/// credentials and a branch is exactly the thing that can be wired to the wrong side.
#[tokio::test]
async fn basic_credentials_still_cost_one_request_each() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));

    let client = server.client();
    let logon = client.connect().await.unwrap().logon().await.unwrap();
    drop(logon);

    assert_eq!(authorizations(&server).await, ["Basic", "Basic"]);
}
