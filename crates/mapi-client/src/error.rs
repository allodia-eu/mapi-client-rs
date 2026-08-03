//! What can go wrong once a network is involved.
//!
//! [`mapi-proto`](mapi_proto) already names everything that can go wrong with the *bytes*. This
//! adds the failures that only exist because something has to carry them: a host that does not
//! answer, a certificate that does not verify, credentials the server will not take.
//!
//! Two rules shape the list. Every variant carries the context needed to act on it — which URL,
//! which credentials, which folder — because a bare "401" or "timeout" sends the reader to the
//! wrong place. And no variant exposes the HTTP client's own error type: the underlying client is
//! an implementation detail, and a public `reqwest::Error` would pin this crate's semantic version
//! to somebody else's. The original is kept as [`source`](core::error::Error::source) for anyone
//! who wants to downcast.

use core::time::Duration;

use mapi_proto::{ErrorCode, SpecialFolder, WellKnownFolder};

/// The result of anything in this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Something this crate could not do.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A setting with no default was never given.
    #[error("{name} was never set; call {how}")]
    MissingSetting {
        /// The setting that is missing.
        name: &'static str,
        /// The method that sets it.
        how: &'static str,
    },

    /// The endpoint URL cannot be used.
    #[error("endpoint URL is unusable ({reason}): {url}")]
    InvalidEndpoint {
        /// The URL as given.
        url: String,
        /// Which rule it broke.
        reason: &'static str,
    },

    /// The endpoint URL is plain HTTP, and nothing said that was intended.
    ///
    /// A MAPI request carries the credentials for a mailbox and the mailbox's contents back. This
    /// crate will not put either on the wire in the clear unless asked to in as many words —
    /// [`MapiClientBuilder::danger_allow_plaintext_http`] exists for the fake servers that tests
    /// point at.
    ///
    /// [`MapiClientBuilder::danger_allow_plaintext_http`]:
    ///     crate::MapiClientBuilder::danger_allow_plaintext_http
    #[error(
        "refusing to send credentials and mailbox data over plaintext HTTP to {url}; use https, \
         or call danger_allow_plaintext_http if this is a test server"
    )]
    PlaintextEndpoint {
        /// The URL as given.
        url: String,
    },

    /// The HTTP client itself could not be built — a certificate that will not parse, a TLS
    /// backend that will not start, a proxy setting that makes no sense.
    #[error("could not build the HTTP client")]
    Setup {
        /// The underlying failure.
        #[source]
        source: Box<dyn core::error::Error + Send + Sync + 'static>,
    },

    /// The endpoint could not be reached at all: DNS, TCP or the TLS handshake.
    #[error("could not reach {url}")]
    Connect {
        /// The URL that was tried.
        url: String,
        /// The underlying failure.
        #[source]
        source: Box<dyn core::error::Error + Send + Sync + 'static>,
    },

    /// The server did not finish answering within the configured timeout.
    ///
    /// Worth raising rather than retrying if it recurs: a server working on a request emits
    /// `PENDING` keep-alives every 30 seconds by default, so a timeout below that measures the
    /// keep-alive interval rather than the server.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.3.3.5 — `X-PendingPeriod`
    #[error("{url} did not answer within {after:?}")]
    Timeout {
        /// The URL that was tried.
        url: String,
        /// The timeout that elapsed.
        after: Duration,
    },

    /// The exchange failed after the connection was established.
    #[error("the request to {url} failed")]
    Request {
        /// The URL that was tried.
        url: String,
        /// The underlying failure.
        #[source]
        source: Box<dyn core::error::Error + Send + Sync + 'static>,
    },

    /// The server refused the credentials.
    ///
    /// `offered` is what the server listed in its `WWW-Authenticate` headers, which is the fact
    /// that turns a bare 401 into a diagnosis: a server offering only `Negotiate` and `NTLM` has
    /// not rejected the password, it has rejected the *scheme*, and no password will fix it. See
    /// [`Credentials`](crate::Credentials) for what this crate implements and why.
    #[error(
        "{url} refused the credentials (HTTP 401): sent {sent}, server accepts {}",
        schemes(.offered)
    )]
    Unauthorized {
        /// The URL that was tried.
        url: String,
        /// The authentication schemes the server named in `WWW-Authenticate`, in the order given.
        offered: Vec<String>,
        /// What this client sent.
        sent: &'static str,
    },

    /// The server answered with an HTTP status that is not a MAPI response.
    ///
    /// A MAPI endpoint reports protocol failures as HTTP 200 with a non-zero `X-ResponseCode`, so
    /// a non-2xx status means the request never reached the protocol at all. The common cause is
    /// an endpoint URL missing its `MailboxId` query parameter, which Exchange answers with an
    /// empty HTTP 400 — measured against Exchange Server SE `15.02.2562.045`.
    #[error("{url} answered HTTP {status}{}", suffix(.detail.as_ref()))]
    Http {
        /// The status code.
        status: u16,
        /// The URL that was tried.
        url: String,
        /// Whatever legible text the body held, if any. Frequently nothing: the 400 above has an
        /// empty body, and the only diagnostic Exchange offers is in the HTTP reason phrase, which
        /// this crate's HTTP client does not surface.
        detail: Option<String>,
    },

    /// The bytes were not what the protocol says they should be, or the request was not one the
    /// session could make.
    #[error(transparent)]
    Protocol(#[from] mapi_proto::Error),

    /// A previous round trip failed in a way that leaves the Session Context's state unknown, so
    /// this connection will not be used again.
    ///
    /// MAPI/HTTP allows exactly one request in flight per Session Context. When a request fails
    /// in transit there is no way to tell whether the server processed it, and sending the next
    /// one regardless is how a client ends up reading somebody else's answer. Reconnect.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.3.3.3 — `X-ResponseCode` 15, one request at a time
    #[error("this connection is no longer usable and must be re-established: {cause}")]
    Poisoned {
        /// What went wrong originally.
        cause: String,
    },

    /// The server ran the batch and refused one of the ROPs in it.
    #[error("{during} was refused: {code}")]
    Rop {
        /// Which operation was being performed, in the caller's terms.
        during: &'static str,
        /// What the server said.
        code: ErrorCode,
    },

    /// The mailbox is not on this server.
    ///
    /// Log on again against `server_name`. This crate does not follow the redirect itself: the new
    /// server needs its own endpoint URL, which comes from Autodiscover rather than from the
    /// distinguished name in this response.
    ///
    /// [MS-OXCSTOR] §2.2.1.1.2 — `RopLogon` redirect response
    #[error("the mailbox is not on this server; log on at {server_name}")]
    WrongServer {
        /// The distinguished name of the server holding the mailbox.
        server_name: String,
    },

    /// The logon response did not include one of the thirteen folders it names.
    #[error("the logon response did not include the {folder} folder")]
    MissingFolder {
        /// The folder that was asked for.
        folder: WellKnownFolder,
    },

    /// This mailbox has no such special folder.
    ///
    /// Ordinary rather than exceptional: Exchange creates the folders of [MS-OXOSFLD] §2.2.3 on
    /// demand, so a mailbox nobody has written a journal entry in has no Journal folder and no
    /// property naming one. `state` carries what the mailbox actually said, which is what tells a
    /// missing folder apart from an entry id the server would not convert.
    ///
    /// [`Logon::special_folders`](crate::Logon::special_folders) reports every folder's state
    /// instead of failing, and is the call to reach for when the absence is not an error.
    #[error("this mailbox has no {folder} folder: {state}")]
    MissingSpecialFolder {
        /// The folder that was asked for.
        folder: SpecialFolder,
        /// What the mailbox said about it.
        state: String,
    },

    /// The server answered, correctly, with something other than what was asked for.
    #[error("expected {expected} in the response, found {found}")]
    Unexpected {
        /// What the request should have produced.
        expected: &'static str,
        /// What came back instead.
        found: &'static str,
    },

    /// The server would not produce a response this large.
    ///
    /// The remedy is to ask for less: a smaller page from
    /// [`TableRead::page_size`](crate::TableRead::page_size), or fewer bytes per stream read.
    ///
    /// **Not, despite what the documents say, a larger buffer.** [MS-OXCROPS] §3.1.5.1.2 has the
    /// client resend with the output buffer set to at least `SizeNeeded`; this crate already asks
    /// for 64 KiB, and Exchange Server SE `15.02.2562.045` reports a `SizeNeeded` of 32,767 in
    /// every case measured, across a thirteenfold range of `MaxRopOut`. Its effective ceiling is
    /// about 32 KiB and raising `MaxRopOut` does not move it — measured at `0x00040000`, the
    /// maximum [MS-OXCRPC] §3.1.4.2 allows. `size_needed` is reported as received rather than
    /// interpreted, because a server that starts computing it is a finding.
    ///
    /// [MS-OXCROPS] §2.2.15.1 — `RopBufferTooSmall`
    /// [MS-OXCROPS] §3.1.5.1.2 — the remedy, which does not apply here
    #[error(
        "the server would not produce a response this large; it asked for a {size_needed}-byte \
         output buffer, which is not more than this crate already requests. Ask for less: a \
         smaller page, or fewer bytes per stream read"
    )]
    ResponseTooLarge {
        /// The buffer size the server reported, as received.
        size_needed: u16,
    },

    /// The server is busy and asked to be left alone for a while.
    ///
    /// [MS-OXCROPS] §2.2.15.2 — `RopBackoff`
    #[error("the server asked for a backoff of {duration_ms} ms")]
    Backoff {
        /// How long the server asked for, in milliseconds.
        duration_ms: u32,
    },

    /// Autodiscover could not be parsed or its address was not usable.
    #[cfg(feature = "autodiscover")]
    #[error(transparent)]
    Autodiscover(#[from] mapi_autodiscover::Error),

    /// Every Autodiscover candidate was tried and none produced a MAPI/HTTP endpoint.
    #[cfg(feature = "autodiscover")]
    #[error("Autodiscover found no MAPI/HTTP endpoint for {address}; tried {}", schemes(.tried))]
    NoEndpoint {
        /// The address that was looked up.
        address: String,
        /// Every URL that was tried, in order.
        tried: Vec<String>,
    },

    /// Autodiscover redirected more times than it is worth following.
    #[cfg(feature = "autodiscover")]
    #[error("Autodiscover redirected more than {limit} times, which is a loop")]
    TooManyRedirects {
        /// The hop limit that was reached.
        limit: usize,
    },
}

/// Formats a list for a message, so an empty one reads as a sentence rather than as nothing.
fn schemes(values: &[String]) -> String {
    if values.is_empty() {
        return "nothing".to_owned();
    }
    values.join(", ")
}

/// Appends a server's own words to a message, when it had any.
fn suffix(detail: Option<&String>) -> String {
    detail.map_or_else(String::new, |text| format!(": {text}"))
}
