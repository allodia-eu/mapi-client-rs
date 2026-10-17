//! The state machine: what is legal when, and what a response means.
//!
//! [`Session`] owns every byte and every piece of protocol state; the caller owns the I/O. Each
//! `begin_*` method hands back a [`Request`] to send, and [`Session::on_response`] takes the
//! headers and payload back. Nothing here opens a socket, spawns a task or reads a clock.
//!
//! Sequencing is enforced rather than documented: MAPI/HTTP allows exactly one request in flight
//! per Session Context, and violating that is reported by the server as `X-ResponseCode` 15
//! (Invalid Sequence) — a diagnostic that points nowhere near the cause.
//!
//! [MS-OXCMAPIHTTP] §3.1.4 — client higher-layer triggered events
//! [MS-OXCMAPIHTTP] §2.2.3.3.3 — `X-ResponseCode` 15, one request at a time

use crate::error::{Error, Result};
use crate::http::{
    ConnectResponse, CookieJar, ExecuteResponse, Headers, Lcid, Payload, Request, RequestType,
    ResponseCode, connect_body, disconnect_body, execute_body,
};
use crate::oxcdata::{LegacyDn, PropertyTag};
use crate::rop::{Decoding, ObjectHandle, RopBatch, RopBuffer, decode_all};

mod builder;
mod columns;
mod outcome;

pub use builder::SessionBuilder;
pub use outcome::{Connected, Execution, Outcome};

/// `Content-Type` for every request. [MS-OXCMAPIHTTP] §2.2.3.2.2
const CONTENT_TYPE: &str = "application/mapi-http";

/// Default `X-ClientApplication`.
///
/// The header's documented format is `Outlook/15.xx.xxxx.xxxx` and servers read it as a version,
/// so the default is a value in that shape rather than this crate's own name. Override it with
/// [`SessionBuilder::client_application`] if you would rather be identifiable.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.6 — `X-ClientApplication`
const DEFAULT_CLIENT_APPLICATION: &str = "Outlook/15.00.0847.4040";

/// Default GUID for `X-RequestId` and `X-ClientInfo`.
///
/// The specification requires this GUID to be unique per client instance, and a crate that
/// performs no I/O cannot obtain randomness to make one. A transport that can — such as
/// `mapi-client` — sets its own through [`SessionBuilder`].
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.2 — `X-RequestId`
/// [MS-OXCMAPIHTTP] §2.2.3.3.4 — `X-ClientInfo`
const DEFAULT_GUID: &str = "{2EF33C39-49C8-421C-B876-CDF7F2AC3AA0}";

/// What the session is waiting for, and what it needs to interpret the answer.
#[derive(Clone, Debug)]
enum Pending {
    /// Carries the distinguished name, so a refusal can name what failed to map.
    Connect(LegacyDn),
    /// Carries each handle slot's column set, for decoding `RopQueryRows` responses, the tag list
    /// of each property fetch, for decoding those, and the slots the batch released, whose column
    /// sets must not outlive them.
    Execute {
        columns: Vec<Option<Vec<PropertyTag>>>,
        property_tags: Vec<Vec<PropertyTag>>,
        /// What each slot held when the batch was built, so a released slot can be resolved back
        /// to the handle whose columns are to be forgotten.
        handles: Vec<ObjectHandle>,
        released: Vec<u8>,
    },
    Disconnect,
    Ping,
}

/// One MAPI/HTTP Session Context, driven entirely by the caller.
///
/// ```
/// use mapi_proto::{LegacyDn, Session};
///
/// let mut session = Session::new();
/// let user_dn = LegacyDn::new("/o=First/ou=Exchange Administrative Group/cn=alice")?;
///
/// let request = session.begin_connect(&user_dn)?;
/// assert_eq!(request.request_type().as_str(), "Connect");
/// assert_eq!(request.headers().get("Content-Type"), Some("application/mapi-http"));
///
/// // POST request.body() to the endpoint with request.headers(), then hand the response back:
/// //     let outcome = session.on_response(&response_headers, &response_payload)?;
/// # Ok::<(), mapi_proto::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct Session {
    client_application: String,
    client_info: String,
    request_guid: String,
    counter: u64,
    lcid_sort: Lcid,
    lcid_string: Lcid,
    cookies: CookieJar,
    pending: Option<Pending>,
    /// Whether a request was given up on before its response arrived. See [`Session::abandon`].
    abandoned: bool,
    connected: bool,
    table_columns: Vec<(ObjectHandle, Vec<PropertyTag>)>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    /// A session with the default client identity.
    #[must_use]
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Configures the client identity headers before building a session.
    #[must_use]
    pub fn builder() -> SessionBuilder {
        SessionBuilder::new()
    }

    /// Whether a Session Context has been established.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    /// Whether a request is in flight, which is the state in which no new one may be sent.
    #[must_use]
    pub const fn is_awaiting_response(&self) -> bool {
        self.pending.is_some()
    }

    /// Whether a request was given up on before its response arrived, which leaves only
    /// [`begin_disconnect`](Self::begin_disconnect) for this Session Context. See
    /// [`abandon`](Self::abandon).
    #[must_use]
    pub const fn is_abandoned(&self) -> bool {
        self.abandoned
    }

    /// Forgets the request in flight, for a caller that will never hand its response back.
    ///
    /// The caller's side of cancellation: a transport that dropped a request part way — a
    /// deadline, a `select!` that chose another branch, a connection that failed — calls this
    /// rather than leaving the session waiting for an answer that is not coming, which would refuse
    /// every later request, `Disconnect` included.
    ///
    /// **What the server did with the request is unknowable**, so the session stops there. Once a
    /// request in a Session Context is abandoned, [`execute`](Self::execute) and
    /// [`begin_ping`](Self::begin_ping) are refused and only
    /// [`begin_disconnect`](Self::begin_disconnect) is allowed:
    ///
    /// * An abandoned `Execute` may have opened handles this session never learnt of, or released
    ///   ones whose column sets it still holds — so the handle table is no longer known, and a
    ///   table read against it could decode rows by another table's columns.
    /// * [MS-OXCMAPIHTTP] §3.2.5.1 has the server "fail every subsequent request" with
    ///   `X-ResponseCode` 15 once it sees two at once in a Session Context, and a request the
    ///   client gave up on may still be running there. Disconnecting risks that once, to free the
    ///   server's context now rather than when it times out; anything more would risk it again.
    ///
    /// The remedy [MS-OXCMAPIHTTP] §3.1.7.2 gives for a response that never arrived is a new
    /// Session Context, passing this one's [`cookies`](Self::cookies) so the server can clean the
    /// old one up (§3.1.5.7).
    ///
    /// Before a Session Context exists there is nothing to lose: an abandoned `Connect` or `PING`
    /// leaves the session as it was, free to try again.
    ///
    /// Returns whether a request was in flight. With none, nothing changes.
    pub fn abandon(&mut self) -> bool {
        let abandoned = self.pending.take().is_some();
        if abandoned && self.connected {
            self.abandoned = true;
            self.table_columns.clear();
        }
        abandoned
    }

    /// The session cookies, which identify the Session Context to the server.
    #[must_use]
    pub const fn cookies(&self) -> &CookieJar {
        &self.cookies
    }

    /// Builds the `Connect` request that establishes a Session Context.
    ///
    /// `user_dn` is Autodiscover's `<User><LegacyDN>`, passed through verbatim. The Session
    /// Context's locale is fixed here and cannot be changed afterwards; set it with
    /// [`SessionBuilder::locale`] before building the session.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidState`] if a request is already in flight or the session is already
    /// connected.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1 — `Connect`
    pub fn begin_connect(&mut self, user_dn: &LegacyDn) -> Result<Request> {
        self.check_idle("send Connect")?;
        if self.connected {
            return Err(Error::InvalidState {
                attempted: "send Connect",
                reason: "this session already has a Session Context",
            });
        }

        let body = connect_body(user_dn, self.lcid_sort, self.lcid_string);
        let request = self.request(RequestType::Connect, body);
        self.pending = Some(Pending::Connect(user_dn.clone()));
        Ok(request)
    }

    /// Builds a `Connect` that re-establishes this session's Session Context, passing the cookies
    /// of the one it replaces.
    ///
    /// [MS-OXCMAPIHTTP] §3.1.5.7: "the only difference between reconnecting and an initial
    /// connection is that the client passes all existing cookies that are associated with the
    /// previous Session Context", which "allows the server to clean up the previous context in a
    /// timely fashion to prevent session limits from being reached". It is §3.1.7.2's remedy for a
    /// response that never arrived, and the only way to free a context whose `Disconnect` the
    /// server refuses — which is what an [abandoned](Self::abandon) request leaves behind when the
    /// server finished it: Exchange advances a sequence cookie on every response, so the next
    /// request carries the value from before the one the client never read, and is refused as
    /// `X-ResponseCode` 15.
    ///
    /// **Everything the old context held is gone**: its handles, and with them every table's
    /// column set, which this session forgets once the answer arrives. A successful reconnect also
    /// clears an abandonment, since the new context has none of the old one's unknowns.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidState`] if a request is in flight or there is no Session Context to
    /// re-establish — a session that never connected sends [`begin_connect`](Self::begin_connect).
    ///
    /// [MS-OXCMAPIHTTP] §3.1.5.7 — reconnecting and establishing a new Session Context
    pub fn begin_reconnect(&mut self, user_dn: &LegacyDn) -> Result<Request> {
        self.check_idle("send a reconnecting Connect")?;
        if !self.connected {
            return Err(Error::InvalidState {
                attempted: "send a reconnecting Connect",
                reason: "there is no Session Context to re-establish; send Connect first",
            });
        }

        let body = connect_body(user_dn, self.lcid_sort, self.lcid_string);
        let request = self.request(RequestType::Connect, body);
        self.pending = Some(Pending::Connect(user_dn.clone()));
        Ok(request)
    }

    /// Builds the `Execute` request that runs a batch of ROPs in one round trip.
    ///
    /// The batch's column sets are remembered here, so the rows that come back decode without the
    /// caller passing columns to anything.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidState`] if a request is in flight or no Session Context exists, plus
    /// whatever the batch itself recorded while it was being built — an unknown handle slot, or a
    /// buffer past what its length fields can describe.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.2 — `Execute`
    pub fn execute(&mut self, batch: RopBatch) -> Result<Request> {
        self.check_idle("send Execute")?;
        if !self.connected {
            return Err(Error::InvalidState {
                attempted: "send Execute",
                reason: "no Session Context yet; send Connect first",
            });
        }

        self.check_not_abandoned("send Execute")?;
        let mut built = batch.build()?;
        self.recall_columns(&mut built.columns, &built.initial_handles);

        let request = self.request(RequestType::Execute, execute_body(&built.bytes));
        self.pending = Some(Pending::Execute {
            columns: built.columns,
            property_tags: built.property_tags,
            handles: built.initial_handles,
            released: built.released,
        });
        Ok(request)
    }

    /// Builds the `Disconnect` request that tears the Session Context down.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidState`] if a request is in flight or there is no Session Context.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.3 — `Disconnect`
    pub fn begin_disconnect(&mut self) -> Result<Request> {
        self.check_idle("send Disconnect")?;
        if !self.connected {
            return Err(Error::InvalidState {
                attempted: "send Disconnect",
                reason: "there is no Session Context to disconnect",
            });
        }

        let request = self.request(RequestType::Disconnect, disconnect_body());
        self.pending = Some(Pending::Disconnect);
        Ok(request)
    }

    /// Builds a `PING` request.
    ///
    /// `PING` asks whether the endpoint is "reachable and operational" and needs no Session
    /// Context: it has no request body, no response body, and nothing in it refers to a session.
    /// Measured against Exchange Server SE `15.02.2562.045`, which answers `X-ResponseCode: 0`
    /// both before a `Connect` and after a `Disconnect`.
    ///
    /// So it is the cheapest available proof that the URL is right, that authentication works and
    /// that whatever answers speaks MAPI/HTTP.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidState`] if a request is already in flight.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.6 — `PING`
    pub fn begin_ping(&mut self) -> Result<Request> {
        self.check_idle("send PING")?;
        self.check_not_abandoned("send PING")?;
        let request = self.request(RequestType::Ping, Vec::new());
        self.pending = Some(Pending::Ping);
        Ok(request)
    }

    /// Interprets the response to the request in flight.
    ///
    /// `payload` is the HTTP response body after chunked transfer decoding and before anything
    /// else: the meta-tag preamble is part of it and is parsed here.
    ///
    /// # Errors
    ///
    /// [`Error::MissingResponseCode`] when the `X-ResponseCode` header is absent — which is what
    /// an endpoint URL missing its `MailboxId` parameter looks like. [`Error::Transport`] when
    /// that code is non-zero. [`Error::ConnectFailed`] or [`Error::ExecuteFailed`] when the server
    /// refused the request itself, and a decoding error if the body does not match its documented
    /// layout.
    pub fn on_response(&mut self, headers: &Headers, payload: &[u8]) -> Result<Outcome> {
        // A response ends the in-flight request whatever it says, so take it before any `?`.
        let pending = self.pending.take().ok_or(Error::NoRequestInFlight)?;

        for value in headers.get_all("Set-Cookie") {
            self.cookies.absorb(value);
        }

        let code = headers
            .get("X-ResponseCode")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .map(ResponseCode::new)
            .ok_or(Error::MissingResponseCode)?;

        let payload = Payload::parse(payload);
        if !code.is_success() {
            return Err(Error::Transport {
                code,
                diagnostic: diagnostic(payload.body()),
            });
        }

        match pending {
            Pending::Connect(user_dn) => self.on_connect(payload.body(), user_dn),
            Pending::Execute {
                columns,
                property_tags,
                handles,
                released,
            } => self.on_execute(
                payload.body(),
                &columns,
                &property_tags,
                &handles,
                &released,
            ),
            Pending::Disconnect => {
                self.connected = false;
                self.abandoned = false;
                self.cookies.clear();
                self.table_columns.clear();
                Ok(Outcome::Disconnected)
            }
            Pending::Ping => Ok(Outcome::Pong),
        }
    }

    fn on_connect(&mut self, body: &[u8], user_dn: LegacyDn) -> Result<Outcome> {
        let response = ConnectResponse::parse(body)?;
        if !response.is_success() {
            return Err(Error::ConnectFailed {
                status: response.status_code,
                code: response.error_code,
                user_dn,
            });
        }

        self.connected = true;
        self.abandoned = false;
        self.table_columns.clear();
        Ok(Outcome::Connected(Connected {
            display_name: response.display_name,
            dn_prefix: response.dn_prefix,
            polls_max: response.polls_max,
            retry_count: response.retry_count,
            retry_delay: response.retry_delay,
        }))
    }

    fn on_execute(
        &mut self,
        body: &[u8],
        columns: &[Option<Vec<PropertyTag>>],
        property_tags: &[Vec<PropertyTag>],
        handles: &[ObjectHandle],
        released: &[u8],
    ) -> Result<Outcome> {
        let response = ExecuteResponse::parse(body)?;
        if !response.is_success() {
            return Err(Error::ExecuteFailed {
                status: response.status_code,
                code: response.error_code,
            });
        }

        let buffer = RopBuffer::parse(&response.rop_buffer)?;
        let responses = decode_all(
            &buffer.rops,
            Decoding {
                columns,
                property_tags,
            },
        )?;
        self.remember_columns(columns, &buffer.handles);
        self.forget_columns(released, handles, &buffer.handles);

        Ok(Outcome::Executed(Execution {
            responses,
            handles: buffer.handles,
        }))
    }

    fn check_not_abandoned(&self, attempted: &'static str) -> Result<()> {
        if self.abandoned {
            return Err(Error::InvalidState {
                attempted,
                reason: concat!(
                    "a request was abandoned before its response arrived, so whether the server ",
                    "acted on it is unknown; only Disconnect is left",
                ),
            });
        }
        Ok(())
    }

    fn check_idle(&self, attempted: &'static str) -> Result<()> {
        if self.pending.is_some() {
            return Err(Error::InvalidState {
                attempted,
                reason: "a request is already in flight, and a Session Context allows only one",
            });
        }
        Ok(())
    }

    /// Builds the headers every request carries, then the request itself.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.2.1 — common request format
    fn request(&mut self, request_type: RequestType, body: Vec<u8>) -> Request {
        self.counter = self.counter.saturating_add(1);

        let mut headers = Headers::new();
        headers
            .append("Content-Type", CONTENT_TYPE)
            .append("X-RequestType", request_type.as_str())
            .append(
                "X-RequestId",
                format!("{}:{}", self.request_guid, self.counter),
            )
            .append("X-ClientApplication", self.client_application.clone())
            .append("X-ClientInfo", self.client_info.clone());

        if let Some(cookie) = self.cookies.header_value() {
            headers.append("Cookie", cookie);
        }

        Request::new(request_type, headers, body)
    }
}

/// Extracts whatever diagnostic text a server put in a failure body.
///
/// Servers answer a rejected request with an HTML error page rather than a protocol body, and the
/// one sentence in it is often the only statement of what was actually wrong.
fn diagnostic(body: &[u8]) -> Option<String> {
    // A binary body is a protocol response that arrived under a failing code, not a message; only
    // something that is legible as text can be quoted back to a human.
    let text = core::str::from_utf8(body).ok()?;
    let paragraph = text
        .split_once("<p>")
        .and_then(|(_, tail)| tail.split_once("</p>"))
        .map(|(inner, _)| inner);

    let text = paragraph.unwrap_or(text).trim();
    let legible = !text.is_empty()
        && !text.contains('<')
        && !text.chars().any(|c| c.is_control() && !c.is_whitespace());

    legible.then(|| text.chars().take(200).collect())
}

#[cfg(test)]
mod tests;
