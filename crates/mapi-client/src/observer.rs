//! Watching the bytes go past.
//!
//! This module is private, so everything a caller needs to know is documented on [`Observer`] and
//! [`Exchange`] themselves, which are re-exported.

use core::fmt::Debug;

use mapi_proto::{Headers, Request, RequestType};

/// One request and the response it produced.
///
/// Borrowed rather than owned: an observer that only wants a length or a header should not pay for
/// a copy of a 64 KiB ROP buffer. Keep what you need.
#[derive(Clone, Copy, Debug)]
pub struct Exchange<'a> {
    request: &'a Request,
    status: u16,
    response_headers: &'a Headers,
    response_body: &'a [u8],
}

impl<'a> Exchange<'a> {
    pub(crate) const fn new(
        request: &'a Request,
        status: u16,
        response_headers: &'a Headers,
        response_body: &'a [u8],
    ) -> Self {
        Self {
            request,
            status,
            response_headers,
            response_body,
        }
    }

    /// Which request type this was, as `X-RequestType` names it.
    #[must_use]
    pub const fn request_type(&self) -> RequestType {
        self.request.request_type()
    }

    /// The headers sent, which are the protocol's own and never include `Authorization`.
    #[must_use]
    pub const fn request_headers(&self) -> &'a Headers {
        self.request.headers()
    }

    /// The request body exactly as it was sent.
    #[must_use]
    pub fn request_body(&self) -> &'a [u8] {
        self.request.body()
    }

    /// The HTTP status the server answered with.
    ///
    /// Worth reading rather than assuming: a MAPI endpoint reports protocol-level refusals as 200
    /// with a non-zero `X-ResponseCode`, so a status that is *not* 200 means the request never
    /// reached the protocol at all.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// The response headers, including every `Set-Cookie`.
    #[must_use]
    pub const fn response_headers(&self) -> &'a Headers {
        self.response_headers
    }

    /// The response payload exactly as it arrived: the meta-tag preamble, then the body.
    ///
    /// This is what [`Session::on_response`](mapi_proto::Session::on_response) is given, before
    /// anything has been parsed out of it.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.7 — response meta-tags
    #[must_use]
    pub const fn response_body(&self) -> &'a [u8] {
        self.response_body
    }
}

/// Something that wants to see every exchange.
///
/// A MAPI response is not readable by inspection: a wrong `RopBuffer` looks exactly like a right
/// one until something decodes it. So the two questions worth asking of a misbehaving deployment —
/// *what did we send* and *what came back* — can only be answered by keeping the bytes. That is
/// what this is for. It is also how `mapi-cli` captures this repository's fixture corpus, so the
/// capture path is the ordinary diagnostic path rather than a second implementation that only runs
/// when somebody remembers to run it.
///
/// Install one with [`MapiClientBuilder::observer`](crate::MapiClientBuilder::observer).
///
/// ```
/// use std::sync::{Arc, Mutex};
///
/// use mapi_client::{Exchange, MapiClient, Observer};
///
/// /// Keeps every exchange, newest last.
/// #[derive(Debug, Default)]
/// struct Transcript(Mutex<Vec<(String, usize)>>);
///
/// impl Observer for Transcript {
///     fn observe(&self, exchange: &Exchange<'_>) {
///         let Ok(mut entries) = self.0.lock() else {
///             return;
///         };
///         entries.push((
///             exchange.request_type().to_string(),
///             exchange.response_body().len(),
///         ));
///     }
/// }
///
/// let transcript = Arc::new(Transcript::default());
/// let builder = MapiClient::builder().observer(Arc::clone(&transcript));
/// // ... drive the client, then read what `transcript` collected.
/// # let _ = (builder, transcript);
/// ```
///
/// # What is and is not seen
///
/// Every exchange that produced an answer, whatever its HTTP status — including the 401 that means
/// the credentials were refused, and the 400 that means the endpoint URL is missing its
/// `MailboxId` parameter. A request that never got an answer at all is not an exchange and is not
/// reported; the error the caller receives is the whole story there.
///
/// **No credential ever reaches an observer.** The `Authorization` header is added by the HTTP
/// client below this layer and is not part of the request this crate builds, so it is not in
/// [`Exchange::request_headers`] and cannot be logged by accident. Everything else is verbatim:
/// session cookies, the distinguished name in a `Connect` body, and whatever the mailbox holds.
/// Treat a transcript as being as sensitive as the mailbox it came from.
///
/// # Implementing one
///
/// [`observe`](Observer::observe) is called from whichever task drove the request, with the
/// exchange borrowed for the duration of the call — so an implementation that is slow makes the
/// request that triggered it look slow. Copy what you need and return.
///
/// [`Debug`] is a supertrait so that a client carrying an observer still prints, which
/// `missing_debug_implementations` would otherwise make impossible to satisfy.
pub trait Observer: Debug + Send + Sync {
    /// Reports one completed exchange.
    fn observe(&self, exchange: &Exchange<'_>);
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use mapi_proto::{LegacyDn, Session};

    use super::*;

    #[derive(Debug, Default)]
    struct Recorder(Mutex<Vec<(RequestType, u16, usize)>>);

    impl Observer for Recorder {
        fn observe(&self, exchange: &Exchange<'_>) {
            self.0.lock().unwrap().push((
                exchange.request_type(),
                exchange.status(),
                exchange.response_body().len(),
            ));
        }
    }

    /// Everything an `Exchange` hands over comes from the request and the response it was built
    /// from, so this is the test that a field is not quietly wired to the wrong source.
    #[test]
    fn an_exchange_reports_both_halves() {
        let user_dn = LegacyDn::new("/o=Example/cn=alice").unwrap();
        let mut session = Session::new();
        let request = session.begin_connect(&user_dn).unwrap();

        let mut response_headers = Headers::new();
        response_headers.append("X-ResponseCode", "0");
        let response_body = b"PROCESSING\r\nDONE\r\n\r\n".to_vec();

        let exchange = Exchange::new(&request, 200, &response_headers, &response_body);

        assert_eq!(exchange.request_type(), RequestType::Connect);
        assert_eq!(
            exchange.request_headers().get("X-RequestType"),
            Some("Connect")
        );
        assert!(exchange.request_headers().get("Authorization").is_none());
        assert_eq!(exchange.request_body(), request.body());
        assert_eq!(exchange.status(), 200);
        assert_eq!(exchange.response_headers().get("X-ResponseCode"), Some("0"));
        assert_eq!(exchange.response_body(), response_body);

        // Copy, so an observer can keep one without borrowing the borrow.
        let copied = exchange;
        assert_eq!(copied.status(), exchange.status());
    }

    /// The shape the documentation promises: an `Arc` the caller keeps a handle to, so what the
    /// observer collected is readable after the client has finished with it.
    #[test]
    fn an_observer_is_shared_rather_than_given_away() {
        let recorder = Arc::new(Recorder::default());
        // Method syntax, not `Arc::clone(&recorder)`: the latter would infer its type parameter
        // from the annotation and then fail to find an `&Arc<dyn Observer>` to clone.
        let observer: Arc<dyn Observer> = recorder.clone();
        let user_dn = LegacyDn::new("/o=Example/cn=alice").unwrap();
        let mut session = Session::new();
        let request = session.begin_connect(&user_dn).unwrap();
        let headers = Headers::new();
        observer.observe(&Exchange::new(&request, 401, &headers, b"nope"));
        let seen = recorder.0.lock().unwrap().clone();
        assert_eq!(seen, vec![(RequestType::Connect, 401, 4)]);
    }
}
