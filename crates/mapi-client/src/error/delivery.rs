//! How far a failed request got: whether the server can have acted on it.
//!
//! [MS-OXCMAPIHTTP] §3.1.7 splits a communication failure in two — while the request was being
//! sent, and after the whole of it had been — because the remedies differ. The first may be sent
//! again as it stands; after the second, whether the server acted cannot be known. That is the
//! question a caller retrying a write has to answer, and it is answered here once, for every
//! error, rather than by each caller reading variants.

use super::Error;

/// How far a failed request got, and so what retrying it risks.
///
/// [`Error::delivery`] answers it for any error. A read can be retried after any of these; a
/// write, or a submit, only after [`NotSent`](Self::NotSent) or [`Refused`](Self::Refused) —
/// after [`Unknown`](Self::Unknown) it may already have happened, and after
/// [`Processed`](Self::Processed) it did, at least in part.
///
/// [MS-OXCMAPIHTTP] §3.1.7 — handling communication failures
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Delivery {
    /// The request never left: refused before it was sent, or the connection failed before
    /// anything was written. [MS-OXCMAPIHTTP] §3.1.7.1 has such a request "resubmitted as-is",
    /// and this crate does that once by itself before reporting it.
    NotSent,
    /// The server answered without acting on it: a 401 or another refusal before the protocol, a
    /// failing `X-ResponseCode` given up front, or a Session Context it does not have.
    Refused,
    /// The whole request was sent and no complete answer came back, or the server failed it after
    /// accepting it. Whether it acted is unknowable — [MS-OXCMAPIHTTP] §3.1.7.2 — and the Session
    /// Context is replaced before anything else is sent.
    Unknown,
    /// The server acted on the request, and the error is about what it did or what it said: a
    /// refused ROP, a response that would not decode, an answer that was not the one asked for.
    Processed,
}

impl Error {
    /// How far the request that failed got. See [`Delivery`].
    #[must_use]
    pub fn delivery(&self) -> Delivery {
        match self {
            Self::MissingSetting { .. }
            | Self::InvalidEndpoint { .. }
            | Self::PlaintextEndpoint { .. }
            | Self::Setup { .. }
            | Self::Connect { .. }
            | Self::Poisoned { .. }
            | Self::SessionReplaced { .. } => Delivery::NotSent,
            Self::Unauthorized { .. } | Self::SessionLost { .. } => Delivery::Refused,
            // A redirect or a client error says the request never reached the protocol. A server
            // error may come from a proxy that had already passed it on.
            Self::Http { status, .. } if (300..500).contains(status) => Delivery::Refused,
            Self::Http { .. } | Self::Timeout { .. } | Self::Request { .. } => Delivery::Unknown,
            Self::Protocol(error) => protocol(error),
            #[cfg(feature = "autodiscover")]
            Self::Autodiscover(_) | Self::NoEndpoint { .. } | Self::TooManyRedirects { .. } => {
                Delivery::NotSent
            }
            Self::NotRefreshed
            | Self::Rop { .. }
            | Self::WrongServer { .. }
            | Self::MissingFolder { .. }
            | Self::MissingSpecialFolder { .. }
            | Self::Unexpected { .. }
            | Self::ResponseTooLarge { .. }
            | Self::Backoff { .. } => Delivery::Processed,
        }
    }
}

/// The codec's errors split by which side of the wire they arise on.
fn protocol(error: &mapi_proto::Error) -> Delivery {
    use mapi_proto::Error as E;
    match error {
        // Raised while building a request, so it never left.
        E::UnencodableValue { .. }
        | E::ValueTooLarge { .. }
        | E::PropertyTypeMismatch { .. }
        | E::StreamReadTooLarge { .. }
        | E::StreamWriteTooLarge { .. }
        | E::SortColumnNotSet { .. }
        | E::RopBufferTooLarge { .. }
        | E::UnknownHandleSlot { .. }
        | E::TooManyHandles { .. }
        | E::InvalidLegacyDn { .. }
        | E::NoRequestInFlight
        | E::InvalidState { .. }
        | E::IcsScopeMismatch { .. }
        | E::InvalidIcsState { .. } => Delivery::NotSent,
        // The transport's own verdict, given before the request was looked at.
        E::MissingResponseCode | E::Transport { .. } | E::ConnectFailed { .. } => Delivery::Refused,
        // Accepted, then failed: how much of it ran is not known. A failed `Execute` is counted
        // here too, because nothing in the response says whether any of its ROPs ran first.
        E::FailedAfterDone { .. } | E::ExecuteFailed { .. } => Delivery::Unknown,
        // Everything else is raised reading a response, so the server had acted.
        _ => Delivery::Processed,
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use mapi_proto::{ErrorCode, ResponseCode};

    use super::*;

    #[test]
    fn what_never_left_is_not_sent() {
        let connect = Error::Connect {
            url: "https://mail.example.test/".to_owned(),
            source: "refused".into(),
        };
        assert_eq!(connect.delivery(), Delivery::NotSent);
        let replaced = Error::SessionReplaced { during: "reading" };
        assert_eq!(replaced.delivery(), Delivery::NotSent);
        let encoding = Error::Protocol(mapi_proto::Error::TooManyHandles { limit: 256 });
        assert_eq!(encoding.delivery(), Delivery::NotSent);
    }

    #[test]
    fn a_refusal_before_the_protocol_is_refused() {
        for status in [302, 400, 401, 411] {
            let http = Error::Http {
                status,
                url: String::new(),
                detail: None,
            };
            assert_eq!(http.delivery(), Delivery::Refused, "{status}");
        }
        let lost = Error::SessionLost {
            code: ResponseCode::CONTEXT_NOT_FOUND,
            diagnostic: None,
        };
        assert_eq!(lost.delivery(), Delivery::Refused);
        let transport = Error::Protocol(mapi_proto::Error::Transport {
            code: ResponseCode::MISSING_HEADER,
            diagnostic: None,
        });
        assert_eq!(transport.delivery(), Delivery::Refused);
    }

    #[test]
    fn a_request_sent_without_a_whole_answer_is_unknown() {
        let timeout = Error::Timeout {
            url: String::new(),
            after: Duration::from_secs(1),
        };
        assert_eq!(timeout.delivery(), Delivery::Unknown);
        let gateway = Error::Http {
            status: 504,
            url: String::new(),
            detail: None,
        };
        assert_eq!(gateway.delivery(), Delivery::Unknown);
        let late = Error::Protocol(mapi_proto::Error::FailedAfterDone {
            code: ResponseCode::CONTEXT_NOT_FOUND,
            diagnostic: None,
        });
        assert_eq!(late.delivery(), Delivery::Unknown);
    }

    #[test]
    fn an_answer_about_what_was_done_is_processed() {
        let refused = Error::Rop {
            during: "saving a message",
            code: ErrorCode::LOGIN_PERMISSION,
        };
        assert_eq!(refused.delivery(), Delivery::Processed);
        let decoding = Error::Protocol(mapi_proto::Error::NoRequestInFlight);
        assert_eq!(decoding.delivery(), Delivery::NotSent);
        let truncated = Error::Protocol(mapi_proto::Error::Truncated {
            at: 0,
            need: 4,
            have: 0,
        });
        assert_eq!(truncated.delivery(), Delivery::Processed);
    }
}
