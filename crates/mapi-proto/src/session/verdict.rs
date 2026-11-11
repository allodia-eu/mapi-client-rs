//! What a response's headers say before its body is looked at: the transport's verdict, how long
//! the Session Context has left, and the server's own words when it refused.
//!
//! [MS-OXCMAPIHTTP] §2.2.3.3.3 — `X-ResponseCode`
//! [MS-OXCMAPIHTTP] §2.2.3.3.8 — `X-ExpirationInfo`

use core::time::Duration;

use crate::error::{Error, Result};
use crate::http::{Headers, Payload, ResponseCode};

/// The transport's verdict on a request, and whether it was given only after `DONE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Verdict {
    pub(super) code: ResponseCode,
    pub(super) after_done: bool,
}

/// The transport's verdict on a request: the `X-ResponseCode` header, unless the headers after
/// `DONE` overturned it.
///
/// [MS-OXCMAPIHTTP] §3.2.5.2: the server "will include a X-ResponseCode header ... if a failure
/// occurs after the initial response is sent", which "gives the server the ability to later fail
/// the request and return a different value". The first verdict is given before the request has
/// run, so a later failing one is the one that stands; a later `0` cannot undo an early failure,
/// because a server that failed a request up front sends no `DONE` to put one after.
///
/// # Errors
///
/// [`Error::MissingResponseCode`] when the HTTP headers carry none at all.
pub(super) fn response_code(headers: &Headers, payload: &Payload) -> Result<Verdict> {
    let parse = |value: &str| value.trim().parse::<u32>().ok().map(ResponseCode::new);
    let first = headers
        .get("X-ResponseCode")
        .and_then(parse)
        .ok_or(Error::MissingResponseCode)?;
    let later = payload
        .headers()
        .get_all("X-ResponseCode")
        .filter_map(parse)
        .find(|code| !code.is_success());
    Ok(match later.filter(|_| first.is_success()) {
        Some(code) => Verdict {
            code,
            after_done: true,
        },
        None => Verdict {
            code: first,
            after_done: false,
        },
    })
}

/// How long the server will keep the Session Context once nothing more is sent, if the response
/// said.
///
/// Read from the HTTP headers, where Exchange puts it, and failing that from the headers that
/// follow `DONE`, where [MS-OXCMAPIHTTP] §3.2.5.2 lets a server put any header it settles only
/// once the request has run. A value that is not a number of milliseconds is no statement at
/// all, rather than a zero that would read as "already expired".
pub(super) fn expiration(headers: &Headers, payload: &Payload) -> Option<Duration> {
    headers
        .get("X-ExpirationInfo")
        .or_else(|| payload.headers().get("X-ExpirationInfo"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_millis)
}

/// Extracts whatever diagnostic text a server put in a failure body.
///
/// Servers answer a rejected request with an HTML error page rather than a protocol body, and the
/// one sentence in it is often the only statement of what was actually wrong.
pub(super) fn diagnostic(body: &[u8]) -> Option<String> {
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
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Headers {
        pairs.iter().map(|(name, value)| (*name, *value)).collect()
    }

    #[test]
    fn a_failure_after_done_overturns_the_first_verdict() {
        let ok = headers(&[("X-ResponseCode", "0")]);
        let clean = Payload::parse(b"PROCESSING\r\nDONE\r\nX-ElapsedTime: 4\r\n\r\n");
        let up_front = |code| {
            Ok(Verdict {
                code,
                after_done: false,
            })
        };
        assert_eq!(response_code(&ok, &clean), up_front(ResponseCode::SUCCESS));

        let failed = Payload::parse(b"PROCESSING\r\nDONE\r\nX-ResponseCode: 10\r\n\r\n");
        assert_eq!(
            response_code(&ok, &failed),
            Ok(Verdict {
                code: ResponseCode::CONTEXT_NOT_FOUND,
                after_done: true
            })
        );

        let restated = Payload::parse(b"PROCESSING\r\nDONE\r\nX-ResponseCode: 0\r\n\r\n");
        assert_eq!(
            response_code(&ok, &restated),
            up_front(ResponseCode::SUCCESS)
        );

        let refused = headers(&[("X-ResponseCode", "7")]);
        assert_eq!(
            response_code(&refused, &restated),
            up_front(ResponseCode::MISSING_HEADER),
            "a later 0 cannot undo an early failure"
        );
        assert_eq!(
            response_code(&headers(&[]), &failed),
            Err(Error::MissingResponseCode),
            "the HTTP header is required even when a later one is present"
        );
    }

    #[test]
    fn the_expiration_comes_from_the_headers_then_from_after_done() {
        let empty = Payload::parse(b"");
        assert_eq!(
            expiration(&headers(&[("X-ExpirationInfo", "900000")]), &empty),
            Some(Duration::from_mins(15))
        );

        let trailing = Payload::parse(b"PROCESSING\r\nDONE\r\nX-ExpirationInfo: 300000\r\n\r\n");
        assert_eq!(
            expiration(&headers(&[]), &trailing),
            Some(Duration::from_mins(5))
        );
        assert_eq!(
            expiration(&headers(&[("X-ExpirationInfo", "60000")]), &trailing),
            Some(Duration::from_mins(1)),
            "the HTTP header, which is where Exchange puts it, wins"
        );
    }

    #[test]
    fn an_expiration_that_is_no_number_is_no_statement() {
        let empty = Payload::parse(b"");
        assert_eq!(expiration(&headers(&[]), &empty), None);
        for value in ["", "soon", "-1", "1.5"] {
            assert_eq!(
                expiration(&headers(&[("X-ExpirationInfo", value)]), &empty),
                None,
                "{value:?}"
            );
        }
    }
}
