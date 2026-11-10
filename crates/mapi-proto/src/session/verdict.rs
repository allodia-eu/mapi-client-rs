//! What a response's headers say before its body is looked at: the transport's verdict, how long
//! the Session Context has left, and the server's own words when it refused.
//!
//! [MS-OXCMAPIHTTP] §2.2.3.3.3 — `X-ResponseCode`
//! [MS-OXCMAPIHTTP] §2.2.3.3.8 — `X-ExpirationInfo`

use core::time::Duration;

use crate::http::{Headers, Payload};

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
