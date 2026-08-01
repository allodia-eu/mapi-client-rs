//! The response stream: a transport verdict, a meta-tag preamble, and then the body.
//!
//! A MAPI/HTTP response is not simply "HTTP body = protocol body". The server may hold the
//! connection open, emitting `PROCESSING` and periodic `PENDING` keep-alives, and only then send
//! `DONE`, a second set of headers, a blank line and the binary body. That preamble is inside the
//! payload, after chunked transfer decoding, so an HTTP client hands it over as part of the body.
//!
//! [MS-OXCMAPIHTTP] §2.2.2.2 — common response format
//! [MS-OXCMAPIHTTP] §2.2.7 — response meta-tags

use crate::http::Headers;

/// The `X-ResponseCode` header: the transport's verdict, before any request body is looked at.
///
/// Reported exactly as received. The numbering below is [MS-OXCMAPIHTTP] §2.2.3.3.3's, and
/// Exchange follows it, but a non-Microsoft implementation was observed returning codes whose own
/// diagnostic text belongs to different numbers. Mapping a code to a meaning by one server's table
/// therefore misreports the other, so the raw value and the server's diagnostic text are both kept.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.3 — `X-ResponseCode`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResponseCode(u32);

impl ResponseCode {
    /// `10` — the Session Context was not found; `Connect` again.
    pub const CONTEXT_NOT_FOUND: Self = Self(10);
    /// `16` — the endpoint is disabled.
    pub const ENDPOINT_DISABLED: Self = Self(16);
    /// `6` — the session context cookie is not valid.
    pub const INVALID_CONTEXT_COOKIE: Self = Self(6);
    /// `5` — the `X-RequestType` header is not one the endpoint knows.
    pub const INVALID_REQUEST_TYPE: Self = Self(5);
    /// `15` — more than one request was in flight on one Session Context.
    pub const INVALID_SEQUENCE: Self = Self(15);
    /// `13` — a required cookie is missing.
    pub const MISSING_COOKIE: Self = Self(13);
    /// `7` — a required header is missing.
    pub const MISSING_HEADER: Self = Self(7);
    /// `0` — the request was properly formatted and accepted.
    pub const SUCCESS: Self = Self(0);

    /// Wraps a raw code.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The code as received.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Whether the transport accepted the request.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 == Self::SUCCESS.0
    }

    /// The name [MS-OXCMAPIHTTP] §2.2.3.3.3 gives this code.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0 => "Success",
            1 => "Unknown Failure",
            2 => "Invalid Verb",
            3 => "Invalid Path",
            4 => "Invalid Header",
            5 => "Invalid Request Type",
            6 => "Invalid Context Cookie",
            7 => "Missing Header",
            8 => "Anonymous Not Allowed",
            9 => "Too Large",
            10 => "Context Not Found",
            11 => "No Privilege",
            12 => "Invalid Request Body",
            13 => "Missing Cookie",
            15 => "Invalid Sequence",
            16 => "Endpoint Disabled",
            17 => "Invalid Response",
            18 => "Endpoint Shutting Down",
            _ => return None,
        })
    }
}

impl core::fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} ({})", self.0),
            None => write!(f, "X-ResponseCode {}", self.0),
        }
    }
}

/// A meta-tag from the response preamble.
///
/// [MS-OXCMAPIHTTP] §2.2.7 — response meta-tags
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum MetaTag {
    /// The server has queued the request.
    Processing,
    /// A keep-alive while the server works.
    Pending,
    /// Processing finished; headers and the body follow.
    Done,
}

impl MetaTag {
    fn parse(line: &str) -> Option<Self> {
        match line.to_ascii_uppercase().as_str() {
            "PROCESSING" => Some(Self::Processing),
            "PENDING" => Some(Self::Pending),
            "DONE" => Some(Self::Done),
            _ => None,
        }
    }
}

/// A response payload split into its three parts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Payload {
    meta_tags: Vec<MetaTag>,
    headers: Headers,
    body: Vec<u8>,
}

impl Payload {
    /// The meta-tags seen, in order.
    #[must_use]
    pub fn meta_tags(&self) -> &[MetaTag] {
        &self.meta_tags
    }

    /// The headers that followed `DONE`, such as `X-ElapsedTime` and `X-StartTime`.
    #[must_use]
    pub const fn headers(&self) -> &Headers {
        &self.headers
    }

    /// The request type's own response body, byte for byte.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Splits a payload that has already been de-chunked by the HTTP client.
    ///
    /// Never fails: this parses bytes from a server nobody here controls, and a payload with no
    /// meta-tag preamble at all — an error page, say — is treated as being entirely body rather
    /// than as a protocol violation. The body is carried through byte-exact; running it through a
    /// lossy UTF-8 conversion would corrupt every ROP buffer.
    #[must_use]
    pub fn parse(raw: &[u8]) -> Self {
        let mut meta_tags = Vec::new();
        let mut headers = Headers::new();
        let mut rest = raw;
        let mut done = false;

        while let Some(line_end) = find_crlf(rest) {
            let (line, tail) = split_line(rest, line_end);
            let line = String::from_utf8_lossy(line).trim().to_owned();

            if done {
                if line.is_empty() {
                    return Self {
                        meta_tags,
                        headers,
                        body: tail.to_vec(),
                    };
                }
                if let Some((name, value)) = line.split_once(':') {
                    headers.append(name.trim(), value.trim());
                }
                rest = tail;
                continue;
            }

            let Some(tag) = MetaTag::parse(&line) else {
                // No meta-tag preamble at all: take the whole payload as the body.
                return Self {
                    meta_tags,
                    headers,
                    body: raw.to_vec(),
                };
            };
            meta_tags.push(tag);
            done = tag == MetaTag::Done;
            rest = tail;
        }

        // Ran out of lines. After DONE that means an empty body; before it, there was no preamble.
        Self {
            body: if done { Vec::new() } else { raw.to_vec() },
            meta_tags,
            headers,
        }
    }
}

/// Splits `raw` at a CRLF found at `at`, returning the line and everything after the CRLF.
fn split_line(raw: &[u8], at: usize) -> (&[u8], &[u8]) {
    let line = raw.get(..at).unwrap_or_default();
    let tail = at
        .checked_add(2)
        .and_then(|start| raw.get(start..))
        .unwrap_or_default();
    (line, tail)
}

fn find_crlf(raw: &[u8]) -> Option<usize> {
    raw.windows(2).position(|pair| pair == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_meta_tags_headers_and_a_binary_body() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"PROCESSING\r\nPENDING\r\nDONE\r\n");
        raw.extend_from_slice(b"X-ElapsedTime: 12\r\nX-StartTime: now\r\n\r\n");
        // A body that is deliberately not valid UTF-8, because a ROP buffer never is.
        raw.extend_from_slice(&[0x00, 0xFF, 0xFE, 0x80, 0x01]);

        let payload = Payload::parse(&raw);
        assert_eq!(
            payload.meta_tags(),
            [MetaTag::Processing, MetaTag::Pending, MetaTag::Done]
        );
        assert_eq!(payload.headers().get("X-ElapsedTime"), Some("12"));
        assert_eq!(payload.headers().get("X-StartTime"), Some("now"));
        assert_eq!(payload.body(), [0x00, 0xFF, 0xFE, 0x80, 0x01]);
    }

    #[test]
    fn done_with_no_additional_headers_still_finds_the_body() {
        let mut raw = b"DONE\r\n\r\n".to_vec();
        raw.extend_from_slice(&[0xAA, 0xBB]);

        let payload = Payload::parse(&raw);
        assert_eq!(payload.meta_tags(), [MetaTag::Done]);
        assert!(payload.headers().is_empty());
        assert_eq!(payload.body(), [0xAA, 0xBB]);
    }

    /// An HTML error page has no preamble. Treating it as a body keeps the diagnostic readable
    /// instead of turning it into a parse failure.
    #[test]
    fn a_payload_with_no_preamble_is_all_body() {
        let raw = b"<html><p>MAPI is not enabled</p></html>";
        let payload = Payload::parse(raw);
        assert!(payload.meta_tags().is_empty());
        assert_eq!(payload.body(), raw);
    }

    #[test]
    fn truncated_payloads_never_panic() {
        for raw in [
            &b""[..],
            &b"DONE"[..],               // no CRLF
            &b"DONE\r\n"[..],           // no blank line
            &b"PROCESSING\r\n"[..],     // never completes
            &b"DONE\r\nX-A: 1\r\n"[..], // headers, then nothing
            &[0xFF, 0xFE, 0x00][..],
        ] {
            let _ = Payload::parse(raw);
        }
        assert!(Payload::parse(b"DONE\r\n").body().is_empty());
        assert_eq!(Payload::parse(b"PROCESSING\r\n").body(), b"PROCESSING\r\n");
    }

    #[test]
    fn response_codes_carry_the_specs_names() {
        assert!(ResponseCode::SUCCESS.is_success());
        assert_eq!(ResponseCode::SUCCESS.name(), Some("Success"));
        assert_eq!(ResponseCode::new(10), ResponseCode::CONTEXT_NOT_FOUND);
        assert_eq!(
            ResponseCode::CONTEXT_NOT_FOUND.to_string(),
            "Context Not Found (10)"
        );
        assert_eq!(ResponseCode::MISSING_HEADER.as_u32(), 7);
        assert!(!ResponseCode::MISSING_COOKIE.is_success());
        for code in [
            ResponseCode::INVALID_REQUEST_TYPE,
            ResponseCode::INVALID_CONTEXT_COOKIE,
            ResponseCode::INVALID_SEQUENCE,
            ResponseCode::ENDPOINT_DISABLED,
        ] {
            assert!(code.name().is_some());
        }
    }

    #[test]
    fn every_documented_response_code_has_a_name() {
        for raw in 0..=18_u32 {
            let code = ResponseCode::new(raw);
            assert_eq!(
                code.name().is_some(),
                raw != 14,
                "code {raw} disagrees with the table in §2.2.3.3.3"
            );
        }
    }

    /// A payload whose first line is not a meta-tag has no preamble at all, even though it does
    /// contain line breaks.
    #[test]
    fn a_line_that_is_not_a_meta_tag_ends_the_preamble_search() {
        let raw = b"HTTP/1.1 400 Bad Request
Content-Length: 0

";
        let payload = Payload::parse(raw);
        assert!(payload.meta_tags().is_empty());
        assert_eq!(payload.body(), raw);
    }

    /// `14` is reserved and everything past `18` is undefined; both have to survive being
    /// received rather than being forced into a known name.
    #[test]
    fn an_unknown_response_code_is_reported_raw() {
        assert_eq!(ResponseCode::new(14).name(), None);
        assert_eq!(ResponseCode::new(99).to_string(), "X-ResponseCode 99");
    }
}
