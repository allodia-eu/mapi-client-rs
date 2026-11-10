//! Reading a response as it arrives.
//!
//! [MS-OXCMAPIHTTP] §3.1.5.6 has the server answer `PROCESSING` at once and `PENDING` while it
//! works, inside a chunked body, and has the client "isolate the receiving of response 'chunks'
//! from the parsing and interpreting of the inner response stream". So the stream is read piece
//! by piece here, the meta-tags are told to the observer as they complete, and the payload is
//! handed to the codec whole.

use std::time::Instant;

use mapi_proto::{MetaTag, Request};
use reqwest::Response;

use super::Transport;
use crate::error::Result;

impl Transport {
    /// Reads the response as it arrives, telling the observer of each meta-tag on the way.
    ///
    /// Read piece by piece rather than whole because the preamble is the point: [MS-OXCMAPIHTTP]
    /// §3.1.5.6 has the server answer `PROCESSING` at once and `PENDING` while it works, and each
    /// piece arriving is what restarts the bound on silence. The body is still handed back whole —
    /// a ROP buffer is only parseable once all of it is in.
    pub(super) async fn read_body(
        &self,
        response: &mut Response,
        request: Option<&Request>,
        started: Instant,
    ) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        let mut preamble = Preamble::default();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| self.classify(error, started))?
        {
            body.extend_from_slice(&chunk);
            if let (Some(request), Some(observer)) = (request, &self.observer) {
                preamble.report(&body, |tag| observer.meta_tag(request.request_type(), tag));
            }
        }
        Ok(body)
    }
}

/// How far through a response's meta-tag preamble the reading has got.
///
/// [MS-OXCMAPIHTTP] §2.2.7 — response meta-tags
#[derive(Debug, Default)]
struct Preamble {
    /// Where the next unread line starts.
    scanned: usize,
    /// Whether `DONE`, or a line that is no meta-tag, has been seen, after which nothing more is.
    over: bool,
}

/// The longest line a meta-tag can be, `PROCESSING`, with room to spare for trailing blanks.
///
/// Only this much of a line is ever searched for its end. A line longer than this is no meta-tag,
/// so a body without a preamble — an error page, a proxy's answer — is given up on at once rather
/// than searched again, end to end, every time another piece of it arrives.
const LONGEST_LINE: usize = 16;

impl Preamble {
    /// Hands `report` every meta-tag on a complete line not yet read.
    fn report(&mut self, body: &[u8], mut report: impl FnMut(MetaTag)) {
        while !self.over {
            let rest = body.get(self.scanned..).unwrap_or_default();
            let window = rest
                .get(..rest.len().min(LONGEST_LINE.saturating_add(2)))
                .unwrap_or_default();
            let Some(end) = window.windows(2).position(|pair| pair == b"\r\n") else {
                self.over = rest.len() > LONGEST_LINE.saturating_add(1);
                return;
            };
            let tag = rest.get(..end).and_then(MetaTag::from_line);
            self.scanned = self.scanned.saturating_add(end).saturating_add(2);
            match tag {
                Some(tag) => {
                    report(tag);
                    self.over = tag == MetaTag::Done;
                }
                None => self.over = true,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A preamble arriving a few bytes at a time is reported a tag at a time, each once, and
    /// nothing after `DONE` — where the headers and the binary body begin — is read as one.
    #[test]
    fn meta_tags_are_reported_once_each_as_their_lines_complete() {
        let whole = b"PROCESSING\r\nPENDING\r\nPENDING\r\nDONE\r\nPENDING\r\n\r\n\x00";
        let mut preamble = Preamble::default();
        let mut seen = Vec::new();
        for end in 1..=whole.len() {
            preamble.report(&whole[..end], |tag| seen.push(tag));
        }
        assert_eq!(
            seen,
            [
                MetaTag::Processing,
                MetaTag::Pending,
                MetaTag::Pending,
                MetaTag::Done
            ]
        );

        let mut page = Preamble::default();
        let mut none = Vec::new();
        page.report(b"<html>\r\nPENDING\r\n", |tag| none.push(tag));
        assert!(none.is_empty(), "a body with no preamble has no meta-tags");

        let mut long = Preamble::default();
        long.report(&[b'x'; 64], |tag| none.push(tag));
        assert!(
            long.over,
            "a line longer than any meta-tag ends the search at once"
        );
        long.report(b"PENDING\r\n", |tag| none.push(tag));
        assert!(none.is_empty());
    }
}
