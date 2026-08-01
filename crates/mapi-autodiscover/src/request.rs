//! The request: a small XML document, and the header without which the answer is useless.

use crate::EmailAddress;

/// The request namespace.
///
/// [MS-OXDSCLI] §2.2.1 — namespaces
const REQUEST_NAMESPACE: &str =
    "http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006";

/// The response schema this crate can read.
///
/// [MS-OXDSCLI] §2.2.3.1.1.1 — `AcceptableResponseSchema`
const RESPONSE_SCHEMA: &str =
    "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a";

/// `X-MapiHttpCapability`: the highest `Protocol` response-format version this crate understands.
///
/// **Without this header the server does not advertise MAPI/HTTP at all** — the `mapiHttp`
/// `Protocol` element is simply absent, and the response looks like a server that does not support
/// the protocol rather than one that was not asked.
///
/// [MS-OXDSCLI] §2.2.2.1 — `X-MapiHttpCapability`
/// [MS-OXDSCLI] §3.2.5.1 — what the server does with it
const MAPI_HTTP_CAPABILITY: &str = "1";

/// An Autodiscover request for the caller to POST.
///
/// This crate performs no I/O. POST [`body`](AutodiscoverRequest::body) to one of the
/// [`candidate_urls`](crate::candidate_urls) with [`headers`](AutodiscoverRequest::headers) and
/// hand the response to [`AutodiscoverResponse::parse`](crate::AutodiscoverResponse::parse).
///
/// [MS-OXDSCLI] §2.2.3 — Autodiscover request
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutodiscoverRequest {
    address: EmailAddress,
    body: String,
}

impl AutodiscoverRequest {
    /// Builds the request for one address.
    #[must_use]
    pub fn new(address: &EmailAddress) -> Self {
        // No escaping pass: EmailAddress refuses every character that would need one, so an
        // address that reaches here cannot change the shape of this document.
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
             <Autodiscover xmlns=\"{REQUEST_NAMESPACE}\">\n\
             \x20 <Request>\n\
             \x20   <EMailAddress>{address}</EMailAddress>\n\
             \x20   <AcceptableResponseSchema>{RESPONSE_SCHEMA}</AcceptableResponseSchema>\n\
             \x20 </Request>\n\
             </Autodiscover>\n"
        );

        Self {
            address: address.clone(),
            body,
        }
    }

    /// The address this request asks about.
    #[must_use]
    pub const fn address(&self) -> &EmailAddress {
        &self.address
    }

    /// The XML body to POST.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// The body, for a transport that would rather own it.
    #[must_use]
    pub fn into_body(self) -> String {
        self.body
    }

    /// The headers to send with it.
    ///
    /// `X-AnchorMailbox` tells a multi-server deployment which mailbox the request is about, so it
    /// can be routed without a redirect.
    ///
    /// [MS-OXDSCLI] §2.2.2 — HTTP headers
    #[must_use]
    pub fn headers(&self) -> [(&'static str, &str); 3] {
        [
            ("Content-Type", "text/xml; charset=utf-8"),
            ("X-MapiHttpCapability", MAPI_HTTP_CAPABILITY),
            ("X-AnchorMailbox", self.address.as_str()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AutodiscoverRequest {
        AutodiscoverRequest::new(&EmailAddress::new("developer@dev.local").unwrap())
    }

    #[test]
    fn the_body_is_the_document_the_specification_shows() {
        let request = request();
        let body = request.body();

        assert!(body.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>"));
        assert!(body.contains(&format!("<Autodiscover xmlns=\"{REQUEST_NAMESPACE}\">")));
        assert!(body.contains("<EMailAddress>developer@dev.local</EMailAddress>"));
        assert!(body.contains(&format!(
            "<AcceptableResponseSchema>{RESPONSE_SCHEMA}</AcceptableResponseSchema>"
        )));
        assert!(body.trim_end().ends_with("</Autodiscover>"));
        assert_eq!(request.address().as_str(), "developer@dev.local");
    }

    /// The one header that decides whether the answer is useful at all.
    #[test]
    fn the_capability_header_is_always_sent() {
        let request = request();
        let headers = request.headers();

        assert_eq!(headers[1], ("X-MapiHttpCapability", "1"));
        assert_eq!(headers[0].0, "Content-Type");
        assert!(headers[0].1.starts_with("text/xml"));
        assert_eq!(headers[2], ("X-AnchorMailbox", "developer@dev.local"));
    }

    #[test]
    fn the_body_can_be_taken_by_value() {
        let body = request().body().to_owned();
        assert_eq!(request().into_body(), body);
    }

    /// The address is put in unescaped, which is only safe because `EmailAddress` refuses every
    /// character that would need escaping. This is the test that keeps those two facts together.
    #[test]
    fn no_address_that_could_reshape_the_document_can_be_built() {
        for attempt in [
            "a@b</EMailAddress><Evil>x</Evil><EMailAddress>c",
            "a&amp;b@dev.local",
            "\"quoted\"@dev.local",
        ] {
            assert!(
                EmailAddress::new(attempt).is_err(),
                "{attempt:?} got through"
            );
        }
    }
}
