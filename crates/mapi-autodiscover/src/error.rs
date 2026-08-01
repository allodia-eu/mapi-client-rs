//! What can go wrong while locating an endpoint.

/// The result of building or parsing an Autodiscover exchange.
pub type Result<T> = core::result::Result<T, Error>;

/// Something this crate could not do.
///
/// A server that answers with an `<Error>` element is *not* one of these: that is a legitimate
/// protocol outcome, reported as [`AutodiscoverResponse::Failed`], because the documented reaction
/// is to try the next candidate URL rather than to give up.
///
/// [`AutodiscoverResponse::Failed`]: crate::AutodiscoverResponse::Failed
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The address cannot be used to build an Autodiscover request.
    #[error("invalid email address: {reason}")]
    InvalidEmailAddress {
        /// Which rule the address broke.
        reason: &'static str,
    },

    /// The response body is not well-formed XML.
    #[error("malformed XML: {detail}")]
    MalformedXml {
        /// What the parser objected to, including its position.
        detail: String,
    },

    /// The response is well-formed XML but not an Autodiscover response.
    ///
    /// [MS-OXDSCLI] §2.2.4 — Autodiscover response
    #[error("the response has no <{element}> element")]
    MissingElement {
        /// The element that should have been there.
        element: &'static str,
    },

    /// The server asked for a redirect but did not say where to.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.2.2 — `Action`
    #[error("<Action>{action}</Action> without the element that says where to go")]
    IncompleteRedirect {
        /// The `Action` value that was given.
        action: String,
    },
}
