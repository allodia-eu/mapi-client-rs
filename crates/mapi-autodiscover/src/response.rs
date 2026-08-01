//! Reading the answer.
//!
//! Two things about this document defeat a naive reader, and both are visible in a capture from a
//! real Exchange Server:
//!
//! 1. **`Autodiscover` and `Response` are in different namespaces** — `.../responseschema/2006` and
//!    `.../outlook/responseschema/2006a` ([MS-OXDSCLI] §2.2.1). A reader that insists on one
//!    namespace throughout finds nothing.
//! 2. **`mapiHttp` names itself with an attribute; every other protocol uses a child element.**
//!    `<Protocol Type="mapiHttp" Version="1">` against `<Protocol><Type>EXCH</Type>`. A reader that
//!    only looks at `<Type>` children never finds MAPI/HTTP at all — and its absence looks exactly
//!    like a server that does not support it.
//!
//! Matching is therefore on local names, with the namespaces documented rather than enforced.
//!
//! [MS-OXDSCLI] §2.2.4 — Autodiscover response

use roxmltree::{Document, Node};

use crate::EmailAddress;
use crate::error::{Error, Result};
use crate::settings::{Protocol, ProtocolType, ServerError, Settings, Urls, User};

/// What a server answered.
///
/// Only [`AutodiscoverResponse::Settings`] ends the search; the other three each say where to look
/// next, or that this URL is not the one.
///
/// [MS-OXDSCLI] §3.1.5 — how a client acts on each of these
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AutodiscoverResponse {
    /// Configuration information. The search is over.
    ///
    /// [MS-OXDSCLI] §3.1.5.4 — Autodiscover configuration information
    Settings(Settings),
    /// Ask again, about a different address.
    ///
    /// [MS-OXDSCLI] §3.1.5.3 — `Action` of `redirectAddr`
    RedirectAddress(EmailAddress),
    /// Ask again, at a different URL.
    ///
    /// [MS-OXDSCLI] §3.1.5.3 — `Action` of `redirectUrl`
    RedirectUrl(String),
    /// The server refused. Try the next candidate URL.
    ///
    /// [MS-OXDSCLI] §3.1.5.5 — Autodiscover server errors
    Failed(ServerError),
}

impl AutodiscoverResponse {
    /// Parses a response body.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedXml`] if the body is not well-formed XML, [`Error::MissingElement`] if it
    /// is XML but not an Autodiscover response, and [`Error::IncompleteRedirect`] if the server
    /// asked for a redirect without saying where to.
    pub fn parse(xml: &str) -> Result<Self> {
        let document = Document::parse(xml).map_err(|error| Error::MalformedXml {
            detail: error.to_string(),
        })?;

        let response = find(document.root_element(), "Response").ok_or(Error::MissingElement {
            element: "Response",
        })?;

        if let Some(error) = child(response, "Error") {
            return Ok(Self::Failed(read_error(error)));
        }

        let account = child(response, "Account");
        let action = account
            .and_then(|node| child(node, "Action"))
            .and_then(text)
            .unwrap_or_default();

        match action.as_str() {
            "redirectAddr" => match account
                .and_then(|node| child(node, "RedirectAddr"))
                .and_then(text)
            {
                Some(address) => Ok(Self::RedirectAddress(EmailAddress::new(address)?)),
                None => Err(Error::IncompleteRedirect { action }),
            },
            "redirectUrl" => match account
                .and_then(|node| child(node, "RedirectUrl"))
                .and_then(text)
            {
                Some(url) => Ok(Self::RedirectUrl(url)),
                None => Err(Error::IncompleteRedirect { action }),
            },
            _ => Ok(Self::Settings(Settings {
                user: child(response, "User").map(read_user).unwrap_or_default(),
                protocols: account.map(read_protocols).unwrap_or_default(),
            })),
        }
    }

    /// The settings, if the server sent any.
    #[must_use]
    pub const fn settings(&self) -> Option<&Settings> {
        match self {
            Self::Settings(settings) => Some(settings),
            _ => None,
        }
    }
}

/// `Protocol` elements are read as direct children of `Account` only: a `WEB` protocol nests
/// further `Protocol` elements inside `<Internal>`, and a descendant search would pull those up to
/// the top level as if the server had offered them there.
fn read_protocols(account: Node<'_, '_>) -> Vec<Protocol> {
    children(account, "Protocol")
        .into_iter()
        .map(read_protocol)
        .collect()
}

fn read_protocol(node: Node<'_, '_>) -> Protocol {
    // The Type attribute is how `mapiHttp` names itself; the Type child element is how everything
    // else does. [MS-OXDSCLI] §2.2.4.1.1.2.6, §2.2.4.1.1.2.6.46
    let named = node
        .attribute("Type")
        .map(str::to_owned)
        .or_else(|| child(node, "Type").and_then(text))
        .unwrap_or_default();

    Protocol {
        kind: ProtocolType::parse(&named),
        version: node.attribute("Version").and_then(|v| v.parse().ok()),
        server: child(node, "Server").and_then(text),
        auth_package: child(node, "AuthPackage").and_then(text),
        mail_store: child(node, "MailStore").map(read_urls).unwrap_or_default(),
        address_book: child(node, "AddressBook")
            .map(read_urls)
            .unwrap_or_default(),
    }
}

fn read_urls(node: Node<'_, '_>) -> Urls {
    Urls {
        internal: child(node, "InternalUrl").and_then(text),
        external: child(node, "ExternalUrl").and_then(text),
    }
}

fn read_user(node: Node<'_, '_>) -> User {
    User {
        display_name: child(node, "DisplayName").and_then(text),
        legacy_dn: child(node, "LegacyDN").and_then(text),
        smtp_address: child(node, "AutoDiscoverSMTPAddress").and_then(text),
        deployment_id: child(node, "DeploymentId").and_then(text),
    }
}

fn read_error(node: Node<'_, '_>) -> ServerError {
    ServerError {
        code: child(node, "ErrorCode")
            .and_then(text)
            .and_then(|code| code.parse().ok()),
        message: child(node, "Message").and_then(text),
        debug_data: child(node, "DebugData")
            .and_then(text)
            .filter(|d| !d.is_empty()),
    }
}

/// The first descendant with this local name, the element itself included.
fn find<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.descendants().find(|candidate| named(*candidate, name))
}

/// The first direct child element with this local name.
fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|candidate| named(*candidate, name))
}

/// Every direct child element with this local name.
///
/// A `Vec` rather than an iterator: an Autodiscover response is a couple of kilobytes, and the
/// lifetime gymnastics a borrowed iterator would need here buy nothing.
fn children<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Vec<Node<'a, 'input>> {
    node.children()
        .filter(|candidate| named(*candidate, name))
        .collect()
}

fn named(node: Node<'_, '_>, name: &str) -> bool {
    node.is_element() && node.tag_name().name() == name
}

/// An element's text, trimmed. The specification's own examples wrap long values across lines.
fn text(node: Node<'_, '_>) -> Option<String> {
    node.text().map(|value| value.trim().to_owned())
}

#[cfg(test)]
mod tests;
