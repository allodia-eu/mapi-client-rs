//! How a request proves who is asking.
//!
//! # Two shapes, not one
//!
//! [`Credentials::Basic`] and [`Credentials::Bearer`] are a header computed once and attached to
//! every request. [`Credentials::Ntlm`] and [`Credentials::Negotiate`] are not: both are multi-leg
//! challenge/response handshakes that authenticate a **TCP connection** rather than a request.
//!
//! That difference is not an implementation detail, because it reaches the transport. A client
//! using either of them pins its connection pool to one connection per host and serialises
//! requests, since a handshake whose legs land on different connections cannot complete — see
//! [`MapiClientBuilder::credentials`](crate::MapiClientBuilder::credentials). The cost is that a
//! clone of such a client does not add concurrency; the benefit is that it works against a
//! default-configured Exchange, which offers exactly those two schemes and nothing else.
//!
//! What is still missing is **Kerberos**. `Negotiate` here is SPNEGO carrying NTLM, which is what
//! every non-Windows client does and what a server with `Negotiate` enabled and `NTLM` disabled
//! accepts. A server that insists on Kerberos is reported as such rather than guessed at.
//!
//! [MS-OXCMAPIHTTP] §3.1.5.1 — the client authenticates before the first request

/// How to authenticate to the endpoint.
///
/// # Secrets
///
/// [`Debug`] is implemented by hand and prints no secret: a password or token would otherwise
/// reach a log the moment anyone derived `Debug` on a struct that holds a client.
///
/// [`PartialEq`] is deliberately **not** implemented. Comparing credentials is a comparison of
/// secrets, and the obvious implementation compares them in non-constant time.
#[derive(Clone)]
#[non_exhaustive]
pub enum Credentials {
    /// Send no `Authorization` header.
    ///
    /// For an endpoint fronted by something that has already authenticated the caller — a
    /// reverse proxy, a service mesh — and for finding out what a server offers.
    None,

    /// HTTP Basic, sent preemptively rather than after a 401.
    ///
    /// The username may be `user`, `user@domain` or `DOMAIN\user`; Exchange accepts all three,
    /// measured against Exchange Server SE `15.02.2562.045`.
    ///
    /// Basic puts a reusable password in every request, so the endpoint must be HTTPS. This crate
    /// enforces that: see [`Error::PlaintextEndpoint`](crate::Error::PlaintextEndpoint).
    Basic {
        /// The account name.
        username: String,
        /// Its password.
        password: String,
    },

    /// An OAuth 2.0 bearer token, as `Authorization: Bearer <token>`.
    ///
    /// Obtaining and refreshing the token is the caller's: this crate attaches what it is given
    /// and never talks to an authorisation server. A token that expires mid-session surfaces as
    /// [`Error::Unauthorized`](crate::Error::Unauthorized) on the next request.
    ///
    /// Unlike [`Credentials::Basic`], this path has not been exercised against a live Exchange by
    /// this crate's authors — only that the header goes out in the documented form.
    Bearer {
        /// The token, without the `Bearer ` prefix.
        token: String,
    },

    /// NTLM v2, as `Authorization: NTLM …` over a three-message handshake.
    ///
    /// The scheme a default-configured Exchange offers alongside `Negotiate`. Measured against
    /// Exchange Server SE `15.02.2562.045`: the handshake costs one extra round trip on the first
    /// request of a connection and nothing thereafter, because IIS answers a completed handshake
    /// with `Persistent-Auth: true` and keeps the connection authenticated.
    ///
    /// Prefer [`Credentials::Negotiate`] when both are offered — a hardened deployment is more
    /// likely to have left `Negotiate` on than `NTLM`.
    #[cfg(feature = "ntlm")]
    Ntlm {
        /// The account, its password, and optionally the workstation name to report.
        identity: mapi_auth::Identity,
    },

    /// SPNEGO, as `Authorization: Negotiate …`, carrying the same NTLM messages.
    ///
    /// [RFC 4559] §4 — the HTTP binding for SPNEGO
    ///
    /// This offers NTLM as its only mechanism. A server that would rather speak Kerberos is told
    /// Kerberos is not available and selects NTLM, which is what SPNEGO exists to arrange; a server
    /// that refuses to select anything else reports
    /// [`Error::Unauthorized`](crate::Error::Unauthorized) with the mechanism named.
    #[cfg(feature = "ntlm")]
    Negotiate {
        /// The account, its password, and optionally the workstation name to report.
        identity: mapi_auth::Identity,
    },
}

impl Credentials {
    /// HTTP Basic credentials.
    #[must_use]
    pub fn basic(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Basic {
            username: username.into(),
            password: password.into(),
        }
    }

    /// An OAuth 2.0 bearer token.
    #[must_use]
    pub fn bearer(token: impl Into<String>) -> Self {
        Self::Bearer {
            token: token.into(),
        }
    }

    /// NTLM v2 credentials.
    ///
    /// The user name may be `DOMAIN\user`, `user@domain` or a bare `user`; see
    /// [`mapi_auth::Identity`] for how each is split, which matters because both halves are inputs
    /// to the response key.
    #[cfg(feature = "ntlm")]
    #[must_use]
    pub fn ntlm(username: &str, password: impl Into<String>) -> Self {
        Self::Ntlm {
            identity: mapi_auth::Identity::new(username, password),
        }
    }

    /// SPNEGO credentials, carrying NTLM.
    #[cfg(feature = "ntlm")]
    #[must_use]
    pub fn negotiate(username: &str, password: impl Into<String>) -> Self {
        Self::Negotiate {
            identity: mapi_auth::Identity::new(username, password),
        }
    }

    /// How to describe what was sent, for a message a human reads after a 401.
    #[must_use]
    pub const fn describe(&self) -> &'static str {
        match self {
            Self::None => "no credentials",
            Self::Basic { .. } => "Basic credentials",
            Self::Bearer { .. } => "a bearer token",
            #[cfg(feature = "ntlm")]
            Self::Ntlm { .. } => "NTLM credentials",
            #[cfg(feature = "ntlm")]
            Self::Negotiate { .. } => "Negotiate credentials",
        }
    }

    /// Which handshake scheme these credentials need, if they need one at all.
    ///
    /// This is the question the transport asks: a scheme here means the connection has to be
    /// pinned and the requests serialised, and `None` means a header is enough.
    #[cfg(feature = "ntlm")]
    pub(crate) const fn handshake(&self) -> Option<(mapi_auth::Scheme, &mapi_auth::Identity)> {
        match self {
            Self::Ntlm { identity } => Some((mapi_auth::Scheme::Ntlm, identity)),
            Self::Negotiate { identity } => Some((mapi_auth::Scheme::Negotiate, identity)),
            _ => None,
        }
    }

    /// Whether these credentials authenticate a connection rather than a request.
    ///
    /// Read by the builder, which has to decide how to configure the connection pool before there
    /// is a transport to ask.
    ///
    /// Without the `ntlm` feature no variant is, so this is constantly false — which is the point:
    /// the builder asks the same question either way, and the answer removes the whole branch.
    #[cfg_attr(
        not(feature = "ntlm"),
        expect(
            clippy::unused_self,
            reason = "the answer is a property of the variant, and there is no such variant here"
        )
    )]
    pub(crate) const fn is_connection_oriented(&self) -> bool {
        #[cfg(feature = "ntlm")]
        {
            matches!(self, Self::Ntlm { .. } | Self::Negotiate { .. })
        }
        #[cfg(not(feature = "ntlm"))]
        {
            false
        }
    }
}

impl Default for Credentials {
    /// [`Credentials::None`].
    fn default() -> Self {
        Self::None
    }
}

/// Prints which scheme is in use and nothing else. See the type's documentation for why.
impl core::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => f.write_str("Credentials::None"),
            Self::Basic { username, .. } => f
                .debug_struct("Credentials::Basic")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Self::Bearer { .. } => f
                .debug_struct("Credentials::Bearer")
                .field("token", &"<redacted>")
                .finish(),
            // `Identity`'s own `Debug` redacts the password, so this delegates rather than
            // repeating the rule in a second place that could drift from the first.
            #[cfg(feature = "ntlm")]
            Self::Ntlm { identity } => f
                .debug_struct("Credentials::Ntlm")
                .field("identity", identity)
                .finish(),
            #[cfg(feature = "ntlm")]
            Self::Negotiate { identity } => f
                .debug_struct("Credentials::Negotiate")
                .field("identity", identity)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the hand-written `Debug`: a password must not reach a log because
    /// somebody derived `Debug` three types further out.
    #[test]
    fn debug_never_prints_a_secret() {
        /// Nested inside another type, which is how a secret actually reaches a log.
        #[derive(Debug)]
        struct Holder {
            #[allow(dead_code, reason = "read only by the derived Debug this test checks")]
            credentials: Credentials,
        }

        let basic = Credentials::basic("alice@example.test", "hunter2");
        let rendered = format!("{basic:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("alice@example.test"));
        assert!(rendered.contains("<redacted>"));

        let bearer = Credentials::bearer("eyJhbGciOiJIUzI1NiJ9.secret");
        let rendered = format!("{bearer:?}");
        assert!(!rendered.contains("secret"), "{rendered}");
        assert!(rendered.contains("<redacted>"));

        let holder = Holder {
            credentials: Credentials::basic("u", "p4ssw0rd"),
        };
        assert!(!format!("{holder:?}").contains("p4ssw0rd"));

        #[cfg(feature = "ntlm")]
        for credentials in [
            Credentials::ntlm("DEV\\developer", "Login123"),
            Credentials::negotiate("developer@dev.local", "Login123"),
        ] {
            let rendered = format!("{credentials:?}");
            assert!(!rendered.contains("Login123"), "{rendered}");
            assert!(rendered.contains("<redacted>"), "{rendered}");
            assert!(rendered.contains("developer"), "{rendered}");
        }
    }

    #[test]
    fn each_scheme_describes_itself_for_a_401_message() {
        assert_eq!(Credentials::None.describe(), "no credentials");
        assert_eq!(Credentials::default().describe(), "no credentials");
        assert_eq!(Credentials::basic("u", "p").describe(), "Basic credentials");
        assert_eq!(Credentials::bearer("t").describe(), "a bearer token");
        assert_eq!(format!("{:?}", Credentials::None), "Credentials::None");

        #[cfg(feature = "ntlm")]
        {
            assert_eq!(Credentials::ntlm("u", "p").describe(), "NTLM credentials");
            assert_eq!(
                Credentials::negotiate("u", "p").describe(),
                "Negotiate credentials"
            );
        }
    }

    /// The question the transport and the builder both ask, and the whole reason the two schemes
    /// are not just two more headers.
    #[test]
    fn only_the_handshake_schemes_are_connection_oriented() {
        assert!(!Credentials::None.is_connection_oriented());
        assert!(!Credentials::basic("u", "p").is_connection_oriented());
        assert!(!Credentials::bearer("t").is_connection_oriented());

        #[cfg(feature = "ntlm")]
        {
            assert!(Credentials::ntlm("u", "p").is_connection_oriented());
            assert!(Credentials::negotiate("u", "p").is_connection_oriented());

            assert!(Credentials::None.handshake().is_none());
            assert!(Credentials::basic("u", "p").handshake().is_none());

            let ntlm = Credentials::ntlm("DEV\\developer", "Login123");
            let (scheme, identity) = ntlm.handshake().expect("NTLM needs a handshake");
            assert_eq!(scheme, mapi_auth::Scheme::Ntlm);
            assert_eq!(identity.domain(), "DEV");
            assert_eq!(identity.username(), "developer");

            let negotiate = Credentials::negotiate("u", "p");
            let (scheme, _) = negotiate.handshake().expect("Negotiate needs a handshake");
            assert_eq!(scheme, mapi_auth::Scheme::Negotiate);
        }
    }
}
