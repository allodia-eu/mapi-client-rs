//! Turning arguments and the environment into a client.
//!
//! Everything that identifies a deployment can be given as an environment variable, and the
//! password only sensibly is: a `--password` on a command line reaches the shell history and the
//! process list of every other user on the machine. The names are the ones
//! `scripts/Test-Live.ps1` already sets, so a shell configured for the live tests can drive this
//! tool with no further ceremony.

use core::time::Duration;
use std::sync::Arc;

use clap::Args;
use mapi_client::{Credentials, Lcid, LegacyDn, MapiClient, MapiClientBuilder};

use crate::Failure;
use crate::report::Dump;

/// Which authentication scheme `--auth` selects.
///
/// The two connection-oriented schemes are behind the same feature as the client's, so a
/// `--no-default-features` build offers `basic` and says so rather than accepting a value it cannot
/// act on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Auth {
    /// HTTP Basic, sent preemptively. Needs Basic enabled on the MAPI virtual directory.
    #[default]
    Basic,
    /// NTLM v2, over a three-message handshake.
    #[cfg(feature = "ntlm")]
    Ntlm,
    /// SPNEGO carrying NTLM.
    #[cfg(feature = "ntlm")]
    Negotiate,
}

/// How to reach one mailbox.
#[derive(Clone, Debug, Args)]
pub(crate) struct Connection {
    /// The `MailStore` URL, verbatim from Autodiscover, including its `?MailboxId=` parameter.
    ///
    /// Without that parameter Exchange answers HTTP 400 with no `X-ResponseCode` at all, which
    /// reads like "MAPI is switched off" rather than "your URL is incomplete".
    #[arg(long, env = "MAPI_LIVE_ENDPOINT", value_name = "URL")]
    endpoint: Option<String>,

    /// The mailbox's `legacyExchangeDN`, again verbatim from Autodiscover.
    ///
    /// Never pass this through a shell that rewrites paths: an MSYS shell turns the leading `/o=`
    /// into a Windows path, and Exchange reports the result as `ecUnknownUser`.
    #[arg(long, env = "MAPI_LIVE_USER_DN", value_name = "DN")]
    user_dn: Option<String>,

    /// An account with rights to that mailbox.
    #[arg(long, env = "MAPI_LIVE_USERNAME", value_name = "NAME")]
    username: Option<String>,

    /// Its password. Prefer the environment variable.
    #[arg(
        long,
        env = "MAPI_LIVE_PASSWORD",
        value_name = "PASSWORD",
        hide_env_values = true
    )]
    password: Option<String>,

    /// Which authentication scheme to use: `basic`, `ntlm` or `negotiate`.
    ///
    /// A default-configured Exchange offers only the last two. `basic` is the default here because
    /// it is what the committed fixture corpus was captured with, and changing the scheme changes
    /// how many HTTP exchanges a capture contains.
    #[arg(
        long,
        env = "MAPI_LIVE_AUTH",
        value_name = "SCHEME",
        default_value = "basic"
    )]
    auth: Auth,

    /// The Session Context's locale, as an [MS-LCID] identifier: `0x0409` is en-US, `0x0413`
    /// nl-NL.
    ///
    /// This asks for the *session's* treatment of data. It is not the mailbox's own configured
    /// language and does not become it — folder names come back in whatever language the mailbox
    /// already holds them, whatever is sent here.
    #[arg(
        long,
        env = "MAPI_LIVE_LOCALE",
        value_name = "LCID",
        default_value = "0x0409"
    )]
    locale: String,

    /// How long one request may take, in seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 30)]
    timeout: u64,

    /// Accept any server certificate, valid or not.
    ///
    /// For a lab whose certificate is self-signed and not in the machine's trust store. It turns
    /// off the check that makes TLS mean anything, so anything answering on that address can read
    /// the credentials in every request.
    #[arg(long)]
    insecure: bool,

    /// Hex-dump every request and response.
    ///
    /// Rides along here rather than in its own group because every subcommand takes a connection,
    /// so this way `--dump` works with all of them. `capture` is the exception: it installs its
    /// own observer, and a client has one.
    #[arg(long)]
    dump: bool,

    /// How much of each body `--dump` shows.
    #[arg(long, value_name = "BYTES", default_value_t = 512)]
    dump_limit: usize,
}

impl Connection {
    /// The endpoint URL, once it is known to be present.
    pub(crate) fn endpoint(&self) -> Result<&str, Failure> {
        self.endpoint.as_deref().ok_or_else(|| {
            missing(
                "endpoint",
                "MAPI_LIVE_ENDPOINT",
                "the MailStore URL from Autodiscover, with its ?MailboxId= parameter",
            )
        })
    }

    /// The distinguished name, once it is known to be present.
    pub(crate) fn user_dn(&self) -> Result<&str, Failure> {
        self.user_dn.as_deref().ok_or_else(|| {
            missing(
                "user-dn",
                "MAPI_LIVE_USER_DN",
                "the mailbox's legacyExchangeDN",
            )
        })
    }

    /// Everything except the endpoint and the distinguished name — which is all Autodiscover
    /// needs, because finding those two is what it is for.
    pub(crate) fn base(&self) -> Result<MapiClientBuilder, Failure> {
        let mut builder = MapiClientBuilder::new()
            .locale(self.lcid()?)
            .timeout(Duration::from_secs(self.timeout))
            .danger_accept_invalid_certificates(self.insecure);

        if let Some(username) = self.username.as_deref() {
            let password = self.password.clone().unwrap_or_default();
            builder = builder.credentials(match self.auth {
                Auth::Basic => Credentials::basic(username, password),
                #[cfg(feature = "ntlm")]
                Auth::Ntlm => Credentials::ntlm(username, password),
                #[cfg(feature = "ntlm")]
                Auth::Negotiate => Credentials::negotiate(username, password),
            });
        }

        // A plaintext endpoint is refused unless it was asked for, and here asking for it is the
        // same act as accepting any certificate: both are "I know this is a lab".
        if self.insecure {
            builder = builder.danger_allow_plaintext_http();
        }

        Ok(builder)
    }

    /// A builder carrying everything given here, ready for an observer or a `build`.
    pub(crate) fn builder(&self) -> Result<MapiClientBuilder, Failure> {
        let endpoint = self.endpoint()?;
        let user_dn = LegacyDn::new(self.user_dn()?)?;
        Ok(self.base()?.endpoint(endpoint).user_dn(user_dn))
    }

    /// A client, with the hex dump attached if it was asked for.
    pub(crate) fn client(&self) -> Result<MapiClient, Failure> {
        let mut builder = self.builder()?;
        if self.dump {
            builder = builder.observer(Arc::new(Dump {
                limit: self.dump_limit,
            }));
        }
        Ok(builder.build()?)
    }

    /// The same, with a different distinguished name — which is what capturing a refused `Connect`
    /// needs, and nothing else should want.
    ///
    /// Built from [`Connection::base`] rather than from [`Connection::builder`] so that the name
    /// being overridden does not also have to be given: requiring `--user-dn` in order to say
    /// "use this other name instead" is a setting whose only effect is to be replaced.
    pub(crate) fn builder_with_dn(&self, user_dn: &str) -> Result<MapiClientBuilder, Failure> {
        let endpoint = self.endpoint()?;
        Ok(self
            .base()?
            .endpoint(endpoint)
            .user_dn(LegacyDn::new(user_dn)?))
    }

    /// The locale identifier, as decimal or `0x`-prefixed hexadecimal.
    fn lcid(&self) -> Result<Lcid, Failure> {
        let text = self.locale.trim();
        let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            Some(hexadecimal) => u32::from_str_radix(hexadecimal, 16),
            None => text.parse::<u32>(),
        };

        parsed.map(Lcid::new).map_err(|_| {
            Failure::from(format!(
                "`{text}` is not a locale identifier. Give a number, as decimal or with a `0x` \
                 prefix: 0x0409 is en-US and 0x0413 is nl-NL. [MS-LCID] lists the rest."
            ))
        })
    }
}

/// The message for a setting that has no default and was not given.
fn missing(flag: &str, variable: &str, what: &str) -> Failure {
    Failure::from(format!(
        "no {flag}. Pass --{flag} or set {variable}: {what}."
    ))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    /// A parser with nothing but a `Connection`, so the argument surface can be tested on its own.
    #[derive(Debug, Parser)]
    struct Harness {
        #[command(flatten)]
        connection: Connection,
    }

    fn parse(arguments: &[&str]) -> Connection {
        let mut all = vec!["mapi-cli"];
        all.extend_from_slice(arguments);
        Harness::try_parse_from(all)
            .expect("valid arguments")
            .connection
    }

    const ENDPOINT: &str = "https://mail.example.test/mapi/emsmdb/?MailboxId=x@example.test";
    const USER_DN: &str = "/o=Example/cn=alice";

    #[test]
    fn a_locale_is_accepted_as_decimal_or_hexadecimal() {
        for (given, expected) in [("0x0409", 0x0409), ("0X0413", 0x0413), ("1043", 1043)] {
            let connection = parse(&["--locale", given]);
            assert_eq!(connection.lcid().expect(given), Lcid::new(expected));
        }

        let error = parse(&["--locale", "nl-NL"])
            .lcid()
            .expect_err("not a number");
        assert!(error.to_string().contains("0x0413"), "{error}");
    }

    /// The two settings with no default are reported by the name of the flag *and* the name of the
    /// environment variable, because whoever hit this used one or the other.
    #[test]
    fn a_missing_setting_names_both_ways_of_giving_it() {
        let bare = parse(&[]);
        let error = bare.endpoint().expect_err("no endpoint");
        assert!(error.to_string().contains("--endpoint"), "{error}");
        assert!(error.to_string().contains("MAPI_LIVE_ENDPOINT"), "{error}");

        let error = parse(&["--endpoint", ENDPOINT])
            .builder()
            .expect_err("no dn");
        assert!(error.to_string().contains("MAPI_LIVE_USER_DN"), "{error}");
    }

    #[test]
    fn a_full_set_of_arguments_builds_a_client() {
        let connection = parse(&[
            "--endpoint",
            ENDPOINT,
            "--user-dn",
            USER_DN,
            "--username",
            "alice@example.test",
            "--password",
            "hunter2",
            "--timeout",
            "5",
        ]);

        let client = connection
            .builder()
            .expect("a builder")
            .build()
            .expect("a client");
        assert_eq!(client.endpoint(), ENDPOINT);
        assert_eq!(client.user_dn().as_str(), USER_DN);
        // A password is never in a `Debug`, which is where a diagnostic would otherwise put it.
        assert!(!format!("{client:?}").contains("hunter2"));
    }

    /// The refused-`Connect` capture is the only thing that needs this, and it must change the
    /// name without disturbing anything else.
    #[test]
    fn a_distinguished_name_can_be_overridden_for_one_client() {
        let connection = parse(&["--endpoint", ENDPOINT, "--user-dn", USER_DN]);
        let client = connection
            .builder_with_dn("/o=Example/cn=nobody")
            .expect("a builder")
            .build()
            .expect("a client");

        assert_eq!(client.user_dn().as_str(), "/o=Example/cn=nobody");
        assert_eq!(client.endpoint(), ENDPOINT);
    }

    /// The `UserDn` field is 8-bit and null-terminated, so a name that is empty or not ASCII
    /// cannot be sent at all — and finding that out here beats finding it out as `ecUnknownUser`,
    /// which reads like an authentication failure.
    #[test]
    fn a_distinguished_name_that_will_not_parse_is_reported_rather_than_sent() {
        for bad in ["", "/o=Exämple/cn=alice"] {
            let connection = parse(&["--endpoint", ENDPOINT, "--user-dn", bad]);
            let error = connection.builder().expect_err("not a legacyExchangeDN");
            assert!(!error.to_string().is_empty(), "{bad:?}");
        }
    }
}
