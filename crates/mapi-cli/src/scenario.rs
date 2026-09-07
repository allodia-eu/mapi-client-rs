//! The conversations that become fixtures, and what drives them.
//!
//! A fixture set is only as good as what it covers, and the thing it has to cover is the *whole*
//! path this workspace claims to implement — including the paging that a small mailbox would
//! otherwise never exercise, and including a refusal, because error paths are exactly what an
//! offline corpus usually lacks and exactly what a client gets wrong.
//!
//! This file is the arguments, the redaction rules and the dispatch. The conversation itself is in
//! [`mod@session`], which is the half that grows with every phase.

mod acts;
mod items;
mod session;
mod writes;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use mapi_client::MapiClient;

use crate::capture::{Recorder, scenario_directory, write_scenario};
use crate::scenario::acts::acts;
use crate::scenario::items::items;
use crate::scenario::session::session;
use crate::scenario::writes::writes;
use crate::scrub::Rules;
use crate::settings::Connection;
use crate::{Failure, report};

/// What `mapi-cli capture` was asked to do.
#[derive(Clone, Debug, Args)]
pub(crate) struct CaptureArguments {
    /// Which conversation to record.
    #[arg(value_enum)]
    scenario: Scenario,

    /// The `fixtures/` directory to write into.
    #[arg(long, value_name = "DIR", default_value = "fixtures")]
    root: PathBuf,

    /// The fixture set, which names the server these came from.
    #[arg(long, value_name = "NAME", default_value = "exchange-se")]
    set: String,

    /// The scenario directory, under the set. Defaults to the scenario's own name.
    #[arg(long, value_name = "NAME")]
    name: Option<String>,

    /// A tab-separated rules file naming everything to redact.
    ///
    /// Without one, nothing is redacted and the capture carries the real host name, the real
    /// mailbox GUIDs and the real distinguished name — which is why this is refused rather than
    /// defaulted. Pass `--no-scrub` to say you meant it.
    #[arg(long, value_name = "FILE")]
    scrub: Option<PathBuf>,

    /// Write the capture with no redaction at all.
    #[arg(long, conflicts_with = "scrub")]
    no_scrub: bool,

    /// Also keep the unredacted originals in a gitignored `raw/` directory.
    #[arg(long)]
    raw: bool,

    /// The distinguished name to use, for the scenarios that need a different one.
    #[arg(long, value_name = "DN")]
    user_dn_override: Option<String>,
}

/// The conversations worth committing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Scenario {
    /// `PING`, `Connect`, `RopLogon`, a paged hierarchy table, a paged contents table, and
    /// `Disconnect` — everything this workspace implements, in one Session Context.
    Session,
    /// A calendar, a contacts folder, and one message read to the bottom — its properties, its
    /// attachments, the message inside one of them, and a body that takes several round trips.
    ///
    /// Needs a mailbox seeded by `scripts\Add-LabItems.ps1`, and refuses to write a capture that
    /// would carry an empty calendar or a body small enough to fit one read.
    Items,
    /// A draft created with a recipient and an attachment, read back, and deleted again.
    ///
    /// The first scenario in the corpus that writes. It is self-cleaning — the delete is the last
    /// thing it does — and it declares the message id the server minted, so a re-capture of an
    /// unchanged server produces the same bytes.
    Writes,
    /// A message whose recipients are replaced, marked read and unread, submitted, moved, and
    /// swept up.
    ///
    /// The second scenario that writes, and the only one that captures a `RopSubmitMessage` — as a
    /// **refusal**, because a successful submit sends real mail on every re-capture and settles on
    /// its own schedule. The successful send is in `mapi-client`'s live suite instead.
    ///
    /// Declares two server-assigned identifiers rather than one: a move mints a new message id and
    /// reports it nowhere, so the scenario reads the destination folder to find out what the
    /// message is now called.
    Acts,
    /// A `Connect` the server refuses because it cannot map the distinguished name.
    ///
    /// Needs `--user-dn-override` naming something the server has never heard of.
    ConnectRefused,
}

impl Scenario {
    fn directory_name(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Items => "items",
            Self::Writes => "writes",
            Self::Acts => "acts",
            Self::ConnectRefused => "connect-refused",
        }
    }
}

/// Drives a scenario and writes it out.
pub(crate) async fn capture(
    connection: &Connection,
    arguments: &CaptureArguments,
) -> Result<(), Failure> {
    let rules = load_rules(arguments)?;
    let recorder = Arc::new(Recorder::default());

    let builder = match arguments.user_dn_override.as_deref() {
        Some(user_dn) => connection.builder_with_dn(user_dn)?,
        None => connection.builder()?,
    };
    let client = builder.observer(Arc::clone(&recorder)).build()?;

    println!("capturing `{}`", arguments.scenario.directory_name());
    match arguments.scenario {
        Scenario::Session => session(&client, &recorder).await?,
        Scenario::Items => items(&client, &recorder).await?,
        Scenario::Writes => writes(&client, &recorder).await?,
        Scenario::Acts => acts(&client, &recorder).await?,
        Scenario::ConnectRefused => connect_refused(&client, &recorder).await?,
    }

    let exchanges = recorder.exchanges();
    if exchanges.is_empty() {
        return Err(Failure::from(
            "the scenario produced no exchanges, so there is nothing to write".to_owned(),
        ));
    }

    let name = arguments
        .name
        .clone()
        .unwrap_or_else(|| arguments.scenario.directory_name().to_owned());
    let directory = scenario_directory(&arguments.root, &arguments.set, &name);

    let written = write_scenario(
        &directory,
        connection.endpoint()?,
        &exchanges,
        &recorder.assigned(),
        &rules,
        arguments.raw,
    )?;

    println!(
        "wrote {} exchange(s) to {}",
        written.len(),
        directory.display()
    );
    let mut redacted = 0_usize;
    for entry in &written {
        println!(
            "  {:<28} {:>9} in  {:>9} out",
            entry.stem,
            report::bytes(entry.request_bytes),
            report::bytes(entry.response_bytes)
        );
        for (_, count) in &entry.redactions {
            redacted = redacted.saturating_add(*count);
        }
    }

    if rules.len() > 0 {
        println!(
            "{redacted} redaction(s) applied from {} rule(s)",
            rules.len()
        );
        if redacted == 0 {
            return Err(Failure::from(
                "no rule matched anything. A rule that matches nothing looks exactly like a rule \
                 that worked, so this is treated as a failure rather than a clean capture."
                    .to_owned(),
            ));
        }
    }

    Ok(())
}

/// Reads the rules file, or refuses to run without one.
fn load_rules(arguments: &CaptureArguments) -> Result<Rules, Failure> {
    match (&arguments.scrub, arguments.no_scrub) {
        (Some(path), _) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| Failure::from(format!("{}: {error}", path.display())))?;
            Ok(Rules::parse(&text)?)
        }
        (None, true) => {
            eprintln!(
                "warning: --no-scrub, so this capture will carry the real host name, mailbox \
                 GUIDs and distinguished name. Do not commit it."
            );
            Ok(Rules::default())
        }
        (None, false) => Err(Failure::from(
            "no --scrub rules. A capture with nothing redacted carries the real host name, the \
             real mailbox GUIDs and the real distinguished name. Pass --scrub with a rules file, \
             or --no-scrub if you genuinely mean to keep them."
                .to_owned(),
        )),
    }
}

/// A `Connect` the server refuses, which is what an unmappable distinguished name looks like on
/// the wire.
///
/// The refusal arrives as HTTP 200 with `X-ResponseCode: 0` and a non-zero `ErrorCode` inside the
/// response body — a shape no amount of HTTP-level checking would catch, and the reason this
/// belongs in the corpus.
///
/// [MS-OXCMAPIHTTP] §2.2.4.1.3 — `Connect` failure response body
async fn connect_refused(client: &MapiClient, recorder: &Recorder) -> Result<(), Failure> {
    recorder.label("");
    match client.connect().await {
        Ok(session) => {
            // Tearing the unexpected session down is the polite thing to do before complaining.
            session.disconnect().await.ok();
            Err(Failure::from(
                "the server accepted the distinguished name. This scenario needs \
                 --user-dn-override naming a mailbox the server has never heard of."
                    .to_owned(),
            ))
        }
        Err(error) => {
            println!("  refused, as intended: {error}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
    struct Harness {
        #[command(flatten)]
        arguments: CaptureArguments,
    }

    fn parse(arguments: &[&str]) -> CaptureArguments {
        let mut all = vec!["capture"];
        all.extend_from_slice(arguments);
        Harness::try_parse_from(all)
            .expect("valid arguments")
            .arguments
    }

    /// The default that matters: capturing without saying anything about redaction is refused,
    /// because the failure mode is a committed fixture carrying a real deployment's identity.
    #[test]
    fn capturing_without_rules_is_refused_rather_than_defaulted() {
        let error = load_rules(&parse(&["session"])).expect_err("no rules");
        assert!(error.to_string().contains("--scrub"), "{error}");
        assert!(error.to_string().contains("--no-scrub"), "{error}");
    }

    #[test]
    fn no_scrub_is_an_explicit_choice_that_works() {
        let rules = load_rules(&parse(&["session", "--no-scrub"])).expect("explicit");
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn a_rules_file_that_does_not_exist_names_itself() {
        let error = load_rules(&parse(&["session", "--scrub", "no-such-file.tsv"]))
            .expect_err("missing file");
        assert!(error.to_string().contains("no-such-file.tsv"), "{error}");
    }

    /// `--scrub` and `--no-scrub` together is a contradiction, and clap refuses it before anything
    /// touches a server.
    #[test]
    fn scrubbing_and_not_scrubbing_are_mutually_exclusive() {
        assert!(
            Harness::try_parse_from(["capture", "session", "--scrub", "r.tsv", "--no-scrub"])
                .is_err()
        );
    }

    #[test]
    fn each_scenario_has_its_own_directory_name() {
        assert_eq!(Scenario::Session.directory_name(), "session");
        assert_eq!(Scenario::Items.directory_name(), "items");
        assert_eq!(Scenario::Writes.directory_name(), "writes");
        assert_eq!(Scenario::ConnectRefused.directory_name(), "connect-refused");
        assert_eq!(
            parse(&["connect-refused"]).scenario,
            Scenario::ConnectRefused
        );
        assert_eq!(parse(&["session"]).set, "exchange-se");
    }
}
