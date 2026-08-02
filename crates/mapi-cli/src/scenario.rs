//! The conversations that become fixtures.
//!
//! A fixture set is only as good as what it covers, and the thing it has to cover is the *whole*
//! path this workspace claims to implement — including the paging that a small mailbox would
//! otherwise never exercise, and including a refusal, because error paths are exactly what an
//! offline corpus usually lacks and exactly what a client gets wrong.
//!
//! Page sizes here are deliberately far smaller than the default fifty. A lab mailbox has fifteen
//! folders and five messages; at the default both tables would arrive in one round trip and the
//! committed corpus would contain no evidence that a second page decodes against the column set
//! the first one established.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use mapi_client::{
    FOLDER_PROPERTIES, FolderId, Logon, MAILBOX_PROPERTIES, MapiClient, PropertyTag, PropertyValue,
    SpecialFolder, TaggedValue, WellKnownFolder,
};

use crate::capture::{Recorder, scenario_directory, write_scenario};
use crate::scrub::Rules;
use crate::settings::Connection;
use crate::{Failure, report};

/// Folders per round trip, chosen so that a fifteen-folder mailbox needs three of them.
const HIERARCHY_PAGE: u16 = 8;

/// Messages per round trip, chosen so that a five-message inbox needs three of them.
const CONTENTS_PAGE: u16 = 2;

/// Folders per round trip for the recursive read, chosen so that a lab mailbox's twenty-six needs
/// two of them.
///
/// Larger than [`HIERARCHY_PAGE`] on purpose: what the recursive capture is evidence *for* is the
/// `Depth` flag and the parent ids that make its flat rows a tree, and four pages of that would
/// treble the corpus to re-prove paging the immediate read already proves.
const DEEP_PAGE: u16 = 20;

/// The comment the capture tries to set on the Store object, and never does.
///
/// [MS-OXCSTOR] §2.2.2.1.2.1 note 14 says Exchange 2013 SP1 and later answer `ecAccessDenied` when
/// a client sets `PidTagComment`, and the lab confirms it — so this write is captured precisely
/// *because* it changes nothing, and it gives the corpus its only evidence of what a refused
/// property looks like: a ROP that succeeded, carrying a `PropertyProblem` that says the property
/// did not.
///
/// If a future server ever accepted it, the mailbox would gain this comment and
/// `Verify-Fixtures.ps1` would report the changed response. Both are visible; neither is quiet.
const COMMENT_PROBE: &str = "mapi-client-rs probe";

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
    /// A `Connect` the server refuses because it cannot map the distinguished name.
    ///
    /// Needs `--user-dn-override` naming something the server has never heard of.
    ConnectRefused,
}

impl Scenario {
    fn directory_name(self) -> &'static str {
        match self {
            Self::Session => "session",
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

/// Everything this workspace implements, in one Session Context.
async fn session(client: &MapiClient, recorder: &Recorder) -> Result<(), Failure> {
    recorder.label("");
    client.ping().await?;

    recorder.label("");
    let connection = client.connect().await?;
    println!("  connected as {:?}", connection.server().display_name());

    recorder.label("logon");
    let mut logon = connection.logon().await?;
    let subtree = logon.folder_id(WellKnownFolder::IpmSubtree)?;

    store_object(&mut logon, recorder).await?;
    hierarchy(&mut logon, recorder, subtree).await?;
    special_folders(&mut logon, recorder).await?;

    recorder.label("contents");
    let mut rows = logon
        .well_known(WellKnownFolder::Inbox)?
        .contents()
        .page_size(CONTENTS_PAGE)
        .rows();
    let mut messages = 0_usize;
    while rows.try_next().await?.is_some() {
        messages = messages.saturating_add(1);
    }
    recorder.label("contents-release");
    rows.close().await?;
    println!("  {messages} message(s) in the Inbox");

    recorder.label("");
    logon.disconnect().await?;
    Ok(())
}

/// The Store object read, and the write the server refuses.
///
/// `RopGetPropertiesAll` is deliberately *not* captured: its answer on the lab carries a dozen
/// server clocks that move on every logon, so a fixture of it would make `Verify-Fixtures.ps1`
/// report a difference every single run and the one difference that mattered would be lost in the
/// noise. Normalising a tagged property list is its own piece of work, and it belongs with the
/// rest of the write-fixture harness.
async fn store_object(logon: &mut Logon, recorder: &Recorder) -> Result<(), Failure> {
    recorder.label("properties");
    let mailbox = logon.store().read(MAILBOX_PROPERTIES).await?;
    println!(
        "  {} store properties, {} of them refused by the server",
        mailbox.len(),
        mailbox
            .iter()
            .filter(|cell| cell.value().as_error().is_some())
            .count()
    );

    // A write the server refuses, which is why it is safe to capture. See `COMMENT_PROBE`.
    recorder.label("properties-refused");
    let problems = logon
        .store()
        .write(&[TaggedValue::new(
            PropertyTag::COMMENT,
            PropertyValue::String(COMMENT_PROBE.into()),
        )?])
        .await?;
    println!(
        "  setting PidTagComment reported {} problem(s)",
        problems.len()
    );
    if problems.is_empty() {
        return Err(Failure::from(
            "the server accepted a write to PidTagComment. [MS-OXCSTOR] §2.2.2.1.2.1 note 14 says \
             it will not, and this capture is only safe to run because of that — the mailbox now \
             carries the probe comment. Remove it, and re-think this scenario before committing."
                .to_owned(),
        ));
    }
    Ok(())
}

/// Both hierarchy reads: the immediate children, paged, and then everything below at every level.
///
/// The first is where the paging evidence lives — the opening round trip sets the columns and every
/// later one is a bare `RopQueryRows` against a handle that still remembers them. The second is the
/// `Depth` flag, captured because the flat rows it produces are only a tree by way of
/// `PidTagParentFolderId`, and a corpus with no recursive read in it would prove nothing about
/// either.
async fn hierarchy(
    logon: &mut Logon,
    recorder: &Recorder,
    subtree: FolderId,
) -> Result<(), Failure> {
    recorder.label("hierarchy");
    let mut rows = logon
        .folder(subtree)
        .subfolders()
        .page_size(HIERARCHY_PAGE)
        .rows();
    let mut folders = 0_usize;
    while rows.try_next().await?.is_some() {
        folders = folders.saturating_add(1);
    }
    recorder.label("hierarchy-release");
    rows.close().await?;
    println!("  {folders} subfolder(s)");

    recorder.label("hierarchy-deep");
    let mut rows = logon
        .folder(subtree)
        .descendants()
        .page_size(DEEP_PAGE)
        .rows();
    let mut descendants = 0_usize;
    while rows.try_next().await?.is_some() {
        descendants = descendants.saturating_add(1);
    }
    recorder.label("hierarchy-deep-release");
    rows.close().await?;
    println!("  {descendants} folder(s) below the IPM subtree, at every level");
    Ok(())
}

/// The entry-id chain, and then the Calendar's own properties.
///
/// Three exchanges: the Inbox's binary properties, the conversion of every one of them that parsed,
/// and a property read on the folder that conversion found. The middle one is the corpus's only
/// evidence of what a `RopIdFromLongTermId` request and response look like, and the last is its
/// only `RopGetPropertiesSpecific` against something other than the Logon object.
async fn special_folders(logon: &mut Logon, recorder: &Recorder) -> Result<(), Failure> {
    recorder.label("special-folders");
    let special = logon.special_folders().await?;
    println!(
        "  {} of {} special folder(s) present",
        special.found(),
        SpecialFolder::ALL.len()
    );

    let Some(calendar) = special.get(SpecialFolder::Calendar) else {
        return Err(Failure::from(
            "this mailbox has no Calendar folder, so the capture would carry no evidence that the \
             entry-id chain reaches one. Open the mailbox in Outlook or OWA once and re-run."
                .to_owned(),
        ));
    };

    recorder.label("folder-properties");
    let details = logon
        .folder(calendar)
        .properties()
        .read(FOLDER_PROPERTIES)
        .await?;
    println!(
        "  the Calendar at {:#018x} answered with {} propert(y/ies)",
        calendar.as_u64(),
        details.len()
    );
    Ok(())
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
        assert_eq!(Scenario::ConnectRefused.directory_name(), "connect-refused");
        assert_eq!(
            parse(&["connect-refused"]).scenario,
            Scenario::ConnectRefused
        );
        assert_eq!(parse(&["session"]).set, "exchange-se");
    }

    /// The page sizes exist to force paging on a small lab mailbox, so a change that quietly
    /// raised them would empty the corpus of its only multi-page evidence.
    #[test]
    fn the_page_sizes_are_small_enough_to_force_paging() {
        const { assert!(HIERARCHY_PAGE < 15, "a lab mailbox has fifteen folders") }
        const { assert!(CONTENTS_PAGE < 5, "a seeded inbox has five messages") }
        const {
            assert!(
                DEEP_PAGE < 26,
                "a lab mailbox has twenty-six folders below the IPM subtree"
            );
        }
    }
}
