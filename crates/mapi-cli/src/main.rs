//! Diagnostic command-line client for MAPI over HTTP.
//!
//! This binary exists for two reasons. It is the tool you reach for when a live server is
//! behaving unexpectedly and you need to see the bytes — and it *is* the fixture capture tool
//! driven by `scripts/Capture-Fixtures.ps1`, which means the capture path is exercised by real
//! diagnostic use rather than only by the capture script.
//!
//! Keeping it a separate crate keeps argument parsing, terminal formatting and hex dumping out of
//! the library dependency tree. It is never published.
//!
//! ```text
//! mapi-cli ping                       is the endpoint there, and do the credentials work?
//! mapi-cli discover alice@example.test   what does Autodiscover say about this mailbox?
//! mapi-cli folders --recursive        walk the whole hierarchy, tagged by container class
//! mapi-cli folders --class IPF.Appointment   list the calendars
//! mapi-cli special --details          find Calendar, Contacts, Drafts and the rest
//! mapi-cli named --verify             what this store numbers the calendar properties as
//! mapi-cli messages --folder inbox    read a contents table
//! mapi-cli messages --newest-first --subject report   sort and filter on the server
//! mapi-cli events                     list calendar entries with start, end and location
//! mapi-cli contacts                   list contacts with their email addresses
//! mapi-cli message --id 0x...  --body open one message, its body and its attachments
//! mapi-cli draft --subject Hi --to a@b.test --attach notes.txt   write one into Drafts
//! mapi-cli contact --name 'Ada Lovelace' --email ada@example.test create a contact
//! mapi-cli event --subject Review --start 2026-09-10T09:00:00Z --end 2026-09-10T10:00:00Z
//! mapi-cli delete --folder drafts --id 0x...   take one back out again
//! mapi-cli properties                 dump every property of the Store object
//! mapi-cli capture session --out fixtures/exchange-se/session-en-us --scrub rules.tsv
//! ```
//!
//! Everything that identifies a deployment is read from the environment — the same four variables
//! `scripts/Test-Live.ps1` uses — so nothing about anybody's lab has to be typed, and a password
//! never reaches a shell history.

// A library must not write to a terminal, which is why the workspace denies these. A binary whose
// entire job is to write to one is the single place that has to opt out, and doing it here rather
// than at each call site keeps the deny in force everywhere else in the workspace.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "this binary's output is its purpose"
)]

mod capture;
mod command;
mod meta;
mod normalise;
mod report;
mod scenario;
mod scrub;
mod settings;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::settings::Connection;

/// Anything that stopped a command finishing.
///
/// A diagnostic tool has no error taxonomy worth designing: every failure here is reported to a
/// person and then the process exits. What matters is that the whole chain of causes is printed,
/// which [`report_failure`] does.
pub(crate) type Failure = Box<dyn core::error::Error + Send + Sync>;

#[derive(Debug, Parser)]
#[command(
    name = "mapi-cli",
    version,
    about = "Diagnostic client for MAPI over HTTP, and the fixture capture tool.",
    long_about = None,
)]
struct Cli {
    #[command(flatten)]
    connection: Connection,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Ask the endpoint whether it is there, without establishing anything.
    ///
    /// The cheapest check that the URL is right, that the credentials work and that whatever
    /// answers speaks MAPI/HTTP. [MS-OXCMAPIHTTP] §2.2.6
    Ping,

    /// Establish a Session Context and report what the server said about the mailbox.
    Connect,

    /// Walk a folder's hierarchy table.
    Folders {
        /// Which folder to list the children of. One of the thirteen a logon names, or a folder id
        /// as `0x...`. Defaults to the IPM subtree, which is the user-visible root.
        #[arg(long, value_name = "FOLDER", default_value = "ipm-subtree")]
        folder: String,

        /// Rows per round trip.
        #[arg(long, value_name = "ROWS", default_value_t = 50)]
        page_size: u16,

        /// List every folder below this one rather than its immediate children.
        ///
        /// Sets the `Depth` bit of `TableFlags`, so the whole tree arrives in one table.
        /// [MS-OXCFOLD] §2.2.1.13.1
        #[arg(long)]
        recursive: bool,

        /// Show only folders of this container class, and its refinements.
        ///
        /// `IPF.Appointment` lists the calendars; `IPF.Contact` lists the contact folders, its
        /// `IPF.Contact.MOC.QuickContacts` kind included. [MS-OXCFOLD] §2.2.2.2.2.3
        #[arg(long, value_name = "CLASS")]
        class: Option<String>,
    },

    /// Find the folders a logon does not name: Calendar, Contacts, Drafts and the rest.
    ///
    /// Two round trips: the entry ids come from binary properties on the Inbox, and only the
    /// server can turn a long-term entry id into an id `RopOpenFolder` takes.
    /// [MS-OXOSFLD] §2.2.3
    Special {
        /// Also open each one and report what it is: name, class, item count, and whether it is a
        /// search folder rather than a real one.
        #[arg(long)]
        details: bool,
    },

    /// Resolve the calendar and contact properties to the ids this mailbox uses for them.
    ///
    /// Named properties have no fixed id: each store allocates one from `0x8000` upwards the first
    /// time it needs the property, so the numbers this prints are meaningful only in the mailbox
    /// that answered. Run it against two mailboxes to see that. [MS-OXCPRPT] §3.1.2
    Named {
        /// Ask the store back what each resolved id is called, and fail if any disagrees.
        ///
        /// `RopGetNamesFromPropertyIds`, which is the only check on the response ordering that
        /// does not come from the same answer being checked. [MS-OXCROPS] §2.2.8.2
        #[arg(long)]
        verify: bool,

        /// Also ask what an id is called *here*, written as `0x8186`. Repeatable.
        ///
        /// Point it at an id another mailbox reported to see what the cross-store mistake actually
        /// costs: the same number is a different property, or none at all.
        #[arg(long = "id", value_name = "ID")]
        ids: Vec<String>,
    },

    /// Read a folder's contents table.
    Messages {
        /// Which folder to read. One of the thirteen a logon names, or a folder id as `0x...`.
        #[arg(long, value_name = "FOLDER", default_value = "inbox")]
        folder: String,

        /// Rows per round trip.
        #[arg(long, value_name = "ROWS", default_value_t = 50)]
        page_size: u16,

        /// How many rows to print. The rest are still read.
        #[arg(long, value_name = "ROWS", default_value_t = 20)]
        limit: usize,

        /// Order by delivery time, newest first, on the server.
        ///
        /// `RopSortTable`. The sort key has to be among the columns read, which
        /// [MS-OXCTABL] §2.2.2.3 requires and this client checks before sending.
        #[arg(long)]
        newest_first: bool,

        /// Show only messages whose subject contains this, matched by the server.
        ///
        /// `RopRestrict` with a content restriction, paired with an existence test because
        /// [MS-OXCDATA] §2.12.9.1 leaves the result on an item with no subject undefined.
        #[arg(long, value_name = "TEXT")]
        subject: Option<String>,
    },

    /// List a calendar's events, with real start times, end times and locations.
    ///
    /// Every one of those is a named property with no fixed id, so this resolves them against the
    /// store first and builds its column set from the answer. [MS-OXOCAL] §2.2.1
    Events {
        /// Which folder to read, as `0x...`. Defaults to the Calendar the entry-id chain finds.
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,

        /// How many events to print. The rest are still read.
        #[arg(long, value_name = "ROWS", default_value_t = 20)]
        limit: usize,
    },

    /// List a contacts folder, with the email addresses that make it worth listing.
    ///
    /// `PidLidEmail1EmailAddress` is a named property, so this costs the same lookup `events` does.
    /// [MS-OXOCNTC] §2.2.1.2
    Contacts {
        /// Which folder to read, as `0x...`. Defaults to the Contacts folder.
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,

        /// How many contacts to print. The rest are still read.
        #[arg(long, value_name = "ROWS", default_value_t = 20)]
        limit: usize,
    },

    /// Open one message: its properties, its recipients, its body and its attachments.
    ///
    /// The body is read with `RopOpenStream`, which is the only reading that works for a message of
    /// any size — a property fetch answers anything past the response buffer with an error rather
    /// than with the value. [MS-OXCPRPT] §2.2.3.2
    Message {
        /// Which folder it lives in. `RopOpenMessage` needs both ids.
        #[arg(long, value_name = "FOLDER", default_value = "inbox")]
        folder: String,

        /// The message id, as `0x...`. `mapi-cli messages` prints these.
        #[arg(long, value_name = "ID")]
        id: String,

        /// Also stream the plain-text and HTML bodies, and report how long each is.
        #[arg(long)]
        body: bool,
    },

    /// Write a message into Drafts, with recipients and an attachment.
    ///
    /// The recipients are addressed one-off — an SMTP address and nothing looked up — because the
    /// address book is NSPI, a separate endpoint this workspace does not implement.
    /// [MS-OXCDATA] §2.2.5.1
    Draft {
        /// The subject.
        #[arg(long, value_name = "TEXT", default_value = "Drafted by mapi-cli")]
        subject: String,

        /// The plain-text body.
        #[arg(long, value_name = "TEXT", default_value = "")]
        body: String,

        /// An SMTP address to address it to. Repeatable.
        #[arg(long = "to", value_name = "ADDRESS")]
        to: Vec<String>,

        /// A file to attach. Its bytes go through `RopWriteStream`, 16 KiB at a time.
        #[arg(long, value_name = "FILE")]
        attach: Option<std::path::PathBuf>,
    },

    /// Create a contact in the Contacts folder.
    ///
    /// Half of what makes a contact a contact is named properties, and one of those is a one-off
    /// entry id — without it a client shows the address and will not send to it.
    /// [MS-OXOCNTC] §2.2.1.2
    Contact {
        /// The display name. Split on its last space into a given name and a surname.
        #[arg(long, value_name = "NAME")]
        name: String,

        /// The SMTP address.
        #[arg(long, value_name = "ADDRESS")]
        email: String,

        /// The company name.
        #[arg(long, value_name = "NAME")]
        company: Option<String>,

        /// The business telephone number.
        #[arg(long, value_name = "NUMBER")]
        phone: Option<String>,
    },

    /// Create a single-instance appointment in the Calendar.
    ///
    /// Both instants are UTC and the `Z` is required: [MS-OXOCAL] §2.2.1.5 specifies the start in
    /// UTC, and this tool will not guess a time zone.
    Event {
        /// The subject.
        #[arg(long, value_name = "TEXT")]
        subject: String,

        /// When it starts, as `2026-09-10T09:00:00Z`.
        #[arg(long, value_name = "INSTANT")]
        start: String,

        /// When it ends, as `2026-09-10T10:00:00Z`.
        #[arg(long, value_name = "INSTANT")]
        end: String,

        /// Where it is.
        #[arg(long, value_name = "TEXT")]
        location: Option<String>,
    },

    /// Delete messages from a folder, by id.
    ///
    /// A soft delete: the server keeps a back-up copy. `RopDeleteMessages` succeeds whether or not
    /// it deleted anything, so this reports what the `PartialCompletion` flag said.
    /// [MS-OXCROPS] §2.2.4.11
    Delete {
        /// Which folder they are in. One of the thirteen a logon names, or a folder id as `0x...`.
        #[arg(long, value_name = "FOLDER", default_value = "drafts")]
        folder: String,

        /// A message id, as `0x...`. Repeatable.
        #[arg(long = "id", value_name = "ID", required = true)]
        ids: Vec<String>,
    },

    /// Dump the Store object's properties: display name, owner, size and quotas.
    ///
    /// With no `--tag`, this asks for everything the object holds, which is the only way to see
    /// what a deployment actually carries as against what [MS-OXCSTOR] §2.2.2.1 documents.
    Properties {
        /// A property tag to read, written id-first as `0x3001001F`. Repeatable. Without any,
        /// every property the Store object has is read.
        #[arg(long, value_name = "TAG")]
        tag: Vec<String>,
    },

    /// Locate a mailbox with Autodiscover.
    ///
    /// Needs no endpoint and no distinguished name — finding those is what it does.
    Discover {
        /// The email address to look up.
        address: String,
    },

    /// Drive a scenario against the live server and write it out as fixtures.
    Capture(scenario::CaptureArguments),
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            report_failure(&error);
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report_failure(error.as_ref());
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), Failure> {
    let connection = cli.connection;

    match cli.command {
        Command::Ping => command::ping(&connection).await,
        Command::Connect => command::connect(&connection).await,
        Command::Folders {
            folder,
            page_size,
            recursive,
            class,
        } => command::folders(&connection, &folder, page_size, recursive, class.as_deref()).await,
        Command::Special { details } => command::special(&connection, details).await,
        Command::Named { verify, ids } => command::named(&connection, verify, &ids).await,
        Command::Messages {
            folder,
            page_size,
            limit,
            newest_first,
            subject,
        } => {
            command::messages(
                &connection,
                &folder,
                page_size,
                limit,
                newest_first,
                subject.as_deref(),
            )
            .await
        }
        Command::Events { folder, limit } => {
            command::events(&connection, folder.as_deref(), limit).await
        }
        Command::Contacts { folder, limit } => {
            command::contacts(&connection, folder.as_deref(), limit).await
        }
        Command::Message { folder, id, body } => {
            command::message(&connection, &folder, &id, body).await
        }
        Command::Draft {
            subject,
            body,
            to,
            attach,
        } => command::draft(&connection, &subject, &body, &to, attach.as_deref()).await,
        Command::Contact {
            name,
            email,
            company,
            phone,
        } => {
            command::contact(
                &connection,
                &name,
                &email,
                company.as_deref(),
                phone.as_deref(),
            )
            .await
        }
        Command::Event {
            subject,
            start,
            end,
            location,
        } => command::event(&connection, &subject, &start, &end, location.as_deref()).await,
        Command::Delete { folder, ids } => command::delete(&connection, &folder, &ids).await,
        Command::Properties { tag } => command::properties(&connection, &tag).await,
        Command::Discover { address } => command::discover(&connection, &address).await,
        Command::Capture(arguments) => scenario::capture(&connection, &arguments).await,
    }
}

/// Prints a failure and every cause underneath it.
///
/// The chain is the whole point: `mapi-client` reports "the server refused the logon", and the
/// cause underneath names the distinguished name it refused. Printing only the top line would
/// throw away the half that says what to do.
fn report_failure(error: &(dyn core::error::Error + 'static)) {
    eprintln!("error: {error}");

    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    /// clap's own consistency checks: duplicate flags, an argument that is both required and
    /// defaulted, a subcommand with no help. Cheap, and it fails at build time rather than in
    /// somebody's hands.
    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn each_subcommand_parses_with_its_defaults() {
        let endpoint = "https://mail.example.test/mapi/emsmdb/?MailboxId=x@example.test";
        let common = ["mapi-cli", "--endpoint", endpoint, "--user-dn", "/o=X/cn=a"];

        let cli = Cli::try_parse_from([&common[..], &["folders"]].concat()).expect("folders");
        assert!(matches!(
            cli.command,
            Command::Folders { page_size: 50, .. }
        ));

        let cli = Cli::try_parse_from(
            [
                &common[..],
                &["messages", "--folder", "0x0100", "--limit", "3"],
            ]
            .concat(),
        )
        .expect("messages");
        match cli.command {
            Command::Messages { folder, limit, .. } => {
                assert_eq!(folder, "0x0100");
                assert_eq!(limit, 3);
            }
            other => panic!("{other:?}"),
        }

        let cli = Cli::try_parse_from([&common[..], &["ping"]].concat()).expect("ping");
        assert!(matches!(cli.command, Command::Ping));

        let cli = Cli::try_parse_from(
            [
                &common[..],
                &["draft", "--to", "a@b.test", "--to", "c@d.test"],
            ]
            .concat(),
        )
        .expect("draft");
        match cli.command {
            Command::Draft { to, attach, .. } => {
                assert_eq!(to, ["a@b.test", "c@d.test"]);
                assert!(attach.is_none());
            }
            other => panic!("{other:?}"),
        }

        // A delete with no id is refused rather than defaulted, because the default would be
        // "delete nothing" and a command that quietly does nothing is worse than one that fails.
        assert!(Cli::try_parse_from([&common[..], &["delete"]].concat()).is_err());
    }

    /// A failure prints its causes, because the cause is usually the actionable half.
    #[test]
    fn a_failure_is_reported_with_its_chain() {
        let dn = mapi_client::LegacyDn::new("").expect_err("an empty name is refused");
        // Nothing to assert about stderr here; what matters is that walking the chain terminates
        // rather than looping on a self-referential source.
        report_failure(&dn);
        let mut depth = 0_usize;
        let mut source = core::error::Error::source(&dn);
        while let Some(cause) = source {
            depth += 1;
            assert!(depth < 16, "the cause chain does not terminate");
            source = cause.source();
        }
    }
}
