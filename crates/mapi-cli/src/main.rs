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
//! mapi-cli folders                    walk the hierarchy table
//! mapi-cli messages --folder inbox    read a contents table
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
        Command::Folders { folder, page_size } => {
            command::folders(&connection, &folder, page_size).await
        }
        Command::Messages {
            folder,
            page_size,
            limit,
        } => command::messages(&connection, &folder, page_size, limit).await,
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
