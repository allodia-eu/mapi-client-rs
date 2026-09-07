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
//! mapi-cli send --subject Hi --to a@b.test   write one and hand it to the transport
//! mapi-cli move --from inbox --to deleted-items --id 0x...   archive one
//! mapi-cli mark --folder inbox --id 0x... --unread   the read bit of PidTagMessageFlags
//! mapi-cli flag --folder inbox --id 0x... --colour red   the follow-up flag, which is not that
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
mod cli;
mod command;
mod meta;
mod normalise;
mod report;
mod scenario;
mod scrub;
mod settings;

use std::process::ExitCode;

use clap::Parser as _;

use crate::cli::{Cli, Command};
use crate::settings::Connection;

/// Anything that stopped a command finishing.
///
/// A diagnostic tool has no error taxonomy worth designing: every failure here is reported to a
/// person and then the process exits. What matters is that the whole chain of causes is printed,
/// which [`report_failure`] does.
pub(crate) type Failure = Box<dyn core::error::Error + Send + Sync>;

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

/// Dispatches the subcommands that only read, and hands the rest to [`run_changing`].
///
/// Two functions rather than one because the file limit and the lint on function length both bite
/// here, and the seam they force is the one the `command` module already draws: reading a mailbox
/// and changing one are different undertakings, and a reader looking for "what can this tool do to
/// my mailbox" should find the list in one place.
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
        Command::State { folder, id } => command::state(&connection, &folder, &id).await,
        Command::Properties { tag } => command::properties(&connection, &tag).await,
        Command::Discover { address, at } => {
            command::discover(&connection, &address, at.as_deref()).await
        }
        Command::Mailboxes { address, open } => {
            command::mailboxes(&connection, &address, open).await
        }
        Command::Capture(arguments) => scenario::capture(&connection, &arguments).await,
        changing => run_changing(connection, changing).await,
    }
}

/// Dispatches every subcommand that writes to a mailbox.
async fn run_changing(connection: Connection, command: Command) -> Result<(), Failure> {
    match command {
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
        Command::Send {
            subject,
            body,
            to,
            attach,
            no_copy,
            discard,
        } => {
            command::send(
                &connection,
                &subject,
                &body,
                &to,
                attach.as_deref(),
                !no_copy && !discard,
                discard,
            )
            .await
        }
        Command::Submit { folder, id } => command::submit(&connection, &folder, &id).await,
        Command::Move {
            from,
            to,
            ids,
            copy,
        } => command::move_messages(&connection, &from, &to, &ids, copy).await,
        Command::Mark {
            folder,
            ids,
            unread,
            receipt,
        } => command::mark(&connection, &folder, &ids, unread, receipt).await,
        Command::Flag {
            folder,
            id,
            text,
            colour,
            complete,
            clear,
        } => {
            command::flag(
                &connection,
                &folder,
                &id,
                &text,
                colour.as_deref(),
                complete,
                clear,
            )
            .await
        }
        Command::Delete { folder, ids } => command::delete(&connection, &folder, &ids).await,
        // Unreachable: `run` handles every other variant itself. A `match` that named them again
        // here would be a second list to keep in step with the first.
        reading => Err(Failure::from(format!(
            "{reading:?} does not change a mailbox and should not have reached here"
        ))),
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

        assert!(Cli::try_parse_from([&common[..], &["ping"]].concat()).is_ok());
    }

    /// The subcommands that change a mailbox, and what each of them refuses to guess.
    ///
    /// Every argument checked here has an obvious default that would be **wrong**: delete nothing,
    /// send it nowhere, move it into the folder it is already in, mark nothing. A command that
    /// quietly does nothing is worse than one that fails, and one that quietly does the wrong thing
    /// to a mailbox is worse again.
    #[test]
    fn the_commands_that_change_a_mailbox_refuse_to_guess() {
        let endpoint = "https://mail.example.test/mapi/emsmdb/?MailboxId=x@example.test";
        let common = ["mapi-cli", "--endpoint", endpoint, "--user-dn", "/o=X/cn=a"];

        assert!(Cli::try_parse_from([&common[..], &["delete"]].concat()).is_err());

        // Nor a send with no recipient, nor a move with no destination, nor a mark with no id.
        // Every one of those has an obvious default that would be wrong: send it nowhere, move it
        // to the folder it is in, mark nothing.
        assert!(Cli::try_parse_from([&common[..], &["send"]].concat()).is_err());
        assert!(
            Cli::try_parse_from([&common[..], &["move", "--to", "inbox"]].concat()).is_err(),
            "a move with no id"
        );
        assert!(Cli::try_parse_from([&common[..], &["mark"]].concat()).is_err());

        let cli =
            Cli::try_parse_from([&common[..], &["send", "--to", "a@b.test", "--no-copy"]].concat())
                .expect("send");
        match cli.command {
            Command::Send {
                to,
                no_copy,
                discard,
                ..
            } => {
                assert_eq!(to, ["a@b.test"]);
                assert!(no_copy);
                assert!(!discard, "a send keeps the message unless told not to");
            }
            other => panic!("{other:?}"),
        }

        // The two are refused together rather than resolved: on Exchange the delete suppresses the
        // Sent Items copy, so "no copy, and also delete" is one outcome asked for twice.
        assert!(
            Cli::try_parse_from(
                [
                    &common[..],
                    &["send", "--to", "a@b.test", "--no-copy", "--discard"]
                ]
                .concat()
            )
            .is_err()
        );

        // Marking a message read and sending the sender a receipt for it are one ROP, and the
        // receipt is off unless asked for. Marking it unread cannot ask for one at all.
        let cli =
            Cli::try_parse_from([&common[..], &["mark", "--id", "0x42", "--unread"]].concat())
                .expect("mark");
        match cli.command {
            Command::Mark {
                folder,
                unread,
                receipt,
                ..
            } => {
                assert_eq!(folder, "inbox");
                assert!(unread);
                assert!(!receipt);
            }
            other => panic!("{other:?}"),
        }
        assert!(
            Cli::try_parse_from(
                [
                    &common[..],
                    &["mark", "--id", "0x42", "--unread", "--receipt"]
                ]
                .concat()
            )
            .is_err(),
            "a receipt for a message being marked unread is not a thing"
        );

        // `--complete` and `--clear` are opposite instructions, so asking for both is refused
        // rather than resolved to whichever the match arm happens to test first.
        assert!(
            Cli::try_parse_from(
                [
                    &common[..],
                    &["flag", "--id", "0x42", "--complete", "--clear"]
                ]
                .concat()
            )
            .is_err()
        );
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
