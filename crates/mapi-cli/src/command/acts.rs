//! The commands that act on an item already in a mailbox: send it, move it, mark it read, and read
//! back what state it is in.
//!
//! The same division as [`writes`](super::writes) makes, for the same reason — and the follow-up
//! flag, which is the one of these that is a property list rather than an operation, is in
//! [`flag`](mod@flag) for that reason.
//!
//! **Every command in this file but one changes a mailbox, and one of them sends mail to a real
//! address.** `mapi-cli` has no dry-run mode: the subcommand is the consent.

/// The follow-up flag, which is a property list rather than a ROP.
mod flag;

pub(crate) use flag::flag;
use mapi_client::{
    MessageClass, MessageFlags, MessageId, NewAttachment, PropertyTag, PropertyValue, ReadFlags,
    Recipient, STATE_PROPERTIES, SpecialFolder, TaggedValue, WellKnownFolder,
};

use super::writes::string;
use crate::settings::Connection;
use crate::{Failure, report};

/// Write a message and send it.
///
/// `keep_copy` and `delete_original` are the two properties that decide where the message ends up,
/// and [MS-OXOMSG] presents them as independent — §2.2.3.10 copies it to a named folder, §2.2.3.8
/// deletes it. **On Exchange Server SE `15.02.2562.045` they are not independent**, measured across
/// all four combinations:
///
/// | `PidTagSentMailSvrEID` | `PidTagDeleteAfterSubmit` | where it ends up |
/// |---|---|---|
/// | present | absent | Sent Items |
/// | present | `0x01` | nowhere |
/// | absent | absent | still in Drafts |
/// | absent | `0x01` | nowhere |
///
/// So the delete wins, and the copy is a *move* rather than a copy: a send with neither leaves the
/// message where it was created rather than filing it anywhere. The command line offers the three
/// outcomes rather than the two properties for that reason, and setting a property the server would
/// disregard is exactly what it avoids.
pub(crate) async fn send(
    connection: &Connection,
    subject: &str,
    body: &str,
    to: &[String],
    attach: Option<&std::path::Path>,
    keep_copy: bool,
    delete_original: bool,
) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let drafts = logon.special_folder(SpecialFolder::Drafts).await?;
    let sent_items = logon.folder_id(WellKnownFolder::SentItems)?;

    let mut recipients = Vec::with_capacity(to.len());
    for address in to {
        recipients.push(Recipient::to(address.as_str(), address.as_str())?);
    }

    let mut attachments = Vec::new();
    if let Some(path) = attach {
        let bytes = std::fs::read(path)
            .map_err(|error| Failure::from(format!("{}: {error}", path.display())))?;
        let name = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| Failure::from(format!("{} has no file name", path.display())))?;
        println!("attaching {name} ({})", report::bytes(bytes.len()));
        attachments.push(NewAttachment::by_value(name, bytes)?);
    }

    let mut draft = logon
        .folder(drafts)
        .create_message(MessageClass::Note)
        .set([
            TaggedValue::new(PropertyTag::SUBJECT, string(subject))?,
            TaggedValue::new(PropertyTag::BODY, string(body))?,
        ])
        .to(recipients)
        .attach(attachments);
    if keep_copy {
        draft = draft.keep_copy_in(sent_items);
    }
    if delete_original {
        draft = draft.deleting_the_original();
    }

    let saved = draft.send().await?;
    println!("sent {:#018x} to {}", saved.id().as_u64(), to.join(", "));
    if keep_copy {
        println!("  filed in Sent Items ({:#018x})", sent_items.as_u64());
    } else if delete_original {
        println!("  kept nowhere: PidTagDeleteAfterSubmit removes it once it has gone");
    } else {
        println!(
            "  left in Drafts ({:#018x}), because nothing said where to file it",
            drafts.as_u64()
        );
    }
    for problem in saved.problems() {
        println!("  the server refused {problem}");
    }
    // The response says the server took the message and nothing more. Saying so is the difference
    // between a tool that reports what happened and one that reports what was hoped for.
    println!("  the server accepted it; delivery is reported in a mailbox, not in a response");

    logon.disconnect().await?;
    Ok(())
}

/// Submit a message that is already in the mailbox.
///
/// Deliberately says nothing about where the message will end up: that is decided by properties the
/// draft already carries, and this command did not write them.
pub(crate) async fn submit(connection: &Connection, folder: &str, id: &str) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let folder_id = super::resolve(&mut logon, folder).await?;
    let message = MessageId::new(super::parse_hexadecimal(id, "a message id")?);

    logon.message(folder_id, message).send().await?;
    println!("submitted {:#018x} from {folder}", message.as_u64());
    println!("  the server accepted it; delivery is reported in a mailbox, not in a response");
    println!(
        "  where it goes now is PidTagSentMailSvrEID and PidTagDeleteAfterSubmit on the message, \
         which this command did not write"
    );

    logon.disconnect().await?;
    Ok(())
}

/// Move or copy messages between two folders.
pub(crate) async fn move_messages(
    connection: &Connection,
    from: &str,
    to: &str,
    ids: &[String],
    copy: bool,
) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let source = super::resolve(&mut logon, from).await?;
    let destination = super::resolve(&mut logon, to).await?;
    let messages = message_ids(ids)?;

    let folder = logon.folder(source);
    let complete = if copy {
        folder.copy_messages(&messages, destination).await?
    } else {
        folder.move_messages(&messages, destination).await?
    };
    let what = if copy { "copied" } else { "moved" };

    // Reported only once the flag has been looked at, as the delete does: RopMoveCopyMessages
    // succeeds whether or not it moved anything, so printing the count first would say "moved 3
    // message(s)" on the very run whose next line is that some of them did not go.
    if !complete {
        return Err(Failure::from(format!(
            "the server reported partial completion, so at least one of those {} message(s) is \
             still in {from} ({:#018x}). RopMoveCopyMessages succeeds either way; the flag is the \
             only thing that says so.",
            messages.len(),
            source.as_u64(),
        )));
    }
    println!(
        "{what} {} message(s) from {from} ({:#018x}) to {to} ({:#018x})",
        messages.len(),
        source.as_u64(),
        destination.as_u64()
    );

    logon.disconnect().await?;
    Ok(())
}

/// Mark messages read or unread.
pub(crate) async fn mark(
    connection: &Connection,
    folder: &str,
    ids: &[String],
    unread: bool,
    receipt: bool,
) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let id = super::resolve(&mut logon, folder).await?;
    let messages = message_ids(ids)?;

    // The three the command line can reach. `rfGenerateReceiptOnly` is the fourth and is not
    // offered: sending a receipt without changing the read state is a thing a mail client does on
    // the user's behalf, not a thing a diagnostic tool should make easy.
    let flags = match (unread, receipt) {
        (true, _) => ReadFlags::Unread,
        (false, true) => ReadFlags::Read,
        (false, false) => ReadFlags::ReadQuietly,
    };

    let complete = logon.folder(id).set_read(&messages, flags).await?;
    if !complete {
        return Err(Failure::from(format!(
            "the server reported partial completion, so at least one of those {} message(s) is \
             unchanged in {folder} ({:#018x}). RopSetReadFlags succeeds either way.",
            messages.len(),
            id.as_u64(),
        )));
    }
    println!(
        "marked {} message(s) {} in {folder} ({:#018x}), ReadFlags 0x{:02X}",
        messages.len(),
        if unread { "unread" } else { "read" },
        id.as_u64(),
        flags.as_u8()
    );
    if !unread && !receipt {
        println!("  the read receipt, if one was pending, was suppressed rather than sent");
    }

    logon.disconnect().await?;
    Ok(())
}
/// Report what state a message is in: read or not, sent or not, flagged or not.
///
/// The only read-only command in this file, and it is here rather than with the other reads because
/// it is what makes the other three checkable. Setting a flag you cannot read back is a diagnostic
/// tool that has taken your word for it.
///
/// **Most of these come back absent on an ordinary message**, and that is the answer rather than a
/// failure: [MS-OXOFLAG] §2.2.1.1 has the flag properties exist only on a flagged message.
pub(crate) async fn state(connection: &Connection, folder: &str, id: &str) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let folder_id = super::resolve(&mut logon, folder).await?;
    let message = MessageId::new(super::parse_hexadecimal(id, "a message id")?);

    let properties = logon
        .message(folder_id, message)
        .properties()
        .read(STATE_PROPERTIES)
        .await?;

    println!("state of {:#018x} in {folder}", message.as_u64());
    for cell in &properties {
        println!("{}", report::property_line(cell));
    }

    let flags = properties
        .get(PropertyTag::MESSAGE_FLAGS)
        .and_then(PropertyValue::as_u32)
        .map(MessageFlags::new)
        .unwrap_or_default();
    println!("  read      {}", flags.is_read());
    println!("  draft     {}", flags.is_draft());
    println!("  submitted {}", flags.is_submitted());
    println!("  flags     {flags}");
    println!("  follow-up {}", flag::status_of(&properties));

    logon.disconnect().await?;
    Ok(())
}

/// Parses a list of `0x...` message ids.
fn message_ids(ids: &[String]) -> Result<Vec<MessageId>, Failure> {
    let mut messages = Vec::with_capacity(ids.len());
    for value in ids {
        messages.push(MessageId::new(super::parse_hexadecimal(
            value,
            "a message id",
        )?));
    }
    Ok(messages)
}

/// The current instant in Unix seconds.
///
/// Here rather than in a library: `mapi-proto` may not have a clock, and `mapi-client` has no
/// reason to invent a flag time on a caller's behalf.
fn now_unix() -> Result<i64, Failure> {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Failure::from("the system clock is before 1970".to_owned()))?;
    i64::try_from(since_epoch.as_secs())
        .map_err(|_| Failure::from("the system clock is past what a FILETIME can hold".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The clock a flag's timestamps come from is one a `FILETIME` can hold. Not a tautology: the
    /// conversion refuses anything before 1601, and this is the only clock in the workspace.
    #[test]
    fn the_clock_this_reads_is_one_a_filetime_can_express() {
        let now = now_unix().expect("a clock after 1970");
        assert!(mapi_client::FileTime::from_unix_seconds(now).is_some());
    }

    /// A `0x...` list, and the failure that names what was wrong with it rather than the count.
    #[test]
    fn message_ids_parse_or_say_which_one_did_not() {
        let parsed = message_ids(&["0x42".to_owned(), "0X0C01".to_owned()]).unwrap();
        assert_eq!(parsed, [MessageId::new(0x42), MessageId::new(0x0C01)]);

        let refused = message_ids(&["42".to_owned()]).expect_err("no 0x prefix");
        assert!(refused.to_string().contains("`42`"), "{refused}");
    }
}
