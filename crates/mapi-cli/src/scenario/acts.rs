//! The conversation that acts on an item: replacing its recipients, marking it read and unread,
//! submitting it, moving it, and taking it away again.
//!
//! The second scenario in the corpus that writes, and it inherits every rule the first one paid
//! for: it deletes what it made, it declares what the server minted, and everything it writes is
//! fixed text at a fixed length. Two rules are new.
//!
//! **The submit is captured as a refusal, and that is deliberate.** A successful
//! `RopSubmitMessage` sends real mail — to another mailbox, on every `Verify-Fixtures.ps1` run,
//! with a settle time nothing reports. A capture cannot clean up after it without polling two
//! mailboxes, and a poll makes the number of exchanges depend on how busy the transport was, which
//! is the one thing a byte-for-byte corpus cannot have. So the corpus carries the request bytes and
//! the shape of a refusal, and `mapi-client`'s live suite carries the successful send. That is the
//! same division this repository already draws between CI and `scripts\Test-Live.ps1`, and the
//! refusal is worth having on its own terms: error paths are exactly what an offline corpus usually
//! lacks.
//!
//! The refusal is a message with no recipients, which Exchange Server SE `15.02.2562.045` answers
//! with `ecInvalidRecips` — a name that does not lead a reader to expect it, and which
//! [MS-OXOMSG] §3.3.5.1.1 does not list. Nothing is delivered, and the message is left exactly as
//! it was: still `mfUnsent`, still deletable.
//!
//! **A move mints a new identifier and reports it nowhere**, so this scenario reads the destination
//! folder back to find out what the message is now called — and declares *that* id to the recorder
//! as well. Two server-assigned values in one conversation, where the first write scenario had one.
//!
//! What this is evidence for, none of which the other scenarios carry:
//!
//! * `RopRemoveAllRecipients`, and the fact that replacing a list is that ROP followed by
//!   `RopModifyRecipients` rather than either alone.
//! * `RopSetReadFlags` twice — once setting the flag, once clearing it — because the two differ by
//!   one byte and that byte is the one [MS-OXCMSG] §2.2.3.10.1 requires to carry a second bit.
//! * `RopSubmitMessage`, and a refusal that carries a body of nothing at all.
//! * `RopMoveCopyMessages` with two folder handles chained in one buffer.

use mapi_client::{
    FolderId, Logon, MessageClass, MessageId, PropertyRow, PropertyTag, PropertyValue, ReadFlags,
    Recipient, SpecialFolder, TaggedValue, WellKnownFolder,
};

use crate::Failure;
use crate::capture::Recorder;

/// A `PtypString` value, as everywhere else in this crate.
fn string(value: &str) -> PropertyValue {
    PropertyValue::String(value.into())
}

/// The subject the message carries, at a fixed length, so anything a failed run leaves behind is
/// identifiable by eye and two captures of an unchanged server agree byte for byte.
const SUBJECT: &str = "mapi-client-rs acts scenario";

/// The two addresses the message is created with, and the one that replaces them.
///
/// All of `example.test`, which [RFC 6761] reserves and which resolves nowhere — so a scenario that
/// somehow reached a successful submit could not deliver anywhere by accident.
const FIRST: [&str; 2] = ["ada@example.test", "grace@example.test"];
const SECOND: &str = "edsger@example.test";

/// The whole conversation, in one Session Context.
pub(super) async fn acts(
    client: &mapi_client::MapiClient,
    recorder: &Recorder,
) -> Result<(), Failure> {
    recorder.label("");
    let connection = client.connect().await?;

    recorder.label("logon");
    let mut logon = connection.logon().await?;

    recorder.label("drafts-folder");
    let drafts = logon.special_folder(SpecialFolder::Drafts).await?;
    let deleted = logon.folder_id(WellKnownFolder::DeletedItems)?;

    recorder.label("create-message");
    let saved = logon
        .folder(drafts)
        .create_message(MessageClass::Note)
        .set([TaggedValue::new(PropertyTag::SUBJECT, string(SUBJECT))?])
        .to([
            Recipient::to(FIRST[0], FIRST[0])?,
            Recipient::to(FIRST[1], FIRST[1])?,
        ])
        .save()
        .await?;
    recorder.server_assigned(
        "the message id RopSaveChangesMessage minted",
        &saved.id().as_u64().to_le_bytes(),
    );
    println!(
        "  created {:#018x} with 2 recipient(s)",
        saved.id().as_u64()
    );

    let outcome = act(&mut logon, recorder, drafts, deleted, saved.id()).await;

    // The cleanup runs whatever happened above, and reports afterwards: a lab that gains a message
    // per failed run is a worse problem than the failure that caused it. Both folders are tried,
    // because where the message is depends on how far the run got.
    recorder.label("delete-leftovers");
    let swept = sweep(&mut logon, drafts, deleted, saved.id()).await;

    recorder.label("");
    logon.disconnect().await?;

    outcome?;
    swept?;
    println!("  swept, so the mailbox is as it was found");
    Ok(())
}

/// Everything between the create and the cleanup.
///
/// Split out so that the cleanup runs on the way out of a failure as well as a success, which is
/// the whole of what makes a write scenario safe to re-capture.
async fn act(
    logon: &mut Logon,
    recorder: &Recorder,
    drafts: FolderId,
    deleted: FolderId,
    id: MessageId,
) -> Result<(), Failure> {
    // Replacing a list is two ROPs. `RopModifyRecipients` addresses rows by position and can never
    // shorten a list, so without the remove this message would keep all three addresses — and the
    // only place that would show up is in whose mailbox it landed.
    recorder.label("replace-recipients");
    logon
        .folder(drafts)
        .message(id)
        .update()
        .replacing_recipients()
        .to([Recipient::to(SECOND, SECOND)?])
        .save()
        .await?;

    recorder.label("read-recipients");
    let opened = logon.folder(drafts).message(id).open().await?;
    println!(
        "  {} recipient(s) after the replace",
        opened.recipient_count()
    );
    if opened.recipient_count() != 1 {
        return Err(Failure::from(format!(
            "the message has {} recipient(s) after RopRemoveAllRecipients and a one-row \
             RopModifyRecipients, so the capture would record a replace that did not replace.",
            opened.recipient_count()
        )));
    }

    // Read then unread, which differ by one byte — and that byte is the one [MS-OXCMSG]
    // §2.2.3.10.1 requires to carry `rfSuppressReceipt` alongside `rfClearReadFlag`.
    recorder.label("mark-read");
    require_complete(
        logon
            .folder(drafts)
            .set_read(&[id], ReadFlags::ReadQuietly)
            .await?,
        "marking the message read",
    )?;
    recorder.label("mark-unread");
    require_complete(
        logon
            .folder(drafts)
            .set_read(&[id], ReadFlags::Unread)
            .await?,
        "marking the message unread",
    )?;

    submit_refused(logon, recorder, drafts, id).await?;

    recorder.label("move-message");
    require_complete(
        logon.folder(drafts).move_messages(&[id], deleted).await?,
        "moving the message",
    )?;

    // And now the message is called something else. Nothing in the move's response says what, so
    // the destination folder is read back — with two columns rather than the default four, because
    // the default carries `PidTagMessageDeliveryTime` and this corpus cannot hold a clock.
    recorder.label("find-moved-message");
    let moved = find(logon, deleted).await?.ok_or_else(|| {
        Failure::from(
            "the moved message is not in Deleted Items, so either the move did not happen or the \
             folder holds something this scenario did not put there."
                .to_owned(),
        )
    })?;
    recorder.server_assigned(
        "the message id RopMoveCopyMessages minted",
        &moved.as_u64().to_le_bytes(),
    );
    println!("  moved, and now called {:#018x}", moved.as_u64());
    if moved == id {
        return Err(Failure::from(
            "the move kept the message's identifier, which is not what this lab measured. The \
             finding recorded against Folder::move_messages needs re-measuring before this \
             capture is committed."
                .to_owned(),
        ));
    }
    Ok(())
}

/// Submits a message the server will refuse, and requires it to be refused.
///
/// The one place in the corpus a `RopSubmitMessage` appears. Its recipients are taken off first,
/// which is what makes the refusal certain — and what makes the whole exchange free of side
/// effects, since a message the server will not accept is a message it does not deliver.
async fn submit_refused(
    logon: &mut Logon,
    recorder: &Recorder,
    drafts: FolderId,
    id: MessageId,
) -> Result<(), Failure> {
    recorder.label("remove-recipients");
    logon
        .folder(drafts)
        .message(id)
        .update()
        .replacing_recipients()
        .save()
        .await?;

    recorder.label("submit-refused");
    let refused = logon.folder(drafts).message(id).send().await;
    match refused {
        Err(mapi_client::Error::Rop { code, .. })
            if code == mapi_client::ErrorCode::INVALID_RECIPIENTS =>
        {
            println!("  the submit was refused with {code}, and nothing was sent");
            Ok(())
        }
        Err(other) => Err(Failure::from(format!(
            "the submit was refused with {other}, not the ecInvalidRecips this capture is built \
             around. A different refusal is a finding — record it before committing the capture."
        ))),
        Ok(()) => Err(Failure::from(
            "the server accepted a message with no recipients. That is mail this capture did not \
             mean to send, and the scenario has to be rebuilt around a refusal that still holds."
                .to_owned(),
        )),
    }
}

/// The one message in a folder, by the subject this scenario wrote.
///
/// Two columns rather than the default set: the default carries
/// `PidTagMessageDeliveryTime`, which is a clock, and a corpus compared byte for byte cannot hold
/// one.
async fn find(logon: &mut Logon, folder: FolderId) -> Result<Option<MessageId>, Failure> {
    let rows = logon
        .folder(folder)
        .contents()
        .columns([PropertyTag::MID, PropertyTag::SUBJECT])
        .collect()
        .await?;
    Ok(rows
        .iter()
        .find(|row| {
            row.string(PropertyTag::SUBJECT)
                .is_some_and(|found| found.as_str() == SUBJECT)
        })
        .and_then(PropertyRow::message_id))
}

/// Takes the message out of whichever folder it ended up in.
///
/// Both are tried because where it is depends on how far the run got, and a delete of a message
/// that is not there succeeds with `PartialCompletion` set — which is why the result is read rather
/// than assumed.
async fn sweep(
    logon: &mut Logon,
    drafts: FolderId,
    deleted: FolderId,
    id: MessageId,
) -> Result<(), Failure> {
    let mut left = Vec::new();
    for folder in [deleted, drafts] {
        if let Some(found) = find(logon, folder).await?
            && !logon.folder(folder).delete_messages(&[found]).await?
        {
            left.push(folder);
        }
    }
    if left.is_empty() {
        return Ok(());
    }
    Err(Failure::from(format!(
        "the server reported partial completion deleting the message this scenario created \
         ({:#018x}) from {} folder(s), so it is still in the mailbox. Remove it before capturing \
         again.",
        id.as_u64(),
        left.len()
    )))
}

/// Turns a `PartialCompletion` of "no" into a failure that names what was incomplete.
fn require_complete(complete: bool, what: &str) -> Result<(), Failure> {
    if complete {
        return Ok(());
    }
    Err(Failure::from(format!(
        "the server reported partial completion {what}. The ROP succeeds either way, so the flag \
         is the only thing that says so — and a capture of it would record an operation that did \
         not happen."
    )))
}
