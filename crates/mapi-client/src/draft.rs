//! Creating an item, giving it recipients and attachments, and committing it.
//!
//! Reading an item is one round trip because the opens chain through a single ROP buffer. Writing
//! one is not, and the reason is worth stating: an attachment's content goes through a stream, a
//! stream write is bounded by a two-byte length field, and the message must be saved **after**
//! every attachment it holds. So the shape is fixed — create, fill, attach, save — and the round
//! trips follow from it rather than from how the API is written.
//!
//! **Nothing exists until the save.** [MS-OXCMSG] §3.2.5.2 has the server hold a new Message object
//! until `RopSaveChangesMessage` arrives, so every failure before that point leaves the mailbox
//! exactly as it was. That is what makes this safe to run against a real mailbox: a half-built
//! message is not a message.
//!
//! [MS-OXCMSG] §3.1.4.2 — creating a Message object
//! [MS-OXCPRPT] §3.1.4.16 — an attachment saves before its message, never after

use mapi_proto::{
    AttachmentNumber, FolderId, MessageClass, MessageId, ObjectHandle, PropertyProblem,
    PropertyTag, PropertyValue, RopBatch, RopId, RopResponse, ServerEntryId, SubmitFlags,
    TaggedValue,
};

use crate::connection::Connection;
use crate::error::{Error, Result};

/// One attachment of the item being created, which is its own object with its own save.
mod attachment;

pub use attachment::NewAttachment;

/// An item being created. Nothing is sent until [`save`](NewMessage::save).
///
/// ```no_run
/// # use mapi_client::{Logon, MessageClass, NewAttachment, PropertyTag, PropertyValue,
/// #                   Recipient, SpecialFolder, TaggedValue};
/// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
/// let drafts = logon.special_folder(SpecialFolder::Drafts).await?;
/// let saved = logon
///     .folder(drafts)
///     .create_message(MessageClass::Note)
///     .set([TaggedValue::new(
///         PropertyTag::SUBJECT,
///         PropertyValue::String("Notes from the lab".into()),
///     )?])
///     .to([Recipient::to("Ada Lovelace", "ada@example.test")?])
///     .attach([NewAttachment::by_value("notes.txt", *b"one line\n")?])
///     .save()
///     .await?;
/// println!("{:#018x}", saved.id().as_u64());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct NewMessage<'a> {
    connection: &'a mut Connection,
    logon: ObjectHandle,
    folder: FolderId,
    class: MessageClass,
    properties: Vec<TaggedValue>,
    recipients: Vec<mapi_proto::Recipient>,
    attachments: Vec<NewAttachment>,
    sent_items: Option<FolderId>,
    delete_after_submit: bool,
    submit: bool,
}

impl<'a> NewMessage<'a> {
    pub(crate) fn new(
        connection: &'a mut Connection,
        logon: ObjectHandle,
        folder: FolderId,
        class: MessageClass,
    ) -> Self {
        Self {
            connection,
            logon,
            folder,
            class,
            properties: Vec::new(),
            recipients: Vec::new(),
            attachments: Vec::new(),
            sent_items: None,
            delete_after_submit: false,
            submit: false,
        }
    }

    /// Adds properties to the item.
    ///
    /// `PidTagMessageClass` is written first, from the class this builder was made with, so a value
    /// given here for that tag is applied *after* it and wins — which is how a caller says
    /// something the [`MessageClass`] catalogue does not cover.
    #[must_use]
    pub fn set<I>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = TaggedValue>,
    {
        self.properties.extend(values);
        self
    }

    /// Addresses the item.
    ///
    /// Every recipient is a one-off — an SMTP address and a display name, with no directory lookup
    /// — which is what makes addressing reachable without the address book endpoint.
    #[must_use]
    pub fn to<I>(mut self, recipients: I) -> Self
    where
        I: IntoIterator<Item = mapi_proto::Recipient>,
    {
        self.recipients.extend(recipients);
        self
    }

    /// Hangs attachments off the item.
    #[must_use]
    pub fn attach<I>(mut self, attachments: I) -> Self
    where
        I: IntoIterator<Item = NewAttachment>,
    {
        self.attachments.extend(attachments);
        self
    }

    /// Files the sent message in a folder — Sent Items, ordinarily.
    ///
    /// `PidTagSentMailSvrEID`, and a builder method rather than a property a caller remembers
    /// because of what forgetting it does: [MS-OXOMSG] §2.2.3.10 makes the filing conditional on
    /// the property being present, and a send without it leaves the message wherever it was
    /// created. See [`send`](Self::send) for the measured table.
    ///
    /// **The document says "copied" and the server moves.** §2.2.3.10 has "a copy of the message
    /// is created in the specified folder after the message is sent", which reads as leaving the
    /// original in place too. On Exchange Server SE `15.02.2562.045` the original does not stay: a
    /// message drafted in Drafts and sent with this set is in Sent Items and nowhere else — **and
    /// it is there under a different id** from the one [`SavedMessage::id`] reported, as a
    /// [`Folder::move_messages`](crate::Folder::move_messages) also mints one. Nothing in the
    /// response says what the new id is.
    ///
    /// The folder must not be a search folder, and the account needs write permission on it.
    ///
    /// Ignored by [`save`](Self::save), which submits nothing.
    ///
    /// [MS-OXOMSG] §2.2.3.10 — `PidTagSentMailSvrEID`
    #[must_use]
    pub const fn keep_copy_in(mut self, folder: FolderId) -> Self {
        self.sent_items = Some(folder);
        self
    }

    /// Removes the message once it has gone, keeping it nowhere.
    ///
    /// `PidTagDeleteAfterSubmit`. **This overrides
    /// [`keep_copy_in`](Self::keep_copy_in)** — [MS-OXOMSG] §3.3.5.1.3 lists the two as separate
    /// bullets with nothing saying one cancels the other, and on Exchange Server SE
    /// `15.02.2562.045` the delete wins: a message sent with both is delivered and then exists in
    /// no folder of the sender's mailbox at all. Setting both is therefore a way to lose the record
    /// of a send while believing one was kept, which is why [`send`](Self::send) documents the
    /// whole table rather than the two properties separately.
    ///
    /// Ignored by [`save`](Self::save), which submits nothing — and the property is written all
    /// the same, because a draft saved now and sent later means the same thing by it.
    ///
    /// [MS-OXOMSG] §2.2.3.8 — `PidTagDeleteAfterSubmit`
    #[must_use]
    pub const fn deleting_the_original(mut self) -> Self {
        self.delete_after_submit = true;
        self
    }

    /// Creates the item, commits it and hands it to the transport.
    ///
    /// *"Send a message"*. Everything [`save`](Self::save) does, and then a `RopSubmitMessage` in
    /// the same buffer as the final save — which is the only order that works, because the submit
    /// acts on what is in the store rather than on the handle's uncommitted state.
    ///
    /// **This sends real mail**, and what comes back says only that the server accepted it. A bad
    /// address produces a non-delivery report in the sender's Inbox some time later, not an error
    /// here.
    ///
    /// **Where the message ends up afterwards is two properties, and they interact.** Measured on
    /// Exchange Server SE `15.02.2562.045` across all four combinations:
    ///
    /// | [`keep_copy_in`] | [`deleting_the_original`] | where it ends up |
    /// |---|---|---|
    /// | set | unset | the folder named |
    /// | set | set | nowhere |
    /// | unset | unset | still where it was created |
    /// | unset | set | nowhere |
    ///
    /// [`keep_copy_in`]: Self::keep_copy_in
    /// [`deleting_the_original`]: Self::deleting_the_original
    ///
    /// [MS-OXOMSG] §3.3.5.1.3 lists the two as independent, and they are not: the delete wins, and
    /// the "copy" is a move. A caller that sets both to be safe keeps no record at all.
    ///
    /// The message also has to be complete before the server will take it, and what "complete"
    /// means is [MS-OXOMSG] §3.2.4.1's — recipients, and the sender properties. This crate does not
    /// decide which of those to write for a caller, for the same reason it does not decide what
    /// makes a contact a contact. Exchange fills the sender properties in itself
    /// (§3.3.5.1.3.2), so a submit with none of them set is accepted and delivered.
    ///
    /// # Errors
    ///
    /// As [`save`](Self::save), plus whatever the submit is refused with —
    /// [`ecTooManyRecips`](mapi_proto::ErrorCode::TOO_MANY_RECIPIENTS), which means **none** of the
    /// recipients got it, and
    /// [`ecMaxSubmissionExceeded`](mapi_proto::ErrorCode::MAX_SUBMISSION_EXCEEDED) for a message
    /// larger than `PidTagMaximumSubmitMessageSize` on the Store object.
    ///
    /// **A refused submit leaves the message saved.** The save happened; only the sending did not,
    /// so what is left behind is an ordinary draft rather than nothing.
    ///
    /// [MS-OXCROPS] §2.2.7.1 — `RopSubmitMessage`
    pub async fn send(mut self) -> Result<SavedMessage> {
        self.submit = true;
        self.write().await
    }

    /// Creates the item and commits it, reporting the id it was given.
    ///
    /// **Two round trips, plus one per attachment and one more per 16 KiB of attachment content.**
    /// The first creates the message, writes its properties and its recipients; the last saves it.
    /// The order is not an implementation detail: an attachment saved after its message is lost
    /// without anything failing ([MS-OXCPRPT] §3.1.4.16), and a message never saved leaves nothing
    /// behind at all.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused any step — `ecAccessDenied` for a folder this account
    /// may not write to — plus whatever a round trip failed with, and [`Error::Protocol`] if a
    /// value could not be encoded without corrupting the buffer.
    ///
    /// A refusal before the final save leaves the mailbox unchanged. A refusal *of* the final save
    /// does too, for the same reason.
    pub async fn save(self) -> Result<SavedMessage> {
        self.write().await
    }

    async fn write(self) -> Result<SavedMessage> {
        let Self {
            connection,
            logon,
            folder,
            class,
            properties,
            recipients,
            attachments,
            sent_items,
            delete_after_submit,
            submit,
        } = self;

        let mut values = vec![TaggedValue::new(
            PropertyTag::MESSAGE_CLASS,
            PropertyValue::String(class.as_str().into()),
        )?];
        if let Some(folder) = sent_items {
            values.push(TaggedValue::new(
                PropertyTag::SENT_MAIL_SVR_EID,
                PropertyValue::ServerId(ServerEntryId::folder(folder)),
            )?);
        }
        if delete_after_submit {
            values.push(TaggedValue::new(
                PropertyTag::DELETE_AFTER_SUBMIT,
                PropertyValue::Boolean(true),
            )?);
        }
        values.extend(properties);

        let mut batch = RopBatch::new();
        let logon_slot = batch.bind(logon);
        let message = batch.create_message(logon_slot, folder);
        batch.set_properties(message, &values);
        if !recipients.is_empty() {
            batch.modify_recipients(message, &recipients);
        }

        let execution = connection.execute(batch, "creating a message").await?;
        let mut problems = execution
            .property_problems()
            .map(|response| response.problems().to_vec())
            .unwrap_or_default();
        let handle = execution
            .handle(message)
            .filter(|handle| !handle.is_none())
            .ok_or(Error::Unexpected {
                expected: "a handle for the new message",
                found: "no message handle in the batch's responses",
            })?;

        let mut numbers = Vec::with_capacity(attachments.len());
        for attachment in attachments {
            match attachment.write(connection, handle).await {
                Ok((number, refused)) => {
                    numbers.push(number);
                    problems.extend(refused);
                }
                // The message handle is still open and nothing has been committed, so it is given
                // back before the failure is reported. A caller drafting a hundred messages that
                // each fail on their attachment would otherwise leave a hundred handles behind on
                // a connection that is still perfectly usable.
                Err(error) => {
                    abandon(connection, handle).await;
                    return Err(error);
                }
            }
        }

        // Deliberately no release on this failure path, where the one above has one. `commit`
        // sends the release in the same buffer as the save, and [MS-OXCROPS] §3.2.5.1 has the
        // server work through the list in order rather than stopping at the first refusal — so a
        // refused save is very likely followed by a release that ran. Releasing again would hand
        // back a handle value the server is free to have reissued, which is worse than leaking
        // one the Session Context reclaims at disconnect anyway.
        let id = commit(connection, handle, submit).await?;
        Ok(SavedMessage {
            id,
            attachments: numbers,
            problems,
            sent: submit,
        })
    }
}

/// Gives a handle back, ignoring whether the server minded.
///
/// A failure here is not worth reporting over the one that caused it: the Session Context times the
/// handle out on its own.
async fn abandon(connection: &mut Connection, handle: ObjectHandle) {
    let mut batch = RopBatch::new();
    let slot = batch.bind(handle);
    batch.release(slot);
    let _ = connection.execute(batch, "releasing a message").await;
}

/// Saves the message, optionally submits it, and gives its handle back — all in one round trip.
///
/// The order is the whole point. `RopSubmitMessage` acts on what is in the store, so a submit
/// before the save sends the message as it was before the properties, the recipients and the
/// attachments were written — which is to say an empty one, successfully.
async fn commit(
    connection: &mut Connection,
    handle: ObjectHandle,
    submit: bool,
) -> Result<MessageId> {
    let mut batch = RopBatch::new();
    let message = batch.bind(handle);
    batch.save_message(message);
    if submit {
        batch.submit_message(message, SubmitFlags::None);
    }
    batch.release(message);

    let what = if submit {
        "sending a message"
    } else {
        "saving a message"
    };
    let execution = connection.execute(batch, what).await?;
    if submit
        && !execution
            .responses()
            .iter()
            .any(|response| response.succeeded(RopId::SUBMIT_MESSAGE))
    {
        return Err(Error::Unexpected {
            expected: "a RopSubmitMessage response",
            found: "no submission in the batch's responses",
        });
    }
    execution
        .responses()
        .iter()
        .find_map(RopResponse::as_saved_message)
        .map(mapi_proto::SaveChangesResponse::message_id)
        .ok_or(Error::Unexpected {
            expected: "a RopSaveChangesMessage response",
            found: "no saved message in the batch's responses",
        })
}

/// What creating an item came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedMessage {
    id: MessageId,
    attachments: Vec<AttachmentNumber>,
    problems: Vec<PropertyProblem>,
    sent: bool,
}

impl SavedMessage {
    /// The id the item now has, which is what names it from here on.
    ///
    /// **Except after a send.** A submitted message is filed by the server, and filing it mints a
    /// new id — so after [`NewMessage::send`] this names the message as it was at the moment of
    /// submission and not as it is now. Measured on Exchange Server SE `15.02.2562.045`: a message
    /// saved as `0x51422B1800000001` appeared in Sent Items as `0xF1512B1800000001`.
    #[must_use]
    pub const fn id(&self) -> MessageId {
        self.id
    }

    /// The number each attachment was given, in the order they were added.
    #[must_use]
    pub fn attachments(&self) -> &[AttachmentNumber] {
        &self.attachments
    }

    /// The properties the server refused, on the message and on its attachments together.
    ///
    /// **Empty is not proof that every property was written.** A server may disregard one that is
    /// read-only for the client and say nothing at all about it ([MS-OXCPRPT] §3.2.5.4), so this is
    /// the failures a server chose to report and not the absence of failure.
    #[must_use]
    pub fn problems(&self) -> &[PropertyProblem] {
        &self.problems
    }

    /// Whether the server reported a problem with any property.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty()
    }

    /// Whether the message was handed to the transport as well as saved.
    ///
    /// `true` only after [`NewMessage::send`]. It says the server accepted the message, which is
    /// all a `RopSubmitMessage` response says — delivery arrives in a mailbox, not in a response.
    #[must_use]
    pub const fn is_sent(&self) -> bool {
        self.sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_message_reports_what_the_server_said_about_it() {
        let saved = SavedMessage {
            id: MessageId::new(0x0D01_0000_0000_0042),
            attachments: vec![AttachmentNumber::new(0)],
            problems: Vec::new(),
            sent: false,
        };
        assert_eq!(saved.id(), MessageId::new(0x0D01_0000_0000_0042));
        assert_eq!(saved.attachments(), [AttachmentNumber::new(0)]);
        assert!(saved.is_clean());
        assert!(saved.problems().is_empty());
        // A save is not a send, and the difference is worth being able to print: the two paths
        // differ by one ROP and produce the same id.
        assert!(!saved.is_sent());
        assert!(
            SavedMessage {
                sent: true,
                ..saved
            }
            .is_sent()
        );
    }
}
