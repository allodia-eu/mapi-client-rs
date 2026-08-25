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
    PropertyTag, PropertyValue, RopBatch, RopResponse, TaggedValue,
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
        let Self {
            connection,
            logon,
            folder,
            class,
            properties,
            recipients,
            attachments,
        } = self;

        let mut values = vec![TaggedValue::new(
            PropertyTag::MESSAGE_CLASS,
            PropertyValue::String(class.as_str().into()),
        )?];
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
        let id = commit(connection, handle).await?;
        Ok(SavedMessage {
            id,
            attachments: numbers,
            problems,
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

/// Saves the message and gives its handle back, in one round trip.
async fn commit(connection: &mut Connection, handle: ObjectHandle) -> Result<MessageId> {
    let mut batch = RopBatch::new();
    let message = batch.bind(handle);
    batch.save_message(message).release(message);

    let execution = connection.execute(batch, "saving a message").await?;
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
}

impl SavedMessage {
    /// The id the item now has, which is what names it from here on.
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
        };
        assert_eq!(saved.id(), MessageId::new(0x0D01_0000_0000_0042));
        assert_eq!(saved.attachments(), [AttachmentNumber::new(0)]);
        assert!(saved.is_clean());
        assert!(saved.problems().is_empty());
    }
}
