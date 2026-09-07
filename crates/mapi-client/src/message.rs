//! A message that has been named, its attachments, and the message an attachment can turn out to
//! be.
//!
//! Nothing here sends anything on its own. Each of these is a description of where an object lives
//! plus a borrow of the [`Logon`](crate::Logon); the ROPs that open the chain travel in the same
//! buffer as the operation that follows, so reaching an attachment's bytes is one round trip and
//! not four.
//!
//! [MS-OXCMSG] — Message and Attachment Object Protocol

use core::borrow::Borrow;

use mapi_proto::{
    AttachmentNumber, FolderId, MessageId, MessageMode, ObjectHandle, OpenMessageResponse,
    PropertyProblem, PropertyTag, Recipient, RopBatch, RopId, RopResponse, SubmitFlags,
    TaggedValue,
};

use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::properties::Properties;
use crate::stream::StreamRead;
use crate::table::{TableKind, TableRead};
use crate::target::{MessagePath, Target};

/// An attachment of a message, and the message an attachment can turn out to be.
mod attachment;

pub use attachment::{Attachment, EmbeddedMessage};

/// A message that has been named but not yet opened.
#[derive(Debug)]
pub struct Message<'a> {
    connection: &'a mut Connection,
    path: MessagePath,
}

impl<'a> Message<'a> {
    pub(crate) fn new(
        connection: &'a mut Connection,
        logon: ObjectHandle,
        folder: FolderId,
        id: MessageId,
    ) -> Self {
        Self {
            connection,
            path: MessagePath { logon, folder, id },
        }
    }

    /// This message's id.
    #[must_use]
    pub const fn id(&self) -> MessageId {
        self.path.id
    }

    /// The folder it lives in.
    ///
    /// Part of the message's identity here, because `RopOpenMessage` takes both ids: a message id
    /// alone is not enough to open one.
    #[must_use]
    pub const fn folder(&self) -> FolderId {
        self.path.folder
    }

    /// Opens the message and reports what the open itself said.
    ///
    /// The subject's two halves, the recipient count and whether the message holds named
    /// properties — all of it comes back with the open rather than needing a property fetch. The
    /// last is worth having before a calendar read: a message with no named properties cannot be
    /// an appointment, and asking the store to resolve ten names for it is a wasted round trip.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused the open — `NotFound` for a message that has been moved
    /// or deleted since the contents table named it — plus whatever the round trip failed with.
    ///
    /// [MS-OXCROPS] §2.2.6.1 — `RopOpenMessage`
    pub async fn open(self) -> Result<OpenMessageResponse> {
        let mut batch = RopBatch::new();
        let opened = Target::Message(self.path).open(&mut batch);
        opened.release(&mut batch);

        let execution = self.connection.execute(batch, "opening a message").await?;
        execution
            .responses()
            .iter()
            .find_map(|response| response.as_open_message(RopId::OPEN_MESSAGE))
            .cloned()
            .ok_or(Error::Unexpected {
                expected: "a RopOpenMessage response",
                found: "no opened message in the batch's responses",
            })
    }

    /// This message's own properties.
    ///
    /// One round trip: the message is opened, read and released in a single `Execute`.
    ///
    /// ```no_run
    /// # use mapi_client::{Logon, MESSAGE_PROPERTIES, MessageId, PropertyTag, WellKnownFolder};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let inbox = logon.folder_id(WellKnownFolder::Inbox)?;
    /// let details = logon
    ///     .message(inbox, MessageId::new(0x0100_0000_0000_0001))
    ///     .properties()
    ///     .read(MESSAGE_PROPERTIES)
    ///     .await?;
    /// println!("{:?}", details.string(PropertyTag::MESSAGE_CLASS));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [MS-OXCMSG] §2.2.1 — Message object properties
    #[must_use]
    pub fn properties(self) -> Properties<'a> {
        Properties::for_target(self.connection, Target::Message(self.path))
    }

    /// Reads one property whole, however long it is.
    ///
    /// The only correct way to read a body: a property fetch answers anything past the response
    /// buffer with `NotEnoughMemory` rather than with the value, and any real body clears that bar.
    ///
    /// ```no_run
    /// # use mapi_client::{Logon, MessageId, PropertyTag, WellKnownFolder};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let inbox = logon.folder_id(WellKnownFolder::Inbox)?;
    /// let body = logon
    ///     .message(inbox, MessageId::new(0x0100_0000_0000_0001))
    ///     .stream(PropertyTag::BODY)
    ///     .read()
    ///     .await?;
    /// println!("{} characters", body.text()?.chars().count());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [MS-OXCROPS] §2.2.9.1 — `RopOpenStream`
    #[must_use]
    pub fn stream(self, tag: PropertyTag) -> StreamRead<'a> {
        StreamRead::new(self.connection, Target::Message(self.path), tag)
    }

    /// Changes an existing item and commits the change.
    ///
    /// The counterpart of [`Folder::create_message`](crate::Folder::create_message), and *"update a
    /// contact"* and *"update a calendar event"* between them. One round trip: the message is
    /// opened read/write, written, saved and released in a single `Execute`.
    ///
    /// **A read/write open can be refused where a read-only one would have succeeded** — see
    /// [`MessageMode`] — so this is not the call to reach for when nothing is being changed.
    ///
    /// [MS-OXCMSG] §3.1.4.3 — saving changes on a Message object
    #[must_use]
    pub fn update(self) -> MessageUpdate<'a> {
        MessageUpdate {
            connection: self.connection,
            path: self.path,
            properties: Vec::new(),
            deletions: Vec::new(),
            recipients: Vec::new(),
            replace_recipients: false,
            submit: false,
        }
    }

    /// Hands this message to the transport.
    ///
    /// *"Send a message"*, for a draft that is already in the store — the counterpart of
    /// [`NewMessage::send`](crate::NewMessage::send), which creates and sends in one go. One round
    /// trip: the message is opened read/write, submitted and released in a single `Execute`.
    ///
    /// **This sends real mail.** There is no dry run. What comes back says the server accepted the
    /// message, and nothing about whether it was delivered — a bad address produces a
    /// non-delivery report in the sender's Inbox some time later, not an error here.
    ///
    /// **The message has to be complete before the server will take it.** [MS-OXOMSG] §3.2.4.1
    /// says which properties that means, and the refusal arrives here rather than where the
    /// omission was: [`ecTooManyRecips`](mapi_proto::ErrorCode::TOO_MANY_RECIPIENTS) means **none**
    /// of the recipients got it, and [`ecAccessDenied`](mapi_proto::ErrorCode::ACCESS_DENIED) is
    /// what an FAI message is refused with, which reads like a permission problem and is not.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused the open or the submit, plus whatever the round trip
    /// failed with.
    ///
    /// [MS-OXCROPS] §2.2.7.1 — `RopSubmitMessage`
    pub async fn send(self) -> Result<()> {
        let mut batch = RopBatch::new();
        let logon = batch.bind(self.path.logon);
        let message = batch.open_message(
            logon,
            self.path.folder,
            self.path.id,
            MessageMode::ReadWrite,
        );
        batch
            .submit_message(message, SubmitFlags::None)
            .release(message);

        let execution = self
            .connection
            .execute(batch, "submitting a message")
            .await?;
        submitted(execution.responses())
    }

    /// The message's attachment table.
    ///
    /// Defaults to [`ATTACHMENT_COLUMNS`](crate::ATTACHMENT_COLUMNS), which carries
    /// `PidTagAttachMethod` — the column that
    /// says whether an attachment's content is bytes or another message. Without it an
    /// `afEmbeddedMessage` attachment is indistinguishable from an empty one.
    ///
    /// **The server reports no row count for this table**, unlike a folder's, so
    /// [`Rows::row_count`](crate::Rows::row_count) stays `None` however many rows arrive.
    ///
    /// [MS-OXCROPS] §2.2.6.17 — `RopGetAttachmentTable`
    #[must_use]
    pub fn attachments(self) -> TableRead<'a> {
        TableRead::new(
            self.connection,
            Target::Message(self.path),
            TableKind::Attachments,
        )
    }

    /// One attachment, by the number its table row reported.
    ///
    /// The number is `PidTagAttachNumber` and is an index within *this* message, so one taken from
    /// another message's table opens a different attachment or none at all.
    #[must_use]
    pub fn attachment(self, number: AttachmentNumber) -> Attachment<'a> {
        Attachment::new(self.connection, self.path, number)
    }
}

/// Changes to make to an existing item. Nothing is sent until [`save`](MessageUpdate::save).
#[derive(Debug)]
pub struct MessageUpdate<'a> {
    connection: &'a mut Connection,
    path: MessagePath,
    properties: Vec<TaggedValue>,
    deletions: Vec<PropertyTag>,
    recipients: Vec<Recipient>,
    replace_recipients: bool,
    submit: bool,
}

impl MessageUpdate<'_> {
    /// Properties to write.
    #[must_use]
    pub fn set<I>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = TaggedValue>,
    {
        self.properties.extend(values);
        self
    }

    /// Recipients to add or change.
    ///
    /// **This does not replace the list.** `RopModifyRecipients` addresses each row by a `RowId`
    /// that is its position here ([MS-OXCMSG] §3.1.5.5), so passing two recipients rewrites the
    /// first two and leaves any others in place. Replacing a list is
    /// [`replacing_recipients`](Self::replacing_recipients) and this together.
    #[must_use]
    pub fn to<I>(mut self, recipients: I) -> Self
    where
        I: IntoIterator<Item = Recipient>,
    {
        self.recipients.extend(recipients);
        self
    }

    /// Properties to remove, in the same round trip as the ones being written.
    ///
    /// **Removing is not writing a zero.** A property some protocols define by its *absence* has to
    /// actually be absent: [MS-OXOFLAG] §2.2.1.1 has `PidTagFlagStatus` "present on the Message
    /// object only if the object has been flagged", so a message carrying a zero there is a message
    /// a conforming reader has no rule for. `RopDeleteProperties` is what makes it absent, and
    /// [MS-OXCPRPT] §3.2.5.5 has the server answer `NotFound` for it afterwards rather than an
    /// empty value.
    ///
    /// The deletes are sent after the writes and before the save, so "set these and remove those"
    /// is one round trip and one commit — a caller doing it in two would leave the message in an
    /// intermediate state that a reader could see.
    ///
    /// [MS-OXCROPS] §2.2.8.8 — `RopDeleteProperties`
    #[must_use]
    pub fn delete<I>(mut self, tags: I) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<PropertyTag>,
    {
        self.deletions
            .extend(tags.into_iter().map(|tag| *tag.borrow()));
        self
    }

    /// Submits the message once the changes are saved.
    ///
    /// In the same buffer and therefore the same round trip, and in the only order that works:
    /// `RopSubmitMessage` acts on what is in the store, so a submit before the save would send the
    /// message as it was before these changes and report success.
    ///
    /// **This sends real mail** — see [`Message::send`] for what the response does and does not
    /// say.
    #[must_use]
    pub const fn and_send(mut self) -> Self {
        self.submit = true;
        self
    }

    /// Takes every existing recipient off the message first.
    ///
    /// `RopRemoveAllRecipients`, sent before the [`to`](Self::to) list rather than instead of it,
    /// so "these are now the recipients" is one round trip and not two.
    ///
    /// Worth reaching for before a send, and easy not to: a draft edited from three recipients
    /// down to two keeps the third, and the only place that shows up is in whose mailbox the
    /// message lands.
    ///
    /// [MS-OXCROPS] §2.2.6.4 — `RopRemoveAllRecipients`
    #[must_use]
    pub const fn replacing_recipients(mut self) -> Self {
        self.replace_recipients = true;
        self
    }

    /// Applies the changes.
    ///
    /// The returned list names the properties the server refused, as
    /// [`Properties::write`](crate::Properties::write) does — and with the same caveat: an empty
    /// list is what a server chose to report, not proof that everything landed.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused the open — `ecNoAccess` for a message this account may
    /// read and not change — or the save, plus whatever the round trip failed with.
    pub async fn save(self) -> Result<Vec<PropertyProblem>> {
        let mut batch = RopBatch::new();
        let logon = batch.bind(self.path.logon);
        let message = batch.open_message(
            logon,
            self.path.folder,
            self.path.id,
            MessageMode::ReadWrite,
        );
        batch.set_properties(message, &self.properties);
        if !self.deletions.is_empty() {
            batch.delete_properties(message, &self.deletions);
        }
        if self.replace_recipients {
            batch.remove_all_recipients(message);
        }
        if !self.recipients.is_empty() {
            batch.modify_recipients(message, &self.recipients);
        }
        batch.save_message(message);
        // After the save, and only ever after it: RopSubmitMessage acts on what is in the store,
        // so a submit sent before the save would send the message as it was before these changes.
        if self.submit {
            batch.submit_message(message, SubmitFlags::None);
        }
        batch.release(message);

        let what = if self.submit {
            "updating and submitting a message"
        } else {
            "updating a message"
        };
        let execution = self.connection.execute(batch, what).await?;
        let problems = execution
            .property_problems()
            .map(|response| response.problems().to_vec())
            .ok_or(Error::Unexpected {
                expected: "a property write response",
                found: "no property problems report in the batch's responses",
            })?;
        if self.submit {
            submitted(execution.responses())?;
        }
        Ok(problems)
    }
}

/// Confirms that a `RopSubmitMessage` is among the responses.
///
/// Its response has no body at all, so this is the whole of what the protocol says about a submit:
/// the server took the message. Delivery is somebody else's report, arriving in a mailbox rather
/// than in an `Execute`.
fn submitted(responses: &[RopResponse]) -> Result<()> {
    if responses
        .iter()
        .any(|response| response.succeeded(RopId::SUBMIT_MESSAGE))
    {
        return Ok(());
    }
    Err(Error::Unexpected {
        expected: "a RopSubmitMessage response",
        found: "no submission in the batch's responses",
    })
}

#[cfg(test)]
mod tests {
    use mapi_proto::{ATTACHMENT_COLUMNS, AttachMethod};

    use super::*;

    /// The default columns have to carry the method, or a listing cannot tell an embedded message
    /// from an empty attachment — and both would print as "0 bytes".
    #[test]
    fn the_attachment_table_defaults_to_columns_that_say_how_to_read_each_row() {
        assert!(ATTACHMENT_COLUMNS.contains(&PropertyTag::ATTACH_METHOD));
        assert!(ATTACHMENT_COLUMNS.contains(&PropertyTag::ATTACH_NUMBER));
        assert!(!AttachMethod::EmbeddedMessage.has_binary_content());
    }
}
