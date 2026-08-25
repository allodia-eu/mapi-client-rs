//! A message that has been named, its attachments, and the message an attachment can turn out to
//! be.
//!
//! Nothing here sends anything on its own. Each of these is a description of where an object lives
//! plus a borrow of the [`Logon`](crate::Logon); the ROPs that open the chain travel in the same
//! buffer as the operation that follows, so reaching an attachment's bytes is one round trip and
//! not four.
//!
//! [MS-OXCMSG] — Message and Attachment Object Protocol

use mapi_proto::{
    AttachmentNumber, FolderId, MessageId, MessageMode, ObjectHandle, OpenMessageResponse,
    PropertyProblem, PropertyTag, Recipient, RopBatch, RopId, TaggedValue,
};

use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::properties::Properties;
use crate::stream::StreamRead;
use crate::table::{TableKind, TableRead};
use crate::target::{MessagePath, Target};

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
            recipients: Vec::new(),
        }
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
        Attachment {
            connection: self.connection,
            message: self.path,
            number,
        }
    }
}

/// Changes to make to an existing item. Nothing is sent until [`save`](MessageUpdate::save).
#[derive(Debug)]
pub struct MessageUpdate<'a> {
    connection: &'a mut Connection,
    path: MessagePath,
    properties: Vec<TaggedValue>,
    recipients: Vec<Recipient>,
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
    /// first two and leaves any others in place. Clearing a list needs `RopRemoveAllRecipients`,
    /// which this crate does not implement.
    #[must_use]
    pub fn to<I>(mut self, recipients: I) -> Self
    where
        I: IntoIterator<Item = Recipient>,
    {
        self.recipients.extend(recipients);
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
        if !self.recipients.is_empty() {
            batch.modify_recipients(message, &self.recipients);
        }
        batch.save_message(message).release(message);

        let execution = self.connection.execute(batch, "updating a message").await?;
        execution
            .property_problems()
            .map(|response| response.problems().to_vec())
            .ok_or(Error::Unexpected {
                expected: "a property write response",
                found: "no property problems report in the batch's responses",
            })
    }
}

/// One attachment of a message, named but not yet opened.
#[derive(Debug)]
pub struct Attachment<'a> {
    connection: &'a mut Connection,
    message: MessagePath,
    number: AttachmentNumber,
}

impl<'a> Attachment<'a> {
    /// Which attachment this is, within its message.
    #[must_use]
    pub const fn number(&self) -> AttachmentNumber {
        self.number
    }

    /// The message it belongs to.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        self.message.id
    }

    /// The attachment's own properties: name, size, MIME type, and how its content is reached.
    ///
    /// Read [`PidTagAttachMethod`](mapi_proto::PropertyTag::ATTACH_METHOD) before anything else.
    /// See [`AttachMethod`](mapi_proto::AttachMethod).
    ///
    /// [MS-OXCMSG] §2.2.2 — Attachment object properties
    #[must_use]
    pub fn properties(self) -> Properties<'a> {
        Properties::for_target(self.connection, self.target())
    }

    /// The attachment's bytes.
    ///
    /// **Only correct when `PidTagAttachMethod` is `afByValue`.** An attachment whose method is
    /// `afEmbeddedMessage` does not hold `PidTagAttachDataBinary` at all, and this then reports the
    /// server's `NotFound` rather than an empty file — see [`embedded`](Self::embedded) for what to
    /// do instead.
    ///
    /// [MS-OXCMSG] §2.2.2.7 — `PidTagAttachDataBinary`
    #[must_use]
    pub fn content(self) -> StreamRead<'a> {
        self.stream(PropertyTag::ATTACH_DATA_BINARY)
    }

    /// Reads one property of the attachment whole.
    #[must_use]
    pub fn stream(self, tag: PropertyTag) -> StreamRead<'a> {
        StreamRead::new(self.connection, self.target(), tag)
    }

    /// The message this attachment *is*, for an `afEmbeddedMessage` attachment.
    ///
    /// A forwarded mail is carried this way: the attachment has no bytes, and its content is
    /// another Message object with its own subject, its own properties and its own attachments.
    /// A client that only ever read [`content`](Self::content) would report it as empty.
    ///
    /// [MS-OXCROPS] §2.2.6.16 — `RopOpenEmbeddedMessage`
    #[must_use]
    pub fn embedded(self) -> EmbeddedMessage<'a> {
        EmbeddedMessage {
            connection: self.connection,
            message: self.message,
            number: self.number,
        }
    }

    const fn target(&self) -> Target {
        Target::Attachment {
            message: self.message,
            number: self.number,
        }
    }
}

/// The message inside an attachment.
///
/// Separate from [`Message`] because it is not named the same way: an embedded message has no
/// folder and no id a caller could hold, only the attachment it lives in. Its id is reported by the
/// open — see [`OpenMessageResponse::embedded_id`].
#[derive(Debug)]
pub struct EmbeddedMessage<'a> {
    connection: &'a mut Connection,
    message: MessagePath,
    number: AttachmentNumber,
}

impl<'a> EmbeddedMessage<'a> {
    /// Opens it, and reports its subject, its recipient count and the id it turned out to have.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused any step of the chain. An attachment whose
    /// `PidTagAttachMethod` is not `afEmbeddedMessage` is refused here rather than answered.
    pub async fn open(self) -> Result<OpenMessageResponse> {
        let mut batch = RopBatch::new();
        let opened = self.target().open(&mut batch);
        opened.release(&mut batch);

        let execution = self
            .connection
            .execute(batch, "opening an embedded message")
            .await?;
        execution
            .responses()
            .iter()
            .find_map(|response| response.as_open_message(RopId::OPEN_EMBEDDED_MESSAGE))
            .cloned()
            .ok_or(Error::Unexpected {
                expected: "a RopOpenEmbeddedMessage response",
                found: "no opened message in the batch's responses",
            })
    }

    /// The embedded message's own properties.
    #[must_use]
    pub fn properties(self) -> Properties<'a> {
        Properties::for_target(self.connection, self.target())
    }

    /// Reads one property of the embedded message whole — its body, most usefully.
    #[must_use]
    pub fn stream(self, tag: PropertyTag) -> StreamRead<'a> {
        StreamRead::new(self.connection, self.target(), tag)
    }

    /// The embedded message's own attachment table — an attachment of an attachment.
    #[must_use]
    pub fn attachments(self) -> TableRead<'a> {
        TableRead::new(self.connection, self.target(), TableKind::Attachments)
    }

    const fn target(&self) -> Target {
        Target::Embedded {
            message: self.message,
            number: self.number,
        }
    }
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
