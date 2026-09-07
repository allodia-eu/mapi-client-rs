//! An attachment of a message, and the message an attachment can turn out to be.
//!
//! Split from [`message`](super) because the two are named differently and that is the whole
//! difficulty: a message has a folder and an id a caller can hold, and an attachment has neither —
//! it is a number within one message, and the message *inside* an attachment has no identity in
//! the store at all.
//!
//! Nothing here sends anything on its own. The opens chain through a single ROP buffer, so reaching
//! the message inside an attachment costs one round trip and not three.
//!
//! [MS-OXCMSG] §2.2.2 — Attachment object properties

use mapi_proto::{AttachmentNumber, MessageId, OpenMessageResponse, PropertyTag, RopBatch, RopId};

use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::properties::Properties;
use crate::stream::StreamRead;
use crate::table::{TableKind, TableRead};
use crate::target::{MessagePath, Target};

/// One attachment of a message, named but not yet opened.
#[derive(Debug)]
pub struct Attachment<'a> {
    connection: &'a mut Connection,
    message: MessagePath,
    number: AttachmentNumber,
}

impl<'a> Attachment<'a> {
    pub(super) const fn new(
        connection: &'a mut Connection,
        message: MessagePath,
        number: AttachmentNumber,
    ) -> Self {
        Self {
            connection,
            message,
            number,
        }
    }

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
