//! What a message is made of in a `FastTransfer` stream: properties, recipients, attachments, and
//! messages inside attachments.
//!
//! [MS-OXCFXICS] §2.2.4.2:
//!
//! ```text
//! messageContent    = [MetaTagDnPrefix] propList messageChildren
//! messageChildren   = [ MetaTagFXDelProp ] [ *recipient ] [ MetaTagFXDelProp ] [ *attachment ]
//! recipient         = StartRecip propList EndToRecip
//! attachment        = NewAttach PidTagAttachNumber attachmentContent EndAttach
//! attachmentContent = [MetaTagDnPrefix] propList [embeddedMessage]
//! embeddedMessage   = StartEmbed messageContent EndEmbed
//! ```

use crate::error::{Error, Result};
use crate::fasttransfer::{Element, Marker, StreamProperty};
use crate::oxcdata::{PropertyTag, PropertyValue};

/// A message's properties and the objects below it.
///
/// [MS-OXCFXICS] §2.2.4.3.16 — `messageContent`
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MessageContent {
    properties: Vec<StreamProperty>,
    recipients: Vec<Vec<StreamProperty>>,
    attachments: Vec<Attachment>,
    replaces_recipients: bool,
    replaces_attachments: bool,
}

impl MessageContent {
    /// The message's own properties, in stream order.
    #[must_use]
    pub fn properties(&self) -> &[StreamProperty] {
        &self.properties
    }

    /// The value of one property, if the stream carried it.
    ///
    /// Matched by tag, which for a named property is the store's own id; see
    /// [`StreamProperty::name`] for the portable form.
    #[must_use]
    pub fn property(&self, tag: PropertyTag) -> Option<&PropertyValue> {
        find(&self.properties, tag)
    }

    /// Each recipient's properties. `PidTagRowid` comes first in every one ([MS-OXCFXICS]
    /// §2.2.4.3.23).
    #[must_use]
    pub fn recipients(&self) -> &[Vec<StreamProperty>] {
        &self.recipients
    }

    /// The attachments, in stream order.
    #[must_use]
    pub fn attachments(&self) -> &[Attachment] {
        &self.attachments
    }

    /// Whether the stream said to discard the recipients the client already holds before adding
    /// these: a `MetaTagFXDelProp` naming `PidTagMessageRecipients`.
    ///
    /// [MS-OXCFXICS] §2.2.4.1.5.1 — "a directive to a client to delete specific subobjects"
    #[must_use]
    pub const fn replaces_recipients(&self) -> bool {
        self.replaces_recipients
    }

    /// The same for attachments, with `PidTagMessageAttachments`.
    #[must_use]
    pub const fn replaces_attachments(&self) -> bool {
        self.replaces_attachments
    }
}

/// One attachment: its number, its properties, and the message it holds if it holds one.
///
/// [MS-OXCFXICS] §2.2.4.3.1 — `attachmentContent`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    number: u32,
    properties: Vec<StreamProperty>,
    embedded: Option<Box<MessageContent>>,
}

impl Attachment {
    /// `PidTagAttachNumber`, which the stream carries straight after `NewAttach`.
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// The attachment's properties.
    #[must_use]
    pub fn properties(&self) -> &[StreamProperty] {
        &self.properties
    }

    /// The value of one property, if the stream carried it.
    #[must_use]
    pub fn property(&self, tag: PropertyTag) -> Option<&PropertyValue> {
        find(&self.properties, tag)
    }

    /// The message inside the attachment, for one whose content is a message.
    #[must_use]
    pub fn embedded(&self) -> Option<&MessageContent> {
        self.embedded.as_deref()
    }
}

/// The first value under `tag`.
pub(crate) fn find(properties: &[StreamProperty], tag: PropertyTag) -> Option<&PropertyValue> {
    properties
        .iter()
        .find(|property| property.tag() == tag)
        .map(StreamProperty::value)
}

/// A position in one unit's elements, read by recursive descent.
pub(crate) struct Cursor<'a> {
    elements: &'a [Element],
    at: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) const fn new(elements: &'a [Element]) -> Self {
        Self { elements, at: 0 }
    }

    pub(crate) fn peek(&self) -> Option<&'a Element> {
        self.elements.get(self.at)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.at >= self.elements.len()
    }

    pub(crate) fn advance(&mut self) {
        self.at = self.at.saturating_add(1);
    }

    /// Consumes `marker` if it is next.
    pub(crate) fn eat(&mut self, marker: Marker) -> bool {
        if matches!(self.peek(), Some(Element::Marker(next)) if *next == marker) {
            self.advance();
            return true;
        }
        false
    }

    /// Requires `marker` next.
    pub(crate) fn expect(&mut self, marker: Marker, within: &'static str) -> Result<()> {
        if self.eat(marker) {
            Ok(())
        } else {
            Err(malformed(within, "a required marker is missing"))
        }
    }

    /// Consumes a meta-property if it is next, handing back its value.
    pub(crate) fn meta(&mut self, tag: PropertyTag) -> Option<&'a PropertyValue> {
        match self.peek() {
            Some(Element::Property(property)) if property.tag() == tag => {
                self.advance();
                Some(property.value())
            }
            _ => None,
        }
    }

    /// A `propList`: properties up to the next marker or structural meta-property.
    ///
    /// `MetaTagDnPrefix` is dropped wherever it appears, because §2.2.4.1.5.6 says it "MUST be
    /// ignored when received", and so is `MetaTagEcWarning`, which a list of messages carries
    /// and nothing here acts on. Every other meta-property ends the list, because the grammar
    /// gives each one a place of its own.
    ///
    /// [MS-OXCFXICS] §2.2.4.3.20 — `propList`
    pub(crate) fn properties(&mut self) -> Vec<StreamProperty> {
        let mut properties = Vec::new();
        while let Some(Element::Property(property)) = self.peek() {
            let tag = property.tag();
            if tag == PropertyTag::META_TAG_DN_PREFIX || tag == PropertyTag::META_TAG_EC_WARNING {
                self.advance();
                continue;
            }
            if is_structural(tag) {
                break;
            }
            properties.push(property.clone());
            self.advance();
        }
        properties
    }

    /// `messageContent`: a message's properties and children.
    pub(crate) fn message_content(&mut self) -> Result<MessageContent> {
        let mut content = MessageContent {
            properties: self.properties(),
            ..MessageContent::default()
        };
        self.message_children(&mut content)?;
        Ok(content)
    }

    /// `messageChildren`: the recipients, then the attachments, each optionally preceded by the
    /// directive to discard what the client holds.
    pub(crate) fn message_children(&mut self, content: &mut MessageContent) -> Result<()> {
        if self.delete_directive(PropertyTag::MESSAGE_RECIPIENTS) {
            content.replaces_recipients = true;
        }
        while self.eat(Marker::StartRecipient) {
            content.recipients.push(self.properties());
            self.expect(Marker::EndRecipient, "a recipient")?;
        }
        if self.delete_directive(PropertyTag::MESSAGE_ATTACHMENTS) {
            content.replaces_attachments = true;
        }
        while self.eat(Marker::NewAttachment) {
            content.attachments.push(self.attachment()?);
        }
        Ok(())
    }

    /// Consumes a `MetaTagFXDelProp` naming `subobject`, if one is next.
    fn delete_directive(&mut self, subobject: PropertyTag) -> bool {
        match self.peek() {
            Some(Element::Property(property))
                if property.tag() == PropertyTag::META_TAG_FX_DEL_PROP
                    && property.value().as_u32() == Some(subobject.as_u32()) =>
            {
                self.advance();
                true
            }
            _ => false,
        }
    }

    /// `attachment`, after its `NewAttach`.
    fn attachment(&mut self) -> Result<Attachment> {
        let number = self
            .meta(PropertyTag::ATTACH_NUMBER)
            .and_then(PropertyValue::as_u32)
            .ok_or_else(|| {
                malformed(
                    "an attachment",
                    "PidTagAttachNumber does not follow NewAttach",
                )
            })?;
        let properties = self.properties();
        let embedded = if self.eat(Marker::StartEmbed) {
            let message = self.message_content()?;
            self.expect(Marker::EndEmbed, "an embedded message")?;
            Some(Box::new(message))
        } else {
            None
        };
        self.expect(Marker::EndAttachment, "an attachment")?;
        Ok(Attachment {
            number,
            properties,
            embedded,
        })
    }
}

/// Whether a meta-property has a place of its own in the grammar, and so ends a `propList`.
fn is_structural(tag: PropertyTag) -> bool {
    [
        PropertyTag::META_TAG_FX_DEL_PROP,
        PropertyTag::META_TAG_INCR_SYNC_GROUP_ID,
        PropertyTag::META_TAG_INCREMENTAL_SYNC_MESSAGE_PARTIAL,
        PropertyTag::META_TAG_NEW_FX_FOLDER,
    ]
    .contains(&tag)
}

/// The error for an element sequence the grammar does not allow.
pub(crate) const fn malformed(within: &'static str, reason: &'static str) -> Error {
    Error::MalformedFastTransfer { within, reason }
}
