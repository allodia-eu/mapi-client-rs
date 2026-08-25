//! Which Server object an operation is aimed at, and how a batch reaches it.
//!
//! MAPI objects nest: an attachment hangs off a message, which hangs off a folder, which hangs off
//! the logon. Reaching an embedded message therefore means three ROPs before the one that was
//! actually wanted — and because ROPs in a single buffer consume the handles earlier ROPs in the
//! same buffer produced, all four still cost one round trip.
//!
//! Keeping that here rather than in each operation is what stops `properties`, `table` and `stream`
//! each growing their own copy of the chain, and what makes "read a property of the message inside
//! this attachment" the same amount of code as "read a property of a folder".
//!
//! **Everything this opens, it releases.** A handle opened and not released lives until the Session
//! Context ends, so a caller reading one property of each of a hundred attachments would leave
//! three hundred behind. The releases travel in the same buffer and cost no round trip.
//!
//! [MS-OXCROPS] §3.1.4.1 — one ROP consumes the handle an earlier ROP produced

use mapi_proto::{
    AttachmentNumber, FolderId, HandleSlot, MessageId, MessageMode, ObjectHandle, RopBatch,
};

/// Where a message lives: the logon it hangs off, and the folder and id that name it.
///
/// `RopOpenMessage` takes the folder id itself, so this is everything needed to open one — there is
/// no `RopOpenFolder` in front of it.
///
/// [MS-OXCROPS] §2.2.6.1.1 — `FolderId`, `MessageId`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MessagePath {
    pub(crate) logon: ObjectHandle,
    pub(crate) folder: FolderId,
    pub(crate) id: MessageId,
}

/// Which object a fetch, a table read or a stream is aimed at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// A handle the server is already holding — the Logon object, or a table being paged.
    Open(ObjectHandle),
    /// A folder to open in the same batch as the operation.
    Folder {
        /// The Logon object the folder hangs off.
        logon: ObjectHandle,
        /// Which folder.
        id: FolderId,
    },
    /// A message to open in the same batch.
    Message(MessagePath),
    /// An attachment of a message, both opened in the same batch.
    Attachment {
        /// The message it belongs to.
        message: MessagePath,
        /// Which attachment, by the number its table row reported.
        number: AttachmentNumber,
    },
    /// The message *inside* an attachment — three opens before the operation.
    ///
    /// The only way to reach an attachment whose `PidTagAttachMethod` is `afEmbeddedMessage`.
    Embedded {
        /// The message holding the attachment.
        message: MessagePath,
        /// Which attachment.
        number: AttachmentNumber,
    },
}

impl Target {
    /// Puts the object into `batch`, along with whatever had to be opened to reach it.
    pub(crate) fn open(self, batch: &mut RopBatch) -> Opened {
        match self {
            Self::Open(handle) => Opened {
                slot: batch.bind(handle),
                opened: Vec::new(),
            },
            Self::Folder { logon, id } => {
                let logon = batch.bind(logon);
                let folder = batch.open_folder(logon, id);
                Opened {
                    slot: folder,
                    opened: vec![folder],
                }
            }
            Self::Message(path) => {
                let message = open_message(batch, path);
                Opened {
                    slot: message,
                    opened: vec![message],
                }
            }
            Self::Attachment { message, number } => {
                let message = open_message(batch, message);
                let attachment = batch.open_attachment(message, number.as_u32());
                Opened {
                    slot: attachment,
                    opened: vec![attachment, message],
                }
            }
            Self::Embedded { message, number } => {
                let message = open_message(batch, message);
                let attachment = batch.open_attachment(message, number.as_u32());
                let embedded = batch.open_embedded_message(attachment);
                Opened {
                    slot: embedded,
                    opened: vec![embedded, attachment, message],
                }
            }
        }
    }
}

/// Opens the message **read-only**, because everything reached through a [`Target`] is a read.
///
/// A read/write open on a message another client already has open can be refused where this one
/// succeeds, so asking for write access a read does not need turns a working read into an error.
/// The write path builds its own batch and says so there.
fn open_message(batch: &mut RopBatch, path: MessagePath) -> HandleSlot {
    let logon = batch.bind(path.logon);
    batch.open_message(logon, path.folder, path.id, MessageMode::ReadOnly)
}

/// An object placed in a batch, and the handles that batch has to give back.
#[derive(Debug)]
pub(crate) struct Opened {
    /// The object the operation acts on.
    pub(crate) slot: HandleSlot,
    /// What this opened, innermost first — the order they are released in.
    opened: Vec<HandleSlot>,
}

impl Opened {
    /// The handles this open created, innermost first.
    ///
    /// For an operation that outlives its own batch — a stream read that takes several round trips
    /// — which has to keep the chain alive and release it at the end instead.
    pub(crate) fn slots(&self) -> &[HandleSlot] {
        &self.opened
    }

    /// Releases everything the open created, in the reverse of the order it was created.
    ///
    /// Called *after* the operation's own ROPs have been added, so the handles are still live when
    /// they are used. A handle bound from an earlier round trip is not released here: this batch
    /// did not open it and something else is still holding it.
    pub(crate) fn release(&self, batch: &mut RopBatch) {
        for slot in &self.opened {
            batch.release(*slot);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path() -> MessagePath {
        MessagePath {
            logon: ObjectHandle::new(0x2A),
            folder: FolderId::new(0x0D01_0000_0000_0001),
            id: MessageId::new(0x0D01_0000_0000_0042),
        }
    }

    /// A bound handle is somebody else's, so nothing is opened and nothing is released.
    #[test]
    fn an_already_open_object_costs_no_rops_at_all() {
        let mut batch = RopBatch::new();
        let opened = Target::Open(ObjectHandle::new(0x2A)).open(&mut batch);
        opened.release(&mut batch);

        assert_eq!(opened.slot.index(), 0);
        assert_eq!(
            batch.len(),
            0,
            "binding is not a ROP, and there is nothing to release"
        );
    }

    /// The chain that costs the most: three opens, the operation, three releases — one round trip.
    #[test]
    fn an_embedded_message_opens_three_objects_and_releases_all_three() {
        let mut batch = RopBatch::new();
        let opened = Target::Embedded {
            message: path(),
            number: AttachmentNumber::new(1),
        }
        .open(&mut batch);
        opened.release(&mut batch);

        // RopOpenMessage, RopOpenAttachment, RopOpenEmbeddedMessage, then three RopRelease.
        assert_eq!(batch.len(), 6);
        assert_eq!(
            opened.slot.index(),
            3,
            "the embedded message is the innermost handle"
        );
    }

    /// Innermost first: the embedded message is released before the attachment it came from.
    #[test]
    fn handles_are_released_from_the_inside_out() {
        let mut batch = RopBatch::new();
        let opened = Target::Attachment {
            message: path(),
            number: AttachmentNumber::new(0),
        }
        .open(&mut batch);

        let message = opened
            .opened
            .get(1)
            .copied()
            .expect("the message was opened");
        assert_eq!(
            opened.slot,
            opened.opened.first().copied().expect("the attachment")
        );
        assert!(
            opened.slot.index() > message.index(),
            "inner objects are allocated later"
        );
    }

    /// Every target reaches an object, and the ones that open something say so.
    #[test]
    fn each_target_opens_what_it_has_to() {
        for (target, opens) in [
            (Target::Open(ObjectHandle::new(1)), 0),
            (
                Target::Folder {
                    logon: ObjectHandle::new(1),
                    id: FolderId::new(2),
                },
                1,
            ),
            (Target::Message(path()), 1),
            (
                Target::Attachment {
                    message: path(),
                    number: AttachmentNumber::new(0),
                },
                2,
            ),
            (
                Target::Embedded {
                    message: path(),
                    number: AttachmentNumber::new(0),
                },
                3,
            ),
        ] {
            let mut batch = RopBatch::new();
            let opened = target.open(&mut batch);
            assert_eq!(opened.opened.len(), opens, "{target:?}");
            assert_eq!(batch.len(), opens, "{target:?}");
        }
    }
}
