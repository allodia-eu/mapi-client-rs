//! `PtypServerId`: an object named by the ids the store holds it under, rather than by an entry id.
//!
//! One property in this crate carries it — `PidTagSentMailSvrEID`, which is how a client says
//! where a copy of a submitted message should be filed. It is a folder id and a message id side by
//! side, and the shape is the whole of it.
//!
//! **`Ours` is not a version byte.** [MS-OXCDATA] §2.11.1.4 gives `0x01` the meaning "the rest of
//! these bytes are this structure" and `0x00` the meaning "this is a client-defined value of
//! whatever size and shape that client chose". So a value whose first byte is zero is not a
//! malformed `PtypServerId` — it is a well-formed one this crate cannot interpret, and reporting
//! the two as the same thing would turn another client's private bookkeeping into a parse error.
//!
//! [MS-OXCDATA] §2.11.1.4 — `PtypServerId` Type

use crate::oxcdata::{FolderId, MessageId};

/// `Ours`: the remaining bytes are the documented structure.
const OURS: u8 = 0x01;

/// How many bytes the documented form occupies: `Ours(1)`, folder id, message id, `Instance(4)`.
const LENGTH: usize = 21;

/// `Instance`: zero everywhere but a search against a multivalued property.
///
/// [MS-OXCDATA] §2.11.1.4 — "MUST be zero in any other context"
const NOT_A_SEARCH: u32 = 0;

/// An object named by the folder and message ids the store knows it under.
///
/// Written by a client to say *where*, not to say *which of two things*: the ids are short-term
/// and mean nothing outside the logon that produced them.
///
/// [MS-OXCDATA] §2.11.1.4 — `PtypServerId` Type
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ServerEntryId {
    /// The documented structure: a folder, and a message in it.
    Ours {
        /// The folder.
        folder: FolderId,
        /// The message, or zero when the value names the folder itself.
        message: MessageId,
    },
    /// A value some other client defined, of a shape this crate has no reading for.
    ///
    /// Kept whole rather than refused. `Ours` = `0x00` is a documented answer, and a decoder that
    /// treated it as damage would report another client's private bookkeeping as a protocol error.
    Foreign(Vec<u8>),
}

impl ServerEntryId {
    /// Names a folder, with a zero message id.
    ///
    /// What `PidTagSentMailSvrEID` wants: [MS-OXOMSG] §2.2.3.10 has the property identify the
    /// folder a sent message is copied into, and §2.11.1.4 requires the message id to be all zeros
    /// when the object pointed to is a folder.
    #[must_use]
    pub const fn folder(folder: FolderId) -> Self {
        Self::Ours {
            folder,
            message: MessageId::new(0),
        }
    }

    /// Names one message in one folder.
    #[must_use]
    pub const fn message(folder: FolderId, message: MessageId) -> Self {
        Self::Ours { folder, message }
    }

    /// The folder, for a value in the documented form.
    #[must_use]
    pub const fn folder_id(&self) -> Option<FolderId> {
        match self {
            Self::Ours { folder, .. } => Some(*folder),
            Self::Foreign(_) => None,
        }
    }

    /// The message, for a value in the documented form that names one.
    ///
    /// `None` for a value that names a folder, where the field is required to be zero — so this
    /// says "no message" rather than handing back an id of zero a caller might try to open.
    #[must_use]
    pub fn message_id(&self) -> Option<MessageId> {
        match self {
            Self::Ours { message, .. } if message.as_u64() != 0 => Some(*message),
            _ => None,
        }
    }

    /// The bytes as the wire carries them.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ours { folder, message } => {
                let mut bytes = Vec::with_capacity(LENGTH);
                bytes.push(OURS);
                bytes.extend_from_slice(&folder.as_u64().to_le_bytes());
                bytes.extend_from_slice(&message.as_u64().to_le_bytes());
                bytes.extend_from_slice(&NOT_A_SEARCH.to_le_bytes());
                bytes
            }
            Self::Foreign(bytes) => bytes.clone(),
        }
    }

    /// Reads a value of this type, whichever of the two shapes it turned out to be.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() != LENGTH || bytes.first() != Some(&OURS) {
            return Self::Foreign(bytes.to_vec());
        }

        // Both reads are known to succeed from the length check above; `map_or` rather than an
        // index keeps the file free of a panic the parser could ever reach.
        let at = |start: usize| {
            bytes
                .get(start..start.saturating_add(8))
                .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
                .map_or(0, u64::from_le_bytes)
        };
        Self::Ours {
            folder: FolderId::new(at(1)),
            message: MessageId::new(at(9)),
        }
    }
}

impl core::fmt::Display for ServerEntryId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ours { folder, message } if message.as_u64() == 0 => {
                write!(f, "folder {:#018x}", folder.as_u64())
            }
            Self::Ours { folder, message } => write!(
                f,
                "message {:#018x} in folder {:#018x}",
                message.as_u64(),
                folder.as_u64()
            ),
            Self::Foreign(bytes) => write!(f, "{} byte(s) another client defined", bytes.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout [MS-OXCDATA] §2.11.1.4 draws, written out by hand rather than produced by the
    /// encoder this is checking.
    #[test]
    fn a_folder_encodes_as_the_twenty_one_bytes_the_diagram_shows() {
        let value = ServerEntryId::folder(FolderId::new(0x0F01_0000_0000_0001));
        assert_eq!(
            value.to_bytes(),
            [
                0x01, // Ours
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0F, // folder ID
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, // message ID, zero for a folder
                0x00, 0x00, 0x00, 0x00, // Instance
            ]
        );
        assert_eq!(value.to_bytes().len(), LENGTH);
        assert_eq!(value.message_id(), None);
        assert_eq!(value.to_string(), "folder 0x0f01000000000001");
    }

    #[test]
    fn a_message_round_trips_through_its_bytes() {
        let value = ServerEntryId::message(
            FolderId::new(0x0F01_0000_0000_0001),
            MessageId::new(0x0F01_0000_0000_0042),
        );
        assert_eq!(ServerEntryId::from_bytes(&value.to_bytes()), value);
        assert_eq!(
            value.folder_id(),
            Some(FolderId::new(0x0F01_0000_0000_0001))
        );
        assert_eq!(
            value.message_id(),
            Some(MessageId::new(0x0F01_0000_0000_0042))
        );
        assert!(value.to_string().starts_with("message 0x0f01000000000042"));
    }

    /// `Ours` = `0x00` means "a client defined this", which is an answer rather than a fault.
    #[test]
    fn a_value_another_client_defined_survives_being_read() {
        let foreign = ServerEntryId::from_bytes(&[0x00, 0xDE, 0xAD]);
        assert_eq!(foreign, ServerEntryId::Foreign(vec![0x00, 0xDE, 0xAD]));
        assert_eq!(foreign.folder_id(), None);
        assert_eq!(foreign.message_id(), None);
        assert_eq!(foreign.to_bytes(), [0x00, 0xDE, 0xAD]);
        assert_eq!(foreign.to_string(), "3 byte(s) another client defined");

        // The right first byte with the wrong length is the same answer: the structure is fixed at
        // 21 bytes, so anything else is not it however the first byte reads.
        assert!(matches!(
            ServerEntryId::from_bytes(&[0x01, 0x02]),
            ServerEntryId::Foreign(_)
        ));
    }
}
