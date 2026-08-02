//! Entry ids: the long-term identifiers that folder properties carry, and the short-term ones
//! ROPs take.
//!
//! **The two are not interconvertible by arithmetic.** A [`FolderId`] names a folder by a 2-byte
//! replica id that is meaningful only inside one logon's Store object; a [`LongTermId`] names the
//! same folder by the 16-byte GUID that replica id stands for. Turning one into the other is a
//! round trip to the server — `RopIdFromLongTermId` and `RopLongTermIdFromId` — because only the
//! server holds the mapping.
//!
//! That matters because the folders a logon does not name — Calendar, Contacts, Drafts, Tasks,
//! Notes, Journal — are found through binary properties holding [`FolderEntryId`] structures, and
//! `RopOpenFolder` takes a [`FolderId`].
//!
//! [MS-OXCDATA] §2.2.1.3 — Global Identifier structure
//! [MS-OXCDATA] §2.2.1.3.1 — `LongTermID` structure
//! [MS-OXCDATA] §2.2.4.1 — Folder `EntryID` structure
//! [MS-OXOSFLD] §2.2.2 — entry ids must be converted with `RopIdFromLongTermId` before use

use crate::error::{Error, Result};
use crate::oxcdata::{FolderId, Guid, MessageId};
use crate::wire::{Reader, Writer};

/// Bytes of counter in a Global Identifier structure.
const GLOBAL_COUNTER_BYTES: usize = 6;

/// A long-term identifier: the Store object's GUID, a 48-bit counter, and two pad bytes.
///
/// The wire form of the identifier a `PidTagIpm*EntryId` property carries, and what
/// `RopIdFromLongTermId` converts into something `RopOpenFolder` will take.
///
/// [MS-OXCDATA] §2.2.1.3.1 — `LongTermID` structure, 24 bytes
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LongTermId {
    database_guid: Guid,
    global_counter: [u8; GLOBAL_COUNTER_BYTES],
}

impl LongTermId {
    /// How many bytes the structure occupies: 16 + 6 + 2.
    pub const SIZE: usize = 24;

    /// Builds one from its two meaningful fields. The pad is always zero.
    #[must_use]
    pub const fn new(database_guid: Guid, global_counter: [u8; GLOBAL_COUNTER_BYTES]) -> Self {
        Self {
            database_guid,
            global_counter,
        }
    }

    /// The GUID of the Store object holding the folder or message.
    ///
    /// This is what a [`ReplicaId`](crate::ReplicaId) stands for, and the reason a long-term id
    /// survives being carried between stores while a short-term one does not.
    #[must_use]
    pub const fn database_guid(&self) -> Guid {
        self.database_guid
    }

    /// The counter as the six bytes the wire carries, in wire order.
    #[must_use]
    pub const fn global_counter_bytes(&self) -> [u8; GLOBAL_COUNTER_BYTES] {
        self.global_counter
    }

    /// The counter as a number, read little-endian.
    ///
    /// Little-endian because [MS-OXCDATA] §2 depicts every field in that order, and because a
    /// short-term id's own counter is read the same way — which is what makes the two comparable.
    /// The documents depict the field and never name its order, so this is a measurement: on
    /// Exchange Server SE `15.02.2562.045`, converting the Inbox's own folder id with
    /// `RopLongTermIdFromId` produced a long-term id whose counter read this way equals
    /// [`FolderId::global_counter`](crate::FolderId::global_counter) of the id it came from, for
    /// both lab mailboxes.
    #[must_use]
    pub const fn global_counter(&self) -> u64 {
        let [b0, b1, b2, b3, b4, b5] = self.global_counter;
        u64::from_le_bytes([b0, b1, b2, b3, b4, b5, 0, 0])
    }

    /// Reads the 24 bytes, pad included.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let database_guid = Guid::from_bytes(r.array::<16>()?);
        let global_counter = r.array::<GLOBAL_COUNTER_BYTES>()?;
        // The pad is documented as zero and is read rather than skipped, so that a buffer whose
        // layout has moved fails here instead of at whatever field follows.
        let _pad = r.u16()?;
        Ok(Self {
            database_guid,
            global_counter,
        })
    }

    /// Writes the 24 bytes, pad included.
    pub(crate) fn write(&self, w: &mut Writer) {
        w.bytes(self.database_guid.as_bytes())
            .bytes(&self.global_counter)
            .u16(0);
    }
}

impl core::fmt::Display for LongTermId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}-{:012X}", self.database_guid, self.global_counter())
    }
}

/// The kind of Store object an entry id refers to.
///
/// A newtype rather than an enum because the set is fixed by a table this crate has no reason to
/// exhaust, and because a value outside it must still survive being received and printed.
///
/// [MS-OXCDATA] §2.2.4 — General `EntryID` `ObjectType` values
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreObjectType(u16);

impl StoreObjectType {
    /// `PrivateFolder`, `0x0001` — a folder in a private mailbox.
    pub const PRIVATE_FOLDER: Self = Self(0x0001);
    /// `PrivateMessage`, `0x0007`.
    pub const PRIVATE_MESSAGE: Self = Self(0x0007);
    /// `PublicFolder`, `0x0003` — a folder in the public message store.
    pub const PUBLIC_FOLDER: Self = Self(0x0003);
    /// `PublicMessage`, `0x0009`.
    pub const PUBLIC_MESSAGE: Self = Self(0x0009);

    /// Wraps a raw value.
    #[must_use]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// The value as the wire carries it.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Whether this type names a folder a server can have written.
    ///
    /// `MappedPublicFolder` (`0x0005`) and `PublicNewsgroupFolder` (`0x000C`) are folder types by
    /// name and are still refused, because this crate parses only what a server sent: [MS-OXCDATA]
    /// §2.2.4 endnote &lt;2&gt; records that the server neither reads nor writes the first — only
    /// Outlook 2003 through 2010 ever produced one — and endnote &lt;1&gt; that Exchange does not
    /// support the newsgroup structure at all. A `0x0005` arriving from Exchange means the bytes
    /// are not the entry id they were read as, which is worth an error rather than an open.
    ///
    /// [MS-OXCDATA] §2.2.4 — Store object types
    #[must_use]
    pub const fn is_folder(self) -> bool {
        matches!(self, Self::PRIVATE_FOLDER | Self::PUBLIC_FOLDER)
    }

    /// The specification's name for this type, if it is one of the four modelled here.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::PRIVATE_FOLDER => "PrivateFolder",
            Self::PUBLIC_FOLDER => "PublicFolder",
            Self::PRIVATE_MESSAGE => "PrivateMessage",
            Self::PUBLIC_MESSAGE => "PublicMessage",
            _ => return None,
        })
    }
}

impl core::fmt::Display for StoreObjectType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} (0x{:04X})", self.0),
            None => write!(f, "0x{:04X}", self.0),
        }
    }
}

/// The 46 bytes a `PidTagIpm*EntryId` property holds.
///
/// `Flags(4) ProviderUID(16) FolderType(2) DatabaseGuid(16) GlobalCounter(6) Pad(2)` — the last
/// 24 of which are exactly a [`LongTermId`], which is what makes the conversion to a
/// [`FolderId`] a matter of handing that tail to `RopIdFromLongTermId`.
///
/// [MS-OXCDATA] §2.2.4.1 — Folder `EntryID` structure
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FolderEntryId {
    provider_uid: Guid,
    object_type: StoreObjectType,
    long_term_id: LongTermId,
}

impl FolderEntryId {
    /// How many bytes the structure occupies: 4 + 16 + 2 + 24.
    pub const SIZE: usize = 46;

    /// The provider that issued this entry id.
    ///
    /// For a folder in a private mailbox this **must equal the `MailboxGuid` the logon reported**,
    /// which is the check that catches an entry id belonging to a different mailbox —
    /// see [`belongs_to`](Self::belongs_to).
    ///
    /// [MS-OXCDATA] §2.2.4.1 — `Provider UID`
    #[must_use]
    pub const fn provider_uid(&self) -> Guid {
        self.provider_uid
    }

    /// The kind of object this refers to.
    ///
    /// [MS-OXCDATA] §2.2.4.1 names this field `FolderType`; its values are the Store object types
    /// of §2.2.4, which is why the type here is [`StoreObjectType`].
    #[must_use]
    pub const fn object_type(&self) -> StoreObjectType {
        self.object_type
    }

    /// The long-term id, which is the tail of the structure and the part a ROP takes.
    #[must_use]
    pub const fn long_term_id(&self) -> LongTermId {
        self.long_term_id
    }

    /// Whether this entry id was issued by the mailbox a logon reported.
    ///
    /// **This is the only thing that tells two mailboxes' folders apart.** Measured on Exchange
    /// Server SE `15.02.2562.045`: the two lab mailboxes, provisioned in different languages,
    /// report *identical* folder ids for six of their seven special folders — Calendar is
    /// `0x0D01000000000001` in both, Contacts `0x0E01000000000001`, and so on. A short-term id is
    /// only meaningful inside the logon that produced it, and here the numbers are literally the
    /// same, so an id cached from one mailbox and used against another opens a real folder and
    /// reports no error at all. The entry ids differ, because this field does.
    ///
    /// [MS-OXCDATA] §2.2.4.1 — for a private mailbox folder, `Provider UID` is the `MailboxGuid`
    #[must_use]
    pub fn belongs_to(&self, mailbox_guid: Guid) -> bool {
        self.provider_uid == mailbox_guid
    }

    /// Parses the value of a `PidTagIpm*EntryId` property.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEntryId`] if the value is not 46 bytes, if its `Flags` are non-zero — which
    /// marks a short-term entry id, and [MS-OXCDATA] §2.2.4.1 requires those four bytes to be zero
    /// in anything stored in a property — or if its object type does not name a folder.
    ///
    /// The last of those three is the one worth having: `PidTagIpmDraftsEntryId` and
    /// `PidTagParentEntryId` are the same 46 bytes as a message's entry id in every respect but
    /// this field, so it is the only thing standing between a folder open and a wrong one.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let length = bytes.len();
        if length != Self::SIZE {
            return Err(Error::InvalidEntryId {
                length,
                reason: "a Folder EntryID is 46 bytes",
            });
        }

        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Error::InvalidEntryId {
                length,
                reason: "non-zero Flags mark a short-term EntryID, which a stored property may \
                         not hold",
            });
        }

        let provider_uid = Guid::from_bytes(r.array::<16>()?);
        let object_type = StoreObjectType::new(r.u16()?);
        if !object_type.is_folder() {
            return Err(Error::InvalidEntryId {
                length,
                reason: "the object type is neither PrivateFolder nor PublicFolder",
            });
        }

        Ok(Self {
            provider_uid,
            object_type,
            long_term_id: LongTermId::read(&mut r)?,
        })
    }

    /// The 46 bytes as the wire carries them.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut w = Writer::new();
        w.u32(0).bytes(self.provider_uid.as_bytes());
        w.u16(self.object_type.as_u16());
        self.long_term_id.write(&mut w);

        let mut out = [0_u8; Self::SIZE];
        // The writer above appends exactly `SIZE` bytes, so the copy is total; `get` rather than
        // indexing keeps that true by construction rather than by reading the lines above.
        if let Some(written) = w.finish().get(..Self::SIZE) {
            out.copy_from_slice(written);
        }
        out
    }
}

impl core::fmt::Display for FolderEntryId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} in {}", self.long_term_id, self.provider_uid)
    }
}

/// The eight bytes `RopIdFromLongTermId` answers with, and `RopLongTermIdFromId` converts.
///
/// A folder id and a message id are structurally identical, and this ROP pair works on either —
/// so which one a value is depends on what was converted, not on the bytes. Keeping that as its
/// own type means the caller says which it asked for, rather than a decoder guessing.
///
/// [MS-OXCROPS] §2.2.3.9.2 — `ObjectId`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortTermId(u64);

impl ShortTermId {
    /// Wraps a raw identifier.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The identifier as the wire carries it.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Read as a folder id, which is what it is when a folder's entry id was converted.
    #[must_use]
    pub const fn as_folder_id(self) -> FolderId {
        FolderId::new(self.0)
    }

    /// Read as a message id, which is what it is when a message's entry id was converted.
    #[must_use]
    pub const fn as_message_id(self) -> MessageId {
        MessageId::new(self.0)
    }
}

impl From<FolderId> for ShortTermId {
    fn from(id: FolderId) -> Self {
        Self(id.as_u64())
    }
}

impl From<MessageId> for ShortTermId {
    fn from(id: MessageId) -> Self {
        Self(id.as_u64())
    }
}

impl core::fmt::Display for ShortTermId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{:016X}", self.0)
    }
}

#[cfg(test)]
mod tests;
