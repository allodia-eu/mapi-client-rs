//! An ICS state, bound to the synchronization scope it was obtained for.
//!
//! **The state does not know its own scope, and the server cannot tell either.** [MS-OXCFXICS]
//! §3.3.5.5: "ICS state does not reflect the synchronization scope it belongs to. Therefore, a
//! client MUST ensure that the ICS state it passes to a server corresponds to the synchronization
//! scope that it was originally obtained for." A state replayed under a different folder or
//! restriction is accepted and answered — with soft deletions for everything the old scope held and
//! the new one does not, or with nothing for what the new one holds and the old one had already
//! seen. Mail is skipped, and nothing says so.
//!
//! So an [`IcsState`] carries its [`SyncScope`] — the synchronization type, the folder, the
//! restriction exactly as it was encoded, and the mailbox instance GUID that §3.3.5.4 has a client
//! validate a replica against — and a download configured for any other scope refuses it before a
//! byte is sent. *Narrowing* a date floor is a new scope as surely as widening one.
//!
//! **What is not part of the scope** is just as deliberate. §3.3.5.5 says the `Normal` and `FAI`
//! flags "do not modify the synchronization scope; they just filter the output", and neither does
//! the property list. That second one is a trap rather than a freedom: a state replayed with a
//! wider property list does not re-send anything already in `MetaTagCnsetSeen`, so properties left
//! out of a metadata pass have to be fetched another way, never by syncing again with more of them.
//!
//! [MS-OXCFXICS] §2.2.1.1 — ICS state properties
//! [MS-OXCFXICS] §3.3.5.4 — mailbox validation
//! [MS-OXCFXICS] §3.3.5.5 — determining the synchronization scope

use crate::error::{Error, Result};
use crate::fasttransfer::FinalState;
use crate::ics::globset::GlobCnt;
use crate::ics::idset::{self, IdSet, split};
use crate::oxcdata::{
    FolderId, Guid, MessageId, PropertyTag, ReplicaId, Restriction, ValueContext,
};
use crate::wire::{Reader, Writer};

/// The first bytes of an encoded state, so that something else handed to
/// [`IcsState::from_bytes`] is refused by name rather than misread.
const MAGIC: [u8; 4] = *b"MICS";

/// The encoding this crate writes. A later one is refused, never guessed at.
const VERSION: u8 = 1;

/// What a synchronization download covers: contents or hierarchy.
///
/// [MS-OXCFXICS] §2.2.3.2.1.1.1 — `SynchronizationType`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SyncKind {
    /// `0x01` — the messages in one folder.
    Contents,
    /// `0x02` — the folders below one folder.
    Hierarchy,
}

impl SyncKind {
    /// The `SynchronizationType` byte.
    pub(crate) const fn as_u8(self) -> u8 {
        match self {
            Self::Contents => 0x01,
            Self::Hierarchy => 0x02,
        }
    }

    const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0x01 => Some(Self::Contents),
            0x02 => Some(Self::Hierarchy),
            _ => None,
        }
    }
}

/// The synchronization scope an ICS state belongs to.
///
/// [MS-OXCFXICS] §3.3.5.5: synchronization type, folder and restriction. The mailbox instance GUID
/// is added because §3.3.5.4 makes the same demand of the mailbox: "a client MUST NOT let a
/// replica of one mailbox synchronize with a different mailbox". It is the GUID `RopLogon` reports
/// as `MailboxGuid`, which is what changes when a mailbox is recreated after a disaster.
///
/// The restriction is held as the bytes `RopSynchronizationConfigure` carries, which is what makes
/// two scopes equal exactly when the server would be asked the same question.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SyncScope {
    mailbox: Guid,
    kind: SyncKind,
    folder: FolderId,
    restriction: Vec<u8>,
}

impl SyncScope {
    /// The contents of one folder, optionally narrowed by a restriction.
    ///
    /// # Errors
    ///
    /// Whatever the restriction refused to encode: a string with an interior NUL, or a value longer
    /// than its COUNT field can express.
    pub fn contents(
        mailbox: Guid,
        folder: FolderId,
        restriction: Option<&Restriction>,
    ) -> Result<Self> {
        let mut w = Writer::new();
        if let Some(restriction) = restriction {
            restriction.write(&mut w, ValueContext::Object)?;
        }
        Ok(Self {
            mailbox,
            kind: SyncKind::Contents,
            folder,
            restriction: w.finish(),
        })
    }

    /// The folders below one folder. A hierarchy download takes no restriction.
    ///
    /// [MS-OXCFXICS] §2.2.3.2.1.1.1 — `RestrictionDataSize` MUST be zero for `Hierarchy`
    #[must_use]
    pub const fn hierarchy(mailbox: Guid, folder: FolderId) -> Self {
        Self {
            mailbox,
            kind: SyncKind::Hierarchy,
            folder,
            restriction: Vec::new(),
        }
    }

    /// The mailbox instance GUID the scope is bound to.
    #[must_use]
    pub const fn mailbox(&self) -> Guid {
        self.mailbox
    }

    /// Contents or hierarchy.
    #[must_use]
    pub const fn kind(&self) -> SyncKind {
        self.kind
    }

    /// The folder synchronized.
    #[must_use]
    pub const fn folder(&self) -> FolderId {
        self.folder
    }

    /// The restriction as `RopSynchronizationConfigure` carries it; empty for none.
    #[must_use]
    pub fn restriction_bytes(&self) -> &[u8] {
        &self.restriction
    }

    /// Which part of the scope differs, for an error that says so.
    fn difference(&self, other: &Self) -> Option<&'static str> {
        if self.mailbox != other.mailbox {
            Some("the mailbox instance GUID")
        } else if self.kind != other.kind {
            Some("the synchronization type")
        } else if self.folder != other.folder {
            Some("the folder")
        } else if self.restriction != other.restriction {
            Some("the restriction")
        } else {
            None
        }
    }
}

/// A change number: which version of a messaging object a download delivered.
///
/// The same eight-byte shape as a [`MessageId`] — a REPLID, then a GLOBCNT — counting changes
/// rather than objects, which is exactly why it gets a type of its own.
///
/// [MS-OXCFXICS] §2.2.2.1 — CN structure
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChangeNumber(u64);

impl ChangeNumber {
    /// Wraps a raw change number, as `PidTagChangeNumber` carries it.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The change number as the little-endian `u64` the wire carries.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// The replica the change was made in.
    #[must_use]
    pub const fn replica_id(self) -> ReplicaId {
        split(self.0).0
    }

    /// The change's counter within that replica.
    #[must_use]
    pub const fn counter(self) -> GlobCnt {
        split(self.0).1
    }
}

impl core::fmt::Display for ChangeNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}-{}", self.replica_id(), self.counter())
    }
}

/// An ICS state: what a client has, bound to the scope it has it for.
///
/// Owned and serialisable — [`to_bytes`](Self::to_bytes) and [`from_bytes`](Self::from_bytes) are
/// a versioned encoding of this crate's own, carrying the scope with the four state properties, so
/// a state persisted by one process and loaded by another arrives with the same protection.
///
/// [MS-OXCFXICS] §2.2.1.1 — `MetaTagIdsetGiven`, `MetaTagCnsetSeen`, `MetaTagCnsetSeenFAI`,
/// `MetaTagCnsetRead`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IcsState {
    scope: SyncScope,
    /// Which REPLGUID each REPLID a download names messages by stands for.
    replicas: Vec<(ReplicaId, Guid)>,
    idset_given: IdSet<Guid>,
    cnset_seen: IdSet<Guid>,
    cnset_seen_fai: IdSet<Guid>,
    cnset_read: IdSet<Guid>,
}

impl IcsState {
    /// The state a first synchronization starts from: nothing given, nothing seen.
    #[must_use]
    pub const fn initial(scope: SyncScope) -> Self {
        Self {
            scope,
            replicas: Vec::new(),
            idset_given: IdSet::new(),
            cnset_seen: IdSet::new(),
            cnset_seen_fai: IdSet::new(),
            cnset_read: IdSet::new(),
        }
    }

    /// The scope this state was obtained for, and the only one it may be used with.
    #[must_use]
    pub const fn scope(&self) -> &SyncScope {
        &self.scope
    }

    /// Whether this is a first synchronization: no state property holds anything.
    #[must_use]
    pub fn is_initial(&self) -> bool {
        self.idset_given.is_empty()
            && self.cnset_seen.is_empty()
            && self.cnset_seen_fai.is_empty()
            && self.cnset_read.is_empty()
    }

    /// `MetaTagIdsetGiven`: the objects the client holds. [MS-OXCFXICS] §2.2.1.1.1
    #[must_use]
    pub const fn idset_given(&self) -> &IdSet<Guid> {
        &self.idset_given
    }

    /// `MetaTagCnsetSeen`: the changes to normal messages the client has. [MS-OXCFXICS] §2.2.1.1.2
    #[must_use]
    pub const fn cnset_seen(&self) -> &IdSet<Guid> {
        &self.cnset_seen
    }

    /// `MetaTagCnsetSeenFAI`: the same for FAI messages. [MS-OXCFXICS] §2.2.1.1.3
    #[must_use]
    pub const fn cnset_seen_fai(&self) -> &IdSet<Guid> {
        &self.cnset_seen_fai
    }

    /// `MetaTagCnsetRead`: the read-state changes the client has. [MS-OXCFXICS] §2.2.1.1.4
    #[must_use]
    pub const fn cnset_read(&self) -> &IdSet<Guid> {
        &self.cnset_read
    }

    /// Records which REPLGUID a REPLID stands for, so that ids from that replica can be folded in
    /// by [`record_message`](Self::record_message).
    ///
    /// A download names messages by REPLID and a state names them by REPLGUID, and only the server
    /// holds the mapping: [MS-OXCFXICS] §3.1.5.4.2 converts one form to the other "by using mapping
    /// operations, as specified in [MS-OXCSTOR]", which is `RopLongTermIdFromId` — the long-term id
    /// of any folder or message from a replica carries that replica's GUID.
    ///
    /// **Not the logon's `ReplId` and `ReplGuid`.** [MS-OXCSTOR] §2.2.1.1.3 calls `ReplId` "the
    /// replica ID for the logon", and on Exchange Server SE `15.02.2562.056` it is a different
    /// replica from the one the mailbox's own messages are numbered in: the logon reported REPLID
    /// 5, every message id in the Inbox carried REPLID 1, and the server's final state named
    /// REPLID 1's counters under a GUID the logon never mentioned. A state folded by the
    /// logon's pair records nothing at all.
    ///
    /// Learnt once per replica and kept in the encoded state, so a resumed download folds from its
    /// first message.
    ///
    /// [MS-OXCROPS] §2.2.3.8 — `RopLongTermIdFromId`
    pub fn map_replica(&mut self, replica: ReplicaId, guid: Guid) {
        match self
            .replicas
            .iter_mut()
            .find(|(known, _)| *known == replica)
        {
            Some(entry) => entry.1 = guid,
            None => self.replicas.push((replica, guid)),
        }
    }

    /// The REPLGUID a REPLID stands for, if [`map_replica`](Self::map_replica) has been told.
    #[must_use]
    pub fn replica_guid(&self, replica: ReplicaId) -> Option<Guid> {
        self.replicas
            .iter()
            .find(|(known, _)| *known == replica)
            .map(|(_, guid)| *guid)
    }

    /// Refuses to be used for any scope but its own.
    ///
    /// # Errors
    ///
    /// [`Error::IcsScopeMismatch`] naming the first part of the scope that differs.
    pub fn check_scope(&self, scope: &SyncScope) -> Result<()> {
        match self.scope.difference(scope) {
            None => Ok(()),
            Some(differs) => Err(Error::IcsScopeMismatch { differs }),
        }
    }

    /// The four state properties as `RopSynchronizationUploadStateStreamBegin` takes them, each
    /// with its tag, leaving out any that is empty.
    ///
    /// `MetaTagIdsetGiven` goes with the `PtypInteger32` tag its section gives it, carrying binary
    /// data all the same, because §3.3.5.13 says clients SHOULD send it that way.
    ///
    /// [MS-OXCFXICS] §2.2.3.2.2.1.1 — `StateProperty`
    /// [MS-OXCFXICS] §3.3.5.13 — sending `MetaTagIdsetGiven`
    #[must_use]
    pub fn state_properties(&self) -> Vec<(PropertyTag, Vec<u8>)> {
        [
            (PropertyTag::META_TAG_IDSET_GIVEN, &self.idset_given),
            (PropertyTag::META_TAG_CNSET_SEEN, &self.cnset_seen),
            (PropertyTag::META_TAG_CNSET_SEEN_FAI, &self.cnset_seen_fai),
            (PropertyTag::META_TAG_CNSET_READ, &self.cnset_read),
        ]
        .into_iter()
        .filter(|(_, set)| !set.is_empty())
        .map(|(tag, set)| (tag, idset::to_bytes(set)))
        .collect()
    }

    /// Folds one downloaded message into the state, which is client-side checkpointing.
    ///
    /// [MS-OXCFXICS] §3.3.5.6: with `Eid` and `CN` set, the client keeps "its `MetaTagIdsetGiven`
    /// and `MetaTagCnsetSeen` (or `MetaTagCnsetSeenFAI`, for folder associated information (FAI)
    /// messages) properties" itself, and a state persisted that way survives "a cancellation or
    /// other abnormal termination". On Exchange it is the *only* way: notes `<2>` and `<42>` have
    /// Exchange 2010 and later answer `RopSynchronizationGetTransferState` with the initial state
    /// until the stream ends.
    ///
    /// `MetaTagCnsetRead` is not folded, because §3.3.5.6 names only the other two and a message
    /// change carries no read-state change number. A download resumed from a checkpoint can report
    /// read states again for messages it already delivered, which costs nothing but repetition.
    ///
    /// Returns whether both ids could be folded. An id from a replica the state has not been told
    /// about — see [`map_replica`](Self::map_replica) — cannot be named by REPLGUID, and is left
    /// out: the message is then downloaded again after a resume, which is the safe direction to be
    /// wrong in.
    pub fn record_message(
        &mut self,
        id: MessageId,
        change: ChangeNumber,
        associated: bool,
    ) -> bool {
        let (replica, counter) = split(id.as_u64());
        let (change_replica, change_counter) = split(change.as_u64());
        let (Some(guid), Some(change_guid)) = (
            self.replica_guid(replica),
            self.replica_guid(change_replica),
        ) else {
            return false;
        };
        self.idset_given.insert(guid, counter);
        let seen = if associated {
            &mut self.cnset_seen_fai
        } else {
            &mut self.cnset_seen
        };
        seen.insert(change_guid, change_counter);
        true
    }

    /// Replaces the state properties with the final state a download ended with.
    ///
    /// The server's own, which §3.3.5.6 recommends keeping over a checkpoint because it "is a much
    /// more efficient version than the version obtained by using checkpointing alone". A property
    /// the `state` element left out becomes empty, since the element *is* the final state.
    ///
    /// Check it with [`check_not_ahead_of`](Self::check_not_ahead_of) first: a final state from a
    /// server that has gone back in time lists as delivered a message it never sent.
    ///
    /// [MS-OXCFXICS] §2.2.4.3.25 — `state` element
    pub fn complete(&mut self, state: FinalState) {
        self.idset_given = state.idset_given;
        self.cnset_seen = state.cnset_seen;
        self.cnset_seen_fai = state.cnset_seen_fai;
        self.cnset_read = state.cnset_read;
    }

    /// Encodes the state, scope and all, for a caller to persist.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&MAGIC)
            .u8(VERSION)
            .bytes(self.scope.mailbox.as_bytes())
            .u8(self.scope.kind.as_u8())
            .u64(self.scope.folder.as_u64());
        write_block(&mut w, &self.scope.restriction);
        w.u16(u16::try_from(self.replicas.len()).unwrap_or(u16::MAX));
        for (replica, guid) in self.replicas.iter().take(usize::from(u16::MAX)) {
            w.u16(replica.as_u16()).bytes(guid.as_bytes());
        }
        for set in [
            &self.idset_given,
            &self.cnset_seen,
            &self.cnset_seen_fai,
            &self.cnset_read,
        ] {
            write_block(&mut w, &idset::to_bytes(set));
        }
        w.finish()
    }

    /// Decodes a state [`to_bytes`](Self::to_bytes) produced.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidIcsState`] for bytes that are not an encoded state, or one of a version this
    /// crate does not know; any decoding error from the IDSETs inside it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let refuse = |reason| Error::InvalidIcsState { reason };
        if r.array::<4>()? != MAGIC {
            return Err(refuse("not an ICS state this crate encoded"));
        }
        if r.u8()? != VERSION {
            return Err(refuse("an encoding version this crate does not know"));
        }
        let mailbox = Guid::from_bytes(r.array::<16>()?);
        let kind = SyncKind::from_u8(r.u8()?).ok_or(refuse("an unknown synchronization type"))?;
        let folder = FolderId::new(r.u64()?);
        let restriction = read_block(&mut r)?.to_vec();
        let mut replicas = Vec::new();
        for _ in 0..r.u16()? {
            replicas.push((ReplicaId::new(r.u16()?), Guid::from_bytes(r.array::<16>()?)));
        }
        let idset_given = idset::read(read_block(&mut r)?)?;
        let cnset_seen = idset::read(read_block(&mut r)?)?;
        let cnset_seen_fai = idset::read(read_block(&mut r)?)?;
        let cnset_read = idset::read(read_block(&mut r)?)?;
        if !r.is_empty() {
            return Err(refuse("bytes after the last state property"));
        }
        Ok(Self {
            scope: SyncScope {
                mailbox,
                kind,
                folder,
                restriction,
            },
            replicas,
            idset_given,
            cnset_seen,
            cnset_seen_fai,
            cnset_read,
        })
    }
}

/// A `u32` length, then that many bytes.
fn write_block(w: &mut Writer, bytes: &[u8]) {
    w.u32(u32::try_from(bytes.len()).unwrap_or(u32::MAX))
        .bytes(bytes);
}

/// The inverse of [`write_block`].
fn read_block<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    let length = usize::try_from(r.u32()?).unwrap_or(usize::MAX);
    r.bytes(length)
}

mod rollback;

#[cfg(test)]
mod tests;
