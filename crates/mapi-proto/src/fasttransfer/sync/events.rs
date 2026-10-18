//! What a content synchronization download reports, one event per unit of its stream.

use crate::error::{ErrorCode, Result};
use crate::fasttransfer::StreamProperty;
use crate::fasttransfer::content::{MessageContent, find, malformed};
use crate::fasttransfer::group::PropertyGroupInfo;
use crate::fasttransfer::sync::{id, idset};
use crate::ics::{ChangeNumber, GlobCnt, IdSet};
use crate::oxcdata::{FileTime, Guid, MessageId, PropertyTag, PropertyValue, ReplicaId};
use crate::wire::Reader;

/// One thing a download reported.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncEvent {
    /// How much is coming, when the download was configured to say.
    ///
    /// [MS-OXCFXICS] §2.2.4.3.19 — `progressTotal`
    Progress(Progress),
    /// A message that is new or changed since the state the download started from.
    Message(MessageChange),
    /// Messages that are gone from the scope, in three kinds kept apart.
    Deletions(Deletions),
    /// Messages whose read state changed.
    ReadStates(ReadStates),
    /// The server's own final state, which replaces any checkpoint.
    State(FinalState),
    /// An object the server could not produce, reported in its place.
    ///
    /// [MS-OXCFXICS] §2.2.4.3.4: the reader unwinds "up to, but not including, the closest element
    /// that supports recovery", which here is the download itself — so what came of the object
    /// before the error is discarded and the next event is read as usual.
    Failed(ErrorInfo),
    /// A unit of the stream whose elements did not fit the grammar, with whatever of its header
    /// could be read.
    ///
    /// Reported and stepped over rather than failing the download: one malformed object must not
    /// cost every object after it.
    Unreadable {
        /// The header, for a message change that got that far.
        header: Option<ChangeHeader>,
        /// What did not fit.
        reason: String,
    },
    /// `IncrSyncEnd`: nothing more is coming.
    End,
}

/// The header every message change begins with: enough to identify the message and to tell one
/// version of it from another.
///
/// [MS-OXCFXICS] §2.2.4.3.14 — `messageChangeHeader`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeHeader {
    source_key: Vec<u8>,
    last_modified: Option<FileTime>,
    change_key: Vec<u8>,
    predecessor_change_list: Vec<u8>,
    associated: bool,
    id: Option<MessageId>,
    size: Option<u32>,
    change_number: Option<ChangeNumber>,
}

impl ChangeHeader {
    pub(crate) fn read(properties: &[StreamProperty]) -> Result<Self> {
        let binary = |tag| match find(properties, tag) {
            Some(PropertyValue::Binary(bytes)) => Some(bytes.clone()),
            _ => None,
        };
        let source_key = binary(PropertyTag::SOURCE_KEY)
            .ok_or_else(|| malformed("a message change header", "PidTagSourceKey is missing"))?;
        Ok(Self {
            source_key,
            last_modified: find(properties, PropertyTag::LAST_MODIFICATION_TIME)
                .and_then(PropertyValue::as_time),
            change_key: binary(PropertyTag::CHANGE_KEY).unwrap_or_default(),
            predecessor_change_list: binary(PropertyTag::PREDECESSOR_CHANGE_LIST)
                .unwrap_or_default(),
            associated: find(properties, PropertyTag::ASSOCIATED)
                .and_then(PropertyValue::as_bool)
                .unwrap_or(false),
            id: id(properties, PropertyTag::MID).map(MessageId::new),
            size: find(properties, PropertyTag::MESSAGE_SIZE).and_then(PropertyValue::as_u32),
            change_number: id(properties, PropertyTag::CHANGE_NUMBER).map(ChangeNumber::new),
        })
    }

    /// `PidTagSourceKey`: the message's identity across replicas. [MS-OXCFXICS] §2.2.1.2.5
    #[must_use]
    pub fn source_key(&self) -> &[u8] {
        &self.source_key
    }

    /// `PidTagLastModificationTime`.
    #[must_use]
    pub const fn last_modified(&self) -> Option<FileTime> {
        self.last_modified
    }

    /// `PidTagChangeKey`: which version this is. [MS-OXCFXICS] §2.2.1.2.7
    #[must_use]
    pub fn change_key(&self) -> &[u8] {
        &self.change_key
    }

    /// `PidTagPredecessorChangeList`: the versions this one supersedes. [MS-OXCFXICS] §2.2.1.2.8
    #[must_use]
    pub fn predecessor_change_list(&self) -> &[u8] {
        &self.predecessor_change_list
    }

    /// `PidTagAssociated`: whether this is an FAI message. [MS-OXCFXICS] §2.2.1.5
    #[must_use]
    pub const fn is_associated(&self) -> bool {
        self.associated
    }

    /// `PidTagMid`, present when the download was configured with `Eid`.
    #[must_use]
    pub const fn id(&self) -> Option<MessageId> {
        self.id
    }

    /// `PidTagMessageSize`, present when the download was configured with `MessageSize`.
    #[must_use]
    pub const fn size(&self) -> Option<u32> {
        self.size
    }

    /// `PidTagChangeNumber`, present when the download was configured with `CN`.
    #[must_use]
    pub const fn change_number(&self) -> Option<ChangeNumber> {
        self.change_number
    }
}

/// A new or changed message.
///
/// **Full or partial.** A full change carries the whole message. A partial one carries only the
/// property groups that changed, each as "the complete content of a property group" — what the
/// group's mapping names and the group omits is to be deleted — and children only where they
/// changed. Which groups changed is the useful part: a change confined to the group holding the
/// read flag or the categories needs no refetch.
///
/// [MS-OXCFXICS] §2.2.4.3.13 — `messageChangeFull`
/// [MS-OXCFXICS] §2.2.4.3.15 — `messageChangePartial`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageChange {
    header: ChangeHeader,
    partial: bool,
    content: MessageContent,
    groups: Vec<PartialGroup>,
    mapping: Option<PropertyGroupInfo>,
    progress: Option<(u32, bool)>,
}

impl MessageChange {
    pub(crate) const fn full(
        header: ChangeHeader,
        content: MessageContent,
        progress: Option<(u32, bool)>,
    ) -> Self {
        Self {
            header,
            partial: false,
            content,
            groups: Vec::new(),
            mapping: None,
            progress,
        }
    }

    pub(crate) const fn partial(
        header: ChangeHeader,
        groups: Vec<PartialGroup>,
        content: MessageContent,
        mapping: Option<PropertyGroupInfo>,
        progress: Option<(u32, bool)>,
    ) -> Self {
        Self {
            header,
            partial: true,
            content,
            groups,
            mapping,
            progress,
        }
    }

    /// The header: identity and version.
    #[must_use]
    pub const fn header(&self) -> &ChangeHeader {
        &self.header
    }

    /// Whether only the changed property groups were sent.
    #[must_use]
    pub const fn is_partial(&self) -> bool {
        self.partial
    }

    /// The message's properties and children. For a partial change, the properties are empty —
    /// they are in [`groups`](Self::groups) — and the children are the ones that changed.
    #[must_use]
    pub const fn content(&self) -> &MessageContent {
        &self.content
    }

    /// The value of one property: from the message for a full change, from whichever changed
    /// group carries it for a partial one.
    #[must_use]
    pub fn property(&self, tag: PropertyTag) -> Option<&PropertyValue> {
        self.content.property(tag).or_else(|| {
            self.groups
                .iter()
                .find_map(|group| find(group.properties(), tag))
        })
    }

    /// The property groups a partial change carried, in stream order.
    #[must_use]
    pub fn groups(&self) -> &[PartialGroup] {
        &self.groups
    }

    /// The mapping the partial change's group indices refer to, as the stream last defined it.
    #[must_use]
    pub const fn group_mapping(&self) -> Option<&PropertyGroupInfo> {
        self.mapping.as_ref()
    }

    /// The size and FAI flag the stream announced before this change, when it was configured with
    /// `Progress`. [MS-OXCFXICS] §2.2.4.3.18
    #[must_use]
    pub const fn announced(&self) -> Option<(u32, bool)> {
        self.progress
    }
}

/// One changed property group of a partial change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialGroup {
    index: u32,
    properties: Vec<StreamProperty>,
}

impl PartialGroup {
    /// The index a group's properties arrive under when they belong to no group in the mapping.
    ///
    /// [MS-OXCFXICS] §2.2.4.3.15 — `0xFFFFFFFF`, "the properties [...] don't exist in any specific
    /// property group"
    pub const UNGROUPED: u32 = 0xFFFF_FFFF;

    pub(crate) const fn new(index: u32, properties: Vec<StreamProperty>) -> Self {
        Self { index, properties }
    }

    /// The group's index in the mapping, or [`UNGROUPED`](Self::UNGROUPED).
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// The group's complete content. Empty for a group that changed by losing every property.
    #[must_use]
    pub fn properties(&self) -> &[StreamProperty] {
        &self.properties
    }
}

/// The messages gone from a scope, in the three kinds [MS-OXCFXICS] §2.2.1.3 keeps apart.
///
/// Whether any of them is a removal is the caller's decision. A message that moved out of a
/// restricted scope still exists; one that expired was in a public folder.
///
/// [MS-OXCFXICS] §2.2.4.3.3 — `deletions`
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Deletions {
    deleted: IdSet<ReplicaId>,
    no_longer_in_scope: IdSet<ReplicaId>,
    expired: IdSet<ReplicaId>,
}

impl Deletions {
    pub(crate) fn read(properties: &[StreamProperty]) -> Result<Self> {
        Ok(Self {
            deleted: idset(properties, PropertyTag::META_TAG_IDSET_DELETED)?,
            no_longer_in_scope: idset(properties, PropertyTag::META_TAG_IDSET_NO_LONGER_IN_SCOPE)?,
            expired: idset(properties, PropertyTag::META_TAG_IDSET_EXPIRED)?,
        })
    }

    /// `MetaTagIdsetDeleted`. [MS-OXCFXICS] §2.2.1.3.1
    #[must_use]
    pub const fn deleted(&self) -> &IdSet<ReplicaId> {
        &self.deleted
    }

    /// `MetaTagIdsetNoLongerInScope`. [MS-OXCFXICS] §2.2.1.3.2
    #[must_use]
    pub const fn no_longer_in_scope(&self) -> &IdSet<ReplicaId> {
        &self.no_longer_in_scope
    }

    /// `MetaTagIdsetExpired` — public folders only; note `<1>` says Exchange 2013 and later do not
    /// send it. [MS-OXCFXICS] §2.2.1.3.3
    #[must_use]
    pub const fn expired(&self) -> &IdSet<ReplicaId> {
        &self.expired
    }
}

/// Messages whose read state changed since the last synchronization.
///
/// [MS-OXCFXICS] §2.2.4.3.22 — `readStateChanges`
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadStates {
    read: IdSet<ReplicaId>,
    unread: IdSet<ReplicaId>,
}

impl ReadStates {
    pub(crate) fn read(properties: &[StreamProperty]) -> Result<Self> {
        Ok(Self {
            read: idset(properties, PropertyTag::META_TAG_IDSET_READ)?,
            unread: idset(properties, PropertyTag::META_TAG_IDSET_UNREAD)?,
        })
    }

    /// `MetaTagIdsetRead`: now read. [MS-OXCFXICS] §2.2.1.3.4
    #[must_use]
    pub const fn marked_read(&self) -> &IdSet<ReplicaId> {
        &self.read
    }

    /// `MetaTagIdsetUnread`: now unread. [MS-OXCFXICS] §2.2.1.3.5
    #[must_use]
    pub const fn marked_unread(&self) -> &IdSet<ReplicaId> {
        &self.unread
    }
}

/// The final ICS state a download ends with, which [`IcsState::complete`] takes in.
///
/// [MS-OXCFXICS] §2.2.4.3.25 — `state`
///
/// [`IcsState::complete`]: crate::IcsState::complete
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FinalState {
    pub(crate) idset_given: IdSet<Guid>,
    pub(crate) cnset_seen: IdSet<Guid>,
    pub(crate) cnset_seen_fai: IdSet<Guid>,
    pub(crate) cnset_read: IdSet<Guid>,
}

impl FinalState {
    pub(crate) fn read(properties: &[StreamProperty]) -> Result<Self> {
        Ok(Self {
            idset_given: idset(properties, PropertyTag::META_TAG_IDSET_GIVEN)?,
            cnset_seen: idset(properties, PropertyTag::META_TAG_CNSET_SEEN)?,
            cnset_seen_fai: idset(properties, PropertyTag::META_TAG_CNSET_SEEN_FAI)?,
            cnset_read: idset(properties, PropertyTag::META_TAG_CNSET_READ)?,
        })
    }

    /// `MetaTagIdsetGiven`.
    #[must_use]
    pub const fn idset_given(&self) -> &IdSet<Guid> {
        &self.idset_given
    }

    /// `MetaTagCnsetSeen`.
    #[must_use]
    pub const fn cnset_seen(&self) -> &IdSet<Guid> {
        &self.cnset_seen
    }

    /// `MetaTagCnsetSeenFAI`.
    #[must_use]
    pub const fn cnset_seen_fai(&self) -> &IdSet<Guid> {
        &self.cnset_seen_fai
    }

    /// `MetaTagCnsetRead`.
    #[must_use]
    pub const fn cnset_read(&self) -> &IdSet<Guid> {
        &self.cnset_read
    }
}

/// How much a download is about to deliver. Approximate, by the document's own account.
///
/// [MS-OXCFXICS] §2.2.2.7 — `ProgressInformation`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    fai_count: u32,
    fai_size: u64,
    normal_count: u32,
    normal_size: u64,
}

impl Progress {
    /// Reads the structure, whatever its `Version` says.
    ///
    /// §2.2.2.7 calls `0x0000` "the only version of this structure defined for this protocol";
    /// the document's own example in §4.5 sends `0x0026`, with the layout §2.2.2.7 describes. So
    /// the version is read and not checked.
    pub(crate) fn read(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let _version = r.u16()?;
        let _padding = r.u16()?;
        let fai_count = r.u32()?;
        let fai_size = r.u64()?;
        let normal_count = r.u32()?;
        let _padding = r.u32()?;
        let normal_size = r.u64()?;
        Ok(Self {
            fai_count,
            fai_size,
            normal_count,
            normal_size,
        })
    }

    /// How many FAI message changes are coming.
    #[must_use]
    pub const fn fai_count(self) -> u32 {
        self.fai_count
    }

    /// Their size in bytes.
    #[must_use]
    pub const fn fai_size(self) -> u64 {
        self.fai_size
    }

    /// How many normal message changes are coming.
    #[must_use]
    pub const fn normal_count(self) -> u32 {
        self.normal_count
    }

    /// Their size in bytes.
    #[must_use]
    pub const fn normal_size(self) -> u64 {
        self.normal_size
    }
}

/// An object the server could not produce, and where it was.
///
/// [MS-OXCFXICS] §2.2.2.10 — `ExtendedErrorInfo`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorInfo {
    code: ErrorCode,
    folder: Option<(Guid, GlobCnt)>,
    message: Option<(Guid, GlobCnt)>,
    diagnostic: Vec<u8>,
}

impl ErrorInfo {
    pub(crate) fn read(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.u16()? != 0 {
            return Err(malformed(
                "ExtendedErrorInfo",
                "a version other than 0x0000",
            ));
        }
        let _padding = r.u16()?;
        let code = ErrorCode::new(r.u32()?);
        let folder = gid(&mut r)?;
        let _padding = r.u16()?;
        let message = gid(&mut r)?;
        let _padding = r.u16()?;
        let _reserved = r.bytes(24)?;
        let count = usize::try_from(r.u32()?).unwrap_or(usize::MAX);
        let offset = usize::try_from(r.u32()?).unwrap_or(usize::MAX);
        let diagnostic = if count == 0 {
            Vec::new()
        } else {
            let end = offset.checked_add(count).ok_or_else(|| {
                malformed(
                    "ExtendedErrorInfo",
                    "AuxBytes past the end of the structure",
                )
            })?;
            bytes
                .get(offset..end)
                .ok_or_else(|| {
                    malformed(
                        "ExtendedErrorInfo",
                        "AuxBytes past the end of the structure",
                    )
                })?
                .to_vec()
        };
        Ok(Self {
            code,
            folder,
            message,
            diagnostic,
        })
    }

    /// Why.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// The folder in context, as its replica GUID and counter; `None` when none was.
    #[must_use]
    pub const fn folder(&self) -> Option<(Guid, GlobCnt)> {
        self.folder
    }

    /// The message in context; `None` when none was.
    #[must_use]
    pub const fn message(&self) -> Option<(Guid, GlobCnt)> {
        self.message
    }

    /// Opaque diagnostic bytes the server attached, which "MAY be logged by the client".
    #[must_use]
    pub fn diagnostic(&self) -> &[u8] {
        &self.diagnostic
    }
}

/// A 22-byte GID: a GUID and a counter. All zeroes means none was in context.
///
/// [MS-OXCDATA] §2.2.1.3 — Global Identifier structure
fn gid(r: &mut Reader<'_>) -> Result<Option<(Guid, GlobCnt)>> {
    let guid = r.array::<16>()?;
    let counter = r.array::<6>()?;
    if guid == [0; 16] && counter == [0; 6] {
        return Ok(None);
    }
    Ok(Some((Guid::from_bytes(guid), GlobCnt::from_bytes(counter))))
}
