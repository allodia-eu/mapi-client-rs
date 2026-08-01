//! `RopLogon` — the ROP that turns a distinguished name into a usable mailbox.
//!
//! Its response is what makes the rest cheap: a private-mailbox logon returns the folder ids of
//! all thirteen special folders, so reaching the Inbox needs neither `RopGetReceiveFolder` nor any
//! `EntryID` parsing.
//!
//! [MS-OXCROPS] §2.2.3.1 — `RopLogon`
//! [MS-OXCSTOR] §2.2.1.1.1 — request buffer
//! [MS-OXCSTOR] §2.2.1.1.3 — success response buffer for a private mailbox

use crate::error::Result;
use crate::oxcdata::{FolderId, Guid, ReplicaId};
use crate::rop::RopId;
use crate::rop::batch::LOGON_ID;
use crate::wire::{Reader, Writer};

/// `LogonFlags`: log on to a private mailbox rather than to public folders.
///
/// [MS-OXCSTOR] §2.2.1.1.1 — `LogonFlags`
const LOGON_FLAG_PRIVATE: u8 = 0x01;

/// `OpenFlags`: `USE_PER_MDB_REPLID_MAPPING`, which is what Outlook sends for a private mailbox.
///
/// Note that `USE_ADMIN_PRIVILEGE` is bit 0 of this same field: setting it for an ordinary user
/// gets the logon refused with `LoginPermission`, which reads like an authentication failure.
///
/// [MS-OXCSTOR] §2.2.1.1.1 — `OpenFlags`
const OPEN_FLAG_USE_PER_MDB_REPLID_MAPPING: u32 = 0x0100_0000;

/// `StoreState`: unused, and the server ignores it. [MS-OXCSTOR] §2.2.1.1.1
const STORE_STATE: u32 = 0x0000_0000;

/// How many folder ids a private-mailbox logon returns.
const FOLDER_COUNT: usize = 13;

/// The special folders a private-mailbox logon reports, in the order the response carries them.
///
/// [MS-OXCSTOR] §2.2.1.1.3 — `FolderIds`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum WellKnownFolder {
    /// The mailbox root. Every other folder here is below it.
    MailboxRoot,
    /// Deferred Action.
    DeferredAction,
    /// Spooler Queue.
    SpoolerQueue,
    /// The interpersonal messages subtree — the root of the user-visible hierarchy.
    IpmSubtree,
    /// Inbox.
    Inbox,
    /// Outbox.
    Outbox,
    /// Sent Items.
    SentItems,
    /// Deleted Items.
    DeletedItems,
    /// Common Views.
    CommonViews,
    /// Schedule.
    Schedule,
    /// Search.
    Search,
    /// Views.
    Views,
    /// Shortcuts.
    Shortcuts,
}

impl WellKnownFolder {
    /// Every folder, in the order the logon response lists them.
    pub const ALL: [Self; FOLDER_COUNT] = [
        Self::MailboxRoot,
        Self::DeferredAction,
        Self::SpoolerQueue,
        Self::IpmSubtree,
        Self::Inbox,
        Self::Outbox,
        Self::SentItems,
        Self::DeletedItems,
        Self::CommonViews,
        Self::Schedule,
        Self::Search,
        Self::Views,
        Self::Shortcuts,
    ];

    /// This folder's position in the response.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::MailboxRoot => 0,
            Self::DeferredAction => 1,
            Self::SpoolerQueue => 2,
            Self::IpmSubtree => 3,
            Self::Inbox => 4,
            Self::Outbox => 5,
            Self::SentItems => 6,
            Self::DeletedItems => 7,
            Self::CommonViews => 8,
            Self::Schedule => 9,
            Self::Search => 10,
            Self::Views => 11,
            Self::Shortcuts => 12,
        }
    }

    /// The name the specification gives this folder.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MailboxRoot => "Mailbox Root",
            Self::DeferredAction => "Deferred Action",
            Self::SpoolerQueue => "Spooler Queue",
            Self::IpmSubtree => "IPM subtree",
            Self::Inbox => "Inbox",
            Self::Outbox => "Outbox",
            Self::SentItems => "Sent Items",
            Self::DeletedItems => "Deleted Items",
            Self::CommonViews => "Common Views",
            Self::Schedule => "Schedule",
            Self::Search => "Search",
            Self::Views => "Views",
            Self::Shortcuts => "Shortcuts",
        }
    }
}

impl core::fmt::Display for WellKnownFolder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// What a successful private-mailbox logon reports.
///
/// [MS-OXCSTOR] §2.2.1.1.3 — success response buffer for a private mailbox
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogonResponse {
    logon_flags: u8,
    folder_ids: Vec<FolderId>,
    mailbox_guid: Guid,
    replica_id: ReplicaId,
    replica_guid: Guid,
}

impl LogonResponse {
    /// The `LogonFlags` the server echoed back.
    #[must_use]
    pub const fn logon_flags(&self) -> u8 {
        self.logon_flags
    }

    /// All thirteen folder ids, in response order.
    #[must_use]
    pub fn folder_ids(&self) -> &[FolderId] {
        &self.folder_ids
    }

    /// One special folder's id.
    #[must_use]
    pub fn folder(&self, folder: WellKnownFolder) -> Option<FolderId> {
        self.folder_ids.get(folder.index()).copied()
    }

    /// The mailbox GUID.
    #[must_use]
    pub const fn mailbox_guid(&self) -> Guid {
        self.mailbox_guid
    }

    /// The replica id for this logon — the short form of [`LogonResponse::replica_guid`].
    #[must_use]
    pub const fn replica_id(&self) -> ReplicaId {
        self.replica_id
    }

    /// The GUID the replica id maps to.
    #[must_use]
    pub const fn replica_guid(&self) -> Guid {
        self.replica_guid
    }

    /// Reads the response body, after `RopId`, `OutputHandleIndex` and a zero `ReturnValue`.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let logon_flags = r.u8()?;
        let mut folder_ids = Vec::with_capacity(FOLDER_COUNT);
        for _ in 0..FOLDER_COUNT {
            folder_ids.push(FolderId::new(r.u64()?));
        }
        let _response_flags = r.u8()?;
        let mailbox_guid = Guid::from_bytes(r.array::<16>()?);
        let replica_id = ReplicaId::new(r.u16()?);
        let replica_guid = Guid::from_bytes(r.array::<16>()?);
        // LogonTime is Seconds, Minutes, Hour, DayOfWeek, Day, Month (one byte each) and Year
        // (two bytes) — eight bytes, not thirteen. Reading it as thirteen overruns by five and
        // turns a perfectly good response into a truncation error.
        // [MS-OXCROPS] §2.2.3.1.2.1 — LogonTime structure
        let _logon_time = r.bytes(8)?;
        let _gwart_time = r.bytes(8)?;
        let _store_state = r.u32()?;

        Ok(Self {
            logon_flags,
            folder_ids,
            mailbox_guid,
            replica_id,
            replica_guid,
        })
    }
}

/// Encodes a `RopLogon` request for a private mailbox.
///
/// [MS-OXCSTOR] §2.2.1.1.1 — request buffer
pub(crate) fn encode_logon(w: &mut Writer, output_index: u8, essdn: &str) {
    // EssdnSize counts the terminating NUL. Getting it wrong makes the server read past the name.
    let size = u16::try_from(essdn.len().saturating_add(1)).unwrap_or(u16::MAX);
    w.u8(RopId::LOGON.as_u8())
        .u8(LOGON_ID)
        .u8(output_index)
        .u8(LOGON_FLAG_PRIVATE)
        .u32(OPEN_FLAG_USE_PER_MDB_REPLID_MAPPING)
        .u32(STORE_STATE)
        .u16(size)
        .ascii_z(essdn);
}

#[cfg(test)]
mod tests;
