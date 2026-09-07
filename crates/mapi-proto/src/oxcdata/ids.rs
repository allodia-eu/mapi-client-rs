//! The identities a caller passes around: folders, messages, mailboxes, users, time.
//!
//! Each is a newtype rather than a bare integer or `String`, so a message id cannot be handed to
//! something expecting a folder id. Both are 64-bit and structurally identical on the wire, which
//! is exactly why the compiler should be the one keeping them apart.

use crate::error::{Error, Result};

/// A folder identifier — a 2-byte replica id followed by a 6-byte counter.
///
/// [MS-OXCDATA] §2.2.1.1 — Folder ID structure
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FolderId(u64);

/// A message identifier — the same shape as a [`FolderId`], scoped to a message.
///
/// [MS-OXCDATA] §2.2.1.2 — Message ID structure
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(u64);

/// Identifies one attachment within its message — the value of `PidTagAttachNumber`.
///
/// A newtype rather than a `u32` for the usual reason and one of its own: this is *not* a MAPI
/// identifier in the [`MessageId`] sense. It is an index the server assigns within a single
/// message, so the same number means a different attachment on every message, and it is only valid
/// against the message whose attachment table reported it.
///
/// [MS-OXCMSG] §2.2.2.6 — `PidTagAttachNumber`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttachmentNumber(u32);

impl AttachmentNumber {
    /// Wraps the number an attachment table row reported.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The number as `RopOpenAttachment`'s `AttachmentID` field carries it.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl core::fmt::Display for AttachmentNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identifies a Store object; the short form of a replica GUID.
///
/// [MS-OXCDATA] §2.2.1.1 — `ReplicaId`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReplicaId(u16);

macro_rules! object_id {
    ($name:ident, $doc:literal) => {
        impl $name {
            #[doc = concat!("Wraps a raw ", $doc, " as it appears on the wire.")]
            #[must_use]
            pub const fn new(raw: u64) -> Self {
                Self(raw)
            }

            /// The identifier as the little-endian `u64` the wire carries.
            #[must_use]
            pub const fn as_u64(self) -> u64 {
                self.0
            }

            /// The replica id: the first two bytes, identifying the Store object.
            #[must_use]
            pub const fn replica_id(self) -> ReplicaId {
                let [low, high, ..] = self.0.to_le_bytes();
                ReplicaId(u16::from_le_bytes([low, high]))
            }

            /// The global counter: the remaining six bytes, little-endian per [MS-OXCDATA] §2.
            #[must_use]
            pub const fn global_counter(self) -> u64 {
                let [_, _, a, b, c, d, e, f] = self.0.to_le_bytes();
                u64::from_le_bytes([a, b, c, d, e, f, 0, 0])
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "0x{:016X}", self.0)
            }
        }
    };
}

object_id!(FolderId, "folder id");
object_id!(MessageId, "message id");

impl ReplicaId {
    /// Wraps a raw replica id.
    #[must_use]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// The replica id as the wire carries it.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl core::fmt::Display for ReplicaId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A 16-byte GUID exactly as the wire carries it.
///
/// [MS-OXCROPS] §2.2.3.1.2 — `MailboxGuid`, `ReplGuid`
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Guid([u8; 16]);

impl Guid {
    /// Wraps 16 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The bytes in wire order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Display for Guid {
    /// Renders the conventional `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` form, in which the first
    /// three groups are little-endian and the last two are byte order as stored.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let part = |range: core::ops::Range<usize>| self.0.get(range).unwrap_or_default();
        write!(f, "{{")?;
        for range in [0..4, 4..6, 6..8] {
            for byte in part(range).iter().rev() {
                write!(f, "{byte:02x}")?;
            }
            write!(f, "-")?;
        }
        for byte in part(8..10) {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "-")?;
        for byte in part(10..16) {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "}}")
    }
}

impl core::fmt::Debug for Guid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Guid({self})")
    }
}

/// A point in time as MAPI stores it: 100-nanosecond intervals since 1601-01-01 UTC.
///
/// [MS-OXCDATA] §2.11.1 — `PtypTime`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileTime(u64);

/// Seconds between the FILETIME epoch (1601-01-01) and the Unix epoch (1970-01-01).
const FILETIME_TO_UNIX_SECONDS: i64 = 11_644_473_600;

/// 100-nanosecond intervals in one second.
const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;

/// 100-nanosecond intervals in one minute, which [MS-OXOFLAG] §2.2.1.3 writes out as 600,000,000.
const FILETIME_TICKS_PER_MINUTE: u64 = 600_000_000;

impl FileTime {
    /// Wraps a raw tick count.
    #[must_use]
    pub const fn new(ticks: u64) -> Self {
        Self(ticks)
    }

    /// The tick count as the wire carries it.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// The same instant, from Unix seconds.
    ///
    /// The bridge every date library in the ecosystem can reach: nothing here parses a calendar
    /// date, and a `PtypTime` cannot be written without one. `None` for an instant before
    /// 1601-01-01, which a `FILETIME` cannot express at all.
    ///
    /// ```
    /// use mapi_proto::FileTime;
    ///
    /// let epoch = FileTime::from_unix_seconds(0).expect("the Unix epoch is after 1601");
    /// assert_eq!(epoch.to_unix_seconds(), Some(0));
    /// assert_eq!(FileTime::from_unix_seconds(i64::MIN), None);
    /// ```
    #[must_use]
    pub fn from_unix_seconds(seconds: i64) -> Option<Self> {
        let ticks = seconds
            .checked_add(FILETIME_TO_UNIX_SECONDS)?
            .checked_mul(i64::try_from(FILETIME_TICKS_PER_SECOND).ok()?)?;
        u64::try_from(ticks).ok().map(Self)
    }

    /// The same instant in Unix seconds, or `None` if it does not fit an `i64`.
    #[must_use]
    pub fn to_unix_seconds(self) -> Option<i64> {
        i64::try_from(self.0 / FILETIME_TICKS_PER_SECOND)
            .ok()?
            .checked_sub(FILETIME_TO_UNIX_SECONDS)
    }

    /// The same instant with its seconds discarded, rounded down to the minute.
    ///
    /// One property in this crate requires it. [MS-OXOFLAG] §2.2.1.3: `PidTagFlagCompleteTime`'s
    /// "smallest resolution MUST be minutes, and the value MUST be a multiple of 600,000,000".
    /// Offered rather than applied silently, because which properties carry that constraint is the
    /// caller's question and truncating a time it did not ask to truncate would be worse.
    ///
    /// ```
    /// use mapi_proto::FileTime;
    ///
    /// let at = FileTime::from_unix_seconds(1_789_030_845).expect("after 1601");
    /// let minute = at.to_whole_minutes();
    /// assert_eq!(minute.to_unix_seconds(), Some(1_789_030_800));
    /// // Already a multiple of 600,000,000, so truncating again changes nothing.
    /// assert_eq!(minute.to_whole_minutes(), minute);
    /// ```
    #[must_use]
    pub const fn to_whole_minutes(self) -> Self {
        // The divisor is a non-zero constant, so `checked_div` cannot answer `None`. Written this
        // way because the workspace forbids the bare operators, and `match` because `unwrap_or` is
        // not `const` on the pinned toolchain.
        match self.0.checked_div(FILETIME_TICKS_PER_MINUTE) {
            Some(minutes) => Self(minutes.saturating_mul(FILETIME_TICKS_PER_MINUTE)),
            None => self,
        }
    }
}

/// A `legacyExchangeDN` — the distinguished name Exchange knows a mailbox by.
///
/// Comes from Autodiscover's `<User><LegacyDN>` and is passed through verbatim. Constructing one
/// by hand is how `Connect` ends up refused with [`ErrorCode::UNKNOWN_USER`], which reads like an
/// authentication failure and is not one.
///
/// [MS-OXCMAPIHTTP] §2.2.4.1.1 — `UserDn`
///
/// [`ErrorCode::UNKNOWN_USER`]: crate::ErrorCode::UNKNOWN_USER
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LegacyDn(String);

impl LegacyDn {
    /// Validates and wraps a distinguished name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLegacyDn`] if the name is empty, holds an interior NUL — which
    /// would silently truncate the request field and shift every field after it — or holds a
    /// non-ASCII character, which the 8-bit `UserDn` field cannot carry unambiguously.
    pub fn new(dn: impl Into<String>) -> Result<Self> {
        let dn = dn.into();
        let reason = if dn.is_empty() {
            Some("a distinguished name cannot be empty")
        } else if dn.contains('\0') {
            Some("a distinguished name cannot contain an interior NUL")
        } else if !dn.is_ascii() {
            Some("the UserDn field is 8-bit, so a distinguished name must be ASCII")
        } else {
            None
        };

        match reason {
            Some(reason) => Err(Error::InvalidLegacyDn { reason }),
            None => Ok(Self(dn)),
        }
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::str::FromStr for LegacyDn {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl core::fmt::Display for LegacyDn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_id_splits_into_replica_and_counter() {
        // Wire order is ReplicaId then GlobalCounter, so a little-endian u64 puts the replica id
        // in the low 16 bits.
        let id = FolderId::new(0x0000_0000_0000_1001);
        assert_eq!(id.replica_id(), ReplicaId::new(0x1001));
        assert_eq!(id.global_counter(), 0);
        assert_eq!(id.as_u64(), 0x1001);
        assert_eq!(id.to_string(), "0x0000000000001001");
        assert_eq!(id.replica_id().as_u16(), 0x1001);
        assert_eq!(id.replica_id().to_string(), "4097");
    }

    #[test]
    fn folder_and_message_ids_do_not_mix() {
        let folder = FolderId::new(7);
        let message = MessageId::new(7);
        assert_eq!(folder.as_u64(), message.as_u64());
        // The point of the newtypes: same bits, different types, no accidental crossing.
        assert_eq!(message.replica_id(), ReplicaId::new(7));
    }

    #[test]
    fn a_guid_renders_in_the_conventional_mixed_endian_form() {
        let guid = Guid::from_bytes([
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
            0x9A, 0xBC,
        ]);
        assert_eq!(guid.to_string(), "{12345678-1234-1234-1234-123456789abc}");
        assert_eq!(
            format!("{guid:?}"),
            "Guid({12345678-1234-1234-1234-123456789abc})"
        );
        assert_eq!(guid.as_bytes().len(), 16);
    }

    /// The value observed from the live Exchange lab, which is what tied the decode to a real
    /// wall-clock time rather than to a plausible-looking integer.
    #[test]
    fn a_filetime_converts_to_unix_seconds() {
        let observed = FileTime::new(134_300_850_968_907_102);
        assert_eq!(observed.to_unix_seconds(), Some(1_785_611_496)); // 2026-08-01T19:11:36Z
        assert_eq!(observed.as_u64(), 134_300_850_968_907_102);
        assert_eq!(FileTime::new(0).to_unix_seconds(), Some(-11_644_473_600));
    }

    #[test]
    fn a_filetime_past_the_end_of_time_does_not_wrap() {
        assert_eq!(
            FileTime::new(u64::MAX).to_unix_seconds(),
            Some(1_833_029_933_770)
        );
    }

    #[test]
    fn a_legacy_dn_rejects_what_would_corrupt_the_request() {
        assert!(LegacyDn::new("/o=First/cn=Recipients/cn=alice").is_ok());
        assert!(LegacyDn::new("").is_err());
        assert!(LegacyDn::new("/o=First\0/cn=x").is_err());
        assert!(LegacyDn::new("/o=Fïrst").is_err());
    }

    #[test]
    fn a_legacy_dn_round_trips_through_its_string_form() {
        let dn: LegacyDn = "/o=First/cn=Recipients/cn=alice".parse().unwrap();
        assert_eq!(dn.as_str(), "/o=First/cn=Recipients/cn=alice");
        assert_eq!(dn.to_string(), dn.as_str());
        assert!("".parse::<LegacyDn>().is_err());
    }
}
