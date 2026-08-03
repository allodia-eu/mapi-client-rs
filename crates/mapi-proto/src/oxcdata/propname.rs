//! Naming a property the specification gives no fixed id, and what a store answers when asked.
//!
//! Every `PidTag` constant is a number the documents fixed once and for all. A `PidLid` is not: it
//! is a **property set** and either a number or a string inside that set, and the 16-bit id a
//! mailbox uses for it is allocated by that mailbox, from `0x8000` upwards, the first time it needs
//! one. Two mailboxes on the same server can and do use different ids for the same property.
//!
//! That is why a resolved id is [`NamedPropertyId`] and not a `u16`. The number on its own is
//! indistinguishable from the number another store uses for something else, and reading a property
//! with the wrong id does not fail — it answers a different property, or nothing, and says nothing
//! about which.
//!
//! [MS-OXCDATA] §2.6.1 — `PropertyName` structure
//! [MS-OXCPRPT] §3.1.4.1 — the client registers or obtains an id for a named property
//! [MS-OXCPRPT] §3.1.2 — an id may be cached for the session, and is not guaranteed to persist

use crate::error::{Error, Result};
use crate::oxcdata::{Guid, PropertySetId, PropertyTag, PropertyType};
use crate::wire::{Reader, Writer};

#[cfg(test)]
mod tests;

/// `Kind` `0x00` — the property is named by a LID.
const KIND_LID: u8 = 0x00;

/// `Kind` `0x01` — the property is named by a string.
const KIND_NAME: u8 = 0x01;

/// `Kind` `0xFF` — the property has no name.
const KIND_NONE: u8 = 0xFF;

/// The terminator counted by `NameSize`, in bytes.
const TERMINATOR_BYTES: usize = 2;

/// How a property is identified inside its property set.
///
/// [MS-OXCDATA] §2.6.1 — `Kind`
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PropertyNameKind {
    /// `0x00` — a long id, which is how every `PidLid` in [MS-OXPROPS] is written.
    Lid(u32),
    /// `0x01` — a string, which is how a client's own properties and the Internet message headers
    /// are named.
    Name(String),
}

impl PropertyNameKind {
    /// The `Kind` byte this is written as.
    const fn code(&self) -> u8 {
        match self {
            Self::Lid(_) => KIND_LID,
            Self::Name(_) => KIND_NAME,
        }
    }
}

/// A named property, as it is written on the wire and as it means the same thing everywhere.
///
/// This is the portable half of a named property: unlike the id a store answers with, a
/// `PropertyName` identifies the same property in every mailbox, which is why the client's cache is
/// keyed on one of these rather than on a number.
///
/// [MS-OXCDATA] §2.6.1 — `PropertyName` structure
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PropertyName {
    set: PropertySetId,
    kind: PropertyNameKind,
}

impl PropertyName {
    /// Names a property by its LID — the form every `PidLid` in [MS-OXPROPS] is written in.
    ///
    /// ```
    /// use mapi_proto::{PropertyName, PropertySetId};
    ///
    /// // PidLidLocation, [MS-OXOCAL] §2.2.1.4
    /// let location = PropertyName::lid(PropertySetId::APPOINTMENT, 0x0000_8208);
    /// assert_eq!(location.as_lid(), Some(0x0000_8208));
    /// ```
    #[must_use]
    pub const fn lid(set: PropertySetId, lid: u32) -> Self {
        Self {
            set,
            kind: PropertyNameKind::Lid(lid),
        }
    }

    /// Names a property by a string inside its set.
    ///
    /// # Errors
    ///
    /// [`Error::UnencodableValue`] if the name holds an interior NUL, which would end the field
    /// early and shift every byte after it, or if its UTF-16 encoding plus the two-byte terminator
    /// does not fit the one-byte `NameSize` field. Both are refused here rather than truncated,
    /// because a truncated name resolves to a *different* property without saying so.
    pub fn named(set: PropertySetId, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let encoded = name
            .encode_utf16()
            .count()
            .saturating_mul(2)
            .saturating_add(TERMINATOR_BYTES);

        let reason = if name.contains('\0') {
            Some("a property name cannot contain an interior NUL")
        } else if encoded > usize::from(u8::MAX) {
            Some("NameSize is one byte, and counts the two-byte terminator")
        } else {
            None
        };

        match reason {
            Some(reason) => Err(Error::UnencodableValue {
                value: "a property name",
                reason,
            }),
            None => Ok(Self {
                set,
                kind: PropertyNameKind::Name(name),
            }),
        }
    }

    /// The set this property is named inside.
    #[must_use]
    pub const fn set(&self) -> PropertySetId {
        self.set
    }

    /// How it is identified inside that set.
    #[must_use]
    pub const fn kind(&self) -> &PropertyNameKind {
        &self.kind
    }

    /// Its LID, if it is named by one.
    #[must_use]
    pub const fn as_lid(&self) -> Option<u32> {
        match self.kind {
            PropertyNameKind::Lid(lid) => Some(lid),
            PropertyNameKind::Name(_) => None,
        }
    }

    /// Its string name, if it is named by one.
    #[must_use]
    pub fn as_name(&self) -> Option<&str> {
        match &self.kind {
            PropertyNameKind::Name(name) => Some(name),
            PropertyNameKind::Lid(_) => None,
        }
    }

    /// Writes the structure: `Kind`, `GUID`, and then whichever of `LID` or `NameSize`/`Name` the
    /// kind calls for.
    ///
    /// `NameSize` **counts the two-byte terminator**. [MS-OXCPRPT] §4.1.1 puts `0x14` against the
    /// nine-character name `TestProp1`, which is eighteen bytes of UTF-16 and two of terminator —
    /// so a client that wrote eighteen would shift every field after it and the server would read
    /// the next `PropertyName`'s `Kind` as part of this one's name.
    ///
    /// [MS-OXCDATA] §2.6.1 — field layout
    pub(crate) fn write(&self, w: &mut Writer) {
        w.u8(self.kind.code()).bytes(self.set.as_guid().as_bytes());
        match &self.kind {
            PropertyNameKind::Lid(lid) => {
                w.u32(*lid);
            }
            PropertyNameKind::Name(name) => {
                let size = name
                    .encode_utf16()
                    .count()
                    .saturating_mul(2)
                    .saturating_add(TERMINATOR_BYTES);
                // Constructed only through `named` — by callers and by `read` alike — and that
                // refuses anything that would not fit the one-byte field.
                w.u8(u8::try_from(size).unwrap_or(u8::MAX)).utf16_z(name);
            }
        }
    }

    /// Reads one structure, as `RopGetNamesFromPropertyIds` answers with, or `None` for an id the
    /// store has no name for.
    ///
    /// **`Kind` `0xFF` is one byte and nothing else.** [MS-OXCDATA] §2.6.1's packet diagram marks
    /// `LID`, `NameSize` and `Name` optional and `GUID` not — so read literally, a `0xFF` entry
    /// would still carry sixteen bytes of property set. Exchange Server SE `15.02.2562.045` sends
    /// no such bytes: asked for the name of the unregistered id `0xFFFE`, it answered a 30-byte ROP
    /// whose `RopSize` ends on the `0xFF` itself. Reading the specification's sixteen bytes there
    /// consumes the next structure, or the handle table, or runs off the buffer — which is how this
    /// was found. The server's reading is the coherent one: `0xFF` means *there is no
    /// `PropertyName`*, and a property set is part of a name.
    ///
    /// The name itself is taken from exactly `NameSize` bytes rather than by scanning for a
    /// terminator, so a size that disagrees with its own contents costs this one name and not the
    /// alignment of every structure after it.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Option<Self>> {
        let at = r.position();
        let kind = r.u8()?;
        if kind == KIND_NONE {
            return Ok(None);
        }

        let set = PropertySetId::from_guid(Guid::from_bytes(r.array::<16>()?));
        let kind = match kind {
            KIND_LID => PropertyNameKind::Lid(r.u32()?),
            KIND_NAME => {
                let name_at = r.position();
                let size = usize::from(r.u8()?);
                let name = utf16_within(r.bytes(size)?, name_at)?;
                // Built through `named` rather than by hand, so what `write` relies on — that a
                // name always fits its own one-byte `NameSize` — holds for one that came off the
                // wire too. A server sending 254 bytes with no terminator would otherwise yield a
                // 127-unit name that re-encodes as a clamped `NameSize` of 255 followed by 256
                // bytes, and every structure after it in the request would be read as part of it.
                return Self::named(set, name).map(Some);
            }
            other => return Err(Error::InvalidPropertyNameKind { kind: other, at }),
        };

        Ok(Some(Self { set, kind }))
    }
}

impl core::fmt::Display for PropertyName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.kind {
            PropertyNameKind::Lid(lid) => write!(f, "{}/0x{lid:08X}", self.set),
            PropertyNameKind::Name(name) => write!(f, "{}/{name}", self.set),
        }
    }
}

/// Decodes a UTF-16LE string held in a fixed run of bytes, stopping at the terminator.
fn utf16_within(raw: &[u8], at: usize) -> Result<String> {
    // An odd NameSize cannot be a UTF-16 string, and `chunks_exact` would drop the last byte
    // rather than say so.
    if !raw.len().is_multiple_of(2) {
        return Err(Error::InvalidUtf16 { at });
    }

    let mut units = Vec::new();
    for pair in raw.chunks_exact(2) {
        let bytes = <[u8; 2]>::try_from(pair).map_err(|_| Error::InvalidUtf16 { at })?;
        let unit = u16::from_le_bytes(bytes);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }

    String::from_utf16(&units).map_err(|_| Error::InvalidUtf16 { at })
}

/// A property id one store allocated for one named property.
///
/// Carries the mailbox that issued it, because the number alone is not enough to use safely.
/// [MS-OXCPRPT] §3.1.2 makes the id valid on any object *within that logon* and guarantees nothing
/// beyond it; ids are allocated per store as each first needs a property, so the same number names
/// a different property in the mailbox next door. Reading with the wrong one is not an error — it
/// is a wrong answer that looks like a right one, which is what [`belongs_to`](Self::belongs_to)
/// is for.
///
/// [MS-OXCDATA] §2.4.2 — `ecUnexpectedId`, the code for an id used against the wrong store
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamedPropertyId {
    store: Guid,
    id: u16,
}

impl NamedPropertyId {
    /// Records an id a store answered with, together with which store answered.
    ///
    /// The mailbox GUID comes from the `RopLogon` response that opened the store. Passing a
    /// different one produces an id that will pass a check it should have failed.
    #[must_use]
    pub const fn new(store: Guid, id: u16) -> Self {
        Self { store, id }
    }

    /// The id, which is the half that goes on the wire.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.id
    }

    /// The mailbox that allocated it.
    #[must_use]
    pub const fn store(self) -> Guid {
        self.store
    }

    /// Whether this id was allocated by the mailbox named here.
    ///
    /// The check to make before using one on a different logon than the one that resolved it.
    #[must_use]
    pub fn belongs_to(self, mailbox_guid: Guid) -> bool {
        self.store == mailbox_guid
    }

    /// The tag that reads or writes this property, given the type its value is carried in.
    ///
    /// The type is a separate argument because a named property's id says nothing about it:
    /// [MS-OXPROPS] gives each `PidLid` a documented data type, and it is the caller's — usually
    /// [`NamedProperty`](crate::NamedProperty)'s — to supply.
    #[must_use]
    pub const fn tag(self, property_type: PropertyType) -> PropertyTag {
        PropertyTag::from_parts(self.id, property_type)
    }
}

impl core::fmt::Display for NamedPropertyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{:04X}", self.id)
    }
}
