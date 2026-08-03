//! The two ROPs that map between a named property and the id one store uses for it.
//!
//! `RopGetPropertyIdsFromNames` is the one every calendar and half of every contact needs:
//! `PidLidAppointmentStartWhole` has no property id until a store allocates one, so a client that
//! wants to read it has to ask first. `RopGetNamesFromPropertyIds` is the inverse, and is what
//! turns a `0x8205` in a property dump back into something a person can act on.
//!
//! Both are positional in the same way a property fetch is: the response carries a bare array with
//! nothing in it saying which request entry each element answers. Unlike a property fetch, no
//! decoding depends on the request — the elements are fixed-width — so the pairing is left to the
//! caller that knows the order it asked in.
//!
//! Three things worth knowing before reading a response:
//!
//! * **An id of `0x0000` means the name could not be mapped**, and the ROP still succeeds.
//!   [MS-OXCPRPT] §2.2.12.2 lists five reasons, from "the name is not registered and the request
//!   did not ask for it to be" to a store that has used all 32,767 of its ids.
//! * **An id is a fact about one store.** [MS-OXCPRPT] §3.1.2 makes it valid on any object within
//!   the logon that answered and guarantees nothing outside it.
//! * **An id with no name is one byte.** See [`PropertyName::read`] — [MS-OXCDATA] §2.6.1's diagram
//!   says otherwise and Exchange does not, and the difference desynchronises the rest of the
//!   buffer.
//!
//! [MS-OXCROPS] §2.2.8.1 — `RopGetPropertyIdsFromNames`
//! [MS-OXCROPS] §2.2.8.2 — `RopGetNamesFromPropertyIds`
//! [MS-OXCPRPT] §2.2.12, §2.2.13 — semantics

use crate::error::Result;
use crate::oxcdata::PropertyName;
use crate::rop::RopId;
use crate::rop::batch::LOGON_ID;
use crate::wire::{Reader, Writer};

/// Whether the server may register a name it has not seen before.
///
/// The difference is not academic. A read-only client that asks for `PidLidLocation` against a
/// mailbox that has never held an appointment gets `0x0000` under [`Existing`] and a **newly
/// allocated id** under [`CreateIfMissing`] — which is a write to the store's mapping table, from
/// a call that reads like a lookup.
///
/// [MS-OXCPRPT] §2.2.12.1 — `Flags`
///
/// [`Existing`]: Self::Existing
/// [`CreateIfMissing`]: Self::CreateIfMissing
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameRegistration {
    /// `0x00` — resolve only what this store has already registered.
    #[default]
    Existing,
    /// `0x02` — allocate an id for any name not already in the store's mapping table.
    ///
    /// Needed to *write* a named property that nothing has written before, and the reason the
    /// operation can fail with `ecAccessDenied` for a user without permission to register one.
    CreateIfMissing,
}

impl NameRegistration {
    /// The `Flags` byte this is written as.
    const fn flags(self) -> u8 {
        match self {
            Self::Existing => 0x00,
            Self::CreateIfMissing => 0x02,
        }
    }
}

/// The ids `RopGetPropertyIdsFromNames` answered with, in the order the names were asked for.
///
/// [MS-OXCROPS] §2.2.8.1.2 — success response buffer
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PropertyIdsResponse {
    ids: Vec<u16>,
}

impl PropertyIdsResponse {
    /// The ids, positionally matched to the names in the request.
    ///
    /// [MS-OXCPRPT] §2.2.12.2 requires this to hold one entry per name asked for, in the same
    /// order, with `0x0000` for any that could not be mapped — so an id here is only meaningful
    /// alongside the list that produced it.
    #[must_use]
    pub fn ids(&self) -> &[u16] {
        &self.ids
    }

    /// Reads the response body, after `RopId`, `InputHandleIndex` and a zero `ReturnValue`.
    ///
    /// The count is a number from a server nobody here controls, so nothing is pre-allocated from
    /// it.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let count = usize::from(r.u16()?);
        let mut ids = Vec::new();
        for _ in 0..count {
            ids.push(r.u16()?);
        }
        Ok(Self { ids })
    }
}

/// The names `RopGetNamesFromPropertyIds` answered with, in the order the ids were asked for.
///
/// [MS-OXCROPS] §2.2.8.2.2 — success response buffer
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PropertyNamesResponse {
    names: Vec<Option<PropertyName>>,
}

impl PropertyNamesResponse {
    /// The names, positionally matched to the ids in the request.
    ///
    /// `None` is an id this store has no name for — a `Kind` of `0xFF`. It keeps its place rather
    /// than being left out, so the answer to the fourth id asked about is still the fourth entry.
    #[must_use]
    pub fn names(&self) -> &[Option<PropertyName>] {
        &self.names
    }

    /// Reads the response body, after `RopId`, `InputHandleIndex` and a zero `ReturnValue`.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let count = usize::from(r.u16()?);
        let mut names = Vec::new();
        for _ in 0..count {
            names.push(PropertyName::read(r)?);
        }
        Ok(Self { names })
    }
}

/// Encodes a `RopGetPropertyIdsFromNames` request.
///
/// [MS-OXCROPS] §2.2.8.1.1 — request buffer
pub(crate) fn encode_property_ids_from_names(
    w: &mut Writer,
    input: u8,
    names: &[PropertyName],
    registration: NameRegistration,
) {
    w.u8(RopId::GET_PROPERTY_IDS_FROM_NAMES.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(registration.flags())
        .u16(u16::try_from(names.len()).unwrap_or(u16::MAX));
    for name in names {
        name.write(w);
    }
}

/// Encodes a `RopGetNamesFromPropertyIds` request.
///
/// [MS-OXCROPS] §2.2.8.2.1 — request buffer
pub(crate) fn encode_names_from_property_ids(w: &mut Writer, input: u8, ids: &[u16]) {
    w.u8(RopId::GET_NAMES_FROM_PROPERTY_IDS.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u16(u16::try_from(ids.len()).unwrap_or(u16::MAX));
    for id in ids {
        w.u16(*id);
    }
}

#[cfg(test)]
mod tests;
