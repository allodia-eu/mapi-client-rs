//! IDSET: a set of folder ids, message ids or change numbers, grouped by the replica that issued
//! them.
//!
//! **There are two forms on the wire and nothing in the bytes says which one a buffer is in.**
//! [MS-OXCFXICS] §3.1.5.4.2: an IDSET that is "persisted across sessions, such as when it
//! represents a portion of an ICS state" names each replica by its 16-byte REPLGUID; one that is
//! "only a part of a transient set of data, like IDs of items that were deleted" names it by its
//! 2-byte REPLID. Read one as the other and every GLOBSET after the first is decoded from the
//! middle of a GUID. So the form is a type parameter, [`IdSet<Guid>`] and [`IdSet<ReplicaId>`], and
//! only the right one can be read from the property that carries it.
//!
//! [MS-OXCFXICS] §2.2.2.4 — IDSET and CNSET structures
//! [MS-OXCFXICS] §3.1.5.4 — serializing an IDSET

use crate::error::Result;
use crate::ics::globset::{GlobCnt, GlobSet, GlobSetRanges};
use crate::oxcdata::{Guid, MessageId, ReplicaId};
use crate::wire::{Reader, Writer};

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::oxcdata::ReplicaId {}
    impl Sealed for crate::oxcdata::Guid {}
}

/// How an IDSET names a replica: by its two-byte REPLID or its sixteen-byte REPLGUID.
///
/// Sealed: these are the two forms [MS-OXCFXICS] §3.1.5.4.2 defines, and there is no third.
pub trait ReplicaKey: sealed::Sealed + Copy + Ord + core::fmt::Debug {}

impl ReplicaKey for ReplicaId {}
impl ReplicaKey for Guid {}

/// How each key is carried on the wire — the half of [`ReplicaKey`] that only this crate needs.
pub(crate) trait WireKey: ReplicaKey {
    /// Reads the key as an IDSET carries it.
    fn read_key(r: &mut Reader<'_>) -> Result<Self>;
    /// Writes the key as an IDSET carries it.
    fn write_key(self, w: &mut Writer);
}

impl WireKey for ReplicaId {
    /// [MS-OXCFXICS] §2.2.2.4.1 — `REPLID (2 bytes)`
    fn read_key(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self::new(r.u16()?))
    }

    fn write_key(self, w: &mut Writer) {
        w.u16(self.as_u16());
    }
}

impl WireKey for Guid {
    /// [MS-OXCFXICS] §2.2.2.4.2 — `REPLGUID (16 bytes)`, ordered by byte-to-byte comparison
    fn read_key(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self::from_bytes(r.array::<16>()?))
    }

    fn write_key(self, w: &mut Writer) {
        w.bytes(self.as_bytes());
    }
}

/// A set of ids, one [`GlobSet`] per replica, in either of the two wire forms.
///
/// The key type is the form: [`IdSet<ReplicaId>`] for the transient sets a download reports —
/// deletions, read-state changes — and [`IdSet<Guid>`] for the four that make up an ICS state.
/// Replicas are kept in ascending order, which is the order both forms are serialized in, and a
/// replica is listed only while it holds a counter, so two sets holding the same ids compare equal
/// however they were built.
///
/// [MS-OXCFXICS] §2.2.2.4 — IDSET
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IdSet<K> {
    replicas: Vec<(K, GlobSet)>,
}

impl<K> Default for IdSet<K> {
    fn default() -> Self {
        Self {
            replicas: Vec::new(),
        }
    }
}

impl<K: ReplicaKey> IdSet<K> {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            replicas: Vec::new(),
        }
    }

    /// Whether no replica holds any id.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.replicas.iter().all(|(_, set)| set.is_empty())
    }

    /// The counters held for one replica, if any.
    #[must_use]
    pub fn get(&self, replica: K) -> Option<&GlobSet> {
        self.position(replica)
            .ok()
            .and_then(|index| self.replicas.get(index))
            .map(|(_, set)| set)
    }

    /// Whether the set holds `counter` for `replica`.
    #[must_use]
    pub fn contains(&self, replica: K, counter: GlobCnt) -> bool {
        self.get(replica).is_some_and(|set| set.contains(counter))
    }

    /// Adds one id. Returns whether it was new.
    pub fn insert(&mut self, replica: K, counter: GlobCnt) -> bool {
        self.entry(replica).is_some_and(|set| set.insert(counter))
    }

    /// Adds every id `other` holds.
    pub fn extend(&mut self, other: &Self) {
        for (replica, set) in other.replicas.iter().filter(|(_, set)| !set.is_empty()) {
            if let Some(entry) = self.entry(*replica) {
                entry.extend(set);
            }
        }
    }

    /// Each replica with the counters held for it, in ascending replica order.
    #[must_use]
    pub fn replicas(&self) -> IdSetReplicas<'_, K> {
        IdSetReplicas(self.replicas.iter())
    }

    fn position(&self, replica: K) -> core::result::Result<usize, usize> {
        self.replicas.binary_search_by(|(key, _)| key.cmp(&replica))
    }

    /// The set for `replica`, created empty where it was missing.
    ///
    /// Never `None` in practice — the entry has just been found or created — but returned as an
    /// option so that no path through a parser holds an index that could panic.
    fn entry(&mut self, replica: K) -> Option<&mut GlobSet> {
        let index = match self.position(replica) {
            Ok(index) => index,
            Err(index) => {
                self.replicas.insert(index, (replica, GlobSet::new()));
                index
            }
        };
        self.replicas.get_mut(index).map(|(_, set)| set)
    }
}

/// Decodes a whole serialized IDSET: replica, GLOBSET, replica, GLOBSET, to the last byte.
///
/// A replica named twice has its two GLOBSETs merged, rather than refused: the document requires
/// each to appear once, but the union is the only reading of two that loses nothing.
///
/// A free function rather than a method so that the wire half of the key, [`WireKey`], stays out
/// of the public API.
pub(crate) fn read<K: WireKey>(bytes: &[u8]) -> Result<IdSet<K>> {
    let mut r = Reader::new(bytes);
    let mut set = IdSet::new();
    while !r.is_empty() {
        let replica = K::read_key(&mut r)?;
        let counters = GlobSet::read(&mut r)?;
        if counters.is_empty() {
            continue;
        }
        if let Some(entry) = set.entry(replica) {
            entry.extend(&counters);
        }
    }
    Ok(set)
}

/// Encodes an IDSET. Replicas holding nothing are left out.
pub(crate) fn to_bytes<K: WireKey>(set: &IdSet<K>) -> Vec<u8> {
    let mut w = Writer::new();
    for (replica, counters) in &set.replicas {
        if !counters.is_empty() {
            replica.write_key(&mut w);
            counters.write(&mut w);
        }
    }
    w.finish()
}

impl IdSet<ReplicaId> {
    /// Whether the set holds this message id.
    #[must_use]
    pub fn contains_message(&self, id: MessageId) -> bool {
        let (replica, counter) = split(id.as_u64());
        self.contains(replica, counter)
    }

    /// Adds a message id. Returns whether it was new.
    pub fn insert_message(&mut self, id: MessageId) -> bool {
        let (replica, counter) = split(id.as_u64());
        self.insert(replica, counter)
    }

    /// Every message id the set holds, lowest replica first, without expanding a range until it is
    /// reached.
    ///
    /// A REPLID-based set from a download is what names the messages deleted or marked read since
    /// the last synchronization, and those are what an adapter acts on one at a time.
    #[must_use]
    pub fn message_ids(&self) -> MessageIds<'_> {
        MessageIds {
            replicas: self.replicas.iter(),
            ranges: None,
            pending: None,
        }
    }
}

/// Splits a folder id, message id or change number into the replica that issued it and its
/// counter.
///
/// The eight bytes are a little-endian REPLID followed by the GLOBCNT in wire order — §4.4 reads
/// `01 00 00 00 00 00 00 05` as REPLID 1 and GLOBCNT 5.
///
/// [MS-OXCDATA] §2.2.1.1 — Folder ID structure
/// [MS-OXCFXICS] §4.4 — the worked example
pub(crate) const fn split(raw: u64) -> (ReplicaId, GlobCnt) {
    let [r0, r1, b0, b1, b2, b3, b4, b5] = raw.to_le_bytes();
    (
        ReplicaId::new(u16::from_le_bytes([r0, r1])),
        GlobCnt::from_bytes([b0, b1, b2, b3, b4, b5]),
    )
}

/// The inverse of [`split`].
pub(crate) const fn join(replica: ReplicaId, counter: GlobCnt) -> u64 {
    let [r0, r1] = replica.as_u16().to_le_bytes();
    let [b0, b1, b2, b3, b4, b5] = counter.as_bytes();
    u64::from_le_bytes([r0, r1, b0, b1, b2, b3, b4, b5])
}

/// The replicas of an [`IdSet`] and the counters held for each, in ascending replica order.
#[derive(Clone, Debug)]
pub struct IdSetReplicas<'a, K>(core::slice::Iter<'a, (K, GlobSet)>);

impl<'a, K: Copy> Iterator for IdSetReplicas<'a, K> {
    type Item = (K, &'a GlobSet);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(key, set)| (*key, set))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

/// Every message id in an [`IdSet<ReplicaId>`], one range at a time.
#[derive(Clone, Debug)]
pub struct MessageIds<'a> {
    replicas: core::slice::Iter<'a, (ReplicaId, GlobSet)>,
    ranges: Option<(ReplicaId, GlobSetRanges<'a>)>,
    /// The next counter to hand out and the last one in its range.
    pending: Option<(u64, u64)>,
}

impl Iterator for MessageIds<'_> {
    type Item = MessageId;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let (Some((next, high)), Some((replica, _))) = (self.pending, &self.ranges) {
                self.pending = next
                    .checked_add(1)
                    .filter(|&n| n <= high)
                    .map(|n| (n, high));
                if let Some(counter) = GlobCnt::from_u64(next) {
                    return Some(MessageId::new(join(*replica, counter)));
                }
                continue;
            }
            if let Some((_, ranges)) = &mut self.ranges
                && let Some((low, high)) = ranges.next()
            {
                self.pending = Some((low.as_u64(), high.as_u64()));
                continue;
            }
            let (replica, set) = self.replicas.next()?;
            self.ranges = Some((*replica, set.ranges()));
        }
    }
}

#[cfg(test)]
mod tests;
