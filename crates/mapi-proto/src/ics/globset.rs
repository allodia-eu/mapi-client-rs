//! GLOBSET: a set of 48-bit counters held as ranges, and the stack machine the wire encodes it
//! with.
//!
//! An ICS state is four of these per replica, and a checkpointing client adds to them once per
//! message, so two properties matter more than they look: **insertion is cheap** — a binary search
//! and at most one merge, not a re-sort — and **the encoding is compact**, because an
//! `MetaTagIdsetGiven` holding one singleton per message would otherwise cost seven bytes a message
//! and travel with every sync.
//!
//! **A counter is six bytes, most significant first.** The documents never name the byte order of
//! a GLOBCNT in prose, but their worked example does: [MS-OXCFXICS] §4.4 reads the Message ID
//! `01 00 00 00 00 00 00 05` as REPLID `0001` and GLOBCNT `000000000005`, and its encoding pushes
//! the five leading zero bytes as the "high-order bytes" the counters share. Ordering here is
//! therefore the ordering of the bytes as the wire carries them, which is what makes a Push of the
//! leading bytes a statement about the counters' *high* bits. Note that this is not how
//! [`FolderId::global_counter`](crate::FolderId::global_counter) reads the same six bytes.
//!
//! [MS-OXCFXICS] §2.2.2.5 — GLOBCNT
//! [MS-OXCFXICS] §2.2.2.6 — GLOBSET, and its five commands
//! [MS-OXCFXICS] §3.1.5.4.3 — encoding and decoding

use crate::error::{Error, Result};
use crate::wire::{Reader, Writer};

/// The number of bytes in a counter.
const WIDTH: usize = 6;

/// The command that ends a GLOBSET. [MS-OXCFXICS] §2.2.2.6.5
const END: u8 = 0x00;
/// The command that drops the bytes of the last Push. [MS-OXCFXICS] §2.2.2.6.2
const POP: u8 = 0x50;
/// The command that encodes up to five ranges in two bytes. [MS-OXCFXICS] §2.2.2.6.3
const BITMASK: u8 = 0x42;
/// The command that encodes one range. [MS-OXCFXICS] §2.2.2.6.4
const RANGE: u8 = 0x52;

/// One 48-bit global counter: the part of a folder id, message id or change number that is not the
/// replica.
///
/// Ordered as the wire carries it, most significant byte first: [MS-OXCFXICS] §4.4 reads the
/// Message ID `01 00 00 00 00 00 00 05` as REPLID `0001` and GLOBCNT `000000000005`, and pushes the
/// leading zeroes as the counters' shared high-order bytes.
///
/// [MS-OXCFXICS] §2.2.2.5 — GLOBCNT
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GlobCnt([u8; WIDTH]);

impl GlobCnt {
    /// The largest counter, `0xFFFF_FFFF_FFFF`.
    pub const MAX: Self = Self([0xFF; WIDTH]);

    /// Wraps the six bytes exactly as the wire carries them.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; WIDTH]) -> Self {
        Self(bytes)
    }

    /// The six bytes, in wire order.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; WIDTH] {
        self.0
    }

    /// The counter as a number, reading its bytes most significant first.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        let [b0, b1, b2, b3, b4, b5] = self.0;
        u64::from_be_bytes([0, 0, b0, b1, b2, b3, b4, b5])
    }

    /// The counter with this value, or `None` past 48 bits.
    #[must_use]
    pub const fn from_u64(value: u64) -> Option<Self> {
        let [high, top, b0, b1, b2, b3, b4, b5] = value.to_be_bytes();
        if high != 0 || top != 0 {
            return None;
        }
        Some(Self([b0, b1, b2, b3, b4, b5]))
    }

    /// The next counter, or `None` after [`MAX`](Self::MAX).
    fn successor(self) -> Option<Self> {
        self.as_u64().checked_add(1).and_then(Self::from_u64)
    }

    /// Whether `next` follows this counter with no gap, which is when two ranges merge.
    fn is_followed_by(self, next: Self) -> bool {
        self.successor() == Some(next)
    }
}

impl core::fmt::Display for GlobCnt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:012X}", self.as_u64())
    }
}

/// A set of global counters, held as sorted, disjoint, non-adjacent inclusive ranges.
///
/// That shape is the "formatted" form [MS-OXCFXICS] §3.1.5.4.1 requires before encoding — ranges
/// "arranged from lowest to highest" with duplicates removed and consecutive values grouped — and
/// keeping it as an invariant rather than producing it on demand is what makes equality a question
/// of content: two sets holding the same counters compare equal however they were built.
///
/// [MS-OXCFXICS] §2.2.2.6 — GLOBSET
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct GlobSet {
    ranges: Vec<(GlobCnt, GlobCnt)>,
}

impl GlobSet {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Whether the set holds no counter at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Whether `value` is in the set.
    #[must_use]
    pub fn contains(&self, value: GlobCnt) -> bool {
        let after = self.ranges.partition_point(|&(low, _)| low <= value);
        after
            .checked_sub(1)
            .and_then(|index| self.ranges.get(index))
            .is_some_and(|&(_, high)| value <= high)
    }

    /// Adds one counter, merging it into the ranges on either side where it touches them.
    ///
    /// Returns whether it was new. One binary search and at most one merge: this is the operation
    /// client-side checkpointing performs once per message, so it is not allowed to re-sort.
    pub fn insert(&mut self, value: GlobCnt) -> bool {
        let after = self.ranges.partition_point(|&(low, _)| low <= value);
        let before = after.checked_sub(1);

        if let Some(&(_, high)) = before.and_then(|index| self.ranges.get(index))
            && value <= high
        {
            return false;
        }

        let joins_before = before
            .and_then(|index| self.ranges.get(index))
            .is_some_and(|&(_, high)| high.is_followed_by(value));
        let joins_after = self
            .ranges
            .get(after)
            .is_some_and(|&(low, _)| value.is_followed_by(low));

        match (before, joins_before, joins_after) {
            (Some(index), true, true) => {
                let next_high = self.ranges.get(after).map(|&(_, high)| high);
                if let (Some(range), Some(next_high)) = (self.ranges.get_mut(index), next_high) {
                    range.1 = next_high;
                }
                self.ranges.remove(after);
            }
            (Some(index), true, false) => {
                if let Some(range) = self.ranges.get_mut(index) {
                    range.1 = value;
                }
            }
            (_, _, true) => {
                if let Some(range) = self.ranges.get_mut(after) {
                    range.0 = value;
                }
            }
            _ => self.ranges.insert(after, (value, value)),
        }
        true
    }

    /// Adds every counter from `low` to `high` inclusive. Nothing happens if `low > high`.
    pub fn insert_range(&mut self, low: GlobCnt, high: GlobCnt) {
        if low <= high {
            self.ranges.push((low, high));
            self.normalise();
        }
    }

    /// Adds every counter `other` holds.
    pub fn extend(&mut self, other: &Self) {
        self.ranges.extend_from_slice(&other.ranges);
        self.normalise();
    }

    /// The ranges, lowest first, each inclusive at both ends.
    #[must_use]
    pub fn ranges(&self) -> GlobSetRanges<'_> {
        GlobSetRanges(self.ranges.iter())
    }

    /// Restores the invariant after ranges were appended in any order: sorted, then merged wherever
    /// two overlap or touch.
    fn normalise(&mut self) {
        self.ranges.sort_unstable();
        let mut merged: Vec<(GlobCnt, GlobCnt)> = Vec::with_capacity(self.ranges.len());
        for &(low, high) in &self.ranges {
            match merged.last_mut() {
                Some(last) if low <= last.1 || last.1.is_followed_by(low) => {
                    last.1 = last.1.max(high);
                }
                _ => merged.push((low, high)),
            }
        }
        self.ranges = merged;
    }

    /// Decodes one serialized GLOBSET, consuming exactly its bytes, End command included.
    ///
    /// The decoder is stricter than the encoder needs to be, because these bytes come from a server
    /// nobody here controls and an ICS state built from a misread one silently skips mail: a Push
    /// past six bytes, a Pop with nothing pushed, a Bitmask without exactly five bytes on the
    /// stack, a Range whose low end is above its high end, an End with bytes still pushed and any
    /// unknown command are all refused.
    ///
    /// **A one-byte Push is accepted.** §2.2.2.6.1 allows `0x01`–`0x06`; §3.1.5.4.3.2.1 says a Push
    /// adds "2 to 6 bytes". The structure section is the one that defines the opcode, and the
    /// opcode *is* the byte count.
    ///
    /// [MS-OXCFXICS] §3.1.5.4.3.2 — decoding
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let mut stack: Vec<u8> = Vec::with_capacity(WIDTH);
        let mut pushes: Vec<usize> = Vec::new();
        let mut ranges = Vec::new();

        loop {
            let at = r.position();
            let refuse = |reason| Error::InvalidGlobset { at, reason };
            match r.u8()? {
                END if stack.is_empty() => break,
                END => return Err(refuse("End with bytes still on the common byte stack")),
                count @ 0x01..=0x06 => {
                    let count = usize::from(count);
                    let total = stack.len().saturating_add(count);
                    if total > WIDTH {
                        return Err(refuse("a Push past the six bytes of a counter"));
                    }
                    stack.extend_from_slice(r.bytes(count)?);
                    if total == WIDTH {
                        // A full stack is a singleton, and its last Push unwinds by itself.
                        let value = counter(&stack, &[]);
                        ranges.push((value, value));
                        stack.truncate(total.saturating_sub(count));
                    } else {
                        pushes.push(count);
                    }
                }
                POP => {
                    let count = pushes.pop().ok_or(refuse("a Pop with nothing pushed"))?;
                    stack.truncate(stack.len().saturating_sub(count));
                }
                BITMASK => {
                    if stack.len() != WIDTH.saturating_sub(1) {
                        return Err(refuse("a Bitmask without five bytes on the stack"));
                    }
                    let start = r.u8()?;
                    let mask = r.u8()?;
                    read_bitmask(&stack, start, mask, &mut ranges)
                        .ok_or(refuse("a Bitmask running past the counter's low byte"))?;
                }
                RANGE => {
                    let tail = WIDTH.saturating_sub(stack.len());
                    let low = counter(&stack, r.bytes(tail)?);
                    let high = counter(&stack, r.bytes(tail)?);
                    if low > high {
                        return Err(refuse("a Range whose low value is above its high value"));
                    }
                    ranges.push((low, high));
                }
                _ => return Err(refuse("an unknown command")),
            }
        }

        let mut set = Self { ranges };
        set.normalise();
        Ok(set)
    }

    /// Encodes the set, End command included.
    ///
    /// Any encoding that decodes to the same counters is correct — "the choice of command used is
    /// an implementation decision" ([MS-OXCFXICS] §3.1.5.4.3.1) — so this one aims at size, since a
    /// checkpointed `MetaTagIdsetGiven` is mostly isolated counters sharing five high bytes:
    ///
    /// * runs of up to five ranges within eight values of each other share one Bitmask;
    /// * an isolated counter is a Push that completes the stack, which unwinds by itself;
    /// * anything else is a Range, after pushing the high bytes its two ends share.
    ///
    /// Leading bytes are pushed once and kept for as long as the next range still begins with them,
    /// which is what the common byte stack is for.
    ///
    /// [MS-OXCFXICS] §3.1.5.4.3.1 — encoding
    pub(crate) fn write(&self, w: &mut Writer) {
        let mut stack = Stack::default();
        let mut index = 0;

        while let Some(&(low, high)) = self.ranges.get(index) {
            let bitmask = self.bitmask_run(index);
            if bitmask >= 2 {
                stack.align(w, low.0.get(..WIDTH.saturating_sub(1)).unwrap_or_default());
                write_bitmask(w, self.ranges.get(index..index.saturating_add(bitmask)));
                index = index.saturating_add(bitmask);
                continue;
            }

            if low == high {
                stack.keep_prefix_of(w, &low.0);
                let rest = low.0.get(stack.len()..).unwrap_or_default();
                if let Ok(count) = u8::try_from(rest.len()) {
                    w.u8(count).bytes(rest);
                }
            } else {
                let shared = shared_prefix(low.0, high.0).min(WIDTH.saturating_sub(1));
                stack.align(w, low.0.get(..shared).unwrap_or_default());
                let tail = stack.len();
                w.u8(RANGE)
                    .bytes(low.0.get(tail..).unwrap_or_default())
                    .bytes(high.0.get(tail..).unwrap_or_default());
            }
            index = index.saturating_add(1);
        }

        stack.clear(w);
        w.u8(END);
    }

    /// How many ranges from `index` on one Bitmask can carry: those whose two ends share the first
    /// range's five high bytes and whose low byte is within eight of its start, up to five.
    ///
    /// [MS-OXCFXICS] §2.2.2.6.3 — "up to five GLOBCNT ranges" within "eight values of each other"
    fn bitmask_run(&self, index: usize) -> usize {
        let Some(&(first, _)) = self.ranges.get(index) else {
            return 0;
        };
        let (prefix, start) = split_low_byte(first);
        let limit = u16::from(start).saturating_add(8);
        self.ranges
            .get(index..)
            .unwrap_or_default()
            .iter()
            .take(5)
            .take_while(|&&(low, high)| {
                let (low_prefix, _) = split_low_byte(low);
                let (high_prefix, high_byte) = split_low_byte(high);
                low_prefix == prefix && high_prefix == prefix && u16::from(high_byte) <= limit
            })
            .count()
    }
}

/// The ranges of a [`GlobSet`], lowest first.
#[derive(Clone, Debug)]
pub struct GlobSetRanges<'a>(core::slice::Iter<'a, (GlobCnt, GlobCnt)>);

impl Iterator for GlobSetRanges<'_> {
    type Item = (GlobCnt, GlobCnt);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().copied()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl ExactSizeIterator for GlobSetRanges<'_> {}

/// The encoder's common byte stack, and the Push groups that a Pop unwinds one at a time.
///
/// [MS-OXCFXICS] §3.1.5.4.3.1.2 — "the Push and Pop commands are used together to adjust the bytes
/// that are stored on the common byte stack"
#[derive(Default)]
struct Stack {
    bytes: Vec<u8>,
    pushes: Vec<usize>,
}

impl Stack {
    fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Pops until what is left is a prefix of `prefix`.
    fn keep_prefix_of(&mut self, w: &mut Writer, prefix: &[u8]) {
        while !prefix.starts_with(&self.bytes) {
            let Some(count) = self.pushes.pop() else {
                break;
            };
            self.bytes.truncate(self.bytes.len().saturating_sub(count));
            w.u8(POP);
        }
    }

    /// Leaves exactly `target` on the stack, popping what differs and pushing what is missing.
    fn align(&mut self, w: &mut Writer, target: &[u8]) {
        while !target.starts_with(&self.bytes) {
            let Some(count) = self.pushes.pop() else {
                break;
            };
            self.bytes.truncate(self.bytes.len().saturating_sub(count));
            w.u8(POP);
        }
        let missing = target.get(self.bytes.len()..).unwrap_or_default();
        if let Ok(count @ 1..) = u8::try_from(missing.len()) {
            w.u8(count).bytes(missing);
            self.bytes.extend_from_slice(missing);
            self.pushes.push(missing.len());
        }
    }

    /// Pops everything, which End requires. [MS-OXCFXICS] §3.1.5.4.3.1.5
    fn clear(&mut self, w: &mut Writer) {
        for _ in self.pushes.drain(..) {
            w.u8(POP);
        }
        self.bytes.clear();
    }
}

/// A counter from the stack's high bytes and a command's low bytes.
fn counter(high: &[u8], low: &[u8]) -> GlobCnt {
    let mut bytes = [0_u8; WIDTH];
    for (slot, byte) in bytes.iter_mut().zip(high.iter().chain(low)) {
        *slot = *byte;
    }
    GlobCnt(bytes)
}

/// How many leading bytes two counters share.
fn shared_prefix(a: [u8; WIDTH], b: [u8; WIDTH]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| **x == *y).count()
}

/// A counter's five high bytes, and its low byte — the two halves a Bitmask cares about.
const fn split_low_byte(counter: GlobCnt) -> ([u8; 5], u8) {
    let [b0, b1, b2, b3, b4, b5] = counter.0;
    ([b0, b1, b2, b3, b4], b5)
}

/// Expands a Bitmask into ranges: `start`, then one value per set bit, bit `n` being `start + 1 +
/// n`.
///
/// `None` if a set bit names a value past `0xFF`, which no low byte can hold.
///
/// [MS-OXCFXICS] §3.1.5.4.3.1.3 — the bit for a value is its low byte minus one more than
/// `StartingValue`
fn read_bitmask(
    high: &[u8],
    start: u8,
    mask: u8,
    ranges: &mut Vec<(GlobCnt, GlobCnt)>,
) -> Option<()> {
    let mut run = (start, start);
    for bit in 0..8_u8 {
        if mask & (1 << bit) == 0 {
            continue;
        }
        let value = start.checked_add(bit)?.checked_add(1)?;
        if run.1.checked_add(1) == Some(value) {
            run.1 = value;
        } else {
            ranges.push((counter(high, &[run.0]), counter(high, &[run.1])));
            run = (value, value);
        }
    }
    ranges.push((counter(high, &[run.0]), counter(high, &[run.1])));
    Some(())
}

/// Writes one Bitmask for ranges that [`GlobSet::bitmask_run`] said fit.
fn write_bitmask(w: &mut Writer, ranges: Option<&[(GlobCnt, GlobCnt)]>) {
    let ranges = ranges.unwrap_or_default();
    let Some(&(first, _)) = ranges.first() else {
        return;
    };
    let [.., start] = first.0;
    let mut mask = 0_u8;
    for &(low, high) in ranges {
        let [.., low_byte] = low.0;
        let [.., high_byte] = high.0;
        for value in low_byte..=high_byte {
            if let Some(bit) = value.checked_sub(start).and_then(|d| d.checked_sub(1)) {
                mask |= 1_u8.checked_shl(u32::from(bit)).unwrap_or(0);
            }
        }
    }
    w.u8(BITMASK).u8(start).u8(mask);
}

#[cfg(test)]
mod tests;
