//! The one value in an incremental download that moves with the rest of the mailbox.
//!
//! A download ends with the server's final ICS state, and that state's `MetaTagCnsetSeen` is "every
//! change from 1 up to the newest", where the newest is the mailbox's, not the folder's. Measured
//! on Exchange Server SE `15.02.2562.056`: the Inbox's final `CnsetSeen` ran `1`–`0x32B377B6`, and
//! after a draft was created and deleted in another folder, `1`–`0x32B377C2`. `CnsetRead` did not
//! move. So every capture after any other scenario has written would differ in those bytes, and
//! nothing else.
//!
//! The upper bound is rewritten to a canonical value, in place: same width, same encoding, still a
//! valid GLOBSET that decodes to "1 up to a constant". Only the exact shape observed is touched —
//! an `IncrSyncStateBegin` marker, then a `MetaTagCnsetSeen` or `MetaTagCnsetSeenFAI` whose every
//! replica's GLOBSET is one `Range` from 1 and an `End`, or the same behind a `Push` of zeroes.
//! Anything else is left exactly as it arrived, so a server that one day encodes the state
//! differently shows up as a difference rather than being silently reshaped.
//!
//! # A state split across two responses
//!
//! The stream is one stream however many `RopFastTransferSourceGetBuffer` responses carry it, and
//! a buffer can end between any two atoms of it or anywhere inside a variable-size value — inside
//! the state, inside the bound itself ([MS-OXCFXICS] §2.2.4.1). So the state is looked for in each
//! download's buffers joined end to end, not in each response alone, and a bound that straddles
//! two of them is rewritten in both.
//!
//! A run starts only at a response whose ROP list ends with a successful
//! `RopFastTransferSourceGetBuffer` — a download's first response, which carries the configuration
//! before it, or a later one. The `RopFastTransferSourceGetBuffer` is the last ROP a download
//! sends, so it is found from the end of the list: the one whose `TransferBufferSize` accounts for
//! every byte up to the end `RopSize` gives, with a zero `ReturnValue` and `Reserved`. What follows
//! is the handle table, so that is where each response joined is cut.
//!
//! A response continues the run before it when its ROP list is that
//! `RopFastTransferSourceGetBuffer` and nothing else, which is how every request after a
//! download's first is answered. A refused one — `ServerBusy`, whose retry carries the buffer — is
//! passed over without ending the run, and a `TransferStatus` of `Done` ends it. Any other response
//! ends it too, a table read or a failed `Execute` among them, and is searched for a state on its
//! own.
//!
//! [MS-OXCFXICS] §2.2.4.3.25 — `state` element
//! [MS-OXCFXICS] §2.2.4.1 — where a stream may be split
//! [MS-OXCFXICS] §2.2.3.1.1.5.2 — `TransferStatus`
//! [MS-OXCFXICS] §2.2.2.6 — GLOBSET commands
//! [MS-OXCROPS] §2.2.12.4.2 — `RopFastTransferSourceGetBuffer` response buffer
//! [MS-OXCRPC] §3.1.4.2.1.1.1 — `rgbIn`: `RopSize`, then the ROP list, then the handle table

use core::ops::Range;

use mapi_proto::RequestType;

use super::{EXECUTE_ROP_LIST, body_offset, succeeded};

/// `IncrSyncStateBegin`, as the stream writes it. [MS-OXCFXICS] §2.2.4.1.4
const STATE_BEGIN: [u8; 4] = [0x03, 0x00, 0x3A, 0x40];
/// `IncrSyncStateEnd`. [MS-OXCFXICS] §2.2.4.1.4
const STATE_END: u32 = 0x403B_0003;
/// `MetaTagCnsetSeen` and `MetaTagCnsetSeenFAI`, the two that run up to the mailbox's newest
/// change.
const BOUNDED: [u32; 2] = [0x6796_0102, 0x67DA_0102];
/// `MetaTagIdsetGiven`, carried with a length despite its `PtypInteger32` tag. [MS-OXCFXICS]
/// §3.2.5.2.1
const IDSET_GIVEN: u32 = 0x4017_0003;
/// The bytes a rewritten bound's low-order part becomes.
const CANONICAL: u8 = 0xFF;

/// `RopFastTransferSourceGetBuffer`'s id. [MS-OXCROPS] §2.2.12.4.2
const ROP_GET_BUFFER: u8 = 0x4E;
/// Where `RopSize` sits in an `Execute` body: just before the ROP list.
const EXECUTE_ROP_SIZE: usize = EXECUTE_ROP_LIST - 2;
/// Where a `RopFastTransferSourceGetBuffer` response's `ReturnValue`, `TransferBufferSize` and
/// `TransferBuffer` sit, from its `RopId`: `InputHandleIndex` (1), then after `ReturnValue` (4)
/// `TransferStatus`, `InProgressCount` and `TotalStepCount` (2 each) and `Reserved` (1).
const GET_BUFFER_RETURN_VALUE: usize = 2;
const GET_BUFFER_STATUS: usize = 6;
const GET_BUFFER_RESERVED: usize = 12;
const GET_BUFFER_SIZE: usize = 13;
const GET_BUFFER_BUFFER: usize = 15;
/// `TransferStatus` `Done`: the last portion of the stream. [MS-OXCFXICS] §2.2.3.1.1.5.2
const DONE: u16 = 0x0003;

/// What an `Execute` response's ROP list is, as far as continuing a stream goes.
enum Shape {
    /// A ROP list that ends with a successful `RopFastTransferSourceGetBuffer`.
    Buffer {
        /// Where the `TransferBuffer` starts.
        start: usize,
        /// Whether its `TransferStatus` is `Done`.
        done: bool,
        /// Whether it is the only ROP in the list: a download's later responses, not its first.
        alone: bool,
    },
    /// A `RopFastTransferSourceGetBuffer` refused, which carries no buffer.
    Refused,
    /// Anything else.
    Other,
}

/// Rewrites the mailbox-wide bound of every final state in a scenario's responses, given in the
/// order they were exchanged, and reports each change against every response whose bytes it
/// touched.
pub(super) fn cnset_bounds(responses: &mut [(RequestType, Vec<u8>)]) -> Vec<Vec<String>> {
    let mut changed = vec![Vec::new(); responses.len()];
    for run in runs(responses) {
        let original: Vec<u8> = run
            .iter()
            .filter_map(|(index, bytes)| responses.get(*index)?.1.get(bytes.clone()))
            .flatten()
            .copied()
            .collect();
        if find(&original, 0, &STATE_BEGIN).is_none() {
            continue;
        }
        let mut stream = original.clone();
        // Where each response's bytes start in the joined stream.
        let starts: Vec<usize> = run
            .iter()
            .scan(0_usize, |at, (_, bytes)| {
                let start = *at;
                *at = at.saturating_add(bytes.len());
                Some(start)
            })
            .collect();
        // The response, and the offset in it, that a byte of the joined stream came from.
        let origin = |at: usize| -> Option<(usize, usize)> {
            let segment = starts
                .partition_point(|start| *start <= at)
                .checked_sub(1)?;
            let (index, bytes) = run.get(segment)?;
            let offset = at.checked_sub(*starts.get(segment)?)?;
            Some((*index, bytes.start.checked_add(offset)?))
        };
        for (tag, value) in rewrite(&mut stream) {
            let mut touched: Vec<usize> = Vec::new();
            for at in value.filter(|at| stream.get(*at) != original.get(*at)) {
                let Some((index, offset)) = origin(at) else {
                    continue;
                };
                if let (Some(slot), Some(byte)) = (
                    responses
                        .get_mut(index)
                        .and_then(|(_, payload)| payload.get_mut(offset)),
                    stream.get(at),
                ) {
                    *slot = *byte;
                }
                if touched.last() != Some(&index) {
                    touched.push(index);
                }
            }
            for index in &touched {
                if let Some(changes) = changed.get_mut(*index) {
                    changes.push(message(tag, touched.len() > 1));
                }
            }
        }
    }
    changed
}

/// Each run of `Execute` responses a download's stream may continue through, as the byte range
/// of each that the stream can occupy: from the body for the first, and from the
/// `TransferBuffer` for each that continues it.
fn runs(responses: &[(RequestType, Vec<u8>)]) -> Vec<Vec<(usize, Range<usize>)>> {
    let mut runs: Vec<Vec<(usize, Range<usize>)>> = Vec::new();
    let mut open = false;
    for (index, (request_type, payload)) in responses.iter().enumerate() {
        let Some((body, end)) =
            rop_list_end(payload).filter(|_| *request_type == RequestType::Execute)
        else {
            open = false;
            continue;
        };
        match (open, shape(payload, body, end)) {
            (
                true,
                Shape::Buffer {
                    start,
                    done,
                    alone: true,
                },
            ) => {
                if let Some(run) = runs.last_mut() {
                    run.push((index, start..end));
                }
                open = !done;
            }
            (true, Shape::Refused) => {}
            (_, Shape::Buffer { done, .. }) => {
                runs.push(vec![(index, body..end)]);
                open = !done;
            }
            (_, Shape::Refused | Shape::Other) => {
                runs.push(vec![(index, body..end)]);
                open = false;
            }
        }
    }
    runs
}

/// Where a successful `Execute` response's body starts and its ROP list ends, if it has the shape
/// of one.
fn rop_list_end(payload: &[u8]) -> Option<(usize, usize)> {
    let body = body_offset(payload).filter(|body| succeeded(payload, *body))?;
    let at = body.checked_add(EXECUTE_ROP_SIZE)?;
    let size = u16::from_le_bytes(payload.get(at..at.checked_add(2)?)?.try_into().ok()?);
    let end = at.checked_add(usize::from(size))?;
    (end <= payload.len()).then_some((body, end))
}

/// What this response's ROP list is: one `RopFastTransferSourceGetBuffer` and nothing else, the
/// shape of a download's later responses, refused or with its buffer — or anything else.
fn shape(payload: &[u8], body: usize, end: usize) -> Shape {
    let Some(first) = body.checked_add(EXECUTE_ROP_LIST) else {
        return Shape::Other;
    };
    if payload.get(first) == Some(&ROP_GET_BUFFER)
        && first
            .checked_add(GET_BUFFER_RETURN_VALUE)
            .and_then(|at| u32_at(payload, at))
            .is_some_and(|value| value != 0)
    {
        return Shape::Refused;
    }
    // The first offset that reads as the list's last ROP, a successful
    // `RopFastTransferSourceGetBuffer`. Earlier ROPs in a download's first response are a handful
    // of bytes each, so it is found before anything its own buffer holds could be read as one.
    (first..end)
        .find_map(|rop| last_get_buffer(payload, rop, end))
        .map_or(Shape::Other, |(start, done)| Shape::Buffer {
            start,
            done,
            alone: start == first.saturating_add(GET_BUFFER_BUFFER),
        })
}

/// Where the `TransferBuffer` starts and whether the stream is done, if a successful
/// `RopFastTransferSourceGetBuffer` response starts at `rop` and ends exactly at `end`.
fn last_get_buffer(payload: &[u8], rop: usize, end: usize) -> Option<(usize, bool)> {
    let u16_at = |offset: usize| -> Option<u16> {
        let at = rop.checked_add(offset)?;
        Some(u16::from_le_bytes(
            payload.get(at..at.checked_add(2)?)?.try_into().ok()?,
        ))
    };
    let start = rop.checked_add(GET_BUFFER_BUFFER)?;
    let anchored = payload.get(rop) == Some(&ROP_GET_BUFFER)
        && u32_at(payload, rop.checked_add(GET_BUFFER_RETURN_VALUE)?) == Some(0)
        && payload.get(rop.checked_add(GET_BUFFER_RESERVED)?) == Some(&0)
        && start.checked_add(usize::from(u16_at(GET_BUFFER_SIZE)?)) == Some(end);
    anchored.then_some((start, u16_at(GET_BUFFER_STATUS)? == DONE))
}

/// What a rewritten bound is reported as, in each response that held some of it.
fn message(tag: u32, split: bool) -> String {
    format!(
        "response body: the upper bound of a final state's `{}` rewritten to a constant, because \
         it is the newest change number in the whole mailbox and moves whenever anything in it is \
         written ([MS-OXCFXICS] §2.2.4.3.25){}",
        if tag == BOUNDED[0] {
            "MetaTagCnsetSeen"
        } else {
            "MetaTagCnsetSeenFAI"
        },
        if split {
            "; the value straddles two `RopFastTransferSourceGetBuffer` responses, and this one \
             holds part of it"
        } else {
            ""
        }
    )
}

/// Rewrites the bound of every final state in `stream`, handing back each rewritten property's
/// tag and where its value lies.
fn rewrite(stream: &mut [u8]) -> Vec<(u32, Range<usize>)> {
    let mut changed = Vec::new();
    let mut from = 0;
    while let Some(found) = find(stream, from, &STATE_BEGIN) {
        from = found.saturating_add(STATE_BEGIN.len());
        changed.extend(state(stream, from));
    }
    changed
}

/// Walks one state's properties up to `IncrSyncStateEnd`, rewriting the two bounded ones.
fn state(payload: &mut [u8], mut at: usize) -> Vec<(u32, Range<usize>)> {
    let mut changed = Vec::new();
    loop {
        let Some(tag) = u32_at(payload, at) else {
            return changed;
        };
        if tag == STATE_END {
            return changed;
        }
        let binary = tag & 0xFFFF == 0x0102 || tag == IDSET_GIVEN;
        let Some(length) = u32_at(payload, at.saturating_add(4)).filter(|_| binary) else {
            // Not a property this element can hold; nothing past here is understood.
            return changed;
        };
        let start = at.saturating_add(8);
        let Some(end) = usize::try_from(length)
            .ok()
            .and_then(|length| start.checked_add(length))
            .filter(|end| *end <= payload.len())
        else {
            return changed;
        };
        if BOUNDED.contains(&tag)
            && let Some(value) = payload.get_mut(start..end)
            && bound(value)
        {
            changed.push((tag, start..end));
        }
        at = end;
    }
}

/// Rewrites the bound of every replica in one REPLGUID-based IDSET, if every replica has exactly
/// the shape "1 up to X". Returns whether anything changed.
fn bound(idset: &mut [u8]) -> bool {
    let mut highs = Vec::new();
    let mut at = 16_usize;
    // Every byte has to be accounted for: a tail that does not make a whole replica is a shape
    // nobody has observed, and is left as it arrived.
    loop {
        let Some((high, end)) = one_range_from_one(idset, at) else {
            return false;
        };
        highs.push(high);
        if end == idset.len() {
            break;
        }
        at = end.saturating_add(16);
    }
    let mut changed = false;
    for (start, width) in highs {
        if let Some(bytes) = idset.get_mut(start..start.saturating_add(width))
            && bytes.iter().any(|byte| *byte != CANONICAL)
        {
            bytes.fill(CANONICAL);
            changed = true;
        }
    }
    changed
}

/// Matches "1 up to X" at `at` — `Range (low = 1, high) · End`, as Exchange encodes it, or the same
/// behind a `Push` of zeroes and closed by a `Pop`, as [MS-OXCFXICS] §4.5's own example does —
/// handing back where the high value's bytes are and how wide, and where the GLOBSET ends.
///
/// Exchange Server SE `15.02.2562.056` sends the bare form: `52`, the six bytes of 1, the six bytes
/// of the bound, `00`.
fn one_range_from_one(idset: &[u8], at: usize) -> Option<((usize, usize), usize)> {
    let first = *idset.get(at)?;
    let (pushed, range) = if first == 0x52 {
        (0, at)
    } else {
        let pushed = usize::from(first);
        if !(1..=5).contains(&pushed) {
            return None;
        }
        let prefix =
            idset.get(at.saturating_add(1)..at.saturating_add(1).saturating_add(pushed))?;
        if prefix.iter().any(|byte| *byte != 0) {
            return None;
        }
        (pushed, at.saturating_add(1).saturating_add(pushed))
    };
    if idset.get(range) != Some(&0x52) {
        return None;
    }
    let width = 6_usize.saturating_sub(pushed);
    let low_at = range.saturating_add(1);
    let low = idset.get(low_at..low_at.saturating_add(width))?;
    let (last, rest) = low.split_last()?;
    if *last != 1 || rest.iter().any(|byte| *byte != 0) {
        return None;
    }
    let high_at = low_at.saturating_add(width);
    let tail = high_at.saturating_add(width);
    let closing: &[u8] = if pushed == 0 { &[0x00] } else { &[0x50, 0x00] };
    if idset.get(tail..tail.saturating_add(closing.len())) != Some(closing) {
        return None;
    }
    Some(((high_at, width), tail.saturating_add(closing.len())))
}

fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| offset.saturating_add(from))
}

fn u32_at(payload: &[u8], at: usize) -> Option<u32> {
    let bytes: [u8; 4] = payload.get(at..at.saturating_add(4))?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests;
