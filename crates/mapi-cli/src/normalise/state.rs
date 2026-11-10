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
//! [MS-OXCFXICS] §2.2.4.3.25 — `state` element
//! [MS-OXCFXICS] §2.2.2.6 — GLOBSET commands

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

/// Rewrites the mailbox-wide bound of every final state in an `Execute` response, reporting each.
pub(super) fn cnset_bounds(payload: &mut [u8], body: usize) -> Vec<String> {
    let mut changed = Vec::new();
    let mut from = body;
    while let Some(found) = find(payload, from, &STATE_BEGIN) {
        from = found.saturating_add(STATE_BEGIN.len());
        changed.extend(state(payload, from));
    }
    changed
}

/// Walks one state's properties up to `IncrSyncStateEnd`, rewriting the two bounded ones.
fn state(payload: &mut [u8], mut at: usize) -> Vec<String> {
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
            changed.push(format!(
                "response body: the upper bound of a final state's `{}` rewritten to a constant, \
                 because it is the newest change number in the whole mailbox and moves whenever \
                 anything in it is written ([MS-OXCFXICS] §2.2.4.3.25)",
                if tag == BOUNDED[0] {
                    "MetaTagCnsetSeen"
                } else {
                    "MetaTagCnsetSeenFAI"
                }
            ));
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
mod tests {
    use super::*;

    const GUID: [u8; 16] = [0x34; 16];

    /// A state as Exchange encodes one: `CnsetSeen` and `CnsetSeenFAI` as "1 up to the newest",
    /// `IdsetGiven` and `CnsetRead` as whatever they are.
    fn state(seen_high: [u8; 4]) -> Vec<u8> {
        // As Exchange encodes it: a bare Range, six bytes each side, then End.
        let globset = |high: [u8; 4]| {
            let mut out = GUID.to_vec();
            out.extend_from_slice(&[0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);
            out.extend_from_slice(&high);
            out.push(0x00);
            out
        };
        let mut out = vec![0xEE, 0xEE];
        out.extend_from_slice(&STATE_BEGIN);
        for (tag, value) in [
            (0x6796_0102_u32, globset(seen_high)),
            (0x67DA_0102, globset([0x00, 0x00, 0x00, 0x09])),
            (0x4017_0003, globset([0x00, 0x00, 0x00, 0x05])),
            (0x67D2_0102, globset([0x18, 0x2A, 0xB3, 0xCB])),
        ] {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&STATE_END.to_le_bytes());
        out
    }

    /// Two captures that differ only in the mailbox's newest change number agree once normalised,
    /// and nothing else in the state is touched.
    #[test]
    fn two_states_that_differ_only_in_the_mailbox_bound_normalise_to_the_same_bytes() {
        let mut first = state([0x32, 0xB3, 0x77, 0xB6]);
        let mut second = state([0x32, 0xB3, 0x77, 0xC2]);
        let untouched = first.clone();
        assert_eq!(cnset_bounds(&mut first, 0).len(), 2);
        assert_eq!(cnset_bounds(&mut second, 0).len(), 2);
        assert_eq!(first, second);
        assert_eq!(first.len(), untouched.len(), "length-preserving");

        let differing: Vec<usize> = (0..first.len())
            .filter(|&i| first[i] != untouched[i])
            .collect();
        assert_eq!(
            differing.len(),
            12,
            "six bytes in each of the two bounded properties"
        );
        assert!(cnset_bounds(&mut first, 0).is_empty(), "idempotent");
    }

    /// A shape other than the one observed is left alone: here a set with a gap in it.
    #[test]
    fn any_other_shape_is_left_exactly_as_it_arrived() {
        let mut odd = state([0x32, 0xB3, 0x77, 0xB6]);
        let at = odd
            .windows(4)
            .position(|window| window == 0x6796_0102_u32.to_le_bytes())
            .unwrap();
        // Turn the first Range's low value into 2: no longer "from 1".
        odd[at + 8 + 16 + 6] = 0x02;
        let before = odd.clone();
        let changed = cnset_bounds(&mut odd, 0);
        assert_eq!(changed.len(), 1, "only CnsetSeenFAI still has the shape");
        assert_eq!(odd[..at + 40], before[..at + 40]);
    }

    #[test]
    fn a_payload_with_no_state_is_not_touched() {
        let mut payload = vec![0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
        let before = payload.clone();
        assert!(cnset_bounds(&mut payload, 0).is_empty());
        assert_eq!(payload, before);

        let mut cut = state([1, 2, 3, 4]);
        cut.truncate(30);
        let before = cut.clone();
        assert!(
            cnset_bounds(&mut cut, 0).is_empty(),
            "a state cut off by its buffer"
        );
        assert_eq!(cut, before);
    }

    /// The pushed form, as [MS-OXCFXICS] §4.5 encodes "1 up to X", is rewritten the same way.
    #[test]
    fn the_documents_pushed_form_is_rewritten_too() {
        let mut idset = GUID.to_vec();
        idset.extend_from_slice(&[
            0x03, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x01, 0x78, 0x4D, 0x1D, 0x50, 0x00,
        ]);
        assert!(bound(&mut idset));
        assert_eq!(&idset[16 + 8..16 + 11], [0xFF; 3]);
        assert!(!bound(&mut idset), "idempotent");
    }

    /// Bytes after the last GLOBSET too few to be another replica are not a shape that was
    /// observed, so the set is left alone.
    #[test]
    fn a_tail_short_of_another_replica_is_left_alone() {
        let mut idset = GUID.to_vec();
        idset.extend_from_slice(&[0x52, 0, 0, 0, 0, 0, 1, 0, 0, 0x32, 0xB3, 0x77, 0xB6, 0x00]);
        idset.extend_from_slice(&[0x34; 5]);
        let before = idset.clone();
        assert!(!bound(&mut idset));
        assert_eq!(idset, before);
    }
}
