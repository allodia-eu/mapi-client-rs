use super::*;

fn cnt(value: u64) -> GlobCnt {
    GlobCnt::from_u64(value).unwrap()
}

fn decode(bytes: &[u8]) -> Result<GlobSet> {
    let mut r = Reader::new(bytes);
    let set = GlobSet::read(&mut r)?;
    assert!(r.is_empty(), "the decoder consumes exactly one GLOBSET");
    Ok(set)
}

fn encode(set: &GlobSet) -> Vec<u8> {
    let mut w = Writer::new();
    set.write(&mut w);
    w.finish()
}

fn ranges(set: &GlobSet) -> Vec<(u64, u64)> {
    set.ranges()
        .map(|(low, high)| (low.as_u64(), high.as_u64()))
        .collect()
}

/// [MS-OXCFXICS] §4.4, GLOBSET 1: five shared bytes pushed, a Range for `05`–`06`, a one-byte Push
/// completing the singleton `10`, a Pop and an End.
#[test]
fn the_documents_first_globset_decodes_to_its_two_ranges() {
    let set = decode(&[
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x05, 0x06, 0x01, 0x10, 0x50, 0x00,
    ])
    .unwrap();
    assert_eq!(ranges(&set), [(0x05, 0x06), (0x10, 0x10)]);
}

/// [MS-OXCFXICS] §4.4, GLOBSET 2: a six-byte Push is a singleton and unwinds by itself, so the End
/// that follows finds the stack empty.
#[test]
fn a_six_byte_push_is_a_singleton_that_needs_no_pop() {
    let set = decode(&[0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00]).unwrap();
    assert_eq!(ranges(&set), [(0x09, 0x09)]);
}

/// [MS-OXCFXICS] §3.1.5.4.3.1.3's own example: `StartingValue` `0x01`, `Bitmask` `0xEB`, is
/// `{0x01-0x03, 0x05-0x05, 0x07-0x09}`.
#[test]
fn the_documents_bitmask_example_decodes_to_its_three_ranges() {
    let set = decode(&[
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x01, 0xEB, 0x50, 0x00,
    ])
    .unwrap();
    assert_eq!(ranges(&set), [(0x01, 0x03), (0x05, 0x05), (0x07, 0x09)]);
}

/// The bitmask the encoder writes for the document's three ranges is the document's own.
#[test]
fn the_encoder_writes_the_documents_bitmask_for_its_ranges() {
    let mut set = GlobSet::new();
    set.insert_range(cnt(0x01), cnt(0x03));
    set.insert(cnt(0x05));
    set.insert_range(cnt(0x07), cnt(0x09));
    assert_eq!(
        encode(&set),
        [
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x01, 0xEB, 0x50, 0x00
        ]
    );
}

/// The `IdsetGiven` of [MS-OXCFXICS] §4.5 pushes five bytes, uses a Bitmask with one bit, then a
/// **one-byte** Push — which §3.1.5.4.3.2.1's "2 to 6 bytes" would forbid and §2.2.2.6.1's
/// `0x01`–`0x06` allows.
#[test]
fn a_one_byte_push_is_valid_as_the_documents_own_example_uses_one() {
    let set = decode(&[
        0x05, 0x00, 0x00, 0x00, 0x78, 0x06, 0x42, 0x01, 0x01, 0x01, 0x0C, 0x50, 0x00,
    ])
    .unwrap();
    assert_eq!(
        ranges(&set),
        [(0x78_0601, 0x78_0602), (0x78_060C, 0x78_060C)]
    );
}

#[test]
fn an_empty_globset_is_one_end_command() {
    assert!(decode(&[0x00]).unwrap().is_empty());
    assert_eq!(encode(&GlobSet::new()), [0x00]);
}

/// Every refusal the decoder makes, each of which would otherwise build a state that silently
/// skips or repeats mail.
#[test]
fn malformed_globsets_are_refused_with_a_reason() {
    for (bytes, reason) in [
        (&[0x05, 0, 0, 0, 0, 0, 0x00][..], "End with bytes still"),
        (
            &[0x04, 0, 0, 0, 0, 0x03, 1, 2, 3, 0x00][..],
            "past the six bytes",
        ),
        (&[0x50, 0x00][..], "Pop with nothing pushed"),
        (
            &[0x04, 0, 0, 0, 0, 0x42, 1, 1, 0x50, 0x00][..],
            "Bitmask without five",
        ),
        (
            &[0x52, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 8, 0x00][..],
            "low value is above",
        ),
        (&[0x07, 0x00][..], "unknown command"),
        (
            &[0x05, 0, 0, 0, 0, 0, 0x42, 0xFF, 0x02, 0x50, 0x00][..],
            "past the counter's low",
        ),
    ] {
        let error = decode(bytes).unwrap_err();
        let Error::InvalidGlobset { reason: said, .. } = error else {
            panic!("{bytes:02X?}: expected InvalidGlobset, got {error:?}");
        };
        assert!(said.contains(reason), "{bytes:02X?}: {said}");
    }
}

#[test]
fn a_truncated_globset_errors_rather_than_panicking() {
    let whole = [
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x05, 0x06, 0x50, 0x00,
    ];
    for end in 0..whole.len() {
        assert!(decode(&whole[..end]).is_err(), "{end} bytes");
    }
}

/// A bitmask whose top bit names `0xFF` itself is fine; one naming a value past it is not.
#[test]
fn a_bitmask_may_reach_the_last_low_byte_and_no_further() {
    let set = decode(&[0x05, 0, 0, 0, 0, 0, 0x42, 0xF7, 0x80, 0x50, 0x00]).unwrap();
    assert_eq!(ranges(&set), [(0xF7, 0xF7), (0xFF, 0xFF)]);
    let only_start = decode(&[0x05, 0, 0, 0, 0, 0, 0x42, 0xFF, 0x00, 0x50, 0x00]).unwrap();
    assert_eq!(ranges(&only_start), [(0xFF, 0xFF)]);
}

#[test]
fn inserting_merges_with_the_ranges_on_either_side() {
    let mut set = GlobSet::new();
    assert!(set.insert(cnt(5)));
    assert!(set.insert(cnt(7)));
    assert_eq!(ranges(&set), [(5, 5), (7, 7)]);
    assert!(set.insert(cnt(6)), "the gap closes");
    assert_eq!(ranges(&set), [(5, 7)]);
    assert!(!set.insert(cnt(6)), "already there");
    assert!(set.insert(cnt(4)));
    assert!(set.insert(cnt(8)));
    assert_eq!(ranges(&set), [(4, 8)]);
    assert!(set.insert(cnt(1)));
    assert_eq!(ranges(&set), [(1, 1), (4, 8)]);
    assert!(set.contains(cnt(1)) && set.contains(cnt(4)) && set.contains(cnt(8)));
    assert!(!set.contains(cnt(2)) && !set.contains(cnt(9)) && !set.contains(cnt(0)));
}

#[test]
fn the_largest_counter_does_not_overflow_a_merge() {
    let mut set = GlobSet::new();
    set.insert(GlobCnt::MAX);
    set.insert(cnt(0xFFFF_FFFF_FFFE));
    assert_eq!(ranges(&set), [(0xFFFF_FFFF_FFFE, 0xFFFF_FFFF_FFFF)]);
    assert_eq!(GlobCnt::from_u64(0x0001_0000_0000_0000), None);
}

#[test]
fn ranges_inserted_in_any_order_normalise_to_the_same_set() {
    let mut a = GlobSet::new();
    a.insert_range(cnt(10), cnt(20));
    a.insert_range(cnt(1), cnt(3));
    a.insert_range(cnt(4), cnt(9));
    let mut b = GlobSet::new();
    b.insert_range(cnt(1), cnt(20));
    assert_eq!(a, b);
    a.insert_range(cnt(5), cnt(2));
    assert_eq!(a, b, "a backwards range adds nothing");
}

/// Whatever the encoder chooses, the decoder reads back the same set — across sets shaped like
/// what a checkpointed state actually holds: mostly isolated counters sharing their high bytes,
/// some runs, and the occasional counter far away.
#[test]
fn every_set_survives_an_encode_and_decode() {
    let mut seed = 0x2545_F491_4F6C_DD1D_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..300 {
        let mut set = GlobSet::new();
        let base = next() & 0xFFFF_FFFF_0000;
        for _ in 0..(next() % 40) {
            let roll = next();
            let value = match roll % 4 {
                0 => next() & 0xFFFF_FFFF_FFFF,
                1 => base | (next() & 0xFFFF),
                _ => base | (next() & 0x3F),
            };
            if roll % 5 == 0 {
                set.insert_range(
                    cnt(value),
                    cnt(value.saturating_add(next() % 300).min(0xFFFF_FFFF_FFFF)),
                );
            } else {
                set.insert(cnt(value));
            }
        }
        let bytes = encode(&set);
        assert_eq!(decode(&bytes).unwrap(), set, "{bytes:02X?}");
    }
}

/// The reason the encoder bothers: a hundred isolated counters in one region cost a Bitmask per
/// five rather than seven bytes each.
#[test]
fn isolated_counters_sharing_high_bytes_encode_compactly() {
    let mut set = GlobSet::new();
    for value in (0..200_u64).step_by(2) {
        set.insert(cnt(0x78_0000 | value));
    }
    let bytes = encode(&set);
    assert!(
        bytes.len() < 100 * 3,
        "{} bytes for 100 counters",
        bytes.len()
    );
    assert_eq!(decode(&bytes).unwrap(), set);
}
