//! The bound rewritten, the shapes left alone, and a state split across two responses.

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
    assert_eq!(rewrite(&mut first).len(), 2);
    assert_eq!(rewrite(&mut second).len(), 2);
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
    assert!(rewrite(&mut first).is_empty(), "idempotent");
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
    let changed = rewrite(&mut odd);
    assert_eq!(changed.len(), 1, "only CnsetSeenFAI still has the shape");
    assert_eq!(odd[..at + 40], before[..at + 40]);
}

#[test]
fn a_payload_with_no_state_is_not_touched() {
    let mut payload = vec![0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    let before = payload.clone();
    assert!(rewrite(&mut payload).is_empty());
    assert_eq!(payload, before);

    let mut cut = state([1, 2, 3, 4]);
    cut.truncate(30);
    let before = cut.clone();
    assert!(
        rewrite(&mut cut).is_empty(),
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

/// An `Execute` payload whose ROP list is one `RopFastTransferSourceGetBuffer` carrying
/// `transfer`, as a download's later requests are answered, with more to come.
fn get_buffer(transfer: &[u8]) -> Vec<u8> {
    get_buffer_with(transfer, 0, 0x0001)
}

/// The same, with a `ReturnValue` and a `TransferStatus` of the test's choosing.
fn get_buffer_with(transfer: &[u8], return_value: u32, status: u16) -> Vec<u8> {
    execute(&get_buffer_rop(transfer, return_value, status))
}

/// One `RopFastTransferSourceGetBuffer` response.
fn get_buffer_rop(transfer: &[u8], return_value: u32, status: u16) -> Vec<u8> {
    let mut rop = vec![ROP_GET_BUFFER, 0x00];
    rop.extend_from_slice(&return_value.to_le_bytes());
    rop.extend_from_slice(&status.to_le_bytes());
    rop.extend_from_slice(&[0x00; 5]); // InProgressCount, TotalStepCount, Reserved
    rop.extend_from_slice(&u16::try_from(transfer.len()).unwrap().to_le_bytes());
    rop.extend_from_slice(transfer);
    rop
}

/// A successful `Execute` payload carrying `rops` as its ROP list.
fn execute(rops: &[u8]) -> Vec<u8> {
    let rop_size = u16::try_from(rops.len().saturating_add(2)).unwrap();
    let size = rop_size.saturating_add(4); // and one handle

    let mut out = b"PROCESSING\r\nDONE\r\nX-ElapsedTime: 0\r\n\r\n".to_vec();
    out.extend_from_slice(&[0x00; 12]); // StatusCode, ErrorCode, Flags
    out.extend_from_slice(&u32::from(size).saturating_add(8).to_le_bytes()); // RopBufferSize
    out.extend_from_slice(&[0x00, 0x00, 0x04, 0x00]); // Version, Flags = Last
    out.extend_from_slice(&size.to_le_bytes()); // Size
    out.extend_from_slice(&size.to_le_bytes()); // SizeActual
    out.extend_from_slice(&rop_size.to_le_bytes());
    out.extend_from_slice(rops);
    out.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // the handle table
    out.extend_from_slice(&0_u32.to_le_bytes()); // AuxiliaryBufferSize
    out
}

/// The `TransferBuffer` of a payload [`get_buffer`] built, found as a run finds it.
fn transfer(payload: &[u8]) -> &[u8] {
    let (body, end) = rop_list_end(payload).unwrap();
    let Shape::Buffer { start, .. } = shape(payload, body, end) else {
        panic!("one RopFastTransferSourceGetBuffer");
    };
    &payload[start..end]
}

/// Wherever the buffer ends — before the state, in its marker, in a property's header, or in
/// the middle of the bound itself — the two halves normalise to the bytes the whole state
/// does, and each response reports what changed in it.
#[test]
fn a_state_split_across_two_responses_normalises_as_if_it_were_whole() {
    let stream = state([0x32, 0xB3, 0x77, 0xB6]);
    let mut whole = [(RequestType::Execute, get_buffer(&stream))];
    let reported = cnset_bounds(&mut whole);
    assert_eq!(reported[0].len(), 2);
    let expected = transfer(&whole[0].1).to_vec();

    // Where each bounded property's six high bytes are: after its tag and length (8), the
    // REPLGUID (16), and the Range command and its low value (7).
    let bounds: Vec<_> = BOUNDED
        .iter()
        .map(|tag| {
            let at = stream
                .windows(4)
                .position(|window| window == tag.to_le_bytes())
                .unwrap();
            at + 31..at + 37
        })
        .collect();
    for cut in 1..stream.len() {
        let mut split = [
            (RequestType::Execute, get_buffer(&stream[..cut])),
            (RequestType::Execute, get_buffer(&stream[cut..])),
        ];
        let reported = cnset_bounds(&mut split);

        let joined = [transfer(&split[0].1), transfer(&split[1].1)].concat();
        assert_eq!(joined, expected, "cut at {cut}");
        let straddling = bounds
            .iter()
            .filter(|bound| bound.start < cut && cut < bound.end)
            .count();
        assert_eq!(
            reported.iter().map(Vec::len).sum::<usize>(),
            2 + straddling,
            "cut at {cut}: a straddling bound is reported in both responses"
        );
        assert_eq!(
            reported[1]
                .iter()
                .filter(|change| change.contains("straddles"))
                .count(),
            straddling,
            "cut at {cut}"
        );
        assert!(
            cnset_bounds(&mut split).iter().all(Vec::is_empty),
            "cut at {cut}: idempotent"
        );
    }
}

/// Where to cut [`state`]'s stream to split `MetaTagCnsetSeen`'s bound down the middle.
fn mid_bound(stream: &[u8]) -> usize {
    let seen = stream
        .windows(4)
        .position(|window| window == BOUNDED[0].to_le_bytes())
        .unwrap();
    seen.saturating_add(34)
}

/// A response that does not continue a download ends the run: a failed `Execute`, another request
/// type, or anything after a buffer whose `TransferStatus` said it was the last. A state cut short
/// there is left as it arrived rather than completed from bytes that are not its own.
#[test]
fn a_state_cut_short_is_not_completed_from_a_response_that_does_not_continue_it() {
    let stream = state([0x32, 0xB3, 0x77, 0xB6]);
    let cut = mid_bound(&stream);
    let mut failed = get_buffer(&stream[cut..]);
    let body = body_offset(&failed).unwrap();
    failed[body] = 0x01; // StatusCode no longer zero

    for (first, second) in [
        (get_buffer(&stream[..cut]), (RequestType::Execute, failed)),
        (
            get_buffer(&stream[..cut]),
            (RequestType::Disconnect, get_buffer(&stream[cut..])),
        ),
        (
            get_buffer_with(&stream[..cut], 0, DONE),
            (RequestType::Execute, get_buffer(&stream[cut..])),
        ),
    ] {
        let mut split = [(RequestType::Execute, first), second];
        let before = split.clone();
        let reported = cnset_bounds(&mut split);
        assert!(reported.iter().all(Vec::is_empty), "{reported:?}");
        assert_eq!(split, before);
    }
}

/// A `RopFastTransferSourceGetBuffer` refused between two buffers — `ServerBusy`, whose retry
/// carries the rest — is passed over, and the buffers on either side of it still join.
#[test]
fn a_refused_buffer_between_two_halves_does_not_separate_them() {
    const SERVER_BUSY: u32 = 0x0000_04B9;
    let stream = state([0x32, 0xB3, 0x77, 0xB6]);
    let cut = mid_bound(&stream);
    let mut split = [
        (RequestType::Execute, get_buffer(&stream[..cut])),
        (RequestType::Execute, get_buffer_with(&[], SERVER_BUSY, 0)),
        (
            RequestType::Execute,
            get_buffer_with(&stream[cut..], 0, DONE),
        ),
    ];
    let refusal = split[1].1.clone();

    let reported = cnset_bounds(&mut split);
    assert_eq!(reported.iter().map(Vec::len).collect::<Vec<_>>(), [1, 0, 2]);
    assert_eq!(split[1].1, refusal, "the refusal holds none of the stream");
    let mut whole = [(RequestType::Execute, get_buffer(&stream))];
    cnset_bounds(&mut whole);
    assert_eq!(
        [transfer(&split[0].1), transfer(&split[2].1)].concat(),
        transfer(&whole[0].1)
    );
}

/// A download's first response carries the configuration's responses before its
/// `RopFastTransferSourceGetBuffer`, and still starts a run the next buffer joins.
#[test]
fn a_downloads_first_response_starts_a_run() {
    let stream = state([0x32, 0xB3, 0x77, 0xB6]);
    let cut = mid_bound(&stream);
    // `RopSynchronizationConfigure` and the three state-upload ROPs, as Exchange answers them.
    let mut opening = Vec::new();
    for rop in [0x70_u8, 0x75, 0x76, 0x77] {
        opening.extend_from_slice(&[rop, 0x01, 0x00, 0x00, 0x00, 0x00]);
    }
    opening.extend_from_slice(&get_buffer_rop(&stream[..cut], 0, 0x0001));
    let mut split = [
        (RequestType::Execute, execute(&opening)),
        (
            RequestType::Execute,
            get_buffer_with(&stream[cut..], 0, DONE),
        ),
    ];

    let reported = cnset_bounds(&mut split);
    assert_eq!(reported.iter().map(Vec::len).collect::<Vec<_>>(), [1, 2]);
}

/// A response whose ROP list does not end with a `RopFastTransferSourceGetBuffer` — a table read,
/// here, whose rows happen to hold the head of a state — starts no run, so the buffer after it is
/// not joined to it.
#[test]
fn a_buffer_after_a_table_read_is_not_joined_to_it() {
    let stream = state([0x32, 0xB3, 0x77, 0xB6]);
    let cut = mid_bound(&stream);
    // `RopQueryRows`: its id, handle index, ReturnValue, Origin, RowCount, then the rows.
    let mut rows = vec![0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    rows.extend_from_slice(&stream[..cut]);
    let mut split = [
        (RequestType::Execute, execute(&rows)),
        (RequestType::Execute, get_buffer(&stream[cut..])),
    ];
    let before = split.clone();

    let reported = cnset_bounds(&mut split);
    assert!(reported.iter().all(Vec::is_empty), "{reported:?}");
    assert_eq!(split, before);
}

/// The committed download is read as the rule says: its first response starts a run, its two
/// later buffers join it, and nothing else joins anything.
#[test]
fn the_committed_downloads_runs_are_its_buffers() {
    let scenario = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/exchange-se/sync-en-us");
    let mut names: Vec<_> = std::fs::read_dir(&scenario)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".response.bin"))
        .collect();
    names.sort();
    let responses: Vec<_> = names
        .iter()
        .map(|name| {
            let kind = if name.contains("-execute-") {
                RequestType::Execute
            } else {
                RequestType::Connect
            };
            (kind, std::fs::read(scenario.join(name)).unwrap())
        })
        .collect();

    let joined: Vec<Vec<&str>> = runs(&responses)
        .into_iter()
        .filter(|run| run.len() > 1)
        .map(|run| run.iter().map(|(index, _)| &names[*index][..2]).collect())
        .collect();
    assert_eq!(joined, [["03", "04", "05"]]);
}
