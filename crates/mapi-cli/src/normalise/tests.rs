use mapi_proto::Payload;

use super::*;

/// A `Connect` success payload with a given retry delay, elapsed time and auxiliary buffer.
fn connect_payload(retry_delay: u32, elapsed: &str, auxiliary: &[u8]) -> Vec<u8> {
    let mut payload = format!("PROCESSING\r\nDONE\r\nX-ElapsedTime: {elapsed}\r\n\r\n")
        .as_bytes()
        .to_vec();
    payload.extend_from_slice(&0_u32.to_le_bytes()); // StatusCode
    payload.extend_from_slice(&0_u32.to_le_bytes()); // ErrorCode
    payload.extend_from_slice(&60_000_u32.to_le_bytes()); // PollsMax
    payload.extend_from_slice(&6_u32.to_le_bytes()); // RetryCount
    payload.extend_from_slice(&retry_delay.to_le_bytes()); // RetryDelay
    payload.extend_from_slice(b"/o=Lab\0"); // DnPrefix
    payload.extend_from_slice(&[0x41, 0x00, 0x00, 0x00]); // DisplayName: "A", then NUL
    payload.extend_from_slice(&u32::try_from(auxiliary.len()).expect("small").to_le_bytes());
    payload.extend_from_slice(auxiliary);
    payload
}

/// An `Execute` payload whose ROP buffer holds one `RopLogon` response.
fn logon_payload(logon_time: [u8; 16]) -> Vec<u8> {
    let mut rops = vec![ROP_LOGON, 0x00];
    rops.extend_from_slice(&0_u32.to_le_bytes()); // ReturnValue
    rops.push(0x01); // LogonFlags
    for index in 0..13_u64 {
        rops.extend_from_slice(&(0x0100_0000_0000_0000 | index).to_le_bytes());
    }
    rops.push(0x01); // ResponseFlags
    rops.extend_from_slice(&[0xAB; 16]); // MailboxGuid
    rops.extend_from_slice(&1_u16.to_le_bytes()); // ReplId
    rops.extend_from_slice(&[0xCD; 16]); // ReplGuid
    rops.extend_from_slice(&logon_time); // LogonTime and GwartTime
    rops.extend_from_slice(&0_u32.to_le_bytes()); // StoreState

    let mut buffer = vec![0x00, 0x00, 0x04, 0x00]; // Version, Flags = Last
    let size = u16::try_from(rops.len().saturating_add(2)).expect("a small buffer");
    buffer.extend_from_slice(&size.to_le_bytes()); // Size
    buffer.extend_from_slice(&size.to_le_bytes()); // SizeActual
    buffer.extend_from_slice(&size.to_le_bytes()); // RopSize
    buffer.extend_from_slice(&rops);
    buffer.extend_from_slice(&0_u32.to_le_bytes()); // one handle

    let mut payload = b"PROCESSING\r\nDONE\r\nX-ElapsedTime: 7\r\n\r\n".to_vec();
    payload.extend_from_slice(&0_u32.to_le_bytes()); // StatusCode
    payload.extend_from_slice(&0_u32.to_le_bytes()); // ErrorCode
    payload.extend_from_slice(&0_u32.to_le_bytes()); // Flags
    payload.extend_from_slice(&u32::try_from(buffer.len()).expect("small").to_le_bytes());
    payload.extend_from_slice(&buffer);
    payload.extend_from_slice(&0_u32.to_le_bytes()); // AuxiliaryBufferSize
    payload
}

/// The property this whole module exists for, and the only one worth stating as a test: two
/// captures of the same exchange, taken at different moments, with different server-chosen numbers
/// and different auxiliary buffers, come out byte-identical.
#[test]
fn two_captures_of_the_same_connect_normalise_to_the_same_bytes() {
    let mut first = connect_payload(13_314, "5", b"AUX-BLOCK-ONE-longer");
    let mut second = connect_payload(13_687, "12", b"AUX-TWO");
    assert_ne!(first, second, "they differ before normalising");

    let changed = response(RequestType::Connect, &mut first);
    response(RequestType::Connect, &mut second);

    assert_eq!(first, second);
    assert_eq!(changed.len(), 3, "{changed:?}");
    assert!(changed.iter().any(|what| what.contains("X-ElapsedTime")));
    assert!(changed.iter().any(|what| what.contains("RetryDelay")));
    assert!(changed.iter().any(|what| what.contains("auxiliary buffer")));
}

/// An elapsed time of `5` and one of `12` are different widths, so zeroing in place would leave
/// two captures still differing — in the number of zeros. This is the case that made the preamble
/// canonical rather than merely blanked.
#[test]
fn preamble_values_of_different_widths_end_up_the_same_width() {
    let mut narrow = connect_payload(0, "5", b"");
    let mut wide = connect_payload(0, "123456", b"");

    response(RequestType::Connect, &mut narrow);
    response(RequestType::Connect, &mut wide);

    assert_eq!(narrow, wide);
    let text = String::from_utf8_lossy(&narrow).into_owned();
    assert!(text.contains("X-ElapsedTime: 0\r\n\r\n"), "{text}");
    assert!(text.starts_with("PROCESSING\r\nDONE\r\n"), "{text}");
}

/// The auxiliary buffer is removed, not zeroed: its length varies too, so keeping it would keep
/// the instability. What is left has to still say `AuxiliaryBufferSize = 0`.
#[test]
fn the_auxiliary_buffer_is_replaced_with_an_empty_one() {
    let mut payload = connect_payload(0, "0", &[0xAB; 269]);
    let before = payload.len();

    let changed = response(RequestType::Connect, &mut payload);

    assert_eq!(payload.len(), before - 269);
    assert!(changed.iter().any(|what| what.contains("auxiliary buffer")));
    assert_eq!(payload.get(payload.len() - 4..), Some(&[0, 0, 0, 0][..]));

    // Idempotent: normalising an already-normalised capture reports nothing and changes nothing.
    let again = payload.clone();
    let changed = response(RequestType::Connect, &mut payload);
    assert_eq!(payload, again);
    assert!(changed.is_empty(), "{changed:?}");
}

/// A normalised payload still parses, which is what makes it usable as a fixture at all.
#[test]
fn a_normalised_payload_still_decodes() {
    let mut payload = logon_payload([0xEE; 16]);
    response(RequestType::Execute, &mut payload);

    let parsed = Payload::parse(&payload);
    assert_eq!(parsed.headers().get("X-ElapsedTime"), Some("0"));

    let rop_start = body_offset(&payload).expect("a preamble") + EXECUTE_ROP_LIST;
    assert_eq!(payload.get(rop_start), Some(&ROP_LOGON));
    assert_eq!(
        payload.get(rop_start + LOGON_TIMES..rop_start + LOGON_TIMES + LOGON_TIMES_LEN),
        Some(&[0_u8; 16][..])
    );
    // The GUIDs on either side of the zeroed range are untouched.
    assert_eq!(payload.get(rop_start + 112), Some(&0xAB));
    assert_eq!(payload.get(rop_start + 145), Some(&0xCD));
    assert_eq!(
        payload.get(rop_start + LOGON_TIMES + LOGON_TIMES_LEN),
        Some(&0x00),
        "StoreState follows"
    );

    // Idempotent: normalising an already-normalised logon reports nothing and changes nothing.
    let again = payload.clone();
    let changed = response(RequestType::Execute, &mut payload);
    assert_eq!(payload, again);
    assert!(changed.is_empty(), "{changed:?}");
}

/// The anchors, which are what stop a wrong guess from corrupting a capture.
#[test]
fn a_payload_that_does_not_match_the_layout_is_left_alone() {
    // An `Execute` that is not a logon: the opcode anchor fails.
    let mut not_a_logon = logon_payload([0xEE; 16]);
    let rop_start = body_offset(&not_a_logon).expect("a preamble") + EXECUTE_ROP_LIST;
    if let Some(byte) = not_a_logon.get_mut(rop_start) {
        *byte = 0x15; // RopQueryRows
    }
    let before = not_a_logon.clone();
    let changed = response(RequestType::Execute, &mut not_a_logon);
    let body = body_offset(&before).expect("a preamble");
    assert_eq!(
        not_a_logon.get(body..),
        before.get(body..),
        "the body was changed by {changed:?}"
    );

    // A `Connect` whose StatusCode is non-zero: nothing past it means anything, so no offset in
    // this module may be used.
    let mut refused = connect_payload(13_314, "5", b"AUX");
    let body = body_offset(&refused).expect("a preamble");
    if let Some(field) = refused.get_mut(body..body + 4) {
        field.copy_from_slice(&1_u32.to_le_bytes());
    }
    let before = refused.clone();
    response(RequestType::Connect, &mut refused);
    assert_eq!(refused.get(body..), before.get(body..));
}

/// An auxiliary buffer whose declared size disagrees with what is there is not the field it was
/// taken for, so it is left alone rather than truncated to a guess.
#[test]
fn a_size_that_disagrees_with_the_bytes_is_not_trusted() {
    let mut payload = connect_payload(0, "0", &[0xAB; 8]);
    let at = connect_auxiliary_size_at(&payload, body_offset(&payload).expect("preamble"))
        .expect("an auxiliary size field");
    if let Some(field) = payload.get_mut(at..at + 4) {
        field.copy_from_slice(&99_u32.to_le_bytes()); // claims 99, carries 8
    }

    let before = payload.clone();
    let changed = auxiliary(&mut payload, Some(at));
    assert_eq!(payload, before);
    assert!(changed.is_empty());
}

/// Truncated and preamble-less payloads are exactly what a misbehaving deployment sends, and this
/// runs against those before anything has decided they are well formed.
#[test]
fn nothing_here_panics_on_a_payload_that_makes_no_sense() {
    for raw in [
        &b""[..],
        &b"DONE"[..],
        &b"DONE\r\n\r\n"[..],
        &b"PROCESSING\r\nDONE\r\nX-StartTime: \r\n\r\n"[..],
        &b"PROCESSING\r\nDONE\r\n\r\n\x00\x00\x00\x00"[..],
        &b"<html><p>MAPI is not enabled</p></html>"[..],
        &[0xFF, 0xFE, 0x00][..],
    ] {
        for request_type in [
            RequestType::Connect,
            RequestType::Execute,
            RequestType::Disconnect,
            RequestType::Ping,
        ] {
            let mut payload = raw.to_vec();
            let _ = response(request_type, &mut payload);
        }
    }
}

/// A `PING` has no body at all, so there is nothing but the preamble to normalise.
#[test]
fn a_ping_normalises_only_its_preamble() {
    let mut payload = b"PROCESSING\r\nDONE\r\nX-ElapsedTime: 3\r\n\
                        X-StartTime: Sun, 02 Aug 2026 14:15:40 GMT\r\n\r\n"
        .to_vec();
    let changed = response(RequestType::Ping, &mut payload);

    assert_eq!(changed.len(), 2, "{changed:?}");
    let text = String::from_utf8_lossy(&payload).into_owned();
    assert_eq!(
        text,
        "PROCESSING\r\nDONE\r\nX-ElapsedTime: 0\r\nX-StartTime: 0\r\n\r\n"
    );
}

/// A preamble with nothing volatile in it is left byte-for-byte alone, rather than rebuilt into
/// something equivalent — which would be a silent difference for `Verify-Fixtures.ps1` to report.
#[test]
fn a_preamble_with_nothing_to_change_is_not_rewritten() {
    let mut payload =
        b"PROCESSING\r\nPENDING\r\nDONE\r\nX-PendingPeriod: 30000\r\n\r\n\x01\x02".to_vec();
    let before = payload.clone();
    assert!(response(RequestType::Ping, &mut payload).is_empty());
    assert_eq!(payload, before);
}
