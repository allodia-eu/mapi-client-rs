//! Removing the handful of things that differ on every capture.
//!
//! A fixture exists so that a difference means something. If a re-capture always differed —
//! because a clock moved, or because a server picked a fresh random number — then
//! `Verify-Fixtures.ps1` would have to explain away its own output every time it ran, and the one
//! difference that mattered would be lost in the noise. So "any difference at all is a finding"
//! is the rule, and this module is what earns it.
//!
//! Four things qualify, each **measured** against Exchange Server SE `15.02.2562.045` rather than
//! assumed:
//!
//! * `X-ElapsedTime` and `X-StartTime` in the response preamble — how long the server took, and
//!   when it started. Rewritten to a single `0`, which is also the only normalisation here that
//!   changes a length: two captures whose elapsed times were `5` and `12` would otherwise still
//!   differ after being zeroed, in the width of the zeros.
//! * `Connect`'s `RetryDelay`, observed as 13314, 13687 and 13835 ms on three consecutive connects
//!   to the same server. It is per-connection advice, not a server constant.
//! * `RopLogon`'s `LogonTime` and `GwartTime` — the moment of the logon.
//! * The **response auxiliary buffer**, which is removed entirely.
//!
//! # The auxiliary buffer, and why it goes
//!
//! Every request this workspace sends carries `AuxiliaryBufferSize = 0`, which Exchange accepts.
//! The *response* is a different matter and is worth stating plainly, because the request-side
//! finding is easy to over-read: a `Connect` response carries a substantial auxiliary buffer —
//! 269 bytes on success and 1438 on a refusal, measured on `15.02.2562.045` — while an `Execute`
//! response carries none.
//!
//! Its contents are `AUX_*` blocks holding the server's fully qualified name and per-connection
//! timings, so it is volatile *and* it is a redaction surface that no scrub rule can cover, since
//! nothing here knows what a future server might put in there. Its length varies too, so zeroing
//! it in place would not make two captures agree.
//!
//! It is therefore replaced with an empty one — `AuxiliaryBufferSize = 0` and nothing after it.
//! The codec reads that field and stops, so a normalised capture decodes exactly as the original
//! did, and `mapi-proto` keeps a unit test that a *non-empty* auxiliary buffer is skipped
//! correctly, because that is the one claim the corpus can no longer make.
//!
//! Nothing here can corrupt a capture by guessing wrong: every offset is checked against an anchor
//! the layout guarantees — a zero `StatusCode`, a `RopLogon` opcode — and a payload that does not
//! match is left exactly as it arrived.
//!
//! [MS-OXCMAPIHTTP] §2.2.7 — response meta-tags
//! [MS-OXCMAPIHTTP] §2.2.4.1.2 — `Connect` success response body
//! [MS-OXCMAPIHTTP] §2.2.4.2.2 — `Execute` success response body
//! [MS-OXCSTOR] §2.2.1.1.3 — `RopLogon` success response buffer

use mapi_proto::RequestType;

/// The preamble headers whose values are the server's own clock.
///
/// [MS-OXCMAPIHTTP] §2.2.7
const VOLATILE_META_TAGS: [&str; 2] = ["X-ElapsedTime", "X-StartTime"];

/// What a volatile preamble value is rewritten to. Fixed width on purpose — see the module
/// documentation.
const CANONICAL_VALUE: &str = "0";

/// `RopLogon`'s opcode, the anchor that says a logon response really is at this offset.
///
/// [MS-OXCROPS] §2.2.3.1
const ROP_LOGON: u8 = 0xFE;

/// Where `RetryDelay` sits in a `Connect` body: after `StatusCode`, `ErrorCode`, `PollsMax` and
/// `RetryCount`, all `u32`.
const CONNECT_RETRY_DELAY: usize = 16;

/// Where `DnPrefix` starts in a `Connect` body: after those five `u32`s.
const CONNECT_DN_PREFIX: usize = 20;

/// Where the ROP list starts in an `Execute` success body: `StatusCode`, `ErrorCode`, `Flags` and
/// `RopBufferSize` (16), then `RPC_HEADER_EXT` (8) and `RopSize` (2).
const EXECUTE_ROP_LIST: usize = 26;

/// Where `RopBufferSize` sits in an `Execute` body.
const EXECUTE_ROP_BUFFER_SIZE: usize = 12;

/// Where `LogonTime` sits in a `RopLogon` response, and how many bytes it and `GwartTime` occupy
/// together: `RopId`, `OutputHandleIndex` and `ReturnValue` (6), `LogonFlags` (1), thirteen
/// `FolderId`s (104), `ResponseFlags` (1), `MailboxGuid` (16), `ReplId` (2), `ReplGuid` (16).
const LOGON_TIMES: usize = 146;
const LOGON_TIMES_LEN: usize = 16;

/// Normalises a response payload, reporting everything it changed.
///
/// The payload is the whole thing an HTTP client handed over: preamble first, then the body.
pub(crate) fn response(request_type: RequestType, payload: &mut Vec<u8>) -> Vec<String> {
    // First, because it can change the payload's length and therefore every offset below it.
    let mut changed = preamble(payload);

    let Some(body) = body_offset(payload) else {
        return changed;
    };

    match request_type {
        RequestType::Connect => {
            changed.extend(retry_delay(payload, body));
            let at = connect_auxiliary_size_at(payload, body);
            changed.extend(auxiliary(payload, at));
        }
        RequestType::Execute => {
            changed.extend(logon_times(payload, body));
            let at = execute_auxiliary_size_at(payload, body);
            changed.extend(auxiliary(payload, at));
        }
        _ => {}
    }

    changed
}

/// Where the body starts: after the meta-tag preamble's blank line.
///
/// `None` when there is no preamble at all, which is what an HTML error page looks like.
fn body_offset(payload: &[u8]) -> Option<usize> {
    let starts_preamble = [&b"PROCESSING"[..], b"PENDING", b"DONE"]
        .into_iter()
        .any(|tag| payload.starts_with(tag));
    if !starts_preamble {
        return None;
    }

    let end = payload
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    end.checked_add(4)
}

/// Rewrites the volatile preamble headers to a canonical value.
fn preamble(payload: &mut Vec<u8>) -> Vec<String> {
    let Some(end) = body_offset(payload) else {
        return Vec::new();
    };
    let Some(original) = payload.get(..end) else {
        return Vec::new();
    };

    let mut changed = Vec::new();
    let mut rebuilt: Vec<u8> = Vec::with_capacity(end);

    // Split on CRLF and keep every line, including the empty one that ends the preamble, so that
    // rebuilding is exactly the inverse of splitting for anything not rewritten.
    for line in original.split(|&byte| byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let text = String::from_utf8_lossy(line);

        let volatile = text.split_once(':').filter(|(name, _)| {
            VOLATILE_META_TAGS
                .iter()
                .any(|volatile| volatile.eq_ignore_ascii_case(name.trim()))
        });

        if let Some((name, value)) = volatile {
            let name = name.trim();
            rebuilt.extend_from_slice(format!("{name}: {CANONICAL_VALUE}\r\n").as_bytes());
            // Reported only when it actually moved. Normalising is idempotent, and a second pass
            // that claimed to have changed something would make an already-normalised capture look
            // freshly edited.
            if value.trim() != CANONICAL_VALUE {
                changed.push(format!(
                    "response preamble: `{name}` value replaced with `{CANONICAL_VALUE}` \
                     ([MS-OXCMAPIHTTP] §2.2.7)"
                ));
            }
        } else {
            rebuilt.extend_from_slice(line);
            rebuilt.extend_from_slice(b"\r\n");
        }
    }

    // `split` on the final `\n` yields a trailing empty piece, which the loop turned into one CRLF
    // too many. Drop it rather than let the blank line that ends the preamble double.
    rebuilt.truncate(rebuilt.len().saturating_sub(2));

    if changed.is_empty() {
        return changed;
    }

    let mut normalised = rebuilt;
    normalised.extend_from_slice(payload.get(end..).unwrap_or_default());
    *payload = normalised;
    changed
}

/// Zeroes `Connect`'s `RetryDelay`, which the server re-rolls for every connection.
fn retry_delay(payload: &mut [u8], body: usize) -> Vec<String> {
    if u32_at(payload, body) != Some(0) {
        return Vec::new();
    }

    let start = body.saturating_add(CONNECT_RETRY_DELAY);
    let Some(field) = payload.get_mut(start..start.saturating_add(4)) else {
        return Vec::new();
    };
    if field == [0; 4] {
        return Vec::new();
    }
    field.fill(0);

    vec![
        "response body: `RetryDelay` zeroed, because the server re-rolls it for every connection \
         ([MS-OXCMAPIHTTP] §2.2.4.1.2)"
            .to_owned(),
    ]
}

/// Zeroes `RopLogon`'s `LogonTime` and `GwartTime`, when this `Execute` carried a logon at all.
fn logon_times(payload: &mut [u8], body: usize) -> Vec<String> {
    if !succeeded(payload, body) {
        return Vec::new();
    }

    let rop = body.saturating_add(EXECUTE_ROP_LIST);
    // The anchors: the first ROP in the buffer really is a `RopLogon`, and it really succeeded —
    // a failed one stops right after `ReturnValue` and has no timestamps to zero.
    if payload.get(rop) != Some(&ROP_LOGON) || u32_at(payload, rop.saturating_add(2)) != Some(0) {
        return Vec::new();
    }

    let start = rop.saturating_add(LOGON_TIMES);
    let Some(field) = payload.get_mut(start..start.saturating_add(LOGON_TIMES_LEN)) else {
        return Vec::new();
    };
    // Reported only when it actually moved, for the same reason `retry_delay` is: normalising is
    // idempotent, and a second pass that claimed to have changed something would make an
    // already-normalised capture look freshly edited.
    if field == [0; LOGON_TIMES_LEN] {
        return Vec::new();
    }
    field.fill(0);

    vec![format!(
        "response body: `RopLogon` `LogonTime` and `GwartTime` zeroed, {LOGON_TIMES_LEN} bytes at \
         +{LOGON_TIMES} of the ROP ([MS-OXCSTOR] §2.2.1.1.3)"
    )]
}

/// Where a `Connect` response's `AuxiliaryBufferSize` is, by walking the two variable-length
/// fields in front of it.
///
/// [MS-OXCMAPIHTTP] §2.2.4.1.2 — `DnPrefix`, `DisplayName`
fn connect_auxiliary_size_at(payload: &[u8], body: usize) -> Option<usize> {
    if u32_at(payload, body) != Some(0) {
        return None;
    }

    // DnPrefix: 8-bit characters, NUL terminated.
    let from = body.checked_add(CONNECT_DN_PREFIX)?;
    let tail = payload.get(from..)?;
    let after_prefix = from
        .checked_add(tail.iter().position(|&byte| byte == 0)?)?
        .checked_add(1)?;

    // DisplayName: UTF-16LE, NUL-NUL terminated, and only on an even offset from its own start.
    let name = payload.get(after_prefix..)?;
    let end = name
        .chunks_exact(2)
        .position(|unit| unit == [0, 0])?
        .checked_mul(2)?
        .checked_add(2)?;

    after_prefix.checked_add(end)
}

/// Where an `Execute` response's `AuxiliaryBufferSize` is: after the ROP buffer it declares.
///
/// [MS-OXCMAPIHTTP] §2.2.4.2.2
fn execute_auxiliary_size_at(payload: &[u8], body: usize) -> Option<usize> {
    if !succeeded(payload, body) {
        return None;
    }
    let size = u32_at(payload, body.checked_add(EXECUTE_ROP_BUFFER_SIZE)?)?;
    body.checked_add(16)?
        .checked_add(usize::try_from(size).ok()?)
}

/// Replaces the auxiliary buffer with an empty one. See the module documentation for why.
fn auxiliary(payload: &mut Vec<u8>, size_at: Option<usize>) -> Vec<String> {
    let Some(at) = size_at else {
        return Vec::new();
    };
    let Some(size) = u32_at(payload, at).filter(|size| *size > 0) else {
        return Vec::new();
    };

    let end = at.saturating_add(4);
    // The declared size has to match what is actually there; if it does not, this is not the field
    // it was taken for and nothing is touched.
    if payload.len().checked_sub(end) != usize::try_from(size).ok() {
        return Vec::new();
    }

    if let Some(field) = payload.get_mut(at..end) {
        field.fill(0);
    }
    payload.truncate(end);

    vec![
        "response body: the auxiliary buffer was replaced with an empty one. A real server sends \
         one carrying its own fully qualified name and per-connection timings, which vary in both \
         content and length; the codec reads `AuxiliaryBufferSize` and stops, so this decodes \
         identically ([MS-OXCMAPIHTTP] §2.2.4.1.2)"
            .to_owned(),
    ]
}

/// Whether a response body's `StatusCode` and `ErrorCode` are both zero.
///
/// Every layout offset past those two fields is only meaningful when they are.
fn succeeded(payload: &[u8], body: usize) -> bool {
    u32_at(payload, body) == Some(0) && u32_at(payload, body.saturating_add(4)) == Some(0)
}

fn u32_at(payload: &[u8], at: usize) -> Option<u32> {
    let bytes: [u8; 4] = payload.get(at..at.saturating_add(4))?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests;
