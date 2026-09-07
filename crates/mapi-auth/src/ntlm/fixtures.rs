//! Challenge messages the tests in this module tree share.
//!
//! Both are built rather than included as files: the first is transcribed from a document anyone
//! can open at the section named, and the second is the first with one pair added, so the
//! difference between them is visible in the source rather than in a hex dump.

/// [MS-NLMP] §4.2.4.3's `CHALLENGE_MESSAGE`, byte for byte.
///
/// It is the challenge the published NTLM v2 values were computed against: `TargetName` is
/// `Server`, `TargetInfo` holds a NetBIOS domain and a NetBIOS computer name, and there is
/// deliberately **no** `MsvAvTimestamp` — which is what makes the document's `temp` reproducible.
pub(crate) fn documented_challenge() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"NTLMSSP\0");
    bytes.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x0C, 0x00, 0x0C, 0x00, 0x38, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x33, 0x82, 0x8A, 0xE2]);
    bytes.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    bytes.extend_from_slice(&[0x00; 8]);
    bytes.extend_from_slice(&[0x24, 0x00, 0x24, 0x00, 0x44, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0F]);
    bytes.extend_from_slice(b"S\0e\0r\0v\0e\0r\0");
    bytes.extend_from_slice(&[0x02, 0x00, 0x0C, 0x00]);
    bytes.extend_from_slice(b"D\0o\0m\0a\0i\0n\0");
    bytes.extend_from_slice(&[0x01, 0x00, 0x0C, 0x00]);
    bytes.extend_from_slice(b"S\0e\0r\0v\0e\0r\0");
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    bytes
}

/// The same challenge with an `MsvAvTimestamp` added, which is what a real server sends.
///
/// One pair changes four things at once — the time is taken from the server rather than the
/// caller, the LM response becomes `Z(24)`, a MIC is provided, and `MsvAvFlags` says so — so it
/// earns a fixture of its own rather than being assembled inside each test that needs it.
pub(crate) fn timestamped_challenge() -> Vec<u8> {
    const TARGET_INFO_AT: usize = 68;
    const FILETIME: u64 = 0x01DD_3EF4_5B8F_7395;

    let mut bytes = documented_challenge();
    let mut pairs = bytes.split_off(TARGET_INFO_AT);
    // Drop the terminator, append the timestamp, put the terminator back.
    pairs.truncate(pairs.len().saturating_sub(4));
    pairs.extend_from_slice(&[0x07, 0x00, 0x08, 0x00]);
    pairs.extend_from_slice(&FILETIME.to_le_bytes());
    pairs.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let len = u16::try_from(pairs.len()).unwrap_or(u16::MAX).to_le_bytes();
    bytes.extend_from_slice(&pairs);
    bytes.splice(40..44, [len, len].concat());
    bytes
}

/// The timestamp [`timestamped_challenge`] carries, for a test that checks it was echoed.
pub(crate) const SERVER_FILETIME: u64 = 0x01DD_3EF4_5B8F_7395;
