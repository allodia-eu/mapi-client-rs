//! The `AV_PAIR` list a server sends in `TargetInfo` and a client sends back inside its response.
//!
//! The list is not metadata. It travels back inside the `NTLMv2_CLIENT_CHALLENGE` and is covered by
//! the `NTProofStr`, so a pair added, dropped or reordered between reading and writing changes the
//! proof and the server rejects the credential. That is why this parses into an ordered list and
//! re-encodes it in the order it arrived, rather than into a map.
//!
//! [MS-NLMP] §2.2.2.1 — `AV_PAIR`

use crate::error::{Error, Result};

/// The end of the list. `AvLen` is zero and nothing follows.
pub(crate) const EOL: u16 = 0x0000;
/// The server's NetBIOS computer name, in UTF-16LE.
pub(crate) const NB_COMPUTER_NAME: u16 = 0x0001;
/// The server's NetBIOS domain name, in UTF-16LE.
pub(crate) const NB_DOMAIN_NAME: u16 = 0x0002;
/// A 32-bit value carrying the client and server configuration bits.
pub(crate) const FLAGS: u16 = 0x0006;
/// The server's local time as a `FILETIME`, little-endian.
pub(crate) const TIMESTAMP: u16 = 0x0007;
/// The service principal name of the target server, in UTF-16LE.
pub(crate) const TARGET_NAME: u16 = 0x0009;
/// The MD5 of a `gss_channel_bindings_struct`.
pub(crate) const CHANNEL_BINDINGS: u16 = 0x000A;

/// `MsvAvFlags` bit 0x2: this client is providing a MIC.
///
/// [MS-NLMP] §2.2.2.1 — the `MsvAvFlags` value
pub(crate) const FLAG_MIC_PROVIDED: u32 = 0x0000_0002;

/// An ordered `AV_PAIR` list, without its terminator.
///
/// The terminator is not held as a pair because it is not one: it is the encoding's end marker, and
/// keeping it in the list would make "append a pair" mean "append after the end".
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct AvPairs {
    pairs: Vec<(u16, Vec<u8>)>,
}

/// Every pair type [MS-NLMP] §2.2.2.1 names, so that a list prints as what it is.
const NAMES: [(u16, &str); 9] = [
    (NB_COMPUTER_NAME, "MsvAvNbComputerName"),
    (NB_DOMAIN_NAME, "MsvAvNbDomainName"),
    (0x0003, "MsvAvDnsComputerName"),
    (0x0004, "MsvAvDnsDomainName"),
    (0x0005, "MsvAvDnsTreeName"),
    (FLAGS, "MsvAvFlags"),
    (TIMESTAMP, "MsvAvTimestamp"),
    (TARGET_NAME, "MsvAvTargetName"),
    (CHANNEL_BINDINGS, "MsvAvChannelBindings"),
];

/// Prints each pair by its `MsvAv…` name, with text values as text.
///
/// A handshake that fails is diagnosed by looking at this list — which pairs the server sent,
/// whether a timestamp was among them, whether the channel binding went out — and a column of
/// numbered byte strings does not answer any of those questions.
impl core::fmt::Debug for AvPairs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut list = f.debug_map();
        for (id, value) in &self.pairs {
            let name = NAMES
                .iter()
                .find(|(known, _)| known == id)
                .map_or_else(|| format!("AvId {id:#06X}"), |(_, name)| (*name).to_owned());
            match core::str::from_utf8(value) {
                Ok(text) if !text.is_empty() => list.entry(&name, &text),
                _ => list.entry(&name, &format_args!("{value:02X?}")),
            };
        }
        list.finish()
    }
}

impl AvPairs {
    /// Reads a list, stopping at the terminator.
    ///
    /// Bytes after the terminator are ignored rather than refused. A server is entitled to pad its
    /// payload, and a client that rejected padding would fail against a deployment that works.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut pairs = Vec::new();
        let mut at = 0usize;

        loop {
            let header = bytes
                .get(at..at.saturating_add(4))
                .ok_or(Error::Truncated {
                    structure: "TargetInfo",
                    field: "an AV_PAIR header",
                    offset: at,
                    len: bytes.len(),
                })?;
            let id =
                u16::from_le_bytes([*header.first().unwrap_or(&0), *header.get(1).unwrap_or(&0)]);
            let len = usize::from(u16::from_le_bytes([
                *header.get(2).unwrap_or(&0),
                *header.get(3).unwrap_or(&0),
            ]));

            if id == EOL {
                return Ok(Self { pairs });
            }

            let start = at.saturating_add(4);
            let end = start.saturating_add(len);
            let value = bytes.get(start..end).ok_or(Error::Truncated {
                structure: "TargetInfo",
                field: "an AV_PAIR value",
                offset: start,
                len: bytes.len(),
            })?;
            pairs.push((id, value.to_vec()));
            at = end;
        }
    }

    /// The value of the first pair with this id.
    pub(crate) fn get(&self, id: u16) -> Option<&[u8]> {
        self.pairs
            .iter()
            .find(|(found, _)| *found == id)
            .map(|(_, value)| value.as_slice())
    }

    /// Adds a pair at the end of the list.
    pub(crate) fn push(&mut self, id: u16, value: impl Into<Vec<u8>>) {
        self.pairs.push((id, value.into()));
    }

    /// Turns a bit on in `MsvAvFlags`, adding the pair if the server did not send one.
    ///
    /// [MS-NLMP] §3.1.5.1.2 states it in exactly this shape — "if there is an `AV_PAIR` with
    /// `MsvAvFlags`, set bit 0x2; else add one" — because the pair is optional in the challenge and
    /// mandatory once a MIC is provided.
    pub(crate) fn set_flag(&mut self, bit: u32) {
        if let Some((_, value)) = self.pairs.iter_mut().find(|(id, _)| *id == FLAGS) {
            let current = read_u32(value);
            *value = (current | bit).to_le_bytes().to_vec();
            return;
        }
        self.pairs.push((FLAGS, bit.to_le_bytes().to_vec()));
    }

    /// The list on the wire, terminated.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (id, value) in &self.pairs {
            out.extend_from_slice(&id.to_le_bytes());
            // A pair whose value will not fit a 16-bit length cannot be encoded; truncating it
            // would produce a list the server parses differently from the one that was meant, so
            // the length saturates and the server rejects a proof computed over the wrong bytes
            // rather than this silently sending something else. No such value exists in practice:
            // every pair this crate adds is a name or a 16-byte hash.
            let len = u16::try_from(value.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(value.get(..usize::from(len)).unwrap_or_default());
        }
        out.extend_from_slice(&EOL.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }
}

/// Reads a little-endian `u32` from a value that a server chose the length of.
///
/// A `MsvAvFlags` shorter than four bytes is malformed, but it is the server's malformation and it
/// arrives on the way to a successful logon; reading what is there and zero-filling the rest keeps
/// the handshake going where refusing would strand it.
fn read_u32(value: &[u8]) -> u32 {
    let mut bytes = [0u8; 4];
    for (slot, byte) in bytes.iter_mut().zip(value.iter()) {
        *slot = *byte;
    }
    u32::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [MS-NLMP] §4.2.4.3 prints this list inside its worked `CHALLENGE_MESSAGE`: a NetBIOS domain
    /// name, a NetBIOS computer name, and the terminator.
    fn documented_list() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x02, 0x00, 0x0C, 0x00]);
        bytes.extend_from_slice(b"D\0o\0m\0a\0i\0n\0");
        bytes.extend_from_slice(&[0x01, 0x00, 0x0C, 0x00]);
        bytes.extend_from_slice(b"S\0e\0r\0v\0e\0r\0");
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        bytes
    }

    #[test]
    fn the_documented_list_round_trips_byte_for_byte() {
        let bytes = documented_list();
        let pairs = AvPairs::parse(&bytes).unwrap();

        assert_eq!(pairs.get(NB_DOMAIN_NAME), Some(&b"D\0o\0m\0a\0i\0n\0"[..]));
        assert_eq!(
            pairs.get(NB_COMPUTER_NAME),
            Some(&b"S\0e\0r\0v\0e\0r\0"[..])
        );
        assert!(pairs.get(NB_DOMAIN_NAME).is_some());
        assert_eq!(pairs.get(TIMESTAMP), None);

        // Order is preserved, because the re-encoded list is covered by the NTProofStr.
        assert_eq!(pairs.encode(), bytes);
    }

    #[test]
    fn bytes_after_the_terminator_are_ignored_rather_than_refused() {
        let mut padded = documented_list();
        padded.extend_from_slice(&[0xFF; 8]);
        assert_eq!(AvPairs::parse(&padded).unwrap().encode(), documented_list());
    }

    #[test]
    fn a_list_that_runs_off_the_end_is_refused_where_it_stopped() {
        // A header that is only two bytes.
        let error = AvPairs::parse(&[0x02, 0x00]).unwrap_err();
        assert!(matches!(
            error,
            Error::Truncated {
                structure: "TargetInfo",
                field: "an AV_PAIR header",
                offset: 0,
                ..
            }
        ));

        // A value shorter than the length declares.
        let error = AvPairs::parse(&[0x02, 0x00, 0x0C, 0x00, 0x44, 0x00]).unwrap_err();
        assert!(matches!(
            error,
            Error::Truncated {
                field: "an AV_PAIR value",
                offset: 4,
                len: 6,
                ..
            }
        ));

        // A list with no terminator at all, which is the same failure one pair later.
        let mut unterminated = documented_list();
        unterminated.truncate(unterminated.len() - 4);
        assert!(AvPairs::parse(&unterminated).is_err());
    }

    #[test]
    fn setting_the_mic_flag_adds_the_pair_when_the_server_sent_none() {
        let mut pairs = AvPairs::parse(&documented_list()).unwrap();
        assert_eq!(pairs.get(FLAGS), None);

        pairs.set_flag(FLAG_MIC_PROVIDED);
        assert_eq!(pairs.get(FLAGS), Some(&[0x02, 0x00, 0x00, 0x00][..]));

        // The added pair goes after the server's, which is where [MS-NLMP] §3.1.5.1.2 puts it.
        let encoded = pairs.encode();
        assert!(encoded.starts_with(&documented_list()[..documented_list().len() - 4]));
    }

    #[test]
    fn setting_the_mic_flag_preserves_bits_the_server_already_set() {
        let mut bytes = vec![0x06, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let mut pairs = AvPairs::parse(&bytes).unwrap();

        pairs.set_flag(FLAG_MIC_PROVIDED);
        assert_eq!(pairs.get(FLAGS), Some(&[0x03, 0x00, 0x00, 0x00][..]));

        // A short value is zero-filled rather than rejected: it is the server's malformation, and
        // refusing it would strand a handshake that is otherwise on its way to succeeding.
        let short = [0x06, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let mut pairs = AvPairs::parse(&short).unwrap();
        pairs.set_flag(FLAG_MIC_PROVIDED);
        assert_eq!(pairs.get(FLAGS), Some(&[0x03, 0x00, 0x00, 0x00][..]));
    }

    #[test]
    fn appended_pairs_keep_their_order_and_their_ids() {
        let mut pairs = AvPairs::default();
        pairs.push(CHANNEL_BINDINGS, [0xAB; 16]);
        pairs.push(TARGET_NAME, b"H\0T\0T\0P\0".to_vec());

        let encoded = pairs.encode();
        let reread = AvPairs::parse(&encoded).unwrap();
        assert_eq!(reread, pairs);
        assert_eq!(reread.get(CHANNEL_BINDINGS), Some(&[0xAB; 16][..]));
        assert_eq!(reread.get(TARGET_NAME), Some(&b"H\0T\0T\0P\0"[..]));

        // An empty list is just the terminator.
        assert_eq!(AvPairs::default().encode(), vec![0, 0, 0, 0]);
    }

    /// The list is what a failed handshake is diagnosed from, so it has to read as one.
    #[test]
    fn a_list_prints_by_pair_name() {
        let mut pairs = AvPairs::parse(&documented_list()).unwrap();
        pairs.push(TIMESTAMP, [0u8; 8]);
        pairs.push(0x00FF, b"unknown".to_vec());

        let rendered = format!("{pairs:?}");
        assert!(rendered.contains("MsvAvNbDomainName"), "{rendered}");
        assert!(rendered.contains("MsvAvTimestamp"), "{rendered}");
        assert!(rendered.contains("AvId 0x00FF"), "{rendered}");
        assert_eq!(format!("{:?}", AvPairs::default()), "{}");
    }

    #[test]
    fn a_value_too_long_for_the_length_field_is_bounded_rather_than_wrapped() {
        let mut pairs = AvPairs::default();
        pairs.push(TARGET_NAME, vec![0x41; 70_000]);
        let encoded = pairs.encode();
        assert_eq!(encoded.len(), 4 + usize::from(u16::MAX) + 4);
    }
}
