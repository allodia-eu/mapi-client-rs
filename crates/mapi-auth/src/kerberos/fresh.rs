//! The clock and the randomness a Kerberos message needs, supplied from outside.
//!
//! The same boundary [`crate::Entropy`] draws for NTLM: this crate has no clock and no source of
//! randomness, so every step that writes a message is handed both. One type serves every message —
//! the KDC requests and the AP-REQ alike — and each takes the part of the bytes it needs.

use core::time::Duration;

use crate::kerberos::asn1::KerberosTime;
use crate::kerberos::crypto::CONFOUNDER;

/// The clock and the randomness one message needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fresh {
    /// The time since the Unix epoch, by the caller's clock.
    pub(crate) now: Duration,
    /// Sixty-four bytes from a cryptographically secure source, fresh for every message: four for
    /// a nonce, sixteen for a confounder, thirty-two for a subkey and four for a sequence number,
    /// with eight to spare.
    pub(crate) random: [u8; 64],
}

impl Fresh {
    /// A KDC request's nonce.
    ///
    /// [RFC 4120] §5.4.1 makes it a `UInt32`, but a Windows Server 2025 KDC was measured answering
    /// a nonce with the top bit set — `0xFFFFFFF0`, `0x80000001` — by closing the connection with
    /// no reply at all. It reads the field as an `Int32`, so the top bit is never set here.
    pub(crate) fn nonce(&self) -> u32 {
        self.word(0) & 0x7FFF_FFFF
    }

    /// The confounder for the one encryption a message makes.
    pub(crate) fn confounder(&self) -> [u8; CONFOUNDER] {
        let mut out = [0u8; CONFOUNDER];
        for (slot, byte) in out.iter_mut().zip(self.random.iter().skip(4)) {
            *slot = *byte;
        }
        out
    }

    /// Key material for a subkey of `len` bytes, at most thirty-two.
    pub(crate) fn subkey(&self, len: usize) -> Vec<u8> {
        self.random
            .iter()
            .skip(20)
            .take(len.min(32))
            .copied()
            .collect()
    }

    /// An AP-REQ's initial sequence number.
    pub(crate) fn sequence(&self) -> u32 {
        self.word(52)
    }

    /// The time to put in a message, moved by the offset a skew error taught us.
    pub(crate) fn stamp(&self, offset: i64) -> (KerberosTime, u32) {
        let seconds = self.now.as_secs().saturating_add_signed(offset);
        (KerberosTime::from_unix(seconds), self.now.subsec_micros())
    }

    /// The offset that would have made our clock read `theirs`.
    ///
    /// [RFC 4120] §3.1.5: a client keeps "the difference (offset) between the authtime value and
    /// the local clock" rather than changing the clock. The times this is used with come from a
    /// `KRB-ERROR`, which is not authenticated, so an offset is used for one retry and reported,
    /// never trusted further than that.
    pub(crate) fn offset_to(&self, theirs: KerberosTime) -> i64 {
        let theirs = i64::try_from(theirs.unix()).unwrap_or(i64::MAX);
        let ours = i64::try_from(self.now.as_secs()).unwrap_or(i64::MAX);
        theirs.saturating_sub(ours)
    }

    fn word(&self, at: usize) -> u32 {
        let mut bytes = [0u8; 4];
        for (slot, byte) in bytes.iter_mut().zip(self.random.iter().skip(at)) {
            *slot = *byte;
        }
        u32::from_be_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_part_comes_from_its_own_bytes_and_the_nonce_keeps_to_31_bits() {
        let mut random = [0u8; 64];
        for (at, byte) in random.iter_mut().enumerate() {
            *byte = u8::try_from(at).unwrap();
        }
        random[..4].copy_from_slice(&[0xFF; 4]);
        let fresh = Fresh {
            now: Duration::new(1_000, 123_456_789),
            random,
        };
        assert_eq!(fresh.nonce(), 0x7FFF_FFFF);
        assert_eq!(
            fresh.confounder(),
            core::array::from_fn(|at| u8::try_from(4 + at).unwrap())
        );
        assert_eq!(fresh.subkey(16), (20..36).collect::<Vec<u8>>());
        assert_eq!(fresh.subkey(64).len(), 32);
        assert_eq!(fresh.sequence(), u32::from_be_bytes([52, 53, 54, 55]));
        assert_eq!(fresh.stamp(0), (KerberosTime::from_unix(1_000), 123_456));
        assert_eq!(fresh.stamp(-400).0, KerberosTime::from_unix(600));
        assert_eq!(fresh.stamp(i64::MIN).0, KerberosTime::from_unix(0));
        assert_eq!(fresh.offset_to(KerberosTime::from_unix(1_300)), 300);
        assert_eq!(fresh.offset_to(KerberosTime::from_unix(400)), -600);
        assert_eq!(
            fresh.offset_to(KerberosTime::from_unix(u64::MAX)),
            i64::MAX - 1_000
        );
    }
}
