//! The two impure inputs a handshake cannot obtain for itself.
//!
//! NTLM needs a random client challenge and the current time. Neither can be had inside a crate
//! that has no clock and no source of randomness, and this crate has neither on purpose: it is the
//! same boundary `mapi-proto` draws, and for the same reason `mapi-client` generates the
//! `X-RequestId` GUID rather than the codec doing it.
//!
//! The boundary earns its keep immediately. [MS-NLMP] §4.2.4 publishes worked NTLM v2 values, and
//! they are only reproducible with the document's own client challenge and timestamp — so a
//! handshake that took its entropy from the environment could not be checked against the
//! specification at all. The test that pins `NTProofStr` is possible because this type exists.

use core::time::Duration;

/// The number of 100-nanosecond intervals between 1601-01-01 and 1970-01-01 UTC.
///
/// [MS-DTYP] §2.3.3 — `FILETIME` counts from 1601; the Unix epoch is 11,644,473,600 seconds later.
const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;

/// How many 100-nanosecond intervals there are in a second.
const INTERVALS_PER_SECOND: u64 = 10_000_000;

/// A client challenge and a timestamp, supplied from outside.
///
/// # Where the challenge has to come from
///
/// It must be **eight bytes from a cryptographically secure random source**, fresh for every
/// handshake. It is the client's half of the mutual freshness guarantee: reuse makes two
/// handshakes replayable against each other, and a predictable value lets somebody who can see the
/// exchange precompute against it. `mapi-client` fills it from the operating system's random
/// source.
///
/// [MS-NLMP] §3.1.5.1.2 — "`ChallengeFromClient` to an 8-byte nonce"
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entropy {
    client_challenge: [u8; 8],
    filetime: u64,
}

impl Entropy {
    /// Entropy from a raw challenge and a `FILETIME`.
    ///
    /// The timestamp is only used when the server sends no `MsvAvTimestamp` of its own. When it
    /// does — which every Exchange-era server does — [MS-NLMP] §3.1.5.1.2 requires the server's
    /// value to be echoed rather than the client's to be used, so this field goes unread.
    #[must_use]
    pub const fn new(client_challenge: [u8; 8], filetime: u64) -> Self {
        Self {
            client_challenge,
            filetime,
        }
    }

    /// Entropy from a raw challenge and a duration since the Unix epoch.
    ///
    /// The convenience is worth having because the conversion is a place to get an epoch wrong by
    /// 369 years, silently, in a field a server usually ignores.
    #[must_use]
    pub fn from_unix_time(client_challenge: [u8; 8], since_epoch: Duration) -> Self {
        let seconds = since_epoch.as_secs().saturating_mul(INTERVALS_PER_SECOND);
        // Sub-second precision, in the same 100-nanosecond units.
        let fraction = u64::from(since_epoch.subsec_nanos())
            .checked_div(100)
            .unwrap_or_default();
        Self::new(
            client_challenge,
            UNIX_EPOCH_AS_FILETIME
                .saturating_add(seconds)
                .saturating_add(fraction),
        )
    }

    /// The eight random bytes.
    pub(crate) const fn client_challenge(self) -> [u8; 8] {
        self.client_challenge
    }

    /// The timestamp, as a `FILETIME`.
    pub(crate) const fn filetime(self) -> u64 {
        self.filetime
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_raw_filetime_is_carried_through_unchanged() {
        let entropy = Entropy::new([0xAA; 8], 0x01DD_3EF4_5B8F_7395);
        assert_eq!(entropy.client_challenge(), [0xAA; 8]);
        assert_eq!(entropy.filetime(), 0x01DD_3EF4_5B8F_7395);
    }

    /// The epoch shift, from the one direction that can be checked by hand: the Unix epoch itself
    /// is exactly the constant, and one second later is the constant plus ten million.
    #[test]
    fn the_unix_epoch_converts_to_the_filetime_epoch() {
        let at_epoch = Entropy::from_unix_time([0; 8], Duration::ZERO);
        assert_eq!(at_epoch.filetime(), UNIX_EPOCH_AS_FILETIME);

        let one_second = Entropy::from_unix_time([0; 8], Duration::from_secs(1));
        assert_eq!(one_second.filetime(), UNIX_EPOCH_AS_FILETIME + 10_000_000);

        // Sub-second precision survives, in 100-nanosecond units.
        let tick = Entropy::from_unix_time([0; 8], Duration::from_nanos(700));
        assert_eq!(tick.filetime(), UNIX_EPOCH_AS_FILETIME + 7);

        // A time no clock will reach saturates rather than wrapping into the past.
        let absurd = Entropy::from_unix_time([0; 8], Duration::from_secs(u64::MAX));
        assert_eq!(absurd.filetime(), u64::MAX);
    }

    #[test]
    fn entropy_is_a_value_that_can_be_compared_and_copied() {
        let one = Entropy::new([1; 8], 5);
        assert_eq!(one, Entropy::new([1; 8], 5));
        assert_ne!(one, Entropy::new([2; 8], 5));
        assert_ne!(one, Entropy::new([1; 8], 6));
        assert!(format!("{one:?}").contains("Entropy"));
    }
}
