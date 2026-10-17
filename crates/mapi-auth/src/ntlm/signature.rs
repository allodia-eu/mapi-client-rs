//! The NTLM message signature, for the one place this crate needs one: SPNEGO's `mechListMIC`.
//!
//! [MS-SPNG] §3.1.5.1 note `<8>` makes the `mechListMIC` mandatory when NTLM is the preferred
//! mechanism and the `AUTHENTICATE_MESSAGE` carries a MIC — which this crate's does whenever the
//! server timestamps its challenge. The MIC is the mechanism's own `GSS_GetMIC` over the
//! `MechTypeList`, and for NTLM that is an `NTLMSSP_MESSAGE_SIGNATURE`.

use crate::ntlm::NegotiateFlags;

/// Every signature is this long, in both of [MS-NLMP] §2.2.2.9's layouts.
const LEN: usize = 16;

/// The signature this session can produce, or `None` if it cannot produce one.
///
/// [MS-NLMP] §3.4.4.3: when `NTLMSSP_NEGOTIATE_ALWAYS_SIGN` is set and `NTLMSSP_NEGOTIATE_SIGN` is
/// not, the signature is a `Version` of 1 with every other byte zero. That is this crate's session
/// exactly — [`NegotiateFlags::REQUESTED`] asks for `ALWAYS_SIGN` and never for `SIGN` — so the
/// signature is the same sixteen bytes whatever is being signed, which is why this takes no
/// message. It is still what the document defines, and what a conforming verifier compares against.
///
/// `SIGN` is refused rather than signed for. With it, §3.4.4.2 computes an HMAC over the message
/// under a key derived from the session key, and §3.1.5.1.2 makes that key RC4-wrapped whenever
/// `KEY_EXCH` comes along with it. Nothing this crate sends can negotiate either flag, so a session
/// with `SIGN` in it is not one this crate made, and answering it with the §3.4.4.3 form would be a
/// signature the other side rejects.
pub(crate) fn signature(flags: NegotiateFlags) -> Option<[u8; LEN]> {
    if flags.contains(NegotiateFlags::ALWAYS_SIGN) && !flags.contains(NegotiateFlags::SIGN) {
        let mut signature = [0u8; LEN];
        if let Some(version) = signature.get_mut(..4) {
            version.copy_from_slice(&1u32.to_le_bytes());
        }
        Some(signature)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_sign_without_sign_is_version_one_and_nothing_else() {
        let dummy = signature(NegotiateFlags::ALWAYS_SIGN).unwrap();
        assert_eq!(
            dummy,
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "§3.4.4.3: Version 1, RandomPad, Checksum and SeqNum all zero"
        );

        // The flags this crate actually negotiates, against the documented example's challenge.
        let negotiated =
            NegotiateFlags::REQUESTED.intersection(NegotiateFlags::from_bits(0xE28A_8233));
        assert_eq!(signature(negotiated), Some(dummy));
    }

    /// Without a session key guarantee there is nothing to sign with, and with `SIGN` the
    /// signature is an HMAC this crate does not compute. Neither is answered with the dummy.
    #[test]
    fn a_session_without_always_sign_or_with_sign_has_no_signature_here() {
        assert_eq!(signature(NegotiateFlags::from_bits(0)), None);
        assert_eq!(
            signature(NegotiateFlags::ALWAYS_SIGN.union(NegotiateFlags::SIGN)),
            None
        );
    }

    /// The precondition the dummy rests on, held where it can break: nothing this crate requests
    /// can bring `SIGN` into a session, whatever the server offers.
    #[test]
    fn no_challenge_can_put_sign_into_a_session_this_crate_negotiates() {
        let everything = NegotiateFlags::from_bits(u32::MAX);
        let negotiated = NegotiateFlags::REQUESTED.intersection(everything);
        assert!(!negotiated.contains(NegotiateFlags::SIGN));
        assert!(!negotiated.contains(NegotiateFlags::KEY_EXCH));
        assert!(negotiated.contains(NegotiateFlags::ALWAYS_SIGN));
    }
}
