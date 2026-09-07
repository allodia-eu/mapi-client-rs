//! The third NTLM message: everything the server needs to check the credential.
//!
//! [MS-NLMP] §2.2.1.3 — `AUTHENTICATE_MESSAGE`

use crate::binding::ChannelBinding;
use crate::crypto;
use crate::entropy::Entropy;
use crate::identity::Identity;
use crate::ntlm::flags::NegotiateFlags;
use crate::ntlm::message::{self, ChallengeMessage};
use crate::ntlm::response;

/// Fixed size of the message before its payload, with the MIC field present.
///
/// The MIC is the reason this is 88 rather than 72. [MS-NLMP] §2.2.1.3 note `<12>` records that
/// servers older than Windows Vista have no MIC field at all, and the worked example in §4.2.4.3 is
/// one of those — its payload starts at 72, right where the MIC would be. The field is always
/// written here, zero-filled when no MIC is provided, because a receiver locates the payload by the
/// offsets in the header rather than by assuming a header size.
const HEADER: usize = 88;

/// Where the MIC sits, once the message has been laid out.
const MIC_OFFSET: usize = 72;

/// Builds the `AUTHENTICATE_MESSAGE` that answers `challenge`.
///
/// `negotiate_message` is the exact `NEGOTIATE_MESSAGE` that opened the handshake: the MIC is an
/// HMAC over all three messages, so the first one has to survive until the third is built.
pub(crate) fn authenticate(
    identity: &Identity,
    challenge: &ChallengeMessage,
    negotiate_message: &[u8],
    entropy: Entropy,
    binding: ChannelBinding,
    target_spn: Option<&str>,
) -> Vec<u8> {
    let response = response::compute(identity, challenge, entropy, binding, target_spn);

    // Only claim what the server also offered. The four flags this crate never asks for stay off
    // either way; what this filters out is a flag the server declined, which would otherwise be a
    // message describing a session that was not negotiated.
    let flags = NegotiateFlags::REQUESTED
        .intersection(challenge.flags)
        .union(NegotiateFlags::UNICODE);

    let domain = crypto::unicode(identity.domain());
    let user = crypto::unicode(identity.username());
    let workstation = crypto::unicode(identity.workstation_name());

    let mut payload = Vec::new();
    let mut header = Vec::with_capacity(HEADER);
    header.extend_from_slice(message::SIGNATURE);
    header.extend_from_slice(&message::TYPE_AUTHENTICATE.to_le_bytes());

    // The order of the triples is fixed by the structure; the order of the payload is not, and
    // this is the order Windows writes it in.
    for field in [
        &response.lm_challenge_response,
        &response.nt_challenge_response,
        &domain,
        &user,
        &workstation,
        &Vec::new(),
    ] {
        push_field(&mut header, &mut payload, field);
    }

    header.extend_from_slice(&flags.bits().to_le_bytes());
    // Version, all zero: NTLMSSP_NEGOTIATE_VERSION is not requested, and §2.2.1.3 requires the
    // field to be zero when it is not.
    header.extend_from_slice(&[0u8; 8]);
    header.extend_from_slice(&[0u8; 16]);

    let mut out = header;
    out.extend_from_slice(&payload);

    if response.mic_provided {
        let mic = mic(
            &response.session_key,
            negotiate_message,
            &challenge.raw,
            &out,
        );
        if let Some(slot) = out.get_mut(MIC_OFFSET..MIC_OFFSET.saturating_add(16)) {
            slot.copy_from_slice(&mic);
        }
    }
    out
}

/// Appends one `len`/`maxlen`/`offset` triple to the header and its bytes to the payload.
///
/// The offset is where the payload will land once the fixed header is in front of it, which is why
/// the header has to be a known size before any of this runs.
fn push_field(header: &mut Vec<u8>, payload: &mut Vec<u8>, value: &[u8]) {
    // Nothing this crate writes approaches 64 KiB — the largest is an NT response, which is a
    // hundred-odd bytes — so the saturating conversion is unreachable rather than lossy.
    let len = u16::try_from(value.len()).unwrap_or(u16::MAX);
    let offset = u32::try_from(HEADER.saturating_add(payload.len())).unwrap_or(u32::MAX);

    header.extend_from_slice(&len.to_le_bytes());
    header.extend_from_slice(&len.to_le_bytes());
    header.extend_from_slice(&offset.to_le_bytes());
    payload.extend_from_slice(value.get(..usize::from(len)).unwrap_or_default());
}

/// The message integrity code over all three messages.
///
/// [MS-NLMP] §3.1.5.1.2 — `HMAC_MD5(ExportedSessionKey, ConcatenationOf(NEGOTIATE_MESSAGE,
/// CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))`, with the `AUTHENTICATE_MESSAGE`'s own MIC field
/// zeroed. It is what stops a man in the middle editing the flags of a handshake in flight — the
/// downgrade the `NEGOTIATE_MESSAGE` is otherwise wide open to, since it is unauthenticated.
fn mic(
    session_key: &crypto::Digest128,
    negotiate_message: &[u8],
    challenge_message: &[u8],
    authenticate_message: &[u8],
) -> crypto::Digest128 {
    let mut input = Vec::with_capacity(
        negotiate_message
            .len()
            .saturating_add(challenge_message.len())
            .saturating_add(authenticate_message.len()),
    );
    input.extend_from_slice(negotiate_message);
    input.extend_from_slice(challenge_message);
    input.extend_from_slice(authenticate_message);
    crypto::hmac_md5(session_key, &input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntlm::avpair::{self, AvPairs};
    use crate::ntlm::fixtures::{documented_challenge, timestamped_challenge};

    fn read_u16(bytes: &[u8], at: usize) -> u16 {
        message::read_u16(bytes, at).unwrap()
    }

    fn read_u32(bytes: &[u8], at: usize) -> u32 {
        message::read_u32(bytes, at).unwrap()
    }

    /// The payload a field triple at `at` points to.
    fn field(bytes: &[u8], at: usize) -> &[u8] {
        let len = usize::from(read_u16(bytes, at));
        let offset = usize::try_from(read_u32(bytes, at.saturating_add(4))).unwrap();
        bytes.get(offset..offset.saturating_add(len)).unwrap()
    }

    fn built() -> Vec<u8> {
        let challenge = ChallengeMessage::parse(&documented_challenge()).unwrap();
        authenticate(
            &Identity::with_domain("Domain", "User", "Password").workstation("COMPUTER"),
            &challenge,
            &message::negotiate(NegotiateFlags::REQUESTED),
            Entropy::new([0xAA; 8], 0),
            ChannelBinding::unbound(),
            None,
        )
    }

    #[test]
    fn the_header_is_the_structure_the_specification_draws() {
        let bytes = built();
        assert_eq!(&bytes[0..8], message::SIGNATURE);
        assert_eq!(read_u32(&bytes, 8), message::TYPE_AUTHENTICATE);

        // Every payload starts at or after the fixed header, so nothing overlaps the MIC.
        for at in [12usize, 20, 28, 36, 44, 52] {
            assert!(
                read_u32(&bytes, at.saturating_add(4)) >= 88,
                "field at {at}"
            );
            // MaxLen mirrors Len, which is what §2.2.1.3 says it SHOULD do.
            assert_eq!(read_u16(&bytes, at), read_u16(&bytes, at.saturating_add(2)));
        }

        assert_eq!(field(&bytes, 28), crypto::unicode("Domain"));
        assert_eq!(field(&bytes, 36), crypto::unicode("User"));
        assert_eq!(field(&bytes, 44), crypto::unicode("COMPUTER"));
        assert_eq!(field(&bytes, 12).len(), 24);
        assert!(field(&bytes, 20).len() > 16);
        // EncryptedRandomSessionKey is empty: no key exchange was negotiated.
        assert_eq!(field(&bytes, 52), b"");

        // Version is zero, and so is the MIC when the server did not timestamp.
        assert_eq!(bytes.get(64..72), Some(&[0u8; 8][..]));
        assert_eq!(bytes.get(MIC_OFFSET..MIC_OFFSET + 16), Some(&[0u8; 16][..]));
    }

    #[test]
    fn the_flags_are_what_both_sides_offered() {
        let bytes = built();
        let sent = NegotiateFlags::from_bits(read_u32(&bytes, 60));

        // The challenge offers signing and sealing; this crate never asks for them, so they are
        // not claimed back.
        assert!(!sent.contains(NegotiateFlags::SIGN));
        assert!(!sent.contains(NegotiateFlags::SEAL));
        assert!(!sent.contains(NegotiateFlags::KEY_EXCH));
        assert!(!sent.contains(NegotiateFlags::VERSION));

        for wanted in [
            NegotiateFlags::UNICODE,
            NegotiateFlags::NTLM,
            NegotiateFlags::EXTENDED_SESSIONSECURITY,
            NegotiateFlags::TARGET_INFO,
            NegotiateFlags::ALWAYS_SIGN,
        ] {
            assert!(sent.contains(wanted), "{wanted:?}");
        }

        // A server that declines a flag gets it dropped rather than claimed anyway.
        let mut declined = documented_challenge();
        let narrowed = 0xE28A_8233u32 & !NegotiateFlags::ALWAYS_SIGN.bits();
        declined.splice(20..24, narrowed.to_le_bytes());
        let challenge = ChallengeMessage::parse(&declined).unwrap();
        let bytes = authenticate(
            &Identity::new("User", "Password"),
            &challenge,
            &[],
            Entropy::new([0; 8], 0),
            ChannelBinding::unbound(),
            None,
        );
        assert!(
            !NegotiateFlags::from_bits(read_u32(&bytes, 60)).contains(NegotiateFlags::ALWAYS_SIGN)
        );
    }

    /// A timestamping server gets a MIC, and it is an HMAC over all three messages with the field
    /// itself zeroed — which is checked by recomputing it the way a server would.
    #[test]
    fn a_timestamping_server_gets_a_mic_over_all_three_messages() {
        let challenge = ChallengeMessage::parse(&timestamped_challenge()).unwrap();
        let negotiate_message = message::negotiate(NegotiateFlags::REQUESTED);
        let identity = Identity::with_domain("Domain", "User", "Password");
        let bytes = authenticate(
            &identity,
            &challenge,
            &negotiate_message,
            Entropy::new([0xAA; 8], 0),
            ChannelBinding::tls_server_end_point(b"a certificate"),
            Some("HTTP/server"),
        );

        let written = &bytes[MIC_OFFSET..MIC_OFFSET + 16];
        assert_ne!(written, [0u8; 16]);

        let session_key = response::compute(
            &identity,
            &challenge,
            Entropy::new([0xAA; 8], 0),
            ChannelBinding::tls_server_end_point(b"a certificate"),
            Some("HTTP/server"),
        )
        .session_key;

        let mut zeroed = bytes.clone();
        zeroed[MIC_OFFSET..MIC_OFFSET + 16].fill(0);
        assert_eq!(
            written,
            mic(&session_key, &negotiate_message, &challenge.raw, &zeroed)
        );

        // And the list inside the response says a MIC is being provided, or the server would not
        // look for one.
        let temp = &field(&bytes, 20)[16..];
        let pairs = AvPairs::parse(&temp[28..]).unwrap();
        assert_eq!(
            pairs.get(avpair::FLAGS),
            Some(&[0x02, 0x00, 0x00, 0x00][..])
        );
    }

    /// The MIC covers the `NEGOTIATE_MESSAGE`, which is the whole reason it exists: that message
    /// is sent before anything is authenticated, so without the MIC its flags can be edited in
    /// flight and neither end would know.
    #[test]
    fn editing_the_negotiate_message_changes_the_mic() {
        let challenge = ChallengeMessage::parse(&timestamped_challenge()).unwrap();
        let identity = Identity::new("User", "Password");
        let build = |negotiate_message: &[u8]| {
            authenticate(
                &identity,
                &challenge,
                negotiate_message,
                Entropy::new([0xAA; 8], 0),
                ChannelBinding::unbound(),
                None,
            )[MIC_OFFSET..MIC_OFFSET + 16]
                .to_vec()
        };

        let honest = message::negotiate(NegotiateFlags::REQUESTED);
        let downgraded = message::negotiate(NegotiateFlags::UNICODE);
        assert_ne!(build(&honest), build(&downgraded));
    }

    #[test]
    fn an_identity_with_no_domain_or_workstation_still_produces_a_valid_layout() {
        let challenge = ChallengeMessage::parse(&documented_challenge()).unwrap();
        let bytes = authenticate(
            &Identity::new("developer@dev.local", "Login123"),
            &challenge,
            &[],
            Entropy::new([7; 8], 0),
            ChannelBinding::unbound(),
            None,
        );

        assert_eq!(field(&bytes, 28), b"");
        assert_eq!(field(&bytes, 44), b"");
        assert_eq!(field(&bytes, 36), crypto::unicode("developer@dev.local"));
        // Empty fields still carry an offset inside the buffer, which is what a reader follows.
        assert!(usize::try_from(read_u32(&bytes, 28)).unwrap() <= bytes.len());
    }
}
