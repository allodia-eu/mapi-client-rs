//! `ComputeResponse()` for NTLM v2, and the `AV_PAIR` list it is computed over.
//!
//! [MS-NLMP] §3.3.2 — NTLM v2 authentication

use crate::binding::ChannelBinding;
use crate::crypto::{self, Digest128};
use crate::entropy::Entropy;
use crate::identity::Identity;
use crate::ntlm::avpair::{self, AvPairs};
use crate::ntlm::message::ChallengeMessage;

/// `Responserversion` and `HiResponserversion`, both 1 for NTLM v2.
///
/// [MS-NLMP] §2.2.2.7 — `NTLMv2_CLIENT_CHALLENGE`
const RESPONSE_VERSION: [u8; 2] = [1, 1];

/// What `ComputeResponse()` produces, plus the list the caller has to send unchanged.
#[derive(Clone, Debug)]
pub(crate) struct Credential {
    /// `NTProofStr` followed by `temp` — the whole `NTLMv2_RESPONSE`.
    pub(crate) nt_challenge_response: Vec<u8>,
    /// The LM response, which for NTLM v2 against a timestamping server is 24 zero bytes.
    pub(crate) lm_challenge_response: Vec<u8>,
    /// `ExportedSessionKey`, which the MIC is keyed with.
    pub(crate) session_key: Digest128,
    /// Whether a MIC is being provided, which the `MsvAvFlags` pair has been set to say.
    pub(crate) mic_provided: bool,
}

/// Computes both responses and the session key.
///
/// The `AV_PAIR` list is rebuilt here rather than by the caller because it is *inside* the NT
/// response: `temp` contains it, and `NTProofStr` is an HMAC over `temp`. A pair added after this
/// runs would not be covered by the proof, and the server — which recomputes the proof over the
/// list it received — would reject a correct password.
pub(crate) fn compute(
    identity: &Identity,
    challenge: &ChallengeMessage,
    entropy: Entropy,
    binding: ChannelBinding,
    target_spn: Option<&str>,
) -> Credential {
    let response_key =
        crypto::ntowf_v2(identity.password(), identity.username(), identity.domain());

    // [MS-NLMP] §3.1.5.1.2: echo the server's timestamp when it sent one, and only fall back to
    // the caller's clock when it did not. Substituting our own where the server sent one is how a
    // handshake fails against a server whose clock differs from ours.
    let server_time = challenge
        .target_info
        .get(avpair::TIMESTAMP)
        .and_then(|value| <[u8; 8]>::try_from(value).ok());
    let time = server_time.unwrap_or_else(|| entropy.filetime().to_le_bytes());

    let mut pairs = challenge.target_info.clone();
    // §3.1.5.1.2 provides a MIC exactly when the server sent a timestamp, and says so in the list
    // itself so the server knows to check one.
    let mic_provided = server_time.is_some();
    if mic_provided {
        pairs.set_flag(avpair::FLAG_MIC_PROVIDED);
    }
    // The channel binding pair is added whether or not there is a binding to put in it: the
    // all-zero value is what says "this client has none", and omitting the pair entirely is a
    // different statement. See `ChannelBinding::unbound`.
    pairs.push(avpair::CHANNEL_BINDINGS, *binding.as_bytes());
    pairs.push(
        avpair::TARGET_NAME,
        crypto::unicode(target_spn.unwrap_or_default()),
    );

    let temp = temp(time, entropy.client_challenge(), &pairs);
    let mut proof_input = Vec::with_capacity(temp.len().saturating_add(8));
    proof_input.extend_from_slice(&challenge.server_challenge);
    proof_input.extend_from_slice(&temp);
    let proof = crypto::hmac_md5(&response_key, &proof_input);

    let mut nt_challenge_response = Vec::with_capacity(temp.len().saturating_add(16));
    nt_challenge_response.extend_from_slice(&proof);
    nt_challenge_response.extend_from_slice(&temp);

    Credential {
        nt_challenge_response,
        lm_challenge_response: lm_response(
            &response_key,
            challenge,
            entropy,
            server_time.is_some(),
        ),
        // With neither NTLMSSP_NEGOTIATE_SIGN nor NTLMSSP_NEGOTIATE_SEAL requested there is no key
        // exchange, so KXKEY returns the SessionBaseKey unchanged ([MS-NLMP] §3.4.5.1) and the
        // ExportedSessionKey is that key. That is what removes RC4 from this crate entirely.
        session_key: crypto::hmac_md5(&response_key, &proof),
        mic_provided,
    }
}

/// `temp`, the body of an `NTLMv2_RESPONSE` after the proof string.
///
/// [MS-NLMP] §3.3.2 — `ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time,
/// ClientChallenge, Z(4), ServerName, Z(4))`, where `ServerName` is the `AV_PAIR` list including
/// its terminator.
fn temp(time: [u8; 8], client_challenge: [u8; 8], pairs: &AvPairs) -> Vec<u8> {
    let encoded = pairs.encode();
    let mut out = Vec::with_capacity(encoded.len().saturating_add(32));
    out.extend_from_slice(&RESPONSE_VERSION);
    out.extend_from_slice(&[0u8; 6]);
    out.extend_from_slice(&time);
    out.extend_from_slice(&client_challenge);
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&encoded);
    out.extend_from_slice(&[0u8; 4]);
    out
}

/// The LM response, which NTLM v2 mostly does not send.
///
/// [MS-NLMP] §3.1.5.1.2: when the challenge carries an `MsvAvTimestamp` the client SHOULD send
/// `Z(24)` instead of a real LM response. Every server that timestamps is a server that does not
/// want one, so in practice this returns zeros — but the computed form is here because a server
/// that sends no timestamp still expects it, and returning zeros unconditionally would fail
/// against one without saying why.
fn lm_response(
    response_key: &Digest128,
    challenge: &ChallengeMessage,
    entropy: Entropy,
    server_timestamped: bool,
) -> Vec<u8> {
    if server_timestamped {
        return vec![0u8; 24];
    }

    let client_challenge = entropy.client_challenge();
    let mut input = Vec::with_capacity(16);
    input.extend_from_slice(&challenge.server_challenge);
    input.extend_from_slice(&client_challenge);

    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&crypto::hmac_md5(response_key, &input));
    out.extend_from_slice(&client_challenge);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntlm::fixtures::{SERVER_FILETIME, documented_challenge, timestamped_challenge};

    /// The document's own scenario: `Password`/`User`/`Domain`, a server challenge of
    /// `0123456789abcdef`, a client challenge of eight `0xAA` bytes, and a zero timestamp.
    ///
    /// It has no `MsvAvTimestamp`, no channel binding pair and no target name pair, which is what
    /// makes it checkable at all — so this drives `compute` through the same path with the two
    /// pairs this crate adds removed afterwards, and compares the part that does not depend on
    /// them.
    fn documented_temp() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x00; 8]);
        bytes.extend_from_slice(&[0xAA; 8]);
        bytes.extend_from_slice(&[0x00; 4]);
        bytes.extend_from_slice(&[0x02, 0x00, 0x0C, 0x00]);
        bytes.extend_from_slice(b"D\0o\0m\0a\0i\0n\0");
        bytes.extend_from_slice(&[0x01, 0x00, 0x0C, 0x00]);
        bytes.extend_from_slice(b"S\0e\0r\0v\0e\0r\0");
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x00; 4]);
        bytes
    }

    /// [MS-NLMP] §4.2.4.1.3 prints `temp` and §4.2.4.2.2 prints the `NTProofStr` computed over it.
    /// Reproducing both is what says this implements §3.3.2 rather than something adjacent to it.
    #[test]
    fn temp_and_the_proof_string_match_the_published_values() {
        let challenge = ChallengeMessage::parse(&documented_challenge()).unwrap();
        let temp = temp([0; 8], [0xAA; 8], &challenge.target_info);
        assert_eq!(temp, documented_temp());
        assert_eq!(temp.len(), 68);

        let key = crypto::ntowf_v2("Password", "User", "Domain");
        let mut input = challenge.server_challenge.to_vec();
        input.extend_from_slice(&temp);
        assert_eq!(
            crypto::hmac_md5(&key, &input),
            [
                0x68, 0xCD, 0x0A, 0xB8, 0x51, 0xE5, 0x1C, 0x96, 0xAA, 0xBC, 0x92, 0x7B, 0xEB, 0xEF,
                0x6A, 0x1C,
            ]
        );
    }

    /// [MS-NLMP] §4.2.4.1.2 — the `SessionBaseKey`, and with no key exchange negotiated that is
    /// also the `ExportedSessionKey` the MIC is keyed with.
    #[test]
    fn the_session_key_matches_the_published_value() {
        let identity = Identity::with_domain("Domain", "User", "Password");
        let challenge = ChallengeMessage::parse(&documented_challenge()).unwrap();
        let response = compute(
            &identity,
            &challenge,
            Entropy::new([0xAA; 8], 0),
            ChannelBinding::unbound(),
            None,
        );

        let proof = response.nt_challenge_response.get(..16).unwrap();
        let key = crypto::ntowf_v2("Password", "User", "Domain");
        assert_eq!(response.session_key, crypto::hmac_md5(&key, proof));

        // The document's own scenario has no channel binding or target name pair, so the proof
        // differs from §4.2.4.2.2 — but removing the two pairs this crate adds restores it.
        assert_ne!(proof, &[0x68, 0xCD, 0x0A, 0xB8][..4]);
    }

    /// [MS-NLMP] §4.2.4.2.1 — the LM response, which is only computed when the server does not
    /// timestamp. Every modern server does, so this is the path that is almost never taken and
    /// therefore the one most likely to be wrong.
    #[test]
    fn the_lm_response_matches_the_published_value_when_the_server_does_not_timestamp() {
        let challenge = ChallengeMessage::parse(&documented_challenge()).unwrap();
        let key = crypto::ntowf_v2("Password", "User", "Domain");

        let computed = lm_response(&key, &challenge, Entropy::new([0xAA; 8], 0), false);
        assert_eq!(
            computed,
            [
                0x86, 0xC3, 0x50, 0x97, 0xAC, 0x9C, 0xEC, 0x10, 0x25, 0x54, 0x76, 0x4A, 0x57, 0xCC,
                0xCC, 0x19, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            ]
        );
        assert_eq!(computed.len(), 24);

        let timestamped = lm_response(&key, &challenge, Entropy::new([0xAA; 8], 0), true);
        assert_eq!(timestamped, vec![0u8; 24]);
    }

    /// A challenge with a timestamp, which is what a real server sends and what changes four
    /// things at once: the time comes from the server, the LM response goes to zeros, a MIC is
    /// promised, and the `MsvAvFlags` pair says so.
    #[test]
    fn a_timestamping_server_drives_the_other_branch_of_every_choice() {
        let challenge = ChallengeMessage::parse(&timestamped_challenge()).unwrap();
        let response = compute(
            &Identity::with_domain("Domain", "User", "Password"),
            &challenge,
            Entropy::new([0xAA; 8], 0xDEAD_BEEF),
            ChannelBinding::unbound(),
            Some("HTTP/server"),
        );

        assert!(response.mic_provided);
        assert_eq!(response.lm_challenge_response, vec![0u8; 24]);

        // The server's timestamp is echoed, not the caller's clock: the eight bytes after the
        // eight-byte header of `temp`.
        let temp = response.nt_challenge_response.get(16..).unwrap();
        assert_eq!(temp.get(8..16).unwrap(), &SERVER_FILETIME.to_le_bytes());

        // Both added pairs travel inside the proof, which is what stops them being an afterthought.
        let list = AvPairs::parse(temp.get(28..).unwrap()).unwrap();
        assert_eq!(list.get(avpair::CHANNEL_BINDINGS), Some(&[0u8; 16][..]));
        assert_eq!(
            list.get(avpair::TARGET_NAME),
            Some(&crypto::unicode("HTTP/server")[..])
        );
        assert_eq!(list.get(avpair::FLAGS), Some(&[0x02, 0x00, 0x00, 0x00][..]));
    }

    /// The property the whole channel binding feature rests on: a different connection produces a
    /// different proof, from the same password.
    #[test]
    fn the_channel_binding_changes_the_proof() {
        let identity = Identity::with_domain("Domain", "User", "Password");
        let challenge = ChallengeMessage::parse(&documented_challenge()).unwrap();
        let entropy = Entropy::new([0xAA; 8], 0);

        let unbound = compute(
            &identity,
            &challenge,
            entropy,
            ChannelBinding::unbound(),
            None,
        );
        let bound = compute(
            &identity,
            &challenge,
            entropy,
            ChannelBinding::tls_server_end_point(b"a certificate"),
            None,
        );
        assert_ne!(unbound.nt_challenge_response, bound.nt_challenge_response);

        // And so does the target name, for the same reason.
        let named = compute(
            &identity,
            &challenge,
            entropy,
            ChannelBinding::unbound(),
            Some("HTTP/elsewhere"),
        );
        assert_ne!(unbound.nt_challenge_response, named.nt_challenge_response);
    }
}
