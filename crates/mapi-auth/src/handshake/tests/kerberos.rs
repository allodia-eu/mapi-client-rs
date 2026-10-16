//! `Negotiate` with Kerberos offered first: one round trip when the server takes it, the legs a
//! skew error or `request-mic` adds, and NTLM when the server picks that instead.

use core::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::{identity, timestamped_challenge, token_of};
use crate::der::{ENUMERATED, OCTET_STRING, OID, SEQUENCE, context, tlv};
use crate::kerberos::client::{KerberosEntropy, ServiceTicket};
use crate::kerberos::crypto::{Enctype, Key};
use crate::kerberos::gss::testing::{
    NOW, acceptor_mic, answer, bound, error_data, krb_error, open, ticket,
};
use crate::spnego::{self, KERBEROS_LEGACY_OID, KERBEROS_OID, NTLM_OID};
use crate::*;

fn entropy(seed: u8) -> KerberosEntropy {
    KerberosEntropy::new([seed; 64], Duration::new(NOW, 250_000_000))
}

fn handshake() -> Handshake {
    let ticket = ServiceTicket {
        credential: ticket(),
        clock_offset: 0,
    };
    Handshake::kerberos(
        ticket,
        identity(),
        Entropy::new([0x11; 8], 0),
        [entropy(3), entropy(5)],
    )
    .channel_binding(bound())
}

/// The AP-REQ inside a header this handshake produced, first leg or later.
fn ap_req_in(header: &str) -> Vec<u8> {
    spnego::parse(&token_of(header))
        .unwrap()
        .response_token
        .unwrap()
}

/// A server's `NegTokenResp` as a `WWW-Authenticate` value.
fn reply(state: u8, mech: Option<&[u8]>, token: Option<&[u8]>, mic: Option<&[u8]>) -> String {
    let mut body = tlv(context(0), &tlv(ENUMERATED, &[state]));
    if let Some(mech) = mech {
        body.extend_from_slice(&tlv(context(1), &tlv(OID, mech)));
    }
    if let Some(token) = token {
        body.extend_from_slice(&tlv(context(2), &tlv(OCTET_STRING, token)));
    }
    if let Some(mic) = mic {
        body.extend_from_slice(&tlv(context(3), &tlv(OCTET_STRING, mic)));
    }
    format!(
        "Negotiate {}",
        BASE64.encode(tlv(context(1), &tlv(SEQUENCE, &body)))
    )
}

fn offered() -> Vec<u8> {
    spnego::mech_type_list(&[KERBEROS_OID, NTLM_OID])
}

/// What IIS was measured doing: `accept-completed`, the standard OID, the AP-REP, no MIC — all on
/// the success that answers the first request.
#[test]
fn a_server_that_takes_kerberos_is_done_in_one_round_trip() {
    for mech in [KERBEROS_OID, KERBEROS_LEGACY_OID] {
        let mut handshake = handshake();
        let first = handshake.initial().unwrap();
        assert!(first.starts_with("Negotiate "));
        let token = token_of(&first);
        assert!(
            token
                .windows(offered().len())
                .any(|window| window == offered()),
            "Kerberos first, then NTLM"
        );
        assert_eq!(handshake.mechanism(), None, "the server has not chosen yet");

        let ap_rep = answer(&ap_req_in(&first));
        handshake
            .finish(Some(&reply(0, Some(mech), Some(&ap_rep), None)))
            .unwrap();
        assert_eq!(handshake.mechanism(), Some(Mechanism::Kerberos));
        assert_eq!(handshake.state(), State::Complete);
    }
}

/// [MS-SPNG] note `<8>`: with AES Kerberos a server's `mechListMIC` is processed, over the list
/// this side offered, under the acceptor's subkey.
#[test]
fn a_servers_mech_list_mic_is_verified() {
    let mut handshake = handshake();
    let first = handshake.initial().unwrap();
    let ap_rep = answer(&ap_req_in(&first));
    let mic = acceptor_mic(&offered());
    let mut forged = mic.clone();
    *forged.last_mut().unwrap() ^= 1;

    let mut tampered = handshake.clone();
    assert_eq!(
        tampered.finish(Some(&reply(
            0,
            Some(KERBEROS_OID),
            Some(&ap_rep),
            Some(&forged)
        ))),
        Err(Error::MechListMicMismatch { received: forged })
    );
    handshake
        .finish(Some(&reply(
            0,
            Some(KERBEROS_OID),
            Some(&ap_rep),
            Some(&mic),
        )))
        .unwrap();
}

/// Mutual authentication asked for is mutual authentication required: a success that does not
/// carry the AP-REP has not proved the server.
#[test]
fn a_success_without_an_ap_rep_proves_nothing() {
    let missing = Err(Error::ServiceReply {
        reason: "a success without the AP-REP that proves the server",
    });
    let mut handshake = handshake();
    assert!(matches!(
        handshake.finish(None),
        Err(Error::OutOfOrder { .. })
    ));
    let _ = handshake.initial().unwrap();
    for value in [
        None,
        Some("Negotiate"),
        Some(&*reply(0, Some(KERBEROS_OID), None, None)),
    ] {
        assert_eq!(handshake.clone().finish(value), missing);
    }
    assert_eq!(
        handshake
            .clone()
            .finish(Some(&reply(2, Some(KERBEROS_OID), None, None))),
        Err(Error::Refused {
            scheme: "Negotiate"
        })
    );
    assert_eq!(
        handshake
            .clone()
            .finish(Some(&reply(0, Some(NTLM_OID), None, None))),
        Err(Error::ServiceReply {
            reason: "a success naming NTLM, which was never run"
        })
    );
    let skew = krb_error(37, NOW + 600, Some(error_data(2, None)));
    assert_eq!(
        handshake.finish(Some(&reply(0, Some(KERBEROS_OID), Some(&skew), None))),
        Err(Error::ServiceReply {
            reason: "a clock-skew error on a response that succeeded"
        })
    );
}

/// [MS-KILE] §3.2.5.8, as IIS was measured doing it: `accept-incomplete` with `KRB_AP_ERR_SKEW`,
/// then a fresh AP-REQ on the server's clock, then the success.
#[test]
fn a_clock_skew_costs_one_more_round_trip() {
    let mut handshake = handshake();
    let _ = handshake.initial().unwrap();
    let skew = krb_error(37, NOW + 600, Some(error_data(2, None)));
    let retry = handshake
        .advance(&reply(1, Some(KERBEROS_OID), Some(&skew), None))
        .unwrap();
    let token = ap_req_in(&retry);
    assert_eq!(
        token_of(&retry).first(),
        Some(&0xA1),
        "a NegTokenResp, not a second Init"
    );
    let seen = open(&token);
    assert_eq!(seen.ctime.unix(), NOW + 600);
    assert_eq!(
        seen.subkey.value,
        vec![5; 32],
        "the second entropy's subkey"
    );
    assert_eq!(handshake.state(), State::AwaitingChallenge);

    handshake
        .finish(Some(&reply(0, None, Some(&answer(&token)), None)))
        .unwrap();
    assert_eq!(handshake.mechanism(), Some(Mechanism::Kerberos));
}

/// [RFC 4178] §5: a server that asks for the initiator's MIC gets it, over the list offered, under
/// the acceptor's subkey and the initiator's own usage.
#[test]
fn a_server_that_requests_the_mic_gets_it() {
    let mut handshake = handshake();
    let first = handshake.initial().unwrap();
    let ap_rep = answer(&ap_req_in(&first));
    let next = handshake
        .advance(&reply(3, Some(KERBEROS_OID), Some(&ap_rep), None))
        .unwrap();
    assert_eq!(handshake.state(), State::Complete);

    let sent = spnego::parse(&token_of(&next)).unwrap();
    assert_eq!(sent.response_token, None);
    let mic = sent.mech_list_mic.unwrap();
    assert_eq!(
        mic[..3],
        [0x04, 0x04, 0x04],
        "a MIC token, under the acceptor's subkey"
    );
    let key = Key::new(Enctype::Aes256Sha1, vec![0x77; 32]).unwrap();
    key.verify_checksum(25, &[&offered()[..], &mic[..16]].concat(), &mic[16..])
        .unwrap();

    // The success after it carries nothing more, and the AP-REP is already proven.
    handshake.finish(Some(&reply(0, None, None, None))).unwrap();
}

/// [RFC 4178] §5 (b), as IIS was measured doing it after a skew retry: the AP-REP arrives on a 401
/// with `accept-incomplete` and the acceptor's `mechListMIC`, which is verified and answered with
/// the initiator's own and `accept-completed` — and a forged one ends the negotiation.
#[test]
fn an_acceptor_mic_on_a_401_is_verified_and_answered() {
    let mut handshake = handshake();
    let _ = handshake.initial().unwrap();
    let skew = krb_error(37, NOW + 600, Some(error_data(2, None)));
    let retry = handshake
        .advance(&reply(1, Some(KERBEROS_OID), Some(&skew), None))
        .unwrap();
    let ap_rep = answer(&ap_req_in(&retry));
    let mic = acceptor_mic(&offered());

    let mut forged = mic.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert_eq!(
        handshake
            .clone()
            .advance(&reply(1, None, Some(&ap_rep), Some(&forged))),
        Err(Error::MechListMicMismatch { received: forged })
    );

    let last = handshake
        .advance(&reply(1, None, Some(&ap_rep), Some(&mic)))
        .unwrap();
    let sent = spnego::parse(&token_of(&last)).unwrap();
    assert_eq!(sent.state, Some(spnego::NegState::AcceptCompleted));
    assert_eq!(sent.response_token, None);
    assert_eq!(sent.mech_list_mic.unwrap()[..3], [0x04, 0x04, 0x04]);
    assert_eq!(handshake.state(), State::Complete);
    handshake.finish(Some(&reply(0, None, None, None))).unwrap();
    assert_eq!(handshake.mechanism(), Some(Mechanism::Kerberos));
}

/// A 401 that is not a skew to retry nor an AP-REP with `request-mic` is a refusal, and a
/// `KRB-ERROR` is reported with its code.
#[test]
fn a_401_to_the_ap_req_is_a_refusal() {
    let mut handshake = handshake();
    let first = handshake.initial().unwrap();
    let refused = Err(Error::Refused {
        scheme: "Negotiate",
    });
    assert_eq!(
        handshake
            .clone()
            .advance(&reply(1, Some(KERBEROS_OID), None, None)),
        refused
    );
    let ap_rep = answer(&ap_req_in(&first));
    assert_eq!(
        handshake
            .clone()
            .advance(&reply(0, Some(KERBEROS_OID), Some(&ap_rep), None)),
        refused
    );
    let error = krb_error(41, NOW, None);
    assert_eq!(
        handshake.advance(&reply(2, Some(KERBEROS_OID), Some(&error), None)),
        Err(Error::ServiceRefused {
            code: 41,
            status: None
        })
    );
}

/// [RFC 4178] §3.2: the server picks NTLM over the optimistic Kerberos token, so NTLM's first
/// message follows inside SPNEGO, and — NTLM not being the preferred mechanism — §5 makes the
/// last token's `mechListMIC` mandatory.
#[test]
fn a_server_that_picks_ntlm_gets_ntlm() {
    let mut handshake = handshake();
    let _ = handshake.initial().unwrap();
    let negotiate = handshake
        .advance(&reply(1, Some(NTLM_OID), None, None))
        .unwrap();
    assert_eq!(handshake.mechanism(), Some(Mechanism::Ntlm));
    let inner = spnego::parse(&token_of(&negotiate))
        .unwrap()
        .response_token
        .unwrap();
    assert_eq!(
        inner.get(8..12),
        Some(&[1, 0, 0, 0][..]),
        "a NEGOTIATE_MESSAGE"
    );

    let last = handshake
        .advance(&reply(1, None, Some(&timestamped_challenge()), None))
        .unwrap();
    let last = spnego::parse(&token_of(&last)).unwrap();
    assert_eq!(
        last.response_token.unwrap().get(8..12),
        Some(&[3, 0, 0, 0][..])
    );
    assert!(last.mech_list_mic.is_some());
    assert_eq!(handshake.state(), State::Complete);
    handshake.finish(Some(&reply(0, None, None, None))).unwrap();
}

#[test]
fn a_mechanism_that_was_not_offered_is_refused_by_name() {
    let mut handshake = handshake();
    let _ = handshake.initial().unwrap();
    let other = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x7F];
    assert_eq!(
        handshake.advance(&reply(1, Some(&other), None, None)),
        Err(Error::UnsupportedMechanism {
            mechanism: "1.3.6.1.4.1.127".to_owned()
        })
    );

    // Kerberos to a handshake that offered only NTLM is not offered either.
    let mut ntlm = Handshake::new(Scheme::Negotiate, identity(), Entropy::new([0x11; 8], 0));
    let _ = ntlm.initial().unwrap();
    assert_eq!(ntlm.mechanism(), Some(Mechanism::Ntlm));
    assert!(matches!(
        ntlm.advance(&reply(1, Some(KERBEROS_OID), Some(b"an AP-REP"), None)),
        Err(Error::UnsupportedMechanism { mechanism }) if mechanism.starts_with("Kerberos")
    ));
}
