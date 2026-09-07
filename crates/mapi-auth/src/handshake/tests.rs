//! The handshake's tests, apart from it because together they cross the 500-line limit.

use super::*;
use crate::ntlm::fixtures::{documented_challenge, timestamped_challenge};

fn identity() -> Identity {
    Identity::with_domain("EXAMPLE", "alice", "hunter2")
}

fn fresh(scheme: Scheme) -> Handshake {
    Handshake::new(scheme, identity(), Entropy::new([0x11; 8], 0))
}

fn token_of(header: &str) -> Vec<u8> {
    BASE64
        .decode(header.split_whitespace().nth(1).unwrap())
        .unwrap()
}

#[test]
fn a_raw_ntlm_handshake_produces_the_two_messages_in_order() {
    let mut handshake = fresh(Scheme::Ntlm);
    assert_eq!(handshake.state(), State::Ready);

    let first = handshake.initial().unwrap();
    assert!(first.starts_with("NTLM "));
    assert_eq!(token_of(&first).get(8..12), Some(&[1, 0, 0, 0][..]));
    assert_eq!(handshake.state(), State::AwaitingChallenge);

    let challenge = format!("NTLM {}", BASE64.encode(timestamped_challenge()));
    let second = handshake.advance(&challenge).unwrap();
    assert!(second.starts_with("NTLM "));
    assert_eq!(token_of(&second).get(8..12), Some(&[3, 0, 0, 0][..]));
    assert_eq!(handshake.state(), State::Complete);
}

#[test]
fn a_negotiate_handshake_wraps_the_same_messages_in_spnego() {
    let mut handshake = fresh(Scheme::Negotiate);
    let first = handshake.initial().unwrap();
    assert!(first.starts_with("Negotiate "));

    // The GSS-API wrapper, and the NTLM message still inside it.
    let token = token_of(&first);
    assert_eq!(token.first(), Some(&0x60));
    assert!(token.windows(8).any(|w| w == b"NTLMSSP\0"));

    let inner = spnego::init_token(&documented_challenge());
    let reply = format!("Negotiate {}", BASE64.encode(&inner));
    let second = handshake.advance(&reply).unwrap();
    let token = token_of(&second);
    assert_eq!(token.first(), Some(&0xA1));
    assert!(token.windows(8).any(|w| w == b"NTLMSSP\0"));
}

/// The two headers a real 401 carries, and the job of picking the right one.
#[test]
fn a_scheme_recognises_its_own_challenge_however_it_is_capitalised() {
    let offered = ["Negotiate", "NTLM TlRMTVNTUAACAAAA", "Basic realm=\"x\""];

    let ntlm: Vec<_> = offered
        .iter()
        .copied()
        .filter(|value| Scheme::Ntlm.matches(value))
        .collect();
    assert_eq!(ntlm, vec!["NTLM TlRMTVNTUAACAAAA"]);

    assert!(Scheme::Negotiate.matches("negotiate abc"));
    assert!(Scheme::Ntlm.matches("ntlm"));
    assert!(!Scheme::Ntlm.matches(""));
    assert!(!Scheme::Ntlm.matches("Negotiate abc"));
    assert_eq!(Scheme::Negotiate.name(), "Negotiate");
}

/// A bare scheme name is what a refused credential looks like, and reporting it as malformed
/// input would send somebody debugging the wrong thing entirely.
#[test]
fn a_bare_scheme_name_is_read_as_a_refusal() {
    let mut handshake = fresh(Scheme::Ntlm);
    let _ = handshake.initial().unwrap();
    assert!(matches!(
        handshake.advance("NTLM").unwrap_err(),
        Error::Refused { scheme: "NTLM" }
    ));
}

#[test]
fn a_challenge_for_another_scheme_is_refused_by_name() {
    let mut handshake = fresh(Scheme::Ntlm);
    let _ = handshake.initial().unwrap();

    let error = handshake.advance("Negotiate abcd").unwrap_err();
    assert!(
        matches!(&error, Error::WrongScheme { expected: "NTLM", offered } if offered.as_deref() == Some("Negotiate")),
        "{error}"
    );

    assert!(matches!(
        handshake.advance("   ").unwrap_err(),
        Error::WrongScheme { offered: None, .. }
    ));
}

#[test]
fn a_challenge_that_is_not_base64_says_so() {
    let mut handshake = fresh(Scheme::Ntlm);
    let _ = handshake.initial().unwrap();
    assert!(matches!(
        handshake.advance("NTLM not!base64!").unwrap_err(),
        Error::NotBase64 { scheme: "NTLM", .. }
    ));
}

#[test]
fn a_negotiate_server_that_rejects_or_sends_no_challenge_is_reported_rather_than_answered() {
    let body = |state: u8| {
        let inner = crate::der::tlv(
            crate::der::context(0),
            &crate::der::tlv(crate::der::ENUMERATED, &[state]),
        );
        let token = crate::der::tlv(
            crate::der::context(1),
            &crate::der::tlv(crate::der::SEQUENCE, &inner),
        );
        format!("Negotiate {}", BASE64.encode(token))
    };

    let mut handshake = fresh(Scheme::Negotiate);
    let _ = handshake.initial().unwrap();
    assert!(matches!(
        handshake.advance(&body(2)).unwrap_err(),
        Error::Refused { .. }
    ));

    // Incomplete or asking for a MIC, but with no token to answer: also a refusal rather than a
    // parse failure.
    for state in [1, 3] {
        let mut handshake = fresh(Scheme::Negotiate);
        let _ = handshake.initial().unwrap();
        assert!(matches!(
            handshake.advance(&body(state)).unwrap_err(),
            Error::Refused { .. }
        ));
    }
}

/// The last `Negotiate` token carries [MS-NLMP] §3.4.4.3's signature as its `mechListMIC`,
/// whether or not the server asked: [MS-SPNG] note `<8>` makes it mandatory once there is a MIC
/// in the `AUTHENTICATE_MESSAGE`. The raw `NTLM` scheme has no SPNEGO layer to carry one.
#[test]
fn the_last_negotiate_token_carries_the_mech_list_mic() {
    let dummy = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for state in [1u8, 3] {
        let mut handshake = fresh(Scheme::Negotiate);
        let _ = handshake.initial().unwrap();
        let reply = format!("Negotiate {}", BASE64.encode(challenge_token(state)));
        let last = spnego::parse(&token_of(&handshake.advance(&reply).unwrap())).unwrap();
        assert_eq!(last.mech_list_mic.as_deref(), Some(&dummy[..]), "{state}");
    }
}

/// A `Negotiate` challenge in the given `negState`, around §4.2.4.3's `CHALLENGE_MESSAGE`.
fn challenge_token(state: u8) -> Vec<u8> {
    use crate::der::{ENUMERATED, OCTET_STRING, SEQUENCE, context, tlv};
    let mut body = tlv(context(0), &tlv(ENUMERATED, &[state]));
    body.extend_from_slice(&tlv(
        context(2),
        &tlv(OCTET_STRING, &documented_challenge()),
    ));
    tlv(context(1), &tlv(SEQUENCE, &body))
}

/// A completing `NegTokenResp`, with or without a `mechListMIC`.
fn completion(state: u8, mic: Option<&[u8]>) -> String {
    use crate::der::{ENUMERATED, OCTET_STRING, SEQUENCE, context, tlv};
    let mut body = tlv(context(0), &tlv(ENUMERATED, &[state]));
    if let Some(mic) = mic {
        body.extend_from_slice(&tlv(context(3), &tlv(OCTET_STRING, mic)));
    }
    format!(
        "Negotiate {}",
        BASE64.encode(tlv(context(1), &tlv(SEQUENCE, &body)))
    )
}

/// [RFC 4178] §5: a server's `mechListMIC` is verified when it arrives, and nothing is demanded
/// when it does not — IIS's final `200` carries `accept-completed` and no `mechListMIC`.
#[test]
fn finish_verifies_a_servers_mech_list_mic_and_accepts_its_absence() {
    let dummy = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut handshake = fresh(Scheme::Negotiate);
    assert!(matches!(
        handshake.finish(None).unwrap_err(),
        Error::OutOfOrder { .. }
    ));
    let _ = handshake.initial().unwrap();
    let reply = format!("Negotiate {}", BASE64.encode(challenge_token(1)));
    let _ = handshake.advance(&reply).unwrap();

    for fine in [None, Some("Negotiate"), Some(completion(0, None).as_str())] {
        handshake.finish(fine).unwrap();
    }
    handshake
        .finish(Some(&completion(0, Some(&dummy))))
        .unwrap();

    let mut forged = dummy;
    forged[4] = 0xFF;
    let error = handshake
        .finish(Some(&completion(0, Some(&forged))))
        .unwrap_err();
    assert_eq!(
        error,
        Error::MechListMicMismatch {
            received: forged.to_vec()
        }
    );
    assert!(matches!(
        handshake.finish(Some(&completion(2, None))).unwrap_err(),
        Error::Refused { .. }
    ));
    assert!(handshake.finish(Some("Negotiate !!")).is_err());

    // The raw NTLM scheme has no last token, so there is nothing for it to check.
    let mut ntlm = fresh(Scheme::Ntlm);
    let _ = ntlm.initial().unwrap();
    let reply = format!("NTLM {}", BASE64.encode(documented_challenge()));
    let _ = ntlm.advance(&reply).unwrap();
    ntlm.finish(Some(&completion(0, Some(&forged)))).unwrap();
}

#[test]
fn a_handshake_cannot_be_driven_out_of_order() {
    let mut handshake = fresh(Scheme::Ntlm);
    assert!(matches!(
        handshake.advance("NTLM abcd").unwrap_err(),
        Error::OutOfOrder {
            state: "not started",
            attempted: "answer a challenge",
        }
    ));

    let _ = handshake.initial().unwrap();
    assert!(matches!(
        handshake.initial().unwrap_err(),
        Error::OutOfOrder {
            state: "waiting for a challenge",
            ..
        }
    ));

    let challenge = format!("NTLM {}", BASE64.encode(timestamped_challenge()));
    let _ = handshake.advance(&challenge).unwrap();
    assert!(matches!(
        handshake.advance(&challenge).unwrap_err(),
        Error::OutOfOrder {
            state: "complete",
            ..
        }
    ));
}

/// A handshake carries a password, so it must not print one — and it is a value a caller may
/// well put inside a struct they derive `Debug` on.
#[test]
fn debug_never_prints_the_password() {
    let rendered = format!("{:?}", fresh(Scheme::Ntlm));
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn the_channel_binding_and_target_name_reach_the_message() {
    let make = |configure: fn(Handshake) -> Handshake| {
        let mut handshake = configure(fresh(Scheme::Ntlm));
        let _ = handshake.initial().unwrap();
        let challenge = format!("NTLM {}", BASE64.encode(timestamped_challenge()));
        token_of(&handshake.advance(&challenge).unwrap())
    };

    let plain = make(|handshake| handshake);
    let bound = make(|handshake| {
        handshake.channel_binding(ChannelBinding::tls_server_end_point(b"a certificate"))
    });
    let named = make(|handshake| handshake.target_spn("HTTP/mail.example.test"));

    assert_ne!(plain, bound);
    assert_ne!(plain, named);
    assert!(named.windows(2).any(|w| w == [0x48, 0x00]));
}
