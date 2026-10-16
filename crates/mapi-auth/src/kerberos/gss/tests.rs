//! The GSS-API context tokens, against an acceptor that holds the session key — which is all an
//! acceptor needs, once it has decrypted the ticket.

use core::time::Duration;

use super::*;
use crate::kerberos::asn1::{
    Fields, PrincipalName, explicit, int, octets, read_flags, read_int32, read_uint32, sequence,
};
use crate::kerberos::kdc::Ticket;

const NOW: u64 = 1_800_000_000;

fn fresh(seed: u8) -> Fresh {
    Fresh {
        now: Duration::new(NOW, 250_000_000),
        random: [seed; 64],
    }
}

fn ticket() -> Credential {
    Credential {
        crealm: "CHILD.EXAMPLE.TEST".to_owned(),
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, &["bob"]),
        ticket: Ticket {
            raw: der::tlv(der::application(1), &[0x30, 0x00]),
            realm: "EXAMPLE.TEST".to_owned(),
            sname: PrincipalName::new(PrincipalName::NT_SRV_INST, &["HTTP", "mail.example.test"]),
        },
        key: Key::new(Enctype::Aes256Sha1, vec![0x42; 32]).unwrap(),
        flags: 0,
        endtime: KerberosTime::from_unix(NOW + 36_000),
    }
}

fn bound() -> ChannelBinding {
    ChannelBinding::tls_server_end_point(b"the server certificate")
}

/// What an acceptor reads out of an AP-REQ token.
struct Seen {
    options: u32,
    raw_ticket: Vec<u8>,
    checksum: Checksum,
    ctime: KerberosTime,
    cusec: u32,
    subkey: EncryptionKey,
    seq_number: u32,
    authorization: Option<Vec<u8>>,
}

fn open(token: &[u8]) -> Seen {
    let (id, message) = unframe(token).unwrap();
    assert_eq!(id, tok_id::AP_REQ);
    let mut reader = Reader::new(STRUCTURE, message);
    let mut inner = reader.expect_nested(der::application(14), "").unwrap();
    let fields = Fields::of(&mut inner, "").unwrap();
    let options = read_flags(&mut fields.required(2, "").unwrap(), "").unwrap();
    let raw_ticket = fields
        .required(3, "")
        .unwrap()
        .read_element()
        .unwrap()
        .to_vec();
    let sealed = EncryptedData::read(&mut fields.required(4, "").unwrap()).unwrap();
    assert_eq!(sealed.etype, 18);
    let plain = ticket()
        .key
        .decrypt(usage::AP_REQ_AUTHENTICATOR, &sealed.cipher)
        .unwrap();
    let mut reader = Reader::new(STRUCTURE, &plain);
    let mut inner = reader.expect_nested(der::application(2), "").unwrap();
    let fields = Fields::of(&mut inner, "").unwrap();
    Seen {
        options,
        raw_ticket,
        checksum: Checksum::read(&mut fields.required(3, "").unwrap()).unwrap(),
        cusec: read_uint32(&mut fields.required(4, "").unwrap(), "").unwrap(),
        ctime: KerberosTime::read(&mut fields.required(5, "").unwrap(), "").unwrap(),
        subkey: EncryptionKey::read(&mut fields.required(6, "").unwrap()).unwrap(),
        seq_number: read_uint32(&mut fields.required(7, "").unwrap(), "").unwrap(),
        authorization: fields
            .optional(8)
            .map(|mut field| field.read_element().unwrap().to_vec()),
    }
}

/// An AP-REP token as an acceptor makes one — [RFC 4120] §5.5.2.
fn ap_rep(ctime: KerberosTime, cusec: u32, subkey: Option<EncryptionKey>, etype: i32) -> Vec<u8> {
    let mut part = vec![
        explicit(0, &ctime.encode()),
        explicit(1, &int(i64::from(cusec))),
    ];
    if let Some(subkey) = subkey {
        part.push(explicit(2, &subkey.encode()));
    }
    part.push(explicit(3, &int(7)));
    let part = der::tlv(der::application(27), &sequence(&part));
    let cipher = ticket()
        .key
        .encrypt(usage::AP_REP, &[9; 16], &part)
        .unwrap();
    let rep = der::tlv(
        der::application(15),
        &sequence(&[
            explicit(0, &int(5)),
            explicit(1, &int(15)),
            explicit(
                2,
                &EncryptedData {
                    etype,
                    kvno: None,
                    cipher,
                }
                .encode(),
            ),
        ]),
    );
    frame(tok_id::AP_REP, &rep)
}

fn acceptor_subkey() -> EncryptionKey {
    EncryptionKey {
        keytype: 18,
        value: vec![0x77; 32],
    }
}

/// A `KRB-ERROR` token as an acceptor makes one, with the server's clock and optional e-data.
fn krb_error(error_code: i32, stime: u64, e_data: Option<Vec<u8>>) -> Vec<u8> {
    let mut fields = vec![
        explicit(0, &int(5)),
        explicit(1, &int(30)),
        explicit(4, &KerberosTime::from_unix(stime).encode()),
        explicit(5, &int(0)),
        explicit(6, &int(i64::from(error_code))),
        explicit(9, &crate::kerberos::asn1::string("EXAMPLE.TEST")),
        explicit(10, &ticket().ticket.sname.encode()),
    ];
    if let Some(data) = e_data {
        fields.push(explicit(12, &octets(&data)));
    }
    frame(
        tok_id::ERROR,
        &der::tlv(der::application(30), &sequence(&fields)),
    )
}

fn error_data(data_type: i64, value: Option<&[u8]>) -> Vec<u8> {
    let mut fields = vec![explicit(1, &int(data_type))];
    if let Some(value) = value {
        fields.push(explicit(2, &octets(value)));
    }
    sequence(&fields)
}

/// [RFC 4121] §4.1 and §4.1.1, and [MS-KILE] §3.2.5.8: the framing, `mutual-required`, the ticket
/// byte for byte, and an authenticator with the `0x8003` checksum, a subkey, a sequence number and
/// — because the context is bound — `KERB_AP_OPTIONS_CBT` inside `AD-IF-RELEVANT`.
#[test]
fn a_bound_ap_req_carries_the_binding_twice() {
    let (_, token) = Initiator::start(ticket(), bound(), 0, &fresh(3)).unwrap();
    assert_eq!(token[0], 0x60, "[APPLICATION 0], RFC 2743 §3.1");
    let seen = open(&token);
    assert_eq!(seen.options, ap::MUTUAL_REQUIRED);
    assert_eq!(seen.raw_ticket, ticket().ticket.raw);
    assert_eq!(seen.ctime, KerberosTime::from_unix(NOW));
    assert_eq!(seen.cusec, 250_000);
    assert_eq!(seen.subkey.keytype, 18);
    assert_eq!(seen.subkey.value, vec![3; 32]);
    assert_eq!(seen.seq_number, 0x0303_0303);

    assert_eq!(seen.checksum.cksumtype, 0x8003);
    let value = &seen.checksum.checksum;
    assert_eq!(
        value.len(),
        24,
        "RFC 4121 §4.1.1: no more than 24 octets without delegation"
    );
    assert_eq!(value[..4], [16, 0, 0, 0]);
    assert_eq!(value[4..20], bound().as_bytes()[..]);
    assert_eq!(
        value[20..],
        [0x22, 0, 0, 0],
        "mutual and integrity, little-endian"
    );

    let cbt = authorization_data(&[(143, vec![0x00, 0x40, 0x00, 0x00])]);
    assert_eq!(seen.authorization, Some(authorization_data(&[(1, cbt)])));
}

#[test]
fn an_unbound_ap_req_says_nothing_about_a_binding() {
    let (_, token) = Initiator::start(ticket(), ChannelBinding::unbound(), 0, &fresh(3)).unwrap();
    let seen = open(&token);
    assert_eq!(seen.checksum.checksum[4..20], [0; 16]);
    assert_eq!(seen.authorization, None);
}

/// [RFC 4120] §3.2.5, and [RFC 4121] §2 and §4.2.6.1: the AP-REP proves the server, its subkey
/// becomes the key for MIC tokens in both directions, and the tokens say so.
#[test]
fn an_ap_rep_that_answers_is_accepted_and_its_subkey_signs() {
    let (mut initiator, token) = Initiator::start(ticket(), bound(), 0, &fresh(3)).unwrap();
    let seen = open(&token);
    let reply = ap_rep(seen.ctime, seen.cusec, Some(acceptor_subkey()), 18);
    assert_eq!(initiator.read(&reply, &fresh(4)).unwrap(), Reply::Accepted);

    // The acceptor's mechListMIC over the mechanism list, as a server would make it.
    let list = b"the DER of the mechanism list";
    let theirs = Key::new(Enctype::Aes256Sha1, vec![0x77; 32]).unwrap();
    let mut header = mic_header(mic_flag::SENT_BY_ACCEPTOR | mic_flag::ACCEPTOR_SUBKEY, 7);
    let checksum = theirs
        .checksum(usage::ACCEPTOR_SIGN, &[&list[..], &header].concat())
        .unwrap();
    header.extend_from_slice(&checksum);
    initiator.verify_mic(list, &header).unwrap();
    let mut tampered = header.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        initiator.verify_mic(list, &tampered),
        Err(Error::Crypto { .. })
    ));
    assert!(initiator.verify_mic(b"another list", &header).is_err());

    // The initiator's own MIC: same key, its own usage and direction, and a sequence that moves.
    let first = initiator.mic(list).unwrap();
    assert_eq!(first[..8], [0x04, 0x04, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(first[8..16], 0x0303_0303u64.to_be_bytes());
    let expected = theirs
        .checksum(usage::INITIATOR_SIGN, &[&list[..], &first[..16]].concat())
        .unwrap();
    assert_eq!(first[16..], expected[..]);
    let second = initiator.mic(list).unwrap();
    assert_eq!(second[8..16], 0x0303_0304u64.to_be_bytes());
}

/// Without an acceptor subkey, the initiator's own subkey is the base key, and the flag is clear.
#[test]
fn without_an_acceptor_subkey_the_initiators_signs() {
    let (mut initiator, token) = Initiator::start(ticket(), bound(), 0, &fresh(3)).unwrap();
    let seen = open(&token);
    initiator
        .read(&ap_rep(seen.ctime, seen.cusec, None, 18), &fresh(4))
        .unwrap();
    let mic = initiator.mic(b"list").unwrap();
    assert_eq!(
        mic[2], 0,
        "neither sent by the acceptor nor under its subkey"
    );
    let ours = Key::new(Enctype::Aes256Sha1, vec![3; 32]).unwrap();
    let expected = ours
        .checksum(usage::INITIATOR_SIGN, &[&b"list"[..], &mic[..16]].concat())
        .unwrap();
    assert_eq!(mic[16..], expected[..]);

    // The acceptor's token must then be under the initiator's subkey too, flag clear.
    let mut header = mic_header(mic_flag::SENT_BY_ACCEPTOR, 7);
    let checksum = ours
        .checksum(usage::ACCEPTOR_SIGN, &[&b"list"[..], &header].concat())
        .unwrap();
    header.extend_from_slice(&checksum);
    initiator.verify_mic(b"list", &header).unwrap();
}

#[test]
fn an_ap_rep_that_does_not_answer_is_refused() {
    let (initiator, token) = Initiator::start(ticket(), bound(), 0, &fresh(3)).unwrap();
    let seen = open(&token);
    for (reply, expected) in [
        (
            ap_rep(seen.ctime, seen.cusec + 1, None, 18),
            "an AP-REP that does not repeat the authenticator's time",
        ),
        (
            ap_rep(seen.ctime, seen.cusec, None, 17),
            "an AP-REP encrypted under a key of another type",
        ),
        (
            ap_rep(
                seen.ctime,
                seen.cusec,
                Some(EncryptionKey {
                    keytype: 23,
                    value: vec![1; 16],
                }),
                18,
            ),
            "an acceptor subkey of a type this client does not implement",
        ),
    ] {
        assert_eq!(
            initiator.clone().read(&reply, &fresh(4)),
            Err(Error::ServiceReply { reason: expected })
        );
    }

    // An AP-REP under another key is not the server's.
    let mut forged = initiator.clone();
    forged.ticket.key = Key::new(Enctype::Aes256Sha1, vec![0x43; 32]).unwrap();
    let reply = ap_rep(seen.ctime, seen.cusec, None, 18);
    assert!(matches!(
        forged.read(&reply, &fresh(4)),
        Err(Error::Crypto {
            usage: Some(12),
            ..
        })
    ));
}

/// [MS-KILE] §3.2.5.8: a `KRB_AP_ERR_SKEW` with `KERB-ERROR-DATA` is retried once, with the time
/// moved to the server's; anything else is the server's refusal.
#[test]
fn a_skew_error_is_retried_once_on_the_servers_clock() {
    let (mut initiator, _) = Initiator::start(ticket(), bound(), 0, &fresh(3)).unwrap();
    let skew = krb_error(37, NOW + 600, Some(error_data(2, None)));
    let Reply::Retry(retry) = initiator.read(&skew, &fresh(5)).unwrap() else {
        panic!("a retry")
    };
    let seen = open(&retry);
    assert_eq!(seen.ctime, KerberosTime::from_unix(NOW + 600));
    assert_eq!(seen.subkey.value, vec![5; 32], "a fresh subkey");
    assert_eq!(
        initiator.read(&skew, &fresh(6)),
        Err(Error::ServiceRefused {
            code: 37,
            status: None
        })
    );

    // A skew error without KERB-ERROR-DATA is not one MS-KILE says to recover from.
    let (mut bare, _) = Initiator::start(ticket(), bound(), 0, &fresh(3)).unwrap();
    assert_eq!(
        bare.read(&krb_error(37, NOW + 600, None), &fresh(5)),
        Err(Error::ServiceRefused {
            code: 37,
            status: None
        })
    );

    // Any other error is reported with the server's status.
    let mut ext = 0xC000_0133u32.to_le_bytes().to_vec(); // STATUS_TIME_DIFFERENCE_AT_DC
    ext.extend_from_slice(&[0; 8]);
    let refusal = krb_error(41, NOW, Some(error_data(3, Some(&ext))));
    assert_eq!(
        bare.read(&refusal, &fresh(5)),
        Err(Error::ServiceRefused {
            code: 41,
            status: Some(0xC000_0133)
        })
    );
}

#[test]
fn a_token_that_is_not_a_kerberos_context_token_is_refused() {
    let (mut initiator, _) = Initiator::start(ticket(), bound(), 0, &fresh(3)).unwrap();
    assert_eq!(
        initiator.read(&frame([0x04, 0x04], &[]), &fresh(4)),
        Err(Error::ServiceReply {
            reason: "a token that is neither an AP-REP nor a KRB-ERROR"
        })
    );

    // The truncated OID Windows 2000 used is accepted, as Windows accepts it.
    let mut legacy = der::tlv(der::OID, LEGACY_OID);
    legacy.extend_from_slice(&[0x02, 0x00, 0xAA]);
    let legacy = der::tlv(der::application(0), &legacy);
    assert_eq!(unframe(&legacy).unwrap(), ([0x02, 0x00], &[0xAA][..]));

    let ntlm = der::tlv(
        der::application(0),
        &der::tlv(der::OID, &[0x2B, 0x06, 0x01]),
    );
    assert!(matches!(unframe(&ntlm), Err(Error::Malformed { .. })));
    let no_id = der::tlv(der::application(0), &der::tlv(der::OID, OID));
    assert!(matches!(unframe(&no_id), Err(Error::Malformed { .. })));
    assert!(matches!(
        unframe(&[0x30, 0x00]),
        Err(Error::Malformed { .. })
    ));
    for len in 0..legacy.len() {
        let _ = unframe(&legacy[..len]);
    }
}

#[test]
fn a_mic_token_that_is_not_the_acceptors_is_refused() {
    let (mut initiator, token) = Initiator::start(ticket(), bound(), 0, &fresh(3)).unwrap();
    let seen = open(&token);
    initiator
        .read(
            &ap_rep(seen.ctime, seen.cusec, Some(acceptor_subkey()), 18),
            &fresh(4),
        )
        .unwrap();
    let good = mic_header(mic_flag::SENT_BY_ACCEPTOR | mic_flag::ACCEPTOR_SUBKEY, 7);
    let refused = Err(Error::ServiceReply {
        reason: "a MIC token that is not the acceptor's, under the context's key",
    });
    for (at, value) in [(0, 0x05), (2, 0x04), (2, 0x01), (3, 0x00)] {
        let mut bad = good.clone();
        bad[at] = value;
        bad.extend_from_slice(&[0; 12]);
        assert_eq!(initiator.verify_mic(b"list", &bad), refused, "byte {at}");
    }
    assert_eq!(
        initiator.verify_mic(b"list", &good[..15]),
        Err(Error::ServiceReply {
            reason: "a MIC token shorter than its header"
        })
    );
}

/// A whole AP-REQ read back field by field, so that nothing the authenticator carries is left
/// unexamined by the tests above.
#[test]
fn every_authenticator_field_reads_back() {
    let (_, token) = Initiator::start(ticket(), bound(), 0, &fresh(3)).unwrap();
    let (_, message) = unframe(&token).unwrap();
    let mut reader = Reader::new(STRUCTURE, message);
    let mut inner = reader.expect_nested(der::application(14), "").unwrap();
    let fields = Fields::of(&mut inner, "").unwrap();
    assert_eq!(
        read_int32(&mut fields.required(0, "").unwrap(), "").unwrap(),
        5
    );
    assert_eq!(
        read_int32(&mut fields.required(1, "").unwrap(), "").unwrap(),
        14
    );
    let sealed = EncryptedData::read(&mut fields.required(4, "").unwrap()).unwrap();
    let plain = ticket().key.decrypt(11, &sealed.cipher).unwrap();
    let mut reader = Reader::new(STRUCTURE, &plain);
    let mut inner = reader.expect_nested(der::application(2), "").unwrap();
    let fields = Fields::of(&mut inner, "").unwrap();
    assert_eq!(
        read_int32(&mut fields.required(0, "").unwrap(), "").unwrap(),
        5
    );
    assert_eq!(
        PrincipalName::read(&mut fields.required(2, "").unwrap()).unwrap(),
        ticket().cname
    );
}
