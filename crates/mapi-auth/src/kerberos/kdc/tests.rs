//! The KDC messages, written and read in the shapes [RFC 4120] §5 gives them.

use super::*;
use crate::kerberos::asn1::{flag, octets, string};

fn principal() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_ENTERPRISE, &["alice@example.test"])
}

fn body() -> KdcReqBody {
    KdcReqBody {
        options: flag(1) | flag(8) | flag(15),
        cname: Some(principal()),
        realm: "EXAMPLE.TEST".to_owned(),
        sname: Some(PrincipalName::new(2, &["krbtgt", "EXAMPLE.TEST"])),
        till: KerberosTime::from_unix(1_800_000_000),
        nonce: 0x1234_5678,
        etypes: vec![20, 19, 18, 17],
        enc_authorization_data: None,
    }
}

/// [RFC 4120] §5.4.1: `[APPLICATION 10]`, pvno 5, msg-type 10, padata only when there is any,
/// and the body exactly as it was encoded.
#[test]
fn an_as_req_is_the_shape_rfc4120_gives_it() {
    let encoded_body = body().encode();
    let padata = [
        PaData {
            padata_type: padata::ENC_TIMESTAMP,
            value: vec![0x30, 0x00],
        },
        PaData {
            padata_type: padata::PAC_REQUEST,
            value: pac_request(true),
        },
    ];
    let as_req = request(Exchange::As, &padata, &encoded_body);
    assert_eq!(as_req[0], 0x6A);

    let mut reader = Reader::new(STRUCTURE, &as_req);
    let mut inner = reader
        .expect_nested(der::application(10), "AS-REQ")
        .unwrap();
    let fields = Fields::of(&mut inner, "KDC-REQ").unwrap();
    assert_eq!(
        read_int32(&mut fields.required(1, "").unwrap(), "").unwrap(),
        5
    );
    assert_eq!(
        read_int32(&mut fields.required(2, "").unwrap(), "").unwrap(),
        10
    );
    assert_eq!(
        PaData::read_all(&mut fields.required(3, "").unwrap()).unwrap(),
        padata
    );
    assert_eq!(
        fields.required(4, "").unwrap().read_element().unwrap(),
        encoded_body
    );

    // A TGS-REQ is authenticated by its PA-TGS-REQ; with no padata at all there is no [3].
    let tgs_req = request(
        Exchange::Tgs,
        &[PaData {
            padata_type: padata::TGS_REQ,
            value: vec![0x6E, 0x00],
        }],
        &encoded_body,
    );
    assert_eq!(tgs_req[0], 0x6C);
    let bare = request(Exchange::Tgs, &[], &encoded_body);
    assert_eq!(bare[0], 0x6C);
    let mut reader = Reader::new(STRUCTURE, &bare);
    let mut inner = reader
        .expect_nested(der::application(12), "TGS-REQ")
        .unwrap();
    assert!(Fields::of(&mut inner, "").unwrap().optional(3).is_none());
}

#[test]
fn the_request_body_carries_its_fields_in_order() {
    let encoded = body().encode();
    let mut reader = Reader::new(STRUCTURE, &encoded);
    let fields = Fields::of(&mut reader, "KDC-REQ-BODY").unwrap();
    assert_eq!(
        read_flags(&mut fields.required(0, "").unwrap(), "").unwrap(),
        flag(1) | flag(8) | flag(15)
    );
    assert_eq!(
        PrincipalName::read(&mut fields.required(1, "").unwrap()).unwrap(),
        principal()
    );
    assert_eq!(
        read_uint32(&mut fields.required(7, "").unwrap(), "").unwrap(),
        0x1234_5678
    );
    let mut etypes = fields
        .required(8, "")
        .unwrap()
        .expect_nested(der::SEQUENCE, "")
        .unwrap();
    let mut seen = Vec::new();
    while !etypes.is_empty() {
        seen.push(read_int32(&mut etypes, "").unwrap());
    }
    assert_eq!(seen, [20, 19, 18, 17], "strongest first");
    assert!(fields.optional(10).is_none());
}

/// The ticket, as a KDC would issue it: realm, sname, and an encrypted part the client never reads.
fn ticket(realm: &str, sname: &PrincipalName) -> Vec<u8> {
    der::tlv(
        der::application(1),
        &sequence(&[
            explicit(0, &int(5)),
            explicit(1, &string(realm)),
            explicit(2, &sname.encode()),
            explicit(
                3,
                &EncryptedData {
                    etype: 18,
                    kvno: Some(3),
                    cipher: vec![0xC1; 48],
                }
                .encode(),
            ),
        ]),
    )
}

fn reply(msg_type: i64, ticket: &[u8]) -> Vec<u8> {
    der::tlv(
        der::application(u8::try_from(msg_type).unwrap()),
        &sequence(&[
            explicit(0, &int(5)),
            explicit(1, &int(msg_type)),
            explicit(
                2,
                &der::tlv(
                    der::SEQUENCE,
                    &PaData {
                        padata_type: padata::ETYPE_INFO2,
                        value: vec![1],
                    }
                    .encode(),
                ),
            ),
            explicit(3, &string("EXAMPLE.TEST")),
            explicit(4, &principal().encode()),
            explicit(5, ticket),
            explicit(
                6,
                &EncryptedData {
                    etype: 18,
                    kvno: None,
                    cipher: vec![0xE0; 64],
                }
                .encode(),
            ),
        ]),
    )
}

#[test]
fn a_reply_is_read_and_its_ticket_kept_byte_for_byte() {
    let sname = PrincipalName::new(2, &["krbtgt", "PARENT.TEST"]);
    let issued = ticket("EXAMPLE.TEST", &sname);
    let as_rep = reply(11, &issued);

    let KdcReply::Rep(rep) = read_reply(Exchange::As, &as_rep).unwrap() else {
        panic!("expected a reply");
    };
    assert_eq!(rep.exchange, Exchange::As);
    assert_eq!(rep.crealm, "EXAMPLE.TEST");
    assert_eq!(rep.cname, principal());
    assert_eq!(rep.ticket.raw, issued, "sent on exactly as issued");
    assert_eq!(rep.ticket.realm, "EXAMPLE.TEST");
    assert_eq!(rep.ticket.sname, sname);
    assert!(rep.ticket.sname.is_krbtgt());
    assert_eq!(rep.enc_part.cipher, vec![0xE0; 64]);
    assert_eq!(rep.padata.len(), 1);

    // A TGS-REP read where an AS-REP was expected, or the wrong msg-type inside the right tag.
    assert!(read_reply(Exchange::Tgs, &as_rep).is_err());
    let mut lying = as_rep.clone();
    let at = lying
        .windows(5)
        .position(|w| w == [0xA1, 0x03, 0x02, 0x01, 11])
        .unwrap();
    lying[at + 4] = 13;
    assert!(read_reply(Exchange::As, &lying).is_err());
}

fn krb_error(code: i64, e_data: Option<&[u8]>) -> Vec<u8> {
    let mut fields = vec![
        explicit(0, &int(5)),
        explicit(1, &int(30)),
        explicit(4, &KerberosTime::from_unix(1_800_000_000).encode()),
        explicit(5, &int(123_456)),
        explicit(6, &int(code)),
        explicit(9, &string("EXAMPLE.TEST")),
        explicit(
            10,
            &PrincipalName::new(2, &["krbtgt", "EXAMPLE.TEST"]).encode(),
        ),
        explicit(11, &string("NEEDED_PREAUTH")),
    ];
    if let Some(data) = e_data {
        fields.push(explicit(12, &octets(data)));
    }
    der::tlv(der::application(30), &sequence(&fields))
}

#[test]
fn a_krb_error_is_read_with_its_time_text_and_data() {
    let KdcReply::Error(error) = read_reply(Exchange::As, &krb_error(25, Some(b"md"))).unwrap()
    else {
        panic!("expected an error");
    };
    assert_eq!(error.error_code, 25);
    assert_eq!(error.stime, KerberosTime::from_unix(1_800_000_000));
    assert_eq!(error.susec, 123_456);
    assert_eq!(error.realm, "EXAMPLE.TEST");
    assert_eq!(error.e_text.as_deref(), Some("NEEDED_PREAUTH"));
    assert_eq!(error.e_data.as_deref(), Some(&b"md"[..]));

    // An error is an error whichever exchange asked.
    assert!(matches!(
        read_reply(Exchange::Tgs, &krb_error(7, None)),
        Ok(KdcReply::Error(KrbError {
            error_code: 7,
            e_data: None,
            ..
        }))
    ));
    assert!(read_reply(Exchange::As, &[]).is_err());
    assert!(read_reply(Exchange::As, &der::tlv(der::application(5), &[])).is_err());
}

fn enc_part(tag: u8) -> Vec<u8> {
    der::tlv(
        der::application(tag),
        &sequence(&[
            explicit(
                0,
                &EncryptionKey {
                    keytype: 18,
                    value: vec![7; 32],
                }
                .encode(),
            ),
            explicit(1, &der::tlv(der::SEQUENCE, &[])),
            explicit(2, &int(0x1234_5678)),
            explicit(4, &flags(flag(9) | flag(10))),
            explicit(5, &KerberosTime::from_unix(1_800_000_000).encode()),
            explicit(7, &KerberosTime::from_unix(1_800_036_000).encode()),
            explicit(9, &string("EXAMPLE.TEST")),
            explicit(
                10,
                &PrincipalName::new(2, &["krbtgt", "EXAMPLE.TEST"]).encode(),
            ),
            // [RFC 6806] §11's encrypted-pa-data, which this client does not read.
            explicit(12, &der::tlv(der::SEQUENCE, &[])),
        ]),
    )
}

/// [RFC 4120] §5.4.2's compatibility note: either tag, whichever exchange.
#[test]
fn an_encrypted_reply_part_is_read_under_either_tag() {
    for tag in [25, 26] {
        let part = EncKdcRepPart::read(&enc_part(tag)).unwrap();
        assert_eq!(part.key.value, vec![7; 32]);
        assert_eq!(part.nonce, 0x1234_5678);
        assert_eq!(part.flags, flag(9) | flag(10), "initial, pre-authent");
        assert_eq!(part.endtime, KerberosTime::from_unix(1_800_036_000));
        assert_eq!(part.srealm, "EXAMPLE.TEST");
        assert!(part.sname.is_krbtgt());
    }
    assert!(EncKdcRepPart::read(&enc_part(27)).is_err());
    assert!(EncKdcRepPart::read(&[]).is_err());
}

#[test]
fn pre_authentication_data_is_written_and_read() {
    assert_eq!(
        pac_request(true),
        [0x30, 0x05, 0xA0, 0x03, 0x01, 0x01, 0xFF],
        "the encoding every Windows client sends"
    );
    assert_eq!(
        pa_enc_ts_enc(KerberosTime::from_unix(0), 5),
        sequence(&[
            explicit(0, &der::tlv(der::GENERALIZED_TIME, b"19700101000000Z")),
            explicit(1, &int(5)),
        ])
    );

    let info = der::tlv(
        der::SEQUENCE,
        &[
            sequence(&[
                explicit(0, &int(18)),
                explicit(1, &string("EXAMPLE.TESTalice")),
                explicit(2, &octets(&[0, 0, 0x10, 0])),
            ]),
            sequence(&[explicit(0, &int(23))]),
        ]
        .concat(),
    );
    let entries = EtypeInfo2::read_all(&info).unwrap();
    assert_eq!(entries[0].etype, 18);
    assert_eq!(entries[0].salt.as_deref(), Some("EXAMPLE.TESTalice"));
    assert_eq!(entries[0].s2kparams.as_deref(), Some(&[0, 0, 0x10, 0][..]));
    assert_eq!(entries[1].etype, 23);
    assert_eq!(entries[1].salt, None);
}

/// [MS-KILE] §2.2.2 and §2.2.1: the extended error's `NTSTATUS` is little-endian; and `e-data`
/// that is a `METHOD-DATA` is not mistaken for one.
#[test]
fn a_windows_error_data_is_read_and_anything_else_is_not() {
    let mut ext = 0xC000_006Au32.to_le_bytes().to_vec(); // STATUS_WRONG_PASSWORD
    ext.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
    let encoded = sequence(&[explicit(1, &int(3)), explicit(2, &octets(&ext))]);
    let data = ErrorData::read(&encoded).unwrap();
    assert_eq!(data.data_type, ErrorData::EXTENDED);
    assert_eq!(data.ntstatus(), Some(0xC000_006A));

    let skew = sequence(&[explicit(1, &int(2))]);
    let data = ErrorData::read(&skew).unwrap();
    assert_eq!(data.data_type, ErrorData::SKEW_RECOVERY);
    assert_eq!(data.ntstatus(), None);

    let method_data = der::tlv(
        der::SEQUENCE,
        &PaData {
            padata_type: 19,
            value: vec![],
        }
        .encode(),
    );
    assert_eq!(ErrorData::read(&method_data), None);
}

#[test]
fn no_truncation_of_a_reply_panics() {
    let rep = reply(11, &ticket("EXAMPLE.TEST", &principal()));
    let error = krb_error(25, Some(&[1, 2, 3]));
    let part = enc_part(25);
    for buffer in [&rep, &error, &part] {
        for len in 0..buffer.len() {
            let slice = &buffer[..len];
            let _ = read_reply(Exchange::As, slice);
            let _ = EncKdcRepPart::read(slice);
            let _ = EtypeInfo2::read_all(slice);
            let _ = ErrorData::read(slice);
        }
    }
}
