//! A Kerberos acceptor for the tests, holding the session key — which is all an acceptor needs
//! once it has decrypted the ticket: it reads what an initiator sends and answers the way IIS was
//! measured answering.

use core::time::Duration;

use super::{frame, mic_flag, mic_header, tok_id, unframe, usage};
use crate::binding::ChannelBinding;
use crate::der::{self, Reader};
use crate::kerberos::asn1::{
    Checksum, EncryptedData, EncryptionKey, Fields, KerberosTime, PrincipalName, STRUCTURE,
    explicit, int, octets, read_flags, read_uint32, sequence,
};
use crate::kerberos::crypto::{Enctype, Key};
use crate::kerberos::exchange::Credential;
use crate::kerberos::fresh::Fresh;
use crate::kerberos::kdc::Ticket;

pub(crate) const NOW: u64 = 1_800_000_000;

pub(crate) fn fresh(seed: u8) -> Fresh {
    Fresh {
        now: Duration::new(NOW, 250_000_000),
        random: [seed; 64],
    }
}

pub(crate) fn ticket() -> Credential {
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

pub(crate) fn bound() -> ChannelBinding {
    ChannelBinding::tls_server_end_point(b"the server certificate")
}

/// What an acceptor reads out of an AP-REQ token.
pub(crate) struct Seen {
    pub(crate) options: u32,
    pub(crate) raw_ticket: Vec<u8>,
    pub(crate) checksum: Checksum,
    pub(crate) ctime: KerberosTime,
    pub(crate) cusec: u32,
    pub(crate) subkey: EncryptionKey,
    pub(crate) seq_number: u32,
    pub(crate) authorization: Option<Vec<u8>>,
}

pub(crate) fn open(token: &[u8]) -> Seen {
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
pub(crate) fn ap_rep(
    ctime: KerberosTime,
    cusec: u32,
    subkey: Option<EncryptionKey>,
    etype: i32,
) -> Vec<u8> {
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

pub(crate) fn acceptor_subkey() -> EncryptionKey {
    EncryptionKey {
        keytype: 18,
        value: vec![0x77; 32],
    }
}

/// A `KRB-ERROR` token as an acceptor makes one, with the server's clock and optional e-data.
pub(crate) fn krb_error(error_code: i32, stime: u64, e_data: Option<Vec<u8>>) -> Vec<u8> {
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

pub(crate) fn error_data(data_type: i64, value: Option<&[u8]>) -> Vec<u8> {
    let mut fields = vec![explicit(1, &int(data_type))];
    if let Some(value) = value {
        fields.push(explicit(2, &octets(value)));
    }
    sequence(&fields)
}

/// The acceptor's `mechListMIC` over `list`, under the acceptor subkey [`acceptor_subkey`].
pub(crate) fn acceptor_mic(list: &[u8]) -> Vec<u8> {
    let key = Key::new(Enctype::Aes256Sha1, vec![0x77; 32]).unwrap();
    let mut token = mic_header(mic_flag::SENT_BY_ACCEPTOR | mic_flag::ACCEPTOR_SUBKEY, 7);
    let checksum = key
        .checksum(usage::ACCEPTOR_SIGN, &[list, &token].concat())
        .unwrap();
    token.extend_from_slice(&checksum);
    token
}

/// Opens an AP-REQ token and answers it with an AP-REP asserting [`acceptor_subkey`].
pub(crate) fn answer(token: &[u8]) -> Vec<u8> {
    let seen = open(token);
    ap_rep(seen.ctime, seen.cusec, Some(acceptor_subkey()), 18)
}
