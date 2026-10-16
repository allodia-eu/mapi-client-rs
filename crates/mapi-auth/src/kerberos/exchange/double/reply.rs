//! Building the double's replies: a ticket it will recognise when it is presented again, and an
//! encrypted part with whatever [`Fault`] the test asked for.

use super::{Fault, Forest, Issued, krbtgt};
use crate::der;
use crate::kerberos::asn1::{
    Checksum, EncryptedData, EncryptionKey, KerberosTime, PaData, PrincipalName, explicit, flag,
    flags, int, sequence, string,
};
use crate::kerberos::crypto::{Enctype, Key};
use crate::kerberos::kdc::padata;

/// One reply to build.
pub(super) struct Reply<'a> {
    pub(super) as_rep: bool,
    pub(super) realm: &'a str,
    pub(super) crealm: String,
    pub(super) cname: PrincipalName,
    pub(super) key: Key,
    pub(super) nonce: u32,
    pub(super) sname: PrincipalName,
    pub(super) tgs_for: Option<String>,
    pub(super) outer: Vec<PaData>,
    pub(super) checksum_over: Option<Vec<u8>>,
}

impl Forest {
    pub(super) fn reply(&mut self, reply: Reply<'_>) -> Vec<u8> {
        let fault = self.fault.take();
        let realm = if fault == Some(Fault::TicketFromAnotherRealm) {
            "ELSEWHERE.TEST"
        } else {
            reply.realm
        };
        let sname = if fault == Some(Fault::TicketNotKrbtgt) {
            PrincipalName::new(2, &["HTTP", "elsewhere.test"])
        } else {
            reply.sname
        };
        let (raw, session) = self.issue(realm, &sname, &reply.crealm, &reply.cname, reply.tgs_for);

        let (ticket_flags, encrypted) = encrypted_pa_data(fault, &reply.key, reply.checksum_over);
        let keytype = match fault {
            Some(Fault::SessionKeyType(keytype)) => keytype,
            _ => 18,
        };
        let inner_sname = if fault == Some(Fault::InnerNameDiffers) {
            krbtgt("ELSEWHERE.TEST")
        } else {
            sname
        };
        let nonce = if fault == Some(Fault::WrongNonce) {
            reply.nonce ^ 1
        } else {
            reply.nonce
        };
        let mut part = vec![
            explicit(
                0,
                &EncryptionKey {
                    keytype,
                    value: session.bytes().to_vec(),
                }
                .encode(),
            ),
            explicit(1, &der::tlv(der::SEQUENCE, &[])),
            explicit(2, &int(i64::from(nonce))),
            explicit(4, &flags(ticket_flags)),
            explicit(5, &KerberosTime::from_unix(self.clock).encode()),
            explicit(
                7,
                &KerberosTime::from_unix(self.clock.saturating_add(36_000)).encode(),
            ),
            explicit(9, &string(realm)),
            explicit(10, &inner_sname.encode()),
        ];
        if !encrypted.is_empty() {
            let list: Vec<u8> = encrypted.iter().flat_map(PaData::encode).collect();
            part.push(explicit(12, &der::tlv(der::SEQUENCE, &list)));
        }
        let (tag, msg_type, usage): (u8, u8, u32) = if reply.as_rep {
            (25, 11, 3)
        } else {
            (26, 13, 8)
        };
        let part = der::tlv(der::application(tag), &sequence(&part));
        let etype = match fault {
            Some(Fault::EncPartEtype(etype)) => etype,
            _ => reply.key.enctype().number(),
        };
        let cipher = reply.key.encrypt(usage, &[0x33; 16], &part).unwrap();
        let cname = if fault == Some(Fault::ClientRenamed) {
            PrincipalName::new(1, &["mallory"])
        } else {
            reply.cname
        };

        let mut fields = vec![explicit(0, &int(5)), explicit(1, &int(i64::from(msg_type)))];
        if !reply.outer.is_empty() {
            let list: Vec<u8> = reply.outer.iter().flat_map(PaData::encode).collect();
            fields.push(explicit(2, &der::tlv(der::SEQUENCE, &list)));
        }
        fields.extend([
            explicit(3, &string(&reply.crealm)),
            explicit(4, &cname.encode()),
            explicit(5, &raw),
            explicit(
                6,
                &EncryptedData {
                    etype,
                    kvno: None,
                    cipher,
                }
                .encode(),
            ),
        ]);
        der::tlv(der::application(msg_type), &sequence(&fields))
    }

    /// Makes a ticket and remembers what it was issued for, so that a later TGS-REQ presenting it
    /// can be checked.
    fn issue(
        &mut self,
        realm: &str,
        sname: &PrincipalName,
        crealm: &str,
        cname: &PrincipalName,
        tgs_for: Option<String>,
    ) -> (Vec<u8>, Key) {
        self.serial = self.serial.wrapping_add(1);
        let session = Key::new(Enctype::Aes256Sha1, vec![self.serial; 32]).unwrap();
        let sealed = EncryptedData {
            etype: 18,
            kvno: Some(2),
            cipher: vec![self.serial; 8],
        };
        let raw = der::tlv(
            der::application(1),
            &sequence(&[
                explicit(0, &int(5)),
                explicit(1, &string(realm)),
                explicit(2, &sname.encode()),
                explicit(3, &sealed.encode()),
            ]),
        );
        self.issued.push(Issued {
            raw: raw.clone(),
            key: session.clone(),
            crealm: crealm.to_owned(),
            cname: cname.clone(),
            tgs_for,
        });
        (raw, session)
    }
}

/// The ticket flags and `encrypted-pa-data` of a reply: [RFC 6806] §11's checksum of the request
/// when one was asked for, and the `PA-SUPPORTED-ENCTYPES` a Windows KDC adds beside it.
fn encrypted_pa_data(fault: Option<Fault>, key: &Key, over: Option<Vec<u8>>) -> (u32, Vec<PaData>) {
    let mut ticket_flags = flag(1) | flag(8);
    let mut encrypted = Vec::new();
    if let Some(over) = over {
        ticket_flags |= flag(15);
        let over = if fault == Some(Fault::ChecksumOverOtherBytes) {
            b"another request".to_vec()
        } else {
            over
        };
        let cksumtype = if fault == Some(Fault::ChecksumOfAnotherType) {
            15
        } else {
            key.enctype().checksum_type()
        };
        let checksum = Checksum {
            cksumtype,
            checksum: key.checksum(56, &over).unwrap(),
        };
        if fault != Some(Fault::ChecksumMissing) {
            encrypted.push(PaData {
                padata_type: padata::REQ_ENC_PA_REP,
                value: checksum.encode(),
            });
        }
        encrypted.push(PaData {
            padata_type: 165,
            value: vec![0; 4],
        });
    }
    (ticket_flags, encrypted)
}
