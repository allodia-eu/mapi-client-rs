//! The `AP-REQ` — [RFC 4120] §5.5.1 — which proves its sender holds a ticket's session key: to a
//! ticket-granting service inside a TGS-REQ's `PA-TGS-REQ` (§5.4.1), and to an application server
//! inside a GSS-API token ([RFC 4121] §4.1).

use crate::der;
use crate::kerberos::asn1::{
    Checksum, EncryptedData, KerberosTime, PVNO, PrincipalName, explicit, flags, int, sequence,
    string,
};

/// The application tag and `msg-type` of an `AP-REQ` — [RFC 4120] §5.5.1.
const AP_REQ: u8 = 14;

/// The application tag of an `Authenticator` — [RFC 4120] §5.5.1.
const AUTHENTICATOR: u8 = 2;

/// `Authenticator` — [RFC 4120] §5.5.1: the part of an `AP-REQ` encrypted under the session key,
/// which is what makes it fresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Authenticator {
    /// `crealm`: the client's realm — the one in the ticket, not the realm being asked.
    pub(crate) crealm: String,
    /// `cname`: the client's name as the KDC canonicalized it.
    pub(crate) cname: PrincipalName,
    /// `cksum`: in a `PA-TGS-REQ`, a keyed checksum of the request body under key usage 6
    /// ([RFC 4120] §7.5.1); in a GSS token, [RFC 4121] §4.1.1's `0x8003` structure.
    pub(crate) cksum: Option<Checksum>,
    /// `cusec`: the microseconds of the client's time.
    pub(crate) cusec: u32,
    /// `ctime`: the client's time, corrected for any skew the KDC has reported.
    pub(crate) ctime: KerberosTime,
}

impl Authenticator {
    /// The `[APPLICATION 2]` element, ready to be encrypted.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut fields = vec![
            explicit(0, &int(PVNO)),
            explicit(1, &string(&self.crealm)),
            explicit(2, &self.cname.encode()),
        ];
        if let Some(cksum) = &self.cksum {
            fields.push(explicit(3, &cksum.encode()));
        }
        fields.push(explicit(4, &int(i64::from(self.cusec))));
        fields.push(explicit(5, &self.ctime.encode()));
        der::tlv(der::application(AUTHENTICATOR), &sequence(&fields))
    }
}

/// An `AP-REQ` presenting `ticket` — the whole `Ticket` element, as the KDC sent it — with an
/// encrypted [`Authenticator`].
///
/// `options` is `ap-options`, numbered as [`super::asn1::flag`] numbers them.
pub(crate) fn request(options: u32, ticket: &[u8], authenticator: &EncryptedData) -> Vec<u8> {
    der::tlv(
        der::application(AP_REQ),
        &sequence(&[
            explicit(0, &int(PVNO)),
            explicit(1, &int(i64::from(AP_REQ))),
            explicit(2, &flags(options)),
            explicit(3, ticket),
            explicit(4, &authenticator.encode()),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::Reader;
    use crate::kerberos::asn1::{Fields, STRUCTURE, read_flags, read_int32, read_string};

    fn authenticator(cksum: Option<Checksum>) -> Authenticator {
        Authenticator {
            crealm: "EXAMPLE.TEST".to_owned(),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, &["alice"]),
            cksum,
            cusec: 42,
            ctime: KerberosTime::from_unix(1_800_000_000),
        }
    }

    /// [RFC 4120] §5.5.1: `[APPLICATION 2]`, `authenticator-vno` 5, and the checksum only when
    /// there is one.
    #[test]
    fn an_authenticator_is_the_shape_rfc4120_gives_it() {
        let cksum = Checksum {
            cksumtype: 16,
            checksum: vec![9; 12],
        };
        let encoded = authenticator(Some(cksum.clone())).encode();
        assert_eq!(encoded[0], 0x62);
        let mut reader = Reader::new(STRUCTURE, &encoded);
        let mut inner = reader
            .expect_nested(der::application(2), "an Authenticator")
            .unwrap();
        let fields = Fields::of(&mut inner, "an Authenticator").unwrap();
        assert_eq!(
            read_int32(&mut fields.required(0, "").unwrap(), "").unwrap(),
            5
        );
        assert_eq!(
            read_string(&mut fields.required(1, "").unwrap(), "").unwrap(),
            "EXAMPLE.TEST"
        );
        assert_eq!(
            Checksum::read(&mut fields.required(3, "").unwrap()).unwrap(),
            cksum
        );
        assert_eq!(
            read_int32(&mut fields.required(4, "").unwrap(), "").unwrap(),
            42
        );
        assert_eq!(
            KerberosTime::read(&mut fields.required(5, "").unwrap(), "").unwrap(),
            KerberosTime::from_unix(1_800_000_000)
        );

        let bare = authenticator(None).encode();
        let mut reader = Reader::new(STRUCTURE, &bare);
        let mut inner = reader.expect_nested(der::application(2), "").unwrap();
        assert!(Fields::of(&mut inner, "").unwrap().optional(3).is_none());
    }

    /// [RFC 4120] §5.5.1: `[APPLICATION 14]`, `msg-type` 14, and the ticket byte for byte.
    #[test]
    fn an_ap_req_carries_the_ticket_unchanged() {
        let ticket = der::tlv(der::application(1), &[0x30, 0x00]);
        let sealed = EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![1, 2, 3],
        };
        let encoded = request(super::super::asn1::flag(2), &ticket, &sealed);
        let mut reader = Reader::new(STRUCTURE, &encoded);
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
        assert_eq!(
            read_flags(&mut fields.required(2, "").unwrap(), "").unwrap(),
            0x2000_0000,
            "mutual-required is flag 2"
        );
        assert_eq!(
            fields.required(3, "").unwrap().read_element().unwrap(),
            ticket
        );
        assert_eq!(
            EncryptedData::read(&mut fields.required(4, "").unwrap()).unwrap(),
            sealed
        );
    }
}
