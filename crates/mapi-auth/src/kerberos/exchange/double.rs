//! A forest of KDCs for the tests, built from this crate's own encoders and cryptography.
//!
//! It answers what [`super::Acquisition`] sends the way the Windows KDCs it was measured against
//! do — `PREAUTH_REQUIRED` with a salt, `WRONG_REALM` with the user's realm in `crealm`, referral
//! tickets for services it does not hold, `PA-REQ-ENC-PA-REP` honoured — and it checks each request
//! the way a KDC would: the timestamp decrypts and is current, the authenticator decrypts under the
//! presented ticket's key and checksums the body, the ticket presented is the one for the realm
//! asked. A request it cannot accept fails the test rather than earning an error, so a client bug
//! cannot hide behind a KDC that was too lenient.

use crate::der::{self, Reader};
use crate::kerberos::asn1::{
    Checksum, EncryptedData, Fields, KerberosTime, PaData, PrincipalName, STRUCTURE, explicit, int,
    octets, read_string, read_uint32, sequence, string,
};
use crate::kerberos::crypto::{Enctype, Key};
use crate::kerberos::kdc::{BRANCH_AWARE, code, pac_options, padata};

/// The KDC's clock, which the tests' [`super::Fresh`] matches unless a test says otherwise.
pub(crate) const KDC_TIME: u64 = 1_800_000_000;

/// The string-to-key iteration count the forest hands out, kept low so that the tests stay fast.
/// The test of a KDC that sends no salt takes [RFC 3962]'s default instead.
const ITERATIONS: [u8; 4] = [0, 0, 0, 2];

/// The `NTSTATUS` a Windows KDC attaches to a wrong password: `STATUS_WRONG_PASSWORD`.
pub(crate) const WRONG_PASSWORD: u32 = 0xC000_006A;

/// What a test asks the next reply to get wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    WrongNonce,
    ChecksumOverOtherBytes,
    ChecksumMissing,
    ChecksumOfAnotherType,
    TicketNotKrbtgt,
    TicketFromAnotherRealm,
    ClientRenamed,
    SessionKeyType(i32),
    EncPartEtype(i32),
    InnerNameDiffers,
    Unparsable,
    /// `PA-ETYPE-INFO2` lists only RC4.
    Rc4Only,
    /// `PA-ETYPE-INFO2` is missing altogether.
    NoEtypeInfo,
    /// `WRONG_REALM` naming the realm asked.
    ReferToItself,
}

pub(crate) struct User {
    pub(crate) name: &'static str,
    pub(crate) upn: &'static str,
    pub(crate) password: &'static str,
    pub(crate) preauth: bool,
}

pub(crate) struct Realm {
    pub(crate) name: &'static str,
    pub(crate) users: Vec<User>,
    pub(crate) services: Vec<&'static str>,
    /// Where a TGS-REQ for a service this realm does not hold is referred.
    pub(crate) referral: Option<&'static str>,
}

struct Issued {
    raw: Vec<u8>,
    key: Key,
    crealm: String,
    cname: PrincipalName,
    /// The realm whose `krbtgt` this is, for a ticket-granting ticket.
    tgs_for: Option<String>,
}

pub(crate) struct Forest {
    pub(crate) realms: Vec<Realm>,
    pub(crate) clock: u64,
    pub(crate) fault: Option<Fault>,
    /// Whether the KDCs honour `PA-REQ-ENC-PA-REP`, as Windows Server 2025 was measured to.
    pub(crate) enc_pa_rep: bool,
    /// Whether `PA-ETYPE-INFO2` carries a salt and an iteration count, as Active Directory does.
    pub(crate) salts: bool,
    /// The realm of every request, in order.
    pub(crate) asked: Vec<String>,
    issued: Vec<Issued>,
    serial: u8,
}

impl Forest {
    pub(crate) fn new(realms: Vec<Realm>) -> Self {
        Self {
            realms,
            clock: KDC_TIME,
            fault: None,
            enc_pa_rep: true,
            salts: true,
            asked: Vec::new(),
            issued: Vec::new(),
            serial: 0,
        }
    }

    fn take(&mut self, fault: Fault) -> bool {
        self.fault.take_if(|next| *next == fault).is_some()
    }

    /// Answers one request sent to `realm`'s KDC.
    pub(crate) fn answer(&mut self, realm: &str, message: &[u8]) -> Vec<u8> {
        self.asked.push(realm.to_owned());
        if self.take(Fault::Unparsable) {
            return vec![0x30, 0x80];
        }
        let mut reader = Reader::new(STRUCTURE, message);
        let tag = reader.peek_tag().unwrap();
        let mut inner = reader.expect_nested(tag, "a request").unwrap();
        let fields = Fields::of(&mut inner, "KDC-REQ").unwrap();
        let padata = PaData::read_all(&mut fields.required(3, "").unwrap()).unwrap();
        let body_bytes = fields
            .required(4, "")
            .unwrap()
            .read_element()
            .unwrap()
            .to_vec();
        let body = Fields::of(&mut Reader::new(STRUCTURE, &body_bytes), "body").unwrap();
        assert_eq!(
            read_string(&mut body.required(2, "").unwrap(), "").unwrap(),
            realm
        );
        let nonce = read_uint32(&mut body.required(7, "").unwrap(), "").unwrap();
        assert!(nonce < 0x8000_0000, "the nonce never has its top bit set");
        let sname = PrincipalName::read(&mut body.required(3, "").unwrap()).unwrap();
        if tag == der::application(10) {
            let cname = PrincipalName::read(&mut body.required(1, "").unwrap()).unwrap();
            self.as_exchange(realm, &cname, &sname, nonce, &padata, message)
        } else {
            assert_eq!(tag, der::application(12));
            self.tgs_exchange(realm, sname, nonce, &padata, &body_bytes)
        }
    }

    fn as_exchange(
        &mut self,
        realm: &str,
        cname: &PrincipalName,
        sname: &PrincipalName,
        nonce: u32,
        padata: &[PaData],
        message: &[u8],
    ) -> Vec<u8> {
        assert_eq!(sname.components, ["krbtgt", realm]);
        let types: Vec<i32> = padata.iter().map(|data| data.padata_type).collect();
        assert!(types.contains(&padata::PAC_REQUEST), "MS-KILE §3.2.5.5");
        assert!(types.contains(&padata::REQ_ENC_PA_REP), "RFC 6806 §11");
        if self.take(Fault::ReferToItself) {
            return self.error(realm, code::WRONG_REALM, Some(realm), None);
        }

        let wanted = cname.components[0].as_str();
        let enterprise = cname.name_type == PrincipalName::NT_ENTERPRISE;
        let found = self.realms.iter().find_map(|home| {
            home.users
                .iter()
                .find(|user| {
                    if enterprise {
                        user.upn.eq_ignore_ascii_case(wanted)
                    } else {
                        home.name == realm && user.name.eq_ignore_ascii_case(wanted)
                    }
                })
                .map(|user| (home.name, user.name, user.password, user.preauth))
        });
        let Some((home, name, password, preauth)) = found else {
            return self.error(realm, code::C_PRINCIPAL_UNKNOWN, None, None);
        };
        if home != realm {
            return self.error(realm, code::WRONG_REALM, Some(home), None);
        }

        let salt = format!("{realm}{name}");
        let key = Key::from_password(
            Enctype::Aes256Sha1,
            password,
            salt.as_bytes(),
            self.params(),
        )
        .unwrap();
        let info = self.etype_info(&salt);
        if preauth {
            let Some(timestamp) = padata
                .iter()
                .find(|data| data.padata_type == padata::ENC_TIMESTAMP)
            else {
                let method_data = der::tlv(
                    der::SEQUENCE,
                    &info
                        .into_iter()
                        .flat_map(|data| data.encode())
                        .collect::<Vec<_>>(),
                );
                return self.error(realm, code::PREAUTH_REQUIRED, None, Some(method_data));
            };
            let sealed =
                EncryptedData::read(&mut Reader::new(STRUCTURE, &timestamp.value)).unwrap();
            assert_eq!(sealed.etype, 18, "the type the PA-ETYPE-INFO2 named");
            let Ok(plain) = key.decrypt(1, &sealed.cipher) else {
                let mut ext = WRONG_PASSWORD.to_le_bytes().to_vec();
                ext.extend_from_slice(&[0; 8]);
                let data = sequence(&[explicit(1, &int(3)), explicit(2, &octets(&ext))]);
                return self.error(realm, code::PREAUTH_FAILED, None, Some(data));
            };
            let fields = Fields::of(&mut Reader::new(STRUCTURE, &plain), "PA-ENC-TS-ENC").unwrap();
            let time = KerberosTime::read(&mut fields.required(0, "").unwrap(), "").unwrap();
            if time.unix().abs_diff(self.clock) > 300 {
                return self.error(realm, code::SKEW, None, None);
            }
        }

        let checksum_over = self.enc_pa_rep.then(|| message.to_vec());
        self.reply(Reply {
            as_rep: true,
            realm,
            crealm: realm.to_owned(),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, &[name]),
            key,
            nonce,
            sname: krbtgt(realm),
            tgs_for: Some(realm.to_owned()),
            outer: if preauth { Vec::new() } else { info },
            checksum_over,
        })
    }

    fn tgs_exchange(
        &mut self,
        realm: &str,
        sname: PrincipalName,
        nonce: u32,
        padata: &[PaData],
        body: &[u8],
    ) -> Vec<u8> {
        let options = padata
            .iter()
            .find(|data| data.padata_type == padata::PAC_OPTIONS)
            .unwrap();
        assert_eq!(options.value, pac_options(BRANCH_AWARE), "MS-KILE §3.2.5.7");
        let ap_req = &padata
            .iter()
            .find(|data| data.padata_type == padata::TGS_REQ)
            .unwrap()
            .value;
        let mut reader = Reader::new(STRUCTURE, ap_req);
        let mut inner = reader
            .expect_nested(der::application(14), "AP-REQ")
            .unwrap();
        let fields = Fields::of(&mut inner, "AP-REQ").unwrap();
        let raw = fields
            .required(3, "")
            .unwrap()
            .read_element()
            .unwrap()
            .to_vec();
        let issued = self.issued.iter().find(|issued| issued.raw == raw).unwrap();
        assert_eq!(
            issued.tgs_for.as_deref(),
            Some(realm),
            "the TGT for the realm asked"
        );
        let sealed = EncryptedData::read(&mut fields.required(4, "").unwrap()).unwrap();
        let plain = issued.key.decrypt(7, &sealed.cipher).unwrap();
        let mut reader = Reader::new(STRUCTURE, &plain);
        let mut inner = reader
            .expect_nested(der::application(2), "Authenticator")
            .unwrap();
        let fields = Fields::of(&mut inner, "Authenticator").unwrap();
        assert_eq!(
            read_string(&mut fields.required(1, "").unwrap(), "").unwrap(),
            issued.crealm
        );
        assert_eq!(
            PrincipalName::read(&mut fields.required(2, "").unwrap()).unwrap(),
            issued.cname
        );
        let cksum = Checksum::read(&mut fields.required(3, "").unwrap()).unwrap();
        assert_eq!(cksum.cksumtype, issued.key.enctype().checksum_type());
        issued
            .key
            .verify_checksum(6, body, &cksum.checksum)
            .unwrap();
        let ctime = KerberosTime::read(&mut fields.required(5, "").unwrap(), "").unwrap();
        let (key, crealm, cname) = (
            issued.key.clone(),
            issued.crealm.clone(),
            issued.cname.clone(),
        );
        if ctime.unix().abs_diff(self.clock) > 300 {
            return self.error(realm, code::SKEW, None, None);
        }

        let spn = sname.components.join("/");
        let here = self
            .realms
            .iter()
            .find(|candidate| candidate.name == realm)
            .unwrap();
        let held = here
            .services
            .iter()
            .any(|service| service.eq_ignore_ascii_case(&spn));
        let (sname, tgs_for) = match (held, here.referral) {
            (true, _) => (sname, None),
            (false, Some(next)) => (krbtgt(next), Some(next.to_owned())),
            (false, None) => return self.error(realm, code::S_PRINCIPAL_UNKNOWN, None, None),
        };
        self.reply(Reply {
            as_rep: false,
            realm,
            crealm,
            cname,
            key,
            nonce,
            sname,
            tgs_for,
            outer: Vec::new(),
            checksum_over: None,
        })
    }

    fn params(&self) -> Option<&'static [u8]> {
        self.salts.then_some(&ITERATIONS[..])
    }

    /// The pre-authentication hints: `PA-ETYPE-INFO2` as Active Directory lists it — the
    /// strongest key the account has and the request asked for, RC4 ignored by the client.
    fn etype_info(&mut self, salt: &str) -> Vec<PaData> {
        if self.take(Fault::NoEtypeInfo) {
            return vec![PaData {
                padata_type: padata::ENC_TIMESTAMP,
                value: Vec::new(),
            }];
        }
        let mut aes = vec![explicit(0, &int(18))];
        if self.salts {
            aes.push(explicit(1, &string(salt)));
            aes.push(explicit(2, &octets(&ITERATIONS)));
        }
        let rc4 = sequence(&[explicit(0, &int(23))]);
        let entries = if self.take(Fault::Rc4Only) {
            rc4
        } else {
            [rc4, sequence(&aes)].concat()
        };
        vec![PaData {
            padata_type: padata::ETYPE_INFO2,
            value: der::tlv(der::SEQUENCE, &entries),
        }]
    }

    fn error(
        &self,
        realm: &str,
        error_code: i32,
        crealm: Option<&str>,
        e_data: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let mut fields = vec![
            explicit(0, &int(5)),
            explicit(1, &int(30)),
            explicit(4, &KerberosTime::from_unix(self.clock).encode()),
            explicit(5, &int(0)),
            explicit(6, &int(i64::from(error_code))),
        ];
        if let Some(crealm) = crealm {
            fields.push(explicit(7, &string(crealm)));
        }
        fields.push(explicit(9, &string(realm)));
        fields.push(explicit(10, &krbtgt(realm).encode()));
        if let Some(data) = e_data {
            fields.push(explicit(12, &octets(&data)));
        }
        der::tlv(der::application(30), &sequence(&fields))
    }
}

mod reply;

use reply::Reply;

fn krbtgt(realm: &str) -> PrincipalName {
    PrincipalName::new(2, &["krbtgt", realm])
}
