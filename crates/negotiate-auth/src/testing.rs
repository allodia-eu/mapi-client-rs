//! A Kerberos KDC and service for tests: what a crate driving this one needs when it has no lab.
//!
//! **Not for production, and not secure.** Behind the `testing` feature, which nothing but a
//! dev-dependency should enable. [`TestKdc`] issues real tickets for one realm, one user and one
//! service — real enough that this crate's own [`TicketRequest`](crate::TicketRequest) and
//! [`Handshake`](crate::Handshake) accept them — with session keys that are a counter rather than
//! random, and it accepts any AP-REQ for a ticket it issued without checking the channel binding.
//!
//! What it is for: driving a client's Kerberos path end to end in CI — the KDC over a socket, the
//! service behind a fake HTTP server — where no domain controller will ever be. The specifications
//! are checked elsewhere: this crate's own tests pin the messages to [RFC 4120] and the crypto to
//! the published vectors, and the live suite pins all of it to a Windows KDC.

use core::time::Duration;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::der::{self, Reader};
use crate::kerberos::asn1::{
    EncryptedData, EncryptionKey, Fields, KerberosTime, PaData, PrincipalName, STRUCTURE, explicit,
    flags, int, octets, read_int32, read_uint32, sequence, string,
};
use crate::kerberos::crypto::{Enctype, Key};
use crate::kerberos::gss;
use crate::kerberos::kdc::{code, padata};
use crate::spnego;

/// The string-to-key iteration count this KDC names: one, so that a test spends no time on it.
const ITERATIONS: [u8; 4] = [0, 0, 0, 1];

/// How long a ticket lasts.
const LIFETIME: u64 = 36_000;

/// A one-realm KDC and the one service it issues tickets for.
#[derive(Debug)]
pub struct TestKdc {
    realm: String,
    user: String,
    service: String,
    user_key: Key,
    now: u64,
    issued: Mutex<Vec<Issued>>,
}

#[derive(Debug)]
struct Issued {
    raw: Vec<u8>,
    key: Key,
    /// Whether this is a ticket-granting ticket rather than the service's.
    tgt: bool,
}

impl TestKdc {
    /// A KDC for `realm`, knowing `user` (by account name or UPN) with `password`, and `service`
    /// (`HTTP/host`), whose clock reads `since_epoch`.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`](crate::Error::Crypto) if the password's key cannot be made, which for the
    /// parameters this KDC uses does not happen.
    pub fn new(
        realm: &str,
        user: &str,
        password: &str,
        service: &str,
        since_epoch: Duration,
    ) -> crate::Result<Self> {
        let account = user.split_once('@').map_or(user, |(account, _)| account);
        let salt = format!("{realm}{account}");
        let user_key = Key::from_password(
            Enctype::Aes256Sha1,
            password,
            salt.as_bytes(),
            Some(&ITERATIONS),
        )?;
        Ok(Self {
            realm: realm.to_owned(),
            user: account.to_owned(),
            service: service.to_owned(),
            user_key,
            now: since_epoch.as_secs(),
            issued: Mutex::new(Vec::new()),
        })
    }

    /// Answers one KDC request — an AS-REQ or a TGS-REQ, without the TCP length prefix — with the
    /// reply, or with a `KRB-ERROR` for anything it will not grant.
    #[must_use]
    pub fn answer(&self, request: &[u8]) -> Vec<u8> {
        self.try_answer(request)
            .unwrap_or_else(|| self.error(60, None))
    }

    fn try_answer(&self, request: &[u8]) -> Option<Vec<u8>> {
        let mut reader = Reader::new(STRUCTURE, request);
        let tag = reader.peek_tag()?;
        let mut inner = reader.expect_nested(tag, "a request").ok()?;
        let fields = Fields::of(&mut inner, "a request").ok()?;
        let padata = fields
            .optional(3)
            .and_then(|mut field| PaData::read_all(&mut field).ok())
            .unwrap_or_default();
        let body = fields
            .required(4, "a body")
            .ok()?
            .read_element()
            .ok()?
            .to_vec();
        let body_fields = Fields::of(&mut Reader::new(STRUCTURE, &body), "a body").ok()?;
        let nonce = read_uint32(&mut body_fields.required(7, "").ok()?, "").ok()?;
        let sname = PrincipalName::read(&mut body_fields.required(3, "").ok()?).ok()?;
        if tag == der::application(10) {
            Some(self.authentication(&padata, nonce))
        } else if tag == der::application(12) {
            self.ticket_granting(&padata, &sname, nonce)
        } else {
            None
        }
    }

    /// The AS exchange: `PREAUTH_REQUIRED` with the salt first, then a TGT for a good timestamp.
    fn authentication(&self, padata: &[PaData], nonce: u32) -> Vec<u8> {
        let Some(timestamp) = padata
            .iter()
            .find(|data| data.padata_type == padata::ENC_TIMESTAMP)
        else {
            let entry = sequence(&[
                explicit(0, &int(18)),
                explicit(1, &string(&format!("{}{}", self.realm, self.user))),
                explicit(2, &octets(&ITERATIONS)),
            ]);
            let info = PaData {
                padata_type: padata::ETYPE_INFO2,
                value: der::tlv(der::SEQUENCE, &entry),
            };
            return self.error(
                code::PREAUTH_REQUIRED,
                Some(der::tlv(der::SEQUENCE, &info.encode())),
            );
        };
        let proven = EncryptedData::read(&mut Reader::new(STRUCTURE, &timestamp.value))
            .ok()
            .and_then(|sealed| self.user_key.decrypt(1, &sealed.cipher).ok());
        if proven.is_none() {
            return self.error(code::PREAUTH_FAILED, None);
        }
        let krbtgt = PrincipalName::new(PrincipalName::NT_SRV_INST, &["krbtgt", &self.realm]);
        self.reply(true, &self.user_key, nonce, &krbtgt)
            .unwrap_or_else(|| self.error(60, None))
    }

    /// The TGS exchange: a ticket for the one service, to the holder of a TGT this KDC issued.
    fn ticket_granting(
        &self,
        padata: &[PaData],
        sname: &PrincipalName,
        nonce: u32,
    ) -> Option<Vec<u8>> {
        let ap_req = &padata
            .iter()
            .find(|data| data.padata_type == padata::TGS_REQ)?
            .value;
        let (raw, _) = open_ap_req(ap_req)?;
        let key = self.key_of(&raw, true)?;
        if sname.components.join("/") != self.service {
            return Some(self.error(code::S_PRINCIPAL_UNKNOWN, None));
        }
        self.reply(false, &key, nonce, sname)
    }

    /// Accepts a `Negotiate` header carrying an AP-REQ for a service ticket this KDC issued, and
    /// returns the `WWW-Authenticate` value of the success that answers it: `accept-completed`,
    /// with the AP-REP. `None` for anything else.
    #[must_use]
    pub fn accept(&self, authorization: &str) -> Option<String> {
        let token = BASE64
            .decode(authorization.strip_prefix("Negotiate ")?)
            .ok()?;
        let mech_token = spnego::parse(&token).ok()?.response_token?;
        let (id, message) = gss::unframe(&mech_token).ok()?;
        if id != [0x01, 0x00] {
            return None;
        }
        let (raw, sealed) = open_ap_req(message)?;
        let key = self.key_of(&raw, false)?;
        let plain = key.decrypt(11, &sealed.cipher).ok()?;
        let mut reader = Reader::new(STRUCTURE, &plain);
        let mut inner = reader
            .expect_nested(der::application(2), "an Authenticator")
            .ok()?;
        let fields = Fields::of(&mut inner, "an Authenticator").ok()?;
        let cusec = read_uint32(&mut fields.required(4, "").ok()?, "").ok()?;
        let ctime = KerberosTime::read(&mut fields.required(5, "").ok()?, "").ok()?;

        let part = der::tlv(
            der::application(27),
            &sequence(&[
                explicit(0, &ctime.encode()),
                explicit(1, &int(i64::from(cusec))),
            ]),
        );
        let cipher = key.encrypt(12, &[0x33; 16], &part).ok()?;
        let ap_rep = der::tlv(
            der::application(15),
            &sequence(&[
                explicit(0, &int(5)),
                explicit(1, &int(15)),
                explicit(
                    2,
                    &EncryptedData {
                        etype: 18,
                        kvno: None,
                        cipher,
                    }
                    .encode(),
                ),
            ]),
        );
        let response = sequence(&[
            explicit(0, &der::tlv(der::ENUMERATED, &[0])),
            explicit(1, &der::tlv(der::OID, gss::OID)),
            explicit(2, &octets(&gss::frame([0x02, 0x00], &ap_rep))),
        ]);
        Some(format!(
            "Negotiate {}",
            BASE64.encode(der::tlv(der::context(1), &response))
        ))
    }

    /// Issues a ticket for `sname` and the reply that carries it, encrypted under `reply_key`.
    fn reply(
        &self,
        as_rep: bool,
        reply_key: &Key,
        nonce: u32,
        sname: &PrincipalName,
    ) -> Option<Vec<u8>> {
        let mut issued = self.issued.lock().ok()?;
        let serial = u8::try_from(issued.len().checked_add(1)?).ok()?;
        let session = Key::new(Enctype::Aes256Sha1, vec![serial; 32]).ok()?;
        let ticket_part = EncryptedData {
            etype: 18,
            kvno: Some(1),
            cipher: vec![serial; 16],
        };
        let raw = der::tlv(
            der::application(1),
            &sequence(&[
                explicit(0, &int(5)),
                explicit(1, &string(&self.realm)),
                explicit(2, &sname.encode()),
                explicit(3, &ticket_part.encode()),
            ]),
        );
        issued.push(Issued {
            raw: raw.clone(),
            key: session.clone(),
            tgt: as_rep,
        });
        drop(issued);

        let part = der::tlv(
            der::application(if as_rep { 25 } else { 26 }),
            &sequence(&[
                explicit(
                    0,
                    &EncryptionKey {
                        keytype: 18,
                        value: session.bytes().to_vec(),
                    }
                    .encode(),
                ),
                explicit(1, &der::tlv(der::SEQUENCE, &[])),
                explicit(2, &int(i64::from(nonce))),
                explicit(4, &flags(0x4000_0000)),
                explicit(5, &KerberosTime::from_unix(self.now).encode()),
                explicit(
                    7,
                    &KerberosTime::from_unix(self.now.checked_add(LIFETIME)?).encode(),
                ),
                explicit(9, &string(&self.realm)),
                explicit(10, &sname.encode()),
            ]),
        );
        let cipher = reply_key
            .encrypt(if as_rep { 3 } else { 8 }, &[0x22; 16], &part)
            .ok()?;
        let msg_type: u8 = if as_rep { 11 } else { 13 };
        let client = PrincipalName::new(PrincipalName::NT_PRINCIPAL, &[&self.user]);
        Some(der::tlv(
            der::application(msg_type),
            &sequence(&[
                explicit(0, &int(5)),
                explicit(1, &int(i64::from(msg_type))),
                explicit(3, &string(&self.realm)),
                explicit(4, &client.encode()),
                explicit(5, &raw),
                explicit(
                    6,
                    &EncryptedData {
                        etype: 18,
                        kvno: None,
                        cipher,
                    }
                    .encode(),
                ),
            ]),
        ))
    }

    /// The session key of a ticket this KDC issued, of the kind asked for.
    fn key_of(&self, raw: &[u8], tgt: bool) -> Option<Key> {
        let issued = self.issued.lock().ok()?;
        issued
            .iter()
            .find(|issued| issued.raw == raw && issued.tgt == tgt)
            .map(|issued| issued.key.clone())
    }

    /// A `KRB-ERROR` — [RFC 4120] §5.9.1 — from this KDC.
    fn error(&self, error_code: i32, e_data: Option<Vec<u8>>) -> Vec<u8> {
        let krbtgt = PrincipalName::new(PrincipalName::NT_SRV_INST, &["krbtgt", &self.realm]);
        let mut fields = vec![
            explicit(0, &int(5)),
            explicit(1, &int(30)),
            explicit(4, &KerberosTime::from_unix(self.now).encode()),
            explicit(5, &int(0)),
            explicit(6, &int(i64::from(error_code))),
            explicit(9, &string(&self.realm)),
            explicit(10, &krbtgt.encode()),
        ];
        if let Some(data) = e_data {
            fields.push(explicit(12, &octets(&data)));
        }
        der::tlv(der::application(30), &sequence(&fields))
    }
}

/// The ticket, whole, and the sealed authenticator of an AP-REQ.
fn open_ap_req(ap_req: &[u8]) -> Option<(Vec<u8>, EncryptedData)> {
    let mut reader = Reader::new(STRUCTURE, ap_req);
    let mut inner = reader
        .expect_nested(der::application(14), "an AP-REQ")
        .ok()?;
    let fields = Fields::of(&mut inner, "an AP-REQ").ok()?;
    let msg_type = read_int32(&mut fields.required(1, "").ok()?, "").ok()?;
    if msg_type != 14 {
        return None;
    }
    let raw = fields.required(3, "").ok()?.read_element().ok()?.to_vec();
    let sealed = EncryptedData::read(&mut fields.required(4, "").ok()?).ok()?;
    Some((raw, sealed))
}

#[cfg(test)]
mod tests;
