//! The AS exchange — [RFC 4120] §3.1 — for the client's ticket-granting ticket: the first leg
//! without pre-authentication, the second with the timestamp the KDC's salt makes possible, and
//! [RFC 6806] §7's client referrals between them.

use super::{
    Acquisition, AsSent, CANONICALIZE, Credential, ENC_PA_REP, Fresh, KdcRequest, MAXIMUM_ENDTIME,
    State, Step, credential, decrypt, krbtgt, refused, reply_error, same_name, same_text, sealed,
    usage,
};
use crate::der::Reader;
use crate::error::Result;
use crate::kerberos::asn1::{Checksum, PaData, STRUCTURE};
use crate::kerberos::crypto::{Enctype, Key};
use crate::kerberos::kdc::{
    self, EncKdcRepPart, EtypeInfo2, Exchange, KdcRep, KdcReply, KdcReqBody, code, padata,
};

impl Acquisition {
    pub(super) fn send_as(
        &mut self,
        realm: String,
        key: Option<Key>,
        skew_retried: bool,
        fresh: &Fresh,
    ) -> Result<KdcRequest> {
        let nonce = fresh.nonce();
        let body = KdcReqBody {
            options: CANONICALIZE,
            cname: Some(self.client.clone()),
            realm: realm.clone(),
            sname: Some(krbtgt(&realm)),
            till: MAXIMUM_ENDTIME,
            nonce,
            etypes: Enctype::PREFERENCE
                .iter()
                .map(|etype| etype.number())
                .collect(),
            enc_authorization_data: None,
        }
        .encode();

        let mut padata = Vec::new();
        if let Some(key) = &key {
            let (time, usec) = fresh.stamp(self.offset);
            let cipher = key.encrypt(
                usage::PA_ENC_TIMESTAMP,
                &fresh.confounder(),
                &kdc::pa_enc_ts_enc(time, usec),
            )?;
            padata.push(PaData {
                padata_type: padata::ENC_TIMESTAMP,
                value: sealed(key, cipher).encode(),
            });
        }
        // [MS-KILE] §3.2.5.5: "The client will always include a PAC request". [RFC 6806] §11: a
        // client "MUST send … PA-REQ-ENC-PA-REP (149) in all AS requests", empty.
        padata.push(PaData {
            padata_type: padata::PAC_REQUEST,
            value: kdc::pac_request(true),
        });
        padata.push(PaData {
            padata_type: padata::REQ_ENC_PA_REP,
            value: Vec::new(),
        });

        let message = kdc::request(Exchange::As, &padata, &body);
        self.state = State::As(AsSent {
            realm: realm.clone(),
            sent: message.clone(),
            nonce,
            key,
            skew_retried,
        });
        Ok(KdcRequest { realm, message })
    }

    pub(super) fn receive_as(&mut self, sent: AsSent, reply: &[u8], fresh: &Fresh) -> Result<Step> {
        match kdc::read_reply(Exchange::As, reply)? {
            KdcReply::Error(error) => match error.error_code {
                // [RFC 4120] §3.1.1: the first leg is sent without pre-authentication, because the
                // key cannot be made until the KDC has said which salt it uses.
                code::PREAUTH_REQUIRED if sent.key.is_none() => {
                    let methods = error
                        .e_data
                        .as_deref()
                        .map(|data| PaData::read_all(&mut Reader::new(STRUCTURE, data)))
                        .transpose()?
                        .unwrap_or_default();
                    let key = self.password_key(&sent.realm, &methods)?;
                    self.send_as(sent.realm, Some(key), sent.skew_retried, fresh)
                        .map(Step::Send)
                }
                code::WRONG_REALM => {
                    let next = error
                        .crealm
                        .filter(|crealm| !same_text(crealm, &sent.realm))
                        .ok_or_else(|| {
                            reply_error(&sent.realm, "a client referral to no other realm")
                        })?;
                    self.count_referral(&sent.realm)?;
                    self.send_as(next, None, false, fresh).map(Step::Send)
                }
                code::SKEW if !sent.skew_retried => {
                    self.offset = fresh.offset_to(error.stime);
                    self.send_as(sent.realm, sent.key, true, fresh)
                        .map(Step::Send)
                }
                _ => Err(refused(sent.realm, &error)),
            },
            KdcReply::Rep(rep) => {
                let tgt = self.as_rep(&sent, &rep)?;
                self.send_tgs(tgt.clone(), tgt, sent.realm, Vec::new(), false, fresh)
                    .map(Step::Send)
            }
        }
    }

    /// The password's key, made the way a `PA-ETYPE-INFO2` says: the first entry of a type this
    /// client implements, which is the KDC's choice from the request's preference order.
    fn password_key(&self, realm: &str, padata: &[PaData]) -> Result<Key> {
        let info = padata
            .iter()
            .find(|data| data.padata_type == padata::ETYPE_INFO2)
            .ok_or_else(|| {
                reply_error(realm, "no PA-ETYPE-INFO2 to make the password's key from")
            })?;
        let (enctype, entry) = EtypeInfo2::read_all(&info.value)?
            .into_iter()
            .find_map(|entry| Enctype::from_number(entry.etype).map(|enctype| (enctype, entry)))
            .ok_or_else(|| reply_error(realm, "the KDC holds no AES key for this account"))?;
        // [RFC 4120] §4: "The default salt string, if none is provided via pre-authentication
        // data, is the concatenation of the principal's realm and name components". Active
        // Directory always provides one.
        let salt = entry
            .salt
            .unwrap_or_else(|| [realm.to_owned(), self.client.components.concat()].concat());
        Key::from_password(
            enctype,
            &self.password,
            salt.as_bytes(),
            entry.s2kparams.as_deref(),
        )
    }

    /// Checks an AS-REP — [RFC 4120] §3.1.5, [RFC 6806] §11 — and returns the TGT it carries.
    fn as_rep(&self, sent: &AsSent, rep: &KdcRep) -> Result<Credential> {
        let realm = sent.realm.as_str();
        // An account that does not require pre-authentication is answered at once, and the AS-REP
        // carries the PA-ETYPE-INFO2 the error would have.
        let key = match &sent.key {
            Some(key) => key.clone(),
            None => self.password_key(realm, &rep.padata)?,
        };
        let part = decrypt(realm, &key, usage::AS_REP, rep, sent.nonce)?;
        if !same_text(&rep.crealm, realm)
            || !same_text(&part.srealm, realm)
            || !same_name(&part.sname, &krbtgt(realm))
        {
            return Err(reply_error(
                realm,
                "a ticket that is not this realm's krbtgt",
            ));
        }
        if part.flags & ENC_PA_REP != 0 {
            verify_request_checksum(realm, &key, &part, &sent.sent)?;
        }
        credential(realm, rep, &part)
    }
}

/// [RFC 6806] §11: "A client MUST reject a response for which it sent PA-REQ-ENC-PA-REP if the
/// ENC-PA-REP ticket flag is set and the PA-REQ-ENC-PA-REP padata item is absent or the checksum is
/// not successfully verified."
///
/// Measured on Windows Server 2025: the flag is set, and the checksum is present, of the reply
/// key's checksum type, over the whole AS-REQ as sent.
fn verify_request_checksum(
    realm: &str,
    key: &Key,
    part: &EncKdcRepPart,
    sent: &[u8],
) -> Result<()> {
    let item = part
        .encrypted_pa_data
        .iter()
        .find(|data| data.padata_type == padata::REQ_ENC_PA_REP)
        .ok_or_else(|| reply_error(realm, "the enc-pa-rep flag without the request's checksum"))?;
    let checksum = Checksum::read(&mut Reader::new(STRUCTURE, &item.value))?;
    if checksum.cksumtype != key.enctype().checksum_type() {
        return Err(reply_error(
            realm,
            "a request checksum of a type the reply key does not use",
        ));
    }
    key.verify_checksum(usage::AS_REQ, sent, &checksum.checksum)
        .map_err(|_| {
            reply_error(
                realm,
                "a request checksum that does not match the request sent",
            )
        })
}
