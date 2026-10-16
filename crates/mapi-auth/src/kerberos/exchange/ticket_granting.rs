//! The TGS exchange — [RFC 4120] §3.3 — for the service's ticket, following [RFC 6806] §8's
//! referrals from realm to realm until the service's own KDC answers.

use super::{
    Acquisition, CANONICALIZE, Credential, Fresh, KdcRequest, MAXIMUM_ENDTIME, State, Step,
    TgsSent, Tickets, credential, decrypt, referral_realm, refused, reply_error, same_name,
    same_text, sealed, usage,
};
use crate::error::Result;
use crate::kerberos::ap::{self, Authenticator};
use crate::kerberos::asn1::{Checksum, PaData};
use crate::kerberos::crypto::Enctype;
use crate::kerberos::kdc::{
    self, BRANCH_AWARE, Exchange, KdcRep, KdcReply, KdcReqBody, code, padata,
};

impl Acquisition {
    pub(super) fn send_tgs(
        &mut self,
        tgt: Credential,
        presented: Credential,
        realm: String,
        visited: Vec<String>,
        skew_retried: bool,
        fresh: &Fresh,
    ) -> Result<KdcRequest> {
        let nonce = fresh.nonce();
        let body = KdcReqBody {
            options: CANONICALIZE,
            cname: None,
            realm: realm.clone(),
            sname: Some(self.service.clone()),
            till: MAXIMUM_ENDTIME,
            nonce,
            etypes: Enctype::PREFERENCE
                .iter()
                .map(|etype| etype.number())
                .collect(),
            enc_authorization_data: None,
        }
        .encode();

        // [RFC 4120] §5.4.1: the PA-TGS-REQ is an AP-REQ whose authenticator checksums the body.
        let key = &presented.key;
        let (ctime, cusec) = fresh.stamp(self.offset);
        let authenticator = Authenticator {
            crealm: presented.crealm.clone(),
            cname: presented.cname.clone(),
            cksum: Some(Checksum {
                cksumtype: key.enctype().checksum_type(),
                checksum: key.checksum(usage::TGS_REQ_CHECKSUM, &body)?,
            }),
            cusec,
            ctime,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };
        let cipher = key.encrypt(
            usage::TGS_REQ_AUTHENTICATOR,
            &fresh.confounder(),
            &authenticator.encode(),
        )?;
        let padata = [
            PaData {
                padata_type: padata::TGS_REQ,
                value: ap::request(0, &presented.ticket.raw, &sealed(key, cipher)),
            },
            PaData {
                padata_type: padata::PAC_OPTIONS,
                value: kdc::pac_options(BRANCH_AWARE),
            },
        ];

        let message = kdc::request(Exchange::Tgs, &padata, &body);
        self.state = State::Tgs(Box::new(TgsSent {
            tgt,
            presented,
            realm: realm.clone(),
            nonce,
            skew_retried,
            visited,
        }));
        Ok(KdcRequest { realm, message })
    }

    pub(super) fn receive_tgs(
        &mut self,
        sent: TgsSent,
        reply: &[u8],
        fresh: &Fresh,
    ) -> Result<Step> {
        let rep = match kdc::read_reply(Exchange::Tgs, reply)? {
            KdcReply::Error(error) if error.error_code == code::SKEW && !sent.skew_retried => {
                self.offset = fresh.offset_to(error.stime);
                return self
                    .send_tgs(
                        sent.tgt,
                        sent.presented,
                        sent.realm,
                        sent.visited,
                        true,
                        fresh,
                    )
                    .map(Step::Send);
            }
            KdcReply::Error(error) => return Err(refused(sent.realm, &error)),
            KdcReply::Rep(rep) => rep,
        };

        let issued = tgs_rep(&sent, &rep)?;
        if same_name(&issued.ticket.sname, &self.service) {
            return Ok(Step::Done(Box::new(Tickets {
                tgt: sent.tgt,
                service: issued,
                clock_offset: self.offset,
            })));
        }

        // Not the service: a referral to the next realm on the path ([RFC 6806] §8), or nothing.
        let next = referral_realm(&issued.ticket.sname)
            .filter(|next| !same_text(next, &sent.realm))
            .ok_or_else(|| {
                reply_error(
                    &sent.realm,
                    "a ticket for a service other than the one asked",
                )
            })?
            .to_owned();
        if sent.visited.iter().any(|realm| same_text(realm, &next)) {
            return Err(reply_error(
                &sent.realm,
                "a referral back to a realm already asked",
            ));
        }
        self.count_referral(&sent.realm)?;
        let mut visited = sent.visited;
        visited.push(sent.realm);
        self.send_tgs(sent.tgt, issued, next, visited, false, fresh)
            .map(Step::Send)
    }
}

/// Checks a TGS-REP — [RFC 4120] §3.3.4, [RFC 6806] §6 — and returns the ticket it carries.
fn tgs_rep(sent: &TgsSent, rep: &KdcRep) -> Result<Credential> {
    let realm = sent.realm.as_str();
    let part = decrypt(realm, &sent.presented.key, usage::TGS_REP, rep, sent.nonce)?;
    if !same_text(&part.srealm, realm) {
        return Err(reply_error(
            realm,
            "a ticket from a realm other than the one asked",
        ));
    }
    // [RFC 6806] §6: "Names MUST NOT be changed in the response to a TGS request".
    if !same_text(&rep.crealm, &sent.presented.crealm)
        || !same_name(&rep.cname, &sent.presented.cname)
    {
        return Err(reply_error(realm, "a reply naming a different client"));
    }
    credential(realm, rep, &part)
}
