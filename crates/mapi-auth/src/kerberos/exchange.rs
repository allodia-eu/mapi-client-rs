//! Getting a service ticket: the AS exchange for a ticket-granting ticket ([RFC 4120] §3.1), then
//! the TGS exchange for the service ([RFC 4120] §3.3), following referrals both ways — a client
//! referral when the account lives in another realm ([RFC 6806] §7), and server referrals from
//! realm to realm until the service's own is reached ([RFC 6806] §8). [MS-KILE] §3.2.5 profiles
//! both.
//!
//! Sans-io like the rest of this crate. [`Acquisition`] says what to send to which realm's KDC and
//! is handed the reply; finding the KDC, the TCP framing and the timeouts are the caller's. Every
//! step takes a [`Fresh`] for the clock and the randomness a request needs, so a test can drive the
//! whole exchange to the byte.
//!
//! # What a reply has to pass
//!
//! An AS-REP is decrypted under the password's key and must repeat the request's nonce, be for
//! `krbtgt` of the realm asked, and — whenever its ticket carries the `enc-pa-rep` flag — carry
//! [RFC 6806] §11's checksum of the request exactly as sent, which is what makes the unprotected
//! first leg tamper-evident. A TGS-REP must repeat its nonce, come from the realm asked, and leave
//! the client's name alone ([RFC 6806] §6). Its ticket is either the service's or a referral to
//! another realm; anything else is refused.

use crate::error::{Error, Result};
use crate::kerberos::asn1::{EncryptedData, KerberosTime, PrincipalName, flag};
use crate::kerberos::crypto::{Enctype, Key};
pub(crate) use crate::kerberos::fresh::Fresh;
use crate::kerberos::kdc::{EncKdcRepPart, ErrorData, KdcRep, KrbError, Ticket};

/// Key usage numbers — [RFC 4120] §7.5.1, and [RFC 6806] §11 for the request checksum.
mod usage {
    /// `PA-ENC-TIMESTAMP`, under the password's key.
    pub(super) const PA_ENC_TIMESTAMP: u32 = 1;
    /// The `enc-part` of an AS-REP.
    pub(super) const AS_REP: u32 = 3;
    /// The checksum over a TGS-REQ's body, inside its authenticator.
    pub(super) const TGS_REQ_CHECKSUM: u32 = 6;
    /// A TGS-REQ's authenticator, under the presented ticket's session key.
    pub(super) const TGS_REQ_AUTHENTICATOR: u32 = 7;
    /// The `enc-part` of a TGS-REP, under that session key.
    pub(super) const TGS_REP: u32 = 8;
    /// `KEY_USAGE_AS_REQ`: [RFC 6806] §11's checksum of the AS-REQ.
    pub(super) const AS_REQ: u32 = 56;
}

/// How many referrals of either kind one acquisition follows — [RFC 6806] §7 and §8: "A suggested
/// limit is 5 referrals before giving up."
const MAX_REFERRALS: u8 = 5;

/// The `canonicalize` KDC option, bit 15 — which [MS-KILE] §3.2.5.1 has a client set, and without
/// which [RFC 6806] §3 sends no referrals.
const CANONICALIZE: u32 = flag(15);

/// The `enc-pa-rep` ticket flag, bit 15 — [RFC 6806] §11.
const ENC_PA_REP: u32 = flag(15);

/// `till` for "as long as the KDC allows" — [RFC 4120] §5.4.1: "if the requested endtime is
/// '19700101000000Z', the requested ticket is to have the maximum endtime permitted according to
/// KDC policy". Measured: a Windows Server 2025 KDC honours it, with its default ten hours.
const MAXIMUM_ENDTIME: KerberosTime = KerberosTime::from_unix(0);

/// A ticket and what goes with it: everything needed to present it again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Credential {
    /// The client's realm, as the KDC canonicalized it.
    pub(crate) crealm: String,
    /// The client's name, as the KDC canonicalized it — what every later authenticator carries.
    pub(crate) cname: PrincipalName,
    /// The ticket.
    pub(crate) ticket: Ticket,
    /// Its session key.
    pub(crate) key: Key,
    /// Its flags.
    pub(crate) flags: u32,
    /// When it stops working, by the KDC's clock.
    pub(crate) endtime: KerberosTime,
}

/// One message for a KDC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KdcRequest {
    /// The realm whose KDC it is for.
    pub(crate) realm: String,
    /// The message, without [RFC 4120] §7.2.2's four-byte TCP length prefix.
    pub(crate) message: Vec<u8>,
}

/// What an acquisition ends with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Tickets {
    /// The client's ticket-granting ticket, for asking for the next service without a password.
    pub(crate) tgt: Credential,
    /// The service ticket that was asked for.
    pub(crate) service: Credential,
    /// Seconds to add to the local clock to match the KDC's, learned from a skew error; 0 if none.
    pub(crate) clock_offset: i64,
}

/// What to do next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Send this to a KDC, and hand the reply to [`Acquisition::receive`].
    Send(KdcRequest),
    /// Finished.
    Done(Box<Tickets>),
}

/// Getting a service ticket, from a password or from a ticket-granting ticket already held.
pub(crate) struct Acquisition {
    /// The client's name as requested: an `NT-ENTERPRISE` UPN or an `NT-PRINCIPAL` account name.
    client: PrincipalName,
    /// The password, for the AS exchange; empty when starting from a ticket-granting ticket.
    password: String,
    /// The service the ticket is for.
    service: PrincipalName,
    /// Seconds by which the KDC's clock leads ours.
    offset: i64,
    /// Referrals followed so far, of either kind.
    referrals: u8,
    state: State,
}

enum State {
    As(AsSent),
    Tgs(Box<TgsSent>),
    Finished,
}

/// An AS-REQ is out.
struct AsSent {
    realm: String,
    /// The request as sent, which [RFC 6806] §11's checksum covers.
    sent: Vec<u8>,
    nonce: u32,
    /// The password's key, once a `PA-ETYPE-INFO2` has said how to make it.
    key: Option<Key>,
    skew_retried: bool,
}

/// A TGS-REQ is out.
struct TgsSent {
    /// The client's own ticket-granting ticket.
    tgt: Credential,
    /// The ticket-granting ticket presented: `tgt`, or a referral from it.
    presented: Credential,
    realm: String,
    nonce: u32,
    skew_retried: bool,
    /// The realms asked before this one, so a referral back to one is refused.
    visited: Vec<String>,
}

impl Acquisition {
    /// Starts with an AS exchange in `realm` for `client`, who knows `password`.
    pub(crate) fn with_password(
        client: PrincipalName,
        realm: &str,
        password: String,
        service: PrincipalName,
        fresh: &Fresh,
    ) -> Result<(Self, KdcRequest)> {
        let mut acquisition = Self::new(client, password, service, 0);
        let request = acquisition.send_as(realm.to_owned(), None, false, fresh)?;
        Ok((acquisition, request))
    }

    /// Starts with a TGS exchange, presenting a ticket-granting ticket already held.
    pub(crate) fn with_tgt(
        tgt: Credential,
        service: PrincipalName,
        clock_offset: i64,
        fresh: &Fresh,
    ) -> Result<(Self, KdcRequest)> {
        let mut acquisition = Self::new(tgt.cname.clone(), String::new(), service, clock_offset);
        let realm = tgt.ticket.realm.clone();
        let request = acquisition.send_tgs(tgt.clone(), tgt, realm, Vec::new(), false, fresh)?;
        Ok((acquisition, request))
    }

    const fn new(
        client: PrincipalName,
        password: String,
        service: PrincipalName,
        offset: i64,
    ) -> Self {
        Self {
            client,
            password,
            service,
            offset,
            referrals: 0,
            state: State::Finished,
        }
    }

    /// Takes a KDC's reply to the last request and says what to do next.
    ///
    /// # Errors
    ///
    /// [`Error::KdcRefused`] when the KDC refused, [`Error::KdcReply`] when its reply fails a
    /// check, [`Error::Crypto`] when it does not decrypt — which for an AS-REP is a wrong
    /// password the KDC did not catch — and [`Error::Malformed`] when it does not parse. Any of
    /// them ends the acquisition, and a later call is [`Error::OutOfOrder`].
    pub(crate) fn receive(&mut self, reply: &[u8], fresh: &Fresh) -> Result<Step> {
        match core::mem::replace(&mut self.state, State::Finished) {
            State::As(sent) => self.receive_as(sent, reply, fresh),
            State::Tgs(sent) => self.receive_tgs(*sent, reply, fresh),
            State::Finished => Err(Error::OutOfOrder {
                state: "finished",
                attempted: "read another KDC reply",
            }),
        }
    }

    fn count_referral(&mut self, realm: &str) -> Result<()> {
        self.referrals = self.referrals.saturating_add(1);
        if self.referrals > MAX_REFERRALS {
            return Err(reply_error(
                realm,
                "more referrals than RFC 6806's limit of five",
            ));
        }
        Ok(())
    }
}

/// Decrypts a reply's encrypted part and checks the two things every reply must get right: the
/// request's nonce, and the same service and realm inside as on the ticket outside.
fn decrypt(realm: &str, key: &Key, usage: u32, rep: &KdcRep, nonce: u32) -> Result<EncKdcRepPart> {
    if rep.enc_part.etype != key.enctype().number() {
        return Err(reply_error(
            realm,
            "a reply encrypted under a key of another type",
        ));
    }
    let part = EncKdcRepPart::read(&key.decrypt(usage, &rep.enc_part.cipher)?)?;
    if part.nonce != nonce {
        return Err(reply_error(realm, "a nonce that is not the request's"));
    }
    if !same_name(&part.sname, &rep.ticket.sname) || !same_text(&part.srealm, &rep.ticket.realm) {
        return Err(reply_error(
            realm,
            "an encrypted part that names another ticket",
        ));
    }
    Ok(part)
}

fn credential(realm: &str, rep: &KdcRep, part: &EncKdcRepPart) -> Result<Credential> {
    let enctype = Enctype::from_number(part.key.keytype)
        .ok_or_else(|| reply_error(realm, "a session key of a type the request did not offer"))?;
    Ok(Credential {
        crealm: rep.crealm.clone(),
        cname: rep.cname.clone(),
        ticket: rep.ticket.clone(),
        key: Key::new(enctype, part.key.value.clone())?,
        flags: part.flags,
        endtime: part.endtime,
    })
}

/// `krbtgt/REALM` — [RFC 4120] §7.3.
fn krbtgt(realm: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_INST, &["krbtgt", realm])
}

/// The realm a referral ticket leads to: the second component of `krbtgt/NEXT`.
fn referral_realm(sname: &PrincipalName) -> Option<&str> {
    match sname.components.as_slice() {
        [_, next] if sname.is_krbtgt() => Some(next),
        _ => None,
    }
}

/// [MS-KILE] §3.1.5.7: "Name comparisons, whether for users or domains, MUST NOT be case
/// sensitive", and "Normalization MUST NOT be performed" — so a case fold and nothing more.
fn same_text(a: &str, b: &str) -> bool {
    a.chars()
        .flat_map(char::to_lowercase)
        .eq(b.chars().flat_map(char::to_lowercase))
}

/// Two principal names with the same components. The name type is not compared: a KDC that
/// canonicalizes may change it ([RFC 6806] §5).
fn same_name(a: &PrincipalName, b: &PrincipalName) -> bool {
    a.components.len() == b.components.len()
        && a.components
            .iter()
            .zip(&b.components)
            .all(|(a, b)| same_text(a, b))
}

fn sealed(key: &Key, cipher: Vec<u8>) -> EncryptedData {
    EncryptedData {
        etype: key.enctype().number(),
        kvno: None,
        cipher,
    }
}

fn refused(realm: String, error: &KrbError) -> Error {
    Error::KdcRefused {
        realm,
        code: error.error_code,
        status: error
            .e_data
            .as_deref()
            .and_then(ErrorData::read)
            .and_then(|data| data.ntstatus()),
    }
}

fn reply_error(realm: &str, reason: &'static str) -> Error {
    Error::KdcReply {
        realm: realm.to_owned(),
        reason,
    }
}

mod authentication;
mod ticket_granting;

#[cfg(test)]
pub(crate) mod double;
#[cfg(test)]
mod tests;
