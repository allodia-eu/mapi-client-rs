//! Kerberos as a GSS-API mechanism — [RFC 4121] — which is what `Negotiate` carries to an HTTP
//! server: the AP-REQ that authenticates the client, the AP-REP that proves the server holds the
//! service key, and the MIC tokens that sign SPNEGO's mechanism list.
//!
//! # What Extended Protection looks at
//!
//! The channel binding travels in the authenticator checksum's `Bnd` field ([RFC 4121] §4.1.1.2),
//! and [MS-KILE] §3.2.5.8 has a client that binds also say so, with `KERB_AP_OPTIONS_CBT` in the
//! authorization data. Both are sent. Measured against Exchange Server SE `15.02.2562.045` on
//! Windows Server 2025, whose MAPI virtual directory has Extended Protection `Require`, it is `Bnd`
//! that decides: an AP-REQ with the all-zero `Bnd` is refused with a bare `401`, and one with the
//! right `Bnd` is accepted with or without `KERB_AP_OPTIONS_CBT` beside it.
//!
//! **Rule: [RFC 6542]'s hash-agility extension is not sent.** [RFC 4121] §4.1.1 provides for an
//! initiator without it — "Initiators that do not support the extensions MUST NOT include more
//! than 24 octets in the checksum field" — and this is one: [MS-KILE] does not mention the
//! extension, and the MD5 `Bnd` is what Exchange was measured checking.
//!
//! # Measured on the same server
//!
//! Its `Negotiate` answer to a good AP-REQ is `accept-completed`, `supportedMech` the standard OID
//! this client sent, an AP-REP that passes [`Initiator::read`]'s checks, and no `mechListMIC`. With
//! the client's clock an hour slow it answers `accept-incomplete` with a `KRB_AP_ERR_SKEW` carrying
//! `KERB-ERROR-DATA` — though this client does not set the extended-error context flag [MS-KILE]
//! §3.2.5.2 maps `ExtendedError` to — and the retry that error makes possible is accepted. A
//! sequence number with the top bit set is accepted too, so unlike a KDC's nonce it is not kept to
//! 31 bits.

use crate::binding::ChannelBinding;
use crate::der::{self, Reader};
use crate::error::{Error, Result};
use crate::kerberos::ap::{self, Authenticator, EncApRepPart};
use crate::kerberos::asn1::{
    Checksum, EncryptedData, EncryptionKey, KerberosTime, STRUCTURE, authorization_data,
};
use crate::kerberos::crypto::{Enctype, Key};
use crate::kerberos::exchange::Credential;
use crate::kerberos::fresh::Fresh;
use crate::kerberos::kdc::{self, ErrorData, KrbError, code};

/// The Kerberos V5 mechanism, `1.2.840.113554.1.2.2` — [RFC 4121] §1, and the OID [MS-SPNG]
/// §3.1.5.2 says an implementation SHOULD use.
pub(crate) const OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];

/// The same mechanism under the OID Windows 2000 truncated it to, `1.2.840.48018.1.2.2`, which
/// [MS-SPNG] note `<10>` says Windows still offers and accepts. Accepted here on what a server
/// sends; never sent.
pub(crate) const LEGACY_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02];

/// `TOK_ID` values — [RFC 4121] §4.1 and §4.2.6.1.
mod tok_id {
    pub(super) const AP_REQ: [u8; 2] = [0x01, 0x00];
    pub(super) const AP_REP: [u8; 2] = [0x02, 0x00];
    pub(super) const ERROR: [u8; 2] = [0x03, 0x00];
    pub(super) const MIC: [u8; 2] = [0x04, 0x04];
}

/// Key usage numbers — [RFC 4120] §7.5.1 and [RFC 4121] §2.
mod usage {
    /// The AP-REQ's authenticator.
    pub(super) const AP_REQ_AUTHENTICATOR: u32 = 11;
    /// The AP-REP's encrypted part.
    pub(super) const AP_REP: u32 = 12;
    /// `KG-USAGE-ACCEPTOR-SIGN`.
    pub(super) const ACCEPTOR_SIGN: u32 = 23;
    /// `KG-USAGE-INITIATOR-SIGN`.
    pub(super) const INITIATOR_SIGN: u32 = 25;
}

/// The authenticator checksum type that carries GSS flags and the channel binding — [RFC 4121]
/// §4.1.1: "The checksum type MUST be 0x8003."
const GSS_CHECKSUM: i32 = 0x8003;

/// Context flags — [RFC 4121] §4.1.1.1. Mutual authentication, so that the server answers with an
/// AP-REP that proves it; and integrity, without which SPNEGO's `mechListMIC` cannot be signed.
const CONTEXT_FLAGS: u32 = 2 | 32;

/// `AD-IF-RELEVANT` — [RFC 4120] §5.2.6.1.
const AD_IF_RELEVANT: i32 = 1;

/// `AD-AUTH-DATA-AP-OPTIONS` — [MS-KILE] §3.2.5.8.
const AD_AUTH_DATA_AP_OPTIONS: i32 = 143;

/// `KERB_AP_OPTIONS_CBT` — [MS-KILE] §3.2.5.8: "encoded as a four byte little-endian unsigned
/// integer".
const KERB_AP_OPTIONS_CBT: u32 = 0x4000;

/// MIC token flags — [RFC 4121] §4.2.2.
mod mic_flag {
    pub(super) const SENT_BY_ACCEPTOR: u8 = 0x01;
    pub(super) const ACCEPTOR_SUBKEY: u8 = 0x04;
}

/// The length of a MIC token's header — [RFC 4121] §4.2.6.1, octets 0 to 15.
const MIC_HEADER: usize = 16;

/// What the server's token said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    /// An AP-REP that checks out: the server holds the service key.
    Accepted,
    /// A `KRB_AP_ERR_SKEW` the client may recover from: send this AP-REQ instead, with the time
    /// moved to the server's.
    Retry(Vec<u8>),
}

/// The client side of one Kerberos security context.
#[derive(Clone, Debug)]
pub(crate) struct Initiator {
    ticket: Credential,
    binding: ChannelBinding,
    /// Seconds by which the other side's clock leads ours.
    offset: i64,
    /// The authenticator's subkey: the base key for MIC tokens unless the server asserts its own.
    subkey: Key,
    /// The next sequence number this side will send ([RFC 4121] §4.2.1).
    sequence: u64,
    /// The authenticator's `ctime` and `cusec`, which the AP-REP must repeat.
    sent: (KerberosTime, u32),
    /// The server's subkey, once an AP-REP has asserted one.
    acceptor_subkey: Option<Key>,
    skew_retried: bool,
}

impl Initiator {
    /// The first token: an AP-REQ presenting `ticket`, bound to `binding`.
    ///
    /// `clock_offset` is what the KDC exchanges learned, if they learned anything.
    pub(crate) fn start(
        ticket: Credential,
        binding: ChannelBinding,
        clock_offset: i64,
        fresh: &Fresh,
    ) -> Result<(Self, Vec<u8>)> {
        let subkey = subkey(&ticket, fresh)?;
        let mut initiator = Self {
            ticket,
            binding,
            offset: clock_offset,
            subkey,
            sequence: 0,
            sent: (KerberosTime::from_unix(0), 0),
            acceptor_subkey: None,
            skew_retried: false,
        };
        let token = initiator.token(fresh)?;
        Ok((initiator, token))
    }

    /// Builds an AP-REQ token — [RFC 4121] §4.1 — with a fresh subkey, sequence number and time.
    fn token(&mut self, fresh: &Fresh) -> Result<Vec<u8>> {
        self.subkey = subkey(&self.ticket, fresh)?;
        let sequence = fresh.sequence();
        self.sequence = u64::from(sequence);
        self.sent = fresh.stamp(self.offset);

        // [RFC 4121] §4.1.1: Lgth, Bnd and Flags, all little-endian.
        let mut checksum = Vec::with_capacity(24);
        checksum.extend_from_slice(&16u32.to_le_bytes());
        checksum.extend_from_slice(self.binding.as_bytes());
        checksum.extend_from_slice(&CONTEXT_FLAGS.to_le_bytes());

        // [MS-KILE] §3.2.5.8: "If ChannelBinding is set to TRUE, the client sends the Authorization
        // Data Type AD-AUTH-DATA-AP-OPTIONS (143) data in the first AD-IF-RELEVANT element".
        let authorization = self.binding.is_bound().then(|| {
            let options = (
                AD_AUTH_DATA_AP_OPTIONS,
                KERB_AP_OPTIONS_CBT.to_le_bytes().to_vec(),
            );
            authorization_data(&[(AD_IF_RELEVANT, authorization_data(&[options]))])
        });

        let authenticator = Authenticator {
            crealm: self.ticket.crealm.clone(),
            cname: self.ticket.cname.clone(),
            cksum: Some(Checksum {
                cksumtype: GSS_CHECKSUM,
                checksum,
            }),
            cusec: self.sent.1,
            ctime: self.sent.0,
            subkey: Some(EncryptionKey {
                keytype: self.subkey.enctype().number(),
                value: self.subkey.bytes().to_vec(),
            }),
            seq_number: Some(sequence),
            authorization_data: authorization,
        };
        let key = &self.ticket.key;
        let cipher = key.encrypt(
            usage::AP_REQ_AUTHENTICATOR,
            &fresh.confounder(),
            &authenticator.encode(),
        )?;
        let sealed = EncryptedData {
            etype: key.enctype().number(),
            kvno: None,
            cipher,
        };
        let request = ap::request(ap::MUTUAL_REQUIRED, &self.ticket.ticket.raw, &sealed);
        Ok(frame(tok_id::AP_REQ, &request))
    }

    /// Reads the server's context token: an AP-REP to check, or a `KRB-ERROR`.
    ///
    /// # Errors
    ///
    /// [`Error::ServiceRefused`] for a `KRB-ERROR` that cannot be retried, [`Error::ServiceReply`]
    /// for an AP-REP that does not answer the AP-REQ, [`Error::Crypto`] for one that does not
    /// decrypt, and [`Error::Malformed`] for a token that does not parse.
    pub(crate) fn read(&mut self, token: &[u8], fresh: &Fresh) -> Result<Reply> {
        let (id, message) = unframe(token)?;
        match id {
            tok_id::AP_REP => {
                self.accept(message)?;
                Ok(Reply::Accepted)
            }
            tok_id::ERROR => {
                let error = kdc::read_error_message(message)?;
                // [MS-KILE] §3.2.5.8: "When the client receives a KRB_AP_ERR_SKEW error … with a
                // KERB-ERROR-DATA structure … the client retries the AP-REQ using the time in the
                // KRB-ERROR message". Once: a second skew is a clock that will not hold still.
                let recoverable = error.error_code == code::SKEW
                    && error.e_data.as_deref().and_then(ErrorData::read).is_some();
                if recoverable && !self.skew_retried {
                    self.skew_retried = true;
                    self.offset = fresh.offset_to(error.stime);
                    return self.token(fresh).map(Reply::Retry);
                }
                Err(refused(&error))
            }
            _ => Err(Error::ServiceReply {
                reason: "a token that is neither an AP-REP nor a KRB-ERROR",
            }),
        }
    }

    /// Checks an AP-REP — [RFC 4120] §3.2.5: it decrypts under the session key, and repeats the
    /// authenticator's time to the microsecond.
    fn accept(&mut self, message: &[u8]) -> Result<()> {
        let sealed = ap::read_reply(message)?;
        let key = &self.ticket.key;
        if sealed.etype != key.enctype().number() {
            return Err(Error::ServiceReply {
                reason: "an AP-REP encrypted under a key of another type",
            });
        }
        let part = EncApRepPart::read(&key.decrypt(usage::AP_REP, &sealed.cipher)?)?;
        if (part.ctime, part.cusec) != self.sent {
            return Err(Error::ServiceReply {
                reason: "an AP-REP that does not repeat the authenticator's time",
            });
        }
        self.acceptor_subkey = part
            .subkey
            .map(|subkey| {
                let enctype = Enctype::from_number(subkey.keytype).ok_or(Error::ServiceReply {
                    reason: "an acceptor subkey of a type this client does not implement",
                })?;
                Key::new(enctype, subkey.value)
            })
            .transpose()?;
        Ok(())
    }

    /// The key MIC tokens are made with, and the flag that says which it is — [RFC 4121] §2: the
    /// acceptor's subkey if it asserted one, the initiator's otherwise.
    fn mic_key(&self) -> (&Key, u8) {
        match &self.acceptor_subkey {
            Some(key) => (key, mic_flag::ACCEPTOR_SUBKEY),
            None => (&self.subkey, 0),
        }
    }

    /// A MIC token over `message` — [RFC 4121] §4.2.6.1 — as the initiator sends it: for SPNEGO,
    /// the `mechListMIC` over the mechanism list.
    pub(crate) fn mic(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let (key, flags) = self.mic_key();
        let mut token = mic_header(flags, self.sequence);
        let checksum = key.checksum(usage::INITIATOR_SIGN, &[message, &token].concat())?;
        token.extend_from_slice(&checksum);
        self.sequence = self.sequence.wrapping_add(1);
        Ok(token)
    }

    /// Verifies the server's MIC token over `message`.
    ///
    /// # Errors
    ///
    /// [`Error::ServiceReply`] if the token is not an acceptor's MIC token made with the key the
    /// context says, and [`Error::Crypto`] if its checksum does not verify.
    pub(crate) fn verify_mic(&self, message: &[u8], token: &[u8]) -> Result<()> {
        let (header, checksum) = token
            .split_at_checked(MIC_HEADER)
            .ok_or(Error::ServiceReply {
                reason: "a MIC token shorter than its header",
            })?;
        let (key, expected) = self.mic_key();
        let well_formed = header.get(..2) == Some(&tok_id::MIC[..])
            && header.get(3..8) == Some(&[0xFF; 5][..])
            && header.get(2).is_some_and(|flags| {
                flags & mic_flag::SENT_BY_ACCEPTOR != 0
                    && flags & mic_flag::ACCEPTOR_SUBKEY == expected
            });
        if !well_formed {
            return Err(Error::ServiceReply {
                reason: "a MIC token that is not the acceptor's, under the context's key",
            });
        }
        key.verify_checksum(usage::ACCEPTOR_SIGN, &[message, header].concat(), checksum)
    }
}

/// A fresh subkey of the ticket's own type: [RFC 3961] random-to-key is the identity for AES.
fn subkey(ticket: &Credential, fresh: &Fresh) -> Result<Key> {
    let enctype = ticket.key.enctype();
    Key::new(enctype, fresh.subkey(enctype.key_len()))
}

/// The sixteen-octet MIC token header — [RFC 4121] §4.2.6.1.
fn mic_header(flags: u8, sequence: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(MIC_HEADER.saturating_add(24));
    header.extend_from_slice(&tok_id::MIC);
    header.push(flags);
    header.extend_from_slice(&[0xFF; 5]);
    header.extend_from_slice(&sequence.to_be_bytes());
    header
}

/// [RFC 2743] §3.1's framing, which [RFC 4121] §4.1 says every context token SHALL have:
/// `[APPLICATION 0]`, the mechanism's OID, then the two-octet `TOK_ID` and the Kerberos message.
pub(crate) fn frame(id: [u8; 2], message: &[u8]) -> Vec<u8> {
    let mut body = der::tlv(der::OID, OID);
    body.extend_from_slice(&id);
    body.extend_from_slice(message);
    der::tlv(der::application(0), &body)
}

/// Takes the framing off a context token, returning its `TOK_ID` and Kerberos message.
pub(crate) fn unframe(token: &[u8]) -> Result<([u8; 2], &[u8])> {
    let mut reader = Reader::new(STRUCTURE, token);
    let mut inner = reader.expect_nested(der::application(0), "a GSS-API token")?;
    let at = inner.offset();
    let oid = inner.expect(der::OID, "a mechanism OID")?;
    if oid != OID && oid != LEGACY_OID {
        return Err(inner.malformed(at, "a token for a mechanism other than Kerberos"));
    }
    let rest = inner.rest();
    match rest.split_first_chunk::<2>() {
        Some((id, message)) => Ok((*id, message)),
        None => Err(Error::Malformed {
            structure: STRUCTURE,
            offset: at,
            reason: "a token with no TOK_ID",
        }),
    }
}

fn refused(error: &KrbError) -> Error {
    Error::ServiceRefused {
        code: error.error_code,
        status: error
            .e_data
            .as_deref()
            .and_then(ErrorData::read)
            .and_then(|data| data.ntstatus()),
    }
}

#[cfg(test)]
mod tests;
