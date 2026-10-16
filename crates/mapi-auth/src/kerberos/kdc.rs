//! The messages of the AS and TGS exchanges — [RFC 4120] §5.4 and §5.9.1, with the pre-
//! authentication data of §5.2.7 and the [MS-KILE] §2.2 structures a Windows KDC adds.
//!
//! Requests are only written and replies only read: this is a client.

use crate::der::{self, Reader};
use crate::error::Result;
use crate::kerberos::asn1::{
    EncryptedData, EncryptionKey, Fields, KerberosTime, PVNO, PaData, PrincipalName, STRUCTURE,
    boolean, explicit, flags, int, read_flags, read_int32, read_octets, read_string, read_uint32,
    sequence,
};

/// `padata-type` values — [RFC 4120] §7.5.2 and [MS-KILE] §3.1.5.1.
pub(crate) mod padata {
    /// `PA-TGS-REQ`: the AP-REQ that authenticates a TGS-REQ.
    pub(crate) const TGS_REQ: i32 = 1;
    /// `PA-ENC-TIMESTAMP`: the encrypted timestamp that proves the password.
    pub(crate) const ENC_TIMESTAMP: i32 = 2;
    /// `PA-ETYPE-INFO2`: which keys the KDC holds for the principal, with their salts.
    pub(crate) const ETYPE_INFO2: i32 = 19;
    /// `PA-PAC-REQUEST` — [MS-KILE] §2.2.3.
    pub(crate) const PAC_REQUEST: i32 = 128;
}

/// `msg-type` and the application tag of each message — [RFC 4120] §5.4.1, §5.4.2, §5.9.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Exchange {
    /// The Authentication Service exchange: `AS-REQ` (10), `AS-REP` (11).
    As,
    /// The Ticket-Granting Service exchange: `TGS-REQ` (12), `TGS-REP` (13).
    Tgs,
}

impl Exchange {
    const fn request(self) -> u8 {
        match self {
            Self::As => 10,
            Self::Tgs => 12,
        }
    }

    const fn reply(self) -> u8 {
        match self {
            Self::As => 11,
            Self::Tgs => 13,
        }
    }
}

/// The application tag of `KRB-ERROR` — [RFC 4120] §5.9.1.
const KRB_ERROR: u8 = 30;

/// `KDC-REQ-BODY` — [RFC 4120] §5.4.1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KdcReqBody {
    /// `kdc-options`, numbered as [`super::asn1::flag`] numbers them.
    pub(crate) options: u32,
    /// `cname`, which only an AS-REQ carries.
    pub(crate) cname: Option<PrincipalName>,
    /// `realm`: the server's realm, which in an AS-REQ is also the client's.
    pub(crate) realm: String,
    /// `sname`.
    pub(crate) sname: Option<PrincipalName>,
    /// `till`: when the ticket should expire.
    pub(crate) till: KerberosTime,
    /// `nonce`, which the reply's encrypted part must repeat.
    pub(crate) nonce: u32,
    /// `etype`, in preference order.
    pub(crate) etypes: Vec<i32>,
    /// `enc-authorization-data`, which only a TGS-REQ carries.
    pub(crate) enc_authorization_data: Option<EncryptedData>,
}

impl KdcReqBody {
    /// The `SEQUENCE`. Kept separate from the request because a TGS-REQ's authenticator carries a
    /// checksum over exactly these bytes ([RFC 4120] §5.5.1).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut fields = vec![explicit(0, &flags(self.options))];
        if let Some(cname) = &self.cname {
            fields.push(explicit(1, &cname.encode()));
        }
        fields.push(explicit(2, &super::asn1::string(&self.realm)));
        if let Some(sname) = &self.sname {
            fields.push(explicit(3, &sname.encode()));
        }
        fields.push(explicit(5, &self.till.encode()));
        fields.push(explicit(7, &int(i64::from(self.nonce))));
        let etypes: Vec<u8> = self
            .etypes
            .iter()
            .flat_map(|etype| int(i64::from(*etype)))
            .collect();
        fields.push(explicit(8, &der::tlv(der::SEQUENCE, &etypes)));
        if let Some(data) = &self.enc_authorization_data {
            fields.push(explicit(10, &data.encode()));
        }
        sequence(&fields)
    }
}

/// An `AS-REQ` or `TGS-REQ` — [RFC 4120] §5.4.1. `body` is [`KdcReqBody::encode`]'s output, passed
/// in already encoded so that the bytes sent are the bytes a checksum was computed over.
pub(crate) fn request(exchange: Exchange, padata: &[PaData], body: &[u8]) -> Vec<u8> {
    let mut fields = vec![
        explicit(1, &int(PVNO)),
        explicit(2, &int(i64::from(exchange.request()))),
    ];
    if !padata.is_empty() {
        // [RFC 4120] §5.4.1: "NOTE: not empty", so an empty list is omitted rather than sent.
        let list: Vec<u8> = padata.iter().flat_map(PaData::encode).collect();
        fields.push(explicit(3, &der::tlv(der::SEQUENCE, &list)));
    }
    fields.push(explicit(4, body));
    der::tlv(der::application(exchange.request()), &sequence(&fields))
}

/// A `Ticket` — [RFC 4120] §5.3 — kept as the bytes the KDC sent, with the two fields a client
/// reads out of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ticket {
    /// The whole `[APPLICATION 1]` element, for sending on unchanged.
    pub(crate) raw: Vec<u8>,
    /// `realm`: the realm that issued it, which is the service's.
    pub(crate) realm: String,
    /// `sname`: whom it is for. `krbtgt/OTHER` here is a referral ([RFC 6806] §8).
    pub(crate) sname: PrincipalName,
}

impl Ticket {
    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let raw = reader.clone().read_element()?.to_vec();
        let mut inner = reader.expect_nested(der::application(1), "a Ticket")?;
        let fields = Fields::of(&mut inner, "a Ticket")?;
        Ok(Self {
            raw,
            realm: read_string(&mut fields.required(1, "a ticket realm")?, "a ticket realm")?,
            sname: PrincipalName::read(&mut fields.required(2, "a ticket sname")?)?,
        })
    }
}

/// An `AS-REP` or `TGS-REP` — [RFC 4120] §5.4.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KdcRep {
    /// Which of the two.
    pub(crate) exchange: Exchange,
    /// `padata`, which in an AS-REP may repeat `PA-ETYPE-INFO2`.
    pub(crate) padata: Vec<PaData>,
    /// `crealm`: the client's realm, canonicalized.
    pub(crate) crealm: String,
    /// `cname`: the client's name, canonicalized.
    pub(crate) cname: PrincipalName,
    /// `ticket`.
    pub(crate) ticket: Ticket,
    /// `enc-part`: an `EncASRepPart` or `EncTGSRepPart`.
    pub(crate) enc_part: EncryptedData,
}

/// `KRB-ERROR` — [RFC 4120] §5.9.1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KrbError {
    /// `error-code` — [RFC 4120] §7.5.9.
    pub(crate) error_code: i32,
    /// `stime`: the KDC's clock, which [MS-KILE] §3.2.5.8's skew recovery uses.
    pub(crate) stime: KerberosTime,
    /// `susec`.
    pub(crate) susec: u32,
    /// `realm`: the realm of the service that answered.
    pub(crate) realm: String,
    /// `e-text`, when the KDC wrote one.
    pub(crate) e_text: Option<String>,
    /// `e-data`: `METHOD-DATA` after `KDC_ERR_PREAUTH_REQUIRED`, `KERB-ERROR-DATA` from a Windows
    /// KDC.
    pub(crate) e_data: Option<Vec<u8>>,
}

/// What a KDC answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum KdcReply {
    /// The ticket that was asked for.
    Rep(KdcRep),
    /// A refusal, or a request for more pre-authentication.
    Error(KrbError),
}

/// Reads a KDC's answer to a request of `exchange` — its reply, or a `KRB-ERROR`.
pub(crate) fn read_reply(exchange: Exchange, bytes: &[u8]) -> Result<KdcReply> {
    let mut reader = Reader::new(STRUCTURE, bytes);
    let tag = reader
        .peek_tag()
        .ok_or_else(|| reader.malformed(0, "an empty reply"))?;
    if tag == der::application(KRB_ERROR) {
        let mut inner = reader.expect_nested(tag, "a KRB-ERROR")?;
        return read_error(&mut inner).map(KdcReply::Error);
    }

    let mut inner = reader.expect_nested(der::application(exchange.reply()), "a KDC reply")?;
    let fields = Fields::of(&mut inner, "a KDC reply")?;
    let pvno = read_int32(&mut fields.required(0, "a pvno")?, "a pvno")?;
    let msg_type = read_int32(&mut fields.required(1, "a msg-type")?, "a msg-type")?;
    if i64::from(pvno) != PVNO || msg_type != i32::from(exchange.reply()) {
        return Err(reader.malformed(0, "a reply with the wrong pvno or msg-type"));
    }
    Ok(KdcReply::Rep(KdcRep {
        exchange,
        padata: fields
            .optional(2)
            .map(|mut field| PaData::read_all(&mut field))
            .transpose()?
            .unwrap_or_default(),
        crealm: read_string(&mut fields.required(3, "a crealm")?, "a crealm")?,
        cname: PrincipalName::read(&mut fields.required(4, "a cname")?)?,
        ticket: Ticket::read(&mut fields.required(5, "a ticket")?)?,
        enc_part: EncryptedData::read(&mut fields.required(6, "an enc-part")?)?,
    }))
}

fn read_error(reader: &mut Reader<'_>) -> Result<KrbError> {
    let fields = Fields::of(reader, "a KRB-ERROR")?;
    Ok(KrbError {
        error_code: read_int32(&mut fields.required(6, "an error-code")?, "an error-code")?,
        stime: KerberosTime::read(&mut fields.required(4, "an stime")?, "an stime")?,
        susec: read_uint32(&mut fields.required(5, "a susec")?, "a susec")?,
        realm: read_string(&mut fields.required(9, "a realm")?, "a realm")?,
        e_text: fields
            .optional(11)
            .map(|mut field| read_string(&mut field, "an e-text"))
            .transpose()?,
        e_data: fields
            .optional(12)
            .map(|mut field| read_octets(&mut field, "an e-data"))
            .transpose()?,
    })
}

/// `EncKDCRepPart` — [RFC 4120] §5.4.2, decrypted from a reply's `enc-part`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncKdcRepPart {
    /// `key`: the session key that goes with the ticket.
    pub(crate) key: EncryptionKey,
    /// `nonce`, which must be the request's.
    pub(crate) nonce: u32,
    /// `flags`: the ticket's flags.
    pub(crate) flags: u32,
    /// `endtime`: when the ticket stops working.
    pub(crate) endtime: KerberosTime,
    /// `srealm`.
    pub(crate) srealm: String,
    /// `sname`, which must match the ticket's.
    pub(crate) sname: PrincipalName,
}

impl EncKdcRepPart {
    /// Reads one from decrypted bytes.
    ///
    /// Either application tag is accepted for either exchange. [RFC 4120] §5.4.2's compatibility
    /// note: "Some implementations unconditionally send an encrypted `EncTGSRepPart` (application
    /// tag number 26) … regardless of whether the reply is a AS-REP or a TGS-REP. In the
    /// interest of compatibility, implementors MAY relax the check on the tag number." This one
    /// does, because the tag is the only thing about the part a client could check and nothing
    /// hangs on it.
    pub(crate) fn read(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(STRUCTURE, bytes);
        let tag = reader
            .peek_tag()
            .ok_or_else(|| reader.malformed(0, "an empty EncKDCRepPart"))?;
        if tag != der::application(25) && tag != der::application(26) {
            return Err(reader.malformed(0, "neither an EncASRepPart nor an EncTGSRepPart"));
        }
        let mut inner = reader.expect_nested(tag, "an EncKDCRepPart")?;
        let fields = Fields::of(&mut inner, "an EncKDCRepPart")?;
        Ok(Self {
            key: EncryptionKey::read(&mut fields.required(0, "a session key")?)?,
            nonce: read_uint32(&mut fields.required(2, "a nonce")?, "a nonce")?,
            flags: read_flags(&mut fields.required(4, "ticket flags")?, "ticket flags")?,
            endtime: KerberosTime::read(&mut fields.required(7, "an endtime")?, "an endtime")?,
            srealm: read_string(&mut fields.required(9, "an srealm")?, "an srealm")?,
            sname: PrincipalName::read(&mut fields.required(10, "an sname")?)?,
        })
    }
}

/// `PA-ENC-TS-ENC` — [RFC 4120] §5.2.7.2: the client's time, which is what gets encrypted under
/// the password's key to prove it.
pub(crate) fn pa_enc_ts_enc(time: KerberosTime, usec: u32) -> Vec<u8> {
    sequence(&[
        explicit(0, &time.encode()),
        explicit(1, &int(i64::from(usec))),
    ])
}

/// `KERB-PA-PAC-REQUEST` — [MS-KILE] §2.2.3, which §3.2.5.5 says a client "will always include".
pub(crate) fn pac_request(include: bool) -> Vec<u8> {
    sequence(&[explicit(0, &boolean(include))])
}

/// One `ETYPE-INFO2-ENTRY` — [RFC 4120] §5.2.7.5: a key the KDC holds, and how to make it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EtypeInfo2 {
    /// `etype`.
    pub(crate) etype: i32,
    /// `salt`, when it is not the default. Active Directory always sends one.
    pub(crate) salt: Option<String>,
    /// `s2kparams`: the iteration count, when it is not the default.
    pub(crate) s2kparams: Option<Vec<u8>>,
}

impl EtypeInfo2 {
    /// Reads `ETYPE-INFO2`, a `SEQUENCE OF ETYPE-INFO2-ENTRY`.
    pub(crate) fn read_all(bytes: &[u8]) -> Result<Vec<Self>> {
        let mut reader = Reader::new(STRUCTURE, bytes);
        let mut list = reader.expect_nested(der::SEQUENCE, "an ETYPE-INFO2")?;
        let mut out = Vec::new();
        while !list.is_empty() {
            let fields = Fields::of(&mut list, "an ETYPE-INFO2-ENTRY")?;
            out.push(Self {
                etype: read_int32(&mut fields.required(0, "an etype")?, "an etype")?,
                salt: fields
                    .optional(1)
                    .map(|mut field| read_string(&mut field, "a salt"))
                    .transpose()?,
                s2kparams: fields
                    .optional(2)
                    .map(|mut field| read_octets(&mut field, "s2kparams"))
                    .transpose()?,
            });
        }
        Ok(out)
    }
}

/// `KERB-ERROR-DATA` — [MS-KILE] §2.2.2: what a Windows KDC or server puts in `e-data`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ErrorData {
    /// `data-type`: 2 for clock skew recovery, 3 for an extended error.
    pub(crate) data_type: i32,
    /// `data-value`: for an extended error, a `KERB-EXT-ERROR` (§2.2.1) whose first four bytes are
    /// an `NTSTATUS`.
    pub(crate) value: Option<Vec<u8>>,
}

impl ErrorData {
    /// `KERB_ERR_TYPE_EXTENDED` — [MS-KILE] §2.2.2.
    pub(crate) const EXTENDED: i32 = 3;
    /// `KERB_AP_ERR_TYPE_SKEW_RECOVERY` — [MS-KILE] §2.2.2.
    pub(crate) const SKEW_RECOVERY: i32 = 2;

    /// Reads one, or `None` if `e-data` holds something else — a `METHOD-DATA`, for instance.
    pub(crate) fn read(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(STRUCTURE, bytes);
        let fields = Fields::of(&mut reader, "a KERB-ERROR-DATA").ok()?;
        Some(Self {
            data_type: read_int32(&mut fields.optional(1)?, "a data-type").ok()?,
            value: fields
                .optional(2)
                .and_then(|mut field| read_octets(&mut field, "a data-value").ok()),
        })
    }

    /// The `NTSTATUS` of a `KERB-EXT-ERROR` — [MS-KILE] §2.2.1, little-endian like every other
    /// field of that C structure.
    pub(crate) fn ntstatus(&self) -> Option<u32> {
        if self.data_type != Self::EXTENDED {
            return None;
        }
        let bytes = self.value.as_deref()?.get(..4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }
}

#[cfg(test)]
mod tests;
