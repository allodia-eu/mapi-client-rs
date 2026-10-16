//! The building blocks every Kerberos message is made of — [RFC 4120] §5.2 and Appendix A.
//!
//! The module is `DEFINITIONS EXPLICIT TAGS`, so every field of every `SEQUENCE` is a context tag
//! `[n]` wrapping a complete element of its own. [`Fields`] reads that shape once, and the encoders
//! here write it, so the message modules read like the ASN.1 they implement.

use crate::der::{self, Reader};
use crate::error::Result;

/// What a reader of these messages calls them in an error.
pub(crate) const STRUCTURE: &str = "Kerberos message";

/// `pvno` — [RFC 4120] §5.4.1: "this field specifies the protocol version number. It MUST be 5".
pub(crate) const PVNO: i64 = 5;

/// `[n] element` — one explicitly tagged field.
pub(crate) fn explicit(n: u8, element: &[u8]) -> Vec<u8> {
    der::tlv(der::context(n), element)
}

/// A `SEQUENCE` of the given encoded fields, in order.
pub(crate) fn sequence(fields: &[Vec<u8>]) -> Vec<u8> {
    der::tlv(der::SEQUENCE, &fields.concat())
}

/// An `INTEGER`. `Int32`, `UInt32` and `Microseconds` are all this ([RFC 4120] §5.2.4).
pub(crate) fn int(value: i64) -> Vec<u8> {
    der::tlv(der::INTEGER, &der::integer(value))
}

/// A `KerberosString`: `GeneralString` restricted to IA5 by [RFC 4120] §5.2.1, and carrying UTF-8
/// by [MS-KILE] §3.1.5.7 — "KILE MUST use UTF-8 encoding of these names".
pub(crate) fn string(value: &str) -> Vec<u8> {
    der::tlv(der::GENERAL_STRING, value.as_bytes())
}

/// An `OCTET STRING`.
pub(crate) fn octets(value: &[u8]) -> Vec<u8> {
    der::tlv(der::OCTET_STRING, value)
}

/// A `BOOLEAN`, with DER's `0xFF` for true ([X690] §11.1).
pub(crate) fn boolean(value: bool) -> Vec<u8> {
    der::tlv(der::BOOLEAN, &[if value { 0xFF } else { 0x00 }])
}

/// `KerberosFlags` — [RFC 4120] §5.2.8: a `BIT STRING` of at least 32 bits, flag 0 the most
/// significant. `flags` holds flag *n* at bit `31 - n`, so the bytes are its big-endian form.
pub(crate) fn flags(flags: u32) -> Vec<u8> {
    let mut contents = vec![0u8];
    contents.extend_from_slice(&flags.to_be_bytes());
    der::tlv(der::BIT_STRING, &contents)
}

/// The `u32` that sets `KerberosFlags` flag `n` — the inverse of [`flags`]'s numbering.
pub(crate) const fn flag(n: u32) -> u32 {
    match 0x8000_0000u32.checked_shr(n) {
        Some(bit) => bit,
        None => 0,
    }
}

/// The explicitly tagged fields of one `SEQUENCE`, read once and then taken by number.
pub(crate) struct Fields<'a> {
    fields: Vec<(u8, Reader<'a>)>,
    /// For a missing required field: where the `SEQUENCE` started.
    at: Reader<'a>,
}

impl<'a> Fields<'a> {
    /// Reads a `SEQUENCE` and indexes its fields by context number.
    ///
    /// A field this crate does not know is kept rather than refused: [RFC 4120] §5 has grown fields
    /// after the fact — [RFC 6806] §11 added `[12] encrypted-pa-data` to `EncKDCRepPart` — and
    /// the ones a client does not use are ones it can ignore.
    pub(crate) fn of(reader: &mut Reader<'a>, reason: &'static str) -> Result<Self> {
        let mut body = reader.expect_nested(der::SEQUENCE, reason)?;
        let at = body.clone();
        let mut fields = Vec::new();
        while !body.is_empty() {
            let offset = body.offset();
            let tag = body
                .peek_tag()
                .ok_or_else(|| body.malformed(offset, reason))?;
            if tag & 0xE0 != 0xA0 {
                return Err(body.malformed(offset, "a field that is not explicitly tagged"));
            }
            fields.push((tag & 0x1F, body.expect_nested(tag, reason)?));
        }
        Ok(Self { fields, at })
    }

    /// The reader inside field `[n]`, which must be present.
    pub(crate) fn required(&self, n: u8, reason: &'static str) -> Result<Reader<'a>> {
        self.optional(n)
            .ok_or_else(|| self.at.malformed(self.at.offset(), reason))
    }

    /// The reader inside field `[n]`, if it is present.
    pub(crate) fn optional(&self, n: u8) -> Option<Reader<'a>> {
        self.fields
            .iter()
            .find(|(number, _)| *number == n)
            .map(|(_, reader)| reader.clone())
    }
}

/// Reads an `INTEGER` that must fit an `Int32`.
pub(crate) fn read_int32(reader: &mut Reader<'_>, reason: &'static str) -> Result<i32> {
    let offset = reader.offset();
    der::read_integer(reader.expect(der::INTEGER, reason)?)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| reader.malformed(offset, reason))
}

/// Reads an `INTEGER` that must fit a `UInt32`.
pub(crate) fn read_uint32(reader: &mut Reader<'_>, reason: &'static str) -> Result<u32> {
    let offset = reader.offset();
    der::read_integer(reader.expect(der::INTEGER, reason)?)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| reader.malformed(offset, reason))
}

/// Reads a `KerberosString` as UTF-8.
pub(crate) fn read_string(reader: &mut Reader<'_>, reason: &'static str) -> Result<String> {
    let offset = reader.offset();
    let bytes = reader.expect(der::GENERAL_STRING, reason)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| reader.malformed(offset, reason))
}

/// Reads an `OCTET STRING`.
pub(crate) fn read_octets(reader: &mut Reader<'_>, reason: &'static str) -> Result<Vec<u8>> {
    Ok(reader.expect(der::OCTET_STRING, reason)?.to_vec())
}

/// Reads `KerberosFlags`, keeping the first 32 flags in [`flags`]'s numbering.
pub(crate) fn read_flags(reader: &mut Reader<'_>, reason: &'static str) -> Result<u32> {
    let offset = reader.offset();
    let contents = reader.expect(der::BIT_STRING, reason)?;
    let (_unused, bits) = contents
        .split_first()
        .ok_or_else(|| reader.malformed(offset, reason))?;
    let mut word = [0u8; 4];
    for (slot, byte) in word.iter_mut().zip(bits) {
        *slot = *byte;
    }
    Ok(u32::from_be_bytes(word))
}

/// `KerberosTime` — [RFC 4120] §5.2.3: `GeneralizedTime`, UTC, no fractional seconds, written
/// `YYYYMMDDHHMMSSZ`. Held as seconds since the Unix epoch, which is what a caller's clock gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct KerberosTime(u64);

impl KerberosTime {
    /// The time `seconds` after 1970-01-01T00:00:00Z.
    pub(crate) const fn from_unix(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Seconds since the Unix epoch.
    pub(crate) const fn unix(self) -> u64 {
        self.0
    }

    /// The `GeneralizedTime` element.
    pub(crate) fn encode(self) -> Vec<u8> {
        der::tlv(der::GENERALIZED_TIME, self.text().as_bytes())
    }

    /// `YYYYMMDDHHMMSSZ`.
    fn text(self) -> String {
        let days = self.0.checked_div(86_400).unwrap_or(0);
        let rest = self.0.checked_rem(86_400).unwrap_or(0);
        let (year, month, day) = civil_from_days(days);
        format!(
            "{year:04}{month:02}{day:02}{:02}{:02}{:02}Z",
            rest.checked_div(3_600).unwrap_or(0),
            rest.checked_rem(3_600)
                .and_then(|r| r.checked_div(60))
                .unwrap_or(0),
            rest.checked_rem(60).unwrap_or(0),
        )
    }

    /// Reads one, refusing anything but the exact form [RFC 4120] §5.2.3 allows.
    pub(crate) fn read(reader: &mut Reader<'_>, reason: &'static str) -> Result<Self> {
        let offset = reader.offset();
        let text = reader.expect(der::GENERALIZED_TIME, reason)?;
        Self::parse(text).ok_or_else(|| reader.malformed(offset, reason))
    }

    fn parse(text: &[u8]) -> Option<Self> {
        let (digits, zone) = text.split_at_checked(14)?;
        if zone != b"Z" || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let number = |from: usize, len: usize| -> Option<u64> {
            digits
                .get(from..from.checked_add(len)?)?
                .iter()
                .try_fold(0u64, |acc, digit| {
                    acc.checked_mul(10)?
                        .checked_add(u64::from(digit.checked_sub(b'0')?))
                })
        };
        let (year, month, day) = (number(0, 4)?, number(4, 2)?, number(6, 2)?);
        let (hour, minute, second) = (number(8, 2)?, number(10, 2)?, number(12, 2)?);
        if year < 1970
            || !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return None;
        }
        let days = days_from_civil(year, month, day)?;
        let seconds = days
            .checked_mul(86_400)?
            .checked_add(hour.checked_mul(3_600)?)?
            .checked_add(minute.checked_mul(60)?)?
            .checked_add(second)?;
        Some(Self(seconds))
    }
}

/// The date `days` after 1970-01-01, by Howard Hinnant's `civil_from_days` for the proleptic
/// Gregorian calendar, restricted to dates on or after the epoch.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days.saturating_add(719_468);
    let era = z.checked_div(146_097).unwrap_or(0);
    let doe = z.saturating_sub(era.saturating_mul(146_097));
    let yoe = doe
        .saturating_sub(doe.checked_div(1_460).unwrap_or(0))
        .saturating_add(doe.checked_div(36_524).unwrap_or(0))
        .saturating_sub(doe.checked_div(146_096).unwrap_or(0))
        .checked_div(365)
        .unwrap_or(0);
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe.checked_div(4).unwrap_or(0))
            .saturating_sub(yoe.checked_div(100).unwrap_or(0)),
    );
    let mp = doy
        .saturating_mul(5)
        .saturating_add(2)
        .checked_div(153)
        .unwrap_or(0);
    let day = doy
        .saturating_sub(
            mp.saturating_mul(153)
                .saturating_add(2)
                .checked_div(5)
                .unwrap_or(0),
        )
        .saturating_add(1);
    let month = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let year = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(u64::from(month <= 2));
    (year, month, day)
}

/// The days from 1970-01-01 to a date on or after it — Hinnant's `days_from_civil`.
fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    let year = year.checked_sub(u64::from(month <= 2))?;
    let era = year.checked_div(400)?;
    let yoe = year.checked_sub(era.checked_mul(400)?)?;
    let shifted = if month > 2 {
        month.checked_sub(3)?
    } else {
        month.checked_add(9)?
    };
    let doy = shifted
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(day)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

/// How many days a month has, for validating a date that came off the wire.
fn days_in_month(year: u64, month: u64) -> u64 {
    let leap = year.checked_rem(4) == Some(0)
        && (year.checked_rem(100) != Some(0) || year.checked_rem(400) == Some(0));
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `PrincipalName` — [RFC 4120] §5.2.2: a name type and the components of the name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrincipalName {
    /// `name-type` — [RFC 4120] §6.2 and [RFC 6806] §5.
    pub(crate) name_type: i32,
    /// `name-string`, one entry per component: `["HTTP", "host.example.test"]`.
    pub(crate) components: Vec<String>,
}

impl PrincipalName {
    /// `NT-ENTERPRISE` — [RFC 6806] §5: the whole of a UPN as a single component.
    pub(crate) const NT_ENTERPRISE: i32 = 10;
    /// `NT-PRINCIPAL` — [RFC 4120] §6.2: "just the name of the principal as in DCE, or for users".
    pub(crate) const NT_PRINCIPAL: i32 = 1;
    /// `NT-SRV-INST` — [RFC 4120] §6.2: a service and other unique instance, such as `krbtgt`.
    pub(crate) const NT_SRV_INST: i32 = 2;

    /// A name of the given type.
    pub(crate) fn new(name_type: i32, components: &[&str]) -> Self {
        Self {
            name_type,
            components: components.iter().map(|part| (*part).to_owned()).collect(),
        }
    }

    /// The `SEQUENCE`.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let parts: Vec<u8> = self
            .components
            .iter()
            .flat_map(|part| string(part))
            .collect();
        sequence(&[
            explicit(0, &int(i64::from(self.name_type))),
            explicit(1, &der::tlv(der::SEQUENCE, &parts)),
        ])
    }

    /// Reads one.
    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let fields = Fields::of(reader, "a PrincipalName")?;
        let name_type = read_int32(&mut fields.required(0, "a name-type")?, "a name-type")?;
        let mut list = fields
            .required(1, "a name-string")?
            .expect_nested(der::SEQUENCE, "a name-string")?;
        let mut components = Vec::new();
        while !list.is_empty() {
            components.push(read_string(&mut list, "a name component")?);
        }
        Ok(Self {
            name_type,
            components,
        })
    }

    /// Whether this names the ticket-granting service — `krbtgt/REALM` ([RFC 4120] §7.3).
    pub(crate) fn is_krbtgt(&self) -> bool {
        self.components
            .first()
            .is_some_and(|first| first.eq_ignore_ascii_case("krbtgt"))
    }
}

/// `EncryptedData` — [RFC 4120] §5.2.9.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncryptedData {
    /// `etype`, the encryption type.
    pub(crate) etype: i32,
    /// `kvno`, the key version, when the key is a long-term one.
    pub(crate) kvno: Option<u32>,
    /// `cipher`.
    pub(crate) cipher: Vec<u8>,
}

impl EncryptedData {
    /// The `SEQUENCE`.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut fields = vec![explicit(0, &int(i64::from(self.etype)))];
        if let Some(kvno) = self.kvno {
            fields.push(explicit(1, &int(i64::from(kvno))));
        }
        fields.push(explicit(2, &octets(&self.cipher)));
        sequence(&fields)
    }

    /// Reads one.
    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let fields = Fields::of(reader, "an EncryptedData")?;
        Ok(Self {
            etype: read_int32(&mut fields.required(0, "an etype")?, "an etype")?,
            kvno: fields
                .optional(1)
                .map(|mut field| read_uint32(&mut field, "a kvno"))
                .transpose()?,
            cipher: read_octets(&mut fields.required(2, "a cipher")?, "a cipher")?,
        })
    }
}

/// `EncryptionKey` — [RFC 4120] §5.2.9: a key and the type it is for.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EncryptionKey {
    /// `keytype`, "actually encryption type".
    pub(crate) keytype: i32,
    /// `keyvalue`.
    pub(crate) value: Vec<u8>,
}

impl core::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("keytype", &self.keytype)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl EncryptionKey {
    /// The `SEQUENCE`.
    pub(crate) fn encode(&self) -> Vec<u8> {
        sequence(&[
            explicit(0, &int(i64::from(self.keytype))),
            explicit(1, &octets(&self.value)),
        ])
    }

    /// Reads one.
    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let fields = Fields::of(reader, "an EncryptionKey")?;
        Ok(Self {
            keytype: read_int32(&mut fields.required(0, "a keytype")?, "a keytype")?,
            value: read_octets(&mut fields.required(1, "a keyvalue")?, "a keyvalue")?,
        })
    }
}

/// `Checksum` — [RFC 4120] §5.2.9.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Checksum {
    /// `cksumtype`.
    pub(crate) cksumtype: i32,
    /// `checksum`.
    pub(crate) checksum: Vec<u8>,
}

impl Checksum {
    /// The `SEQUENCE`.
    pub(crate) fn encode(&self) -> Vec<u8> {
        sequence(&[
            explicit(0, &int(i64::from(self.cksumtype))),
            explicit(1, &octets(&self.checksum)),
        ])
    }
}

/// `PA-DATA` — [RFC 4120] §5.2.7. Note the first tag is `[1]`, not `[0]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PaData {
    /// `padata-type`.
    pub(crate) padata_type: i32,
    /// `padata-value`, whose contents depend on the type.
    pub(crate) value: Vec<u8>,
}

impl PaData {
    /// The `SEQUENCE`.
    pub(crate) fn encode(&self) -> Vec<u8> {
        sequence(&[
            explicit(1, &int(i64::from(self.padata_type))),
            explicit(2, &octets(&self.value)),
        ])
    }

    /// Reads one.
    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let fields = Fields::of(reader, "a PA-DATA")?;
        Ok(Self {
            padata_type: read_int32(&mut fields.required(1, "a padata-type")?, "a padata-type")?,
            value: read_octets(&mut fields.required(2, "a padata-value")?, "a padata-value")?,
        })
    }

    /// Reads `SEQUENCE OF PA-DATA`, which is also `METHOD-DATA` ([RFC 4120] §5.9.1).
    pub(crate) fn read_all(reader: &mut Reader<'_>) -> Result<Vec<Self>> {
        let mut list = reader.expect_nested(der::SEQUENCE, "a SEQUENCE OF PA-DATA")?;
        let mut out = Vec::new();
        while !list.is_empty() {
            out.push(Self::read(&mut list)?);
        }
        Ok(out)
    }
}

/// `AuthorizationData` — [RFC 4120] §5.2.6: `SEQUENCE OF SEQUENCE { ad-type, ad-data }`.
pub(crate) fn authorization_data(entries: &[(i32, Vec<u8>)]) -> Vec<u8> {
    let body: Vec<u8> = entries
        .iter()
        .flat_map(|(ad_type, data)| {
            sequence(&[
                explicit(0, &int(i64::from(*ad_type))),
                explicit(1, &octets(data)),
            ])
        })
        .collect();
    der::tlv(der::SEQUENCE, &body)
}

#[cfg(test)]
mod tests;
