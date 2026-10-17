//! The four AES encryption types [MS-KILE] §3.1.5.2 requires, and no others.
//!
//! [MS-KILE] §3.1.5.2 makes AES a MUST — `aes256-cts-hmac-sha1-96` and `aes128-cts-hmac-sha1-96`
//! from [RFC 3962], `aes128-cts-hmac-sha256-128` and `aes256-cts-hmac-sha384-192` from [RFC 8009] —
//! and RC4-HMAC and DES a SHOULD. This crate implements the first four and declines the rest:
//! [RFC 8429] deprecates RC4 in Kerberos, DES is gone from every Windows still supported, and
//! leaving both out keeps RC4 and DES out of the workspace, as the NTLM work already did.
//!
//! Everything here is pinned byte for byte to published vectors: [RFC 3961] Appendix A.1 for
//! `n-fold`, [RFC 3962] Appendix B for string-to-key and ciphertext stealing, and [RFC 8009]
//! Appendix A for the SHA-2 types end to end.
//!
//! # The SHA-2 types are a MUST that Windows ships switched off
//!
//! [MS-KILE] §3.1.5.2 makes both a MUST; notes `<14>` and `<15>`, attached to the §2.2.7 bit flags
//! rather than to §3.1.5.2, say each "is supported in Windows 11, version 24H2 and later and
//! Windows Server 2025 and later … This is disabled by default." Measured, and consistent with
//! that: a Windows Server 2025 (`10.0.26100`) KDC at the Windows2025 domain functional level, with
//! no Kerberos encryption-type policy set, asked for only `aes256-cts-hmac-sha384-192` or
//! `aes128-cts-hmac-sha256-128`, lists no `PA-ETYPE-INFO2` entry and refuses a timestamp encrypted
//! under either with `KDC_ERR_ETYPE_NOSUPP`. It answers the same with the "Future encryption
//! types" policy on (`SupportedEncryptionTypes` `0x7FFFFFF8`), for an account whose password was
//! last set before that policy was. This client offers them anyway, strongest first, as
//! §3.1.5.2 requires; such a KDC answers with `aes256-cts-hmac-sha1-96`, and the SHA-1 types are
//! the ones exercised live.

mod cts;
mod nfold;
mod rfc3962;
mod rfc8009;

use rfc8009::Variant;

use crate::error::{Error, Result};

/// The length of the confounder every encryption starts with: one AES block — [RFC 3961] §5.3's
/// `conf`, "random string of length c", and [RFC 8009] §5's `N`.
pub(crate) const CONFOUNDER: usize = cts::BLOCK;

/// Why an operation in this module failed, before it is attached to a key usage.
type Fault = &'static str;

/// The most string-to-key iterations this client will run for a KDC.
///
/// The count is the KDC's to choose ([RFC 3962] §4), so an answer from a spoofed KDC could ask for
/// up to 2³² of them and stall the client. [RFC 3962] §4 says a limit, if there is one, "SHOULD be
/// no less than 50,000"; this one is twenty times that, and thirty times [RFC 8009]'s own default
/// of 32,768.
const MAX_ITERATIONS: u32 = 1_000_000;

/// An encryption type, by its assigned number — [RFC 3961] §8, [RFC 3962] §7, [RFC 8009] §7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Enctype {
    /// `aes128-cts-hmac-sha1-96`, 17.
    Aes128Sha1,
    /// `aes256-cts-hmac-sha1-96`, 18.
    Aes256Sha1,
    /// `aes128-cts-hmac-sha256-128`, 19.
    Aes128Sha256,
    /// `aes256-cts-hmac-sha384-192`, 20.
    Aes256Sha384,
}

impl Enctype {
    /// Every type, strongest first, which is the order a request lists them in.
    pub(crate) const PREFERENCE: [Self; 4] = [
        Self::Aes256Sha384,
        Self::Aes128Sha256,
        Self::Aes256Sha1,
        Self::Aes128Sha1,
    ];

    /// The type a number names, if it is one of these four.
    pub(crate) const fn from_number(number: i32) -> Option<Self> {
        match number {
            17 => Some(Self::Aes128Sha1),
            18 => Some(Self::Aes256Sha1),
            19 => Some(Self::Aes128Sha256),
            20 => Some(Self::Aes256Sha384),
            _ => None,
        }
    }

    /// The assigned number.
    pub(crate) const fn number(self) -> i32 {
        match self {
            Self::Aes128Sha1 => 17,
            Self::Aes256Sha1 => 18,
            Self::Aes128Sha256 => 19,
            Self::Aes256Sha384 => 20,
        }
    }

    /// The checksum type paired with it — [RFC 3962] §7 (15, 16) and [RFC 8009] §7 (19, 20).
    pub(crate) const fn checksum_type(self) -> i32 {
        match self {
            Self::Aes128Sha1 => 15,
            Self::Aes256Sha1 => 16,
            Self::Aes128Sha256 => 19,
            Self::Aes256Sha384 => 20,
        }
    }

    /// The protocol key's length in bytes.
    pub(crate) const fn key_len(self) -> usize {
        match self {
            Self::Aes128Sha1 | Self::Aes128Sha256 => 16,
            Self::Aes256Sha1 | Self::Aes256Sha384 => 32,
        }
    }

    /// The iteration count when the KDC names none — [RFC 3962] §4 (4,096) and [RFC 8009] §4
    /// (32,768).
    const fn default_iterations(self) -> u32 {
        match self {
            Self::Aes128Sha1 | Self::Aes256Sha1 => 4_096,
            Self::Aes128Sha256 | Self::Aes256Sha384 => 32_768,
        }
    }

    /// Which [RFC 8009] variant, for the SHA-2 types.
    const fn variant(self) -> Option<Variant> {
        match self {
            Self::Aes128Sha1 | Self::Aes256Sha1 => None,
            Self::Aes128Sha256 => Some(Variant::Sha256),
            Self::Aes256Sha384 => Some(Variant::Sha384),
        }
    }
}

/// A protocol key of one encryption type: a long-term key made from a password, or a session key a
/// KDC handed out.
///
/// [`Debug`] prints the type and never the bytes, so that a key can live inside a struct that
/// derives it without reaching a log.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Key {
    enctype: Enctype,
    bytes: Vec<u8>,
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Key")
            .field("enctype", &self.enctype)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Key {
    /// A key a KDC sent, after checking it is the length its type needs.
    pub(crate) fn new(enctype: Enctype, bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() == enctype.key_len() {
            Ok(Self { enctype, bytes })
        } else {
            Err(Error::Crypto {
                usage: None,
                reason: "a key that is not the length its encryption type requires",
            })
        }
    }

    /// The long-term key for a password — [RFC 3962] §4 and [RFC 8009] §4.
    ///
    /// `salt` and `params` are what the KDC sent in `PA-ETYPE-INFO2` ([RFC 4120] §5.2.7.5); the
    /// salt is never guessed, because Active Directory's is not the [RFC 4120] default. `params`,
    /// when present, is the iteration count as four big-endian octets, where `00 00 00 00` means
    /// 2³² ([RFC 3962] §4).
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] if `params` is not four octets or asks for more than [`MAX_ITERATIONS`].
    pub(crate) fn from_password(
        enctype: Enctype,
        password: &str,
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Self> {
        let iterations = match params {
            None => enctype.default_iterations(),
            Some(&[a, b, c, d]) => u32::from_be_bytes([a, b, c, d]),
            Some(_) => {
                return Err(Error::Crypto {
                    usage: None,
                    reason: "string-to-key parameters that are not four octets",
                });
            }
        };
        if iterations == 0 || iterations > MAX_ITERATIONS {
            return Err(Error::Crypto {
                usage: None,
                reason: "a string-to-key iteration count above the limit this client will run",
            });
        }

        // [MS-KILE] §3.1.5.7: names are UTF-8 and not normalised, and the password is treated the
        // same way; `str` is already the one and the other is simply not done.
        let password = password.as_bytes();
        let bytes = match enctype.variant() {
            None => rfc3962::string_to_key(enctype.key_len(), password, salt, iterations),
            Some(variant) => rfc8009::string_to_key(variant, password, salt, iterations),
        }
        .map_err(|reason| Error::Crypto {
            usage: None,
            reason,
        })?;
        Ok(Self { enctype, bytes })
    }

    /// The encryption type.
    pub(crate) const fn enctype(&self) -> Enctype {
        self.enctype
    }

    /// The raw key, for the one place that needs to send it: a subkey inside an authenticator.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encrypts under a key usage ([RFC 4120] §7.5.1), with a confounder the caller supplies.
    ///
    /// The confounder is an input rather than drawn here because this crate has no randomness of
    /// its own: it is what makes the published vectors reproducible, and the caller is the one
    /// with an operating system to ask.
    pub(crate) fn encrypt(
        &self,
        usage: u32,
        confounder: &[u8; CONFOUNDER],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        match self.enctype.variant() {
            None => rfc3962::encrypt(&self.bytes, usage, confounder, plaintext),
            Some(variant) => rfc8009::encrypt(variant, &self.bytes, usage, confounder, plaintext),
        }
        .map_err(|reason| fault(usage, reason))
    }

    /// Decrypts and checks the integrity of something encrypted under a key usage.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] naming the usage, if it is malformed or its integrity check fails —
    /// which, for the reply to a password logon, is what a wrong password looks like.
    pub(crate) fn decrypt(&self, usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self.enctype.variant() {
            None => rfc3962::decrypt(&self.bytes, usage, ciphertext),
            Some(variant) => rfc8009::decrypt(variant, &self.bytes, usage, ciphertext),
        }
        .map_err(|reason| fault(usage, reason))
    }

    /// The keyed checksum of a message under a key usage.
    pub(crate) fn checksum(&self, usage: u32, message: &[u8]) -> Result<Vec<u8>> {
        match self.enctype.variant() {
            None => rfc3962::checksum(&self.bytes, usage, message),
            Some(variant) => rfc8009::checksum(variant, &self.bytes, usage, message),
        }
        .map_err(|reason| fault(usage, reason))
    }

    /// Whether `checksum` is this key's checksum of `message` under `usage`, compared in constant
    /// time.
    pub(crate) fn verify_checksum(
        &self,
        usage: u32,
        message: &[u8],
        checksum: &[u8],
    ) -> Result<()> {
        if constant_time_eq(&self.checksum(usage, message)?, checksum) {
            Ok(())
        } else {
            Err(fault(usage, "its checksum does not verify"))
        }
    }
}

fn fault(usage: u32, reason: Fault) -> Error {
    Error::Crypto {
        usage: Some(usage),
        reason,
    }
}

/// Equality that takes as long however early the inputs differ, for comparing MACs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Hex with any spacing, which is how every RFC prints its vectors.
    pub(crate) fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn the_four_types_round_trip_through_their_numbers() {
        for enctype in Enctype::PREFERENCE {
            assert_eq!(Enctype::from_number(enctype.number()), Some(enctype));
        }
        // RC4-HMAC (23) and the DES types are declined, not unknown by accident.
        for declined in [1, 3, 23, 0, -1] {
            assert_eq!(Enctype::from_number(declined), None);
        }
        assert_eq!(Enctype::Aes256Sha1.checksum_type(), 16);
        assert_eq!(Enctype::Aes256Sha384.key_len(), 32);
    }

    /// [RFC 3962] Appendix B's first vector, reached through the public constructor with the
    /// iteration count as a KDC would send it.
    #[test]
    fn a_password_key_takes_its_iterations_from_the_kdcs_parameters() {
        let key = Key::from_password(
            Enctype::Aes256Sha1,
            "password",
            b"ATHENA.MIT.EDUraeburn",
            Some(&[0, 0, 0, 1]),
        )
        .unwrap();
        assert_eq!(
            key.bytes(),
            hex("fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161")
        );
        assert_eq!(key.enctype(), Enctype::Aes256Sha1);
        assert!(
            !format!("{key:?}").contains("fe"),
            "Debug prints no key bytes"
        );
    }

    #[test]
    fn iteration_counts_a_kdc_should_not_ask_for_are_refused() {
        for params in [&[0u8, 0, 0, 0][..], &[0, 0x0F, 0x42, 0x41], &[0, 0, 1]] {
            assert!(
                Key::from_password(Enctype::Aes128Sha1, "p", b"s", Some(params)).is_err(),
                "{params:02X?}"
            );
        }
    }

    #[test]
    fn a_key_of_the_wrong_length_for_its_type_is_refused() {
        assert!(Key::new(Enctype::Aes256Sha1, vec![0; 16]).is_err());
        assert!(Key::new(Enctype::Aes128Sha256, vec![0; 16]).is_ok());
    }

    #[test]
    fn every_type_encrypts_decrypts_and_checksums_under_a_usage() {
        for enctype in Enctype::PREFERENCE {
            let key = Key::new(enctype, vec![0x42; enctype.key_len()]).unwrap();
            let sealed = key.encrypt(11, &[1; CONFOUNDER], b"authenticator").unwrap();
            assert_eq!(key.decrypt(11, &sealed).unwrap(), b"authenticator");

            let error = key.decrypt(12, &sealed).unwrap_err();
            assert!(
                matches!(
                    error,
                    Error::Crypto {
                        usage: Some(12),
                        ..
                    }
                ),
                "{enctype:?}: {error}"
            );

            let sum = key.checksum(6, b"body").unwrap();
            key.verify_checksum(6, b"body", &sum).unwrap();
            assert!(key.verify_checksum(6, b"bodY", &sum).is_err());
        }
    }
}
