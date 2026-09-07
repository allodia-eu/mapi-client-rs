//! The four hashes NTLM v2 is built out of, and the string encoding they consume.
//!
//! Nothing here makes a choice: every function is named by [MS-NLMP] §3.3.2 or by the channel
//! binding rule in [RFC 5929] §4.1, and exists so that the code computing a response reads like the
//! pseudocode it implements.
//!
//! MD4 and MD5 are both long broken as hashes. They are not a choice either — NTLM specifies them,
//! and a client that substituted something stronger would not authenticate. What protects the
//! password on the wire is TLS, which is why `mapi-client` refuses a plaintext endpoint.

use hmac::digest::KeyInit;
use hmac::digest::generic_array::GenericArray;
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::{Digest, Md5};
use sha2::{Sha256, Sha384, Sha512};

/// A 128-bit digest, which is what every NTLM key and proof string is.
pub(crate) type Digest128 = [u8; 16];

/// MD5's block size, which is the one key length HMAC uses exactly as it is given.
const HMAC_BLOCK: usize = 64;

/// UTF-16LE, which [MS-NLMP] calls `UNICODE()`.
///
/// [MS-NLMP] §6 — `UNICODE(string)`: the string in two-byte little-endian characters
pub(crate) fn unicode(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len().saturating_mul(2));
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// MD4, which NTLM uses for the NT hash of a password and for nothing else.
///
/// [MS-NLMP] §3.3.2 — `MD4(UNICODE(Passwd))`
pub(crate) fn md4(bytes: &[u8]) -> Digest128 {
    Md4::digest(bytes).into()
}

/// MD5.
///
/// [MS-NLMP] §3.1.5.1.2 — `MD5_HASH(ClientChannelBindingsUnhashed)`
pub(crate) fn md5(bytes: &[u8]) -> Digest128 {
    Md5::digest(bytes).into()
}

/// HMAC-MD5, which every NTLM v2 key derivation is an application of.
///
/// [MS-NLMP] §3.3.2 — `HMAC_MD5(key, message)`
pub(crate) fn hmac_md5(key: &[u8], message: &[u8]) -> Digest128 {
    // RFC 2104's key preparation, done here rather than inside the constructor. It is the same
    // rule either way — hash a key longer than the block, then zero-pad to the block — but doing
    // it explicitly means the key handed over is always exactly one block, which is the length
    // `KeyInit::new` takes infallibly. The alternative is the fallible constructor and a branch
    // for a failure that cannot happen, which is a worse thing to have in a crypto path than four
    // lines of padding.
    let mut block = [0u8; HMAC_BLOCK];
    let shortened;
    let source = if key.len() > HMAC_BLOCK {
        shortened = md5(key);
        &shortened[..]
    } else {
        key
    };
    for (slot, byte) in block.iter_mut().zip(source.iter()) {
        *slot = *byte;
    }

    let mut mac = <Hmac<Md5> as KeyInit>::new(GenericArray::from_slice(&block));
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// The response key both NTLM v2 responses are derived from.
///
/// The user name is folded to upper case and the domain is not. That asymmetry is the
/// specification's, and it is the reason [`Identity`](crate::Identity) splits a name rather than
/// carrying it whole: both halves are inputs to this key, so splitting `DOMAIN\user` wrongly
/// produces a well-formed message that authenticates as nobody.
///
/// [MS-NLMP] §3.3.2 — `NTOWFv2(Passwd, User, UserDom)`
pub(crate) fn ntowf_v2(password: &str, user: &str, domain: &str) -> Digest128 {
    let key = md4(&unicode(password));
    let identity = unicode(&format!("{}{domain}", user.to_uppercase()));
    hmac_md5(&key, &identity)
}

/// Which hash a `tls-server-end-point` channel binding uses for a given certificate.
///
/// [RFC 5929] §4.1 — the certificate's own signature hash, except that MD5 and SHA-1 are replaced
/// by SHA-256. The rule exists so the binding is not weaker than the connection it binds, and it
/// is why this cannot simply always be SHA-256: a certificate signed with SHA-384 must be hashed
/// with SHA-384 or the server computes a different value and the handshake fails with an error
/// about credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CertificateHash {
    /// SHA-256, and the substitute for MD5 and SHA-1.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl CertificateHash {
    /// Hashes the certificate's DER.
    pub(crate) fn digest(self, der: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(der).to_vec(),
            Self::Sha384 => Sha384::digest(der).to_vec(),
            Self::Sha512 => Sha512::digest(der).to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [MS-NLMP] §4.2.1 and §4.2.4.1.1 — the published values, which is the only way to know that
    /// the upper-casing applies to the user and not to the domain.
    #[test]
    fn ntowf_v2_matches_the_published_test_vector() {
        assert_eq!(
            ntowf_v2("Password", "User", "Domain"),
            [
                0x0C, 0x86, 0x8A, 0x40, 0x3B, 0xFD, 0x7A, 0x93, 0xA3, 0x00, 0x1E, 0xF2, 0x2E, 0xF0,
                0x2E, 0x3F,
            ]
        );

        // Folding the domain too would change the key, which is exactly the bug this pins.
        assert_ne!(
            ntowf_v2("Password", "User", "DOMAIN"),
            ntowf_v2("Password", "User", "Domain")
        );
        // Folding the user does not, because the specification folds it first.
        assert_eq!(
            ntowf_v2("Password", "user", "Domain"),
            ntowf_v2("Password", "USER", "Domain")
        );
    }

    /// [MS-NLMP] §4.2.1 — `Passwd` and `User` as the document prints them.
    #[test]
    fn unicode_is_utf16_little_endian() {
        assert_eq!(unicode("User"), b"U\0s\0e\0r\0");
        assert_eq!(unicode(""), Vec::<u8>::new());
        // Outside the basic multilingual plane, which is two code units rather than one.
        assert_eq!(unicode("\u{1F600}"), vec![0x3D, 0xD8, 0x00, 0xDE]);
    }

    /// RFC 1320 §A.5 and RFC 1321 §A.5 print these; NTLM's NT hash is the first of them.
    #[test]
    fn the_hashes_are_the_hashes_they_claim_to_be() {
        assert_eq!(
            md4(b"abc"),
            [
                0xA4, 0x48, 0x01, 0x7A, 0xAF, 0x21, 0xD8, 0x52, 0x5F, 0xC1, 0x0A, 0xE8, 0x7A, 0xA6,
                0x72, 0x9D,
            ]
        );
        assert_eq!(
            md5(b"abc"),
            [
                0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0, 0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1,
                0x7F, 0x72,
            ]
        );
    }

    /// RFC 2202 §2, test case 1.
    #[test]
    fn hmac_md5_matches_its_own_published_vector() {
        assert_eq!(
            hmac_md5(&[0x0B; 16], b"Hi There"),
            [
                0x92, 0x94, 0x72, 0x7A, 0x36, 0x38, 0xBB, 0x1C, 0x13, 0xF4, 0x8E, 0xF8, 0x15, 0x8B,
                0xFC, 0x9D,
            ]
        );
        // A key longer than the block size is pre-hashed rather than refused.
        assert_eq!(hmac_md5(&[0xAA; 80], b"x").len(), 16);
        assert_eq!(hmac_md5(&[], b"x").len(), 16);
    }

    #[test]
    fn each_certificate_hash_produces_its_own_length() {
        assert_eq!(CertificateHash::Sha256.digest(b"cert").len(), 32);
        assert_eq!(CertificateHash::Sha384.digest(b"cert").len(), 48);
        assert_eq!(CertificateHash::Sha512.digest(b"cert").len(), 64);
        assert_ne!(CertificateHash::Sha256, CertificateHash::Sha384);
    }
}
