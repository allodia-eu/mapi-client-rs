//! Binding a handshake to the TLS connection it runs over.
//!
//! An NTLM exchange proves knowledge of a password and says nothing about *where* it was proved.
//! A relay that sits between a client and a server can therefore pass the three messages through
//! unchanged and end up authenticated as the client. A channel binding closes that: the client
//! hashes something unique to its own TLS connection into the `AUTHENTICATE_MESSAGE`, so a message
//! replayed onto a different connection no longer matches.
//!
//! Microsoft calls the feature **Extended Protection for Authentication**, and IIS has three
//! settings for it — `None`, `Allow` and `Require`. Under `Require` an `AUTHENTICATE_MESSAGE`
//! without a matching binding is refused, and the refusal looks exactly like a wrong password,
//! which is what makes this worth getting right rather than leaving to be discovered.
//!
//! [MS-NLMP] §3.1.5.1.2 — `MsvAvChannelBindings`, set to `MD5_HASH(ClientChannelBindingsUnhashed)`

use crate::crypto::{self, CertificateHash};
use crate::der::{self, Reader};

/// The prefix [RFC 5929] §4.1 puts in front of the certificate hash.
const PREFIX: &[u8] = b"tls-server-end-point:";

/// A channel binding, already reduced to the sixteen bytes that go on the wire.
///
/// Build one with [`ChannelBinding::tls_server_end_point`] from the server certificate the TLS
/// handshake presented. [`ChannelBinding::unbound`] is the all-zero value Windows sends when it has
/// no binding to offer, which a server set to `Require` refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelBinding {
    hash: crypto::Digest128,
}

impl ChannelBinding {
    /// The binding for a TLS connection whose server presented `certificate_der`.
    ///
    /// The certificate is the end-entity one — what the peer sent, not a CA above it — in DER.
    /// `reqwest` hands it over as `TlsInfo::peer_certificate()`.
    ///
    /// The hash is chosen from the certificate's own signature algorithm, per [RFC 5929] §4.1, so
    /// that the binding is never weaker than the connection: SHA-256, SHA-384 or SHA-512, with
    /// MD5 and SHA-1 promoted to SHA-256. A certificate whose algorithm is not recognised — or
    /// one this cannot parse at all — is hashed with SHA-256, which is both the overwhelmingly
    /// common answer and the safe guess, since a wrong guess costs a refused handshake rather than
    /// a weakened one.
    #[must_use]
    pub fn tls_server_end_point(certificate_der: &[u8]) -> Self {
        let digest = signature_hash(certificate_der).digest(certificate_der);

        let mut application_data = Vec::with_capacity(PREFIX.len().saturating_add(digest.len()));
        application_data.extend_from_slice(PREFIX);
        application_data.extend_from_slice(&digest);

        Self {
            hash: crypto::md5(&gss_channel_bindings(&application_data)),
        }
    }

    /// The all-zero binding, which says "this client has none".
    ///
    /// [MS-NLMP] §3.1.5.1.2 spells this out: with no unhashed binding available the client still
    /// adds the AV pair, with `Z(16)` as its value. Sending the pair rather than omitting it is
    /// what lets a server distinguish a client that cannot bind from one that did not try.
    #[must_use]
    pub const fn unbound() -> Self {
        Self { hash: [0; 16] }
    }

    /// The sixteen bytes that go into NTLM's `MsvAvChannelBindings` AV pair and Kerberos's `Bnd`
    /// field — [RFC 4121] §4.1.1.2 hashes the same structure the same way.
    pub(crate) const fn as_bytes(&self) -> &crypto::Digest128 {
        &self.hash
    }

    /// Whether there is a binding at all, rather than the all-zero "none".
    ///
    /// Kerberos says so separately: [MS-KILE] §3.2.5.8 has a client that binds also send
    /// `KERB_AP_OPTIONS_CBT`, and one that does not, not.
    pub(crate) fn is_bound(&self) -> bool {
        self.hash != [0; 16]
    }
}

impl Default for ChannelBinding {
    /// [`ChannelBinding::unbound`].
    fn default() -> Self {
        Self::unbound()
    }
}

/// Serialises a `gss_channel_bindings_struct` with only its application data filled in.
///
/// [RFC 2744] §3.11 gives the structure; the two address fields are left empty because the
/// `tls-server-end-point` binding type carries everything it needs in the application data, and
/// because an address that differed between the two ends would break a binding that is supposed to
/// be about the certificate. Every length is little-endian: [RFC 4121] §4.1.1.2 says so for the
/// Kerberos `Bnd` field ("each integer field and input length field SHALL be formatted into four
/// octets, using little-endian octet ordering"), and NTLM's binding is the same hash of the same
/// structure.
fn gss_channel_bindings(application_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(application_data.len().saturating_add(20));
    // initiator_addrtype, initiator_address.length, acceptor_addrtype, acceptor_address.length
    out.extend_from_slice(&[0; 16]);
    let len = u32::try_from(application_data.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(application_data);
    out
}

/// Reads the signature algorithm out of a certificate and maps it to the hash [RFC 5929] wants.
///
/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }` ([RFC 5280]
/// §4.1), so this skips the first element and reads the OID out of the second.
fn signature_hash(certificate_der: &[u8]) -> CertificateHash {
    let Ok(mut certificate) =
        Reader::new("certificate", certificate_der).expect_nested(der::SEQUENCE, "")
    else {
        return CertificateHash::Sha256;
    };
    // tbsCertificate, which is skipped rather than parsed.
    if certificate.read().is_err() {
        return CertificateHash::Sha256;
    }
    let Ok(mut algorithm) = certificate.expect_nested(der::SEQUENCE, "") else {
        return CertificateHash::Sha256;
    };
    let Ok(oid) = algorithm.expect(der::OID, "") else {
        return CertificateHash::Sha256;
    };

    match oid {
        // sha384WithRSAEncryption 1.2.840.113549.1.1.12, ecdsa-with-SHA384 1.2.840.10045.4.3.3
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C]
        | [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03] => CertificateHash::Sha384,
        // sha512WithRSAEncryption 1.2.840.113549.1.1.13, ecdsa-with-SHA512 1.2.840.10045.4.3.4
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D]
        | [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04] => CertificateHash::Sha512,
        // id-RSASSA-PSS 1.2.840.113549.1.1.10, whose hash is in its parameters, not its OID.
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A] => pss_hash(&mut algorithm),
        // Everything else, including SHA-256, SHA-1 and MD5, which [RFC 5929] §4.1 promotes.
        _ => CertificateHash::Sha256,
    }
}

/// The hash an RSASSA-PSS signature names in its parameters.
///
/// [RFC 4055] §3.1 — `RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0] HashAlgorithm DEFAULT
/// sha1, … }`. An absent or unreadable `hashAlgorithm` is SHA-1 by that default, which
/// [RFC 5929] §4.1 promotes to SHA-256 like any other.
fn pss_hash(algorithm: &mut Reader<'_>) -> CertificateHash {
    let hash = algorithm
        .expect_nested(der::SEQUENCE, "")
        .and_then(|mut params| params.expect_nested(der::context(0), ""))
        .and_then(|mut tagged| tagged.expect_nested(der::SEQUENCE, ""))
        .and_then(|mut identifier| identifier.expect(der::OID, "").map(<[u8]>::to_vec));

    match hash.as_deref() {
        // id-sha384 2.16.840.1.101.3.4.2.2
        Ok([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]) => CertificateHash::Sha384,
        // id-sha512 2.16.840.1.101.3.4.2.3
        Ok([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]) => CertificateHash::Sha512,
        _ => CertificateHash::Sha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the outer shape of a certificate: enough for the algorithm to be found, and nothing
    /// more, because that is all this reads.
    fn certificate_signed_with(oid: &[u8]) -> Vec<u8> {
        let tbs = der::tlv(der::SEQUENCE, &[0x02, 0x01, 0x01]);
        let algorithm = der::tlv(der::SEQUENCE, &der::tlv(der::OID, oid));
        der::tlv(der::SEQUENCE, &[tbs, algorithm].concat())
    }

    #[test]
    fn the_hash_follows_the_certificates_own_signature_algorithm() {
        let cases = [
            (
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B][..],
                CertificateHash::Sha256,
            ),
            (
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C][..],
                CertificateHash::Sha384,
            ),
            (
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D][..],
                CertificateHash::Sha512,
            ),
            (
                &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03][..],
                CertificateHash::Sha384,
            ),
            (
                &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04][..],
                CertificateHash::Sha512,
            ),
            // sha1WithRSAEncryption, which [RFC 5929] §4.1 promotes to SHA-256 rather than using.
            (
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05][..],
                CertificateHash::Sha256,
            ),
        ];
        for (oid, expected) in cases {
            assert_eq!(
                signature_hash(&certificate_signed_with(oid)),
                expected,
                "{oid:02X?}"
            );
        }
    }

    /// RSASSA-PSS names its hash in its parameters, so the OID alone says nothing about it.
    #[test]
    fn a_pss_signature_is_hashed_with_the_hash_its_parameters_name() {
        const PSS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
        let signed = |hash: Option<&[u8]>| {
            let params = hash.map_or_else(Vec::new, |oid| {
                der::tlv(
                    der::context(0),
                    &der::tlv(der::SEQUENCE, &der::tlv(der::OID, oid)),
                )
            });
            let algorithm = der::tlv(
                der::SEQUENCE,
                &[der::tlv(der::OID, PSS), der::tlv(der::SEQUENCE, &params)].concat(),
            );
            let tbs = der::tlv(der::SEQUENCE, &[0x02, 0x01, 0x01]);
            der::tlv(der::SEQUENCE, &[tbs, algorithm].concat())
        };

        let sha384 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
        let sha512 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
        let sha256 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        assert_eq!(
            signature_hash(&signed(Some(&sha384))),
            CertificateHash::Sha384
        );
        assert_eq!(
            signature_hash(&signed(Some(&sha512))),
            CertificateHash::Sha512
        );
        assert_eq!(
            signature_hash(&signed(Some(&sha256))),
            CertificateHash::Sha256
        );
        // The DEFAULT, SHA-1, promoted.
        assert_eq!(signature_hash(&signed(None)), CertificateHash::Sha256);
        assert_eq!(
            signature_hash(&certificate_signed_with(PSS)),
            CertificateHash::Sha256
        );
    }

    /// A certificate this cannot read is hashed with SHA-256 rather than refused: the cost of
    /// guessing wrong is a handshake the server declines, and there is nothing better to do with
    /// bytes that are not a certificate.
    #[test]
    fn an_unreadable_certificate_falls_back_to_sha256() {
        for der in [
            vec![],
            vec![0x30, 0x02, 0x05, 0x00], // a sequence with no algorithm
            vec![0x30, 0x04, 0x30, 0x00, 0x05, 0x00], // an algorithm that is not a sequence
            vec![0x30, 0x06, 0x30, 0x00, 0x30, 0x02, 0x05, 0x00], // a sequence with no OID
            b"not a certificate at all".to_vec(),
        ] {
            assert_eq!(signature_hash(&der), CertificateHash::Sha256, "{der:02X?}");
        }
    }

    /// The structure the server hashes too, laid out byte for byte: five little-endian lengths,
    /// four of them zero, then the prefixed digest.
    #[test]
    fn the_bindings_structure_is_four_empty_addresses_and_the_application_data() {
        let encoded = gss_channel_bindings(b"tls-server-end-point:AB");
        assert_eq!(encoded.len(), 20 + 23);
        assert_eq!(encoded[0..16], [0; 16]);
        assert_eq!(encoded[16..20], 23u32.to_le_bytes());
        assert_eq!(&encoded[20..], b"tls-server-end-point:AB");
    }

    #[test]
    fn a_binding_is_the_md5_of_that_structure() {
        let certificate =
            certificate_signed_with(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]);
        let binding = ChannelBinding::tls_server_end_point(&certificate);

        let expected = {
            let digest = CertificateHash::Sha256.digest(&certificate);
            let mut data = PREFIX.to_vec();
            data.extend_from_slice(&digest);
            crypto::md5(&gss_channel_bindings(&data))
        };
        assert_eq!(binding.as_bytes(), &expected);

        // Different certificate, different binding — the property the whole feature rests on.
        let other = certificate_signed_with(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]);
        assert_ne!(ChannelBinding::tls_server_end_point(&other), binding);
    }

    #[test]
    fn an_unbound_binding_is_sixteen_zero_bytes() {
        assert_eq!(ChannelBinding::unbound().as_bytes(), &[0; 16]);
        assert_eq!(ChannelBinding::default(), ChannelBinding::unbound());
        assert_ne!(
            ChannelBinding::tls_server_end_point(b"anything"),
            ChannelBinding::unbound()
        );
        assert!(!ChannelBinding::unbound().is_bound());
        assert!(ChannelBinding::tls_server_end_point(b"certificate").is_bound());
    }
}
