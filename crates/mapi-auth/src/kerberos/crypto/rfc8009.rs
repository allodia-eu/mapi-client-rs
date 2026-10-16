//! The two SHA-2 AES encryption types: `aes128-cts-hmac-sha256-128` (19) and
//! `aes256-cts-hmac-sha384-192` (20).
//!
//! [RFC 8009] keeps [RFC 3962]'s cipher and changes everything around it: keys come from an
//! SP 800-108 KDF over HMAC-SHA2 rather than from `DK`, the salt is prefixed with the encryption
//! type's name, and the integrity check is computed over the ciphertext rather than the plaintext.
//! [MS-KILE] §3.1.5.2 makes both a MUST.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};

use super::cts::{self, BLOCK};
use super::{CONFOUNDER, Fault, constant_time_eq};

/// Which of the two, and so which hash and which lengths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Variant {
    /// `aes128-cts-hmac-sha256-128`.
    Sha256,
    /// `aes256-cts-hmac-sha384-192`.
    Sha384,
}

impl Variant {
    /// The name [RFC 8009] §4 prepends to the salt, so that the two types never share a base key.
    const fn name(self) -> &'static [u8] {
        match self {
            Self::Sha256 => b"aes128-cts-hmac-sha256-128",
            Self::Sha384 => b"aes256-cts-hmac-sha384-192",
        }
    }

    /// The AES key length in bytes — [RFC 8009] §4's `keylength`.
    const fn key_len(self) -> usize {
        match self {
            Self::Sha256 => 16,
            Self::Sha384 => 32,
        }
    }

    /// The truncated HMAC's length, which is also `Kc`'s and `Ki`'s — [RFC 8009] §5: 128 bits for
    /// SHA-256 and 192 for SHA-384.
    const fn h(self) -> usize {
        match self {
            Self::Sha256 => 16,
            Self::Sha384 => 24,
        }
    }

    fn hmac(self, key: &[u8], message: &[u8]) -> Result<Vec<u8>, Fault> {
        // HMAC accepts a key of any length; see the same note in `rfc3962`.
        Ok(match self {
            Self::Sha256 => {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(key).map_err(|_| "HMAC refused its key")?;
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha384 => {
                let mut mac =
                    Hmac::<Sha384>::new_from_slice(key).map_err(|_| "HMAC refused its key")?;
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
        })
    }
}

/// `KDF-HMAC-SHA2(key, label, k)` without a context — [RFC 8009] §3: `k-truncate(HMAC(key,
/// 0x00000001 | label | 0x00 | k))`, with `k` in bits as four big-endian octets.
fn kdf(variant: Variant, key: &[u8], label: &[u8], bytes: usize) -> Result<Vec<u8>, Fault> {
    let bits = u32::try_from(bytes.saturating_mul(8)).map_err(|_| "a derived key that long")?;
    let mut input = 1u32.to_be_bytes().to_vec();
    input.extend_from_slice(label);
    input.push(0);
    input.extend_from_slice(&bits.to_be_bytes());
    Ok(variant.hmac(key, &input)?.into_iter().take(bytes).collect())
}

/// [RFC 8009] §4: `saltp = enctype-name | 0x00 | salt`, PBKDF2 with the variant's HMAC-SHA2, then
/// `base-key = KDF-HMAC-SHA2(tkey, "kerberos", keylength)`.
pub(super) fn string_to_key(
    variant: Variant,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, Fault> {
    let mut saltp = variant.name().to_vec();
    saltp.push(0);
    saltp.extend_from_slice(salt);

    let mut tkey = vec![0u8; variant.key_len()];
    match variant {
        Variant::Sha256 => pbkdf2::pbkdf2_hmac::<Sha256>(password, &saltp, iterations, &mut tkey),
        Variant::Sha384 => pbkdf2::pbkdf2_hmac::<Sha384>(password, &saltp, iterations, &mut tkey),
    }
    kdf(variant, &tkey, b"kerberos", variant.key_len())
}

/// The three per-usage keys — [RFC 8009] §5: `Kc` and `Ki` are `h` long, `Ke` is the AES key
/// length.
fn derive(variant: Variant, base: &[u8], usage: u32, kind: u8) -> Result<Vec<u8>, Fault> {
    let mut label = usage.to_be_bytes().to_vec();
    label.push(kind);
    let len = if kind == 0xAA {
        variant.key_len()
    } else {
        variant.h()
    };
    kdf(variant, base, &label, len)
}

/// [RFC 8009] §5's encryption function: `C = E(Ke, N | plaintext, IV)`, `H = HMAC(Ki, IV | C)`,
/// `ciphertext = C | H[1..h]`, with the initial cipher state of zero.
pub(super) fn encrypt(
    variant: Variant,
    base: &[u8],
    usage: u32,
    confounder: &[u8; CONFOUNDER],
    plaintext: &[u8],
) -> Result<Vec<u8>, Fault> {
    let ke = derive(variant, base, usage, 0xAA)?;
    let ki = derive(variant, base, usage, 0x55)?;
    let mut data = confounder.to_vec();
    data.extend_from_slice(plaintext);

    let mut out = cts::encrypt(&ke, &data)?;
    let mut signed = vec![0u8; BLOCK];
    signed.extend_from_slice(&out);
    out.extend(variant.hmac(&ki, &signed)?.into_iter().take(variant.h()));
    Ok(out)
}

/// [RFC 8009] §5's decryption function, which checks the HMAC **before** decrypting — the order
/// the document gives, and the one that never runs AES over a forgery.
pub(super) fn decrypt(
    variant: Variant,
    base: &[u8],
    usage: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Fault> {
    let ke = derive(variant, base, usage, 0xAA)?;
    let ki = derive(variant, base, usage, 0x55)?;
    let split = ciphertext
        .len()
        .checked_sub(variant.h())
        .ok_or("shorter than its integrity check")?;
    let (body, mac) = ciphertext
        .split_at_checked(split)
        .ok_or("shorter than its integrity check")?;

    let mut signed = vec![0u8; BLOCK];
    signed.extend_from_slice(body);
    let expected = variant.hmac(&ki, &signed)?;
    if !constant_time_eq(expected.get(..variant.h()).unwrap_or_default(), mac) {
        return Err("its integrity check failed, which is what the wrong key looks like");
    }
    let plain = cts::decrypt(&ke, body)?;
    Ok(plain.get(CONFOUNDER..).unwrap_or_default().to_vec())
}

/// [RFC 8009] §6's `get_mic`: `HMAC(Kc, message)[1..h]`.
pub(super) fn checksum(
    variant: Variant,
    base: &[u8],
    usage: u32,
    message: &[u8],
) -> Result<Vec<u8>, Fault> {
    let kc = derive(variant, base, usage, 0x99)?;
    Ok(variant
        .hmac(&kc, message)?
        .into_iter()
        .take(variant.h())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::super::tests::hex;
    use super::*;

    /// The salt [RFC 8009] Appendix A uses: sixteen random bytes that happen to be valid UTF-8,
    /// then the realm and principal.
    fn appendix_salt() -> Vec<u8> {
        let mut salt = hex("10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61");
        salt.extend_from_slice(b"ATHENA.MIT.EDUraeburn");
        salt
    }

    const BASE_128: &str = "37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C";
    const BASE_256: &str = "6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98 \
                            00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52";

    #[test]
    fn string_to_key_matches_appendix_a() {
        assert_eq!(
            string_to_key(Variant::Sha256, b"password", &appendix_salt(), 32768).unwrap(),
            hex("08 9B CA 48 B1 05 EA 6E A7 7C A5 D2 F3 9D C5 E7")
        );
        assert_eq!(
            string_to_key(Variant::Sha384, b"password", &appendix_salt(), 32768).unwrap(),
            hex("45 BD 80 6D BF 6A 83 3A 9C FF C1 C9 45 89 A2 22 \
                 36 7A 79 BC 21 C4 13 71 89 06 E9 F5 78 A7 84 67")
        );
    }

    #[test]
    fn key_derivation_matches_appendix_a() {
        let cases = [
            (
                Variant::Sha256,
                BASE_128,
                "B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3",
                "9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E",
                "9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C",
            ),
            (
                Variant::Sha384,
                BASE_256,
                "EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4 BA 41 F2 8F AF 69 E7 3D",
                "56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 \
                 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49",
                "69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F",
            ),
        ];
        for (variant, base, kc, ke, ki) in cases {
            let base = hex(base);
            assert_eq!(
                derive(variant, &base, 2, 0x99).unwrap(),
                hex(kc),
                "{variant:?} Kc"
            );
            assert_eq!(
                derive(variant, &base, 2, 0xAA).unwrap(),
                hex(ke),
                "{variant:?} Ke"
            );
            assert_eq!(
                derive(variant, &base, 2, 0x55).unwrap(),
                hex(ki),
                "{variant:?} Ki"
            );
        }
    }

    /// Every sample encryption in [RFC 8009] Appendix A — empty, shorter than a block, exactly a
    /// block and longer than one, at both sizes — all under key usage 2.
    #[test]
    fn encryption_matches_appendix_a() {
        let plaintexts = [
            "",
            "00 01 02 03 04 05",
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14",
        ];
        let sha256 = [
            (
                "7E 58 95 EA F2 67 24 35 BA D8 17 F5 45 A3 71 48",
                "EF 85 FB 89 0B B8 47 2F 4D AB 20 39 4D CA 78 1D \
                 AD 87 7E DA 39 D5 0C 87 0C 0D 5A 0A 8E 48 C7 18",
            ),
            (
                "7B CA 28 5E 2F D4 13 0F B5 5B 1A 5C 83 BC 5B 24",
                "84 D7 F3 07 54 ED 98 7B AB 0B F3 50 6B EB 09 CF B5 54 02 CE F7 E6 \
                 87 7C E9 9E 24 7E 52 D1 6E D4 42 1D FD F8 97 6C",
            ),
            (
                "56 AB 21 71 3F F6 2C 0A 14 57 20 0F 6F A9 94 8F",
                "35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A \
                 E0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2 \
                 95 FB 48 52 E7 D8 3E 1E 7C 48 C3 7E EB E6 B0 D3",
            ),
            (
                "A7 A4 E2 9A 47 28 CE 10 66 4F B6 4E 49 AD 3F AC",
                "72 0F 73 B1 8D 98 59 CD 6C CB 43 46 11 5C D3 36 \
                 C7 0F 58 ED C0 C4 43 7C 55 73 54 4C 31 C8 13 BC E1 E6 D0 72 C1 \
                 86 B3 9A 41 3C 2F 92 CA 9B 83 34 A2 87 FF CB FC",
            ),
        ];
        let sha384 = [
            (
                "F7 64 E9 FA 15 C2 76 47 8B 2C 7D 0C 4E 5F 58 E4",
                "41 F5 3F A5 BF E7 02 6D 91 FA F9 BE 95 91 95 A0 \
                 58 70 72 73 A9 6A 40 F0 A0 19 60 62 1A C6 12 74 8B 9B BF BE 7E B4 CE 3C",
            ),
            (
                "B8 0D 32 51 C1 F6 47 14 94 25 6F FE 71 2D 0B 9A",
                "4E D7 B3 7C 2B CA C8 F7 4F 23 C1 CF 07 E6 2B C7 B7 5F B3 F6 37 B9 \
                 F5 59 C7 F6 64 F6 9E AB 7B 60 92 23 75 26 EA 0D 1F 61 CB 20 D6 9D 10 F2",
            ),
            (
                "53 BF 8A 0D 10 52 65 D4 E2 76 42 86 24 CE 5E 63",
                "BC 47 FF EC 79 98 EB 91 E8 11 5C F8 D1 9D AC 4B \
                 BB E2 E1 63 E8 7D D3 7F 49 BE CA 92 02 77 64 F6 \
                 8C F5 1F 14 D7 98 C2 27 3F 35 DF 57 4D 1F 93 2E 40 C4 FF 25 5B 36 A2 66",
            ),
            (
                "76 3E 65 36 7E 86 4F 02 F5 51 53 C7 E3 B5 8A F1",
                "40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE \
                 10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2 B2 A6 02 AC 86 \
                 FE F6 EC B6 47 D6 29 5F AE 07 7A 1F EB 51 75 08 D2 C1 6B 41 92 E0 1F 62",
            ),
        ];

        for (variant, base, samples) in [
            (Variant::Sha256, BASE_128, sha256),
            (Variant::Sha384, BASE_256, sha384),
        ] {
            let base = hex(base);
            for (plaintext, (confounder, ciphertext)) in plaintexts.iter().zip(samples) {
                let plaintext = hex(plaintext);
                let confounder: [u8; CONFOUNDER] = hex(confounder).try_into().unwrap();
                let sealed = encrypt(variant, &base, 2, &confounder, &plaintext).unwrap();
                assert_eq!(
                    sealed,
                    hex(ciphertext),
                    "{variant:?}, {} bytes",
                    plaintext.len()
                );
                assert_eq!(decrypt(variant, &base, 2, &sealed).unwrap(), plaintext);

                let mut forged = sealed.clone();
                *forged.last_mut().unwrap() ^= 1;
                assert!(decrypt(variant, &base, 2, &forged).is_err());
            }
        }
    }

    #[test]
    fn checksums_match_appendix_a() {
        let message = hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14");
        assert_eq!(
            checksum(Variant::Sha256, &hex(BASE_128), 2, &message).unwrap(),
            hex("D7 83 67 18 66 43 D6 7B 41 1C BA 91 39 FC 1D EE")
        );
        assert_eq!(
            checksum(Variant::Sha384, &hex(BASE_256), 2, &message).unwrap(),
            hex("45 EE 79 15 67 EE FC A3 7F 4A C1 E0 22 2D E8 0D 43 C3 BF A0 66 99 67 2A")
        );
    }

    #[test]
    fn a_ciphertext_shorter_than_its_mac_is_refused() {
        assert!(decrypt(Variant::Sha384, &hex(BASE_256), 2, &[0; 23]).is_err());
    }
}
