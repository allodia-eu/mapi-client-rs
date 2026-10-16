//! The two SHA-1 AES encryption types: `aes128-cts-hmac-sha1-96` (17) and `aes256-cts-hmac-sha1-96`
//! (18).
//!
//! [RFC 3962] defines them as instances of [RFC 3961] §5.3's simplified profile: three keys derived
//! from the base key by `DK`, AES-CTS for the encryption, and HMAC-SHA1 truncated to 96 bits for
//! both the integrity check and the checksum.

use hmac::{Hmac, Mac};
use sha1::Sha1;

use super::cts::{self, BLOCK, Block};
use super::nfold::nfold;
use super::{CONFOUNDER, Fault, constant_time_eq};

/// The truncated HMAC's length — [RFC 3962] §6: "HMAC output size, h — 12 octets (96 bits)".
const H: usize = 12;

/// `tkey = random2key(PBKDF2(passphrase, salt, iter_count, keylength)); key = DK(tkey,
/// "kerberos")` — [RFC 3962] §4, with HMAC-SHA1 as PBKDF2's pseudorandom function.
pub(super) fn string_to_key(
    key_len: usize,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, Fault> {
    let mut tkey = vec![0u8; key_len];
    pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, iterations, &mut tkey);
    dk(&tkey, b"kerberos")
}

/// `DK(Key, Constant) = random-to-key(DR(Key, Constant))` — [RFC 3961] §5.1.
///
/// `DR` encrypts the constant, `n-folded` to a block, and keeps encrypting its own output until
/// there are enough bits for a key; `random-to-key` is the identity for AES ([RFC 3962] §6).
pub(super) fn dk(key: &[u8], constant: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut block: Block = [0; BLOCK];
    for (slot, byte) in block.iter_mut().zip(nfold(constant, BLOCK)) {
        *slot = byte;
    }
    let mut out = Vec::with_capacity(key.len().saturating_add(BLOCK));
    while out.len() < key.len() {
        block = cts::encrypt_block(key, block)?;
        out.extend_from_slice(&block);
    }
    out.truncate(key.len());
    Ok(out)
}

/// One of the three per-usage keys — [RFC 3961] §5.3: the usage number as four big-endian octets,
/// followed by `0x99` for `Kc`, `0xAA` for `Ke` or `0x55` for `Ki`.
fn derive(base: &[u8], usage: u32, kind: u8) -> Result<Vec<u8>, Fault> {
    let mut constant = usage.to_be_bytes().to_vec();
    constant.push(kind);
    dk(base, &constant)
}

/// [RFC 3961] §5.3's encryption function: `ciphertext = E(Ke, conf | plaintext) | HMAC(Ki, conf |
/// plaintext)[1..h]`. The message block size is one octet ([RFC 3962] §6), so there is no padding.
pub(super) fn encrypt(
    base: &[u8],
    usage: u32,
    confounder: &[u8; CONFOUNDER],
    plaintext: &[u8],
) -> Result<Vec<u8>, Fault> {
    let ke = derive(base, usage, 0xAA)?;
    let ki = derive(base, usage, 0x55)?;
    let mut data = confounder.to_vec();
    data.extend_from_slice(plaintext);

    let mut out = cts::encrypt(&ke, &data)?;
    out.extend(hmac(&ki, &data)?.into_iter().take(H));
    Ok(out)
}

/// [RFC 3961] §5.3's decryption function: decrypt, then check the HMAC over what came out, then
/// drop the confounder.
pub(super) fn decrypt(base: &[u8], usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>, Fault> {
    let ke = derive(base, usage, 0xAA)?;
    let ki = derive(base, usage, 0x55)?;
    let split = ciphertext
        .len()
        .checked_sub(H)
        .ok_or("shorter than its integrity check")?;
    let (body, mac) = ciphertext
        .split_at_checked(split)
        .ok_or("shorter than its integrity check")?;

    let plain = cts::decrypt(&ke, body)?;
    let expected = hmac(&ki, &plain)?;
    if !constant_time_eq(expected.get(..H).unwrap_or_default(), mac) {
        return Err("its integrity check failed, which is what the wrong key looks like");
    }
    Ok(plain.get(CONFOUNDER..).unwrap_or_default().to_vec())
}

/// [RFC 3961] §5.4's `get_mic`: `HMAC(Kc, message)[1..h]`.
pub(super) fn checksum(base: &[u8], usage: u32, message: &[u8]) -> Result<Vec<u8>, Fault> {
    let kc = derive(base, usage, 0x99)?;
    Ok(hmac(&kc, message)?.into_iter().take(H).collect())
}

fn hmac(key: &[u8], message: &[u8]) -> Result<Vec<u8>, Fault> {
    // HMAC accepts a key of any length, so this cannot fail; the error is mapped rather than
    // unwrapped because a panic in a crypto path is worse than an error nobody will see.
    let mut mac = Hmac::<Sha1>::new_from_slice(key).map_err(|_| "HMAC refused its key")?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::super::tests::hex;
    use super::*;

    /// Password, salt, iterations, then the AES-128 and AES-256 keys the appendix prints.
    type Vector<'a> = (&'a [u8], &'a [u8], u32, &'a str, &'a str);

    /// [RFC 3962] Appendix B, every string-to-key vector at both key sizes. The printed "AES key"
    /// is the key after `DK(tkey, "kerberos")`, so each case covers PBKDF2, `n-fold` and `DR`
    /// together.
    #[test]
    fn every_published_string_to_key_vector() {
        let x64 = "X".repeat(64);
        let x65 = "X".repeat(65);
        let cases: [Vector<'_>; 7] = [
            (
                b"password",
                b"ATHENA.MIT.EDUraeburn",
                1,
                "42263c6e89f4fc28b8df68ee09799f15",
                "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
            ),
            (
                b"password",
                b"ATHENA.MIT.EDUraeburn",
                2,
                "c651bf29e2300ac27fa469d693bdda13",
                "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff",
            ),
            (
                b"password",
                b"ATHENA.MIT.EDUraeburn",
                1200,
                "4c01cd46d632d01e6dbe230a01ed642a",
                "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a",
            ),
            (
                b"password",
                &[0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12],
                5,
                "e9b23d52273747dd5c35cb55be619d8e",
                "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31",
            ),
            (
                x64.as_bytes(),
                b"pass phrase equals block size",
                1200,
                "59d1bb789a828b1aa54ef9c2883f69ed",
                "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34",
            ),
            (
                x65.as_bytes(),
                b"pass phrase exceeds block size",
                1200,
                "cb8005dc5f90179a7f02104c0018751d",
                "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b",
            ),
            (
                "\u{1D11E}".as_bytes(),
                b"EXAMPLE.COMpianist",
                50,
                "f149c1f2e154a73452d43e7fe62a56e5",
                "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e",
            ),
        ];
        for (password, salt, iterations, aes128, aes256) in cases {
            assert_eq!(
                string_to_key(16, password, salt, iterations).unwrap(),
                hex(aes128),
                "AES-128, {iterations} iterations"
            );
            assert_eq!(
                string_to_key(32, password, salt, iterations).unwrap(),
                hex(aes256),
                "AES-256, {iterations} iterations"
            );
        }
    }

    #[test]
    fn what_is_encrypted_decrypts_and_what_is_altered_does_not() {
        for key in [vec![0x11u8; 16], vec![0x22u8; 32]] {
            for len in [0, 1, 15, 16, 17, 100] {
                let plaintext: Vec<u8> = (0..len).map(|n| u8::try_from(n).unwrap()).collect();
                let sealed = encrypt(&key, 3, &[0x5A; CONFOUNDER], &plaintext).unwrap();
                assert_eq!(sealed.len(), CONFOUNDER + len + H);
                assert_eq!(decrypt(&key, 3, &sealed).unwrap(), plaintext);

                // The wrong usage derives different keys, and so does the wrong base key.
                assert!(decrypt(&key, 4, &sealed).is_err());
                let mut flipped = sealed.clone();
                flipped[0] ^= 1;
                assert!(decrypt(&key, 3, &flipped).is_err());
            }
        }
        assert!(decrypt(&[0x11; 16], 3, &[0; 11]).is_err());
    }

    #[test]
    fn a_checksum_is_keyed_by_usage_and_is_twelve_bytes() {
        let key = [0x33u8; 32];
        let a = checksum(&key, 6, b"message").unwrap();
        assert_eq!(a.len(), H);
        assert_eq!(a, checksum(&key, 6, b"message").unwrap());
        assert_ne!(a, checksum(&key, 7, b"message").unwrap());
        assert_ne!(a, checksum(&key, 6, b"massage").unwrap());
    }
}
