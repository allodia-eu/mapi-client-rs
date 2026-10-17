//! AES in CBC mode with ciphertext stealing, which is the cipher every AES encryption type uses.
//!
//! [RFC 3962] §5 defines it for the SHA-1 types and [RFC 8009] §5 reuses it as CBC-CS3 for the
//! SHA-2 ones. The initial vector is always zero here: [RFC 3961] §5.3 starts every encryption from
//! the "initial cipher state", and a Kerberos message is never encrypted as the continuation of
//! another, so the cipher state carried between messages is never needed and is not kept.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

/// Why a CBC-CS3 operation could not run. The caller knows which key usage was involved and turns
/// this into [`Error::Decryption`](crate::Error::Decryption) with it.
pub(super) type Result<T> = core::result::Result<T, &'static str>;

/// AES's block size, in bytes.
pub(super) const BLOCK: usize = 16;

/// One AES block.
pub(super) type Block = [u8; BLOCK];

/// AES with whichever key length the encryption type uses.
///
/// Boxed because an expanded AES-256 key schedule is close to a kilobyte, and the enum is built
/// once per encryption and dropped straight after.
enum Cipher {
    Aes128(Box<Aes128>),
    Aes256(Box<Aes256>),
}

impl Cipher {
    /// The cipher for a 16- or 32-byte key. Every key this crate holds is one of the two, because
    /// [`Enctype::key_len`](super::Enctype::key_len) is what sizes them.
    fn new(key: &[u8]) -> Result<Self> {
        match key.len() {
            16 => Ok(Self::Aes128(Box::new(Aes128::new(
                GenericArray::from_slice(key),
            )))),
            32 => Ok(Self::Aes256(Box::new(Aes256::new(
                GenericArray::from_slice(key),
            )))),
            _ => Err("an AES key must be 16 or 32 bytes"),
        }
    }

    fn encrypt(&self, block: Block) -> Block {
        let mut block = GenericArray::from(block);
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block(&mut block),
            Self::Aes256(cipher) => cipher.encrypt_block(&mut block),
        }
        block.into()
    }

    fn decrypt(&self, block: Block) -> Block {
        let mut block = GenericArray::from(block);
        match self {
            Self::Aes128(cipher) => cipher.decrypt_block(&mut block),
            Self::Aes256(cipher) => cipher.decrypt_block(&mut block),
        }
        block.into()
    }
}

/// One block encrypted on its own, which is what [RFC 3961] §5.1's `DR` repeats.
pub(super) fn encrypt_block(key: &[u8], block: Block) -> Result<Block> {
    Ok(Cipher::new(key)?.encrypt(block))
}

/// CBC-CS3 encryption from a zero initial vector.
///
/// [RFC 3962] §5: "If exactly one block is to be encrypted, that block is simply encrypted with
/// AES", and otherwise ciphertext stealing is "always used for the last two blocks of the data …
/// If the data length is a multiple of the block size, this is equivalent to plain CBC mode with
/// the last two ciphertext blocks swapped." Input shorter than a block never occurs — every
/// Kerberos encryption starts with a block-sized confounder — and is refused rather than padded.
pub(super) fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::new(key)?;
    let blocks = to_blocks(plaintext)?;

    // Plain CBC over the zero-padded input. Padding with zeros is what makes the stolen bytes
    // come out right: the last plaintext block XORed into the previous ciphertext leaves that
    // ciphertext's own bytes wherever the padding was.
    let mut chained = Vec::with_capacity(blocks.len());
    let mut previous = [0u8; BLOCK];
    for block in &blocks {
        let encrypted = cipher.encrypt(xor(block, &previous));
        chained.push(encrypted);
        previous = encrypted;
    }

    let tail = tail_len(plaintext.len());
    let mut out = Vec::with_capacity(plaintext.len());
    match chained.as_slice() {
        [only] => out.extend_from_slice(only),
        [front @ .., second_last, last] => {
            for block in front {
                out.extend_from_slice(block);
            }
            out.extend_from_slice(last);
            out.extend(second_last.iter().take(tail));
        }
        [] => {}
    }
    Ok(out)
}

/// CBC-CS3 decryption from a zero initial vector, the inverse of [`encrypt`].
pub(super) fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::new(key)?;
    if ciphertext.len() < BLOCK {
        return Err(too_short());
    }
    if ciphertext.len() == BLOCK {
        let block = to_blocks(ciphertext)?
            .first()
            .copied()
            .unwrap_or([0; BLOCK]);
        return Ok(cipher.decrypt(block).to_vec());
    }

    // The input is C1 … C(n-2), then C(n) whole, then the first `tail` bytes of C(n-1).
    let tail = tail_len(ciphertext.len());
    let split = ciphertext.len().saturating_sub(tail).saturating_sub(BLOCK);
    let (front, rest) = ciphertext.split_at_checked(split).ok_or_else(too_short)?;
    let (last_whole, partial) = rest.split_at_checked(BLOCK).ok_or_else(too_short)?;
    let front = to_blocks(front)?;
    let last_whole = to_blocks(last_whole)?
        .first()
        .copied()
        .unwrap_or([0; BLOCK]);

    // Decrypting C(n) gives P(n) padded with zeros, XORed with C(n-1): its first `tail` bytes XOR
    // the partial block are P(n), and the rest are the bytes of C(n-1) that were stolen.
    let opened = cipher.decrypt(last_whole);
    let mut second_last = [0u8; BLOCK];
    for (slot, byte) in second_last
        .iter_mut()
        .zip(partial.iter().chain(opened.iter().skip(tail)))
    {
        *slot = *byte;
    }
    let final_plain: Vec<u8> = opened
        .iter()
        .zip(partial.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    let mut out = Vec::with_capacity(ciphertext.len());
    let mut previous = [0u8; BLOCK];
    for block in front.iter().chain(core::iter::once(&second_last)) {
        out.extend_from_slice(&xor(&cipher.decrypt(*block), &previous));
        previous = *block;
    }
    out.extend(final_plain);
    Ok(out)
}

/// How many bytes the last block holds: 1 to 16, never 0.
fn tail_len(len: usize) -> usize {
    match len.checked_rem(BLOCK) {
        Some(0) | None => BLOCK,
        Some(rest) => rest,
    }
}

/// Splits into blocks, zero-padding the last.
fn to_blocks(bytes: &[u8]) -> Result<Vec<Block>> {
    if bytes.len() < BLOCK && !bytes.is_empty() {
        return Err(too_short());
    }
    Ok(bytes
        .chunks(BLOCK)
        .map(|chunk| {
            let mut block = [0u8; BLOCK];
            for (slot, byte) in block.iter_mut().zip(chunk) {
                *slot = *byte;
            }
            block
        })
        .collect())
}

fn xor(a: &Block, b: &Block) -> Block {
    let mut out = [0u8; BLOCK];
    for ((slot, x), y) in out.iter_mut().zip(a).zip(b) {
        *slot = x ^ y;
    }
    out
}

fn too_short() -> &'static str {
    "shorter than one AES block"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    /// [RFC 3962] Appendix B's ciphertext-stealing vectors: the AES-128 key "chicken teriyaki",
    /// a zero initial vector, and inputs of 17, 31, 32, 47, 48 and 64 bytes — one block and a
    /// byte, a partial second block, exactly two, and so on.
    #[test]
    fn every_published_vector_encrypts_and_decrypts() {
        const KEY: &[u8] = b"chicken teriyaki";
        const TEXT: &[u8] = b"I would like the General Gau's Chicken, please, and wonton soup.";
        let cases = [
            (17, "c6353568f2bf8cb4d8a580362da7ff7f 97"),
            (
                31,
                "fc00783e0efdb2c1d445d4c8eff7ed22 97687268d6ecccc0c07b25e25ecfe5",
            ),
            (
                32,
                "39312523a78662d5be7fcbcc98ebf5a8 97687268d6ecccc0c07b25e25ecfe584",
            ),
            (
                47,
                "97687268d6ecccc0c07b25e25ecfe584 b3fffd940c16a18c1b5549d2f838029e \
                 39312523a78662d5be7fcbcc98ebf5",
            ),
            (
                48,
                "97687268d6ecccc0c07b25e25ecfe584 9dad8bbb96c4cdc03bc103e1a194bbd8 \
                 39312523a78662d5be7fcbcc98ebf5a8",
            ),
            (
                64,
                "97687268d6ecccc0c07b25e25ecfe584 39312523a78662d5be7fcbcc98ebf5a8 \
                 4807efe836ee89a526730dbc2f7bc840 9dad8bbb96c4cdc03bc103e1a194bbd8",
            ),
        ];
        for (len, expected) in cases {
            let plaintext = &TEXT[..len];
            let ciphertext = encrypt(KEY, plaintext).unwrap();
            assert_eq!(ciphertext, hex(expected), "{len} bytes");
            assert_eq!(
                decrypt(KEY, &ciphertext).unwrap(),
                plaintext,
                "{len} bytes back"
            );
        }
    }

    #[test]
    fn exactly_one_block_is_plain_aes_and_less_is_refused() {
        let key = [7u8; 32];
        let block = [9u8; BLOCK];
        let ciphertext = encrypt(&key, &block).unwrap();
        assert_eq!(ciphertext, encrypt_block(&key, block).unwrap());
        assert_eq!(decrypt(&key, &ciphertext).unwrap(), block);

        assert!(encrypt(&key, &[1; 15]).is_err());
        assert!(decrypt(&key, &[1; 15]).is_err());
        assert!(
            encrypt(&[0; 24], &block).is_err(),
            "AES-192 is not a Kerberos key length"
        );
    }
}
