//! `n-fold`, which stretches a short constant to a cipher's block size.
//!
//! Written the way [RFC 3961] §5.1 defines it rather than the way it is usually optimised:
//! replicate the input to the least common multiple of the two lengths, rotating each copy thirteen
//! bits further right than the last, then add the output-sized chunks together in one's complement.
//! The constants it is given are a few bytes long, so the plain form costs nothing and can be
//! checked against the definition line by line.

/// `n-fold(input)` to `out_len` bytes.
///
/// [RFC 3961] §5.1 — "To n-fold a number X, replicate the input value to a length that is the least
/// common multiple of n and the length of X. Before each repetition, the input is rotated to the
/// right by 13 bit positions. The successive n-bit chunks are added together using 1's-complement
/// addition (that is, with end-around carry)."
pub(super) fn nfold(input: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    if input.is_empty() || out_len == 0 {
        return out;
    }

    let copies = lcm(input.len(), out_len)
        .checked_div(input.len())
        .unwrap_or(0);
    let mut stream = Vec::with_capacity(copies.saturating_mul(input.len()));
    for copy in 0..copies {
        stream.extend(rotate_right(input, copy.saturating_mul(13)));
    }

    for chunk in stream.chunks(out_len) {
        add_ones_complement(&mut out, chunk);
    }
    out
}

/// The input rotated right by `bits`, as a big-endian bit string.
///
/// Bit 0 is the most significant bit of the first byte, which is the "Big-Endian -- Most
/// Significant Byte first" reading [RFC 3961] §5.1 gives. Output bit `k` is input bit `k - bits`,
/// modulo the length.
fn rotate_right(input: &[u8], bits: usize) -> Vec<u8> {
    let len = input.len().saturating_mul(8);
    let shift = bits.checked_rem(len).unwrap_or(0);
    let mut out = vec![0u8; input.len()];
    for (index, byte) in out.iter_mut().enumerate() {
        for bit in 0..8 {
            let position = index.saturating_mul(8).saturating_add(bit);
            // Adding `len` before subtracting keeps the arithmetic unsigned; the remainder undoes
            // it.
            let source = position
                .saturating_add(len)
                .saturating_sub(shift)
                .checked_rem(len)
                .unwrap_or(0);
            if bit_at(input, source) {
                *byte |= 0x80u8
                    .checked_shr(u32::try_from(bit).unwrap_or(0))
                    .unwrap_or(0);
            }
        }
    }
    out
}

/// Whether big-endian bit `position` of `bytes` is set.
fn bit_at(bytes: &[u8], position: usize) -> bool {
    let byte = bytes
        .get(position.checked_div(8).unwrap_or(0))
        .copied()
        .unwrap_or(0);
    let offset = u32::try_from(position.checked_rem(8).unwrap_or(0)).unwrap_or(0);
    byte.checked_shl(offset).unwrap_or(0) & 0x80 != 0
}

/// `sum += chunk`, big-endian, with the carry out of the top wrapped round to the bottom.
///
/// The end-around carry is what makes it one's-complement addition. It is applied until it stops
/// propagating; adding a single carry to a sum can carry out of the top at most once more.
fn add_ones_complement(sum: &mut [u8], chunk: &[u8]) {
    let mut carry = 0u16;
    for (slot, byte) in sum.iter_mut().rev().zip(chunk.iter().rev()) {
        let total = u16::from(*slot)
            .saturating_add(u16::from(*byte))
            .saturating_add(carry);
        *slot = total.to_be_bytes()[1];
        carry = total.checked_shr(8).unwrap_or(0);
    }
    while carry != 0 {
        let mut next = carry;
        for slot in sum.iter_mut().rev() {
            if next == 0 {
                break;
            }
            let total = u16::from(*slot).saturating_add(next);
            *slot = total.to_be_bytes()[1];
            next = total.checked_shr(8).unwrap_or(0);
        }
        carry = next;
    }
}

/// The least common multiple of two non-zero lengths.
fn lcm(a: usize, b: usize) -> usize {
    a.checked_div(gcd(a, b)).unwrap_or(0).saturating_mul(b)
}

/// Euclid's greatest common divisor.
fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let remainder = a.checked_rem(b).unwrap_or(0);
        a = b;
        b = remainder;
    }
    a
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

    /// [RFC 3961] Appendix A.1, every vector, in the order printed.
    #[test]
    fn every_published_vector_folds_to_its_printed_value() {
        let cases: [(&[u8], usize, &str); 11] = [
            (b"012345", 8, "be072631276b1955"),
            (b"password", 7, "78a07b6caf85fa"),
            (b"Rough Consensus, and Running Code", 8, "bb6ed30870b7f0e0"),
            (
                b"password",
                21,
                "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e",
            ),
            (
                b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
                24,
                "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
            ),
            (b"Q", 21, "518a54a2 15a8452a 518a54a2 15a8452a 518a54a2 15"),
            // The two-letter input the appendix prints, as its bytes.
            (
                &[0x62, 0x61],
                21,
                "fb25d531 ae897449 9f52fd92 ea9857c4 ba24cf29 7e",
            ),
            (b"kerberos", 8, "6b657262 65726f73"),
            (b"kerberos", 16, "6b657262 65726f73 7b9b5b2b 93132b93"),
            (
                b"kerberos",
                21,
                "8372c236 344e5f15 50cd0747 e15d62ca 7a5a3bce a4",
            ),
            (
                b"kerberos",
                32,
                "6b657262 65726f73 7b9b5b2b 93132b93 5c9bdcda d95c9899 c4cae4de e6d6cae4",
            ),
        ];
        for (input, out_len, expected) in cases {
            assert_eq!(
                nfold(input, out_len),
                hex(expected),
                "{}-fold({:?})",
                out_len * 8,
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn an_empty_input_or_output_folds_to_zeros() {
        assert_eq!(nfold(b"", 4), vec![0; 4]);
        assert!(nfold(b"x", 0).is_empty());
    }
}
