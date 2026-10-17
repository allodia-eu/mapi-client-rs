//! The two numeric value types that are not what their width suggests.
//!
//! Split from the value enum's own file because both carry a rule a caller would otherwise have to
//! look up: a `PtypFloating32` is held as bits for the same reason a `PtypFloating64` is, and a
//! `PtypCurrency` is an integer whose unit is a ten-thousandth.
//!
//! [MS-OXCDATA] §2.11.1 — `PtypFloating32`, `PtypCurrency`

/// A `PtypFloating32` value, held as the four bytes the wire carried.
///
/// Bits rather than an `f32` for the reason [`Floating64`](crate::Floating64) gives: so that a
/// [`PropertyValue`](crate::PropertyValue) stays `Eq`, `Ord` and `Hash`.
///
/// [MS-OXCDATA] §2.11.1 — "4 bytes; a 32-bit floating point number"
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Floating32(u32);

impl Floating32 {
    /// Wraps the raw bit pattern as the wire carries it.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Wraps a number.
    #[must_use]
    pub const fn new(value: f32) -> Self {
        Self(value.to_bits())
    }

    /// The bit pattern, which little-endian encoded is the wire form.
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        self.0
    }

    /// The number.
    #[must_use]
    pub const fn as_f32(self) -> f32 {
        f32::from_bits(self.0)
    }
}

impl core::fmt::Display for Floating32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_f32())
    }
}

/// A `PtypCurrency` value: a signed count of ten-thousandths.
///
/// A newtype rather than an `i64` because the unit is the whole difficulty — `12345` is `1.2345` —
/// and a bare integer invites reading it as whole units.
///
/// [MS-OXCDATA] §2.11.1 — "a 64-bit signed, scaled integer representation of a decimal currency
/// value, with four places to the right of the decimal point"
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Currency(i64);

impl Currency {
    /// Wraps a count of ten-thousandths, as the wire carries it.
    #[must_use]
    pub const fn from_scaled(ten_thousandths: i64) -> Self {
        Self(ten_thousandths)
    }

    /// The count of ten-thousandths.
    #[must_use]
    pub const fn scaled(self) -> i64 {
        self.0
    }
}

impl core::fmt::Display for Currency {
    /// Four decimal places, exactly, as the value carries them.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let sign = if self.0 < 0 { "-" } else { "" };
        let magnitude = self.0.unsigned_abs();
        write!(f, "{sign}{}.{:04}", magnitude / 10_000, magnitude % 10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_currency_shows_four_decimal_places_whatever_its_sign() {
        assert_eq!(Currency::from_scaled(12_345).to_string(), "1.2345");
        assert_eq!(Currency::from_scaled(-50).to_string(), "-0.0050");
        assert_eq!(Currency::from_scaled(i64::MIN).scaled(), i64::MIN);
        assert_eq!(
            Currency::from_scaled(i64::MIN).to_string(),
            "-922337203685477.5808"
        );
    }

    #[test]
    fn a_float_keeps_its_bits() {
        let value = Floating32::new(1.5);
        assert_eq!(value.to_bits(), 0x3FC0_0000);
        assert_eq!(
            Floating32::from_bits(0x3FC0_0000).as_f32().to_bits(),
            1.5_f32.to_bits()
        );
        assert_eq!(value.to_string(), "1.5");
    }
}
