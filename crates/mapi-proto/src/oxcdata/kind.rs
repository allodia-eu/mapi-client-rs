//! The type half of a property tag, and where a value of that type is being read from.
//!
//! [MS-OXCDATA] §2.11.1 — property data types
//! [MS-OXCDATA] §2.11.1.1 — COUNT data type values

/// Where a property value is being read from.
///
/// Nothing in a value's own bytes says which context produced it, and two separate things depend
/// on the answer:
///
/// * **How wide its COUNT field is.** [MS-OXCDATA] §2.11.1.1: inside ROP buffers a `PtypBinary`
///   byte count is 16 bits and a `PtypMultiple` value count is 32 bits; inside extended rules
///   ([MS-OXORULE] §2.2.4) and the address book endpoint ([MS-OXCMAPIHTTP] §2.2.5) both are 32
///   bits. Reading the wrong width does not fail — it consumes the wrong number of bytes and
///   silently misreads every property after the first binary one — so the width is a parameter of
///   the decoder rather than a constant it assumes.
/// * **Whether a string of exactly 255 characters was truncated.** A table cuts a long value short
///   and reports it nowhere ([MS-OXCDATA] §2.8.2), so its length is the only signal there is. A
///   property fetch does not truncate: an oversized value comes back as `NotEnoughMemory` instead
///   ([MS-OXCPRPT] §2.2.3.2), so classifying by length there would report a whole 255-character
///   display name as damaged.
///
/// The second is why this is not simply a width. `RopGetPropertiesSpecific` answers with a
/// `PropertyRow` — structurally the same thing a table row is — and is still not a table read.
///
/// Only the two ROP-buffer contexts are modelled, because they are the only two this crate reads.
/// Adding the address book endpoint means adding a variant here, which the `match` arms below then
/// refuse to compile until somebody has answered for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ValueContext {
    /// A row of a table — `RopQueryRows`, `RopFindRow`.
    TableRow,
    /// A property fetch on one object — `RopGetPropertiesSpecific`, `RopGetPropertiesAll`.
    Object,
}

impl ValueContext {
    /// The COUNT that prefixes a `PtypBinary` value.
    ///
    /// [MS-OXCDATA] §2.11.1.1 — 16 bits in a ROP buffer
    pub(crate) const fn binary_count(self) -> CountWidth {
        match self {
            // Both of these are ROP buffers. Matching rather than returning a constant is the
            // point: a context whose counts are 32 bits has to answer this question, not inherit
            // an answer given for a different buffer.
            Self::TableRow | Self::Object => CountWidth::Short,
        }
    }

    /// The COUNT that prefixes a `PtypMultiple` value.
    ///
    /// **[MS-OXCDATA] contradicts itself here.** §2.11.1.1 says value counts for every
    /// `PtypMultiple` type are 32 bits wide inside ROP buffers; §2.11.2.1, describing the same
    /// buffers, says "the first element in the ROP buffer is a 16-bit integer specifying the number
    /// of entries". Both are v20250520.
    ///
    /// **§2.11.1.1 is the one a real server follows**, measured on Exchange Server SE
    /// `15.02.2562.045` against both lab mailboxes: `PidTagAdditionalRenEntryIds` read as a
    /// hierarchy-table column arrives as six binary values totalling 50 bytes, and two further
    /// columns placed *after* it still decode to the folder ids and names a read without it
    /// produced. At 16 bits those two columns would have started four bytes early. The test is
    /// `a_multivalued_column_decodes_at_the_documented_count_width` in `mapi-client`'s live suite.
    pub(crate) const fn multiple_count(self) -> CountWidth {
        match self {
            Self::TableRow | Self::Object => CountWidth::Long,
        }
    }

    /// Whether a string of exactly the table limit is to be reported as possibly truncated.
    pub(crate) const fn truncates_strings(self) -> bool {
        match self {
            Self::TableRow => true,
            Self::Object => false,
        }
    }
}

/// How many bytes a COUNT field occupies.
///
/// An enum rather than a number so that the two readings a COUNT can have are the only two that
/// exist, and neither the decoder nor the encoder has a third case to fall through to.
///
/// [MS-OXCDATA] §2.11.1.1 — COUNT data type values
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum CountWidth {
    /// 16 bits.
    Short,
    /// 32 bits.
    Long,
}

impl CountWidth {
    /// The largest count the field can express.
    pub(crate) const fn limit(self) -> usize {
        match self {
            Self::Short => 0xFFFF,
            // Written out rather than derived, because `u32::MAX as usize` is an `as` conversion
            // and `usize::from` is not usable in a `const fn` on the pinned toolchain.
            Self::Long => 0xFFFF_FFFF,
        }
    }
}

/// The type half of a property tag, which decides how many bytes a value occupies.
///
/// [MS-OXCDATA] §2.11.1 — property data types
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PropertyType {
    /// `PtypInteger16`, `0x0002`: 2 bytes.
    Integer16,
    /// `PtypInteger32`, `0x0003`: 4 bytes.
    Integer32,
    /// `PtypFloating64`, `0x0005`: 8 bytes, IEEE 754 binary64.
    Floating64,
    /// `PtypErrorCode`, `0x000A`: 4 bytes holding an error code instead of a value.
    ErrorCode,
    /// `PtypBoolean`, `0x000B`: 1 byte, restricted to 0 or 1.
    Boolean,
    /// `PtypObject`, `0x000D`: not a value at all.
    ///
    /// A message store server MUST NOT return one of these through a property fetch; the value is
    /// reached with `RopOpenStream` or `RopOpenEmbeddedMessage` instead. Modelled so that a tag
    /// carrying it can be named and reported, not so that a value of it can be decoded.
    ///
    /// [MS-OXCDATA] §2.11.1.5 — `PtypObject` and `PtypEmbeddedTable`
    Object,
    /// `PtypInteger64`, `0x0014`: 8 bytes.
    Integer64,
    /// `PtypString8`, `0x001E`: null-terminated 8-bit, in the code page the session negotiated.
    String8,
    /// `PtypString`, `0x001F`: null-terminated UTF-16LE.
    String,
    /// `PtypTime`, `0x0040`: 8 bytes of 100-nanosecond intervals since 1601-01-01 UTC.
    Time,
    /// `PtypGuid`, `0x0048`: 16 bytes.
    Guid,
    /// `PtypBinary`, `0x0102`: a COUNT of bytes, then that many bytes.
    Binary,
    /// `PtypMultipleInteger32`, `0x1003`: a COUNT of values, then that many `PtypInteger32`.
    MultipleInteger32,
    /// `PtypMultipleString`, `0x101F`: a COUNT of values, then that many `PtypString`.
    MultipleString,
    /// `PtypMultipleBinary`, `0x1102`: a COUNT of values, then that many `PtypBinary`.
    MultipleBinary,
    /// A type this crate does not model. Its length is unknown, so a value of this type cannot be
    /// skipped over — decoding stops instead of guessing.
    Unsupported(u16),
}

impl PropertyType {
    /// Reads a type code as the wire carries it.
    #[must_use]
    pub const fn new(raw: u16) -> Self {
        match raw {
            0x0002 => Self::Integer16,
            0x0003 => Self::Integer32,
            0x0005 => Self::Floating64,
            0x000A => Self::ErrorCode,
            0x000B => Self::Boolean,
            0x000D => Self::Object,
            0x0014 => Self::Integer64,
            0x001E => Self::String8,
            0x001F => Self::String,
            0x0040 => Self::Time,
            0x0048 => Self::Guid,
            0x0102 => Self::Binary,
            0x1003 => Self::MultipleInteger32,
            0x101F => Self::MultipleString,
            0x1102 => Self::MultipleBinary,
            other => Self::Unsupported(other),
        }
    }

    /// The type code as the wire carries it.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Integer16 => 0x0002,
            Self::Integer32 => 0x0003,
            Self::Floating64 => 0x0005,
            Self::ErrorCode => 0x000A,
            Self::Boolean => 0x000B,
            Self::Object => 0x000D,
            Self::Integer64 => 0x0014,
            Self::String8 => 0x001E,
            Self::String => 0x001F,
            Self::Time => 0x0040,
            Self::Guid => 0x0048,
            Self::Binary => 0x0102,
            Self::MultipleInteger32 => 0x1003,
            Self::MultipleString => 0x101F,
            Self::MultipleBinary => 0x1102,
            Self::Unsupported(raw) => raw,
        }
    }

    /// The specification's name for this type, if it is one this crate models.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::Integer16 => "PtypInteger16",
            Self::Integer32 => "PtypInteger32",
            Self::Floating64 => "PtypFloating64",
            Self::ErrorCode => "PtypErrorCode",
            Self::Boolean => "PtypBoolean",
            Self::Object => "PtypObject",
            Self::Integer64 => "PtypInteger64",
            Self::String8 => "PtypString8",
            Self::String => "PtypString",
            Self::Time => "PtypTime",
            Self::Guid => "PtypGuid",
            Self::Binary => "PtypBinary",
            Self::MultipleInteger32 => "PtypMultipleInteger32",
            Self::MultipleString => "PtypMultipleString",
            Self::MultipleBinary => "PtypMultipleBinary",
            Self::Unsupported(_) => return None,
        })
    }

    /// Whether this type holds a list of values rather than one.
    ///
    /// Every `PtypMultiple` type sets the `0x1000` bit, which is what makes this a property of the
    /// code rather than a list to keep in step.
    ///
    /// [MS-OXCDATA] §2.11.1.3 — all `PtypMultiple` types set the `0x1000` bit
    #[must_use]
    pub const fn is_multivalued(self) -> bool {
        self.as_u16() & 0x1000 != 0
    }
}

impl core::fmt::Display for PropertyType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "unmodelled type 0x{:04X}", self.as_u16()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every modelled type, with the code [MS-OXCDATA] §2.11.1 gives it. Transcribed from the
    /// table rather than from this crate's own `new`, so a typo in one is not confirmed by the
    /// other.
    const MODELLED: [(u16, PropertyType, &str); 15] = [
        (0x0002, PropertyType::Integer16, "PtypInteger16"),
        (0x0003, PropertyType::Integer32, "PtypInteger32"),
        (0x0005, PropertyType::Floating64, "PtypFloating64"),
        (0x000A, PropertyType::ErrorCode, "PtypErrorCode"),
        (0x000B, PropertyType::Boolean, "PtypBoolean"),
        (0x000D, PropertyType::Object, "PtypObject"),
        (0x0014, PropertyType::Integer64, "PtypInteger64"),
        (0x001E, PropertyType::String8, "PtypString8"),
        (0x001F, PropertyType::String, "PtypString"),
        (0x0040, PropertyType::Time, "PtypTime"),
        (0x0048, PropertyType::Guid, "PtypGuid"),
        (0x0102, PropertyType::Binary, "PtypBinary"),
        (
            0x1003,
            PropertyType::MultipleInteger32,
            "PtypMultipleInteger32",
        ),
        (0x101F, PropertyType::MultipleString, "PtypMultipleString"),
        (0x1102, PropertyType::MultipleBinary, "PtypMultipleBinary"),
    ];

    #[test]
    fn types_map_both_ways() {
        for (raw, expected, name) in MODELLED {
            assert_eq!(PropertyType::new(raw), expected, "0x{raw:04X}");
            assert_eq!(expected.as_u16(), raw, "{name}");
            assert_eq!(expected.name(), Some(name));
            assert_eq!(expected.to_string(), name);
        }
    }

    /// The `0x1000` bit is the specification's own marker for a multivalued type, so this is a
    /// check that the modelled codes are the ones the table gives rather than that the bit works.
    #[test]
    fn the_multivalue_bit_identifies_the_list_types() {
        for (_, property_type, name) in MODELLED {
            assert_eq!(
                property_type.is_multivalued(),
                name.starts_with("PtypMultiple"),
                "{name}"
            );
        }
        assert!(!PropertyType::new(0x0000).is_multivalued());
    }

    #[test]
    fn an_unmodelled_type_survives_being_read_and_says_so() {
        // PtypCurrency, which this crate has no reason to decode yet.
        let currency = PropertyType::new(0x0006);
        assert_eq!(currency, PropertyType::Unsupported(0x0006));
        assert_eq!(currency.as_u16(), 0x0006);
        assert_eq!(currency.name(), None);
        assert_eq!(currency.to_string(), "unmodelled type 0x0006");
    }

    /// The widths that decide how many bytes a variable-length value occupies. Wrong here means
    /// every property after the first binary one decodes against the wrong bytes, with no error.
    ///
    /// [MS-OXCDATA] §2.11.1.1
    #[test]
    fn a_rop_buffer_counts_bytes_in_sixteen_bits_and_values_in_thirty_two() {
        for context in [ValueContext::TableRow, ValueContext::Object] {
            assert_eq!(context.binary_count(), CountWidth::Short, "{context:?}");
            assert_eq!(context.multiple_count(), CountWidth::Long, "{context:?}");
        }
        assert_eq!(CountWidth::Short.limit(), usize::from(u16::MAX));
        assert_eq!(
            CountWidth::Long.limit(),
            usize::try_from(u32::MAX).expect("a 32-bit count fits a usize here")
        );
    }

    /// Only a table truncates. A property fetch answers `NotEnoughMemory` instead, so a
    /// 255-character value read from an object is the whole value.
    #[test]
    fn only_a_table_row_classifies_a_string_by_its_length() {
        assert!(ValueContext::TableRow.truncates_strings());
        assert!(!ValueContext::Object.truncates_strings());
    }
}
