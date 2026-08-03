//! Restrictions — the filter that decides which rows a table shows.
//!
//! A Boolean expression the server evaluates against every item, so "the messages whose subject
//! contains this" costs one round trip rather than reading the folder and discarding most of it.
//!
//! Six of the twelve packet formats are modelled: the three that combine restrictions and the three
//! a filter is actually built from. The rest — `ComparePropertiesRestriction`,
//! `BitMaskRestriction`, `SizeRestriction`, `SubObjectRestriction`, `CommentRestriction`,
//! `CountRestriction` — are left out because nothing in the requested operations needs one, and an
//! encoder for a structure nobody sends is an untested encoder.
//!
//! **The result of a restriction on a property an item does not have is undefined**
//! ([MS-OXCDATA] §2.12.9.1), not false. That is why [`Restriction::exists`] is in the modelled six
//! and why [`Restriction::content`] documents pairing with it.
//!
//! [MS-OXCDATA] §2.12 — restrictions

use crate::error::Result;
use crate::oxcdata::TaggedValue;
use crate::oxcdata::kind::ValueContext;
use crate::wire::Writer;

/// How closely a [`Restriction::content`] match has to fit.
///
/// [MS-OXCDATA] §2.12.4.1 — `FuzzyLevelLow`, `FuzzyLevelHigh`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FuzzyLevel {
    low: u16,
    high: u16,
}

impl FuzzyLevel {
    /// `FL_IGNORECASE`, `0x0001`.
    const IGNORE_CASE: u16 = 0x0001;
    /// `FL_IGNORENONSPACE`, `0x0002` — diacritics do not count.
    const IGNORE_NON_SPACE: u16 = 0x0002;
    /// `FL_LOOSE`, `0x0004` — match wherever possible.
    const LOOSE: u16 = 0x0004;

    /// `FL_FULLSTRING`: the value and the property match in their entirety.
    #[must_use]
    pub const fn full_string() -> Self {
        Self {
            low: 0x0000,
            high: 0,
        }
    }

    /// `FL_SUBSTRING`: the value appears somewhere in the property.
    #[must_use]
    pub const fn substring() -> Self {
        Self {
            low: 0x0001,
            high: 0,
        }
    }

    /// `FL_PREFIX`: the property starts with the value.
    #[must_use]
    pub const fn prefix() -> Self {
        Self {
            low: 0x0002,
            high: 0,
        }
    }

    /// Also match regardless of case.
    ///
    /// String values only — [MS-OXCDATA] §2.12.4.1 says the high half applies to nothing else.
    #[must_use]
    pub const fn ignoring_case(self) -> Self {
        Self {
            high: self.high | Self::IGNORE_CASE,
            ..self
        }
    }

    /// Also ignore diacritical marks.
    #[must_use]
    pub const fn ignoring_diacritics(self) -> Self {
        Self {
            high: self.high | Self::IGNORE_NON_SPACE,
            ..self
        }
    }

    /// Match wherever possible, ignoring case and non-spacing characters.
    #[must_use]
    pub const fn loose(self) -> Self {
        Self {
            high: self.high | Self::LOOSE,
            ..self
        }
    }

    /// The `FuzzyLevelLow` field.
    #[must_use]
    pub const fn low(self) -> u16 {
        self.low
    }

    /// The `FuzzyLevelHigh` field.
    #[must_use]
    pub const fn high(self) -> u16 {
        self.high
    }
}

/// How a [`Restriction::property`] comparison is made.
///
/// [MS-OXCDATA] §2.12.5.1 — `RelOp`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RelationalOperator {
    /// `RELOP_LT`, `0x00`.
    LessThan,
    /// `RELOP_LE`, `0x01`.
    LessThanOrEqual,
    /// `RELOP_GT`, `0x02`.
    GreaterThan,
    /// `RELOP_GE`, `0x03`.
    GreaterThanOrEqual,
    /// `RELOP_EQ`, `0x04`.
    Equal,
    /// `RELOP_NE`, `0x05`.
    NotEqual,
}

impl RelationalOperator {
    /// The `RelOp` byte as the wire carries it.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::LessThan => 0x00,
            Self::LessThanOrEqual => 0x01,
            Self::GreaterThan => 0x02,
            Self::GreaterThanOrEqual => 0x03,
            Self::Equal => 0x04,
            Self::NotEqual => 0x05,
        }
    }
}

/// A filter for a table.
///
/// ```
/// use mapi_proto::{FuzzyLevel, PropertyTag, PropertyValue, Restriction, TaggedValue};
///
/// let subject = TaggedValue::new(PropertyTag::SUBJECT, PropertyValue::String("report".into()))?;
/// // A content restriction on a property an item does not have is *undefined*, not false, so the
/// // existence test goes with it rather than being implied.
/// let filter = Restriction::all([
///     Restriction::exists(PropertyTag::SUBJECT),
///     Restriction::content(FuzzyLevel::substring().ignoring_case(), subject),
/// ]);
/// # Ok::<(), mapi_proto::Error>(())
/// ```
///
/// [MS-OXCDATA] §2.12 — restrictions
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Restriction {
    /// `AndRestriction`, `0x00` — true when every child is.
    And(Vec<Restriction>),
    /// `OrRestriction`, `0x01` — true when any child is.
    Or(Vec<Restriction>),
    /// `NotRestriction`, `0x02` — true when its child is not.
    Not(Box<Restriction>),
    /// `ContentRestriction`, `0x03` — a string or binary property matched against a value.
    Content {
        /// How closely the two have to fit.
        level: FuzzyLevel,
        /// The property, and what to match it against. One value rather than a separate tag: the
        /// structure carries the tag twice, and letting a caller supply two would let them differ.
        value: TaggedValue,
    },
    /// `PropertyRestriction`, `0x04` — a property compared with a constant.
    Property {
        /// The comparison.
        operator: RelationalOperator,
        /// The property, and the constant to compare it with.
        value: TaggedValue,
    },
    /// `ExistRestriction`, `0x08` — the property has a value at all.
    Exist(crate::oxcdata::PropertyTag),
}

impl Restriction {
    /// Every one of these has to hold.
    #[must_use]
    pub fn all<I>(children: I) -> Self
    where
        I: IntoIterator<Item = Self>,
    {
        Self::And(children.into_iter().collect())
    }

    /// Any one of these has to hold.
    #[must_use]
    pub fn any<I>(children: I) -> Self
    where
        I: IntoIterator<Item = Self>,
    {
        Self::Or(children.into_iter().collect())
    }

    /// This must not hold.
    ///
    /// Named `negate` rather than `not` because a free function called `not` on a type that is not
    /// `std::ops::Not` reads as an operator and is not one.
    #[must_use]
    pub fn negate(child: Self) -> Self {
        Self::Not(Box::new(child))
    }

    /// A string or binary property matched against a value.
    ///
    /// **Pair this with [`exists`](Self::exists) under [`all`](Self::all).** [MS-OXCDATA]
    /// §2.12.9.1 says the result of a property-based restriction on an item that does not hold the
    /// property is *undefined* — so a subject filter over a folder holding one message with no
    /// subject at all has no defined answer for that row unless the existence test is there too.
    #[must_use]
    pub const fn content(level: FuzzyLevel, value: TaggedValue) -> Self {
        Self::Content { level, value }
    }

    /// A property compared with a constant.
    ///
    /// Carries the same caveat as [`content`](Self::content).
    #[must_use]
    pub const fn property(operator: RelationalOperator, value: TaggedValue) -> Self {
        Self::Property { operator, value }
    }

    /// The property has a value on this item.
    #[must_use]
    pub const fn exists(tag: crate::oxcdata::PropertyTag) -> Self {
        Self::Exist(tag)
    }

    /// Writes the restriction packet.
    ///
    /// Counts are 16 bits here because this is a ROP buffer. [MS-OXCDATA] §2.12 says the same
    /// fields are 32 bits inside extended rules and search-folder definitions, which is the COUNT
    /// problem in a third place — so the context is threaded through rather than assumed, exactly
    /// as it is for property values.
    ///
    /// # Errors
    ///
    /// Whatever the embedded values refused: a string with an interior NUL, or a binary longer than
    /// its own COUNT field can express.
    pub(crate) fn write(&self, w: &mut Writer, context: ValueContext) -> Result<()> {
        match self {
            Self::And(children) => write_group(w, 0x00, children, context)?,
            Self::Or(children) => write_group(w, 0x01, children, context)?,
            Self::Not(child) => {
                w.u8(0x02);
                child.write(w, context)?;
            }
            Self::Content { level, value } => {
                w.u8(0x03)
                    .u16(level.low())
                    .u16(level.high())
                    .u32(value.tag().as_u32());
                value.write(w, context)?;
            }
            Self::Property { operator, value } => {
                w.u8(0x04).u8(operator.as_u8()).u32(value.tag().as_u32());
                value.write(w, context)?;
            }
            Self::Exist(tag) => {
                w.u8(0x08).u32(tag.as_u32());
            }
        }
        Ok(())
    }
}

/// Writes an `AndRestriction` or an `OrRestriction`, which share a layout.
fn write_group(
    w: &mut Writer,
    restrict_type: u8,
    children: &[Restriction],
    context: ValueContext,
) -> Result<()> {
    w.u8(restrict_type)
        .u16(u16::try_from(children.len()).unwrap_or(u16::MAX));
    for child in children {
        child.write(w, context)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oxcdata::{PropertyTag, PropertyValue};

    fn subject(text: &str) -> TaggedValue {
        TaggedValue::new(PropertyTag::SUBJECT, PropertyValue::String(text.into()))
            .expect("a string value for a string tag")
    }

    /// The fuzzy levels [MS-OXCDATA] §2.12.4.1 lists, and the bits that combine with them.
    #[test]
    fn the_fuzzy_levels_are_the_documented_values() {
        assert_eq!(FuzzyLevel::full_string().low(), 0x0000);
        assert_eq!(FuzzyLevel::substring().low(), 0x0001);
        assert_eq!(FuzzyLevel::prefix().low(), 0x0002);
        assert_eq!(FuzzyLevel::full_string().high(), 0x0000);

        assert_eq!(FuzzyLevel::substring().ignoring_case().high(), 0x0001);
        assert_eq!(FuzzyLevel::substring().ignoring_diacritics().high(), 0x0002);
        assert_eq!(FuzzyLevel::substring().loose().high(), 0x0004);
        assert_eq!(
            FuzzyLevel::prefix()
                .ignoring_case()
                .ignoring_diacritics()
                .high(),
            0x0003,
            "the high half is a bit field"
        );
        assert_eq!(FuzzyLevel::prefix().ignoring_case().low(), 0x0002);
    }

    #[test]
    fn the_relational_operators_are_the_documented_values() {
        for (operator, raw) in [
            (RelationalOperator::LessThan, 0x00),
            (RelationalOperator::LessThanOrEqual, 0x01),
            (RelationalOperator::GreaterThan, 0x02),
            (RelationalOperator::GreaterThanOrEqual, 0x03),
            (RelationalOperator::Equal, 0x04),
            (RelationalOperator::NotEqual, 0x05),
        ] {
            assert_eq!(operator.as_u8(), raw, "{operator:?}");
        }
    }

    /// A content restriction: type, both fuzzy halves, the tag, then the tag again as part of the
    /// `TaggedValue`, then the value.
    #[test]
    fn a_content_restriction_matches_the_spec_layout() {
        let mut w = Writer::new();
        Restriction::content(FuzzyLevel::substring().ignoring_case(), subject("hi"))
            .write(&mut w, ValueContext::Object)
            .expect("an encodable value");

        #[rustfmt::skip]
        let expected = vec![
            0x03,                               // RestrictType
            0x01, 0x00,                         // FuzzyLevelLow: FL_SUBSTRING
            0x01, 0x00,                         // FuzzyLevelHigh: FL_IGNORECASE
            0x1F, 0x00, 0x37, 0x00,             // PropertyTag
            0x1F, 0x00, 0x37, 0x00,             // TaggedValue's own tag
            b'h', 0x00, b'i', 0x00, 0x00, 0x00, // "hi", UTF-16LE, null-terminated
        ];
        assert_eq!(w.finish(), expected);
    }

    #[test]
    fn an_exist_restriction_is_a_type_and_a_tag() {
        let mut w = Writer::new();
        Restriction::exists(PropertyTag::SUBJECT)
            .write(&mut w, ValueContext::Object)
            .expect("nothing to encode");
        assert_eq!(w.finish(), vec![0x08, 0x1F, 0x00, 0x37, 0x00]);
    }

    /// The combining forms nest, and their counts are 16 bits in a ROP buffer.
    #[test]
    fn the_combining_restrictions_nest_and_count_their_children() {
        let mut w = Writer::new();
        Restriction::all([
            Restriction::exists(PropertyTag::SUBJECT),
            Restriction::negate(Restriction::exists(PropertyTag::MID)),
        ])
        .write(&mut w, ValueContext::Object)
        .expect("nothing to encode");

        #[rustfmt::skip]
        let expected = vec![
            0x00,                   // AndRestriction
            0x02, 0x00,             // RestrictCount
            0x08, 0x1F, 0x00, 0x37, 0x00, // ExistRestriction on PidTagSubject
            0x02,                   // NotRestriction
            0x08, 0x14, 0x00, 0x4A, 0x67, // ExistRestriction on PidTagMid
        ];
        assert_eq!(w.finish(), expected);

        let mut empty = Writer::new();
        Restriction::any([])
            .write(&mut empty, ValueContext::Object)
            .expect("nothing to encode");
        assert_eq!(empty.finish(), vec![0x01, 0x00, 0x00]);
    }

    #[test]
    fn a_property_restriction_carries_its_operator() {
        let mut w = Writer::new();
        let flags = TaggedValue::new(PropertyTag::MESSAGE_FLAGS, PropertyValue::Integer32(1))
            .expect("an integer value for an integer tag");
        Restriction::property(RelationalOperator::Equal, flags)
            .write(&mut w, ValueContext::Object)
            .expect("an encodable value");

        #[rustfmt::skip]
        let expected = vec![
            0x04,                   // RestrictType
            0x04,                   // RELOP_EQ
            0x03, 0x00, 0x07, 0x0E, // PidTagMessageFlags
            0x03, 0x00, 0x07, 0x0E, // TaggedValue's own tag
            0x01, 0x00, 0x00, 0x00, // the value
        ];
        assert_eq!(w.finish(), expected);
    }

    /// A value the wire cannot carry is refused rather than truncated — the same rule the property
    /// encoder follows, reached through a different path.
    #[test]
    fn a_value_that_cannot_be_encoded_is_refused() {
        let mut w = Writer::new();
        let bad = subject("ends\0early");
        assert!(
            Restriction::content(FuzzyLevel::full_string(), bad)
                .write(&mut w, ValueContext::Object)
                .is_err()
        );
    }
}
