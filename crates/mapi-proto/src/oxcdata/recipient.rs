//! Recipients: what kind each one is, and the `RecipientRow` that carries an address with no
//! directory behind it.
//!
//! Reading a message hands its recipient rows back **undecoded** — see
//! [`OpenRecipient`](crate::OpenRecipient) — because [MS-OXCDATA] §2.8.3.2's grammar is a bitfield
//! whose every field is conditional and nothing in reading a message needs it. Writing one is the
//! other way round: there is no way to address a message without producing that structure exactly,
//! so this is where it gets built.
//!
//! **Only the one-off form is built here**, deliberately. Every other `Type` in §2.8.3.1 names
//! something the address book holds, and the address book is NSPI — a separate endpoint and a
//! separate protocol this workspace does not implement. A one-off recipient needs no lookup at
//! all, which is what makes ordinary sending reachable from here.
//!
//! Three fields in the row are easy to get wrong and are stated here rather than left to the code:
//!
//! * **`AddressType` is ASCII whatever the `U` flag says.** §2.8.3.2 calls it "a null-terminated
//!   ASCII string" with no reference to `U`, while `EmailAddress` and `DisplayName` two paragraphs
//!   below are Unicode when `U` is set. Writing all three the same way shifts every field after the
//!   first.
//! * **`RecipientFlags` is a little-endian `u16`** with the masks §2.8.3.1 gives — settled by
//!   [MS-OXCMSG] §4.7.1's worked example, whose `51 06` is `0x0651` and matches all five flags its
//!   prose names. That is the opposite byte order from the one-off flag word in
//!   [`OneOffEntryId`](crate::OneOffEntryId), which is the same shape of bitfield in the same
//!   document.
//! * **A row with no columns still ends in a `PropertyRow`, and a `PropertyRow` is never empty.**
//!   §2.8.3.2 makes `RecipientProperties` a `PropertyRow` (§2.8.1) rather than an optional field,
//!   and every `PropertyRow` begins with a one-byte `Flag`. Leaving it out when
//!   `RecipientColumnCount` is zero costs one byte, which is enough: Exchange Server SE
//!   `15.02.2562.045` answers the whole `Execute` with `ecRpcFormat` (`0x000004B6`) — "the server
//!   is unable to parse the ROP requests in the ROP input buffer" ([MS-OXCROPS] §3.2.5.1) — rather
//!   than failing the ROP, so nothing in the response says which ROP was wrong. Measured, after
//!   exactly that.
//!
//! [MS-OXCDATA] §2.8.3 — `RecipientRow` structure
//! [MS-OXCMSG] §2.2.3.1.2 — `RecipientType`

use crate::error::Result;
use crate::oxcdata::OneOffEntryId;
use crate::wire::Writer;

/// `Type` = `NoType` (`0x0`), which is what a recipient the directory has never heard of is.
const TYPE_NO_TYPE: u16 = 0x0000;

/// `O` — this recipient has a non-standard address type, so `AddressType` is included.
///
/// Required by §2.8.3.2 for `AddressType` to be present at all when `Type` is `NoType`.
const FLAG_ADDRESS_TYPE: u16 = 0x8000;

/// `U` — `EmailAddress`, `DisplayName` and the rest are UTF-16LE with two-byte terminators.
const FLAG_UNICODE: u16 = 0x0200;

/// `S` — `TransmittableDisplayName` equals `DisplayName`, so `T` is clear and the field is absent.
const FLAG_SAME_TRANSMITTABLE: u16 = 0x0040;

/// `D` — `DisplayName` is included.
const FLAG_DISPLAY_NAME: u16 = 0x0010;

/// `E` — `EmailAddress` is included.
const FLAG_EMAIL_ADDRESS: u16 = 0x0008;

/// `Flag` `0x00` — a `StandardPropertyRow`, in which every value is present and none is an error.
///
/// [MS-OXCDATA] §2.8.1.1 — `StandardPropertyRow`
const STANDARD_PROPERTY_ROW: u8 = 0x00;

/// The flags every row this crate writes carries.
const ONE_OFF_FLAGS: u16 = FLAG_ADDRESS_TYPE
    | FLAG_UNICODE
    | FLAG_SAME_TRANSMITTABLE
    | FLAG_DISPLAY_NAME
    | FLAG_EMAIL_ADDRESS
    | TYPE_NO_TYPE;

/// What kind of recipient one row describes.
///
/// A bitwise OR of at most one value from the type table with any number of the resend flags, so
/// the type is the low nibble and the flags live above it.
///
/// [MS-OXCMSG] §2.2.3.1.2 — `RecipientType`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipientType(u8);

impl RecipientType {
    /// `0x03` — a blind carbon-copy recipient.
    pub const BLIND_CARBON_COPY: Self = Self(0x03);
    /// `0x02` — a carbon-copy recipient.
    pub const CARBON_COPY: Self = Self(0x02);
    /// `0x01` — a primary (To) recipient.
    pub const PRIMARY: Self = Self(0x01);

    /// Wraps the byte as received.
    #[must_use]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// The byte as the wire carries it, flags included.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// The type alone, with the resend flags masked off.
    ///
    /// The flags are `0x10` and `0x80` ([MS-OXCMSG] §2.2.3.1.2), so a `To` recipient that failed on
    /// a previous attempt arrives as `0x11` and would not compare equal to
    /// [`PRIMARY`](Self::PRIMARY) without this.
    #[must_use]
    pub const fn kind(self) -> Self {
        Self(self.0 & 0x0F)
    }

    /// The name of the kind, if it is one the document lists.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.kind() {
            Self::PRIMARY => "To",
            Self::CARBON_COPY => "Cc",
            Self::BLIND_CARBON_COPY => "Bcc",
            _ => return None,
        })
    }
}

impl core::fmt::Display for RecipientType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => f.pad(name),
            None => write!(f, "recipient type 0x{:02X}", self.0),
        }
    }
}

/// One recipient to put on a message, addressed with no directory lookup.
///
/// ```
/// use mapi_proto::Recipient;
///
/// let recipients = [
///     Recipient::to("Ada Lovelace", "ada@example.test")?,
///     Recipient::cc("Grace Hopper", "grace@example.test")?,
/// ];
/// assert_eq!(
///     recipients[0].to_string(),
///     "To: Ada Lovelace <ada@example.test>"
/// );
/// # Ok::<(), mapi_proto::Error>(())
/// ```
///
/// [MS-OXCDATA] §2.8.3.2 — `RecipientRow` structure
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Recipient {
    kind: RecipientType,
    address: OneOffEntryId,
}

impl Recipient {
    /// A primary (To) recipient.
    ///
    /// # Errors
    ///
    /// As [`smtp`](Self::smtp).
    pub fn to(display_name: impl Into<String>, email_address: impl Into<String>) -> Result<Self> {
        Self::smtp(RecipientType::PRIMARY, display_name, email_address)
    }

    /// A carbon-copy recipient.
    ///
    /// # Errors
    ///
    /// As [`smtp`](Self::smtp).
    pub fn cc(display_name: impl Into<String>, email_address: impl Into<String>) -> Result<Self> {
        Self::smtp(RecipientType::CARBON_COPY, display_name, email_address)
    }

    /// A blind carbon-copy recipient.
    ///
    /// # Errors
    ///
    /// As [`smtp`](Self::smtp).
    pub fn bcc(display_name: impl Into<String>, email_address: impl Into<String>) -> Result<Self> {
        Self::smtp(
            RecipientType::BLIND_CARBON_COPY,
            display_name,
            email_address,
        )
    }

    /// A recipient of the given kind, by SMTP address.
    ///
    /// # Errors
    ///
    /// [`Error::UnencodableValue`](crate::Error::UnencodableValue) if either string holds an
    /// interior NUL — see [`OneOffEntryId::smtp`].
    pub fn smtp(
        kind: RecipientType,
        display_name: impl Into<String>,
        email_address: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            kind,
            address: OneOffEntryId::smtp(display_name, email_address)?,
        })
    }

    /// Whether this is a To, Cc or Bcc recipient.
    #[must_use]
    pub const fn kind(&self) -> RecipientType {
        self.kind
    }

    /// The address, as the identifier that is the whole of what is known about it.
    #[must_use]
    pub const fn address(&self) -> &OneOffEntryId {
        &self.address
    }

    /// Writes the `RecipientRow` — everything after `RecipientRowSize`.
    ///
    /// `RecipientColumnCount` is zero because every property a one-off recipient has is already one
    /// of the row's own fields, and [MS-OXCMSG] §2.2.3.5.1 forbids naming those in
    /// `RecipientColumns` anyway. The `PropertyRow` after it is still there — a
    /// `StandardPropertyRow` whose `Flag` is `0x00` and whose `ValueArray` is empty. See the
    /// module documentation for what omitting that one byte costs.
    ///
    /// [MS-OXCDATA] §2.8.1 — `PropertyRow` structure
    pub(crate) fn write_row(&self, w: &mut Writer) {
        // `AddressType` is ASCII whatever `U` says. See the module documentation.
        w.u16(ONE_OFF_FLAGS).ascii_z(self.address.address_type());
        w.utf16_z(self.address.email_address())
            .utf16_z(self.address.display_name())
            .u16(0)
            .u8(STANDARD_PROPERTY_ROW);
    }
}

impl core::fmt::Display for Recipient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}: {} <{}>",
            self.kind,
            self.address.display_name(),
            self.address.email_address()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_kinds_are_the_values_the_document_lists() {
        for (kind, raw, name) in [
            (RecipientType::PRIMARY, 0x01, "To"),
            (RecipientType::CARBON_COPY, 0x02, "Cc"),
            (RecipientType::BLIND_CARBON_COPY, 0x03, "Bcc"),
        ] {
            assert_eq!(kind.as_u8(), raw);
            assert_eq!(RecipientType::new(raw), kind);
            assert_eq!(kind.name(), Some(name));
            assert_eq!(kind.to_string(), name);
        }
    }

    /// A recipient that failed on a previous attempt arrives with `0x10` set, and comparing the
    /// whole byte would call it an unknown kind.
    #[test]
    fn the_resend_flags_are_not_part_of_the_kind() {
        let resent = RecipientType::new(0x11);
        assert_eq!(resent.kind(), RecipientType::PRIMARY);
        assert_eq!(resent.name(), Some("To"));
        assert_eq!(resent.as_u8(), 0x11);

        let unknown = RecipientType::new(0x07);
        assert_eq!(unknown.name(), None);
        assert_eq!(unknown.to_string(), "recipient type 0x07");
    }

    /// The flags, spelled out against [MS-OXCDATA] §2.8.3.1's masks rather than against the
    /// constant that produces them.
    #[test]
    fn the_row_flags_say_exactly_which_fields_follow() {
        assert_eq!(ONE_OFF_FLAGS & 0x0007, 0x0000, "Type is NoType");
        assert_eq!(ONE_OFF_FLAGS & 0x8000, 0x8000, "O: AddressType is present");
        assert_eq!(ONE_OFF_FLAGS & 0x0200, 0x0200, "U: strings are Unicode");
        assert_eq!(ONE_OFF_FLAGS & 0x0010, 0x0010, "D: DisplayName is present");
        assert_eq!(ONE_OFF_FLAGS & 0x0008, 0x0008, "E: EmailAddress is present");
        assert_eq!(
            ONE_OFF_FLAGS & 0x0020,
            0x0000,
            "T is clear, because S says the two names are equal"
        );
        assert_eq!(ONE_OFF_FLAGS & 0x0400, 0x0000, "I: no SimpleDisplayName");
    }

    /// `AddressType` is the one string in the row that stays 8-bit. Writing it as UTF-16 would
    /// shift the address and the display name, and the server would store somebody else.
    #[test]
    fn the_address_type_is_ascii_and_the_two_names_are_not() {
        let mut w = Writer::new();
        Recipient::to("Ada", "a@b.test")
            .expect("a recipient")
            .write_row(&mut w);
        let bytes = w.finish();

        let mut expected = Vec::new();
        expected.extend_from_slice(&ONE_OFF_FLAGS.to_le_bytes());
        expected.extend_from_slice(b"SMTP\0");
        expected.extend("a@b.test".encode_utf16().flat_map(u16::to_le_bytes));
        expected.extend_from_slice(&[0x00, 0x00]);
        expected.extend("Ada".encode_utf16().flat_map(u16::to_le_bytes));
        expected.extend_from_slice(&[0x00, 0x00]);
        // RecipientColumnCount, then the StandardPropertyRow flag that follows it whatever that
        // count is.
        expected.extend_from_slice(&[0x00, 0x00, 0x00]);

        assert_eq!(bytes, expected);
    }

    /// The byte the row cannot do without.
    ///
    /// [MS-OXCDATA] §2.8.3.2 makes `RecipientProperties` a `PropertyRow` rather than an optional
    /// field, and §2.8.1.1 gives every `PropertyRow` a leading `Flag`. Dropping it when there are
    /// no columns makes the *whole* `Execute` unparsable — `ecRpcFormat`, with nothing in the
    /// response naming the ROP that was wrong.
    #[test]
    fn a_row_with_no_columns_still_ends_in_a_property_row() {
        let mut w = Writer::new();
        Recipient::to("Ada", "a@b.test")
            .expect("a recipient")
            .write_row(&mut w);
        let bytes = w.finish();

        assert_eq!(
            bytes.get(bytes.len().saturating_sub(3)..),
            Some(&[0x00, 0x00, STANDARD_PROPERTY_ROW][..])
        );
    }

    #[test]
    fn each_constructor_sets_the_kind_it_names() {
        assert_eq!(
            Recipient::to("A", "a@b.test").expect("to").kind(),
            RecipientType::PRIMARY
        );
        assert_eq!(
            Recipient::cc("A", "a@b.test").expect("cc").kind(),
            RecipientType::CARBON_COPY
        );
        let bcc = Recipient::bcc("A", "a@b.test").expect("bcc");
        assert_eq!(bcc.kind(), RecipientType::BLIND_CARBON_COPY);
        assert_eq!(bcc.address().email_address(), "a@b.test");
        assert_eq!(bcc.to_string(), "Bcc: A <a@b.test>");

        assert!(Recipient::to("A\0B", "a@b.test").is_err());
    }
}
