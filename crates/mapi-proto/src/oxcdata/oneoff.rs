//! One-off entry ids: naming a recipient that is not in the directory.
//!
//! Every other way of addressing somebody goes through the address book — NSPI, a separate
//! endpoint and a separate protocol this workspace does not implement at all. A One-Off `EntryID`
//! is the alternative: **all the information about the recipient is inside the identifier**, so an
//! SMTP address can be used with no lookup of any kind.
//!
//! That is what makes it worth having here twice over. It is how a contact's electronic address is
//! recorded ([MS-OXOCNTC] §2.2.1.2.5, `PidLidEmail1OriginalEntryId`), and it is the shape a
//! recipient takes when nothing has resolved it.
//!
//! # The flag word is the one field here that is not little-endian
//!
//! [MS-OXCDATA] §2.2.5.1's diagram and its prose masks only agree if the two flag bytes are read
//! **big-endian**, which is the opposite of §2.8.3.1's `RecipientFlags` — a bitfield of the same
//! shape, in the same document, drawn in the other byte order. Nothing says so, and reading it the
//! usual way does not fail: it produces a value whose two reserved fields are set and whose `U`
//! bit is clear, so a decoder would then read plainly UTF-16LE strings as 8-bit ones.
//!
//! Settled by measurement rather than by reading. Exchange Server SE `15.02.2562.045` answered
//! `PidLidEmail1OriginalEntryId` on a contact holding `ada@example.test` with a flag word of
//! `01 80`, whose strings are visibly UTF-16LE. Read big-endian that is `M` (pure MIME) and `U`
//! (Unicode) with every reserved bit zero; read little-endian it is `0x8001`, which sets both
//! reserved fields and clears `U`.
//!
//! [MS-OXCDATA] §2.2.5.1 — One-Off `EntryID` structure

use crate::error::{Error, Result};
use crate::oxcdata::Guid;
use crate::wire::{Reader, Writer};

/// `ProviderUID`, which [MS-OXCDATA] §2.2.5.1 fixes for every one-off `EntryID` ever written.
///
/// [MS-OXCDATA] §2.2.4 gives the same sixteen bytes as the provider of a "one-off recipient".
const ONE_OFF_PROVIDER: [u8; 16] = [
    0x81, 0x2B, 0x1F, 0xA4, 0xBE, 0xA3, 0x10, 0x19, 0x9D, 0x6E, 0x00, 0xDD, 0x01, 0x0F, 0x54, 0x02,
];

/// `Version`, `0x0000`.
const VERSION: u16 = 0x0000;

/// The first flag byte: `Pad(1) MAE(2) Format(4) M(1)`.
///
/// `M` alone, which is "send this recipient pure MIME rather than TNEF", with no Macintosh
/// encoding and no message format named. Exactly what Exchange writes — see the module
/// documentation.
const FLAGS_HIGH_MIME: u8 = 0x01;

/// The second flag byte: `U(1) R(2) L(1) Pad(4)`.
///
/// `U` alone: the three strings that follow are UTF-16LE with two-byte terminators, and the server
/// may look the address up in the address book.
const FLAGS_LOW_UNICODE: u8 = 0x80;

/// `U`, within the second flag byte.
const UNICODE_BIT: u8 = 0x80;

/// How many bytes precede the first string: `Flags(4) ProviderUID(16) Version(2) Flags(2)`.
const HEADER_BYTES: usize = 24;

/// The address type an SMTP address has, and the only one this crate writes by itself.
///
/// [MS-OXOABK] §2.2.3.13 — `PidTagAddressType`
pub const SMTP_ADDRESS_TYPE: &str = "SMTP";

/// A recipient that exists nowhere but in this identifier.
///
/// Three strings and a provider that says "there is nothing to look up". Building one costs no
/// round trip, which is the whole point: the alternative is the address book endpoint, which is a
/// different protocol.
///
/// ```
/// use mapi_proto::OneOffEntryId;
///
/// let one_off = OneOffEntryId::smtp("Ada Lovelace", "ada@example.test")?;
/// assert_eq!(one_off.email_address(), "ada@example.test");
/// assert_eq!(one_off.address_type(), "SMTP");
/// # Ok::<(), mapi_proto::Error>(())
/// ```
///
/// [MS-OXCDATA] §2.2.5.1 — One-Off `EntryID` structure
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OneOffEntryId {
    display_name: String,
    address_type: String,
    email_address: String,
}

impl OneOffEntryId {
    /// Names a recipient by SMTP address.
    ///
    /// # Errors
    ///
    /// [`Error::UnencodableValue`] if any of the strings holds an interior NUL, which would end its
    /// own field early and shift every field after it — so the server would read a *different*
    /// address rather than report a problem.
    pub fn smtp(display_name: impl Into<String>, email_address: impl Into<String>) -> Result<Self> {
        Self::new(display_name, SMTP_ADDRESS_TYPE, email_address)
    }

    /// Names a recipient by an address type this crate does not fix.
    ///
    /// # Errors
    ///
    /// As [`smtp`](Self::smtp).
    pub fn new(
        display_name: impl Into<String>,
        address_type: impl Into<String>,
        email_address: impl Into<String>,
    ) -> Result<Self> {
        let one_off = Self {
            display_name: display_name.into(),
            address_type: address_type.into(),
            email_address: email_address.into(),
        };
        if one_off.strings().iter().any(|field| field.contains('\0')) {
            return Err(Error::UnencodableValue {
                value: "a one-off entry id string",
                reason: "the NUL would terminate the field early and shift every field after it, \
                         which the server reads as a different address rather than as an error",
            });
        }
        Ok(one_off)
    }

    /// What a person sees.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The address type — [`SMTP_ADDRESS_TYPE`] for anything this crate builds.
    #[must_use]
    pub fn address_type(&self) -> &str {
        &self.address_type
    }

    /// The address itself.
    #[must_use]
    pub fn email_address(&self) -> &str {
        &self.email_address
    }

    /// The identifier as the wire carries it.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        // The two flag bytes are written a byte at a time rather than as a `u16`, because they are
        // *not* a little-endian word. See the module documentation.
        w.u32(0).bytes(&ONE_OFF_PROVIDER).u16(VERSION);
        w.u8(FLAGS_HIGH_MIME).u8(FLAGS_LOW_UNICODE);
        w.utf16_z(&self.display_name)
            .utf16_z(&self.address_type)
            .utf16_z(&self.email_address);
        w.finish()
    }

    /// Reads one back.
    ///
    /// Both string widths are handled, because the `U` bit says which and a client does not choose
    /// what a server sent. What this does *not* do is guess a code page: an 8-bit one-off is
    /// decoded byte-for-codepoint, which is Latin-1 and is said here rather than presented as a
    /// decode.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEntryId`] if the value is too short to hold the fixed header, if its `Flags`
    /// are non-zero — which marks a short-term `EntryID`, and [MS-OXCDATA] §2.2.5.1 has those four
    /// bytes zero in anything stored in a property — or if its `ProviderUID` is not the one-off
    /// provider. The last is the check worth having: an address book `EntryID` is the same shape
    /// with a different provider, and reading one as this would report a directory user as a
    /// one-off.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let length = bytes.len();
        if length < HEADER_BYTES {
            return Err(Error::InvalidEntryId {
                length,
                reason: "a one-off entry id is at least 24 bytes before its first string",
            });
        }

        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Error::InvalidEntryId {
                length,
                reason: "non-zero Flags mark a short-term entry id, which a stored \
                         property may not hold",
            });
        }
        if r.array::<16>()? != ONE_OFF_PROVIDER {
            return Err(Error::InvalidEntryId {
                length,
                reason: "the ProviderUID is not the one-off provider, so this identifier names \
                         something the directory holds",
            });
        }
        let _version = r.u16()?;
        let _high = r.u8()?;
        let unicode = r.u8()? & UNICODE_BIT != 0;

        let read = |r: &mut Reader<'_>| -> Result<String> {
            if unicode {
                r.utf16_z()
            } else {
                Ok(r.bytes_z()?.iter().copied().map(char::from).collect())
            }
        };
        Ok(Self {
            display_name: read(&mut r)?,
            address_type: read(&mut r)?,
            email_address: read(&mut r)?,
        })
    }

    fn strings(&self) -> [&str; 3] {
        [&self.display_name, &self.address_type, &self.email_address]
    }
}

impl core::fmt::Display for OneOffEntryId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} <{}:{}>",
            self.display_name, self.address_type, self.email_address
        )
    }
}

/// The provider that marks an identifier as naming a one-off recipient.
///
/// Exposed so that a caller holding a `PidTagEntryId` can tell a one-off from a directory entry
/// without parsing either.
#[must_use]
pub fn one_off_provider() -> Guid {
    Guid::from_bytes(ONE_OFF_PROVIDER)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes Exchange Server SE `15.02.2562.045` wrote into `PidLidEmail1OriginalEntryId` for a
    /// contact seeded through EWS with the address `ada@example.test`, taken verbatim.
    ///
    /// This is the whole reason the flag word is written a byte at a time: `01 80` read as a
    /// little-endian `u16` is `0x8001`, which sets both of the structure's reserved fields and
    /// clears the `U` bit — and the strings after it are visibly UTF-16LE.
    const MEASURED: [u8; 102] = [
        0x00, 0x00, 0x00, 0x00, 0x81, 0x2B, 0x1F, 0xA4, 0xBE, 0xA3, 0x10, 0x19, 0x9D, 0x6E, 0x00,
        0xDD, 0x01, 0x0F, 0x54, 0x02, 0x00, 0x00, 0x01, 0x80, 0x61, 0x00, 0x64, 0x00, 0x61, 0x00,
        0x40, 0x00, 0x65, 0x00, 0x78, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x70, 0x00, 0x6C, 0x00, 0x65,
        0x00, 0x2E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x00, 0x00, 0x53, 0x00,
        0x4D, 0x00, 0x54, 0x00, 0x50, 0x00, 0x00, 0x00, 0x61, 0x00, 0x64, 0x00, 0x61, 0x00, 0x40,
        0x00, 0x65, 0x00, 0x78, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x70, 0x00, 0x6C, 0x00, 0x65, 0x00,
        0x2E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn what_this_writes_is_what_the_server_wrote() {
        let one_off =
            OneOffEntryId::smtp("ada@example.test", "ada@example.test").expect("no interior NUL");
        assert_eq!(one_off.to_bytes(), MEASURED.to_vec());
    }

    #[test]
    fn a_measured_identifier_reads_back_to_what_it_says() {
        let parsed = OneOffEntryId::parse(&MEASURED).expect("the server's own bytes");
        assert_eq!(parsed.display_name(), "ada@example.test");
        assert_eq!(parsed.address_type(), "SMTP");
        assert_eq!(parsed.email_address(), "ada@example.test");
        assert_eq!(
            parsed.to_string(),
            "ada@example.test <SMTP:ada@example.test>"
        );
    }

    #[test]
    fn every_identifier_this_writes_reads_back_unchanged() {
        let one_off = OneOffEntryId::smtp("Ada Lovelace", "ada@example.test").expect("a name");
        assert_eq!(
            OneOffEntryId::parse(&one_off.to_bytes()).expect("its own bytes"),
            one_off
        );
    }

    /// An 8-bit one-off is what a server that cleared the `U` bit would send. Nothing here writes
    /// one; reading it is what keeps "the server sent MBCS" from arriving as an error.
    #[test]
    fn an_eight_bit_identifier_decodes_byte_for_codepoint() {
        let mut bytes = vec![0_u8; 4];
        bytes.extend_from_slice(&ONE_OFF_PROVIDER);
        bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]);
        bytes.extend_from_slice(b"caf\xE9\0SMTP\0a@b.test\0");

        let parsed = OneOffEntryId::parse(&bytes).expect("an MBCS one-off");
        assert_eq!(parsed.display_name(), "caf\u{E9}");
        assert_eq!(parsed.email_address(), "a@b.test");
    }

    /// The check that keeps a directory user from being reported as a one-off: an address book
    /// `EntryID` is the same shape with a different provider.
    #[test]
    fn an_identifier_from_another_provider_is_refused() {
        let mut bytes = MEASURED.to_vec();
        if let Some(byte) = bytes.get_mut(4) {
            *byte = 0xDC;
        }
        assert!(matches!(
            OneOffEntryId::parse(&bytes),
            Err(Error::InvalidEntryId { .. })
        ));

        let mut short_term = MEASURED.to_vec();
        if let Some(byte) = short_term.first_mut() {
            *byte = 0x01;
        }
        assert!(matches!(
            OneOffEntryId::parse(&short_term),
            Err(Error::InvalidEntryId { .. })
        ));

        assert!(matches!(
            OneOffEntryId::parse(&[0x00; 8]),
            Err(Error::InvalidEntryId { length: 8, .. })
        ));
        assert_eq!(one_off_provider(), Guid::from_bytes(ONE_OFF_PROVIDER));
    }

    /// An interior NUL would end its field early and shift the two after it, so the server would
    /// read a different address rather than fail.
    #[test]
    fn a_string_with_an_interior_nul_is_refused_rather_than_truncated() {
        assert!(OneOffEntryId::smtp("Ada\0Lovelace", "ada@example.test").is_err());
        assert!(OneOffEntryId::smtp("Ada", "ada\0@example.test").is_err());
        assert!(OneOffEntryId::new("Ada", "SM\0TP", "ada@example.test").is_err());
    }

    #[test]
    fn truncated_identifiers_never_panic() {
        for length in 0..MEASURED.len() {
            let _ = OneOffEntryId::parse(MEASURED.get(..length).unwrap_or_default());
        }
    }
}
