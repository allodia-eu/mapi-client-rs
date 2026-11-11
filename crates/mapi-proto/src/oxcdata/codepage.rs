//! Code pages: what an 8-bit string's bytes mean.
//!
//! **An 8-bit MAPI string carries no encoding of its own.** A `PtypString8` value is "in a
//! specific 8-bit or MBCS code page" ([MS-OXCDATA] §2.11.1.2), and which one is said somewhere
//! else: by the code page the client sent at `Connect`, for a ROP buffer, or by the property type
//! itself, for a `FastTransfer` stream's code-page string types ([MS-OXCFXICS] §2.2.4.1.1.1). The
//! bytes alone cannot tell Windows-1252 from Windows-1251, and reading either as UTF-8 or Latin-1
//! turns `€` and every Cyrillic letter into something else without a word.
//!
//! So a [`CodePage`] is a type, and only a code page this crate can decode can be one. The
//! decoders are the WHATWG Encoding Standard's, through `encoding_rs`, which is what browsers use
//! for the same Windows code pages and what their tables were reconciled against.
//!
//! [MS-OXCDATA] §2.11.1.2 — string property values
//! [MS-OXCMAPIHTTP] §2.2.4.1.1 — `DefaultCodePage`

use encoding_rs::Encoding;

use crate::error::{Error, Result};
use crate::oxcdata::PropertyTag;

/// A Windows code page that 8-bit and multibyte strings are written in.
///
/// Constructed only through [`new`](Self::new), which refuses a code page this crate cannot
/// decode, so that [`decode`](Self::decode) has only one way to fail: bytes that are not text in
/// this code page at all.
///
/// The supported set is every Windows ANSI code page (874, 932, 936, 949, 950 and 1250–1258);
/// ISO 8859-1, and the parts of ISO 8859 the Encoding Standard decodes as themselves (2–8, 13, 15);
/// KOI8-R and KOI8-U; the Mac and OEM pages it keeps (10000, 10007, 866); UTF-8 (65001); EUC-JP
/// (51932) and the two ISO-2022-JP pages it can read (50220, 50221); GB 18030; and US-ASCII.
///
/// Left out on purpose: ISO 8859-9 and -11, which the standard reads as Windows-1254 and -874
/// and so differently in `0x80`–`0x9F`; and 50222, whose shift-out half-width katakana the
/// standard's ISO-2022-JP decoder refuses.
///
/// [MS-OXCDATA] §2.11.1.2 — string property values
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodePage(u16);

/// How a supported code page is decoded.
enum Decoder {
    /// One of the Encoding Standard's decoders.
    Whatwg(&'static Encoding),
    /// ISO 8859-1 as Windows defines it: every byte is the codepoint of the same value. Not the
    /// Encoding Standard's `iso-8859-1`, which is Windows-1252 under another name and would read
    /// `0x80` as `€`.
    Latin1,
    /// US-ASCII: seven bits, and a byte with the eighth set is not text.
    Ascii,
}

impl CodePage {
    /// Windows-1252, Western European: the code page this crate's sessions connect with unless
    /// told otherwise.
    pub const WINDOWS_1252: Self = Self(1252);

    /// A code page by its Windows identifier.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCodePage`] for an identifier this crate has no decoder for — an OEM
    /// page such as 437, an EBCDIC one, or a number that names nothing. Refused here, rather than
    /// when a string arrives, so that a session cannot be configured with a code page whose strings
    /// it would then be unable to read.
    pub fn new(id: u16) -> Result<Self> {
        let page = Self(id);
        match page.decoder() {
            Some(_) => Ok(page),
            None => Err(Error::UnsupportedCodePage { code_page: id }),
        }
    }

    /// The Windows identifier, as the wire carries it.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Decodes bytes written in this code page.
    ///
    /// `None` when the bytes are not text in this code page: a multibyte page's lead byte with no
    /// trail byte, a byte US-ASCII does not define, UTF-8 that is not UTF-8. Never a string with
    /// replacement characters standing in for what could not be read — a caller handed one could
    /// not tell it from a string that really holds `U+FFFD`.
    ///
    /// ```
    /// use mapi_proto::CodePage;
    ///
    /// let cyrillic = CodePage::new(1251).unwrap();
    /// assert_eq!(cyrillic.decode(&[0xCF, 0xF0, 0xE8]).as_deref(), Some("При"));
    /// // The same three bytes in the code page sessions default to.
    /// assert_eq!(
    ///     CodePage::WINDOWS_1252
    ///         .decode(&[0xCF, 0xF0, 0xE8])
    ///         .as_deref(),
    ///     Some("Ïðè")
    /// );
    /// ```
    #[must_use]
    pub fn decode(self, bytes: &[u8]) -> Option<String> {
        match self.decoder()? {
            Decoder::Whatwg(encoding) => encoding
                .decode_without_bom_handling_and_without_replacement(bytes)
                .map(std::borrow::Cow::into_owned),
            Decoder::Latin1 => Some(bytes.iter().copied().map(char::from).collect()),
            Decoder::Ascii => bytes
                .is_ascii()
                .then(|| bytes.iter().copied().map(char::from).collect()),
        }
    }

    /// Decodes the value of property `tag`, written in this code page.
    ///
    /// [`decode`](Self::decode), with the refusal turned into the error every reader of a property
    /// value reports it as.
    ///
    /// # Errors
    ///
    /// [`Error::UndecodableString`] naming `tag` and this code page, if the bytes are not text in
    /// it.
    pub fn decode_property(self, tag: PropertyTag, bytes: &[u8]) -> Result<String> {
        self.decode(bytes).ok_or(Error::UndecodableString {
            tag,
            code_page: self.0,
            reason: "the bytes are not text in that code page",
        })
    }

    /// The decoder for this code page, if there is one.
    ///
    /// Windows identifiers, mapped to the Encoding Standard's encodings by the identifiers its
    /// index pages name. Where the standard folds a Windows page into a superset — 936 into GBK,
    /// 949 into the extended EUC-KR that is Windows' own 949, 932 into the `Shift_JIS` that is
    /// Windows-31J — the superset decodes every byte sequence the page itself defines to the same
    /// characters.
    const fn decoder(self) -> Option<Decoder> {
        Some(Decoder::Whatwg(match self.0 {
            866 => encoding_rs::IBM866,
            874 => encoding_rs::WINDOWS_874,
            932 => encoding_rs::SHIFT_JIS,
            936 => encoding_rs::GBK,
            949 => encoding_rs::EUC_KR,
            950 => encoding_rs::BIG5,
            1250 => encoding_rs::WINDOWS_1250,
            1251 => encoding_rs::WINDOWS_1251,
            1252 => encoding_rs::WINDOWS_1252,
            1253 => encoding_rs::WINDOWS_1253,
            1254 => encoding_rs::WINDOWS_1254,
            1255 => encoding_rs::WINDOWS_1255,
            1256 => encoding_rs::WINDOWS_1256,
            1257 => encoding_rs::WINDOWS_1257,
            1258 => encoding_rs::WINDOWS_1258,
            10000 => encoding_rs::MACINTOSH,
            10007 => encoding_rs::X_MAC_CYRILLIC,
            20866 => encoding_rs::KOI8_R,
            21866 => encoding_rs::KOI8_U,
            28592 => encoding_rs::ISO_8859_2,
            28593 => encoding_rs::ISO_8859_3,
            28594 => encoding_rs::ISO_8859_4,
            28595 => encoding_rs::ISO_8859_5,
            28596 => encoding_rs::ISO_8859_6,
            28597 => encoding_rs::ISO_8859_7,
            28598 => encoding_rs::ISO_8859_8,
            28603 => encoding_rs::ISO_8859_13,
            28605 => encoding_rs::ISO_8859_15,
            38598 => encoding_rs::ISO_8859_8_I,
            50220 | 50221 => encoding_rs::ISO_2022_JP,
            51932 => encoding_rs::EUC_JP,
            54936 => encoding_rs::GB18030,
            65001 => encoding_rs::UTF_8,
            20127 => return Some(Decoder::Ascii),
            28591 => return Some(Decoder::Latin1),
            _ => return None,
        }))
    }
}

impl core::fmt::Display for CodePage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "code page {}", self.0)
    }
}

impl TryFrom<u16> for CodePage {
    type Error = Error;

    fn try_from(id: u16) -> Result<Self> {
        Self::new(id)
    }
}

#[cfg(test)]
mod tests;
