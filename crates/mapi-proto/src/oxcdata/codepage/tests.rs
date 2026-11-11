use super::*;

fn page(id: u16) -> CodePage {
    CodePage::new(id).unwrap()
}

/// The bytes Exchange Server SE `15.02.2562.056` sent for the subject `Café € ž При 日本` read as
/// `PtypString8`, under a session connected with code page 1252 and then with 1251. Characters the
/// code page cannot hold arrive as `?`, which is the server's conversion, not this decoder's.
#[test]
fn what_the_lab_sent_decodes_to_what_was_written() {
    let western = [
        0x43, 0x61, 0x66, 0xE9, 0x20, 0x80, 0x20, 0x9E, 0x20, 0x3F, 0x3F, 0x3F,
    ];
    assert_eq!(
        CodePage::WINDOWS_1252.decode(&western).as_deref(),
        Some("Café € ž ???")
    );

    // 1251 has no é or ž, and Exchange substituted the nearest letters it does have.
    let cyrillic = [
        0x43, 0x61, 0x66, 0x65, 0x20, 0x88, 0x20, 0x7A, 0x20, 0xCF, 0xF0, 0xE8,
    ];
    assert_eq!(
        page(1251).decode(&cyrillic).as_deref(),
        Some("Cafe € z При")
    );
}

/// `0x80` is the byte that tells Windows-1252 from Latin-1, which is what this crate used to read
/// 8-bit text as: the euro sign in one, a C1 control in the other.
#[test]
fn windows_1252_is_not_latin_1() {
    assert_eq!(CodePage::WINDOWS_1252.decode(&[0x80]).as_deref(), Some("€"));
    assert_eq!(page(28591).decode(&[0x80]).as_deref(), Some("\u{80}"));
    assert_eq!(page(28591).decode(&[0xE9]).as_deref(), Some("é"));
}

/// The multibyte Windows code pages, two characters each.
#[test]
fn the_multibyte_pages_decode_their_own_characters() {
    assert_eq!(
        page(932).decode(&[0x93, 0xFA, 0x96, 0x7B]).as_deref(),
        Some("日本")
    );
    assert_eq!(
        page(936).decode(&[0xD6, 0xD0, 0xCE, 0xC4]).as_deref(),
        Some("中文")
    );
    assert_eq!(
        page(949).decode(&[0xC7, 0xD1, 0xB1, 0xB9]).as_deref(),
        Some("한국")
    );
    assert_eq!(
        page(950).decode(&[0xA4, 0xA4, 0xA4, 0xE5]).as_deref(),
        Some("中文")
    );
    assert_eq!(page(65001).decode("é".as_bytes()).as_deref(), Some("é"));
}

/// Bytes that are not text in their code page are refused, never handed back with replacement
/// characters in them.
#[test]
fn bytes_that_are_not_text_are_refused() {
    // A Shift_JIS lead byte with nothing after it.
    assert_eq!(page(932).decode(&[0x93]), None);
    assert_eq!(page(65001).decode(&[0xC3]), None);
    assert_eq!(page(20127).decode(&[0x41, 0x80]), None);
    assert_eq!(page(20127).decode(b"ASCII").as_deref(), Some("ASCII"));

    let tag = PropertyTag::new(0x0037_001E);
    assert_eq!(
        page(932).decode_property(tag, &[0x93]),
        Err(Error::UndecodableString {
            tag,
            code_page: 932,
            reason: "the bytes are not text in that code page",
        })
    );
    assert_eq!(
        page(932).decode_property(tag, &[0x93, 0xFA]).as_deref(),
        Ok("\u{65E5}")
    );
}

/// A code page with no decoder cannot be constructed, so nothing can be configured with one.
#[test]
fn a_code_page_without_a_decoder_is_refused() {
    for id in [0, 437, 1200, 1201, 28599, 50222, 65000] {
        assert_eq!(
            CodePage::new(id),
            Err(Error::UnsupportedCodePage { code_page: id }),
            "{id}"
        );
    }
    assert_eq!(CodePage::try_from(1252), Ok(CodePage::WINDOWS_1252));
    assert_eq!(CodePage::WINDOWS_1252.as_u16(), 1252);
    assert_eq!(page(1251).to_string(), "code page 1251");
}

/// Every identifier the decoder table names constructs, and decodes ASCII as itself.
#[test]
fn every_supported_page_reads_ascii() {
    let supported: Vec<u16> = (0..=u16::MAX)
        .filter(|&id| CodePage::new(id).is_ok())
        .collect();
    assert_eq!(supported.len(), 36, "{supported:?}");
    for id in supported {
        // ISO-2022-JP is the one stateful page; plain ASCII is still itself in it.
        assert_eq!(
            page(id).decode(b"Subject").as_deref(),
            Some("Subject"),
            "{id}"
        );
    }
}
