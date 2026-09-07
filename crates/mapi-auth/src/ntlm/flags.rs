//! The `NegotiateFlags` field the three NTLM messages all carry.
//!
//! [MS-NLMP] §2.2.2.5 — `NEGOTIATE`

/// The options a message declares.
///
/// [MS-NLMP] draws this field as thirty-two lettered bits rather than as a table of names, which
/// makes a transcription error invisible. Every value here is therefore checked against the
/// document's own worked example: §4.2.4 prints a `CHALLENGE_MESSAGE` carrying `0xE28A8233` and
/// names the thirteen flags that make it up, and
/// `the_documented_example_decomposes_into_its_named_flags` adds them back up.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct NegotiateFlags(u32);

/// Every flag with a name, for rendering a set of them.
///
/// This is also what keeps the constants above honest about being a complete transcription of
/// §2.2.2.5 rather than the subset this crate happens to use: a flag that is named but never
/// referenced anywhere is a flag nobody checked.
const NAMED: [(NegotiateFlags, &str); 18] = [
    (NegotiateFlags::UNICODE, "UNICODE"),
    (NegotiateFlags::OEM, "OEM"),
    (NegotiateFlags::REQUEST_TARGET, "REQUEST_TARGET"),
    (NegotiateFlags::SIGN, "SIGN"),
    (NegotiateFlags::SEAL, "SEAL"),
    (NegotiateFlags::LM_KEY, "LM_KEY"),
    (NegotiateFlags::NTLM, "NTLM"),
    (NegotiateFlags::ANONYMOUS, "ANONYMOUS"),
    (NegotiateFlags::ALWAYS_SIGN, "ALWAYS_SIGN"),
    (NegotiateFlags::TARGET_TYPE_DOMAIN, "TARGET_TYPE_DOMAIN"),
    (NegotiateFlags::TARGET_TYPE_SERVER, "TARGET_TYPE_SERVER"),
    (
        NegotiateFlags::EXTENDED_SESSIONSECURITY,
        "EXTENDED_SESSIONSECURITY",
    ),
    (
        NegotiateFlags::REQUEST_NON_NT_SESSION_KEY,
        "REQUEST_NON_NT_SESSION_KEY",
    ),
    (NegotiateFlags::TARGET_INFO, "TARGET_INFO"),
    (NegotiateFlags::VERSION, "VERSION"),
    (NegotiateFlags::NEGOTIATE_128, "NEGOTIATE_128"),
    (NegotiateFlags::KEY_EXCH, "KEY_EXCH"),
    (NegotiateFlags::NEGOTIATE_56, "NEGOTIATE_56"),
];

/// Names the flags that are set, which is what somebody debugging a 401 actually wants to read.
///
/// A bare `0xE28A8233` in a log is a number to go and look up; the names are the answer to the
/// question that was being asked.
impl core::fmt::Debug for NegotiateFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#010X}", self.0)?;
        let mut first = true;
        for (flag, name) in NAMED {
            if !self.contains(flag) {
                continue;
            }
            f.write_str(if first { " (" } else { " | " })?;
            f.write_str(name)?;
            first = false;
        }
        if first { Ok(()) } else { f.write_str(")") }
    }
}

impl NegotiateFlags {
    /// A session key exists whether or not signing was asked for, which is what the MIC needs.
    pub(crate) const ALWAYS_SIGN: Self = Self(0x0000_8000);
    /// The client is authenticating anonymously.
    pub(crate) const ANONYMOUS: Self = Self(0x0000_0800);
    /// NTLM v2 session security. Required for the responses this crate computes.
    pub(crate) const EXTENDED_SESSIONSECURITY: Self = Self(0x0008_0000);
    /// The session key is exchanged rather than derived, which needs RC4 to unwrap.
    pub(crate) const KEY_EXCH: Self = Self(0x4000_0000);
    /// The LM session key is requested. Mutually exclusive with extended session security.
    pub(crate) const LM_KEY: Self = Self(0x0000_0080);
    /// 128-bit encryption. Only meaningful alongside signing or sealing.
    pub(crate) const NEGOTIATE_128: Self = Self(0x2000_0000);
    /// 56-bit encryption. Only meaningful alongside signing or sealing.
    pub(crate) const NEGOTIATE_56: Self = Self(0x8000_0000);
    /// NTLM authentication, as opposed to the older LM.
    pub(crate) const NTLM: Self = Self(0x0000_0200);
    /// Strings in this exchange are OEM. Never set by this crate.
    pub(crate) const OEM: Self = Self(0x0000_0002);
    /// What this crate asks for, and deliberately does not.
    ///
    /// Four flags are absent on purpose, and each absence removes work rather than capability:
    ///
    /// * **`SIGN` and `SEAL`** — NTLM's own message integrity and confidentiality. HTTP does not
    ///   carry them, and the connection is TLS, which is what `mapi-client` enforces by refusing a
    ///   plaintext endpoint.
    /// * **`KEY_EXCH`** — without `SIGN` or `SEAL` there is no key to exchange. [MS-NLMP]
    ///   §3.1.5.1.2 only wraps a session key when one of those is negotiated, so leaving this unset
    ///   means `ExportedSessionKey` is the `KeyExchangeKey`, and the RC4 that would otherwise be
    ///   needed to encrypt it is not.
    /// * **`VERSION`** — the `Version` field is documented as being for debugging only, and this
    ///   crate would have to invent a Windows build number to fill it in.
    ///
    /// `ALWAYS_SIGN` *is* set despite `SIGN` being absent: §2.2.2.5 makes it the flag that
    /// guarantees a session key exists at all, and the MIC in the `AUTHENTICATE_MESSAGE` is
    /// computed with that key.
    pub(crate) const REQUESTED: Self = Self(
        Self::UNICODE.0
            | Self::REQUEST_TARGET.0
            | Self::NTLM.0
            | Self::ALWAYS_SIGN.0
            | Self::EXTENDED_SESSIONSECURITY.0
            | Self::TARGET_INFO.0,
    );
    /// A session key that is not the NT one is requested.
    pub(crate) const REQUEST_NON_NT_SESSION_KEY: Self = Self(0x0040_0000);
    /// Asks the server to name itself in `TargetName`.
    pub(crate) const REQUEST_TARGET: Self = Self(0x0000_0004);
    /// Message sealing is requested.
    pub(crate) const SEAL: Self = Self(0x0000_0020);
    /// Message signing is requested.
    pub(crate) const SIGN: Self = Self(0x0000_0010);
    /// `TargetInfo` is present, which is what makes an NTLM v2 response possible.
    pub(crate) const TARGET_INFO: Self = Self(0x0080_0000);
    /// `TargetName` is a domain name.
    pub(crate) const TARGET_TYPE_DOMAIN: Self = Self(0x0001_0000);
    /// `TargetName` is a server name.
    pub(crate) const TARGET_TYPE_SERVER: Self = Self(0x0002_0000);
    /// Strings in this exchange are UTF-16LE.
    pub(crate) const UNICODE: Self = Self(0x0000_0001);
    /// The `Version` field is populated. Documented as being for debugging only.
    pub(crate) const VERSION: Self = Self(0x0200_0000);

    /// The flags as the field they are.
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }

    /// Reads the field.
    pub(crate) const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Whether every flag in `other` is set here.
    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The flags set in both.
    pub(crate) const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// The flags set in either.
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [MS-NLMP] §4.2.4 lists the thirteen flags in its worked `CHALLENGE_MESSAGE` by name, and
    /// §4.2.4.3 prints the message with `33 82 8a e2` in the field. Adding the named flags back up
    /// has to reproduce that word, which is what makes every constant above a transcription that
    /// was checked rather than one that was typed.
    #[test]
    fn the_documented_example_decomposes_into_its_named_flags() {
        let named = [
            NegotiateFlags::KEY_EXCH,
            NegotiateFlags::NEGOTIATE_56,
            NegotiateFlags::NEGOTIATE_128,
            NegotiateFlags::VERSION,
            NegotiateFlags::TARGET_INFO,
            NegotiateFlags::EXTENDED_SESSIONSECURITY,
            NegotiateFlags::TARGET_TYPE_SERVER,
            NegotiateFlags::ALWAYS_SIGN,
            NegotiateFlags::NTLM,
            NegotiateFlags::SEAL,
            NegotiateFlags::SIGN,
            NegotiateFlags::OEM,
            NegotiateFlags::UNICODE,
        ]
        .into_iter()
        .fold(NegotiateFlags::default(), NegotiateFlags::union);

        assert_eq!(named.bits(), 0xE28A_8233);
        assert_eq!(named.bits().to_le_bytes(), [0x33, 0x82, 0x8A, 0xE2]);
    }

    /// §4.2.4.3's `AUTHENTICATE_MESSAGE` carries `35 82 88 e2` at offset 0x3C — a different set,
    /// which is the second independent check on the same constants.
    #[test]
    fn the_documented_authenticate_flags_decompose_too() {
        let named = [
            NegotiateFlags::NEGOTIATE_56,
            NegotiateFlags::KEY_EXCH,
            NegotiateFlags::NEGOTIATE_128,
            NegotiateFlags::VERSION,
            NegotiateFlags::TARGET_INFO,
            NegotiateFlags::EXTENDED_SESSIONSECURITY,
            NegotiateFlags::ALWAYS_SIGN,
            NegotiateFlags::NTLM,
            NegotiateFlags::SEAL,
            NegotiateFlags::SIGN,
            NegotiateFlags::REQUEST_TARGET,
            NegotiateFlags::UNICODE,
        ]
        .into_iter()
        .fold(NegotiateFlags::default(), NegotiateFlags::union);

        assert_eq!(named.bits().to_le_bytes(), [0x35, 0x82, 0x88, 0xE2]);
    }

    #[test]
    fn what_this_crate_requests_is_what_it_can_answer() {
        let requested = NegotiateFlags::REQUESTED;
        assert_eq!(requested.bits(), 0x0088_8205);

        for wanted in [
            NegotiateFlags::UNICODE,
            NegotiateFlags::REQUEST_TARGET,
            NegotiateFlags::NTLM,
            NegotiateFlags::ALWAYS_SIGN,
            NegotiateFlags::EXTENDED_SESSIONSECURITY,
            NegotiateFlags::TARGET_INFO,
        ] {
            assert!(requested.contains(wanted), "{wanted:?}");
        }

        // The four that are absent on purpose. Each would oblige this crate to do work it does
        // not do: RC4 for the key exchange, a signing state machine, an invented build number.
        for unwanted in [
            NegotiateFlags::SIGN,
            NegotiateFlags::SEAL,
            NegotiateFlags::KEY_EXCH,
            NegotiateFlags::VERSION,
            NegotiateFlags::OEM,
            NegotiateFlags::LM_KEY,
            NegotiateFlags::ANONYMOUS,
        ] {
            assert!(!requested.contains(unwanted), "{unwanted:?}");
        }
    }

    #[test]
    fn set_operations_do_what_they_say() {
        let both = NegotiateFlags::UNICODE.union(NegotiateFlags::NTLM);
        assert!(both.contains(NegotiateFlags::UNICODE));
        assert!(both.contains(NegotiateFlags::NTLM));
        assert!(!both.contains(NegotiateFlags::SEAL));

        let shared = both.intersection(NegotiateFlags::UNICODE.union(NegotiateFlags::SEAL));
        assert_eq!(shared, NegotiateFlags::UNICODE);

        assert_eq!(NegotiateFlags::from_bits(0xE28A_8233).bits(), 0xE28A_8233);
        assert_eq!(NegotiateFlags::default().bits(), 0);
        // Every flag is contained in the empty set vacuously only when it is itself empty.
        assert!(NegotiateFlags::default().contains(NegotiateFlags::default()));
    }

    /// Not decoration: the reason a 401 is debuggable at all is that the flags print as names.
    #[test]
    fn flags_print_as_the_names_they_are_set_from() {
        let rendered = format!("{:?}", NegotiateFlags::from_bits(0xE28A_8233));
        assert!(rendered.starts_with("0xE28A8233 ("), "{rendered}");
        for name in ["UNICODE", "NTLM", "KEY_EXCH", "TARGET_TYPE_SERVER"] {
            assert!(rendered.contains(name), "{rendered}");
        }
        assert!(!rendered.contains("ANONYMOUS"), "{rendered}");
        assert_eq!(format!("{:?}", NegotiateFlags::default()), "0x00000000");

        // Every bit the specification names is in the table, so a flag cannot be transcribed and
        // then never looked at again.
        assert_eq!(NAMED.len(), 18);
    }
}
