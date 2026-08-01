use super::*;
use crate::oxcdata::LegacyDn;

#[test]
fn known_codes_carry_the_specs_own_names() {
    for (code, name, raw) in [
        (ErrorCode::SUCCESS, "Success", 0x0000_0000),
        (ErrorCode::UNKNOWN_USER, "UnknownUser", 0x0000_03EB),
        (ErrorCode::LOGIN_PERMISSION, "LoginPermission", 0x0000_03F2),
        (ErrorCode::GENERAL_FAILURE, "GeneralFailure", 0x8000_4005),
        (ErrorCode::NOT_SUPPORTED, "NotSupported", 0x8004_0102),
        (ErrorCode::STRING_TOO_LONG, "StringTooLong", 0x8004_0105),
        (ErrorCode::NOT_FOUND, "NotFound", 0x8004_010F),
        (ErrorCode::VERSION_MISMATCH, "VersionMismatch", 0x8004_0110),
        (ErrorCode::LOGON_FAILED, "LogonFailed", 0x8004_0111),
        (ErrorCode::NETWORK_ERROR, "NetworkError", 0x8004_0115),
        (ErrorCode::TOO_BIG, "TooBig", 0x8004_0305),
        (ErrorCode::ACCESS_DENIED, "AccessDenied", 0x8007_0005),
    ] {
        assert_eq!(code.as_u32(), raw);
        assert_eq!(code.name(), Some(name));
        assert_eq!(ErrorCode::new(raw), code);
        assert_eq!(ErrorCode::from(raw), code);
    }
}

/// The set is open: a code this crate has never heard of still has to survive being received,
/// compared and printed.
#[test]
fn an_unknown_code_survives_and_prints_its_value() {
    let unknown = ErrorCode::new(0x8004_0999);
    assert_eq!(unknown.name(), None);
    assert_eq!(unknown.to_string(), "unrecognised error code 0x80040999");
    assert!(!unknown.is_success());
}

#[test]
fn success_is_the_default_and_the_only_code_that_is_success() {
    assert!(ErrorCode::default().is_success());
    assert_eq!(ErrorCode::default(), ErrorCode::SUCCESS);
    assert_eq!(ErrorCode::SUCCESS.to_string(), "Success (0x00000000)");
    assert!(!ErrorCode::ACCESS_DENIED.is_success());
}

/// Every message has to say what to do next, not merely that something went wrong.
#[test]
fn errors_explain_themselves() {
    let dn = LegacyDn::new("/o=First/cn=alice").unwrap();
    let cases = [
        (
            Error::Truncated {
                at: 4,
                need: 8,
                have: 2,
            },
            "truncated at 4: need 8 bytes, 2 remain",
        ),
        (Error::Unterminated { at: 7 }, "unterminated string at 7"),
        (Error::InvalidUtf16 { at: 3 }, "invalid UTF-16 at 3"),
        (
            Error::InvalidValueFlag { flag: 0x07, at: 1 },
            "invalid flagged-value flag 0x07 at 1",
        ),
        (
            Error::UnknownHandleSlot { index: 2 },
            "handle slot 2 does not belong to this batch",
        ),
        (
            Error::ConnectFailed {
                code: ErrorCode::UNKNOWN_USER,
                user_dn: dn,
            },
            "Connect refused for /o=First/cn=alice: UnknownUser (0x000003EB)",
        ),
        (
            Error::InvalidState {
                attempted: "send Execute",
                reason: "no Session Context yet; send Connect first",
            },
            "cannot send Execute: no Session Context yet; send Connect first",
        ),
    ];

    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn transport_errors_report_the_diagnostic_when_there_is_one() {
    let with = Error::Transport {
        code: ResponseCode::CONTEXT_NOT_FOUND,
        diagnostic: Some("session expired".to_owned()),
    };
    assert_eq!(
        with.to_string(),
        "transport refused the request: Context Not Found (10), session expired"
    );

    let without = Error::Transport {
        code: ResponseCode::MISSING_COOKIE,
        diagnostic: None,
    };
    assert!(without.to_string().ends_with("no diagnostic"));
}

#[test]
fn buffer_and_type_errors_name_the_limit_they_hit() {
    assert_eq!(
        Error::RopBufferTooLarge {
            bytes: 70_000,
            limit: 65_535
        }
        .to_string(),
        "ROP buffer is 70000 bytes, past the 65535-byte limit of its length field"
    );
    assert_eq!(
        Error::TooManyHandles { limit: 256 }.to_string(),
        "a ROP batch cannot hold more than 256 handle slots"
    );
    assert_eq!(
        Error::UnsupportedPropertyType {
            property_type: 0x0102,
            at: 9
        }
        .to_string(),
        "unsupported property type 0x0102 at 9"
    );
    assert_eq!(
        Error::ObfuscatedRopBuffer { flags: 0x0005 }.to_string(),
        "ROP buffer is compressed or obfuscated (RPC_HEADER_EXT flags 0x0005)"
    );
    assert_eq!(
        Error::UnmodelledRop {
            rop: RopId::new(0x07),
            at: 6
        }
        .to_string(),
        "unmodelled ROP 0x07 in the response stream at 6"
    );
    assert_eq!(
        Error::UnknownColumns { handle_index: 3 }.to_string(),
        "no column set known for handle index 3: send RopSetColumns first"
    );
    assert_eq!(
        Error::ExecuteFailed {
            status: 10,
            code: ErrorCode::NETWORK_ERROR
        }
        .to_string(),
        "Execute refused (StatusCode 0x0000000A): NetworkError (0x80040115)"
    );
}

#[test]
fn the_remaining_variants_have_messages_too() {
    assert!(
        Error::MissingResponseCode
            .to_string()
            .contains("X-ResponseCode")
    );
    assert!(
        Error::NoRequestInFlight
            .to_string()
            .contains("no request is in flight")
    );
    assert!(
        Error::InvalidLegacyDn {
            reason: "a distinguished name cannot be empty"
        }
        .to_string()
        .contains("cannot be empty")
    );
}

/// `Result` is the crate's, and errors compose with `?` through it.
#[test]
fn the_crate_result_alias_composes() {
    fn fallible(fail: bool) -> Result<u8> {
        if fail {
            return Err(Error::NoRequestInFlight);
        }
        Ok(1)
    }

    assert_eq!(fallible(false).unwrap(), 1);
    assert!(fallible(true).is_err());
}
