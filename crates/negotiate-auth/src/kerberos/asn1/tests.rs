//! The building blocks against values computed independently of this code.

use super::*;

fn reader(bytes: &[u8]) -> Reader<'_> {
    Reader::new(STRUCTURE, bytes)
}

/// Each instant was computed with Python's `datetime`, not with this module: the epoch, both ends
/// of a leap day, a date past 2026, the last second of 2099 and the last a four-digit year allows.
#[test]
fn times_are_written_as_rfc4120_requires_and_read_back() {
    let cases = [
        (0, "19700101000000Z"),
        (951_782_400, "20000229000000Z"),
        (951_868_799, "20000229235959Z"),
        (1_800_000_000, "20270115080000Z"),
        (4_102_444_799, "20991231235959Z"),
        (253_402_300_799, "99991231235959Z"),
    ];
    for (seconds, text) in cases {
        let time = KerberosTime::from_unix(seconds);
        let encoded = time.encode();
        assert_eq!(
            encoded,
            der::tlv(der::GENERALIZED_TIME, text.as_bytes()),
            "{seconds}"
        );
        assert_eq!(
            KerberosTime::read(&mut reader(&encoded), "a time").unwrap(),
            time
        );
        assert_eq!(time.unix(), seconds);
    }
}

/// [RFC 4120] §5.2.3: UTC, no fractional seconds, nothing but `YYYYMMDDHHMMSSZ`.
#[test]
fn a_time_that_is_not_exactly_the_kerberos_form_is_refused() {
    for text in [
        "19700230000000Z",   // the thirtieth of February
        "19690101000000Z",   // before the epoch
        "19701301000000Z",   // a thirteenth month
        "19700101240000Z",   // the twenty-fifth hour
        "19700101000060Z",   // a sixty-first second
        "19700101000000",    // no zone
        "19700101000000+01", // not UTC
        "19700101000000.5Z", // a fraction
        "1970010100000AZ",   // a letter
        "",
    ] {
        let encoded = der::tlv(der::GENERALIZED_TIME, text.as_bytes());
        assert!(
            KerberosTime::read(&mut reader(&encoded), "a time").is_err(),
            "{text:?}"
        );
    }
    // 2100 is not a leap year; 2000 was.
    let encoded = der::tlv(der::GENERALIZED_TIME, b"21000229000000Z");
    assert!(KerberosTime::read(&mut reader(&encoded), "a time").is_err());
}

/// [RFC 4120] §5.2.8: flag 0 is the most significant bit, and at least 32 bits are sent.
#[test]
fn flags_number_from_the_most_significant_bit() {
    assert_eq!(flag(0), 0x8000_0000);
    assert_eq!(flag(1), 0x4000_0000);
    assert_eq!(flag(15), 0x0001_0000);
    assert_eq!(flag(31), 1);
    assert_eq!(flag(32), 0);

    // forwardable (1), renewable (8), canonicalize (15): what a request typically sets.
    let set = flag(1) | flag(8) | flag(15);
    let encoded = flags(set);
    assert_eq!(
        encoded,
        [der::BIT_STRING, 0x05, 0x00, 0x40, 0x81, 0x00, 0x00]
    );
    assert_eq!(read_flags(&mut reader(&encoded), "flags").unwrap(), set);

    // A sender that sends more than 32 bits, or fewer, is read for the first 32.
    let long = der::tlv(der::BIT_STRING, &[0, 0x80, 0, 0, 1, 0xFF]);
    assert_eq!(
        read_flags(&mut reader(&long), "flags").unwrap(),
        0x8000_0001
    );
    let short = der::tlv(der::BIT_STRING, &[0, 0x80]);
    assert_eq!(
        read_flags(&mut reader(&short), "flags").unwrap(),
        0x8000_0000
    );
    assert!(read_flags(&mut reader(&der::tlv(der::BIT_STRING, &[])), "flags").is_err());
}

#[test]
fn a_principal_name_round_trips_and_knows_a_ticket_granting_service() {
    let service = PrincipalName::new(PrincipalName::NT_SRV_INST, &["HTTP", "mail.example.test"]);
    let encoded = service.encode();
    assert_eq!(PrincipalName::read(&mut reader(&encoded)).unwrap(), service);
    assert!(!service.is_krbtgt());
    assert!(PrincipalName::new(2, &["KRBTGT", "EXAMPLE.TEST"]).is_krbtgt());

    let plain = PrincipalName::new(PrincipalName::NT_PRINCIPAL, &["alice"]);
    assert_eq!(
        PrincipalName::read(&mut reader(&plain.encode())).unwrap(),
        plain
    );

    // [MS-KILE] §3.1.5.7: names are UTF-8.
    let user = PrincipalName::new(PrincipalName::NT_ENTERPRISE, &["zoë@example.test"]);
    assert_eq!(
        PrincipalName::read(&mut reader(&user.encode())).unwrap(),
        user
    );
    let invalid = sequence(&[
        explicit(0, &int(1)),
        explicit(
            1,
            &der::tlv(der::SEQUENCE, &der::tlv(der::GENERAL_STRING, &[0xFF])),
        ),
    ]);
    assert!(PrincipalName::read(&mut reader(&invalid)).is_err());
}

#[test]
fn the_shared_structures_round_trip() {
    for kvno in [None, Some(2), Some(u32::MAX)] {
        let data = EncryptedData {
            etype: 18,
            kvno,
            cipher: vec![1, 2, 3],
        };
        assert_eq!(
            EncryptedData::read(&mut reader(&data.encode())).unwrap(),
            data
        );
    }

    let key = EncryptionKey {
        keytype: 18,
        value: vec![0xAB; 32],
    };
    assert_eq!(
        EncryptionKey::read(&mut reader(&key.encode())).unwrap(),
        key
    );
    assert!(
        !format!("{key:?}").contains("171"),
        "Debug prints no key bytes"
    );

    let padata = vec![
        PaData {
            padata_type: 2,
            value: vec![9],
        },
        PaData {
            padata_type: 128,
            value: vec![],
        },
    ];
    let list = der::tlv(
        der::SEQUENCE,
        &padata.iter().flat_map(PaData::encode).collect::<Vec<_>>(),
    );
    assert_eq!(PaData::read_all(&mut reader(&list)).unwrap(), padata);

    let checksum = Checksum {
        cksumtype: 0x8003,
        checksum: vec![0; 24],
    };
    assert_eq!(
        Checksum::read(&mut reader(&checksum.encode())).unwrap(),
        checksum
    );
    assert_eq!(
        authorization_data(&[(143, vec![0, 0x40, 0, 0])]),
        der::tlv(
            der::SEQUENCE,
            &sequence(&[
                explicit(0, &int(143)),
                explicit(1, &octets(&[0, 0x40, 0, 0]))
            ])
        )
    );
    assert_eq!(boolean(true), [der::BOOLEAN, 1, 0xFF]);
    assert_eq!(boolean(false), [der::BOOLEAN, 1, 0x00]);
}

/// A field this crate does not know is ignored, a field that is not explicitly tagged is refused,
/// and a missing required one names what was missing.
#[test]
fn fields_are_taken_by_number_and_unknown_ones_ignored() {
    let encoded = sequence(&[explicit(0, &int(7)), explicit(12, &octets(b"later"))]);
    let fields = Fields::of(&mut reader(&encoded), "a test").unwrap();
    assert_eq!(
        read_int32(&mut fields.required(0, "zero").unwrap(), "zero").unwrap(),
        7
    );
    assert!(fields.optional(5).is_none());
    let error = fields.required(5, "field five").unwrap_err();
    assert!(error.to_string().contains("field five"), "{error}");

    let untagged = sequence(&[int(7)]);
    assert!(Fields::of(&mut reader(&untagged), "a test").is_err());
}

#[test]
fn integers_out_of_range_for_their_type_are_refused() {
    let big = int(i64::from(u32::MAX));
    assert!(read_int32(&mut reader(&big), "an Int32").is_err());
    assert_eq!(
        read_uint32(&mut reader(&big), "a UInt32").unwrap(),
        u32::MAX
    );
    assert!(read_uint32(&mut reader(&int(-1)), "a UInt32").is_err());
    assert!(read_int32(&mut reader(&der::tlv(der::INTEGER, &[])), "an Int32").is_err());
}

/// The same promise every parser in this workspace makes: no prefix of a valid encoding panics.
#[test]
fn no_truncation_of_a_valid_structure_panics() {
    let name = PrincipalName::new(2, &["krbtgt", "EXAMPLE.TEST"]).encode();
    let data = EncryptedData {
        etype: 18,
        kvno: Some(1),
        cipher: vec![7; 40],
    }
    .encode();
    for buffer in [&name, &data] {
        for len in 0..buffer.len() {
            let _ = PrincipalName::read(&mut reader(&buffer[..len]));
            let _ = EncryptedData::read(&mut reader(&buffer[..len]));
            let _ = EncryptionKey::read(&mut reader(&buffer[..len]));
            let _ = PaData::read_all(&mut reader(&buffer[..len]));
            let _ = KerberosTime::read(&mut reader(&buffer[..len]), "a time");
        }
    }
}
