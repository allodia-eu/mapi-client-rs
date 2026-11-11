//! An item another implementation wrote, with one extended property of every type it can write,
//! synchronized and read back value by value.
//!
//! **EWS writes it**, not this crate: the point is values whose encoding nobody here chose. EWS can
//! be asked for an extended property of 23 types — every scalar and list [MS-OXCDATA] §2.11.1
//! names except `PtypErrorCode`, `PtypNull`, `PtypObject` and the ROP-buffer-only types — and an
//! incremental download has to bring each one back as the value EWS was given, in the type the
//! store holds it in. Each property is also read back without a type, which is how the store says
//! what that type is.
//!
//! **Two of the 23 are not what they say.** Measured on Exchange Server SE `15.02.2562.056`: EWS
//! stores a `Currency` as `PtypInteger64` and an `ApplicationTime` as `PtypFloating64`, lists
//! likewise, so no EWS item carries a `PtypCurrency` or a `PtypFloatingTime`. This crate writes
//! those four types itself, under their own names on the same draft, before the download that is
//! checked.
//!
//! Self-cleaning like the rest of the suite: the draft carries [`MARKER`] and is swept away before
//! the test starts and after it reads, whether or not the reading succeeded.
//!
//! [MS-OXCFXICS] §2.2.4.1.3 — serialization of simple types

use mapi_client::mapi_proto::fasttransfer::MessageChange;
use mapi_client::{
    ContentsDownload, Currency, FileTime, Floating32, Floating64, FolderId, Guid, Logon, MessageId,
    PropertyName, PropertySetId, PropertyTag, PropertyType, PropertyValue, SpecialFolder,
    TableString, TaggedValue,
};

use super::{MARKER, drain, messages, subject, sweep};

/// The property set every property here is named in, made up for this test.
const SET: Guid = Guid::from_bytes([
    0xB4, 0xA3, 0xC2, 0xF1, 0x5E, 0x0D, 0x60, 0x4F, 0x8A, 0x71, 0x92, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7,
]);

/// `{01234567-89ab-cdef-0123-456789abcdef}`, the value of the `CLSID` properties.
const CLSID: Guid = Guid::from_bytes([
    0x67, 0x45, 0x23, 0x01, 0xAB, 0x89, 0xEF, 0xCD, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
]);

/// 2026-11-10T12:34:56Z and 2001-02-03T04:05:06Z, as FILETIMEs.
const NOVEMBER: u64 = 134_387_876_960_000_000;
const FEBRUARY: u64 = 126_256_467_060_000_000;

/// One extended property: its LID in [`SET`], its EWS type, the values EWS is given, and what the
/// download has to bring back.
struct Case {
    lid: u32,
    ews_type: &'static str,
    values: &'static [&'static str],
    expected: fn() -> PropertyValue,
}

/// Single values are written as one `Value`, lists as `Values`, and the EWS type says which.
const CASES: [Case; 23] = [
    Case {
        lid: 0x01,
        ews_type: "Short",
        values: &["-12345"],
        expected: || PropertyValue::Integer16(53_191),
    },
    Case {
        lid: 0x02,
        ews_type: "Integer",
        values: &["-123456789"],
        expected: || PropertyValue::Integer32(4_171_510_507),
    },
    Case {
        lid: 0x03,
        ews_type: "Long",
        values: &["1234567890123"],
        expected: || PropertyValue::Integer64(1_234_567_890_123),
    },
    Case {
        lid: 0x04,
        ews_type: "Float",
        values: &["1.5"],
        expected: || PropertyValue::Floating32(Floating32::new(1.5)),
    },
    Case {
        lid: 0x05,
        ews_type: "Double",
        values: &["3.25"],
        expected: || PropertyValue::Floating64(Floating64::new(3.25)),
    },
    Case {
        lid: 0x06,
        ews_type: "Currency",
        values: &["123456789"],
        // Stored as PtypInteger64: see the module documentation.
        expected: || PropertyValue::Integer64(123_456_789),
    },
    Case {
        lid: 0x07,
        ews_type: "ApplicationTime",
        values: &["45000.25"],
        // Stored as PtypFloating64.
        expected: || PropertyValue::Floating64(Floating64::new(45_000.25)),
    },
    Case {
        lid: 0x08,
        ews_type: "Boolean",
        values: &["true"],
        expected: || PropertyValue::Boolean(true),
    },
    Case {
        lid: 0x09,
        ews_type: "SystemTime",
        values: &["2026-11-10T12:34:56Z"],
        expected: || PropertyValue::Time(FileTime::new(NOVEMBER)),
    },
    Case {
        lid: 0x0A,
        ews_type: "CLSID",
        values: &["01234567-89ab-cdef-0123-456789abcdef"],
        expected: || PropertyValue::Guid(CLSID),
    },
    Case {
        lid: 0x0B,
        ews_type: "Binary",
        values: &["AAEC/w=="],
        expected: || PropertyValue::Binary(vec![0x00, 0x01, 0x02, 0xFF]),
    },
    Case {
        lid: 0x0C,
        ews_type: "String",
        values: &["Caf\u{E9} \u{20AC} \u{41F}\u{440}\u{438} \u{65E5}\u{672C}"],
        expected: || {
            PropertyValue::String(TableString::from(
                "Caf\u{E9} \u{20AC} \u{41F}\u{440}\u{438} \u{65E5}\u{672C}",
            ))
        },
    },
    Case {
        lid: 0x11,
        ews_type: "ShortArray",
        values: &["1", "-2"],
        expected: || PropertyValue::MultipleInteger16(vec![1, 65_534]),
    },
    Case {
        lid: 0x12,
        ews_type: "IntegerArray",
        values: &["7", "-1"],
        expected: || PropertyValue::MultipleInteger32(vec![7, u32::MAX]),
    },
    Case {
        lid: 0x13,
        ews_type: "LongArray",
        values: &["9", "-9"],
        expected: || PropertyValue::MultipleInteger64(vec![9, u64::MAX - 8]),
    },
    Case {
        lid: 0x14,
        ews_type: "FloatArray",
        values: &["0.5", "-2"],
        expected: || {
            PropertyValue::MultipleFloating32(vec![Floating32::new(0.5), Floating32::new(-2.0)])
        },
    },
    Case {
        lid: 0x15,
        ews_type: "DoubleArray",
        values: &["0.125", "1e10"],
        expected: || {
            PropertyValue::MultipleFloating64(vec![Floating64::new(0.125), Floating64::new(1e10)])
        },
    },
    Case {
        lid: 0x16,
        ews_type: "CurrencyArray",
        values: &["10000", "-5"],
        expected: || PropertyValue::MultipleInteger64(vec![10_000, u64::MAX - 4]),
    },
    Case {
        lid: 0x17,
        ews_type: "ApplicationTimeArray",
        values: &["1.5", "2"],
        expected: || {
            PropertyValue::MultipleFloating64(vec![Floating64::new(1.5), Floating64::new(2.0)])
        },
    },
    Case {
        lid: 0x19,
        ews_type: "SystemTimeArray",
        values: &["2026-11-10T12:34:56Z", "2001-02-03T04:05:06Z"],
        expected: || {
            PropertyValue::MultipleTime(vec![FileTime::new(NOVEMBER), FileTime::new(FEBRUARY)])
        },
    },
    Case {
        lid: 0x1A,
        ews_type: "CLSIDArray",
        values: &[
            "01234567-89ab-cdef-0123-456789abcdef",
            "00000000-0000-0000-0000-000000000000",
        ],
        expected: || PropertyValue::MultipleGuid(vec![CLSID, Guid::from_bytes([0; 16])]),
    },
    Case {
        lid: 0x1B,
        ews_type: "BinaryArray",
        values: &["AQ==", "AA=="],
        expected: || PropertyValue::MultipleBinary(vec![vec![0x01], vec![0x00]]),
    },
    Case {
        lid: 0x1C,
        ews_type: "StringArray",
        values: &["one", "\u{41F}\u{440}\u{438}"],
        expected: || {
            PropertyValue::MultipleString(vec![
                TableString::from("one"),
                TableString::from("\u{41F}\u{440}\u{438}"),
            ])
        },
    },
];

/// The subject of the draft EWS writes.
fn draft_subject() -> String {
    format!("{MARKER}: every extended property type")
}

/// The `CreateItem` body: a draft carrying every case as an extended property.
fn create_item() -> String {
    use core::fmt::Write as _;

    let set = SET.to_string();
    let set = set.trim_matches(['{', '}']);
    let mut properties = String::new();
    for case in &CASES {
        let mut values = String::new();
        for value in case.values {
            write!(values, "<t:Value>{value}</t:Value>").unwrap();
        }
        if case.ews_type.ends_with("Array") {
            values = format!("<t:Values>{values}</t:Values>");
        }
        write!(
            properties,
            "<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId=\"{set}\" PropertyId=\"{}\" \
             PropertyType=\"{}\" />{values}</t:ExtendedProperty>",
            case.lid, case.ews_type
        )
        .unwrap();
    }
    format!(
        "<m:CreateItem MessageDisposition=\"SaveOnly\">\
         <m:SavedItemFolderId><t:DistinguishedFolderId Id=\"drafts\" /></m:SavedItemFolderId>\
         <m:Items><t:Message><t:Subject>{}</t:Subject>{properties}</t:Message></m:Items>\
         </m:CreateItem>",
        draft_subject()
    )
}

/// What sends an EWS request: Windows PowerShell 5.1, the lab's own way in.
///
/// The lab's EWS offers `Negotiate` and `NTLM` only, which `Invoke-WebRequest -Credential` answers
/// as `scripts\Add-LabItems.ps1` does. This crate's own NTLM is bound to its MAPI transport, and
/// the live suite only ever runs where `Test-Live.ps1` — which needs 5.1 anyway — does.
const SEND: &str = r"
$ErrorActionPreference = 'Stop'
$password = ConvertTo-SecureString $env:MAPI_EWS_PASSWORD -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential(
    $env:MAPI_EWS_USERNAME, $password)
$response = Invoke-WebRequest -Uri $env:MAPI_EWS_URL -Method Post -UseBasicParsing `
    -ContentType 'text/xml; charset=utf-8' -Credential $credential `
    -Body ([System.IO.File]::ReadAllBytes($env:MAPI_EWS_BODY))
[Console]::Out.Write($response.Content)
";

/// Windows PowerShell 5.1, by full path: it is not on every machine's `PATH`.
const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

/// Sends one EWS request as the mailbox owner, and fails on any `ResponseCode` but `NoError` — EWS
/// answers 200 for a request it refused.
fn ews(body: &str) {
    let endpoint = reqwest::Url::parse(&crate::required("MAPI_LIVE_ENDPOINT")).expect("a URL");
    let url = format!(
        "https://{}/EWS/Exchange.asmx",
        endpoint.host_str().expect("a host")
    );
    let envelope = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:t=\"http://schemas.microsoft.com/exchange/services/2006/types\" \
         xmlns:m=\"http://schemas.microsoft.com/exchange/services/2006/messages\">\
         <soap:Header><t:RequestServerVersion Version=\"Exchange2013\" /></soap:Header>\
         <soap:Body>{body}</soap:Body></soap:Envelope>"
    );
    let request = std::env::temp_dir().join(format!("mapi-ews-{}.xml", std::process::id()));
    std::fs::write(&request, envelope).expect("the request written out");
    // A PowerShell 7 module path breaks 5.1's own modules; see scripts\_Boot.ps1.
    let output = std::process::Command::new(POWERSHELL)
        .args(["-NoProfile", "-NonInteractive", "-Command", SEND])
        .env_remove("PSModulePath")
        .env("MAPI_EWS_URL", url)
        .env("MAPI_EWS_BODY", &request)
        .env("MAPI_EWS_USERNAME", crate::required("MAPI_LIVE_USERNAME"))
        .env("MAPI_EWS_PASSWORD", crate::required("MAPI_LIVE_PASSWORD"))
        .output()
        .expect("Windows PowerShell runs");
    let _ = std::fs::remove_file(&request);
    let text = String::from_utf8_lossy(&output.stdout);
    let codes = text.matches("ResponseCode>").count() / 2;
    let fine = text.matches("ResponseCode>NoError<").count();
    assert!(
        output.status.success() && codes > 0 && codes == fine,
        "EWS refused the request: {text}{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The four types no EWS item can carry, written by this crate: LID, label, value.
fn written_here() -> [(u32, &'static str, PropertyValue); 4] {
    [
        (
            0x26,
            "PtypCurrency",
            PropertyValue::Currency(Currency::from_scaled(123_456_789)),
        ),
        (
            0x27,
            "PtypFloatingTime",
            PropertyValue::FloatingTime(Floating64::new(45_000.25)),
        ),
        (
            0x36,
            "PtypMultipleCurrency",
            PropertyValue::MultipleCurrency(vec![
                Currency::from_scaled(10_000),
                Currency::from_scaled(-5),
            ]),
        ),
        (
            0x37,
            "PtypMultipleFloatingTime",
            PropertyValue::MultipleFloatingTime(vec![Floating64::new(1.5), Floating64::new(2.0)]),
        ),
    ]
}

/// Every property the draft carries — EWS's and this crate's — as LID, label and expected value.
fn everything() -> Vec<(u32, &'static str, PropertyValue)> {
    CASES
        .iter()
        .map(|case| (case.lid, case.ews_type, (case.expected)()))
        .chain(written_here())
        .collect()
}

fn name(lid: u32) -> PropertyName {
    PropertyName::lid(PropertySetId::from_guid(SET), lid)
}

/// Writes [`written_here`] onto the draft EWS made.
async fn write_the_rest(logon: &mut Logon, folder: FolderId, id: MessageId) -> Result<(), String> {
    let values = written_here();
    let ids = logon
        .register_names(values.iter().map(|(lid, ..)| name(*lid)))
        .await
        .map_err(|error| format!("registering the names: {error}"))?
        .clone();
    let tagged = values.into_iter().map(|(lid, _, value)| {
        let tag = ids
            .tag(&name(lid), value.property_type().expect("a value"))
            .expect("a registered name");
        TaggedValue::new(tag, value).expect("a value of the tag's type")
    });
    let problems = logon
        .message(folder, id)
        .update()
        .set(tagged)
        .save()
        .await
        .map_err(|error| format!("writing the rest: {error}"))?;
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!("the server refused some of them: {problems:?}"))
    }
}

/// Each property's value in the change, matched by the name the stream carries inline, and in the
/// type the store reports when it is asked for the property without one.
async fn check(logon: &mut Logon, folder: FolderId, change: &MessageChange) -> Result<(), String> {
    let everything = everything();
    let names: Vec<PropertyName> = everything.iter().map(|(lid, ..)| name(*lid)).collect();
    let ids = logon
        .register_names(names.clone())
        .await
        .map_err(|error| format!("resolving the names: {error}"))?;
    let untyped: Vec<PropertyTag> = names
        .iter()
        .map(|name| {
            ids.tag(name, PropertyType::Unspecified)
                .expect("a resolved name")
        })
        .collect();
    let id = change.header().id().ok_or("the change carries no MID")?;
    let stored = logon
        .message(folder, id)
        .properties()
        .read(untyped)
        .await
        .map_err(|error| format!("reading the properties back: {error}"))?;

    let mut wrong = Vec::new();
    for ((name, (_, label, expected)), cell) in names.iter().zip(&everything).zip(stored.cells()) {
        let streamed = change
            .content()
            .properties()
            .iter()
            .find(|property| property.name() == Some(name));
        let value = streamed.map(|property| property.value().clone());
        let streamed_type = streamed.map(|property| property.tag().property_type());
        let stored_type = cell.tag().property_type();
        println!("  {label:>24}: stored as {stored_type}, streamed as {value:?}");
        if value.as_ref() != Some(expected) || streamed_type != Some(stored_type) {
            wrong.push(format!(
                "{label}: {value:?} streamed, {expected:?} expected, stored as {stored_type}"
            ));
        }
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(wrong.join("; "))
    }
}

/// The change for the draft, in a whole download of `folder`.
async fn download(logon: &mut Logon, folder: FolderId) -> Option<MessageChange> {
    let (events, _) = drain(logon, folder, ContentsDownload::new(), None).await;
    let wanted = draft_subject();
    messages(&events)
        .into_iter()
        .find(|change| subject(change) == wanted)
        .cloned()
}

#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn every_type_ews_can_write_syncs_back_as_written() {
    let mut logon = crate::client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let drafts = logon.special_folder(SpecialFolder::Drafts).await.unwrap();
    sweep(&mut logon, drafts).await;

    ews(&create_item());
    let outcome = async {
        let created = download(&mut logon, drafts)
            .await
            .ok_or("the first download did not report the draft")?;
        let id = created.header().id().ok_or("the change carries no MID")?;
        write_the_rest(&mut logon, drafts, id).await?;
        let change = download(&mut logon, drafts)
            .await
            .ok_or("the second download did not report the draft")?;
        check(&mut logon, drafts, &change).await
    }
    .await;

    sweep(&mut logon, drafts).await;
    logon.disconnect().await.unwrap();
    outcome.expect("every property syncs back as it was written");
}
