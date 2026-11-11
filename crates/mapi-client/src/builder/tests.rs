use super::*;

#[test]
fn https_endpoints_are_accepted_and_kept_verbatim() {
    let url = "https://mail.example.test/mapi/emsmdb/?MailboxId=abc@example.test";
    let parsed = parse_endpoint(url, false).unwrap();
    assert_eq!(parsed.as_str(), url);
    assert_eq!(parsed.query(), Some("MailboxId=abc@example.test"));
}

/// The rule that stops a password reaching the wire in the clear, and the one escape hatch.
#[test]
fn plaintext_is_refused_unless_it_was_asked_for() {
    let url = "http://localhost:8080/mapi/emsmdb/";
    assert!(matches!(
        parse_endpoint(url, false),
        Err(Error::PlaintextEndpoint { .. })
    ));
    assert!(parse_endpoint(url, true).is_ok());
}

/// Anything that is not an absolute `http`/`https` URL with a host, including the two shapes a
/// caller is most likely to reach for by mistake: a bare path and a scheme-less host.
///
/// Note what is *not* here: `https:///mapi/emsmdb/`. The URL standard collapses the extra
/// slash and reads `mapi` as the host, which is a perfectly good single-label intranet name —
/// so it is accepted, and a check for "no host" after a successful parse of a special scheme
/// would be a branch that never runs.
#[test]
fn anything_that_is_not_an_http_url_is_refused() {
    for url in [
        "ftp://mail.example.test/mapi",
        "file:///etc/passwd",
        "/mapi/emsmdb/",
        "mail.example.test/mapi",
        "https://",
        "",
    ] {
        assert!(
            matches!(
                parse_endpoint(url, true),
                Err(Error::InvalidEndpoint { .. })
            ),
            "{url} was accepted"
        );
    }
}

#[test]
fn the_two_settings_with_no_default_are_reported_by_name() {
    let missing_both = MapiClientBuilder::new().build();
    assert!(matches!(
        missing_both,
        Err(Error::MissingSetting {
            name: "endpoint",
            ..
        })
    ));

    let missing_dn = MapiClientBuilder::default()
        .endpoint("https://mail.example.test/mapi/emsmdb/")
        .build();
    assert!(matches!(
        missing_dn,
        Err(Error::MissingSetting {
            name: "user_dn",
            ..
        })
    ));
}

/// The reason this knob exists: an on-premises Exchange fronted by a certificate from an
/// organisation's own CA, on a machine that does not have that CA installed.
///
/// Both shapes a CA gets handed out in are accepted, and the same throwaway certificate is
/// committed in each so that this is a statement about real certificate bytes.
#[test]
fn a_real_certificate_authority_is_accepted_as_pem_or_der() {
    for certificate in [
        include_bytes!("../../tests/example-ca.pem").to_vec(),
        include_bytes!("../../tests/example-ca.der").to_vec(),
    ] {
        let client = MapiClientBuilder::new()
            .endpoint("https://mail.example.test/mapi/emsmdb/")
            .user_dn(LegacyDn::new("/o=Example/cn=alice").unwrap())
            .root_certificate(certificate)
            .build();
        assert!(client.is_ok(), "{client:?}");
    }
}

/// Every knob at once, which is the only way to notice one that stopped being wired up.
#[test]
fn every_setting_reaches_the_client() {
    let client = MapiClientBuilder::new()
        .endpoint("https://mail.example.test/mapi/emsmdb/?MailboxId=x@example.test")
        .user_dn(LegacyDn::new("/o=Example/cn=alice").unwrap())
        .credentials(Credentials::bearer("a-token"))
        .locale(Lcid::new(0x0413))
        .code_page(CodePage::new(1251).unwrap())
        .client_application("Outlook/15.00.0000.0000")
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(1))
        .danger_accept_invalid_certificates(true)
        .build()
        .expect("a client");

    assert_eq!(
        client.endpoint(),
        "https://mail.example.test/mapi/emsmdb/?MailboxId=x@example.test"
    );
    assert_eq!(client.user_dn().as_str(), "/o=Example/cn=alice");
    assert_eq!(client.code_page.as_u16(), 1251);
    assert_eq!(client.locale, Lcid::new(0x0413));
}

#[test]
fn a_certificate_that_will_not_parse_is_reported_as_a_setup_failure() {
    let broken = MapiClientBuilder::new()
        .endpoint("https://mail.example.test/mapi/emsmdb/")
        .user_dn(LegacyDn::new("/o=Example/cn=alice").unwrap())
        .root_certificate(b"-----BEGIN CERTIFICATE-----\nnot a certificate\n".to_vec())
        .build();
    assert!(matches!(broken, Err(Error::Setup { .. })), "{broken:?}");
}

/// A builder is a value, and a client built from one carries no secret into its `Debug`.
#[test]
fn debug_output_carries_no_secret() {
    let builder = MapiClientBuilder::new()
        .endpoint("https://mail.example.test/mapi/emsmdb/")
        .user_dn(LegacyDn::new("/o=Example/cn=alice").unwrap())
        .credentials(Credentials::basic("alice", "hunter2"));
    assert!(!format!("{builder:?}").contains("hunter2"));
    assert!(!format!("{:?}", builder.build().unwrap()).contains("hunter2"));
}

/// A builder's clones share its ticket cache, and one given other credentials does not: the
/// cache is keyed by service, so sharing it would present one account's tickets for another.
#[cfg(feature = "kerberos")]
#[test]
fn other_credentials_get_a_ticket_cache_of_their_own() {
    let alice = MapiClientBuilder::new().credentials(Credentials::negotiate("alice", "a"));
    assert!(Arc::ptr_eq(&alice.kerberos, &alice.clone().kerberos));
    let bob = alice
        .clone()
        .credentials(Credentials::negotiate("bob", "b"));
    assert!(!Arc::ptr_eq(&alice.kerberos, &bob.kerberos));
}
