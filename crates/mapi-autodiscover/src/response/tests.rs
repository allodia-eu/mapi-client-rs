use super::*;

/// A capture from the live Exchange lab, scrubbed. See the comment at the top of the file.
const EXCHANGE_SE: &str = include_str!("../../tests/exchange-se-mapihttp.xml");

/// The query parameter Exchange puts on both MAPI URLs.
const MAILBOX_ID: &str = "?MailboxId=00000000-0000-0000-0000-000000000000@dev.local";

/// Wraps a fragment in the two elements every response has, so the fragments stay readable.
fn response(inner: &str) -> String {
    format!("<Autodiscover><Response>{inner}</Response></Autodiscover>")
}

fn settings(xml: &str) -> Settings {
    match AutodiscoverResponse::parse(xml) {
        Ok(AutodiscoverResponse::Settings(settings)) => settings,
        other => panic!("expected settings, got {other:?}"),
    }
}

#[test]
fn a_real_exchange_response_yields_a_mapi_http_endpoint() {
    let settings = settings(EXCHANGE_SE);
    let endpoint = settings.mapi_http().expect("no mapiHttp protocol");

    assert_eq!(
        endpoint.mail_store_url(),
        Some(format!("https://exchange-lab-01/mapi/emsmdb/{MAILBOX_ID}")).as_deref()
    );
    assert_eq!(
        endpoint.address_book_url(),
        Some(format!("https://exchange-lab-01/mapi/nspi/{MAILBOX_ID}")).as_deref()
    );
    assert!(endpoint.legacy_dn().starts_with("/o=Dev/ou=Exchange"));
    assert_eq!(endpoint.version(), 1);
    assert_eq!(endpoint.mail_store().external(), None);
    assert_eq!(
        endpoint.address_book().internal(),
        endpoint.address_book_url()
    );
}

#[test]
fn the_user_element_is_read_whole() {
    let settings = settings(EXCHANGE_SE);
    let user = settings.user();

    assert_eq!(user.display_name(), Some("Lab Test User"));
    assert_eq!(user.smtp_address(), Some("developer@dev.local"));
    assert_eq!(
        user.deployment_id(),
        Some("00000000-0000-0000-0000-000000000000")
    );
    assert!(user.legacy_dn().unwrap().contains("cn=Recipients"));
}

/// `mapiHttp` names itself with a `Type` attribute; every other protocol uses a `Type` child
/// element. A reader that only looks at one of those never finds MAPI/HTTP at all — and its
/// absence is indistinguishable from a server that does not support it.
#[test]
fn both_ways_of_naming_a_protocol_are_understood() {
    let settings = settings(EXCHANGE_SE);
    let types: Vec<_> = settings
        .protocols()
        .iter()
        .map(|protocol| protocol.protocol_type().to_string())
        .collect();

    assert_eq!(types, vec!["mapiHttp", "WEB"]);
}

/// The `WEB` protocol nests further `Protocol` elements inside `<Internal>`. A descendant search
/// would hoist that nested `EXCH` to the top level, as if the server had offered it there.
#[test]
fn nested_protocols_are_not_hoisted_to_the_top_level() {
    let settings = settings(EXCHANGE_SE);
    assert_eq!(settings.protocols().len(), 2);
    assert!(
        !settings
            .protocols()
            .iter()
            .any(|protocol| *protocol.protocol_type() == ProtocolType::Exch),
        "the nested EXCH protocol was read as a top-level one"
    );
}

#[test]
fn a_deployment_without_mapi_http_says_so_rather_than_guessing() {
    let xml = response(
        "<User><LegacyDN>/o=X/cn=y</LegacyDN></User>
         <Account>
           <Action>settings</Action>
           <Protocol>
             <Type>EXPR</Type>
             <Server>rpc.contoso.com</Server>
             <AuthPackage>Ntlm</AuthPackage>
           </Protocol>
         </Account>",
    );

    let settings = settings(&xml);
    assert_eq!(settings.mapi_http(), None);

    let protocol = settings.protocols().first().unwrap();
    assert_eq!(*protocol.protocol_type(), ProtocolType::Expr);
    assert_eq!(protocol.server(), Some("rpc.contoso.com"));
    assert_eq!(protocol.auth_package(), Some("Ntlm"));
    assert_eq!(protocol.version(), None);
    assert!(protocol.mail_store().is_empty());
    assert!(protocol.address_book().is_empty());
}

#[test]
fn an_external_url_is_used_when_there_is_no_internal_one() {
    let xml = response(
        "<User><LegacyDN>/o=X/cn=y</LegacyDN></User>
         <Account><Action>settings</Action>
           <Protocol Type=\"mapiHttp\" Version=\"1\">
             <MailStore>
               <ExternalUrl>https://mail.contoso.com/mapi/emsmdb/?MailboxId=x</ExternalUrl>
             </MailStore>
           </Protocol>
         </Account>",
    );

    let endpoint = settings(&xml).mapi_http().unwrap();
    assert_eq!(endpoint.mail_store().internal(), None);
    assert!(
        endpoint
            .mail_store_url()
            .unwrap()
            .starts_with("https://mail.")
    );
    assert_eq!(endpoint.address_book_url(), None);
}

#[test]
fn a_redirect_to_another_address_is_reported_as_one() {
    let xml = response(
        "<Account>
           <Action>redirectAddr</Action>
           <RedirectAddr>user@other.example</RedirectAddr>
         </Account>",
    );

    assert_eq!(
        AutodiscoverResponse::parse(&xml).unwrap(),
        AutodiscoverResponse::RedirectAddress(EmailAddress::new("user@other.example").unwrap())
    );
}

#[test]
fn a_redirect_to_another_url_is_reported_as_one() {
    let url = "https://autodiscover.other.example/Autodiscover/Autodiscover.xml";
    let xml = response(&format!(
        "<Account>
           <Action>redirectUrl</Action>
           <RedirectUrl>{url}</RedirectUrl>
         </Account>"
    ));

    assert_eq!(
        AutodiscoverResponse::parse(&xml).unwrap(),
        AutodiscoverResponse::RedirectUrl(url.to_owned())
    );
}

#[test]
fn a_redirect_that_does_not_say_where_to_is_an_error() {
    for action in ["redirectAddr", "redirectUrl"] {
        let xml = response(&format!("<Account><Action>{action}</Action></Account>"));
        assert_eq!(
            AutodiscoverResponse::parse(&xml),
            Err(Error::IncompleteRedirect {
                action: action.to_owned()
            })
        );
    }
}

#[test]
fn a_redirect_to_an_unusable_address_is_refused() {
    let xml = response(
        "<Account>
           <Action>redirectAddr</Action>
           <RedirectAddr>not an address</RedirectAddr>
         </Account>",
    );

    assert!(matches!(
        AutodiscoverResponse::parse(&xml),
        Err(Error::InvalidEmailAddress { .. })
    ));
}

/// A server error is an answer, not a parse failure: the documented reaction is to try the next
/// candidate URL.
#[test]
fn a_server_error_is_reported_as_an_answer() {
    let xml = response(
        "<Error Time=\"16:56:32.6194367\" Id=\"2422600485\">
           <ErrorCode>600</ErrorCode>
           <Message>Invalid Request</Message>
           <DebugData />
         </Error>",
    );

    let AutodiscoverResponse::Failed(error) = AutodiscoverResponse::parse(&xml).unwrap() else {
        panic!("expected a server error");
    };
    assert_eq!(error.code(), Some(600));
    assert_eq!(error.message(), Some("Invalid Request"));
    assert_eq!(error.debug_data(), None, "an empty DebugData is not data");
    assert_eq!(error.to_string(), "Autodiscover error 600: Invalid Request");
}

#[test]
fn a_server_error_prints_whatever_it_was_given() {
    for (inner, expected) in [
        (
            "<Error><ErrorCode>500</ErrorCode></Error>",
            "Autodiscover error 500",
        ),
        (
            "<Error><Message>no code</Message></Error>",
            "Autodiscover error: no code",
        ),
        (
            "<Error/>",
            "Autodiscover error, with no code and no message",
        ),
    ] {
        let xml = response(inner);
        let AutodiscoverResponse::Failed(error) = AutodiscoverResponse::parse(&xml).unwrap() else {
            panic!("expected a server error");
        };
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn malformed_and_unrelated_documents_are_told_apart() {
    assert!(matches!(
        AutodiscoverResponse::parse("<Autodiscover><Response>"),
        Err(Error::MalformedXml { .. })
    ));
    assert!(matches!(
        AutodiscoverResponse::parse(""),
        Err(Error::MalformedXml { .. })
    ));
    assert_eq!(
        AutodiscoverResponse::parse("<html><body>Sign in</body></html>"),
        Err(Error::MissingElement {
            element: "Response"
        })
    );
}

/// The classic XML attack: an entity that reads a file off the parser's own disk. `roxmltree` does
/// not expand external entities, so this stays an error rather than becoming a file read.
#[test]
fn external_entities_are_not_expanded() {
    let body = response(
        "<User><DisplayName>&xxe;</DisplayName></User>
         <Account><Action>settings</Action></Account>",
    );
    let xml = format!(
        "<?xml version=\"1.0\"?>
         <!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\"> ]>
         {body}"
    );

    match AutodiscoverResponse::parse(&xml) {
        Err(Error::MalformedXml { .. }) => {}
        Ok(AutodiscoverResponse::Settings(settings)) => {
            let name = settings.user().display_name().unwrap_or_default();
            assert!(
                !name.contains("[fonts]") && !name.contains("[extensions]"),
                "an external entity was expanded: {name:?}"
            );
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn text_is_trimmed_because_the_specifications_own_examples_wrap_lines() {
    let xml = response(
        "<User><LegacyDN>
           /o=X/cn=y
         </LegacyDN></User>
         <Account><Action>settings</Action></Account>",
    );
    assert_eq!(settings(&xml).user().legacy_dn(), Some("/o=X/cn=y"));
}

#[test]
fn a_response_without_settings_has_none_to_hand_out() {
    let xml = response(
        "<Account>
           <Action>redirectUrl</Action>
           <RedirectUrl>https://x.example/Autodiscover/Autodiscover.xml</RedirectUrl>
         </Account>",
    );
    assert_eq!(AutodiscoverResponse::parse(&xml).unwrap().settings(), None);
}

/// The counterpart to the test above: the same accessor that answers `None` for a redirect has to
/// hand the settings out when the server did send them.
#[test]
fn a_settings_response_hands_its_settings_out() {
    let xml = response(
        "<User><DisplayName>Someone</DisplayName></User>
         <Account><Action>settings</Action></Account>",
    );

    let parsed = AutodiscoverResponse::parse(&xml).unwrap();
    let settings = parsed.settings().expect("a settings response has settings");

    assert_eq!(settings.user().display_name(), Some("Someone"));
}

/// A response with no `Account` at all is not a failure to parse: the `User` element on its own is
/// still an answer about the mailbox.
#[test]
fn a_response_with_only_a_user_still_parses() {
    let xml = response("<User><DisplayName>Someone</DisplayName></User>");
    let settings = settings(&xml);

    assert_eq!(settings.user().display_name(), Some("Someone"));
    assert!(settings.protocols().is_empty());
    assert_eq!(settings.mapi_http(), None, "no LegacyDN, so no endpoint");
}

/// The namespaces are documented but not enforced, because the outer element and the inner one are
/// in *different* namespaces and a reader that insists on either one finds nothing.
#[test]
fn both_namespaces_are_accepted() {
    let outer = "http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006";
    let inner = "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a";
    let xml = format!(
        "<Autodiscover xmlns=\"{outer}\">
           <Response xmlns=\"{inner}\">
             <User><DisplayName>Someone</DisplayName></User>
           </Response>
         </Autodiscover>"
    );

    assert_eq!(settings(&xml).user().display_name(), Some("Someone"));
}
