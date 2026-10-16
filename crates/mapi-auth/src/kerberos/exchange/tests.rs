//! The AS and TGS exchanges, driven end to end against [`double::Forest`].

use super::double::{Fault, Forest, KDC_TIME, Realm, User, WRONG_PASSWORD};
use super::*;

fn alice() -> User {
    User {
        name: "alice",
        upn: "alice@example.test",
        password: "hunter2",
        preauth: true,
    }
}

/// A root realm holding the service, and a child realm whose KDC refers to it — the shape of the
/// lab's own forest.
fn forest() -> Forest {
    Forest::new(vec![
        Realm {
            name: "EXAMPLE.TEST",
            users: vec![
                alice(),
                User {
                    name: "carol",
                    upn: "carol@example.test",
                    password: "hunter3",
                    preauth: false,
                },
            ],
            services: vec!["HTTP/mail.example.test", "HOST/other.example.test"],
            referral: None,
        },
        Realm {
            name: "CHILD.EXAMPLE.TEST",
            users: vec![User {
                name: "bob",
                upn: "bob@child.example.test",
                password: "hunter2",
                preauth: true,
            }],
            services: Vec::new(),
            referral: Some("EXAMPLE.TEST"),
        },
    ])
}

/// A chain of `len` realms, each referring to the next, with the service in the last.
fn chain(len: usize) -> Forest {
    const NAMES: [&str; 8] = [
        "R0.TEST", "R1.TEST", "R2.TEST", "R3.TEST", "R4.TEST", "R5.TEST", "R6.TEST", "R7.TEST",
    ];
    let names = &NAMES[..len];
    Forest::new(
        names
            .iter()
            .zip(names.iter().skip(1).map(Some).chain([None]))
            .map(|(name, next)| Realm {
                name,
                users: if *name == "R0.TEST" {
                    vec![alice()]
                } else {
                    Vec::new()
                },
                services: if next.is_none() {
                    vec!["HTTP/mail.example.test"]
                } else {
                    Vec::new()
                },
                referral: next.copied(),
            })
            .collect(),
    )
}

fn service() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_INST, &["HTTP", "mail.example.test"])
}

fn upn(name: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_ENTERPRISE, &[name])
}

fn fresh(seed: u8) -> Fresh {
    Fresh {
        now: Duration::from_secs(KDC_TIME),
        random: [seed; 20],
    }
}

/// Runs an acquisition to its end against `forest`.
fn drive(forest: &mut Forest, start: Result<(Acquisition, KdcRequest)>) -> Result<Tickets> {
    let (mut acquisition, mut request) = start?;
    for seed in 1..32 {
        let reply = forest.answer(&request.realm, &request.message);
        match acquisition.receive(&reply, &fresh(seed)) {
            Ok(Step::Send(next)) => request = next,
            Ok(Step::Done(tickets)) => return Ok(*tickets),
            Err(error) => {
                let after = acquisition.receive(&reply, &fresh(seed));
                assert!(
                    matches!(after, Err(Error::OutOfOrder { .. })),
                    "an error ends it"
                );
                return Err(error);
            }
        }
    }
    panic!("an acquisition that never ends");
}

fn logon(
    forest: &mut Forest,
    client: PrincipalName,
    realm: &str,
    password: &str,
) -> Result<Tickets> {
    drive(
        forest,
        Acquisition::with_password(client, realm, password.to_owned(), service(), &fresh(0)),
    )
}

fn reason(result: Result<Tickets>) -> &'static str {
    match result {
        Err(Error::KdcReply { reason, .. }) => reason,
        other => panic!("expected a refused reply, got {other:?}"),
    }
}

/// The whole of a password logon: AS without and then with pre-authentication, then the TGS.
#[test]
fn a_password_logon_ends_with_the_service_ticket() {
    let mut forest = forest();
    let tickets = logon(
        &mut forest,
        upn("alice@example.test"),
        "EXAMPLE.TEST",
        "hunter2",
    )
    .unwrap();
    assert_eq!(forest.asked, ["EXAMPLE.TEST"; 3]);

    assert!(tickets.tgt.ticket.sname.is_krbtgt());
    assert_eq!(tickets.tgt.ticket.realm, "EXAMPLE.TEST");
    // The UPN went in as NT-ENTERPRISE; the canonical name came back, and is what is kept.
    assert_eq!(tickets.tgt.cname, PrincipalName::new(1, &["alice"]));
    assert_eq!(tickets.tgt.crealm, "EXAMPLE.TEST");
    assert_eq!(tickets.service.ticket.sname, service());
    assert_eq!(tickets.service.cname, tickets.tgt.cname);
    assert_eq!(tickets.service.key.enctype(), Enctype::Aes256Sha1);
    assert_eq!(
        tickets.service.endtime,
        KerberosTime::from_unix(KDC_TIME + 36_000)
    );
    assert_ne!(
        tickets.service.flags & flag(1),
        0,
        "the KDC's flags are kept"
    );
    assert_eq!(tickets.clock_offset, 0);

    // The ticket-granting ticket buys the next service without the password.
    let next = PrincipalName::new(PrincipalName::NT_SRV_INST, &["HOST", "other.example.test"]);
    let more = drive(
        &mut forest,
        Acquisition::with_tgt(tickets.tgt.clone(), next.clone(), 0, &fresh(9)),
    )
    .unwrap();
    assert_eq!(more.service.ticket.sname, next);
    assert_eq!(more.tgt, tickets.tgt);
    assert_eq!(forest.asked.len(), 4);
}

#[test]
fn a_wrong_password_is_the_kdcs_refusal_with_its_status() {
    let error = logon(
        &mut forest(),
        upn("alice@example.test"),
        "EXAMPLE.TEST",
        "hunter3",
    )
    .unwrap_err();
    assert_eq!(
        error,
        Error::KdcRefused {
            realm: "EXAMPLE.TEST".to_owned(),
            code: 24,
            status: Some(WRONG_PASSWORD),
        }
    );
}

#[test]
fn unknown_accounts_and_services_are_the_kdcs_refusals() {
    let unknown = logon(
        &mut forest(),
        PrincipalName::new(1, &["nobody"]),
        "EXAMPLE.TEST",
        "x",
    );
    assert!(matches!(
        unknown,
        Err(Error::KdcRefused {
            code: 6,
            status: None,
            ..
        })
    ));

    let mut forest = forest();
    let nowhere = PrincipalName::new(2, &["HTTP", "nowhere.example.test"]);
    let result = drive(
        &mut forest,
        Acquisition::with_password(
            upn("alice@example.test"),
            "EXAMPLE.TEST",
            "hunter2".to_owned(),
            nowhere,
            &fresh(0),
        ),
    );
    assert!(matches!(result, Err(Error::KdcRefused { code: 7, .. })));
}

/// Both kinds of referral in one logon, the lab's own path: a child-realm user named by UPN and
/// sent first to the root realm ([RFC 6806] §7), then a service in the root realm, reached by a
/// referral from the child's KDC ([RFC 6806] §8).
#[test]
fn a_child_realm_user_reaches_a_root_realm_service() {
    let mut forest = forest();
    let tickets = logon(
        &mut forest,
        upn("bob@child.example.test"),
        "EXAMPLE.TEST",
        "hunter2",
    )
    .unwrap();
    assert_eq!(
        forest.asked,
        [
            "EXAMPLE.TEST",
            "CHILD.EXAMPLE.TEST",
            "CHILD.EXAMPLE.TEST",
            "CHILD.EXAMPLE.TEST",
            "EXAMPLE.TEST"
        ]
    );
    assert_eq!(tickets.tgt.ticket.realm, "CHILD.EXAMPLE.TEST");
    assert_eq!(tickets.service.ticket.realm, "EXAMPLE.TEST");
    assert_eq!(
        tickets.service.crealm, "CHILD.EXAMPLE.TEST",
        "the client keeps its own realm"
    );
}

#[test]
fn referrals_stop_at_five_and_never_go_back() {
    let five = logon(
        &mut chain(6),
        upn("alice@example.test"),
        "R0.TEST",
        "hunter2",
    )
    .unwrap();
    assert_eq!(five.service.ticket.realm, "R5.TEST");
    let six = logon(
        &mut chain(7),
        upn("alice@example.test"),
        "R0.TEST",
        "hunter2",
    );
    assert_eq!(reason(six), "more referrals than RFC 6806's limit of five");

    let mut circle = chain(2);
    circle.realms[1].services.clear();
    circle.realms[1].referral = Some("R0.TEST");
    let result = logon(&mut circle, upn("alice@example.test"), "R0.TEST", "hunter2");
    assert_eq!(reason(result), "a referral back to a realm already asked");

    let mut forest = forest();
    forest.fault = Some(Fault::ReferToItself);
    let result = logon(
        &mut forest,
        upn("alice@example.test"),
        "EXAMPLE.TEST",
        "hunter2",
    );
    assert_eq!(reason(result), "a client referral to no other realm");
}

/// [RFC 4120] §3.1.5's clock offset, learned from the KDC's `KRB_AP_ERR_SKEW` and used from then
/// on — in the AS exchange, and again when a cached TGT meets a KDC whose clock has moved.
#[test]
fn a_skewed_clock_is_corrected_once() {
    let mut forest = forest();
    forest.clock = KDC_TIME + 1_000;
    let tickets = logon(
        &mut forest,
        upn("alice@example.test"),
        "EXAMPLE.TEST",
        "hunter2",
    )
    .unwrap();
    assert_eq!(tickets.clock_offset, 1_000);
    assert_eq!(forest.asked.len(), 4, "one extra AS-REQ");

    forest.clock = KDC_TIME - 2_000;
    let again = drive(
        &mut forest,
        Acquisition::with_tgt(tickets.tgt, service(), 1_000, &fresh(9)),
    )
    .unwrap();
    assert_eq!(again.clock_offset, -2_000);
}

#[test]
fn a_clock_that_keeps_moving_is_refused() {
    let mut forest = forest();
    forest.clock = KDC_TIME + 1_000;
    let tickets = logon(
        &mut forest,
        upn("alice@example.test"),
        "EXAMPLE.TEST",
        "hunter2",
    )
    .unwrap();
    forest.clock = KDC_TIME + 5_000;
    let (mut acquisition, request) =
        Acquisition::with_tgt(tickets.tgt, service(), 0, &fresh(1)).unwrap();
    let skew = forest.answer(&request.realm, &request.message);
    let Step::Send(retry) = acquisition.receive(&skew, &fresh(2)).unwrap() else {
        panic!("a retry")
    };
    forest.clock = KDC_TIME + 9_000;
    let skew = forest.answer(&retry.realm, &retry.message);
    assert!(matches!(
        acquisition.receive(&skew, &fresh(3)),
        Err(Error::KdcRefused { code: 37, .. })
    ));
}

/// An account without pre-authentication is answered at once, and the AS-REP's own
/// `PA-ETYPE-INFO2` says how to make the key that decrypts it.
#[test]
fn an_account_without_pre_authentication_is_answered_at_once() {
    let mut forest = forest();
    let tickets = logon(
        &mut forest,
        upn("carol@example.test"),
        "EXAMPLE.TEST",
        "hunter3",
    )
    .unwrap();
    assert_eq!(forest.asked.len(), 2);
    assert_eq!(tickets.tgt.cname.components, ["carol"]);

    // There is no KDC refusal to catch a wrong password then: the reply simply does not decrypt.
    let wrong = logon(
        &mut forest,
        upn("carol@example.test"),
        "EXAMPLE.TEST",
        "hunter2",
    );
    assert!(matches!(wrong, Err(Error::Crypto { usage: Some(3), .. })));
}

/// [RFC 4120] §4's default salt, for a KDC that names none. Active Directory always names one.
#[test]
fn a_kdc_that_sends_no_salt_gets_the_default_one() {
    let mut forest = forest();
    forest.salts = false;
    logon(
        &mut forest,
        PrincipalName::new(1, &["alice"]),
        "EXAMPLE.TEST",
        "hunter2",
    )
    .unwrap();
}

#[test]
fn fresh_input_is_split_and_the_nonce_kept_to_31_bits() {
    let mut random = [0xFF; 20];
    random[4..].copy_from_slice(&[7; 16]);
    let fresh = Fresh {
        now: Duration::new(1_000, 123_456_789),
        random,
    };
    assert_eq!(fresh.nonce(), 0x7FFF_FFFF);
    assert_eq!(fresh.confounder(), [7; 16]);
    assert_eq!(fresh.stamp(0), (KerberosTime::from_unix(1_000), 123_456));
    assert_eq!(fresh.stamp(-400).0, KerberosTime::from_unix(600));
    assert_eq!(fresh.stamp(i64::MIN).0, KerberosTime::from_unix(0));
}

/// [MS-KILE] §3.1.5.7: case-insensitive, beyond ASCII, and nothing else.
#[test]
fn names_compare_without_case_and_without_normalisation() {
    assert!(same_text("ÄLICE.EXAMPLE.TEST", "älice.example.test"));
    assert!(
        !same_text("alice", "alicе"),
        "a Cyrillic е is not a Latin e"
    );
    assert!(!same_text("e\u{301}", "\u{e9}"), "no normalisation");
    assert!(same_name(
        &service(),
        &PrincipalName::new(10, &["http", "MAIL.example.test"])
    ));
    assert!(!same_name(&service(), &PrincipalName::new(2, &["HTTP"])));
    assert_eq!(referral_realm(&krbtgt("NEXT.TEST")), Some("NEXT.TEST"));
    assert_eq!(referral_realm(&service()), None);
    assert_eq!(referral_realm(&PrincipalName::new(2, &["krbtgt"])), None);
}

mod faults;
