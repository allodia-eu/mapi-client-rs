//! Reading `WWW-Authenticate`: one challenge per scheme, however the server wrote them.
//!
//! [RFC 9110] §11.6.1 defines the header as `#challenge`, a list, so one header can carry several
//! challenges, separated by commas. IIS sends one header per scheme, but a proxy in front of it
//! may fold them into one. A comma also separates one challenge's auth-params, so an element only
//! starts a new challenge when it opens with a scheme: a token followed by a space or by nothing.
//! A token followed by `=` is an auth-param, and stays with the challenge before it.
//!
//! [RFC 9110] §11.6.1 — `WWW-Authenticate`
//! [RFC 9110] §11.3 — `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`

use reqwest::Response;

/// Every challenge the `WWW-Authenticate` headers carry, one per scheme, in the order given.
pub(crate) fn challenges(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(split)
        .collect()
}

/// The scheme each challenge names, which is what an error message quotes.
pub(crate) fn scheme_names(challenges: &[String]) -> Vec<String> {
    challenges
        .iter()
        .filter_map(|value| value.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// One header value's challenges.
fn split(value: &str) -> Vec<String> {
    let mut challenges: Vec<String> = Vec::new();
    // [RFC 9110] §5.6.1: a recipient ignores empty list elements.
    for element in elements(value)
        .map(str::trim)
        .filter(|element| !element.is_empty())
    {
        match challenges.last_mut() {
            Some(last) if !starts_challenge(element) => {
                last.push_str(", ");
                last.push_str(element);
            }
            _ => challenges.push(element.to_owned()),
        }
    }
    challenges
}

/// A list's comma-separated elements; a comma inside a quoted string separates nothing.
fn elements(value: &str) -> impl Iterator<Item = &str> {
    let mut quoted = false;
    let mut escaped = false;
    value.split(move |character| {
        if escaped {
            escaped = false;
            return false;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' => return !quoted,
            _ => {}
        }
        false
    })
}

/// Whether a list element opens a challenge, rather than carrying the next auth-param of the one
/// before it.
fn starts_challenge(element: &str) -> bool {
    let token = element.find([' ', '\t', '=']).unwrap_or(element.len());
    token > 0
        && !element
            .get(token..)
            .unwrap_or_default()
            .trim_start()
            .starts_with('=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_challenge_per_header_comes_back_as_it_was_sent() {
        assert_eq!(split("NTLM"), ["NTLM"]);
        assert_eq!(split("Basic realm=\"mail\""), ["Basic realm=\"mail\""]);
        assert_eq!(
            split("Negotiate oYGBMH+gAwoBAaE=="),
            ["Negotiate oYGBMH+gAwoBAaE=="]
        );
    }

    /// The `Bearer` challenge Exchange Server SE `15.02.2562.056` sends is one challenge with two
    /// auth-params, and stays one.
    #[test]
    fn auth_params_stay_with_their_challenge() {
        let bearer = "Bearer client_id=\"00000002-0000-0ff1-ce00-000000000000\", \
                      token_types=\"app_asserted_user_v1 service_asserted_app_v1\"";
        assert_eq!(split(bearer), [bearer]);
        assert_eq!(
            split("Basic realm = \"x\", charset=UTF-8"),
            ["Basic realm = \"x\", charset=UTF-8"]
        );
    }

    #[test]
    fn folded_challenges_are_taken_apart() {
        assert_eq!(
            split("Negotiate, NTLM, Basic realm=\"mail\", charset=UTF-8"),
            ["Negotiate", "NTLM", "Basic realm=\"mail\", charset=UTF-8"]
        );
    }

    #[test]
    fn a_comma_in_a_quoted_string_separates_nothing() {
        assert_eq!(
            split("Basic realm=\"a, \\\"b\\\", c\", Negotiate"),
            ["Basic realm=\"a, \\\"b\\\", c\"", "Negotiate"]
        );
    }

    #[test]
    fn empty_elements_are_ignored() {
        assert_eq!(split(" , NTLM,, "), ["NTLM"]);
        assert!(split("").is_empty());
        assert_eq!(
            scheme_names(&split("Basic realm=x, NTLM")),
            ["Basic", "NTLM"]
        );
    }
}
