// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::digest_challenge::{DIGEST_CHALLENGE_QUOTING_INVALID, RFC_7616_3_3};
use crate::violations::ViolationDef;

/// One entry, for the one thing § 3.3 says about a challenge's parameters that
/// nothing else in this crate reads.
static DECLARED: &[&ViolationDef] = &[&DIGEST_CHALLENGE_QUOTING_INVALID];

/// The parameters § 3.3 requires a challenge to write as a `quoted-string`.
// cite(RFC 7616 § 3.3): "For historical reasons, a sender MUST only generate the quoted string syntax values for the following parameters: realm, domain, nonce, opaque, and qop."
const MUST_QUOTE: &[&str] = &["realm", "domain", "nonce", "opaque", "qop"];

/// And the ones it requires a challenge not to.
// cite(RFC 7616 § 3.3): "For historical reasons, a sender MUST NOT generate the quoted string syntax values for the following parameters: stale and algorithm."
const MUST_NOT_QUOTE: &[&str] = &["stale", "algorithm"];

/// Report a `Digest` challenge whose parameters are spelled the way § 3.3
/// refuses.
///
/// **The mirror of `digest_auth_valid`, and the reason it is a second rule is
/// the reason the entry is a second entry.** That rule reads § 3.4 over
/// `Authorization` and `Proxy-Authorization`; this reads § 3.3 over
/// `WWW-Authenticate` and `Proxy-Authenticate`. The two sections write
/// different quoting lists — `qop` is quoted in a challenge and unquoted in
/// credentials — so a reader answering for both would have to hold two
/// contradictory claims about one parameter name, and a finding names a
/// different sender each way.
///
/// **Only the quoting.** § 3.3 says a good deal more about a challenge — that
/// `charset` admits one value, that `userhash` admits two, that `domain` is a
/// space-separated list of URIs — and none of it is read here. Those are
/// further entries on this subject rather than this rule's silence being an
/// argument that they do not exist; `description()` says so, because a rule
/// named after a section is read as answering for it.
pub struct DigestChallengeValid;

impl RuleMeta for DigestChallengeValid {
    fn id(&self) -> &'static str {
        "digest_challenge_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Reports a `Digest` challenge that writes one of its parameters in the syntax RFC 7616 §3.3 refuses for it. The section closes with two sentences: \"For historical reasons, a sender MUST only generate the quoted string syntax values for the following parameters: realm, domain, nonce, opaque, and qop\", and \"For historical reasons, a sender MUST NOT generate the quoted string syntax values for the following parameters: stale and algorithm\".\n\n**The lists are the challenge's, not the credential's.** §3.4 writes the same pair of sentences about what a client sends back, over a different set of names — and `qop` is on the opposite side of each: a server must quote it, a client must not. `digest_auth_valid` enforces §3.4 over `Authorization` and `Proxy-Authorization`; this rule enforces §3.3 over `WWW-Authenticate` and `Proxy-Authenticate`, and neither answers for the other.\n\n**Both spellings derive from the grammar**, which is why this is a rule and not a parse error: §11.2's `auth-param` offers `token / quoted-string` for every value, and RFC 7616 removes the choice per parameter for reasons it states outright. What it costs a sender is that recipients of these parameters were deployed against one spelling each.\n\n**Only the quoting is read here.** §3.3 also says `charset`'s only allowed value is \"UTF-8\", that `userhash` is \"true\" or \"false\", and that `domain` is a space-separated list of URIs. None of that is checked by this rule, and its silence about them is not a claim that they hold."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_7616_3_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// The challenge is the server's, in both fields that carry one: § 11.7.1
    /// writes `Proxy-Authenticate` as the same production offered by whoever
    /// answered, and a proxy inserting its own occupies the server position on
    /// the seam this reads.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(every parameter on the side its own list puts it)"),
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Digest realm=\"users\", nonce=\"abc\", qop=\"auth\", stale=false, algorithm=SHA-256",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a nonce the section admits only as a quoted-string)"),
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Digest realm=\"users\", nonce=abc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(qop is quoted in a challenge and unquoted in credentials)"),
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Digest realm=\"users\", nonce=\"abc\", qop=auth",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(and the list pointing the other way)"),
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Digest realm=\"users\", nonce=\"abc\", stale=\"true\"",
            },
        ]
    }
}

impl Rule for DigestChallengeValid {
    fn needs_response(&self) -> bool {
        // A challenge only exists in a response, so a transaction with none has
        // nothing here to read.
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(resp) = &tx.response else {
            return Vec::new();
        };
        let mut out = Vec::new();
        // Both fields § 11 writes as `#challenge`, walked from the shared list
        // rather than named here: RFC 7616 § 3.8 has the scheme authenticate to
        // proxies through the second, and a reader that named only the first is
        // how the proxy half of § 11.7 came to be unread before.
        // cite(RFC 7616 § 3.8): "The Digest Authentication scheme can also be used for authenticating users to proxies, proxies to proxies, or proxies to origin servers by use of the Proxy-Authenticate and Proxy-Authorization header fields."
        for field in crate::helpers::auth::CHALLENGE_FIELDS {
            let Some(value) =
                crate::helpers::headers::combined_field_value_as_written(&resp.headers, field.key)
            else {
                continue;
            };
            // A defect of the list -- an empty member, a parameter before any
            // scheme -- is the framework reader's finding and not this one's:
            // `challenge_list_defects` reports it under the production it
            // broke, and the challenges beside it are read here as any others.
            let (challenges, _) = crate::helpers::auth::split_and_group_challenges(&value);
            for challenge in &challenges {
                // The scheme is a case-insensitive token, and only this one
                // scheme's document writes the lists below.
                // cite(RFC 9110 § 11.1): "It uses a case-insensitive token to identify the authentication scheme"
                let (scheme, tail) = crate::helpers::auth::split_scheme_and_tail(
                    crate::helpers::headers::trim_ows(challenge),
                );
                if !scheme.eq_ignore_ascii_case("digest") {
                    continue;
                }
                let Some(rest) = tail else { continue };
                // A parameter list that will not parse is the framework's to
                // report, for the same reason the grouping above is.
                // A malformed member is the framework reader's finding; the
                // members beside it are graded here as they would be alone.
                let (params, _) = crate::helpers::auth::parse_auth_params(rest);
                // **Every parameter, not the first.** A challenge writing two
                // of them in the wrong syntax is two values to respell, and one
                // finding naming one of them would leave the sender to
                // rediscover the other after the repair.
                for (name, value) in &params {
                    let quoted = value.starts_with('"');
                    let name = name.as_str();
                    if MUST_QUOTE.contains(&name) && !quoted {
                        // The value is a `token` on this branch, so wrapping it
                        // in DQUOTEs is always the repair and the message can
                        // say so outright.
                        out.push(ctx.by_server().report_with(
                            &DIGEST_CHALLENGE_QUOTING_INVALID,
                            format!(
                                "{} writes the Digest challenge parameter '{name}' as the token '{shown}', and RFC 7616 \u{a7}3.3 admits only the quoted string syntax for it (\"a sender MUST only generate the quoted string syntax values for the following parameters: realm, domain, nonce, opaque, and qop\") \u{2014} write {name}=\"{shown}\" instead",
                                field.shown,
                                shown = crate::helpers::shown::shown_in_finding(value)
                            ),
                        ));
                    } else if MUST_NOT_QUOTE.contains(&name) && quoted {
                        // **The interior, not the value as written.** A
                        // `quoted-string` shown whole comes back with its
                        // DQUOTEs escaped, so the message would print a string
                        // no reader can find in the response — and the DQUOTEs
                        // are the thing being reported, not part of the value.
                        //
                        // The repair is only named where the interior is a
                        // `token`, because that is the only case where removing
                        // the DQUOTEs leaves something `auth-param` derives. An
                        // interior that is not one is a second thing wrong and
                        // this rule does not guess at it.
                        let inner = crate::helpers::quoted_string::unescape_quoted_string(value)
                            .unwrap_or_else(|_| value.to_string());
                        let shown = crate::helpers::shown::shown_in_finding(&inner);
                        let repair = if crate::helpers::token::find_invalid_token_char(&inner)
                            .is_none()
                            && !inner.is_empty()
                        {
                            format!(" \u{2014} write {name}={shown} instead")
                        } else {
                            String::new()
                        };
                        out.push(ctx.by_server().report_with(
                            &DIGEST_CHALLENGE_QUOTING_INVALID,
                            format!(
                                "{} writes the Digest challenge parameter '{name}' as a quoted string holding '{shown}', and RFC 7616 \u{a7}3.3 forbids that spelling for it (\"a sender MUST NOT generate the quoted string syntax values for the following parameters: stale and algorithm\"){repair}",
                                field.shown,
                            ),
                        ));
                    }
                }
            }
        }
        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &DigestChallengeValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn judge(status: u16, field: &str, value: &str) -> Vec<Violation> {
        let tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        let mut tx = tx;
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[(field, value)]);
        crate::test_helpers::run_rule_all(
            &DigestChallengeValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["digest_challenge_valid"]),
        )
    }

    /// The two lists of § 3.3, and the parameter that sits on the opposite one
    /// in § 3.4.
    #[rstest]
    #[case(r#"Digest realm="r", nonce=abc"#, 1)]
    #[case(r#"Digest realm=r, nonce="n""#, 1)]
    #[case(r#"Digest realm="r", nonce="n", opaque=xyz"#, 1)]
    // `qop` is quoted in a challenge and unquoted in a credential, which is the
    // whole reason this is a second entry from `digest_credentials_quoting_invalid`.
    #[case(r#"Digest realm="r", nonce="n", qop=auth"#, 1)]
    #[case(r#"Digest realm="r", nonce="n", stale="true""#, 1)]
    #[case(r#"Digest realm="r", nonce="n", algorithm="MD5""#, 1)]
    // Every parameter on the side its own list puts it.
    #[case(
        r#"Digest realm="r", nonce="n", qop="auth", stale=false, algorithm=SHA-256"#,
        0
    )]
    // A parameter on neither list is judged by neither: § 3.3 names seven and
    // says nothing about the spelling of anything else.
    #[case(r#"Digest realm="r", nonce="n", charset=UTF-8, userhash="true""#, 0)]
    // Another scheme's challenge is another document's.
    #[case(r#"Basic realm=r"#, 0)]
    // A member the framework refuses is its reader's finding, and does not
    // withdraw this one: the parse used to answer the whole challenge with
    // the first refused member, so the `nonce` beside it went unread.
    #[case(r#"Digest realm="r", nonce=abc, =x"#, 1)]
    #[case(r#"Digest realm="r", b@d=1, nonce=abc"#, 1)]
    fn the_two_lists_are_read_over_a_digest_challenge(
        #[case] value: &str,
        #[case] expected: usize,
    ) {
        let v = judge(401, "www-authenticate", value);
        assert_eq!(v.len(), expected, "{value}: {v:?}");
        assert!(v
            .iter()
            .all(|f| f.violation == "digest_challenge_quoting_invalid"));
    }

    /// **Every parameter, not the first.** A challenge misspelling two of them
    /// is two values to respell, and the walk that answered once left the
    /// sender to rediscover the second after fixing the first.
    #[test]
    fn a_challenge_answers_for_each_parameter_it_misspells() {
        let v = judge(
            401,
            "www-authenticate",
            r#"Digest realm=r, nonce=n, stale="true""#,
        );
        assert_eq!(v.len(), 3, "{v:?}");
    }

    /// § 11.7.1 writes the proxy's field as the same production and RFC 7616
    /// § 3.8 has the scheme authenticate to proxies through it, so naming one
    /// field in the reader would have left the other unread.
    #[test]
    fn the_proxy_field_carries_the_same_challenge() {
        let v = judge(407, "proxy-authenticate", r#"Digest realm="r", nonce=abc"#);
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].message.contains("Proxy-Authenticate"));
    }

    /// The DQUOTEs are what the finding is about, so the message shows the
    /// interior rather than the value as written — a `quoted-string` rendered
    /// whole comes back with its delimiters escaped, and an operator grepping
    /// the response for that string finds nothing.
    #[test]
    fn a_quoted_value_is_shown_without_the_delimiters_it_is_reported_for() {
        let v = judge(
            401,
            "www-authenticate",
            r#"Digest realm="r", nonce="n", stale="true""#,
        );
        let m = &v[0].message;
        assert!(m.contains("holding 'true'"), "{m}");
        assert!(!m.contains('\\'), "{m}");
        assert!(m.contains("write stale=true instead"), "{m}");
    }
}
