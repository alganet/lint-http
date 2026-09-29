// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::auth_param::RFC_9110_11_5;
use crate::violations::challenge::CHALLENGE_REALM_AMBIGUOUS;
use crate::violations::ViolationDef;

pub struct AuthenticationChallengeValid;

/// One entry, and it is the challenge subject's rather than the field's: the
/// production is `WWW-Authenticate`'s today and `Proxy-Authenticate`'s the day
/// a rule reads one, and a realm blurred across two schemes is the same
/// configuration either way.
static DECLARED: &[&ViolationDef] = &[&CHALLENGE_REALM_AMBIGUOUS];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_11_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("11.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1",
    note: "WWW-Authenticate",
};

impl RuleMeta for AuthenticationChallengeValid {
    fn id(&self) -> &'static str {
        "authentication_challenge_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Warn when a single response advertises the same `realm` value across multiple authentication schemes of one challenge field — `WWW-Authenticate` or `Proxy-Authenticate`, each judged on its own, because § 11.5 makes a protection space the canonical root *and* the realm, so an origin's `realm=\"x\"` and a proxy's `realm=\"x\"` name two spaces rather than one ambiguous one. A realm identifies a protection space and re-using the same realm string for different schemes can cause ambiguity and confuse credential selection. This is a **heuristic** check (HTTP does not strictly forbid this pattern), and it is intended to help operators spot potentially confusing authentication configurations. (RFC 9110 §11.5)"
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_11_5, RFC_9110_11_6_1]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm=\"users\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: NewScheme realm=\"admin\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm=\"shared\"\nWWW-Authenticate: NewScheme realm=\"shared\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the other field § 11 writes as `#challenge`)"),
                snippet: "HTTP/1.1 407 Proxy Authentication Required\nProxy-Authenticate: Basic realm=\"shared\"\nProxy-Authenticate: NewScheme realm=\"shared\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(one realm string, two protection spaces: § 11.5 defines a space by its root as well as its realm)"),
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm=\"shared\"\nProxy-Authenticate: Digest realm=\"shared\"",
            },
        ]
    }
}

impl Rule for AuthenticationChallengeValid {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let mut out = Vec::new();

        // Only check response headers; ignore non-UTF8 header values
        if let Some(resp) = &tx.response {
            // Each field § 11 writes as `#challenge`, and each with a realm map
            // of its own. § 11.5 makes a protection space the canonical root
            // *and* the realm, so an origin's `realm="x"` and a proxy's
            // `realm="x"` name two spaces and a credential for one is not a
            // credential for the other. Sharing one map across the two fields
            // would report that pair as the ambiguity this rule is about, which
            // is the one reading of "same realm" the document rules out.
            // cite(RFC 9110 § 11.5): "The realm value is a string, generally assigned by the origin server, that can have additional semantics specific to the authentication scheme."
            use std::collections::{HashMap, HashSet};

            for field in crate::helpers::auth::CHALLENGE_FIELDS {
                // Map of normalized_realm -> set of auth-schemes that advertise it
                let mut realms: HashMap<String, HashSet<String>> = HashMap::new();

                for s in crate::helpers::headers::field_lines(&resp.headers, field.key) {
                    // split assembled challenges
                    // The list's own defects are the framework reader's; the
                    // challenges beside them are still challenges.
                    let (challenges, _) = crate::helpers::auth::split_and_group_challenges(s);

                    for ch in challenges.iter() {
                        let ch = ch.trim();
                        if ch.is_empty() {
                            continue;
                        }
                        // extract scheme (first token before whitespace)
                        let mut parts = ch.splitn(2, char::is_whitespace);
                        let scheme = parts.next().unwrap_or("").trim().to_ascii_lowercase();

                        let mut realm_opt: Option<String> = None;
                        if let Some(rest) = parts.next() {
                            let rest = rest.trim();
                            if rest.contains('=') {
                                {
                                    let (params, _) = crate::helpers::auth::parse_auth_params(rest);
                                    if let Some(r) = params.get("realm") {
                                        // Normalize quoted and unquoted realm to the same
                                        // string before comparing: a sender must quote it, but
                                        // recipients accept both forms, so `realm="a"` and
                                        // `realm=a` denote the same protection space. (quoted-
                                        // string unescaping is helper-owned.)
                                        // cite(RFC 9110 § 11.5): "Recipients might have to support both token and quoted-string syntax for maximum interoperability with existing clients that have been accepting both notations for a long time."
                                        if r.starts_with('"') {
                                            if let Ok(unq) =
                                                crate::helpers::quoted_string::unescape_quoted_string(r)
                                            {
                                                realm_opt = Some(unq);
                                            }
                                        } else {
                                            realm_opt = Some(r.trim().to_string());
                                        }
                                    }
                                }
                            }
                        }

                        if let Some(realm) = realm_opt {
                            let entry = realms.entry(realm).or_default();
                            entry.insert(scheme);
                        }
                    }
                }

                // Flag any realm advertised by more than one distinct auth-scheme. The
                // heuristic reading: a realm names a protection space, and §11.5 casts each
                // space as having "its own authentication scheme", so one realm spanning
                // several schemes is an ambiguous configuration (not spec-forbidden — hence a
                // heuristic). The converse is explicitly permitted, which is why the check
                // counts schemes-per-realm and not realms-per-scheme.
                // cite(RFC 9110 § 11.5): "Note that a response can have multiple challenges with the same auth-scheme but with different realms."
                // One finding per realm, because a realm *is* the unit this rule
                // judges: § 11.5 partitions a server's resources into protection
                // spaces and each realm names one of them, so two ambiguous realms
                // are two ambiguous protection spaces and each is configured
                // somewhere of its own. Returning at the first reported one and
                // hid the rest.
                //
                // The schemes of a single realm stay in one message: that is the
                // one ambiguity, and it is the several schemes together that make
                // it.
                //
                // Sorted, because the realms come out of a HashMap and a finding
                // that changes order between runs is a finding nothing can be
                // asserted about.
                let mut ambiguous: Vec<(&String, Vec<String>)> = realms
                    .iter()
                    .filter(|(_, schemes)| schemes.len() > 1)
                    .map(|(realm, schemes)| {
                        let mut schemes_vec: Vec<String> = schemes.iter().cloned().collect();
                        schemes_vec.sort();
                        (realm, schemes_vec)
                    })
                    .collect();
                ambiguous.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));

                for (realm, schemes) in ambiguous {
                    out.push(ctx.report_with(
                        &CHALLENGE_REALM_AMBIGUOUS,
                        format!(
                            "{} realm \"{}\" is advertised by multiple auth-schemes: {}",
                            field.shown,
                            realm,
                            schemes.join(", ")
                        ),
                    ));
                }
            }
        }

        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AuthenticationChallengeValid;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_resp(v: &str) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_response(401, &[("www-authenticate", v)])
    }

    /// **The realm map is per field, and both fields have one.**
    ///
    /// `Proxy-Authenticate` carried the same production and nothing read it, so
    /// a proxy advertising one realm under two schemes drew nothing. The second
    /// row is the half a shared map would get wrong: § 11.5 defines a
    /// protection space by its canonical root *as well as* its realm, so an
    /// origin's `realm="shared"` and a proxy's are two spaces and no credential
    /// is ambiguous between them — a single map would have reported the pair as
    /// the very ambiguity this entry is about.
    #[test]
    fn each_challenge_field_has_its_own_realms() {
        let rule = AuthenticationChallengeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let judge = |status: u16, pairs: &[(&str, &str)]| {
            let tx = crate::test_helpers::make_test_transaction_with_response(status, pairs);
            crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
        };

        let found = judge(
            407,
            &[
                ("proxy-authenticate", "Basic realm=\"shared\""),
                ("proxy-authenticate", "NewScheme realm=\"shared\""),
            ],
        )
        .expect("a proxy advertising one realm under two schemes is the same ambiguity");
        assert_eq!(found.violation, "challenge_realm_ambiguous");
        assert!(
            found.message.contains("Proxy-Authenticate"),
            "the finding says {:?} and does not name the field it read",
            found.message
        );

        assert!(
            judge(
                401,
                &[
                    ("www-authenticate", "Basic realm=\"shared\""),
                    ("proxy-authenticate", "Digest realm=\"shared\""),
                ],
            )
            .is_none(),
            "one realm string in two fields is two protection spaces, not one ambiguous one",
        );
    }

    #[test]
    fn single_challenge_no_violation() {
        let rule = AuthenticationChallengeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let tx = make_resp("Basic realm=\"example\"");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_schemes_same_realm_is_violation() {
        let rule = AuthenticationChallengeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let tx = make_resp("Basic realm=\"a\", NewAuth realm=\"a\"");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let vv = v.unwrap();
        assert_eq!(vv.violation, "challenge_realm_ambiguous");
        assert!(vv.message.contains("realm \"a\""));
    }

    /// A realm names one protection space, so two ambiguous realms are two
    /// ambiguous spaces and each is configured somewhere of its own. The first
    /// used to be the whole answer. Ordered by realm, because the realms are
    /// gathered in a HashMap.
    #[test]
    fn each_ambiguous_realm_is_its_own_finding() {
        let rule = AuthenticationChallengeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let tx = make_resp(
            "Basic realm=\"admin\", NewAuth realm=\"admin\", \
             Basic realm=\"users\", NewAuth realm=\"users\"",
        );
        let all = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(all.len(), 2, "{all:?}");
        assert!(
            all[0].message.contains("realm \"admin\""),
            "{}",
            all[0].message
        );
        assert!(
            all[1].message.contains("realm \"users\""),
            "{}",
            all[1].message
        );
        // The schemes of one realm stay in one message: that is the one ambiguity.
        assert!(
            all[0].message.contains("basic, newauth"),
            "{}",
            all[0].message
        );
    }

    #[test]
    fn different_realms_no_violation() {
        let rule = AuthenticationChallengeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let tx = make_resp("Basic realm=\"a\", NewAuth realm=\"b\"");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_header_fields_checked() {
        let rule = AuthenticationChallengeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "www-authenticate",
            hyper::header::HeaderValue::from_static("Basic realm=\"a\""),
        );
        hm.append(
            "www-authenticate",
            hyper::header::HeaderValue::from_static("NewAuth realm=\"a\""),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn quoted_and_unquoted_realm_match_is_violation() {
        let rule = AuthenticationChallengeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        // Basic realm="a" and NewAuth realm=a -> should be treated equal
        let tx = make_resp("Basic realm=\"a\", NewAuth realm=a");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        let rule = AuthenticationChallengeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "www-authenticate",
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_with_escaped_quote_matches() {
        let rule = AuthenticationChallengeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        // realm with escaped quote inside quoted-string
        let tx = make_resp("Basic realm=\"a\\\"b\", NewAuth realm=\"a\\\"b\"");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn missing_realm_among_challenges_is_not_violation() {
        let rule = AuthenticationChallengeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        // NewAuth has no realm, Basic has realm a
        let tx = make_resp("Basic realm=\"a\", NewAuth");
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "authentication_challenge_valid",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope() {
        let rule = AuthenticationChallengeValid;
        assert_eq!(rule.id(), "authentication_challenge_valid");
        assert!(rule.needs_response());
    }
}
