// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct AuthenticationChallengeValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_11_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("11.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.5",
    note: "Establishing a Protection Space (Realm)",
};
const RFC_9110_11_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("11.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1",
    note: "WWW-Authenticate",
};

impl Rule for AuthenticationChallengeValid {
    fn id(&self) -> &'static str {
        "authentication_challenge_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
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
            use std::collections::{HashMap, HashSet};

            // Map of normalized_realm -> set of auth-schemes that advertise it
            let mut realms: HashMap<String, HashSet<String>> = HashMap::new();

            for s in crate::helpers::headers::field_lines(&resp.headers, "www-authenticate") {
                // split assembled challenges
                let challenges = match crate::helpers::auth::split_and_group_challenges(s) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

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
                            if let Ok(params) = crate::helpers::auth::parse_auth_params(rest) {
                                if let Some(r) = params.get("realm") {
                                    // Normalize quoted and unquoted realm to the same
                                    // string before comparing: a sender must quote it, but
                                    // recipients accept both forms, so `realm="a"` and
                                    // `realm=a` denote the same protection space. (quoted-
                                    // string unescaping is helper-owned.)
                                    // cite(RFC 9110 § 11.5): "Recipients might have to support both token and quoted-string syntax for maximum interoperability with existing clients that have been accepting both notations for a long time."
                                    if r.starts_with('"') {
                                        if let Ok(unq) =
                                            crate::helpers::headers::unescape_quoted_string(r)
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
            // cite(RFC 9110 § 11.5): "These realms allow the protected resources on a server to be partitioned into a set of protection spaces, each with its own authentication scheme and/or authorization database."
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
                out.push(self.violation(
                    ctx.severity,
                    format!(
                        "WWW-Authenticate realm \"{}\" is advertised by multiple auth-schemes: {}",
                        realm,
                        schemes.join(", ")
                    ),
                ));
            }
        }

        out
    }

    fn description(&self) -> &'static str {
        "Warn when a single response advertises the same `realm` value across multiple `WWW-Authenticate` authentication schemes. A realm identifies a protection space and re-using the same realm string for different schemes can cause ambiguity and confuse credential selection. This is a **heuristic** check (HTTP does not strictly forbid this pattern), and it is intended to help operators spot potentially confusing authentication configurations. (RFC 9110 §11.5)"
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_11_5, RFC_9110_11_6_1]
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
        ]
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
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
