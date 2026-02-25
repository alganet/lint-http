// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerAuthenticationChallengeValidity;

impl Rule for ServerAuthenticationChallengeValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_authentication_challenge_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Only check response headers; ignore non-UTF8 header values
        if let Some(resp) = &tx.response {
            use std::collections::{HashMap, HashSet};

            // Map of normalized_realm -> set of auth-schemes that advertise it
            let mut realms: HashMap<String, HashSet<String>> = HashMap::new();

            for hv in resp.headers.get_all("www-authenticate").iter() {
                if let Ok(s) = hv.to_str() {
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
                                        // normalize realm for consistent comparison
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
            }

            // Now find any realm that is advertised by more than one distinct auth-scheme
            for (realm, schemes) in realms.iter() {
                if schemes.len() > 1 {
                    let mut schemes_vec: Vec<String> = schemes.iter().cloned().collect();
                    schemes_vec.sort();
                    let msg = format!(
                        "WWW-Authenticate realm \"{}\" is advertised by multiple auth-schemes: {}",
                        realm,
                        schemes_vec.join(", ")
                    );
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: msg,
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_resp(v: &str) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_response(401, &[("www-authenticate", v)])
    }

    #[test]
    fn single_challenge_no_violation() {
        let rule = ServerAuthenticationChallengeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_resp("Basic realm=\"example\"");
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_schemes_same_realm_is_violation() {
        let rule = ServerAuthenticationChallengeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_resp("Basic realm=\"a\", NewAuth realm=\"a\"");
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let vv = v.unwrap();
        assert!(vv.message.contains("realm \"a\""));
    }

    #[test]
    fn different_realms_no_violation() {
        let rule = ServerAuthenticationChallengeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_resp("Basic realm=\"a\", NewAuth realm=\"b\"");
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_header_fields_checked() {
        let rule = ServerAuthenticationChallengeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
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
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn quoted_and_unquoted_realm_match_is_violation() {
        let rule = ServerAuthenticationChallengeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        // Basic realm="a" and NewAuth realm=a -> should be treated equal
        let tx = make_resp("Basic realm=\"a\", NewAuth realm=a");
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        let rule = ServerAuthenticationChallengeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "www-authenticate",
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_with_escaped_quote_matches() {
        let rule = ServerAuthenticationChallengeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        // realm with escaped quote inside quoted-string
        let tx = make_resp("Basic realm=\"a\\\"b\", NewAuth realm=\"a\\\"b\"");
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn missing_realm_among_challenges_is_not_violation() {
        let rule = ServerAuthenticationChallengeValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        // NewAuth has no realm, Basic has realm a
        let tx = make_resp("Basic realm=\"a\", NewAuth");
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "server_authentication_challenge_validity",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope() {
        let rule = ServerAuthenticationChallengeValidity;
        assert_eq!(rule.id(), "server_authentication_challenge_validity");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
