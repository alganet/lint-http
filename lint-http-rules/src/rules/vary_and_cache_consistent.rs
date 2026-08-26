// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Responses that include `Vary: *` cannot be selected by caches for
/// subsequent requests (a `Vary: *` always fails to match; see RFC 9111 §4.1).
/// If a response also advertises explicit cacheability directives such as
/// `Cache-Control: max-age`/`s-maxage` or `public`, those directives are
/// likely ineffective because caches cannot select stored responses when
/// `Vary: *` is present. This rule flags those cases as likely misconfiguration.
pub struct VaryAndCacheConsistent;

impl Rule for VaryAndCacheConsistent {
    fn id(&self) -> &'static str {
        "vary_and_cache_consistent"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

        // A `Vary: *` can never be matched by a cache, so any explicit
        // cacheability directive on the same response is ineffective.
        //
        // The walk this replaced read the field lines one at a time and returned
        // no finding at all when `to_str` refused one — so a single `obs-text`
        // octet anywhere in the value stood the rule down — and it did not join
        // them, so a `*` written on a second field line was not a `*` here while
        // it was one to `prefer_header_and_preference_applied`. Both are
        // `helpers::headers::vary_nomination`'s answer now, for all three rules
        // that ask.
        //
        // cite(RFC 9111 § 4.1): "A stored response with a Vary header field value containing a member "*" always fails to match."
        if !crate::helpers::headers::vary_nomination(&resp.headers).is_wildcard() {
            return None;
        }

        // If Vary: * is present, an explicit cacheability directive is likely ineffective (the
        // response can never be selected). No sentence says this pairing is illegal, so this is
        // a misconfiguration heuristic, recorded in the tracker.
        for hv in resp.headers.get_all("cache-control").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => continue,
            };

            for member in crate::helpers::headers::split_commas_respecting_quotes(s) {
                let m = member;
                if m.is_empty() {
                    continue;
                }
                // directive = token [ '=' ... ]
                let name = m
                    .split('=')
                    .next()
                    .expect("split always yields at least one item")
                    .trim()
                    .to_ascii_lowercase();
                match name.as_str() {
                    // Only directives that *advertise reuse* are flagged. `no-cache` is
                    // deliberately excluded: it promises no reuse benefit (it requires
                    // revalidation), so pairing it with Vary: * is not a misconfiguration signal.
                    "max-age" | "s-maxage" | "public" => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Response includes Vary: '*' and Cache-Control directive '{}'; Vary: '*' prevents caches from selecting stored responses, making cache directives like '{}' ineffective (see RFC 9111 §4.1)",
                                name, name
                            ),
                        });
                    }
                    _ => {}
                }
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Vary and Cache Consistency")
    }

    fn description(&self) -> &'static str {
        "When a response includes `Vary: *`, caches cannot select that stored response for subsequent requests (a `Vary: *` always fails to match). If the same response advertises explicit cacheability directives (such as `Cache-Control: max-age`/`s-maxage` or `public`), those directives are likely ineffective for reuse by caches. This rule flags cases where `Vary: *` and explicit cacheability directives are both present."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1",
                note:
                    "Calculating Cache Keys with the Vary Header Field (a `Vary: *` never matches)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-3",
                note: "Storing Responses in Caches (cacheability requirements)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nVary: Accept-Encoding\nCache-Control: max-age=3600\n\n<response body>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nVary: *\nCache-Control: max-age=3600\n\n<response body>",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &VaryAndCacheConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_tx(vary: Option<&str>, cc: Option<&str>) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = vary {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("vary", v)]);
            if let Some(c) = cc {
                tx.response
                    .as_mut()
                    .unwrap()
                    .headers
                    .append("cache-control", c.parse().unwrap());
            }
        } else if let Some(c) = cc {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("cache-control", c)]);
        }
        tx
    }

    #[rstest]
    #[case(Some("*"), Some("max-age=3600"), true)]
    #[case(Some("*"), Some("s-maxage=3600"), true)]
    #[case(Some("*"), Some("public"), true)]
    #[case(Some("*"), Some("public, max-age=60"), true)]
    #[case(Some("*"), Some("no-cache"), false)]
    #[case(Some("Accept-Encoding"), Some("max-age=60"), false)]
    #[case(None, Some("max-age=60"), false)]
    fn check_cases(
        #[case] vary: Option<&str>,
        #[case] cc: Option<&str>,
        #[case] expect_violation: bool,
    ) {
        let rule = VaryAndCacheConsistent;
        let tx = make_tx(vary, cc);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for vary={:?}, cc={:?}",
                vary,
                cc
            );
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for vary={:?}, cc={:?}: {:?}",
                vary,
                cc,
                v
            );
        }
    }

    /// The two ways the walk this rule used to hold could not see a `*`.
    #[test]
    fn the_star_is_found_across_the_fields_lines_and_past_an_obs_text_octet() {
        use hyper::header::{HeaderName, HeaderValue};
        let judge = |vary: &[&[u8]]| {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            let headers = &mut tx.response.as_mut().expect("a response").headers;
            for line in vary {
                headers.append(
                    HeaderName::from_static("vary"),
                    HeaderValue::from_bytes(line).expect("a test Vary value"),
                );
            }
            headers.append(
                "cache-control",
                "max-age=3600".parse().expect("a directive"),
            );
            crate::test_helpers::run_rule(
                &VaryAndCacheConsistent,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "vary_and_cache_consistent",
                ]),
            )
        };

        // §5.3 makes the lines one value and `#( "*" / field-name )` is what
        // licenses the join, so this `*` is a member. Read line by line it was
        // not one.
        assert!(judge(&[b"accept-encoding", b"*"]).is_some());
        // `to_str` refuses %xE9, and refusing it used to end the rule — so a
        // `*` beside an `obs-text` octet drew nothing at all.
        assert!(judge(&[b"caf\xe9, *"]).is_some());
        assert!(judge(&[b"caf\xe9", b"*"]).is_some());
        // And an `obs-text` octet on its own still nominates no `*`.
        assert!(judge(&[b"caf\xe9"]).is_none());
    }

    #[test]
    fn non_utf8_cache_control_ignored() {
        // non-utf8 cache-control should not panic the rule
        use hyper::header::HeaderValue;
        let rule = VaryAndCacheConsistent;
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("vary", "*")]);
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .insert("cache-control", bad);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = VaryAndCacheConsistent;
        assert_eq!(rule.id(), "vary_and_cache_consistent");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn vary_star_across_multiple_header_fields_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = VaryAndCacheConsistent;

        // Vary: Accept-Encoding and Vary: * across header fields, plus Cache-Control: max-age
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("vary", HeaderValue::from_static("Accept-Encoding"));
        hm.append("vary", HeaderValue::from_static("*"));
        hm.append("cache-control", HeaderValue::from_static("max-age=60"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn cache_control_case_insensitive_directive_detection() {
        let rule = VaryAndCacheConsistent;

        // Public (mixed case) should be detected
        let tx = make_tx(Some("*"), Some("Public"));
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());

        // MAX-AGE uppercase
        let tx2 = make_tx(Some("*"), Some("MAX-AGE=60"));
        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v2.is_some());
    }

    #[test]
    fn multiple_cache_control_headers_with_max_age_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = VaryAndCacheConsistent;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.insert("vary", HeaderValue::from_static("*"));
        hm.append("cache-control", HeaderValue::from_static("no-cache"));
        hm.append("cache-control", HeaderValue::from_static("max-age=60"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn extension_directive_only_is_not_a_violation() {
        // Vary: * with a non-cacheability extension should not be flagged
        let rule = VaryAndCacheConsistent;
        let tx = make_tx(Some("*"), Some("foo=bar"));
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = VaryAndCacheConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "vary_and_cache_consistent",
        ]);
        // validate should succeed without error
        rule.validate(&cfg)?;
        Ok(())
    }
}
