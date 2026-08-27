// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Sec-Fetch-Site` header must be one of the canonical values listed in
/// the Fetch Metadata spec: `cross-site`, `same-origin`, `same-site`, or `none`.
/// The match is exact: the values are lowercase tokens and the
/// structured-field token carries no case folding; token syntax is validated.
pub struct SecFetchSiteValueValid;

impl Rule for SecFetchSiteValueValid {
    fn id(&self) -> &'static str {
        "sec_fetch_site_value_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // Sec-Fetch-* are request-sent headers; check only requests
            // cite(Fetch Metadata § 2.3): "HTTP request header exposes the relationship between a request initiator’s origin and its target’s origin"
            let headers = &tx.request.headers;
            let count = headers.get_all("sec-fetch-site").iter().count();
            if count == 0 {
                return None;
            }

            // A single structured-field item, never a list, so a sender may not repeat
            // the field.
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            if count > 1 {
                return Some(self.violation(
                    ctx.severity,
                    "Multiple Sec-Fetch-Site header fields present".into(),
                ));
            }

            // cite(RFC 9110 § 5.5): "newly defined fields SHOULD limit their values to visible US-ASCII octets (VCHAR), SP, and HTAB"
            let val = match crate::helpers::headers::get_header_str(headers, "sec-fetch-site") {
                Some(v) => v.trim(),
                None => {
                    return Some(self.violation(
                        ctx.severity,
                        "Sec-Fetch-Site header contains non-ASCII or control characters".into(),
                    ))
                }
            };

            // An empty value cannot be a token (§2.3 words it without the MUST its
            // sibling sections carry, but the constraint is the same).
            // cite(Fetch Metadata § 2.3): "It is a Structured Field whose value is a token."
            if val.is_empty() {
                return Some(self.violation(ctx.severity, "Sec-Fetch-Site header is empty".into()));
            }

            // Token must not contain invalid token chars. This checks the HTTP `token`
            // grammar, slightly looser than sf-token; the closed value match below is
            // what actually gates acceptance, so the difference only picks which
            // message a bad value gets.
            // cite(Fetch Metadata § 2.3): "It is a Structured Field whose value is a token."
            if let Some(c) = crate::helpers::token::find_invalid_token_char(val) {
                return Some(self.violation(
                    ctx.severity,
                    format!(
                        "Sec-Fetch-Site header contains invalid token character: '{}'",
                        c
                    ),
                ));
            }

            // The spec tells servers to ignore unknown values for forward compatibility;
            // this rule lints the sender, where an unknown value means a non-conforming
            // (or non-browser) origin of the header, so it flags instead.
            // cite(Fetch Metadata § 2.1): "In order to support forward-compatibility with as-yet-unknown request types, servers SHOULD ignore this header if it contains an invalid value."
            // cite(Fetch Metadata § 2.3): "Valid Sec-Fetch-Site values include "cross-site", "same-origin", "same-site", and "none"."
            match val {
                "cross-site" | "same-origin" | "same-site" | "none" => None,
                _ => Some(self.violation(
                    ctx.severity,
                    format!("Unrecognized Sec-Fetch-Site value: '{}'", val),
                )),
            }
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Requests that include the `Sec-Fetch-Site` request header must use one of the canonical values defined by the Fetch Metadata specification: `cross-site`, `same-origin`, `same-site`, or `none`. This rule validates the header token syntax and that the value is exactly one of the accepted identifiers — the values are lowercase tokens and structured-field tokens carry no case folding, so `Same-Origin` is not a valid value. Multiple header fields (repeated `Sec-Fetch-Site`) are treated as a violation (possible header injection) and will be flagged."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "Fetch Metadata",
            section: Some("2.3"),
            url: "https://www.w3.org/TR/fetch-metadata/#sec-fetch-site-header",
            note: "Fetch Metadata (W3C) — `Sec-Fetch-Site`: an sf-token whose valid values are the four initiator/target relationships",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Sec-Fetch-Site: same-origin",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Sec-Fetch-Site: cross-site",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Sec-Fetch-Site: invalid",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Sec-Fetch-Site:",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SecFetchSiteValueValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("same-origin"), false)]
    #[case(Some("same-site"), false)]
    #[case(Some("cross-site"), false)]
    #[case(Some("none"), false)]
    #[case(Some("Same-Origin"), true)] // the values are lowercase; the match is exact
    #[case(Some(""), true)]
    #[case(Some("invalid"), true)]
    #[case(None, false)]
    fn sec_fetch_site_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = SecFetchSiteValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_site_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-site", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
    }

    #[test]
    fn non_utf8_is_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = SecFetchSiteValueValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("sec-fetch-site", bad);
        tx.request.headers = hm;

        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_site_value_valid",
        ]);
        // get_header_str will return None for non-utf8 and this rule treats non-UTF8 as violation
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn invalid_token_char_reports_violation() {
        let rule = SecFetchSiteValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_site_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-site", "b@d")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid token character"));
    }

    #[test]
    fn whitespace_around_value_is_accepted() {
        let rule = SecFetchSiteValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_site_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-site", " same-origin ")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_none(),
            "whitespace around token should be trimmed and accepted"
        );
    }

    #[test]
    fn multiple_header_fields_first_valid_second_invalid() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = SecFetchSiteValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_site_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-site", HeaderValue::from_static("same-origin"));
        hm.append("sec-fetch-site", HeaderValue::from_static("invalid"));
        tx.request.headers = hm;

        // Multiple header fields are always a violation (potential header injection)
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some(), "expected violation for multiple header fields");
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Multiple Sec-Fetch-Site"),
            "expected message to mention multiple headers, got: {}",
            msg
        );
    }

    #[test]
    fn multiple_header_fields_both_invalid_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = SecFetchSiteValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_site_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-site", HeaderValue::from_static("bad1"));
        hm.append("sec-fetch-site", HeaderValue::from_static("bad2"));
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some(),
            "expected violation when all header field values are invalid"
        );
    }

    #[test]
    fn multiple_header_fields_both_valid_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = SecFetchSiteValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_site_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-site", HeaderValue::from_static("same-origin"));
        hm.append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some(),
            "expected violation when multiple valid header field values are present"
        );
    }

    #[test]
    fn message_and_id() {
        let rule = SecFetchSiteValueValid;
        assert_eq!(rule.id(), "sec_fetch_site_value_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "sec_fetch_site_value_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
