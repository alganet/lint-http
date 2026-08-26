// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Sec-Fetch-User` header must be the structured-boolean true (serialized as `?1`) when present.
/// The header is request-scoped and only expected on navigation requests. Multiple header
/// fields or non-ASCII values are flagged as violations.
pub struct SecFetchUserValueValid;

impl Rule for SecFetchUserValueValid {
    fn id(&self) -> &'static str {
        "sec_fetch_user_value_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        // A request header; absence is the normal case (it rides only user-activated
        // navigations).
        // cite(Fetch Metadata § 2.4): "HTTP request header exposes whether or not a navigation request was triggered by user activation."
        let headers = &tx.request.headers;
        let count = headers.get_all("sec-fetch-user").iter().count();
        if count == 0 {
            return None;
        }

        // A single structured-field item, never a list, so a sender may not repeat
        // the field.
        // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
        if count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: ctx.severity,
                message: "Multiple Sec-Fetch-User header fields present".into(),
            });
        }

        // cite(RFC 9110 § 5.5): "newly defined fields SHOULD limit their values to visible US-ASCII octets (VCHAR), SP, and HTAB"
        let val = match crate::helpers::headers::get_header_str(headers, "sec-fetch-user") {
            Some(v) => v.trim(),
            None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: ctx.severity,
                    message: "Sec-Fetch-User header contains non-ASCII or control characters"
                        .into(),
                })
            }
        };

        // An empty value cannot be an sf-boolean.
        // cite(Fetch Metadata § 2.4): "It is a Structured Field whose value is a boolean."
        if val.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: ctx.severity,
                message: "Sec-Fetch-User header is empty".into(),
            });
        }

        // The canonical serialization for a structured-boolean true is `?1`. `?0` is a
        // well-formed sf-boolean but never a well-formed *Sec-Fetch-User*: the header is
        // only ever sent when it is true, so its presence carrying anything else is wrong.
        // cite(Fetch Metadata): "Sec-Fetch-User = sf-boolean Note: The header is delivered only for navigation requests, and only when its value is true."
        if val != "?1" {
            return Some(Violation {
                rule: self.id().into(),
                severity: ctx.severity,
                message: format!(
                    "Unrecognized Sec-Fetch-User value: '{}'; expected '?1'",
                    val
                ),
            });
        }

        None
    }

    fn description(&self) -> &'static str {
        "Requests that include the `Sec-Fetch-User` request header MUST only include the structured-boolean `true` value (serialized as `?1`) when present. This header is sent by user agents for navigation requests that were triggered by a user activation. Multiple header fields or non-ASCII values will be flagged as violations."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "Fetch Metadata",
            section: Some("2.4"),
            url: "https://www.w3.org/TR/fetch-metadata/#sec-fetch-user-header",
            note: "Fetch Metadata (W3C) — `Sec-Fetch-User` header (boolean, serialized as `?1`)",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Sec-Fetch-User: ?1",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Sec-Fetch-User:  ?1  # whitespace is allowed and trimmed",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Sec-Fetch-User: true",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Sec-Fetch-User:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Sec-Fetch-User: 1",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SecFetchUserValueValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("?1"), false)]
    #[case(Some(" ?1 "), false)]
    #[case(Some("true"), true)]
    #[case(Some("1"), true)]
    #[case(Some(""), true)]
    #[case(None, false)]
    fn sec_fetch_user_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = SecFetchUserValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_user_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-user", v)]);
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
    fn false_serialization_reports_violation() {
        let rule = SecFetchUserValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_user_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-user", "?0")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Unrecognized Sec-Fetch-User"));
    }

    #[test]
    fn structured_boolean_with_suffix_reports_violation() {
        let rule = SecFetchUserValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_user_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-user", "?1;param")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Unrecognized Sec-Fetch-User"));
    }

    #[test]
    fn comma_separated_single_field_reports_violation() {
        let rule = SecFetchUserValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_user_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-user", "?1,?1")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Unrecognized Sec-Fetch-User"));
    }

    #[test]
    fn whitespace_only_header_reports_violation() {
        let rule = SecFetchUserValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_user_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-user", "   ")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("is empty"));
    }

    #[test]
    fn multiple_header_fields_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = SecFetchUserValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_user_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-user", HeaderValue::from_static("?1"));
        hm.append("sec-fetch-user", HeaderValue::from_static("?1"));
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple Sec-Fetch-User"));
    }

    #[test]
    fn non_utf8_is_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = SecFetchUserValueValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("sec-fetch-user", bad);
        tx.request.headers = hm;

        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_user_value_valid",
        ]);
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
    fn message_and_id() {
        let rule = SecFetchUserValueValid;
        assert_eq!(rule.id(), "sec_fetch_user_value_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "sec_fetch_user_value_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
