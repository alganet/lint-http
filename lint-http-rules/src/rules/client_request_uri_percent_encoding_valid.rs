// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientRequestUriPercentEncodingValid;

impl Rule for ClientRequestUriPercentEncodingValid {
    fn id(&self) -> &'static str {
        "client_request_uri_percent_encoding_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let s = tx.request.uri.as_str();
        if let Some(msg) = crate::helpers::uri::check_percent_encoding(s) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!("{} in request-target", msg),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Client Request URI Percent Encoding Valid")
    }

    fn description(&self) -> &'static str {
        "This rule checks that percent-encodings (pct-encodings) in the request-target are well-formed: each `%` must be followed by exactly two hexadecimal digits. Malformed percent-encodings can lead to ambiguous URIs or incorrect parsing by intermediaries."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 3986",
            section: Some("2.1"),
            url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1",
            note: "Percent-Encoding",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /path%20with%20spaces HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /path%2 HTTP/1.1\nHost: example.com\n# incomplete percent-encoding\n\nGET /path%GG HTTP/1.1\nHost: example.com\n# invalid hex digits",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientRequestUriPercentEncodingValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("/path/to/resource", false)]
    #[case("/path%20with%20spaces", false)]
    #[case("/path%2Fwith%2Fslashes", false)]
    #[case("/%41BC", false)]
    #[case("/mix%2fCase%2F", false)]
    #[case("/incomplete%2", true)]
    #[case("/endswith%", true)]
    #[case("/bad%2Gchar", true)]
    #[case("/bad%zz", true)]
    fn check_percent_encoding(#[case] uri: &str, #[case] expect_violation: bool) {
        let rule = ClientRequestUriPercentEncodingValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = uri.to_string();

        let config = crate::test_helpers::make_test_config_with_severity(rule.id(), "error");

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );

        if expect_violation {
            assert!(violation.is_some());
            let v = violation.unwrap();
            assert_eq!(v.rule, "client_request_uri_percent_encoding_valid");
            assert!(
                v.message.contains('%')
                    || v.message.contains("Percent-encoding")
                    || v.message.contains("Invalid")
            );
        } else {
            assert!(violation.is_none());
        }
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientRequestUriPercentEncodingValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
