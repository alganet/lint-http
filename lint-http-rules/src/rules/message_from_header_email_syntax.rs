// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageFromHeaderEmailSyntax;

impl Rule for MessageFromHeaderEmailSyntax {
    fn id(&self) -> &'static str {
        "message_from_header_email_syntax"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // From is a request header
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let req = &tx.request;

        // cite(RFC 9110 § 10.1.2): "The "From" header field contains an Internet email address for a human user who controls the requesting user agent."
        for hv in req.headers.get_all("from").iter() {
            let s = match hv.to_str() {
                Ok(v) => v,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "From header value is not valid UTF-8".into(),
                    })
                }
            };

            if s.trim().is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "From header must not be empty".into(),
                });
            }

            if crate::helpers::headers::validate_mailbox_list(s).is_err() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("From header value is not a valid mailbox-list: '{}'", s),
                });
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "This rule validates the `From` request header's mailbox-list syntax. It accepts common mailbox forms such as a bare `addr-spec` (e.g., `alice@example.com`) or a `display-name <addr-spec>` entry. The validator is conservative: it rejects obvious errors such as missing `@`, empty local-part or domain, unbalanced angle brackets, control characters, or malformed quoted local-parts."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.1.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.2",
                note: "Header field definition and reference",
            },
            crate::rules::SpecRef {
                spec: "RFC 5322",
                section: Some("3.4"),
                url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4",
                note: "Mailbox and mailbox-list syntax (note: full RFC 5322 parsing is complex; this rule uses a conservative subset to catch common errors)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(single addr-spec)"),
                snippet: "GET / HTTP/1.1\nFrom: alice@example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(display name)"),
                snippet: "GET / HTTP/1.1\nFrom: Alice <alice@example.com>",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(multiple addresses)"),
                snippet: "GET / HTTP/1.1\nFrom: Alice <alice@example.com>, bob@example.org",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(missing @)"),
                snippet: "GET / HTTP/1.1\nFrom: not-an-email",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(empty domain)"),
                snippet: "GET / HTTP/1.1\nFrom: alice@",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(unbalanced angle-brackets)"),
                snippet: "GET / HTTP/1.1\nFrom: Alice <alice@example.com",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageFromHeaderEmailSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_tx_with_from(f: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("from", f)]);
        tx
    }

    #[rstest]
    #[case("alice@example.com", false)]
    #[case("Alice <alice@example.com>", false)]
    #[case("Alice <alice@example.com>, bob@example.org", false)]
    #[case("\"Quoted Local\" <\"a\\\"b\"@exa.com>", false)]
    #[case("", true)]
    #[case("not-an-email", true)]
    #[case("<no-at-sign>", true)]
    #[case("alice@", true)]
    #[case("@example.com", true)]
    #[case("Alice <alice@example.com", true)]
    fn check_from_header(#[case] from: &str, #[case] expect_violation: bool) {
        let rule = MessageFromHeaderEmailSyntax;
        let tx = make_tx_with_from(from);
        let config = crate::test_helpers::make_test_config_with_severity(
            "message_from_header_email_syntax",
            "warn",
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", from);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", from);
        }
    }

    #[test]
    fn non_utf8_header_value_is_violation() {
        let rule = MessageFromHeaderEmailSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        // create non-utf8 header value
        headers.insert(
            hyper::header::HeaderName::from_static("from"),
            hyper::header::HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.request.headers = headers;

        let config = crate::test_helpers::make_test_config_with_severity(
            "message_from_header_email_syntax",
            "warn",
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not valid UTF-8"));
    }

    #[test]
    fn scope_is_client() {
        let rule = MessageFromHeaderEmailSyntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
