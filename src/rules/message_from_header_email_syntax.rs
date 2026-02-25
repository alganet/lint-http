// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageFromHeaderEmailSyntax;

impl Rule for MessageFromHeaderEmailSyntax {
    type Config = crate::rules::RuleConfig;

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
        config: &Self::Config,
    ) -> Option<Violation> {
        let req = &tx.request;

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
}

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
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

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

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

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
