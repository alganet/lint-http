// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageConnectionHeaderTokensValid;

impl Rule for MessageConnectionHeaderTokensValid {
    fn id(&self) -> &'static str {
        "message_connection_header_tokens_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let check = |headers: &hyper::HeaderMap| -> Option<Violation> {
            // cite(RFC 9110 § 7.6.1): "The "Connection" header field allows the sender to list desired control options for the current connection."
            for hv in headers.get_all(hyper::header::CONNECTION).iter() {
                let s = match hv.to_str() {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                for part in s.split(',') {
                    let token = part.trim();
                    if token.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Empty token in Connection header".into(),
                        });
                    }

                    // Validate token matches header field-name token grammar by attempting to
                    // parse as a HeaderName. Header names are case-insensitive; use the bytes
                    // as-is.
                    if hyper::header::HeaderName::from_bytes(token.as_bytes()).is_err() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid token in Connection header: '{}'", token),
                        });
                    }
                }
            }
            None
        };

        // Request
        if let Some(v) = check(&tx.request.headers) {
            return Some(v);
        }

        // Response
        if let Some(resp) = &tx.response {
            if let Some(v) = check(&resp.headers) {
                return Some(v);
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Ensures tokens in the `Connection` header are syntactically valid header field-name tokens.\n\nThe `Connection` header nominates header field names that are hop-by-hop for the connection. Each token in a `Connection` field must be a valid token that can appear as a header field name (i.e., match the tchar grammar). Rejecting malformed tokens helps catch header-injection or malformed requests.\n\nFor each `Connection` header field and each comma-separated token:\n- The token must be non-empty.\n- The token must match header field-name syntax (as parsed by `hyper::header::HeaderName`).\n\nThe rule treats token syntax only; it does not currently require that the named header field actually be present in the message (some tokens are connection options, e.g., `close`)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("7.6.1"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1",
            note: "Connection header field",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Connection: upgrade, keep-alive",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Connection: a/b\n# \"/\" not allowed in header name\n\nConnection: \"\"\n# empty token",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageConnectionHeaderTokensValid;

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case("keep-alive", false)]
    #[case("transfer-encoding", false)]
    #[case("upgrade", false)]
    #[case("a/b", true)]
    #[case("", true)]
    fn request_connection_token_cases(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageConnectionHeaderTokensValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        // If the token is empty we insert an empty header value to mimic malformed input
        if value.is_empty() {
            hm.insert(hyper::header::CONNECTION, HeaderValue::from_static(""));
        } else {
            hm.insert(hyper::header::CONNECTION, HeaderValue::from_str(value)?);
        }
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "case '{}' expected violation", value);
        } else {
            assert!(v.is_none(), "case '{}' expected no violation", value);
        }

        Ok(())
    }

    #[rstest]
    #[case("keep-alive", false)]
    #[case("transfer-encoding", false)]
    #[case("upgrade", false)]
    #[case("a/b", true)]
    #[case("", true)]
    fn response_connection_token_cases(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageConnectionHeaderTokensValid;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        if value.is_empty() {
            hm.insert(hyper::header::CONNECTION, HeaderValue::from_static(""));
        } else {
            hm.insert(hyper::header::CONNECTION, HeaderValue::from_str(value)?);
        }
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "case '{}' expected violation", value);
        } else {
            assert!(v.is_none(), "case '{}' expected no violation", value);
        }

        Ok(())
    }

    #[test]
    fn multiple_tokens_and_spacing() -> anyhow::Result<()> {
        let rule = MessageConnectionHeaderTokensValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            hyper::header::CONNECTION,
            HeaderValue::from_static("upgrade, keep-alive"),
        );
        tx.request.headers = hm;

        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .is_none());
        Ok(())
    }

    #[test]
    fn multiple_header_fields_validation() -> anyhow::Result<()> {
        let rule = MessageConnectionHeaderTokensValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            hyper::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        hm.append(hyper::header::CONNECTION, HeaderValue::from_static("a/b"));
        tx.request.headers = hm;

        // Should report a violation due to invalid 'a/b' token
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .is_some());
        Ok(())
    }

    #[test]
    fn missing_header_returns_none() -> anyhow::Result<()> {
        let rule = MessageConnectionHeaderTokensValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = hyper::HeaderMap::new();

        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .is_none());
        Ok(())
    }

    #[test]
    fn non_utf8_connection_header_returns_none() -> anyhow::Result<()> {
        let rule = MessageConnectionHeaderTokensValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        // Insert a non-UTF8 header value to exercise the to_str() Err branch
        hm.insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_bytes(&[0xffu8])?,
        );
        tx.request.headers = hm;

        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .is_none());
        Ok(())
    }

    #[test]
    fn scope_is_both() -> anyhow::Result<()> {
        let rule = MessageConnectionHeaderTokensValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
        Ok(())
    }
}
