// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageTransferEncodingChunkedFinal;

impl Rule for MessageTransferEncodingChunkedFinal {
    fn id(&self) -> &'static str {
        "message_transfer_encoding_chunked_final"
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
            let mut codings: Vec<String> = Vec::new();
            for hv in headers.get_all(hyper::header::TRANSFER_ENCODING).iter() {
                let s = match hv.to_str() {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                for token in crate::helpers::headers::parse_list_header(s) {
                    codings.push(token.to_ascii_lowercase());
                }
            }

            if codings.is_empty() {
                return None;
            }

            // If 'chunked' appears anywhere other than the final coding it's a violation
            if let Some(pos) = codings.iter().position(|c| c == "chunked") {
                if pos != codings.len() - 1 {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                        "Transfer-Encoding 'chunked' must be the final coding: codings found '{}'",
                        codings.join(", ")
                    ),
                    });
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
        "Ensures that when `Transfer-Encoding` includes the `chunked` transfer coding, it appears as the final transfer coding.\n\nPer RFC 9112 §7.1, the `chunked` transfer-coding must always be the final transfer-coding applied to a message. Intermediate codecs cannot follow `chunked`, because chunked encoding is the format used to delimit the message body.\n\nIf a message includes `Transfer-Encoding: ...` values and any of them is `chunked`, then `chunked` must be the final coding in the sequence. The rule checks all `Transfer-Encoding` header fields and the order of comma-separated codings."
    }

    fn rfc_reference(&self) -> Option<&'static str> {
        Some("[RFC 9112 §7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1): Transfer-Encoding")
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                snippet: "Transfer-Encoding: gzip, chunked\n\nTransfer-Encoding: chunked",
            },
            Example {
                compliance: Compliance::NonCompliant,
                snippet: "Transfer-Encoding: chunked, gzip\n# chunked must be final\n\n# Multiple header fields where an earlier field contains chunked\n# and later fields contain other codings",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageTransferEncodingChunkedFinal;

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case("chunked", false)]
    #[case("gzip, chunked", false)]
    #[case("chunked, gzip", true)]
    #[case("compress, chunked", false)]
    #[case("compress, chunked, gzip", true)]
    #[case("gzip, chunked, gzip", true)]
    #[case("gzip, chunked, identity", true)]
    #[case("gzip, compress", false)]
    fn request_transfer_encoding_cases(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTransferEncodingChunkedFinal;

        let tx = crate::test_helpers::make_test_transaction_with_headers(&[(
            "transfer-encoding",
            value,
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "request '{}' expected violation", value);
        } else {
            assert!(v.is_none(), "request '{}' expected no violation", value);
        }

        Ok(())
    }

    #[test]
    fn request_no_transfer_encoding_header_returns_none() -> anyhow::Result<()> {
        let rule = MessageTransferEncodingChunkedFinal;

        let tx = crate::test_helpers::make_test_transaction();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[rstest]
    #[case("chunked", false)]
    #[case("gzip, chunked", false)]
    #[case("chunked, gzip", true)]
    #[case("gzip, compress", false)]
    fn response_transfer_encoding_cases(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTransferEncodingChunkedFinal;

        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("transfer-encoding", value)],
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "response '{}' expected violation", value);
        } else {
            assert!(v.is_none(), "response '{}' expected no violation", value);
        }

        Ok(())
    }

    #[test]
    fn multiple_header_fields_ordering_is_preserved() -> anyhow::Result<()> {
        let rule = MessageTransferEncodingChunkedFinal;

        // Two header fields: first 'chunked', second 'gzip' -> should violate
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("transfer-encoding", "chunked"),
            ("transfer-encoding", "gzip"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn check_non_utf8() -> anyhow::Result<()> {
        let rule = MessageTransferEncodingChunkedFinal;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        // 0xFF is not a valid UTF-8 character
        let bad_value = HeaderValue::from_bytes(&[0xFF])?;
        hm.insert(hyper::header::TRANSFER_ENCODING, bad_value);
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none()); // Rule skips invalid UTF-8 headers
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageTransferEncodingChunkedFinal;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
