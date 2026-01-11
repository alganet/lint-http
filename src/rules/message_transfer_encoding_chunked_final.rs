// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageTransferEncodingChunkedFinal;

impl Rule for MessageTransferEncodingChunkedFinal {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_transfer_encoding_chunked_final"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
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
}

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

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            hyper::header::TRANSFER_ENCODING,
            HeaderValue::from_str(value)?,
        );
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
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

        let mut tx = crate::test_helpers::make_test_transaction();
        // Ensure there is no Transfer-Encoding header
        tx.request.headers = hyper::HeaderMap::new();

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
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

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            hyper::header::TRANSFER_ENCODING,
            HeaderValue::from_str(value)?,
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
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
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            hyper::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        hm.append(
            hyper::header::TRANSFER_ENCODING,
            HeaderValue::from_static("gzip"),
        );
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
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

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none()); // Rule skips invalid UTF-8 headers
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageTransferEncodingChunkedFinal;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
