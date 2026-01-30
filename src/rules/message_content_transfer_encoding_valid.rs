// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentTransferEncodingValid;

impl Rule for MessageContentTransferEncodingValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_content_transfer_encoding_valid"
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
        // Allowed encodings per RFC 2045 §6
        let allowed = ["7bit", "8bit", "binary", "quoted-printable", "base64"];

        let check_header = |hdr_name: &str, val: &str| -> Option<Violation> {
            // ignore non-UTF8 values (headers::get_header_str already does this check)
            let s = val.trim();
            if s.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("{} header is empty", hdr_name),
                });
            }

            // RFC 2045 defines a single token value here; if commas are present it's likely malformed
            let parts: Vec<&str> = crate::helpers::headers::parse_list_header(s).collect();
            if parts.len() > 1 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "{} header must contain a single token (not a comma-separated list)",
                        hdr_name
                    ),
                });
            }

            let tok = parts[0];
            if let Some(c) = crate::helpers::token::find_invalid_token_char(tok) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("{} header contains invalid character: '{}'", hdr_name, c),
                });
            }

            if !allowed.contains(&tok.to_ascii_lowercase().as_str()) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Unrecognized Content-Transfer-Encoding '{}'", tok),
                });
            }

            None
        };

        // Check response headers
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("Content-Transfer-Encoding").iter() {
                if let Ok(val) = hv.to_str() {
                    if let Some(v) = check_header("Content-Transfer-Encoding", val) {
                        return Some(v);
                    }
                }
            }
        }

        // Check request headers
        for hv in tx
            .request
            .headers
            .get_all("Content-Transfer-Encoding")
            .iter()
        {
            if let Ok(val) = hv.to_str() {
                if let Some(v) = check_header("Content-Transfer-Encoding", val) {
                    return Some(v);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(None, false)]
    #[case(Some("7bit"), false)]
    #[case(Some("BASE64"), false)]
    #[case(Some("quoted-printable"), false)]
    #[case(Some("x-custom"), true)]
    #[case(Some("base64, gzip"), true)]
    #[case(Some("bad@token"), true)]
    fn content_transfer_encoding_cases(
        #[case] hdr: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentTransferEncodingValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = hdr {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-transfer-encoding", v)]);
        }

        let violation = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn non_utf8_header_values_are_ignored() -> anyhow::Result<()> {
        let rule = MessageContentTransferEncodingValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "content-transfer-encoding",
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn request_header_valid_and_request_scoped_is_checked() -> anyhow::Result<()> {
        let rule = MessageContentTransferEncodingValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        // valid request header should not produce a violation
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-transfer-encoding", "8bit")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());

        // invalid request header should produce a violation
        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-transfer-encoding",
            "xcodec",
        )]);
        let v2 = rule.check_transaction(&tx2, None, &cfg);
        assert!(v2.is_some());
        Ok(())
    }

    #[test]
    fn empty_header_value_is_violation_and_multiple_headers_with_one_invalid_is_reported(
    ) -> anyhow::Result<()> {
        let rule = MessageContentTransferEncodingValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        // empty header value
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-transfer-encoding", " ")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());

        // multiple header fields where one is invalid -> should report violation
        let tx2 = crate::test_helpers::make_test_transaction_with_headers(&[
            ("content-transfer-encoding", "base64"),
            ("content-transfer-encoding", "x-bad"),
        ]);
        let v2 = rule.check_transaction(&tx2, None, &cfg);
        assert!(v2.is_some());
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageContentTransferEncodingValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
