// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentDispositionTokenValid;

impl Rule for MessageContentDispositionTokenValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_content_disposition_token_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Helper to validate a single Content-Disposition header value
        let check_value = |hdr_name: &str, val: &str| -> Option<Violation> {
            // Trim whitespace and split off parameters
            let s = val.trim();
            if s.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("{} header value must not be empty", hdr_name),
                });
            }

            let dispo = s.split(';').next().unwrap().trim();
            if dispo.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("{} header disposition-type must not be empty", hdr_name),
                });
            }

            if let Some(c) = crate::helpers::token::find_invalid_token_char(dispo) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "{} disposition-type contains invalid token character: '{}'",
                        hdr_name, c
                    ),
                });
            }

            None
        };

        // Check in responses
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("content-disposition").iter() {
                if let Ok(s) = hv.to_str() {
                    if let Some(v) = check_value("Content-Disposition", s) {
                        return Some(v);
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Content-Disposition header value is not valid UTF-8".into(),
                    });
                }
            }
        }

        // Check in requests (rare but possible in multipart/form-data parts or other contexts)
        for hv in tx.request.headers.get_all("content-disposition").iter() {
            if let Ok(s) = hv.to_str() {
                if let Some(v) = check_value("Content-Disposition", s) {
                    return Some(v);
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Disposition header value is not valid UTF-8".into(),
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

    #[rstest]
    #[case(Some("attachment; filename=\"a.txt\""), false)]
    #[case(Some("inline"), false)]
    #[case(Some("form-data; name=\"field\"; filename=\"a.png\""), false)]
    #[case(Some("x-custom"), false)]
    #[case(Some(""), true)]
    #[case(Some("; filename=\"a\""), true)]
    #[case(Some("bad@type; filename=\"a\""), true)]
    #[case(None, false)]
    fn response_cases(#[case] value: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = value {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-disposition", v)]);
        }

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
            assert!(v.is_some(), "expected violation for '{:?}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{:?}'", value);
        }
    }

    #[test]
    fn request_header_checked() {
        let rule = MessageContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "form-data; name=\"x\"",
        )]);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_header_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-disposition", HeaderValue::from_bytes(&[0xff])?);
        tx.response.as_mut().unwrap().headers = hm;

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
        Ok(())
    }

    #[test]
    fn request_non_utf8_header_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-disposition", HeaderValue::from_bytes(&[0xff])?);
        tx.request.headers = hm;

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
        Ok(())
    }

    #[test]
    fn multiple_header_fields_checked() {
        let rule = MessageContentDispositionTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut hm = HeaderMap::new();
        hm.append("content-disposition", HeaderValue::from_static("inline"));
        hm.append("content-disposition", HeaderValue::from_static("bad@type"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });

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
    }

    #[test]
    fn whitespace_only_is_violation() {
        let rule = MessageContentDispositionTokenValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-disposition", "   ")],
        );
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
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageContentDispositionTokenValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
