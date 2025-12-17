// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;

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
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        let check = |headers: &hyper::HeaderMap| -> Option<Violation> {
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
                            severity: crate::rules::get_rule_severity(_config, self.id()),
                            message: "Empty token in Connection header".into(),
                        });
                    }

                    // Validate token matches header field-name token grammar by attempting to
                    // parse as a HeaderName. Header names are case-insensitive; use the bytes
                    // as-is.
                    if hyper::header::HeaderName::from_bytes(token.as_bytes()).is_err() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: crate::rules::get_rule_severity(_config, self.id()),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_context;
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
        let (_client, state) = make_test_context();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        // If the token is empty we insert an empty header value to mimic malformed input
        if value.is_empty() {
            hm.insert(hyper::header::CONNECTION, HeaderValue::from_static(""));
        } else {
            hm.insert(hyper::header::CONNECTION, HeaderValue::from_str(value)?);
        }
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, &state, &crate::config::Config::default());
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
        let (_client, state) = make_test_context();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        if value.is_empty() {
            hm.insert(hyper::header::CONNECTION, HeaderValue::from_static(""));
        } else {
            hm.insert(hyper::header::CONNECTION, HeaderValue::from_str(value)?);
        }
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            headers: hm,
        });

        let v = rule.check_transaction(&tx, &state, &crate::config::Config::default());
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
        let (_client, state) = make_test_context();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            hyper::header::CONNECTION,
            HeaderValue::from_static("upgrade, keep-alive"),
        );
        tx.request.headers = hm;

        assert!(rule
            .check_transaction(&tx, &state, &crate::config::Config::default())
            .is_none());
        Ok(())
    }

    #[test]
    fn multiple_header_fields_validation() -> anyhow::Result<()> {
        let rule = MessageConnectionHeaderTokensValid;
        let (_client, state) = make_test_context();

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
            .check_transaction(&tx, &state, &crate::config::Config::default())
            .is_some());
        Ok(())
    }

    #[test]
    fn missing_header_returns_none() -> anyhow::Result<()> {
        let rule = MessageConnectionHeaderTokensValid;
        let (_client, state) = make_test_context();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = hyper::HeaderMap::new();

        assert!(rule
            .check_transaction(&tx, &state, &crate::config::Config::default())
            .is_none());
        Ok(())
    }
}
