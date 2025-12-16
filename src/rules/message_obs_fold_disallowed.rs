// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;

pub struct MessageObsFoldDisallowed;

impl Rule for MessageObsFoldDisallowed {
    fn id(&self) -> &'static str {
        "message_obs_fold_disallowed"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        let check = |headers: &hyper::HeaderMap| -> Option<Violation> {
            for (name, value) in headers.iter() {
                let bytes = value.as_bytes();
                // Obs-fold is CRLF followed by SP or HTAB ("\r\n " or "\r\n\t").
                // Some input may encode CRLF as literal escape sequences ("\\r\\n ") in logs
                // or serialized values; detect both real CRLF bytes and escaped "\\r\\n".
                let raw_fold = bytes.windows(3).any(|w| w == b"\r\n " || w == b"\r\n\t");
                let escaped_fold = bytes
                    .windows(5)
                    .any(|w| w == b"\\r\\n " || w == b"\\r\\n\t")
                    || bytes.windows(6).any(|w| w == b"\\r\\n\\t");
                if raw_fold || escaped_fold {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: crate::rules::get_rule_severity(_config, self.id()),
                        message: format!(
                            "Obs-fold (CRLF SP/HTAB) found in header '{}': value contains obsolete line folding",
                            name.as_str()
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
    use crate::test_helpers::{make_test_conn, make_test_context};
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case("normal", false)]
    #[case("contains crlf sp", true)]
    #[case("contains crlf tab", true)]
    fn request_obs_fold_cases(
        #[case] scenario: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageObsFoldDisallowed;
        let (_client, state) = make_test_context();
        let conn = make_test_conn();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();

        match scenario {
            "normal" => {
                hm.insert("x-test", HeaderValue::from_static("ok"));
            }
            "contains crlf sp" => {
                // Use escaped form since HeaderValue forbids raw CRLF bytes in values.
                hm.insert("x-fold", HeaderValue::from_static("foo\\r\\n bar"));
            }
            "contains crlf tab" => {
                hm.insert("x-fold", HeaderValue::from_static("a\\r\\n\\tb"));
            }
            _ => unreachable!(),
        }

        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, &conn, &state, &crate::config::Config::default());
        if expect_violation {
            assert!(v.is_some());
            let msg = v.unwrap().message;
            assert!(msg.contains("Obs-fold") || msg.contains("obsolete line folding"));
        } else {
            assert!(v.is_none());
        }

        Ok(())
    }

    #[rstest]
    #[case("normal", false)]
    #[case("contains crlf sp", true)]
    fn response_obs_fold_cases(
        #[case] scenario: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageObsFoldDisallowed;
        let (_client, state) = make_test_context();
        let conn = make_test_conn();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();

        match scenario {
            "normal" => {
                hm.insert("x-ok", HeaderValue::from_static("ok"));
            }
            "contains crlf sp" => {
                hm.insert("x-fold", HeaderValue::from_static("v1\\r\\n v2"));
            }
            _ => unreachable!(),
        }

        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            headers: hm,
        });

        let v = rule.check_transaction(&tx, &conn, &state, &crate::config::Config::default());
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }

        Ok(())
    }

    #[test]
    fn no_headers_returns_none() -> anyhow::Result<()> {
        let rule = MessageObsFoldDisallowed;
        let (_client, state) = make_test_context();
        let conn = make_test_conn();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = hyper::HeaderMap::new();

        assert!(rule
            .check_transaction(&tx, &conn, &state, &crate::config::Config::default())
            .is_none());
        Ok(())
    }
}
