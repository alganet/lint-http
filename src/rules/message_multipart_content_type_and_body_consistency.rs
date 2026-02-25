// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageMultipartContentTypeAndBodyConsistency;

impl Rule for MessageMultipartContentTypeAndBodyConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_multipart_content_type_and_body_consistency"
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
        // Check request body when Content-Type is multipart
        if let Some(hv) = tx.request.headers.get("content-type") {
            if let Ok(s) = hv.to_str() {
                if let Some(boundary) = crate::helpers::headers::extract_multipart_boundary(s) {
                    if let Some(b) = &tx.request_body {
                        if let Some(v) =
                            check_body_contains_boundary("request", &boundary, b.as_ref(), config)
                        {
                            return Some(v);
                        }
                    }
                }
            }
        }

        // Check response body when Content-Type is multipart
        if let Some(resp) = &tx.response {
            if let Some(hv) = resp.headers.get("content-type") {
                if let Ok(s) = hv.to_str() {
                    if let Some(boundary) = crate::helpers::headers::extract_multipart_boundary(s) {
                        if let Some(b) = &tx.response_body {
                            if let Some(v) = check_body_contains_boundary(
                                "response",
                                &boundary,
                                b.as_ref(),
                                config,
                            ) {
                                return Some(v);
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

fn check_body_contains_boundary(
    which: &str,
    boundary: &str,
    body: &[u8],
    config: &crate::rules::RuleConfig,
) -> Option<Violation> {
    let marker = ["--", boundary].concat();
    let final_marker = ["--", boundary, "--"].concat();
    let has_marker = haystack_contains(body, marker.as_bytes());
    if !has_marker {
        return Some(Violation {
            rule: MessageMultipartContentTypeAndBodyConsistency.id().into(),
            severity: config.severity,
            message: format!(
                "Invalid multipart Content-Type in {}: body does not contain boundary marker '--{}'",
                which, boundary
            ),
        });
    }
    let has_final = haystack_contains(body, final_marker.as_bytes());
    if !has_final {
        return Some(Violation {
            rule: MessageMultipartContentTypeAndBodyConsistency.id().into(),
            severity: config.severity,
            message: format!(
                "Invalid multipart Content-Type in {}: body missing terminating boundary '--{}--'",
                which, boundary
            ),
        });
    }
    None
}

fn haystack_contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn valid_multipart_with_final_boundary_ok() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        tx.response_body = Some(Bytes::from_static(
            b"--abc\r\nContent-Type: text/plain\r\n\r\nhi\r\n--abc--\r\n",
        ));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn missing_boundary_marker_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        tx.response_body = Some(Bytes::from_static(b"no boundaries here"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("--abc"));
    }

    #[test]
    fn missing_final_boundary_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        tx.response_body = Some(Bytes::from_static(b"--abc\r\nPart\r\n--abc\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("missing terminating boundary"));
    }

    #[test]
    fn non_multipart_content_type_is_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text/plain")],
        );
        tx.response_body = Some(Bytes::from_static(b"no boundaries"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn no_body_present_is_ignored() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn request_body_checked_too() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "multipart/form-data; boundary=xyz",
        )]);
        tx.request_body = Some(Bytes::from_static(b"--xyz\r\nfoo\r\n--xyz--\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_boundary_unescaped_ok() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=\"a b\"")],
        );
        tx.response_body = Some(Bytes::from_static(b"--a b\r\nx\r\n--a b--\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn malformed_content_type_is_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "not-a-media-type")],
        );
        tx.response_body = Some(Bytes::from_static(b"no boundaries"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_or_malformed_boundary_is_ignored() {
        // quoted empty -> helper should treat as missing
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=\"\"")],
        );
        tx.response_body = Some(Bytes::from_static(b"no boundaries"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());

        // malformed quoted-string -> ignored
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=\"unterminated")],
        );
        tx2.response_body = Some(Bytes::from_static(b"no boundaries"));
        let v2 = rule.check_transaction(
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v2.is_none());
    }

    #[test]
    fn request_missing_boundary_marker_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "multipart/form-data; boundary=xyz",
        )]);
        tx.request_body = Some(Bytes::from_static(b"no boundaries here"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("--xyz"));
        assert!(msg.contains("request"));
    }

    #[test]
    fn request_missing_final_boundary_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "multipart/form-data; boundary=xyz",
        )]);
        tx.request_body = Some(Bytes::from_static(b"--xyz\r\nPart\r\n--xyz\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("terminating boundary"));
    }

    #[test]
    fn response_final_marker_alone_is_accepted() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        // body contains only the final boundary marker
        tx.response_body = Some(Bytes::from_static(b"--abc--\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_escaped_boundary_unescaped_ok() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=\"a\\\"b\"")],
        );
        // unescaped boundary is: a"b
        tx.response_body = Some(Bytes::from_static(b"--a\"b\r\nx\r\n--a\"b--\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_colon_boundary_ok() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[(
                "content-type",
                "multipart/mixed; boundary=\"gc0pJq0M:08jU534c0p\"",
            )],
        );
        tx.response_body = Some(Bytes::from_static(
            b"--gc0pJq0M:08jU534c0p\r\npart\r\n--gc0pJq0M:08jU534c0p--\r\n",
        ));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn binary_body_marker_ok() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=bin")],
        );
        tx.response_body = Some(Bytes::from_static(b"\x00\x01--bin\x02--bin--\x03"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn haystack_edge_cases() {
        // empty needle -> true
        assert!(haystack_contains(b"abc", b""));
        // hay shorter than needle -> false
        assert!(!haystack_contains(b"a", b"--abcd"));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(
            &mut cfg,
            "message_multipart_content_type_and_body_consistency",
        );
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
