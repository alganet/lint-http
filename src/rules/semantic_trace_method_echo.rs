// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct SemanticTraceMethodEcho;

impl Rule for SemanticTraceMethodEcho {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "semantic_trace_method_echo"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        if !tx.request.method.eq_ignore_ascii_case("TRACE") {
            return None;
        }

        // RFC 9110: client MUST NOT generate content in a TRACE request.
        if tx.request.headers.contains_key("transfer-encoding") {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "TRACE request MUST NOT include content (Transfer-Encoding present)"
                    .into(),
            });
        }

        if let Ok(Some(n)) = crate::helpers::headers::validate_content_length(&tx.request.headers) {
            if n > 0 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "TRACE request MUST NOT include content (Content-Length {})",
                        n
                    ),
                });
            }
        }

        if matches!(tx.request.body_length, Some(n) if n > 0) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message:
                    "TRACE request MUST NOT include content (captured request body length > 0)"
                        .into(),
            });
        }

        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // RFC 9110 §9.3.8 uses SHOULD for successful TRACE responses.
        // Do not enforce message/http for non-success responses.
        if !(200..300).contains(&resp.status) {
            return None;
        }

        // For TRACE responses that appear to carry content, expect message/http media type.
        let has_response_content = matches!(resp.body_length, Some(n) if n > 0)
            || resp.headers.contains_key("transfer-encoding")
            || matches!(
                crate::helpers::headers::validate_content_length(&resp.headers),
                Ok(Some(n)) if n > 0
            );

        if !has_response_content {
            return None;
        }

        let ct = match resp.headers.get("content-type") {
            None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "TRACE response with content should use Content-Type: message/http"
                        .into(),
                });
            }
            Some(raw) => match raw.to_str() {
                Ok(v) => v,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "TRACE response Content-Type contains non-UTF-8 bytes; expected message/http".into(),
                    });
                }
            },
        };

        let parsed = match crate::helpers::headers::parse_media_type(ct) {
            Ok(p) => p,
            Err(_) => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "TRACE response Content-Type '{}' is invalid; expected message/http",
                        ct
                    ),
                });
            }
        };

        if !(parsed.type_.eq_ignore_ascii_case("message")
            && parsed.subtype.eq_ignore_ascii_case("http"))
        {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "TRACE response Content-Type '{}' should be message/http",
                    ct
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace_tx() -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "TRACE".to_string();
        tx
    }

    #[test]
    fn id_and_scope() {
        let r = SemanticTraceMethodEcho;
        assert_eq!(r.id(), "semantic_trace_method_echo");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn non_trace_request_is_ignored() {
        let rule = SemanticTraceMethodEcho;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn trace_request_with_transfer_encoding_is_violation() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("transfer-encoding", "chunked")]);

        let v = rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("MUST NOT include content"));
    }

    #[test]
    fn trace_request_with_positive_content_length_is_violation() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-length", "1")]);

        let v = rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("Content-Length 1"));
    }

    #[test]
    fn trace_request_with_captured_body_is_violation() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.request.body_length = Some(4);

        let v = rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("captured request body"));
    }

    #[test]
    fn trace_request_with_zero_content_length_is_ok() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-length", "0")]);

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn trace_request_with_invalid_content_length_is_ignored_by_this_rule() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-length", "abc")]);

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn trace_response_with_content_and_message_http_is_ok() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "message/http; charset=utf-8",
            )]),
            body_length: Some(10),
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn trace_response_with_content_and_missing_content_type_is_violation() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),
            body_length: Some(10),
        });

        let v = rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("message/http"));
    }

    #[test]
    fn trace_response_with_content_and_non_utf8_content_type_is_violation() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "content-type",
            hyper::header::HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers,
            body_length: Some(10),
        });

        let v = rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("message/http"));
    }

    #[test]
    fn trace_response_with_content_and_non_message_http_is_violation() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "text/plain",
            )]),
            body_length: Some(10),
        });

        let v = rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("should be message/http"));
    }

    #[test]
    fn trace_response_with_invalid_content_type_syntax_is_violation() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-type", "text")]),
            body_length: Some(10),
        });

        let v = rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("is invalid"));
    }

    #[test]
    fn trace_response_without_content_is_ignored() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),
            body_length: Some(0),
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn trace_response_transfer_encoding_implies_content_and_requires_message_http() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "transfer-encoding",
                "chunked",
            )]),
            body_length: None,
        });

        let v = rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("message/http"));
    }

    #[test]
    fn trace_response_content_length_implies_content() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[
                ("content-length", "7"),
                ("content-type", "message/http"),
            ]),
            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn non_2xx_trace_response_with_regular_error_content_type_is_allowed() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 405,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[
                ("content-type", "application/json"),
                ("content-length", "32"),
            ]),
            body_length: Some(32),
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn trace_response_with_invalid_content_length_does_not_imply_content() {
        let rule = SemanticTraceMethodEcho;
        let mut tx = make_trace_tx();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "abc")]),
            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "semantic_trace_method_echo",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
