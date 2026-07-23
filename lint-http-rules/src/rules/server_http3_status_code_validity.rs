// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerHttp3StatusCodeValidity;

impl Rule for ServerHttp3StatusCodeValidity {
    fn id(&self) -> &'static str {
        "server_http3_status_code_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Only applies to HTTP/3 connections. Scoping, not a normative check — no cite.
        if tx.request.version != "HTTP/3" {
            return None;
        }

        let resp = tx.response.as_ref()?;

        // Only check responses that are themselves HTTP/3. In a reverse-proxy
        // setup the upstream response may be HTTP/1.1 (where 101 is valid).
        if resp.version != "HTTP/3" {
            return None;
        }

        // § 4.5 is the only place RFC 9114 mentions 101 at all.
        // cite(RFC 9114 § 4.5): "HTTP/3 does not support the HTTP Upgrade mechanism (Section 7.8 of [HTTP]) or the 101 (Switching Protocols) informational status code (Section 15.2.2 of [HTTP])."
        if resp.status == 101 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message:
                    "HTTP/3 does not support 101 (Switching Protocols); use extended CONNECT instead"
                        .into(),
            });
        }

        // Informational (1xx) responses consist of only a HEADERS frame — no content,
        // no trailers. One sentence governs all three checks in this block.
        // cite(RFC 9110 § 15.2): "A 1xx response is terminated by the end of the header section; it cannot contain content or trailers."
        if (100..200).contains(&resp.status) {
            // Content-Length MUST NOT appear on a 1xx response — it announces content.
            if resp.headers.contains_key("content-length") {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "HTTP/3 {} informational response must not include Content-Length",
                        resp.status
                    ),
                });
            }

            // A captured body on a 1xx response indicates DATA frames were
            // sent after an informational HEADERS frame, which is invalid.
            if let Some(len) = resp.body_length {
                if len > 0 {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "HTTP/3 {} informational response must not contain a message body",
                            resp.status
                        ),
                    });
                }
            }

            // Informational responses do not carry trailers (RFC 9110 §15.2).
            if resp.trailers.is_some() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "HTTP/3 {} informational response must not contain trailer fields",
                        resp.status
                    ),
                });
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("HTTP/3 Status Code Validity")
    }

    fn description(&self) -> &'static str {
        "HTTP/3 does not support the `101 (Switching Protocols)` informational status code. The protocol upgrade mechanism used in HTTP/1.1 has no equivalent in HTTP/3; applications that require protocol switching should use extended CONNECT (RFC 9220) instead.\n\nAdditionally, informational (1xx) responses in HTTP/3 consist of only a HEADERS frame and must not include a message body, `Content-Length` header, or trailer fields.\n\nThis rule applies when the request version is `HTTP/3`. Response properties are checked only when the response's own version is also `HTTP/3`; in a reverse-proxy setup the upstream response may arrive via HTTP/1.1 where `101` is legitimate."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.5",
                note: "HTTP Upgrade",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1",
                note: "HTTP Message Framing, where interim and final responses are described. This note said HTTP Message Exchanges, which is not a section RFC 9114 has",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2",
                note: "Informational 1xx",
            },
            crate::rules::SpecRef {
                spec: "RFC 9220",
                section: None,
                url: "https://www.rfc-editor.org/rfc/rfc9220.html",
                note: "Bootstrapping WebSockets with HTTP/3",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/3 100 Continue",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/3 103 Early Hints\nLink: </style.css>; rel=preload; as=style",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/3 200 OK\nContent-Type: text/html",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/3 101 Switching Protocols\nUpgrade: websocket",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/3 100 Continue\nContent-Length: 0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/3 103 Early Hints\nLink: </style.css>; rel=preload; as=style\n\n<body data follows>",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerHttp3StatusCodeValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_h3_transaction_with_response(
        status: u16,
        resp_headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, resp_headers);
        tx.request.version = "HTTP/3".into();
        if let Some(ref mut resp) = tx.response {
            resp.version = "HTTP/3".into();
        }
        tx
    }

    // --- 101 Switching Protocols is forbidden ---

    #[test]
    fn status_101_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(101, &[("upgrade", "websocket")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("should be a violation");
        assert_eq!(v.rule, "server_http3_status_code_validity");
        assert_eq!(v.severity, crate::lint::Severity::Warn);
        assert!(v.message.contains("101"));
    }

    #[test]
    fn status_101_bare_is_violation() {
        // 101 without any extra headers is still a violation
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(101, &[]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("101"));
    }

    // --- Valid 1xx informational responses ---

    #[rstest]
    #[case(100, &[])]
    #[case(102, &[])]
    #[case(103, &[("link", "</style.css>; rel=preload; as=style")])]
    fn valid_1xx_is_ok(#[case] status: u16, #[case] headers: &[(&str, &str)]) {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(status, headers);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- 1xx with Content-Length is violation ---

    #[test]
    fn informational_100_with_content_length_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(100, &[("content-length", "0")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("should be a violation");
        assert_eq!(v.rule, "server_http3_status_code_validity");
        assert!(v.message.contains("100"));
        assert!(v.message.contains("Content-Length"));
    }

    #[test]
    fn informational_103_with_content_length_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(103, &[("content-length", "42")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("103"));
        assert!(msg.contains("Content-Length"));
    }

    // --- 1xx with body is violation ---

    #[test]
    fn informational_with_body_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(10);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("message body"));
    }

    #[test]
    fn informational_with_zero_body_length_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(0);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- 1xx with trailers is violation ---

    #[test]
    fn informational_with_trailers_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
                "x-checksum",
                "abc",
            )]));
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("trailer"));
    }

    // --- Non-informational statuses are ok ---

    #[rstest]
    #[case(200)]
    #[case(204)]
    #[case(301)]
    #[case(304)]
    #[case(404)]
    #[case(500)]
    fn non_informational_status_is_ok(#[case] status: u16) {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(status, &[]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- HTTP version gating ---

    #[test]
    fn http11_101_is_not_checked() {
        let rule = ServerHttp3StatusCodeValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            101,
            &[("upgrade", "websocket")],
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn h3_request_non_h3_response_101_is_not_checked() {
        // Reverse-proxy scenario: client is HTTP/3 but upstream is HTTP/1.1
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            101,
            &[("upgrade", "websocket")],
        );
        tx.request.version = "HTTP/3".into();
        // response.version stays HTTP/1.1

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- No response case ---

    #[test]
    fn no_response_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/3".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Edge cases: 1xx boundary ---

    #[test]
    fn status_199_with_content_length_is_violation() {
        // 199 is still in the 1xx informational range
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(199, &[("content-length", "0")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("199"));
    }

    #[test]
    fn status_200_with_content_length_is_ok() {
        // 200 is not informational; Content-Length is allowed
        let rule = ServerHttp3StatusCodeValidity;
        let tx = make_h3_transaction_with_response(200, &[("content-length", "42")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Edge cases: non-informational with body/trailers are ok ---

    #[test]
    fn non_informational_with_body_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(200, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(100);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_informational_with_trailers_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(200, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
                "x-checksum",
                "abc",
            )]));
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Edge cases: priority of checks ---

    #[test]
    fn content_length_check_takes_priority_over_body_check() {
        // When both Content-Length and body are present, Content-Length is flagged first
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[("content-length", "10")]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(10);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Content-Length"));
    }

    #[test]
    fn status_101_takes_priority_over_1xx_checks() {
        // 101 is flagged as forbidden before any 1xx content checks
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(101, &[("content-length", "0")]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(10);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("101"));
    }

    // --- Edge cases: informational with no body_length (None) ---

    #[test]
    fn informational_with_no_body_length_is_ok() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = None;
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Edge case: HTTP/2 request with version gating ---

    #[test]
    fn http2_request_is_not_checked() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(101, &[("upgrade", "h2c")]);
        tx.request.version = "HTTP/2.0".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // --- Edge case: 102 Processing with body ---

    #[test]
    fn informational_102_with_body_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(102, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.body_length = Some(5);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("102"));
    }

    // --- Edge case: empty trailers HeaderMap is still a violation ---

    #[test]
    fn informational_with_empty_trailers_is_violation() {
        // Even an empty trailing HEADERS frame is invalid on 1xx (RFC 9110 §15.2)
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(100, &[]);
        if let Some(ref mut resp) = tx.response {
            resp.trailers = Some(hyper::HeaderMap::new());
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("trailer"));
    }

    // --- Edge case: 103 Early Hints with trailers ---

    #[test]
    fn informational_103_with_trailers_is_violation() {
        let rule = ServerHttp3StatusCodeValidity;
        let mut tx = make_h3_transaction_with_response(
            103,
            &[("link", "</style.css>; rel=preload; as=style")],
        );
        if let Some(ref mut resp) = tx.response {
            resp.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
                "x-timing", "50ms",
            )]));
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("trailer"));
    }

    // --- Scope and config validation ---

    #[test]
    fn scope_is_server() {
        let rule = ServerHttp3StatusCodeValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_http3_status_code_validity");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
