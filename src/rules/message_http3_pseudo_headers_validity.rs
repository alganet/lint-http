// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageHttp3PseudoHeadersValidity;

impl Rule for MessageHttp3PseudoHeadersValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_http3_pseudo_headers_validity"
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
        // Only applies to HTTP/3 transactions.
        if tx.request.version != "HTTP/3" {
            return None;
        }

        // :method pseudo-header is required (RFC 9114 §4.3).
        let method = tx.request.method.trim();
        if method.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "HTTP/3 request missing required ':method' pseudo-header".into(),
            });
        }

        let is_connect = method.eq_ignore_ascii_case("CONNECT");

        if is_connect {
            // CONNECT requests require an authority (RFC 9114 §4.4).
            // In the canonical model, the authority comes from the request-target
            // (authority-form) or, for extended CONNECT using origin-form, from
            // the Host header.
            let uri_trimmed = tx.request.uri.trim();
            if uri_trimmed.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "HTTP/3 CONNECT request missing required ':authority' pseudo-header or Host header"
                            .into(),
                });
            }
            let has_authority =
                crate::helpers::uri::extract_authority_from_request_target(uri_trimmed).is_some();
            let has_host = tx.request.headers.contains_key("host");
            let is_origin_form = uri_trimmed.starts_with('/');
            if is_origin_form {
                // Extended CONNECT: origin-form target, authority MUST come from Host.
                if !has_host {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "HTTP/3 extended CONNECT request with origin-form target must include Host header as authority"
                            .into(),
                    });
                }
            } else if !has_authority && !has_host {
                // Authority-form (or absolute-form) CONNECT without any authority.
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "HTTP/3 CONNECT request must include ':authority' pseudo-header or Host header"
                            .into(),
                });
            }
        } else {
            // Non-CONNECT: :path pseudo-header is required (RFC 9114 §4.3).
            // Asterisk-form ("*") is only valid for OPTIONS (RFC 9110 §7.1).
            let uri_trimmed = tx.request.uri.trim();
            if uri_trimmed == "*" {
                if !method.eq_ignore_ascii_case("OPTIONS") {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message:
                            "Asterisk ('*') request-target is only permitted with OPTIONS method"
                                .into(),
                    });
                }
            } else {
                let has_path =
                    crate::helpers::uri::extract_path_from_request_target(uri_trimmed).is_some();
                if !has_path {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "HTTP/3 request missing required ':path' pseudo-header".into(),
                    });
                }
            }

            // For schemes with a mandatory authority component (http, https),
            // the request MUST contain either :authority or Host (RFC 9114 §4.3.1).
            // HTTP/3 always runs over QUIC/TLS, so the scheme is always http or
            // https — the authority requirement applies to all non-CONNECT requests.
            let has_authority =
                crate::helpers::uri::extract_authority_from_request_target(&tx.request.uri)
                    .is_some();
            let has_host = tx.request.headers.contains_key("host");
            if !has_authority && !has_host {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "HTTP/3 request must include ':authority' pseudo-header or Host header"
                            .into(),
                });
            }
        }

        // Response: :status pseudo-header must be valid (RFC 9114 §4.3).
        if let Some(resp) = &tx.response {
            if resp.version == "HTTP/3" && !(100..=599).contains(&resp.status) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "HTTP/3 response ':status' pseudo-header must be a 3-digit code (100-599)"
                            .into(),
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

    fn make_h3_transaction() -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/3".into();
        tx
    }

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

    // --- :method pseudo-header required ---

    #[test]
    fn empty_method_is_violation() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":method"));
    }

    #[test]
    fn whitespace_only_method_is_violation() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "   ".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":method"));
    }

    // --- :path pseudo-header required for non-CONNECT ---

    #[test]
    fn get_with_path_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/path".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn get_origin_form_with_host_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/resource".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn get_without_path_is_violation() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "example.com:443".into(); // authority-form, no path
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":path"));
    }

    #[test]
    fn options_asterisk_with_host_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "OPTIONS".into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn asterisk_non_options_is_violation() {
        // Asterisk-form is only permitted with OPTIONS (RFC 9110 §7.1).
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Asterisk"));
    }

    #[rstest]
    #[case("POST")]
    #[case("PUT")]
    #[case("DELETE")]
    #[case("PATCH")]
    #[case("HEAD")]
    fn asterisk_non_options_methods_are_violation(#[case] bad_method: &str) {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = bad_method.into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Asterisk"));
    }

    // --- :authority or Host required ---

    #[test]
    fn origin_form_without_host_is_violation() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/resource".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    #[test]
    fn absolute_form_has_authority_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/path".into();
        tx.request.headers = hyper::HeaderMap::new(); // no Host needed

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn asterisk_without_host_or_authority_is_violation() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "OPTIONS".into();
        tx.request.uri = "*".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    // --- CONNECT ---

    #[test]
    fn connect_with_authority_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:443".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_with_empty_uri_is_violation() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    #[test]
    fn connect_with_whitespace_only_uri_is_violation() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "   ".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    #[test]
    fn connect_origin_form_with_host_is_ok() {
        // Extended CONNECT (RFC 9220) may use origin-form with Host header.
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "/ws".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_origin_form_without_host_is_violation() {
        // Extended CONNECT with origin-form but no Host header.
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "/ws".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("extended CONNECT"));
    }

    #[test]
    fn connect_asterisk_without_host_is_violation() {
        // CONNECT with "*" URI: extract_authority returns None, no Host → violation.
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "*".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }

    #[test]
    fn connect_asterisk_with_host_is_ok() {
        // CONNECT with "*" URI but Host header present → ok.
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "*".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com:443")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_authority_form_without_host_is_ok() {
        // Authority-form (host:port) is valid for CONNECT even without Host header.
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:443".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Response :status ---

    #[test]
    fn response_valid_status_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let tx = make_h3_transaction_with_response(200, &[]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn response_status_zero_is_violation() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let tx = make_h3_transaction_with_response(0, &[]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":status"));
    }

    #[test]
    fn response_status_above_599_is_violation() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let tx = make_h3_transaction_with_response(600, &[]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":status"));
    }

    #[rstest]
    #[case(100)]
    #[case(200)]
    #[case(301)]
    #[case(404)]
    #[case(500)]
    #[case(599)]
    fn response_valid_status_range_is_ok(#[case] status: u16) {
        let rule = MessageHttp3PseudoHeadersValidity;
        let tx = make_h3_transaction_with_response(status, &[]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- HTTP version gating ---

    #[rstest]
    #[case("HTTP/1.1")]
    #[case("HTTP/1.0")]
    #[case("HTTP/2")]
    #[case("HTTP/2.0")]
    fn non_h3_version_is_skipped(#[case] version: &str) {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = version.into();
        tx.request.method = "".into(); // would be a violation for HTTP/3

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Response version gating ---

    #[test]
    fn response_non_h3_version_not_checked() {
        // HTTP/3 request but HTTP/1.1 upstream response (reverse-proxy).
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(0, &[]);
        tx.request.version = "HTTP/3".into();
        // Response version stays HTTP/1.1 — status 0 should not be flagged.

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- No response case ---

    #[test]
    fn request_only_no_response_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/".into();
        tx.response = None;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Scope and config validation ---

    #[test]
    fn scope_is_both() {
        let rule = MessageHttp3PseudoHeadersValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_http3_pseudo_headers_validity");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    // --- RFC edge cases ---

    #[test]
    fn connect_ipv6_authority_is_ok() {
        // CONNECT with bracketed IPv6 authority (RFC 9114 §4.4).
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "[::1]:443".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn extended_connect_with_scheme_and_path_is_ok() {
        // Extended CONNECT (RFC 9220) includes :scheme, :path, :authority.
        // We do not flag this because we cannot distinguish basic from extended
        // CONNECT in the canonical data model.
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "https://example.com/ws".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn post_origin_form_with_host_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "POST".into();
        tx.request.uri = "/submit".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("host", "example.com"),
            ("content-type", "application/json"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn head_absolute_uri_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "HEAD".into();
        tx.request.uri = "https://example.com/resource".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn response_status_boundary_99_is_violation() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let tx = make_h3_transaction_with_response(99, &[]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":status"));
    }

    #[test]
    fn host_present_but_empty_counts_as_present() {
        // An empty Host header still counts as "present" for the authority
        // presence check. Value validation is handled by other rules.
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/resource".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("host", "")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn delete_with_absolute_uri_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "DELETE".into();
        tx.request.uri = "https://example.com/resource/42".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_uri_for_non_connect_is_path_violation() {
        // Empty URI means both :path and :authority are missing.
        // :path check fires first.
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":path"));
    }

    #[test]
    fn root_path_with_query_and_host_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/?q=search".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_case_insensitive() {
        // Method comparison is case-insensitive.
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "connect".into();
        tx.request.uri = "example.com:443".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn absolute_uri_with_port_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com:8443/path".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn informational_response_100_is_ok() {
        // 1xx informational responses are valid (RFC 9114 §4.1).
        let rule = MessageHttp3PseudoHeadersValidity;
        let tx = make_h3_transaction_with_response(100, &[]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn id_returns_correct_value() {
        let rule = MessageHttp3PseudoHeadersValidity;
        assert_eq!(rule.id(), "message_http3_pseudo_headers_validity");
    }

    #[test]
    fn connect_with_valid_response_is_ok() {
        // Validates response :status check runs after CONNECT request passes.
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction_with_response(200, &[]);
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:443".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_with_invalid_response_status_is_violation() {
        // CONNECT request is valid, but response :status is invalid.
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction_with_response(0, &[]);
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:443".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":status"));
    }

    #[test]
    fn whitespace_only_uri_non_connect_is_path_violation() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "   ".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":path"));
    }

    #[test]
    fn both_authority_and_host_present_is_ok() {
        // When both :authority (via absolute URI) and Host are present, no violation.
        // Value consistency is checked by message_http3_host_authority_consistency.
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/path".into();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn put_origin_form_with_host_is_ok() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "PUT".into();
        tx.request.uri = "/resource/1".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("host", "example.com"),
            ("content-type", "application/json"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn patch_origin_form_without_host_is_violation() {
        let rule = MessageHttp3PseudoHeadersValidity;
        let mut tx = make_h3_transaction();
        tx.request.method = "PATCH".into();
        tx.request.uri = "/resource/1".into();
        tx.request.headers = hyper::HeaderMap::new();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains(":authority"));
    }
}
