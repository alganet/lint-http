// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageHttp3HostAuthorityConsistency;

impl Rule for MessageHttp3HostAuthorityConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_http3_host_authority_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
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

        // Extract authority from the request URI (derived from :authority pseudo-header).
        let authority =
            crate::helpers::uri::extract_authority_from_request_target(&tx.request.uri)?;

        // If there is no Host header, nothing to compare (absence of Host when
        // :authority is present is valid per RFC 9114 §4.3.1).
        let host_value = tx.request.headers.get("host")?;
        let host_str = match host_value.to_str() {
            Ok(s) => s,
            Err(_) => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Host header contains non-UTF-8 value".into(),
                });
            }
        };

        let host_trimmed = host_str.trim();

        // Both must not be empty when both are present (RFC 9114 §4.3.1).
        if host_trimmed.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message:
                    "Host header must not be empty when :authority pseudo-header is also present"
                        .into(),
            });
        }

        // The values MUST contain the same value (RFC 9114 §4.3.1).
        // Hostnames are case-insensitive (RFC 3986 §3.2.2).
        if !authority.eq_ignore_ascii_case(host_trimmed) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    ":authority '{}' and Host '{}' are inconsistent",
                    authority, host_trimmed
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_h3_transaction_with_uri_and_host(
        uri: &str,
        host: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/3".into();
        tx.request.uri = uri.to_string();
        if let Some(h) = host {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("host", h)]);
        } else {
            tx.request.headers = hyper::HeaderMap::new();
        }
        tx
    }

    // --- Consistent values: no violation ---

    #[rstest]
    #[case("https://example.com/path", "example.com")]
    #[case("https://example.com:8080/path", "example.com:8080")]
    #[case("https://Example.COM/path", "example.com")]
    #[case("https://example.com/path", "Example.COM")]
    #[case("https://EXAMPLE.COM:443/path", "example.com:443")]
    #[case("https://[::1]:8080/path", "[::1]:8080")]
    fn consistent_authority_and_host_is_ok(#[case] uri: &str, #[case] host: &str) {
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx = make_h3_transaction_with_uri_and_host(uri, Some(host));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Inconsistent values: violation ---

    #[rstest]
    #[case(
        "https://example.com/path",
        "other.com",
        ":authority 'example.com' and Host 'other.com'"
    )]
    #[case(
        "https://example.com:8080/path",
        "example.com:9090",
        ":authority 'example.com:8080' and Host 'example.com:9090'"
    )]
    #[case(
        "https://example.com:443/path",
        "example.com",
        ":authority 'example.com:443' and Host 'example.com'"
    )]
    #[case(
        "https://example.com/path",
        "example.com:443",
        ":authority 'example.com' and Host 'example.com:443'"
    )]
    fn inconsistent_authority_and_host_is_violation(
        #[case] uri: &str,
        #[case] host: &str,
        #[case] expected_message_contains: &str,
    ) {
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx = make_h3_transaction_with_uri_and_host(uri, Some(host));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains(expected_message_contains),
            "expected '{}' in '{}'",
            expected_message_contains,
            msg
        );
    }

    // --- Only one present: no violation ---

    #[test]
    fn authority_present_host_absent_is_ok() {
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx = make_h3_transaction_with_uri_and_host("https://example.com/path", None);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn origin_form_uri_with_host_is_ok() {
        // When URI is origin-form, no authority can be extracted -> no comparison.
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx = make_h3_transaction_with_uri_and_host("/path", Some("example.com"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Empty Host header: violation ---

    #[test]
    fn empty_host_with_authority_is_violation() {
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx = make_h3_transaction_with_uri_and_host("https://example.com/path", Some(""));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must not be empty"));
    }

    #[test]
    fn whitespace_only_host_with_authority_is_violation() {
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx = make_h3_transaction_with_uri_and_host("https://example.com/path", Some("  "));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must not be empty"));
    }

    // --- HTTP version gating ---

    #[test]
    fn http11_is_not_checked() {
        let rule = MessageHttp3HostAuthorityConsistency;
        let mut tx =
            make_h3_transaction_with_uri_and_host("https://example.com/path", Some("other.com"));
        tx.request.version = "HTTP/1.1".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn http2_is_not_checked() {
        let rule = MessageHttp3HostAuthorityConsistency;
        let mut tx =
            make_h3_transaction_with_uri_and_host("https://example.com/path", Some("other.com"));
        tx.request.version = "HTTP/2.0".into();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Non-UTF-8 Host header ---

    #[test]
    fn host_non_utf8_is_violation() {
        let rule = MessageHttp3HostAuthorityConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/3".into();
        tx.request.uri = "https://example.com/path".into();
        let bad = hyper::header::HeaderValue::from_bytes(&[0xff])
            .expect("should construct non-utf8 header");
        tx.request.headers = hyper::HeaderMap::new();
        tx.request.headers.insert("host", bad);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-UTF-8"));
    }

    // --- RFC edge cases ---

    #[test]
    fn host_with_surrounding_whitespace_matches_after_trim() {
        // Host header values may contain OWS; trimming ensures correct comparison.
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx = make_h3_transaction_with_uri_and_host(
            "https://example.com/path",
            Some("  example.com  "),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_authority_form_consistent_is_ok() {
        // CONNECT uses authority-form (host:port) as the request-target,
        // which IS the :authority value and must match Host.
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx = make_h3_transaction_with_uri_and_host("example.com:443", Some("example.com:443"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_authority_form_inconsistent_is_violation() {
        // CONNECT with different Host than authority-form target.
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx = make_h3_transaction_with_uri_and_host("example.com:443", Some("other.com:443"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("inconsistent"));
    }

    #[test]
    fn ipv6_without_port_consistent() {
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx = make_h3_transaction_with_uri_and_host("https://[::1]/path", Some("[::1]"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn trailing_dot_mismatch_is_violation() {
        // "example.com." and "example.com" are different values per literal comparison.
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx =
            make_h3_transaction_with_uri_and_host("https://example.com./path", Some("example.com"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("inconsistent"));
    }

    #[test]
    fn query_string_does_not_leak_into_authority() {
        // Authority extraction must stop at '?'.
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx =
            make_h3_transaction_with_uri_and_host("https://example.com?q=1", Some("example.com"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn fragment_does_not_leak_into_authority() {
        let rule = MessageHttp3HostAuthorityConsistency;
        let tx =
            make_h3_transaction_with_uri_and_host("https://example.com#frag", Some("example.com"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    // --- Scope and config validation ---

    #[test]
    fn scope_is_client() {
        let rule = MessageHttp3HostAuthorityConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_http3_host_authority_consistency");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
