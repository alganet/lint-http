// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure that the request method makes sense for the advertised HTTP version and
/// that it is appropriate for the presence (or absence) of a message body.
///
/// RFC 9110 gives explicit guidance about which methods are allowed to carry a
/// request body and even obliges clients to avoid sending bodies when the
/// semantics are undefined or explicitly forbidden (e.g. GET, HEAD, TRACE,
/// CONNECT).  This rule flags requests that claim to have a body while using a
/// method whose semantics do not allow it.  It also provides a later extension
/// point for version-specific method validity checks.
///
/// For now we only check the body-related semantics because that is the
/// "HTTP correctness" issue captured in `NEXT.md`.  GET/HEAD/DELETE/TRACE/
/// CONNECT requests with non-zero content are considered violations.  All other
/// methods are assumed to permit a body (POST, PUT, PATCH, OPTIONS, etc.).
///
/// The rule name includes "version" to leave room for future additions such as
/// warning about methods that predate or postdate the declared HTTP version.
///
pub struct ClientRequestVersionMethodValidity;

impl Rule for ClientRequestVersionMethodValidity {
    fn id(&self) -> &'static str {
        "client_request_version_method_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let method = tx.request.method.as_str();

        // Determine whether the request seems to include a body by looking at
        // the headers.  We intentionally mirror the logic used by the earlier
        // `client_request_method_body_consistency` rule for consistency.
        if !crate::helpers::headers::has_request_body(&tx.request.headers) {
            return None; // no body claimed, nothing to check
        }

        // Methods that do *not* define request-content semantics and which RFC
        // 9110 either forbids or discourages from carrying a body.
        let method_upper = method.to_ascii_uppercase();
        if method_upper == "GET"
            || method_upper == "HEAD"
            || method_upper == "DELETE"
            || method_upper == "TRACE"
            || method_upper == "CONNECT"
        {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "{} request contains an unexpected message body (method does not allow content according to RFC 9110)",
                    method
                ),
            });
        }

        // Future: could also validate method applicability based on
        // `tx.request.version` here.

        None
    }

    fn description(&self) -> &'static str {
        "Clients SHOULD use request methods whose semantics align with the message\ncontent they are sending.  Some methods either forbid or have no defined\nsemantics for a request body; sending content with those methods can lead to\ninteroperability problems or security risks (e.g. request smuggling).  This\nrule flags any request that claims a non-zero body when the method's\nsemantics do not allow it.\n\nThe most obvious examples are GET and HEAD (which have no defined request\npayload semantics) but the same guidance applies to DELETE, TRACE, and\nCONNECT.  By enforcing this rule, users are encouraged to choose methods like\nPOST, PUT, PATCH, or OPTIONS when content is required."
    }

    fn rfc_reference(&self) -> Option<&'static str> {
        Some("RFC 9110 §9.3.1 (GET) – ‘‘A client **SHOULD NOT** generate content in a GET request ...’’")
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                snippet:
                    "POST /upload HTTP/1.1\nHost: example.com\nContent-Length: 123\n\n<binary data>",
            },
            Example {
                compliance: Compliance::Compliant,
                snippet: "DELETE /resource/42 HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                snippet: "GET /search HTTP/1.1\nHost: example.com\nContent-Length: 5\n\nhello",
            },
            Example {
                compliance: Compliance::NonCompliant,
                snippet: "TRACE / HTTP/1.1\nHost: example.com\nContent-Length: 1\n\nx",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientRequestVersionMethodValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_tx_with_req(
        method: &str,
        headers: Vec<(&str, &str)>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&headers);
        tx
    }

    #[rstest]
    #[case("GET", vec![], false)]
    #[case("GET", vec![("content-length", "0")], false)]
    #[case("GET", vec![("content-length", "10")], true)]
    #[case("HEAD", vec![("content-length", "1")], true)]
    #[case("DELETE", vec![("transfer-encoding", "chunked")], true)]
    #[case("TRACE", vec![("content-length", "1")], true)]
    #[case("CONNECT", vec![("content-length", "1")], true)]
    #[case("POST", vec![("content-length", "1")], false)]
    #[case("PUT", vec![("transfer-encoding", "chunked")], false)]
    fn method_body_cases(
        #[case] method: &str,
        #[case] headers: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) {
        let rule = ClientRequestVersionMethodValidity;
        let tx = make_tx_with_req(method, headers);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );

        if expect_violation {
            assert!(v.is_some(), "expected violation for {}", method);
        } else {
            assert!(v.is_none(), "unexpected violation for {}: {:?}", method, v);
        }
    }

    #[test]
    fn invalid_content_length_is_ignored() {
        let rule = ClientRequestVersionMethodValidity;
        let tx = make_tx_with_req("GET", vec![("content-length", "not-a-number")]);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn content_length_overflow_is_ignored() {
        let rule = ClientRequestVersionMethodValidity;
        let huge = "9".repeat(100);
        let tx = make_tx_with_req("GET", vec![("content-length", huge.as_str())]);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_or_whitespace_content_length_is_ignored() {
        let rule = ClientRequestVersionMethodValidity;
        let tx_empty = make_tx_with_req("GET", vec![("content-length", "")]);
        let tx_space = make_tx_with_req("GET", vec![("content-length", "   ")]);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let v_empty = rule.check_transaction(
            &tx_empty,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v_empty.is_none());

        let v_space = rule.check_transaction(
            &tx_space,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v_space.is_none());
    }

    #[test]
    fn violation_messages_are_informative() {
        let rule = ClientRequestVersionMethodValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let tx = make_tx_with_req("GET", vec![("content-length", "10")]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("GET request"));

        let tx2 = make_tx_with_req("TRACE", vec![("transfer-encoding", "chunked")]);
        let v2 = rule
            .check_transaction(
                &tx2,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v2.message.contains("TRACE request"));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "client_request_version_method_validity");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
