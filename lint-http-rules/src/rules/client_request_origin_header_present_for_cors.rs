// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientRequestOriginHeaderPresentForCors;

impl Rule for ClientRequestOriginHeaderPresentForCors {
    fn id(&self) -> &'static str {
        "client_request_origin_header_present_for_cors"
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
        let req = &tx.request;
        let headers = &req.headers;

        // If this looks like a CORS preflight (OPTIONS with Access-Control-Request-Method)
        // then Origin header MUST be present and syntactically valid.
        if req.method == "OPTIONS"
            && (headers.get("access-control-request-method").is_some()
                || headers.get("access-control-request-headers").is_some())
        {
            // Origin must be present
            match crate::helpers::headers::get_header_str(headers, "origin") {
                Some(origin_val) => {
                    if let Some(err) = crate::helpers::uri::validate_origin_value(origin_val) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Origin header invalid: {}", err),
                        });
                    }
                }
                None => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "CORS preflight request missing Origin header".into(),
                    })
                }
            }
        }

        // If request-target is absolute-form and its origin differs from Host header,
        // consider it cross-origin and require Origin header to be present.
        if let Some(target_origin) = crate::helpers::uri::extract_origin_if_absolute(&req.uri) {
            if let Some(host_hdr) = crate::helpers::headers::get_header_str(headers, "host") {
                // host header may include port; compare authority portion
                let host_authority = host_hdr.trim();
                // extract authority from target_origin (after '://')
                if let Some(delimiter_pos) = target_origin.find("://") {
                    let target_authority = &target_origin[delimiter_pos + 3..];
                    if !target_authority.eq_ignore_ascii_case(host_authority) {
                        // they differ; require Origin header
                        if crate::helpers::headers::get_header_str(headers, "origin").is_none() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Cross-origin absolute-form request missing Origin header"
                                    .into(),
                            });
                        }
                    }
                }
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Origin Header Presence for CORS Preflight and Cross-Origin Absolute-form Requests")
    }

    fn description(&self) -> &'static str {
        "This rule enforces that requests which indicate cross-origin intent include an `Origin` header. In particular:\n\n- CORS preflight requests (an `OPTIONS` request with `Access-Control-Request-Method` or `Access-Control-Request-Headers`) MUST include an `Origin` header.\n- If a client uses an absolute-form request-target whose origin differs from the `Host` header, the request is treated as cross-origin and SHOULD include an `Origin` header.\n\nThe rule validates that `Origin` is present where required and that its value is syntactically plausible (a serialized origin such as `https://example.com` or the literal `null`). This rule applies to client requests (RuleScope::Client)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 6454",
                section: None,
                url: "https://www.rfc-editor.org/rfc/rfc6454.html",
                note: "The Web Origin Concept",
            },
            crate::rules::SpecRef {
                spec: "Fetch",
                section: None,
                url: "https://fetch.spec.whatwg.org/#origin-header",
                note: "CORS / Fetch: Origin header semantics",
            },
            crate::rules::SpecRef {
                spec: "MDN Origin",
                section: None,
                url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Origin",
                note: "Origin",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(preflight)"),
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\nOrigin: https://example.org\nAccess-Control-Request-Method: POST",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(absolute-form same origin)"),
                snippet: "GET http://example.com/resource HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(preflight missing Origin)"),
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\nAccess-Control-Request-Method: POST",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(absolute-form to other origin missing Origin)"),
                snippet: "GET http://other.example/resource HTTP/1.1\nHost: example.com",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientRequestOriginHeaderPresentForCors;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::{make_headers_from_pairs, make_test_transaction};

    #[rstest]
    fn preflight_without_origin_is_violation() {
        let rule = ClientRequestOriginHeaderPresentForCors;
        let mut tx = make_test_transaction();
        tx.request.method = "OPTIONS".into();
        tx.request.headers = make_headers_from_pairs(&[("access-control-request-method", "POST")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("missing Origin"));
    }

    #[rstest]
    fn preflight_with_origin_ok() {
        let rule = ClientRequestOriginHeaderPresentForCors;
        let mut tx = make_test_transaction();
        tx.request.method = "OPTIONS".into();
        tx.request.headers = make_headers_from_pairs(&[
            ("access-control-request-method", "POST"),
            ("origin", "https://example.com"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn preflight_with_invalid_origin_is_violation() {
        let rule = ClientRequestOriginHeaderPresentForCors;
        let mut tx = make_test_transaction();
        tx.request.method = "OPTIONS".into();
        tx.request.headers = make_headers_from_pairs(&[
            ("access-control-request-method", "POST"),
            ("origin", "http:///bad"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Origin header invalid"));
    }

    #[rstest]
    fn absolute_form_cross_origin_missing_origin_is_violation() {
        let rule = ClientRequestOriginHeaderPresentForCors;
        let mut tx = make_test_transaction();
        tx.request.uri = "http://other.example/resource".into();
        tx.request.headers = make_headers_from_pairs(&[("host", "example.com")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("Cross-origin absolute-form request missing Origin header"));
    }

    #[rstest]
    fn absolute_form_same_origin_without_origin_ok() {
        let rule = ClientRequestOriginHeaderPresentForCors;
        let mut tx = make_test_transaction();
        tx.request.uri = "http://example.com/resource".into();
        tx.request.headers = make_headers_from_pairs(&[("host", "example.com")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientRequestOriginHeaderPresentForCors;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = ClientRequestOriginHeaderPresentForCors;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "client_request_origin_header_present_for_cors".into(),
            toml::Value::Table(table),
        );

        rule.validate(&cfg)?;
        Ok(())
    }
}
