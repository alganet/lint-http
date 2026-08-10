// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageHttp2PseudoHeadersValidity;

impl Rule for MessageHttp2PseudoHeadersValidity {
    fn id(&self) -> &'static str {
        "message_http2_pseudo_headers_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Validate request-related pseudo-header semantics using canonical transaction fields.
        // Many capture formats do not retain raw HTTP/2 pseudo-header names in the HeaderMap (they are
        // represented as `RequestInfo.method` and `RequestInfo.uri` in the canonical transaction). Validate
        // those canonical fields conservatively to detect malformed pseudo-header-like values.

        // Validate :method -> RequestInfo.method
        let method = tx.request.method.trim();
        // cite(RFC 9113 § 8.3): "All pseudo-header fields MUST appear in a field block before all regular field lines."
        if let Some(c) = crate::helpers::token::find_invalid_token_char(method) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!("Invalid token '{}' in :method (request method)", c),
            });
        }

        // CONNECT special-case: request-target must be authority-form (no path)
        let method_is_connect = method.eq_ignore_ascii_case("CONNECT");

        // Use helpers::uri to decide whether request URI contains a path
        let path_opt = crate::helpers::uri::extract_path_from_request_target(&tx.request.uri);

        if method_is_connect {
            // CONNECT must not have a path, and the request-target should be authority-form
            if path_opt.is_some() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "HTTP/2 CONNECT-like request must not include a path in the request-target"
                            .into(),
                });
            }
            // Validate authority-like form (host[:port]) similar to Host header rules
            let auth = tx.request.uri.trim();
            if auth.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "CONNECT request-target (authority) is empty".into(),
                });
            }
            if auth.contains('@') {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "CONNECT request-target must not include userinfo".into(),
                });
            }
            if auth.starts_with('[') {
                if crate::helpers::ipv6::parse_bracketed_ipv6(auth).is_none() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "CONNECT request-target contains malformed bracketed IPv6".into(),
                    });
                }
            } else {
                // If there are multiple ':' characters this is likely an unbracketed IPv6
                // literal (with or without a trailing port). Reject it — IPv6 literals
                // in authority must be bracketed.
                let colon_count = auth.chars().filter(|&c| c == ':').count();
                if colon_count > 1 {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "CONNECT request-target IPv6 literal must be bracketed".into(),
                    });
                }

                // Single colon -> host:port, validate port
                if auth.contains(':') {
                    if let Some(idx) = auth.rfind(':') {
                        let port = &auth[idx + 1..];
                        if port.is_empty() || !port.chars().all(|c: char| c.is_ascii_digit()) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "CONNECT request-target port invalid".into(),
                            });
                        }
                        if let Ok(n) = port.parse::<u32>() {
                            if n == 0 || n > 65535 {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "CONNECT request-target port out of range".into(),
                                });
                            }
                        }
                    }
                }
            }
        } else {
            // Non-CONNECT: accept asterisk-form for OPTIONS, otherwise require a path component
            let s_trim = tx.request.uri.trim();
            if s_trim == "*" {
                if !method.eq_ignore_ascii_case("OPTIONS") {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message:
                            "Asterisk ('*') request-target is only permitted with OPTIONS method"
                                .into(),
                    });
                }
            } else if path_opt.is_none() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "HTTP/2 request missing ':path' pseudo-header equivalent (no path in request-target)".into(),
                });
            }
            // Validate path for whitespace and percent-encoding correctness
            if let Some(p) = path_opt {
                if crate::helpers::uri::contains_whitespace(&p) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "':path' equivalent in request-target contains whitespace".into(),
                    });
                }
                if let Some(msg) = crate::helpers::uri::check_percent_encoding(&p) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Invalid percent-encoding in request-target path: {}",
                            msg
                        ),
                    });
                }
            }
        }

        // If request URI appears to be absolute (contains '://'), validate scheme and authority.
        // We run scheme validation even if `extract_origin_if_absolute` returns `None` (which happens
        // for invalid schemes or missing authority) so we can surface helpful violations.
        if tx.request.uri.contains("://") {
            // Validate scheme even for invalid origins like "1http://..."
            if let Some(msg) = crate::helpers::uri::validate_scheme_if_present(&tx.request.uri) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Invalid scheme in request-target: {}", msg),
                });
            }
            // If origin can be cleanly extracted, reuse origin-based checks.
            if let Some(origin) = crate::helpers::uri::extract_origin_if_absolute(&tx.request.uri) {
                if let Some(colon_idx) = origin.find("://") {
                    let authority = &origin[colon_idx + 3..];
                    if authority.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Absolute request-target missing authority".into(),
                        });
                    }
                    if authority.contains('@') {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Request-target authority must not include userinfo".into(),
                        });
                    }
                    if authority.starts_with('[')
                        && crate::helpers::ipv6::parse_bracketed_ipv6(authority).is_none()
                    {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Request-target authority contains malformed bracketed IPv6"
                                .into(),
                        });
                    }
                }
            } else {
                // `extract_origin_if_absolute` failed (likely missing authority or whitespace in origin).
                // If it contains '://', but couldn't extract origin, it's an absolute-form with issues.
                // Check for missing authority explicitly.
                if let Some(idx) = tx.request.uri.find("://") {
                    let after = &tx.request.uri[idx + 3..];
                    if after.is_empty() || after.starts_with('/') {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Absolute request-target missing authority".into(),
                        });
                    }
                }
            }
        }

        // **The response half is not this rule's.** This branch used to report a
        // status outside 100–599 as a `:status` defect, and it ran on *every*
        // transaction: this rule has no version gate, so an out-of-range status in
        // an HTTP/1.1 status-line was reported here, as a pseudo-header the message
        // never carried, on top of the report from the rule that owns the question.
        // Two of this rule's own tests asserted it, both built on
        // `make_test_transaction_with_response`, whose responses are HTTP/1.1.
        //
        // The range is RFC 9110 § 15's and holds for every version. RFC 9113
        // § 8.3.2 defines `:status` as carrying "the HTTP status code field (see
        // Section 15 of [HTTP])" and states no range of its own, so there was never
        // an HTTP/2 sentence under the check; `server_status_code_valid_range` asks
        // it of every version. What § 8.3.2 does require — that the field be present
        // in all responses, including interim ones — cannot fail in this model:
        // `ResponseInfo.status` is a `u16` that always holds a value.
        //
        // cite(RFC 9113 § 8.3.2): "For HTTP/2 responses, a single ":status" pseudo-header field is defined that carries the HTTP status code field (see Section 15 of [HTTP])."
        // cite(RFC 9113 § 8.3.2): "This pseudo-header field MUST be included in all responses, including interim responses; otherwise, the response is malformed (Section 8.1.1)."

        None
    }

    fn description(&self) -> &'static str {
        "Validate HTTP/2 request pseudo-header fields. Requests must carry the appropriate fields (e.g., `:method` and `:path` for most requests, `:authority` for CONNECT), and their values are validated for basic syntax (tokens, percent-encoding) to detect malformed or protocol-inconsistent headers. The rule also accepts the asterisk-form (`*`) only when the method is `OPTIONS` (see specifications).\n\n**Nothing here reads the response.** RFC 9113 §8.3.2 requires a response to carry exactly one `:status` pseudo-header field, which the canonical transaction model always supplies as a `u16`, so its absence has no representation to check; and the range that value must fall in is RFC 9110 §15's, which is the same for every HTTP version and is reported by `server_status_code_valid_range`."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1",
                note: "Request pseudo-header fields — defines `:method`, `:scheme`, `:authority`, and `:path` and their presence/format rules (including `*` for OPTIONS and omitted `:path` for CONNECT)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.2",
                note: "Response pseudo-header fields — defines the `:status` pseudo-header for responses",
            },
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5",
                note: "CONNECT method — CONNECT requests omit `:scheme` and `:path` and use `:authority` to carry host[:port]",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: ":method: GET\n:scheme: https\n:authority: example.com\n:path: /",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: ":method: OPTIONS\n:path: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: ":method: GET",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: ":method: CONNECT\n:authority: example.com:443\n:path: /",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageHttp2PseudoHeadersValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("GET", "/", false, None)]
    #[case("GET", "", true, Some("missing ':path'"))]
    #[case("CONNECT", "example.com:443", false, None)]
    #[case("CONNECT", "/", true, Some("must not include a path"))]
    #[case("GE T", "/", true, Some("Invalid token"))]
    fn request_pseudo_cases(
        #[case] method: &str,
        #[case] uri: &str,
        #[case] expect_violation: bool,
        #[case] expected_contains: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        tx.request.uri = uri.to_string();
        let rule = MessageHttp2PseudoHeadersValidity;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some());
            if let Some(sub) = expected_contains {
                assert!(v.unwrap().message.contains(sub));
            }
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageHttp2PseudoHeadersValidity;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "message_http2_pseudo_headers_validity".into(),
            toml::Value::Table(table),
        );
        rule.validate(&cfg)?;
        Ok(())
    }

    #[test]
    fn request_absolute_scheme_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "1http://example.com/".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid scheme"));
    }

    #[test]
    fn request_path_percent_encoding_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/bad%2G".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid percent-encoding"));
    }

    #[test]
    fn request_path_whitespace_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/foo bar".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("contains whitespace"));
    }

    #[test]
    fn connect_empty_authority_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("CONNECT request-target (authority) is empty"));
    }

    #[test]
    fn connect_malformed_ipv6_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "[::1".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("malformed bracketed IPv6"));
    }

    #[test]
    fn connect_port_invalid_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:abc".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("port invalid"));
    }

    #[test]
    fn connect_port_out_of_range_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:70000".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("port out of range"));
    }

    #[test]
    fn connect_empty_port_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "example.com:".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("port invalid"));
    }

    #[test]
    fn connect_userinfo_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "user:pass@example.com".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must not include userinfo"));
    }

    #[test]
    fn connect_bracketed_ipv6_with_port_valid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "[::1]:443".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn connect_unbracketed_ipv6_without_port_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "::1".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must be bracketed"));
    }

    #[test]
    fn connect_unbracketed_ipv6_with_port_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "fe80::1:80".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must be bracketed"));
    }

    #[test]
    fn request_absolute_origin_valid_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https://example.com/path".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn request_path_percent_encoding_valid_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "/ok%20here".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn method_token_non_ascii_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GE€T".into();
        tx.request.uri = "/".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid token"));
    }

    /// The status range is RFC 9110 § 15's, is the same for every HTTP version, and
    /// is `server_status_code_valid_range`'s finding. Both statuses here were
    /// asserted as violations of *this* rule until the branch was removed — on
    /// HTTP/1.1 responses, which is what `make_test_transaction_with_response`
    /// builds and what this ungated rule was reporting.
    #[rstest]
    #[case(99)]
    #[case(700)]
    fn out_of_range_status_is_not_this_rules_finding(#[case] status: u16) {
        let tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        let history = crate::transaction_history::TransactionHistory::empty();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_none(), "{v:?}");

        let owner = crate::rules::server_status_code_valid_range::ServerStatusCodeValidRange;
        assert!(
            owner
                .check_transaction(
                    &tx,
                    &history,
                    &crate::test_helpers::make_test_config_with_enabled_rules(&[owner.id()]),
                )
                .is_some(),
            "status {status} is reported by nobody"
        );
    }

    #[test]
    fn absolute_missing_authority_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "https:///path".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("Absolute request-target missing authority"));
    }

    #[test]
    fn absolute_authority_userinfo_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "http://user:pass@example.com/path".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("must not include userinfo"));
    }

    #[test]
    fn asterisk_form_options_is_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "OPTIONS".into();
        tx.request.uri = "*".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn asterisk_form_non_options_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".into();
        tx.request.uri = "*".into();
        let v = MessageHttp2PseudoHeadersValidity.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "message_http2_pseudo_headers_validity",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Asterisk ('*')"));
    }
}
