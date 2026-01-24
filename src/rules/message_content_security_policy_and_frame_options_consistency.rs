// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentSecurityPolicyAndFrameOptionsConsistency;

impl Rule for MessageContentSecurityPolicyAndFrameOptionsConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_content_security_policy_and_frame_options_consistency"
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
        // Only check responses
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // Collect CSP frame-ancestors info across header fields
        let mut csp_found = false;
        let mut csp_none = false;
        let mut csp_self = false;
        let mut csp_origins: Vec<String> = Vec::new();

        for hv in resp.headers.get_all("content-security-policy").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => continue, // other rule flags non-utf8
            };

            for raw_dir in s.split(';') {
                let dir = raw_dir.trim();
                if dir.is_empty() {
                    continue;
                }
                let mut parts = dir.split_whitespace();
                let name = match parts.next() {
                    Some(n) => n,
                    None => continue,
                };
                if !name.eq_ignore_ascii_case("frame-ancestors") {
                    continue;
                }

                csp_found = true;

                // parse members
                let mut had_member = false;
                for member in parts {
                    let m = member.trim();
                    if m.is_empty() {
                        continue;
                    }
                    had_member = true;
                    // strip single quotes if present
                    let token = if m.len() >= 2 && m.starts_with('\'') && m.ends_with('\'') {
                        &m[1..m.len() - 1]
                    } else {
                        m
                    };
                    if token.eq_ignore_ascii_case("none") {
                        csp_none = true;
                    } else if token.eq_ignore_ascii_case("self") {
                        csp_self = true;
                    } else {
                        // treat as origin candidate (store normalized without trailing slash)
                        let mut o = token.to_string();
                        if o.ends_with('/') {
                            o.pop();
                        }
                        csp_origins.push(o);
                    }
                }

                // If directive had no members (e.g., 'frame-ancestors'), treat as malformed; skip
                if !had_member {
                    continue;
                }
            }
        }

        // If no CSP frame-ancestors, nothing to compare
        if !csp_found {
            return None;
        }

        // Get X-Frame-Options header
        let xfo_count = resp.headers.get_all("x-frame-options").iter().count();
        if xfo_count == 0 {
            return None;
        }
        if xfo_count > 1 {
            // Other rule will report duplicate header; avoid duplicate diagnostics here
            return None;
        }

        let xfo_val =
            match crate::helpers::headers::get_header_str(&resp.headers, "x-frame-options") {
                Some(v) => v.trim(),
                None => return None, // non-utf8 -> let dedicated rule report
            };

        // Recognize canonical forms
        if xfo_val.eq_ignore_ascii_case("DENY") {
            // DENY forbids framing; contradiction if CSP permits any framing
            if csp_none {
                // Both deny -> ok
                return None;
            }
            // CSP permits framing if it had any non-'none' member
            if csp_self || !csp_origins.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "X-Frame-Options: DENY contradicts Content-Security-Policy frame-ancestors which permits framing".into(),
                });
            }
            return None;
        }

        if xfo_val.eq_ignore_ascii_case("SAMEORIGIN") {
            // SAMEORIGIN permits same-origin; contradiction only if CSP explicitly forbids all
            if csp_none {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Security-Policy frame-ancestors: 'none' forbids framing while X-Frame-Options: SAMEORIGIN permits same-origin frames".into(),
                });
            }
            // otherwise compatible (both allow some framing)
            return None;
        }

        // ALLOW-FROM
        if xfo_val.len() >= 10 && xfo_val[..10].eq_ignore_ascii_case("ALLOW-FROM") {
            let rest = xfo_val[10..].trim_start();
            if rest.is_empty() {
                return None; // malformed XFO, other rule will report
            }
            let allow_origin = if let Some(stripped) = rest.strip_suffix('/') {
                stripped
            } else {
                rest
            };

            // If CSP forbids all -> contradiction
            if csp_none {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("X-Frame-Options: ALLOW-FROM {} permits framing but Content-Security-Policy frame-ancestors is 'none'", rest),
                });
            }

            // If CSP has explicit origins, require the ALLOW-FROM origin to be present
            if !csp_origins.is_empty() {
                let mut matched = false;
                for o in &csp_origins {
                    if o.eq_ignore_ascii_case(allow_origin) {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    // Maybe CSP used 'self' and that matches server origin; compare to request origin
                    if csp_self {
                        // derive request origin
                        let req_origin = extract_origin_from_uri(&tx.request.uri);
                        if let Some(rorig) = req_origin {
                            if rorig.eq_ignore_ascii_case(allow_origin) {
                                return None; // matches self
                            }
                        }
                    }

                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("X-Frame-Options: ALLOW-FROM {} is not included in Content-Security-Policy frame-ancestors", rest),
                    });
                }
            }

            // if CSP only had 'self', check if ALLOW-FROM equals request origin
            if csp_self && csp_origins.is_empty() {
                let req_origin = extract_origin_from_uri(&tx.request.uri);
                if let Some(rorig) = req_origin {
                    if rorig.eq_ignore_ascii_case(allow_origin) {
                        return None;
                    } else {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("X-Frame-Options: ALLOW-FROM {} does not match Content-Security-Policy frame-ancestors 'self' (origin {})", rest, rorig),
                        });
                    }
                }
            }

            // Otherwise compatible
            return None;
        }

        // Unsupported XFO form -> ignore (other rule flags)
        None
    }
}

// Helper to derive origin from a request uri like "http://example/" -> "http://example"
fn extract_origin_from_uri(uri: &str) -> Option<String> {
    let s = uri.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(pos) = s.find("://") {
        let scheme = &s[..pos];
        let rest = &s[pos + 3..];
        let host_part = if let Some(idx) = rest.find('/') {
            &rest[..idx]
        } else {
            rest
        };
        if host_part.is_empty() {
            return None;
        }
        let mut origin = format!("{}://{}", scheme, host_part);
        if origin.ends_with('/') {
            origin.pop();
        }
        return Some(origin);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_cfg() -> crate::rules::RuleConfig {
        crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        }
    }

    #[rstest]
    #[case("frame-ancestors 'none'", "SAMEORIGIN", true)]
    #[case("frame-ancestors 'self'", "DENY", true)]
    #[case("frame-ancestors https://a", "ALLOW-FROM https://b", true)]
    #[case("frame-ancestors https://a https://b", "ALLOW-FROM https://b", false)]
    #[case("frame-ancestors 'none'", "DENY", false)]
    #[case("frame-ancestors 'self'", "ALLOW-FROM https://example", true)]
    fn consistency_cases(#[case] csp: &str, #[case] xfo: &str, #[case] expect_violation: bool) {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", csp),
            ("x-frame-options", xfo),
        ]);

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for csp='{}' xfo='{}'",
                csp,
                xfo
            );
        } else {
            assert!(
                v.is_none(),
                "unexpected violation {:?} for csp='{}' xfo='{}'",
                v,
                csp,
                xfo
            );
        }
    }

    #[test]
    fn non_utf8_headers_are_ignored_by_this_rule() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        // make a non-utf8 header value for XFO
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "frame-ancestors 'self'",
        )]);
        headers.insert("x-frame-options", bad);
        tx.response.as_mut().unwrap().headers = headers;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn mismatched_allow_from_vs_self_reports_violation() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        // request uri default origin from test is http://example
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'self'"),
            ("x-frame-options", "ALLOW-FROM https://example"),
        ]);

        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("does not match"));
    }

    #[test]
    fn scope_and_id_expected() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        assert_eq!(
            rule.id(),
            "message_content_security_policy_and_frame_options_consistency"
        );
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(
            &mut cfg,
            "message_content_security_policy_and_frame_options_consistency",
        );
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn multiple_csp_headers_handled() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // two CSP headers, one has frame-ancestors
        let headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "default-src 'self'"),
            ("content-security-policy", "frame-ancestors https://a"),
            ("x-frame-options", "ALLOW-FROM https://a"),
        ]);
        tx.response.as_mut().unwrap().headers = headers;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn malformed_frame_ancestors_no_members_is_ignored() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors"),
            ("x-frame-options", "DENY"),
        ]);
        // since the directive is malformed (no members) we treat as absent and no violation
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn multiple_xfo_headers_are_ignored() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://a"),
            ("x-frame-options", "DENY"),
        ]);
        // add a second XFO header to simulate duplicates
        headers.append("x-frame-options", "DENY".parse().unwrap());
        tx.response.as_mut().unwrap().headers = headers;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn allow_from_trailing_slash_matches_csp_origin() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://example"),
            ("x-frame-options", "ALLOW-FROM https://example/"),
        ]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn unsupported_xfo_form_is_ignored() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://example"),
            ("x-frame-options", "UNKNOWN https://example"),
        ]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn allow_from_matches_request_origin_with_self() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        // request uri default origin from test is http://example
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "http://example/path".into();
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'self'"),
            ("x-frame-options", "ALLOW-FROM http://example"),
        ]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn malformed_allow_from_is_ignored() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://a"),
            ("x-frame-options", "ALLOW-FROM"),
        ]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn allow_from_case_insensitive_match_with_csp_origin() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://EXample"),
            ("x-frame-options", "ALLOW-FROM https://example"),
        ]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn extract_origin_from_uri_various_cases() {
        assert_eq!(
            extract_origin_from_uri("http://example/"),
            Some("http://example".into())
        );
        assert_eq!(
            extract_origin_from_uri("https://example:8080/path"),
            Some("https://example:8080".into())
        );
        assert_eq!(extract_origin_from_uri("noscheme.com/path"), None);
        assert_eq!(extract_origin_from_uri(""), None);
    }

    #[test]
    fn csp_report_only_ignored() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            (
                "content-security-policy-report-only",
                "frame-ancestors 'none'",
            ),
            ("x-frame-options", "SAMEORIGIN"),
        ]);
        // report-only policies should not affect framing enforcement -> ignore
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn sameorigin_with_self_is_compatible() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'self'"),
            ("x-frame-options", "SAMEORIGIN"),
        ]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_csp_header_is_ignored() {
        let rule = MessageContentSecurityPolicyAndFrameOptionsConsistency;
        let cfg = make_cfg();

        // make a non-utf8 header value for CSP
        let bad = hyper::header::HeaderValue::from_bytes(&[0xff]).unwrap();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers =
            crate::test_helpers::make_headers_from_pairs(&[("x-frame-options", "DENY")]);
        headers.insert("content-security-policy", bad);
        tx.response.as_mut().unwrap().headers = headers;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }
}
