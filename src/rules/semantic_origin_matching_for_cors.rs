// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct SemanticOriginMatchingForCors;

impl Rule for SemanticOriginMatchingForCors {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "semantic_origin_matching_for_cors"
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
        let req = &tx.request;
        let headers = &req.headers;

        // Nothing to do if request did not include Origin header
        let origin = match crate::helpers::headers::get_header_str(headers, "origin") {
            Some(o) => o.trim(),
            None => return None,
        };

        // Validate origin syntax using shared helper (handles "null" and serialized origins).
        if let Some(reason) = crate::helpers::uri::validate_origin_value(origin) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!("Invalid Origin header value '{}': {}", origin, reason),
            });
        }

        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // Check for Access-Control-Allow-Origin header in response
        let mut acao_values: Vec<String> = Vec::new();
        for hv in resp.headers.get_all("access-control-allow-origin").iter() {
            match hv.to_str() {
                Ok(s) => acao_values.push(s.to_string()),
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Access-Control-Allow-Origin header contains non-ASCII or control characters".into(),
                    });
                }
            }
        }
        if acao_values.is_empty() {
            return None;
        }

        // Multiple header fields are not permitted; treat as violation early
        if acao_values.len() > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Access-Control-Allow-Origin header fields present; only a single value is allowed".into(),
            });
        }

        // Now we have exactly one header field; validate its value semantics
        let acao_raw = acao_values[0].trim();
        // Must be a single value (not a comma-separated list)
        let members: Vec<String> = crate::helpers::headers::parse_list_header(acao_raw)
            .map(|m| m.to_string())
            .collect();
        if members.len() != 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Access-Control-Allow-Origin must be a single value".into(),
            });
        }

        let acao_val = members.into_iter().next().unwrap().trim().to_string();

        // `*` is permitted only when credentials are not allowed
        if acao_val == "*" {
            if let Some(cred) = crate::helpers::headers::get_header_str(
                &resp.headers,
                "access-control-allow-credentials",
            ) {
                if cred.trim().eq_ignore_ascii_case("true") {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Access-Control-Allow-Origin '*' is not allowed when Access-Control-Allow-Credentials is true".into(),
                    });
                }
            }
            return None;
        }

        // For any other value, it must match the request's Origin header.
        // The only special case is the `null` origin, which should compare
        // case-insensitively per test expectations.  We normalise both sides to
        // lower-case "null" when either looks like it.
        let acao_norm = if acao_val.eq_ignore_ascii_case("null") {
            "null".to_string()
        } else {
            acao_val.clone()
        };
        let origin_norm = if origin.eq_ignore_ascii_case("null") {
            "null".to_string()
        } else {
            origin.to_string()
        };

        if acao_norm != origin_norm {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Access-Control-Allow-Origin '{}' does not match request Origin '{}'",
                    acao_val, origin
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

    use crate::test_helpers::{
        make_headers_from_pairs, make_test_rule_config, make_test_transaction,
        make_test_transaction_with_response,
    };

    #[rstest]
    fn no_origin_header_ignored() {
        let rule = SemanticOriginMatchingForCors;
        let tx = make_test_transaction_with_response(200, &[]);
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[rstest]
    fn no_acao_header_ignored() {
        let rule = SemanticOriginMatchingForCors;
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        // response has no ACAO
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[rstest]
    fn valid_matching_origin_ok() {
        let rule = SemanticOriginMatchingForCors;
        let mut tx = make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "https://example.com")],
        );
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[rstest]
    fn wildcard_without_credentials_ok() {
        let rule = SemanticOriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", "*")]);
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[rstest]
    fn wildcard_with_credentials_violation() {
        let rule = SemanticOriginMatchingForCors;
        let mut tx = make_test_transaction_with_response(
            200,
            &[
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "true"),
            ],
        );
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        let v = rule
            .check_transaction(&tx, None, &make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("'*' is not allowed"));
    }

    #[rstest]
    fn acao_mismatch_violation() {
        let rule = SemanticOriginMatchingForCors;
        let mut tx = make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "https://other.com")],
        );
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        let v = rule
            .check_transaction(&tx, None, &make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("does not match request Origin"));
    }

    #[rstest]
    fn origin_null_matches_null() {
        let rule = SemanticOriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", "null")]);
        tx.request.headers = make_headers_from_pairs(&[("origin", "null")]);
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[rstest]
    fn wildcard_with_credentials_case_insensitive_violation() {
        let rule = SemanticOriginMatchingForCors;
        let mut tx = make_test_transaction_with_response(
            200,
            &[
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "TRUE"),
            ],
        );
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://example.com")]);
        let v = rule
            .check_transaction(&tx, None, &make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("'*' is not allowed"));
    }

    #[rstest]
    fn acao_comma_list_violation() {
        let rule = SemanticOriginMatchingForCors;
        let mut tx = make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "https://a, https://b")],
        );
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://a")]);
        let v = rule
            .check_transaction(&tx, None, &make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("single value"));
    }

    #[rstest]
    fn multiple_header_fields_violation() {
        let rule = SemanticOriginMatchingForCors;
        let mut tx = make_test_transaction();
        tx.request.headers = make_headers_from_pairs(&[("origin", "https://a")]);
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "https://a")]);
        hdrs.append(
            "access-control-allow-origin",
            hyper::header::HeaderValue::from_static("https://b"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
            body_length: None,
        });
        let v = rule
            .check_transaction(&tx, None, &make_test_rule_config())
            .unwrap();
        assert!(v.message.contains("Multiple Access-Control-Allow-Origin"));
    }

    #[rstest]
    fn origin_null_case_insensitive_request_matches_null_response() {
        let rule = SemanticOriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", "null")]);
        tx.request.headers = make_headers_from_pairs(&[("origin", "NULL")]);
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }
    #[rstest]
    fn origin_null_case_insensitive_response_matches_null_request() {
        let rule = SemanticOriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", "NULL")]);
        tx.request.headers = make_headers_from_pairs(&[("origin", "null")]);
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }
    #[rstest]
    fn invalid_origin_header_violation() {
        let rule = SemanticOriginMatchingForCors;
        let mut tx =
            make_test_transaction_with_response(200, &[("access-control-allow-origin", "*")]);
        tx.request.headers = make_headers_from_pairs(&[("origin", "bad://")]);
        let v = rule
            .check_transaction(&tx, None, &make_test_rule_config())
            .unwrap();
        // The helper now returns a generic message for missing authority,
        // so we simply check for the word "Origin" to avoid brittle tests.
        assert!(v.message.contains("Origin"));
    }

    #[test]
    fn scope_is_server() {
        let rule = SemanticOriginMatchingForCors;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = SemanticOriginMatchingForCors;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "semantic_origin_matching_for_cors".into(),
            toml::Value::Table(table),
        );
        let _engine = rule.validate_and_box(&cfg)?;
        Ok(())
    }
}
