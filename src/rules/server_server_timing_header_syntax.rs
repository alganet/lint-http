// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Server-Timing` header must follow the metric syntax:
/// `metric-name *( OWS ";" OWS server-timing-param )`
/// where `metric-name` and `server-timing-param` names are `token`s and
/// parameter values are `token` or `quoted-string`. The `dur` parameter
/// SHOULD parse as a floating-point value when present.
pub struct ServerServerTimingHeaderSyntax;

impl Rule for ServerServerTimingHeaderSyntax {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_server_timing_header_syntax"
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
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        for hv in resp.headers.get_all("Server-Timing").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Server-Timing header contains non-UTF8 value".into(),
                    })
                }
            };

            // detect empty metric tokens such as trailing commas or consecutive commas
            for raw in s.split(',') {
                if raw.trim().is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Server-Timing header contains empty metric (e.g., trailing or consecutive commas)".into(),
                    });
                }
            }

            for metric in crate::helpers::headers::parse_list_header(s) {
                // Metric has form: name *(";" param)
                let mut parts = metric.split(';');
                let name = parts.next().unwrap().trim();
                if name.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Server-Timing metric name is empty".into(),
                    });
                }

                if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Server-Timing metric name contains invalid token character: '{}'",
                            c
                        ),
                    });
                }

                use std::collections::HashSet;
                let mut seen_params = HashSet::new();

                for raw_param in parts {
                    let raw_param = raw_param.trim();
                    if raw_param.is_empty() {
                        // trailing semicolon or empty param — ignore per lenient parsing
                        continue;
                    }

                    // Must be name=value
                    let mut nv = raw_param.splitn(2, '=');
                    let pname = nv.next().unwrap().trim();
                    if pname.is_empty() {
                        // skip empty param names per spec guidance
                        continue;
                    }
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(pname) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Server-Timing parameter name contains invalid token character: '{}'",
                                c
                            ),
                        });
                    }

                    // Duplicate params: spec says ignore duplicates after first; treat as OK
                    if seen_params.contains(pname) {
                        continue;
                    }
                    seen_params.insert(pname.to_string());

                    let rhs = match nv.next() {
                        Some(r) => r.trim(),
                        None => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Server-Timing parameter '{}' missing '=' or value",
                                    pname
                                ),
                            })
                        }
                    };

                    if rhs.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Server-Timing parameter '{}' has empty value", pname),
                        });
                    }

                    // value can be token or quoted-string
                    if rhs.starts_with('"') {
                        if let Err(msg) = crate::helpers::headers::validate_quoted_string(rhs) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Server-Timing parameter '{}' quoted-string error: {}",
                                    pname, msg
                                ),
                            });
                        }

                        // If dur is quoted, try parsing the inside as float; tolerate quoted dur per lenient parsing
                        if pname.eq_ignore_ascii_case("dur") {
                            let inner = &rhs[1..rhs.len() - 1];
                            if inner.is_empty() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "Server-Timing 'dur' parameter has empty value".into(),
                                });
                            }
                            if inner.parse::<f64>().is_err() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Server-Timing 'dur' parameter is not a number: '{}'",
                                        inner
                                    ),
                                });
                            }
                        }
                    } else {
                        // token value
                        if let Some(c) = crate::helpers::token::find_invalid_token_char(rhs) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Server-Timing parameter value contains invalid token character: '{}'",
                                    c
                                ),
                            });
                        }

                        if pname.eq_ignore_ascii_case("dur") && rhs.parse::<f64>().is_err() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Server-Timing 'dur' parameter is not a number: '{}'",
                                    rhs
                                ),
                            });
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("miss, db;dur=53, app;dur=47.2"), false)]
    #[case(Some("cache;desc=\"Cache Read\";dur=23.2"), false)]
    #[case(Some("customView, dc;desc=atl"), false)]
    // quoted dur (valid)
    #[case(Some("db;dur=\"23.5\""), false)]
    // quoted dur empty
    #[case(Some("db;dur=\"\""), true)]
    // quoted dur not a number
    #[case(Some("db;dur=\"abc\""), true)]
    // duplicate params (second invalid) should be ignored
    #[case(Some("db;dur=50;dur=abc"), false)]
    // trailing semicolon ignored
    #[case(Some("db;dur=5;"), false)]
    // missing metric name (leading semicolon)
    #[case(Some(";dur=23"), true)]
    // bad metric token
    #[case(Some("b@d;dur=5"), true)]
    // bad param name
    #[case(Some("db;d@r=5"), true)]
    // dur not numeric
    #[case(Some("db;dur=abc"), true)]
    // unquoted param value with space (invalid token)
    #[case(Some("db;desc=Cache Read"), true)]
    // unterminated quoted-string
    #[case(Some("db;desc=\"unfinished"), true)]
    // param missing '=' or value
    #[case(Some("db;desc"), true)]
    // empty param name should be ignored
    #[case(Some("db;=5"), false)]
    // empty param (space) ignored
    #[case(Some("db; ;dur=5"), false)]
    // extra chars after terminating quoted-string
    #[case(Some("db;desc=\"abc\"x"), true)]
    // empty param value after '='
    #[case(Some("db;desc="), true)]
    // param value with invalid token char
    #[case(Some("db;desc=bad@value"), true)]
    // quoted-string with escaped quote is valid
    #[case(Some("db;desc=\"a\\\"b\""), false)]
    // detect empty metric tokens: leading, trailing, consecutive commas
    #[case(Some(",miss"), true)]
    #[case(Some("miss,"), true)]
    #[case(Some("miss,,db"), true)]
    // no Server-Timing header present
    #[case(None, false)]

    fn server_timing_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = ServerServerTimingHeaderSyntax;
        let tx = match header {
            Some(h) => crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("Server-Timing", h)],
            ),
            None => crate::test_helpers::make_test_transaction_with_response(200, &[]),
        };

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let v = rule.check_transaction(&tx, None, &config);
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
    }

    #[test]
    fn multiple_header_fields_merged() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = ServerServerTimingHeaderSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("Server-Timing", HeaderValue::from_static("miss, db;dur=53"));
        hm.append("Server-Timing", HeaderValue::from_static("app;dur=47.2"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = ServerServerTimingHeaderSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("Server-Timing", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("non-UTF8"));
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_server_timing_header_syntax");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn duplicate_params_are_ignored() {
        let rule = ServerServerTimingHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("Server-Timing", "db;dur=50;dur=abc")],
        );
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none(), "duplicate params should be ignored");
    }

    #[test]
    fn empty_param_name_is_ignored() {
        let rule = ServerServerTimingHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("Server-Timing", "db;=5")],
        );
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none(), "empty parameter name should be ignored");
    }

    #[test]
    fn quoted_string_extra_chars_reports_violation() {
        let rule = ServerServerTimingHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("Server-Timing", "db;desc=\"abc\"x")],
        );
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        // underlying helper reports a generic quoted-string problem
        assert!(
            msg.contains("Quoted-string not properly quoted")
                || msg.contains("Invalid characters after quoted-string")
        );
    }

    #[test]
    fn param_missing_equals_reports_violation() {
        let rule = ServerServerTimingHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("Server-Timing", "db;desc")],
        );
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("missing '=' or value"));
    }

    #[test]
    fn empty_param_value_reports_violation() {
        let rule = ServerServerTimingHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("Server-Timing", "db;desc=")],
        );
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("has empty value"));
    }

    #[test]
    fn param_value_invalid_token_char_reports_violation() {
        let rule = ServerServerTimingHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("Server-Timing", "db;desc=bad@value")],
        );
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("parameter value contains invalid token character"));
    }

    #[test]
    fn no_response_returns_none() {
        let rule = ServerServerTimingHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction();
        // tx.response is None
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    // Direct tests for quoted-string helper to exercise control chars and termination paths
    #[test]
    fn helper_quoted_string_control_char_reports_violation() {
        let s = "\"bad\x01str\"";
        let res = crate::helpers::headers::validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Control character"));
    }

    #[test]
    fn helper_quoted_string_unterminated_reports_violation() {
        let s = "\"unfinished";
        let res = crate::helpers::headers::validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Quoted-string not properly quoted"));
    }

    #[test]
    fn helper_quoted_string_extra_chars_reports_violation() {
        let s = "\"abc\"x";
        let res = crate::helpers::headers::validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Quoted-string not properly quoted"));
    }

    #[test]
    fn helper_quoted_string_with_escaped_quote_is_valid() {
        let s = "\"a\\\"b\""; // "a\"b"
        let res = crate::helpers::headers::validate_quoted_string(s);
        assert!(res.is_ok());
    }
}
