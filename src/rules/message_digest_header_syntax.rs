// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use base64::Engine;

pub struct MessageDigestHeaderSyntax;

impl Rule for MessageDigestHeaderSyntax {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_digest_header_syntax"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Shared parser for comma-separated key=value members
        let parse_key_value_members = |value: &str,
                                       empty_member_msg: &str,
                                       missing_eq_fmt: &str,
                                       empty_alg_fmt: &str|
         -> Result<Vec<(String, String)>, String> {
            let mut members = Vec::new();
            for member in value.split(',') {
                let m = member.trim();
                if m.is_empty() {
                    return Err(empty_member_msg.to_string());
                }
                match m.find('=') {
                    None => return Err(missing_eq_fmt.replace("{}", m)),
                    Some(eq) => {
                        let alg = m[..eq].trim();
                        let val = m[eq + 1..].trim();
                        if alg.is_empty() {
                            return Err(empty_alg_fmt.replace("{}", m));
                        }
                        members.push((alg.to_string(), val.to_string()));
                    }
                }
            }
            Ok(members)
        };

        // Shared parser for comma-separated token-only members (e.g., Want-Digest)
        let parse_token_list = |value: &str,
                                empty_member_msg: &str,
                                invalid_token_fmt: &str|
         -> Result<Vec<String>, String> {
            let mut members = Vec::new();
            for member in value.split(',') {
                let m = member.trim();
                if m.is_empty() {
                    return Err(empty_member_msg.to_string());
                }
                if let Some(c) = crate::helpers::token::find_invalid_token_char(m) {
                    return Err(invalid_token_fmt.replace("{}", &c.to_string()));
                }
                members.push(m.to_string());
            }
            Ok(members)
        };

        // Helper to validate legacy `Digest` header member value (alg=base64)
        let validate_legacy_digest = |value: &str| -> Option<String> {
            let members = match parse_key_value_members(
                value,
                "Digest header contains empty member",
                "Digest member '{}' missing '=' separator",
                "Digest member '{}' has empty algorithm",
            ) {
                Err(e) => return Some(e),
                Ok(m) => m,
            };

            for (alg, val) in members {
                if val.is_empty() {
                    return Some(format!("Digest member '{}' has empty value", alg));
                }

                // Algorithm must be a token
                if let Some(c) = crate::helpers::token::find_invalid_token_char(&alg) {
                    return Some(format!(
                        "Digest algorithm contains invalid character: '{}'",
                        c
                    ));
                }

                // Value must be valid base64
                let decoded = base64::engine::general_purpose::STANDARD.decode(&val);
                if decoded.is_err() {
                    return Some(format!(
                        "Digest value for algorithm '{}' is not valid base64",
                        alg
                    ));
                }
            }
            None
        };

        // Helper to validate new RFC 9530 fields (Content-Digest / Repr-Digest)
        // Structured-field dictionary syntax: alg=:base64:[, alg2=:base64:]
        let validate_structured_digest = |value: &str| -> Option<String> {
            let members = match parse_key_value_members(
                value,
                "Digest field contains empty member",
                "Digest member '{}' missing '=' separator",
                "Digest member '{}' has empty algorithm",
            ) {
                Err(e) => return Some(e),
                Ok(m) => m,
            };

            for (alg, val) in members {
                if let Some(c) = crate::helpers::token::find_invalid_token_char(&alg) {
                    return Some(format!(
                        "Digest algorithm contains invalid character: '{}'",
                        c
                    ));
                }

                // Value must be a byte sequence in the form :BASE64:
                if !(val.starts_with(':') && val.ends_with(':') && val.len() >= 3) {
                    return Some(format!(
                        "Digest member '{}={}' value must be a byte sequence like ':b64:'",
                        alg, val
                    ));
                }
                let inner = &val[1..val.len() - 1];
                if inner.is_empty() {
                    return Some(format!("Digest member '{}' has empty byte sequence", alg));
                }
                let decoded = base64::engine::general_purpose::STANDARD.decode(inner);
                if decoded.is_err() {
                    return Some(format!(
                        "Digest value for algorithm '{}' is not valid base64",
                        alg
                    ));
                }
            }
            None
        };

        // Helper to validate Want-Content-Digest / Want-Repr-Digest dictionaries
        // Syntax: alg=weight[, alg2=weight]
        let validate_want_field = |value: &str| -> Option<String> {
            let members = match parse_key_value_members(
                value,
                "Want-* header contains empty member",
                "Want member '{}' missing '=' separator",
                "Want member '{}' has empty algorithm",
            ) {
                Err(e) => return Some(e),
                Ok(m) => m,
            };

            for (alg, val) in members {
                if let Some(c) = crate::helpers::token::find_invalid_token_char(&alg) {
                    return Some(format!(
                        "Want-* algorithm contains invalid character: '{}'",
                        c
                    ));
                }

                // Weight must be integer 0..=10
                match val.parse::<i64>() {
                    Ok(n) => {
                        if !(0..=10).contains(&n) {
                            return Some(format!("Want-* weight '{}' out of range 0..=10", val));
                        }
                    }
                    Err(_) => return Some(format!("Want-* weight '{}' is not an integer", val)),
                }
            }
            None
        };

        // Helper to validate legacy Want-Digest header (comma-separated token list)
        let validate_want_digest = |value: &str| -> Option<String> {
            parse_token_list(
                value,
                "Want-Digest header contains empty member",
                "Want-Digest algorithm contains invalid character: '{}'",
            )
            .err()
        };

        // Check deprecated legacy headers and validate them (requests)
        if let Some(hv) = tx.request.headers.get_all("digest").iter().next() {
            if let Ok(s) = hv.to_str() {
                // First validate legacy syntax
                if let Some(msg) = validate_legacy_digest(s) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Invalid Digest header in request: {} (obsoleted by RFC 9530)",
                            msg
                        ),
                    });
                }

                // If syntax ok, report deprecation
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Digest header is obsoleted by RFC 9530; prefer Content-Digest or Repr-Digest".into(),
                });
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Digest header value is not valid UTF-8".into(),
                });
            }
        }

        // Check deprecated legacy Want-Digest header in requests
        if let Some(hv) = tx.request.headers.get_all("want-digest").iter().next() {
            if let Ok(s) = hv.to_str() {
                // Validate token list
                if let Some(msg) = validate_want_digest(s) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Invalid Want-Digest header in request: {} (obsoleted by RFC 9530)",
                            msg
                        ),
                    });
                }

                // If syntax ok, report deprecation
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Want-Digest header is obsoleted by RFC 9530; prefer Want-Content-Digest or Want-Repr-Digest".into(),
                });
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Want-Digest header value is not valid UTF-8".into(),
                });
            }
        }

        // Responses: check deprecated legacy 'Digest' header
        if let Some(resp) = &tx.response {
            if let Some(hv) = resp.headers.get_all("digest").iter().next() {
                if let Ok(s) = hv.to_str() {
                    if let Some(msg) = validate_legacy_digest(s) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid Digest header in response: {} (obsoleted by RFC 9530)",
                                msg
                            ),
                        });
                    }

                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Digest header is obsoleted by RFC 9530; prefer Content-Digest or Repr-Digest".into(),
                    });
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Digest header value is not valid UTF-8".into(),
                    });
                }
            }
        }

        // Validate new RFC 9530 integrity fields in requests
        for hv in tx.request.headers.get_all("content-digest").iter() {
            if let Ok(s) = hv.to_str() {
                if let Some(msg) = validate_structured_digest(s) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Invalid Content-Digest header in request: {} (RFC 9530 §2)",
                            msg
                        ),
                    });
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Digest header value is not valid UTF-8".into(),
                });
            }
        }

        for hv in tx.request.headers.get_all("repr-digest").iter() {
            if let Ok(s) = hv.to_str() {
                if let Some(msg) = validate_structured_digest(s) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Invalid Repr-Digest header in request: {} (RFC 9530 §3)",
                            msg
                        ),
                    });
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Repr-Digest header value is not valid UTF-8".into(),
                });
            }
        }

        // Validate integrity preference fields (Want-Content-Digest / Want-Repr-Digest)
        for hv in tx.request.headers.get_all("want-content-digest").iter() {
            if let Ok(s) = hv.to_str() {
                if let Some(msg) = validate_want_field(s) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Invalid Want-Content-Digest header in request: {} (RFC 9530 §4)",
                            msg
                        ),
                    });
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Want-Content-Digest header value is not valid UTF-8".into(),
                });
            }
        }

        for hv in tx.request.headers.get_all("want-repr-digest").iter() {
            if let Ok(s) = hv.to_str() {
                if let Some(msg) = validate_want_field(s) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Invalid Want-Repr-Digest header in request: {} (RFC 9530 §4)",
                            msg
                        ),
                    });
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Want-Repr-Digest header value is not valid UTF-8".into(),
                });
            }
        }

        // Validate new RFC 9530 integrity fields in responses
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("content-digest").iter() {
                if let Ok(s) = hv.to_str() {
                    if let Some(msg) = validate_structured_digest(s) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid Content-Digest header in response: {} (RFC 9530 §2)",
                                msg
                            ),
                        });
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Content-Digest header value is not valid UTF-8".into(),
                    });
                }
            }

            for hv in resp.headers.get_all("repr-digest").iter() {
                if let Ok(s) = hv.to_str() {
                    if let Some(msg) = validate_structured_digest(s) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid Repr-Digest header in response: {} (RFC 9530 §3)",
                                msg
                            ),
                        });
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Repr-Digest header value is not valid UTF-8".into(),
                    });
                }
            }

            for hv in resp.headers.get_all("want-content-digest").iter() {
                if let Ok(s) = hv.to_str() {
                    if let Some(msg) = validate_want_field(s) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid Want-Content-Digest header in response: {} (RFC 9530 §4)",
                                msg
                            ),
                        });
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Want-Content-Digest header value is not valid UTF-8".into(),
                    });
                }
            }

            for hv in resp.headers.get_all("want-repr-digest").iter() {
                if let Ok(s) = hv.to_str() {
                    if let Some(msg) = validate_want_field(s) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid Want-Repr-Digest header in response: {} (RFC 9530 §4)",
                                msg
                            ),
                        });
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Want-Repr-Digest header value is not valid UTF-8".into(),
                    });
                }
            }
        }

        // Deprecation: Content-MD5 header is deprecated; prefer Content-Digest
        if let Some(hv) = tx.request.headers.get_all("content-md5").iter().next() {
            if hv.to_str().is_ok() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "Content-MD5 header is deprecated; use Content-Digest instead (RFC 9530)"
                            .into(),
                });
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-MD5 header value is not valid UTF-8".into(),
                });
            }
        }

        if let Some(resp) = &tx.response {
            if let Some(hv) = resp.headers.get_all("content-md5").iter().next() {
                if hv.to_str().is_ok() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Content-MD5 header is deprecated; use Content-Digest instead (RFC 9530)".into(),
                    });
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Content-MD5 header value is not valid UTF-8".into(),
                    });
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

    fn make_req_digest(value: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("digest", value)]);
        tx
    }

    fn make_resp_digest(value: &str) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_response(200, &[("digest", value)])
    }

    fn make_req_want_digest(value: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("want-digest", value)]);
        tx
    }

    #[rstest]
    #[case("SHA-256", true)]
    #[case("SHA-256, SHA-512", true)]
    #[case("sha-256", true)]
    #[case("sha@1", true)]
    #[case("", true)]
    #[case("SHA-256,", true)]
    fn request_want_digest_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let rule = MessageDigestHeaderSyntax;
        let tx = make_req_want_digest(value);
        let cfg = crate::test_helpers::make_test_rule_config();

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
    }

    #[test]
    fn non_utf8_request_want_digest_is_violation() -> anyhow::Result<()> {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("want-digest", bad);
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn want_digest_deprecation_is_reported() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("want-digest", "SHA-256")]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("obsoleted") || msg.contains("prefer Want-Content-Digest"));
    }

    #[test]
    fn multiple_want_digest_header_fields_are_checked() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("want-digest", HeaderValue::from_static("SHA-256"));
        hm.append("want-digest", HeaderValue::from_static("sha-256"));
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_digest_header_syntax");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[rstest]
    #[case("SHA-256=YWJj", true)] // 'abc' -> YWJj
    #[case("SHA-256=YWJj, SHA-512=ZGVm", true)] // two members
    #[case("sha-256=YWJj", true)] // algorithm case is allowed as token (not enforced)
    #[case("SHA-256=not-base64!", true)]
    #[case("=YWJj", true)]
    #[case("SHA256", true)]
    #[case("", true)]
    #[case("SHA-256=", true)]
    #[case("SHA-256=Y WJj", true)]
    fn request_digest_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let rule = MessageDigestHeaderSyntax;
        let tx = make_req_digest(value);
        let cfg = crate::test_helpers::make_test_rule_config();

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
    }

    #[rstest]
    #[case("SHA-256=YWJj", true)]
    #[case("SHA-256=notbase64", true)]
    fn response_digest_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let rule = MessageDigestHeaderSyntax;
        let tx = make_resp_digest(value);
        let cfg = crate::test_helpers::make_test_rule_config();

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
    }

    #[test]
    fn empty_header_absent_returns_none() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction();
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_request_header_value_is_violation() -> anyhow::Result<()> {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("digest", bad);
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn non_utf8_response_header_value_is_violation() -> anyhow::Result<()> {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("digest", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
        });
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn algorithm_invalid_token_char_is_violation() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("digest", "SHA@1=YWJj")]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn legacy_digest_deprecation_is_reported() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("digest", "SHA-256=YWJj")]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("obsoleted") || msg.contains("prefer Content-Digest"));
    }

    #[test]
    fn content_digest_structured_syntax_valid() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-digest", "sha-256=:dGVzdA==:")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn content_digest_structured_syntax_invalid_base64() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-digest", "sha-256=:not-base64!:")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn want_content_digest_valid_weights() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-512=3, sha-256=10")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn want_content_digest_invalid_weight_is_violation() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-256=20")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn want_content_digest_in_request_invalid_weight_is_violation() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("want-content-digest", "sha-256=20".parse().unwrap());
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn content_md5_deprecation_is_reported() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-md5", "dGVzdA==")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        // Add a simple check that presence of header yields a violation via our rule: we will add handling next
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn repr_digest_structured_syntax_valid() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("repr-digest", "sha-256=:dGVzdA==:")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn repr_digest_structured_syntax_invalid_base64() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("repr-digest", "sha-256=:not-base64!:")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn repr_digest_structured_syntax_invalid_base64_in_request() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "repr-digest",
            "sha-256=:not-base64!:",
        )]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn want_repr_digest_valid_weights() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-repr-digest", "sha-512=0, sha-256=10")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn want_repr_digest_invalid_weight_is_violation() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-repr-digest", "sha-256=20")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn content_digest_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("content-digest", bad);
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn content_digest_multiple_fields_are_checked() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:dGVzdA==:"),
        );
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:not-base64!:"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn want_content_digest_non_integer_is_violation() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-256=abc")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn repr_digest_request_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("repr-digest", bad);
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn repr_digest_response_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("repr-digest", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn content_digest_response_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("content-digest", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn want_content_digest_missing_equals_is_violation() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-256")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn multiple_digest_header_fields_are_checked() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        // Construct headers with two digest fields: one valid, one invalid
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("digest", HeaderValue::from_static("SHA-256=YWJj"));
        hm.append("digest", HeaderValue::from_static("SHA-256=not-base64!"));
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    // Parametrized tests for structured digest fields (Content-Digest & Repr-Digest)
    #[rstest]
    #[case("content-digest", "sha-256=:dGVzdA==:", false)]
    #[case("content-digest", "sha-256=:not-base64!:", true)]
    #[case("content-digest", "sha-256=dGVzdA==", true)] // missing byte sequence colons
    #[case("content-digest", "sha-256=:", true)] // empty inner
    #[case("content-digest", "= :dGVzdA==:", true)] // missing alg
    #[case("content-digest", "sha@1=:dGVzdA==:", true)] // invalid alg token char
    #[case("repr-digest", "sha-256=:dGVzdA==:", false)]
    #[case("repr-digest", "sha-256=:not-base64!:", true)]
    fn structured_digest_cases(
        #[case] header: &str,
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[(header, value)]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for '{}: {}'",
                header,
                value
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}: {}'",
                header,
                value
            );
        }
    }

    // Non-UTF8 tests for structured digest and want headers
    #[test]
    fn content_digest_non_utf8_in_request_is_violation() -> anyhow::Result<()> {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("content-digest", bad);
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn want_content_digest_response_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("want-content-digest", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    // Non-UTF8 request tests for Want-* headers (parametrized)
    #[rstest]
    #[case("want-content-digest")]
    #[case("want-repr-digest")]
    fn want_field_request_non_utf8_is_violation(
        #[case] header: &'static str,
    ) -> anyhow::Result<()> {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append(header, bad);
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    // Parametrized tests for Want-* weights and invalid forms
    #[rstest]
    #[case("want-content-digest", "sha-512=3, sha-256=10", false)]
    #[case("want-content-digest", "sha-256=20", true)]
    #[case("want-content-digest", "sha-256=-1", true)]
    #[case("want-content-digest", "sha-256=abc", true)]
    #[case("want-content-digest", "sha@1=5", true)]
    #[case("want-repr-digest", "sha-512=0, sha-256=10", false)]
    #[case("want-repr-digest", "sha-256=11", true)]
    fn want_field_cases(#[case] header: &str, #[case] value: &str, #[case] expect_violation: bool) {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[(header, value)]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for '{}: {}'",
                header,
                value
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}: {}'",
                header,
                value
            );
        }
    }

    // Content-MD5 detection tests for both request and response
    #[test]
    fn content_md5_request_deprecation_is_reported() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-md5", "dGVzdA==")]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn content_md5_non_utf8_is_violation_in_request() -> anyhow::Result<()> {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("content-md5", bad);
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn content_md5_response_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("content-md5", bad);
        tx.response.as_mut().unwrap().headers = hm;

        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    // Combined header scenario: Digest (legacy) with Content-Digest — Digest should be reported first
    #[test]
    fn digest_and_content_digest_combined_reports_digest_deprecation() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("digest", HeaderValue::from_static("SHA-256=YWJj"));
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:dGVzdA==:"),
        );
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        // Since legacy Digest is checked first, we expect a violation about Digest being obsoleted
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("obsoleted") || msg.contains("prefer Content-Digest"));
    }

    // Edge-case tests: empty members, missing '=' in structured fields, trailing commas, and content-md5 response
    #[test]
    fn legacy_digest_empty_member_is_violation() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "digest",
            "SHA-256=YWJj,,SHA-512=ZGVm",
        )]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[rstest]
    #[case("content-digest", "sha-256:dGVzdA==:", true)] // missing '=' separator
    #[case("repr-digest", "sha-256:dGVzdA==:", true)]
    #[case("content-digest", "sha-256=:dGVzdA==:,", true)] // trailing comma -> empty member
    fn structured_digest_missing_equals_or_empty(
        #[case] header: &str,
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[(header, value)]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
    }

    #[test]
    fn content_digest_multiple_fields_in_request_are_checked() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:dGVzdA==:"),
        );
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:not-base64!:"),
        );
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn legacy_digest_trailing_comma_is_empty_member_violation() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("digest", "SHA-256=YWJj,")]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn header_name_case_insensitive_content_digest() {
        let rule = MessageDigestHeaderSyntax;
        // Use mixed-case header name to test case-insensitivity
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "Content-Digest",
            "sha-256=:dGVzdA==:",
        )]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn content_digest_multiple_valid_fields_request_and_response_checked() {
        let rule = MessageDigestHeaderSyntax;
        use hyper::header::HeaderValue;
        // Request: multiple valid content-digest fields
        let mut req = crate::test_helpers::make_test_transaction();
        let mut hm_req = crate::test_helpers::make_headers_from_pairs(&[]);
        hm_req.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:dGVzdA==:"),
        );
        hm_req.append(
            "content-digest",
            HeaderValue::from_static("sha-512=:dGVzdA==:"),
        );
        req.request.headers = hm_req;
        let cfg = crate::test_helpers::make_test_rule_config();
        let vreq = rule.check_transaction(&req, None, &cfg);
        assert!(vreq.is_none());

        // Response: multiple valid content-digest fields
        let mut resp_tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:dGVzdA==:"),
        );
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-512=:dGVzdA==:"),
        );
        resp_tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });
        let vresp = rule.check_transaction(&resp_tx, None, &cfg);
        assert!(vresp.is_none());
    }

    #[test]
    fn repr_digest_trims_spaces_and_is_valid() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("repr-digest", " sha-256 = :dGVzdA==: ")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn want_field_space_around_equals_accepted_and_missing_equals_in_multi_is_violation() {
        let rule = MessageDigestHeaderSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();

        // space around equals accepted
        let tx_ok = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-512 = 2")],
        );
        let v_ok = rule.check_transaction(&tx_ok, None, &cfg);
        assert!(v_ok.is_none());

        // missing equals in multi-members is a violation
        let tx_bad = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-512=3, sha-256")],
        );
        let v_bad = rule.check_transaction(&tx_bad, None, &cfg);
        assert!(v_bad.is_some());
        let msg = v_bad.unwrap().message;
        assert!(msg.contains("missing '=' separator") || msg.contains("not an integer"));
    }

    #[test]
    fn structured_digest_missing_equals_returns_meaningful_message() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-digest", "sha-256:dGVzdA==:")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Invalid Content-Digest header") && msg.contains("RFC 9530"));
    }

    #[test]
    fn want_field_empty_member_is_violation() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-256=3, ,sha-512=5")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn content_md5_response_deprecation_is_reported() {
        let rule = MessageDigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-md5", "dGVzdA==")],
        );
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn legacy_digest_trailing_comma_is_empty_member_violation_again() {
        let rule = MessageDigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("digest", "SHA-256=YWJj,")]);
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageDigestHeaderSyntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
