// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use std::collections::HashSet;

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentDispositionParameterValidity;

impl Rule for MessageContentDispositionParameterValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_content_disposition_parameter_validity"
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
        let check_value = |hdr_name: &str, val: &str| -> Option<Violation> {
            let s = val.trim();
            if s.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("{} header value must not be empty", hdr_name),
                });
            }

            let mut parts = s.splitn(2, ';');
            let dispo = parts.next().unwrap().trim();
            let params_part = parts.next().map(|p| p.trim()).unwrap_or("");

            if dispo.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("{} header disposition-type must not be empty", hdr_name),
                });
            }

            if params_part.is_empty() {
                return None;
            }

            // Track parameter names (case-insensitive) to detect duplicates
            let mut seen: HashSet<String> = HashSet::new();

            for p_raw in crate::helpers::headers::split_semicolons_respecting_quotes(params_part) {
                let p = p_raw.trim();
                if p.is_empty() {
                    continue;
                }
                let eq = p.find('=');
                if eq.is_none() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "{} has malformed parameter '{}': missing '='",
                            hdr_name, p
                        ),
                    });
                }
                let eq = eq.unwrap();
                let (name, value) = p.split_at(eq);
                let name = name.trim();
                let name_lc = name.to_ascii_lowercase();

                // Parameter names may be ext-token (token followed by '*')
                let is_ext = name_lc.ends_with('*');

                // Validate name token (allow trailing '*')
                let bare_name = if is_ext {
                    &name[..name.len() - 1]
                } else {
                    name
                };
                if bare_name.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("{} contains empty parameter name", hdr_name),
                    });
                }
                if let Some(c) = crate::helpers::token::find_invalid_token_char(bare_name) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "{} parameter name contains invalid token character: '{}'",
                            hdr_name, c
                        ),
                    });
                }

                // check duplicates (case-insensitive, include '*')
                if seen.contains(&name_lc) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("{} contains duplicate parameter: '{}'", hdr_name, name),
                    });
                }
                seen.insert(name_lc);

                let val = value[1..].trim(); // skip '='
                if val.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("{} parameter '{}' has empty value", hdr_name, name),
                    });
                }

                // Branch on certain well-known parameter names for stronger checks
                if !is_ext && name.eq_ignore_ascii_case("filename") {
                    // filename can be token or quoted-string
                    if val.starts_with('"') {
                        if let Err(e) = crate::helpers::headers::validate_quoted_string(val) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "{} filename parameter invalid quoted-string: {}",
                                    hdr_name, e
                                ),
                            });
                        }
                    } else if let Some(c) = crate::helpers::token::find_invalid_token_char(val) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "{} filename parameter contains invalid token character: '{}'",
                                hdr_name, c
                            ),
                        });
                    }
                } else if is_ext && name.eq_ignore_ascii_case("filename*") {
                    // ext-value (RFC 5987)
                    if let Err(e) = crate::helpers::headers::validate_ext_value(val) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "{} filename* extended value invalid: {}",
                                hdr_name, e
                            ),
                        });
                    }
                } else if name.eq_ignore_ascii_case("size") {
                    // allow token or quoted-string with digits only
                    let raw_val = if val.starts_with('"') {
                        match crate::helpers::headers::unescape_quoted_string(val) {
                            Ok(u) => u.trim().to_string(),
                            Err(e) => {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "{} size parameter invalid quoted-string: {}",
                                        hdr_name, e
                                    ),
                                })
                            }
                        }
                    } else {
                        val.to_string()
                    };

                    if !raw_val.chars().all(|c| c.is_ascii_digit()) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "{} size parameter must be numeric: '{}'",
                                hdr_name, raw_val
                            ),
                        });
                    }
                } else {
                    // Generic parameter: value should be token or quoted-string; ext-parameters already handled
                    if is_ext {
                        // extended parameter value must be ext-value
                        if let Err(e) = crate::helpers::headers::validate_ext_value(val) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "{} extended parameter '{}' invalid: {}",
                                    hdr_name, name, e
                                ),
                            });
                        }
                    } else if val.starts_with('"') {
                        if let Err(e) = crate::helpers::headers::validate_quoted_string(val) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "{} parameter '{}' invalid quoted-string: {}",
                                    hdr_name, name, e
                                ),
                            });
                        }
                    } else if let Some(c) = crate::helpers::token::find_invalid_token_char(val) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "{} parameter '{}' contains invalid token character: '{}'",
                                hdr_name, name, c
                            ),
                        });
                    }
                }
            }

            None
        };

        // Check in responses
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("content-disposition").iter() {
                if let Ok(s) = hv.to_str() {
                    if let Some(v) = check_value("Content-Disposition", s) {
                        return Some(v);
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Content-Disposition header value is not valid UTF-8".into(),
                    });
                }
            }
        }

        // Check in requests (multipart/form-data parts etc.)
        for hv in tx.request.headers.get_all("content-disposition").iter() {
            if let Ok(s) = hv.to_str() {
                if let Some(v) = check_value("Content-Disposition", s) {
                    return Some(v);
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Disposition header value is not valid UTF-8".into(),
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

    #[rstest]
    #[case(Some("attachment; filename=example.txt"), false)]
    #[case(Some("attachment; filename=\"a.txt\""), false)]
    #[case(Some("attachment; filename=\"a;b.txt\""), false)]
    #[case(Some("attachment; filename*=UTF-8''%e2%82%ac%20rates"), false)]
    #[case(Some("attachment; filename=example.txt; size=12345"), false)]
    #[case(
        Some("attachment; filename=example.txt; filename*=UTF-8''%e2%82%ac%20rates"),
        false
    )]
    #[case(Some("attachment; filename=example.txt; filename=other.txt"), true)]
    #[case(Some("attachment; filename*=UTF-8'%e2%82%ac"), true)]
    #[case(Some("attachment; size=12a"), true)]
    #[case(Some("attachment; bad@name=foo"), true)]
    #[case(Some("attachment; filename=\"unterminated"), true)]
    #[case(Some("attachment; badparam"), true)]
    #[case(Some("attachment; param=bad@val"), true)]
    #[case(Some("attachment; filename="), true)]
    #[case(
        Some("attachment; title*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates"),
        false
    )]
    #[case(
        Some("attachment; filename*=UTF-8''%e2%82%ac%20rates; filename*=UTF-8''%e2%82%ac%20rates"),
        true
    )]
    #[case(Some("   "), true)]
    #[case(Some("; filename=\"a\""), true)]
    #[case(Some("attachment; =value"), true)]
    #[case(Some("attachment; filename=a; FILENAME=other"), true)]
    #[case(Some("attachment; title*=UTF-8''hello@world"), true)]
    #[case(Some("attachment; *=value"), true)]
    #[case(Some("attachment; param=abc"), false)]
    #[case(Some("attachment; filename=bad@name"), true)]
    #[case(Some("attachment; filename*=UTF-8''%zz%20rates"), true)]
    #[case(Some("attachment; title*="), true)]
    #[case(Some("attachment"), false)]
    #[case(Some("attachment; size=\"123\""), false)]
    #[case(Some("attachment; x-title=\"abc\""), false)]
    fn response_cases(#[case] value: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = value {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-disposition", v)]);
        }

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let v = rule.check_transaction(&tx, None, &config);
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{:?}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{:?}'", value);
        }
    }

    #[test]
    fn request_header_checked() {
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "form-data; name=\"x\"; filename=example.png",
        )]);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_header_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-disposition", HeaderValue::from_bytes(&[0xff])?);
        tx.response.as_mut().unwrap().headers = hm;

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageContentDispositionParameterValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn generic_param_unterminated_quoted_reports_violation() {
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "attachment; param=\"unterminated",
        )]);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_some());
    }

    #[test]
    fn size_quoted_non_numeric_reports_violation() {
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "attachment; size=\"12a\"",
        )]);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_some());
    }

    #[test]
    fn request_non_utf8_header_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-disposition", HeaderValue::from_bytes(&[0xff])?);
        tx.request.headers = hm;

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_content_disposition_fields_are_checked() {
        use hyper::header::HeaderValue;
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append(
            "content-disposition",
            HeaderValue::from_static("attachment; filename=example.txt"),
        );
        hm.append(
            "content-disposition",
            HeaderValue::from_static("attachment; badparam"),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_some());
    }

    #[test]
    fn empty_param_is_ignored() {
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "attachment; ; filename=a",
        )]);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_none());
    }

    #[test]
    fn filename_star_empty_value_allowed() {
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "attachment; filename*=UTF-8''",
        )]);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_none());
    }

    #[test]
    fn generic_param_escaped_quote_in_quoted_string_is_valid() {
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "attachment; title=\"a\\\"b\"",
        )]);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_none());
    }

    #[test]
    fn filename_star_invalid_message_contains_reason() {
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "attachment; filename*=UTF-8''%zz",
        )]);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config).unwrap();
        assert!(v.message.contains("filename* extended value invalid"));
    }

    #[test]
    fn extended_param_invalid_message_contains_reason() {
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "attachment; title*=UTF-8''hello@world",
        )]);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config).unwrap();
        assert!(v.message.contains("extended parameter 'title*' invalid"));
    }

    #[test]
    fn size_quoted_invalid_quoted_string_reports_violation() {
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "attachment; size=\"unterminated",
        )]);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_some());
    }

    #[test]
    fn request_header_violation_is_reported() {
        let rule = MessageContentDispositionParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-disposition",
            "form-data; filename=bad@name",
        )]);
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_some());
    }
}
