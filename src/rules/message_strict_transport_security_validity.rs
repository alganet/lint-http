// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageStrictTransportSecurityValidity;

impl Rule for MessageStrictTransportSecurityValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_strict_transport_security_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Only applicable to responses
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        for hv in resp.headers.get_all("strict-transport-security").iter() {
            let v = match hv.to_str() {
                Ok(s) => s.trim(),
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Strict-Transport-Security header contains non-UTF8 value".into(),
                    });
                }
            };

            if v.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Strict-Transport-Security header must not be empty".into(),
                });
            }

            let mut saw_max_age = false;
            let mut max_age_count = 0usize;

            for member in crate::helpers::headers::split_semicolons_respecting_quotes(v) {
                let member = member.trim();
                if member.is_empty() {
                    // skip stray semicolons but flag as violation
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Empty directive in Strict-Transport-Security header".into(),
                    });
                }

                // directive = token [ "=" token ]
                let mut kv = member.splitn(2, '=');
                let name = kv.next().unwrap().trim();
                if name.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Empty directive name in Strict-Transport-Security header".into(),
                    });
                }

                if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Strict-Transport-Security directive name contains invalid character: '{}'", c),
                    });
                }

                let lname = name.to_ascii_lowercase();
                match lname.as_str() {
                    "max-age" => {
                        max_age_count += 1;
                        saw_max_age = true;
                        // must have a value
                        if let Some(vpart) = kv.next() {
                            let vpart = vpart.trim();
                            if vpart.is_empty() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "Strict-Transport-Security 'max-age' must have a numeric value".into(),
                                });
                            }
                            if let Some(c) = crate::helpers::token::find_invalid_token_char(vpart) {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Strict-Transport-Security 'max-age' contains invalid character: '{}'", c),
                                });
                            }
                            if vpart.chars().any(|ch| !ch.is_ascii_digit()) {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "Strict-Transport-Security 'max-age' must be a non-negative integer".into(),
                                });
                            }
                            if vpart.parse::<u64>().is_err() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "Strict-Transport-Security 'max-age' value is not a valid integer".into(),
                                });
                            }
                        } else {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Strict-Transport-Security 'max-age' must have a value"
                                    .into(),
                            });
                        }
                    }
                    "includesubdomains" => {
                        // canonical name is includeSubDomains, but accept case-insensitively
                        // must NOT have a value
                        if kv.next().is_some() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Strict-Transport-Security 'includeSubDomains' directive must not have a value".into(),
                            });
                        }
                    }
                    "preload" => {
                        if kv.next().is_some() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Strict-Transport-Security 'preload' directive must not have a value".into(),
                            });
                        }
                    }
                    _ => {
                        // Unknown directives: allow but ensure if a value is present it is token or quoted-string
                        if let Some(vpart) = kv.next() {
                            let vpart = vpart.trim();
                            if vpart.starts_with('"') {
                                if let Err(e) =
                                    crate::helpers::headers::validate_quoted_string(vpart)
                                {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!("Invalid quoted-string in Strict-Transport-Security directive value: {}", e),
                                    });
                                }
                            } else if let Some(c) =
                                crate::helpers::token::find_invalid_token_char(vpart)
                            {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Strict-Transport-Security directive '{}' value contains invalid character: '{}'", name, c),
                                });
                            }
                        }
                    }
                }
            }

            if max_age_count > 1 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "Strict-Transport-Security MUST NOT contain multiple 'max-age' directives"
                            .into(),
                });
            }

            if !saw_max_age {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "Strict-Transport-Security header missing required 'max-age' directive"
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

    fn make_resp(val: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "strict-transport-security",
                val,
            )]),

            body_length: None,
        });
        tx
    }

    #[rstest]
    #[case("max-age=63072000", false)]
    #[case("max-age=0", false)]
    #[case("max-age=63072000; includeSubDomains; preload", false)]
    #[case("includeSubDomains", true)]
    #[case("max-age=abc", true)]
    #[case("max-age=63072000; includeSubDomains=1", true)]
    #[case("max-age=63072000; preload=1", true)]
    #[case("max-age=63072000; max-age=1", true)]
    fn cases(#[case] val: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = MessageStrictTransportSecurityValidity;
        let tx = make_resp(val);
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let got = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .is_some();
        assert_eq!(got, expect_violation, "value: {}", val);
        Ok(())
    }

    #[test]
    fn non_utf8_header_is_violation() {
        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.append(
            "strict-transport-security",
            HeaderValue::from_bytes(b"max-age=1\xFF" as &[u8]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers,

            body_length: None,
        });
        let rule = MessageStrictTransportSecurityValidity;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());
    }

    #[test]
    fn empty_value_is_violation() {
        let rule = MessageStrictTransportSecurityValidity;
        let tx = make_resp("");
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());
    }

    #[test]
    fn trailing_semicolon_reports_empty_directive() {
        let rule = MessageStrictTransportSecurityValidity;
        let tx = make_resp("max-age=1;");
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());
    }

    #[test]
    fn unknown_directive_with_bad_quoted_string_reports_violation() {
        let rule = MessageStrictTransportSecurityValidity;
        let tx = make_resp("max-age=1; foo=\"unterminated");
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());
    }

    #[test]
    fn unknown_directive_with_invalid_token_value_reports_violation() {
        let rule = MessageStrictTransportSecurityValidity;
        let tx = make_resp("max-age=1; bar=bad@val");
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());
    }

    #[test]
    fn unknown_directive_with_quoted_string_is_ok() {
        let rule = MessageStrictTransportSecurityValidity;
        let tx = make_resp("max-age=1; foo=\"valid\"");
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[test]
    fn max_age_empty_value_is_violation() {
        let rule = MessageStrictTransportSecurityValidity;
        let tx = make_resp("max-age=");
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());
    }

    #[test]
    fn max_age_without_equals_is_violation() {
        let rule = MessageStrictTransportSecurityValidity;
        let tx = make_resp("max-age");
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());
    }

    #[test]
    fn max_age_quoted_is_violation() {
        let rule = MessageStrictTransportSecurityValidity;
        let tx = make_resp("max-age=\"3600\"");
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());
    }

    #[test]
    fn directive_name_with_invalid_char_is_violation() {
        let rule = MessageStrictTransportSecurityValidity;
        let tx = make_resp("ma x=1");
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());
    }

    #[test]
    fn unknown_directive_with_token_value_is_ok() {
        let rule = MessageStrictTransportSecurityValidity;
        let tx = make_resp("max-age=1; foo=bar");
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[test]
    fn include_subdomains_case_insensitive_is_ok() {
        let rule = MessageStrictTransportSecurityValidity;
        let tx = make_resp("max-age=1; IncludeSubDomains");
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[test]
    fn multiple_header_fields_one_invalid_reports_violation() {
        // two header fields: one valid, one missing max-age
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[
                ("strict-transport-security", "max-age=1"),
                ("strict-transport-security", "includeSubDomains"),
            ]),

            body_length: None,
        });
        let rule = MessageStrictTransportSecurityValidity;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_strict_transport_security_validity");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
