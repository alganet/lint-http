// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct MessageTrailerHeadersValid;

impl Rule for MessageTrailerHeadersValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_trailer_headers_valid"
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
        // Cache Connection header nomination once for both request and response checks
        let connection_val =
            crate::helpers::headers::get_header_str(&tx.request.headers, "connection").or_else(
                || {
                    tx.response.as_ref().and_then(|r| {
                        crate::helpers::headers::get_header_str(&r.headers, "connection")
                    })
                },
            );

        // Helper to validate Trailer header(s) in a set of headers
        let check_headers = |hdrs: &hyper::HeaderMap| -> Option<Violation> {
            for hv in hdrs.get_all("trailer").iter() {
                let val = match hv.to_str() {
                    Ok(s) => s,
                    Err(_) => {
                        return Some(Violation {
                            rule: self.id().to_string(),
                            severity: config.severity,
                            message: "Trailer header value is not valid UTF-8".into(),
                        });
                    }
                };

                // Empty header value (or whitespace-only) is a violation
                if val.trim().is_empty() {
                    return Some(Violation {
                        rule: self.id().to_string(),
                        severity: config.severity,
                        message: "Trailer header contains empty member".into(),
                    });
                }

                for member in crate::helpers::headers::parse_list_header(val) {
                    if member.is_empty() {
                        return Some(Violation {
                            rule: self.id().to_string(),
                            severity: config.severity,
                            message: "Trailer header contains empty member".into(),
                        });
                    }

                    if let Some(ch) = crate::helpers::token::find_invalid_token_char(member) {
                        return Some(Violation {
                            rule: self.id().to_string(),
                            severity: config.severity,
                            message: format!(
                                "Trailer header contains invalid character '{}' in member '{}'",
                                ch, member
                            ),
                        });
                    }

                    if crate::helpers::headers::is_hop_by_hop_header(member, connection_val) {
                        return Some(Violation {
                            rule: self.id().to_string(),
                            severity: config.severity,
                            message: format!("Trailer header nominates hop-by-hop header '{}'; trailers must not be hop-by-hop headers", member),
                        });
                    }
                }
            }
            None
        };

        // Check request headers for Trailer
        if let Some(v) = check_headers(&tx.request.headers) {
            return Some(v);
        }

        // Check response headers for Trailer
        if let Some(resp) = &tx.response {
            if let Some(v) = check_headers(&resp.headers) {
                return Some(v);
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
    #[case("ETag, Expires", false)]
    #[case("My-Header", false)]
    #[case("Connection", true)]
    #[case("Transfer-Encoding", true)]
    #[case("bad token", true)]
    fn trailer_cases(
        #[case] trailer_val: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        // Response case
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("trailer", trailer_val)]);

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation but got none for '{}': {:?}",
                trailer_val,
                v
            );
        } else {
            assert!(
                v.is_none(),
                "expected no violation but got one for '{}': {:?}",
                trailer_val,
                v
            );
        }

        // Connection nominated token conflict
        if !expect_violation {
            // add a Connection header nominating a token that also appears in Trailer
            let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx2.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[
                    ("connection", "Keep-Alive"),
                    ("trailer", "Keep-Alive"),
                ]);
            let v2 = rule.check_transaction(&tx2, None, &cfg);
            assert!(
                v2.is_some(),
                "expected violation when Trailer nominates header listed in Connection"
            );
        }

        Ok(())
    }

    #[test]
    fn trailer_empty_member_is_violation() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("trailer", "")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn request_trailer_valid_is_ok() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("trailer", "ETag")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn request_trailer_invalid_token_reports_violation() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("trailer", "bad token")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn invalid_token_violation_message_includes_char_and_member() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("trailer", "bad token")]);
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("invalid character"));
        assert!(v.message.contains("bad token"));
        Ok(())
    }

    #[test]
    fn hop_by_hop_violation_message_includes_header_name() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("trailer", "Transfer-Encoding")]);
        let v = rule.check_transaction(&tx, None, &cfg).unwrap();
        assert!(v.message.contains("nominate") || v.message.contains("hop-by-hop"));
        assert!(v.message.contains("Transfer-Encoding"));
        Ok(())
    }

    #[test]
    fn request_trailer_connection_nominated_reports_violation() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("connection", "Keep-Alive"),
            ("trailer", "Keep-Alive"),
        ]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn non_utf8_trailer_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append("trailer", HeaderValue::from_bytes(&[0xff])?);
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn request_non_utf8_trailer_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.append("trailer", HeaderValue::from_bytes(&[0xff])?);
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn request_trailer_response_connection_nominated_reports_violation() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("connection", "Keep-Alive")]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("trailer", "Keep-Alive")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn request_trailer_lowercase_token_matches_connection_case_insensitive() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("connection", "Keep-Alive"),
            ("trailer", "keep-alive"),
        ]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn response_trailer_whitespace_only_is_violation() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("trailer", "   ")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn request_trailer_whitespace_only_is_violation() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("trailer", "   ")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_trailer_header_fields_iterated_reports_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append("trailer", HeaderValue::from_static("ETag"));
        hm.append("trailer", HeaderValue::from_static("bad token"));
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn trailer_nominates_trailer_itself_is_violation() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("trailer", "trailer")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageTrailerHeadersValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "message_trailer_headers_valid".into(),
            toml::Value::Table(table),
        );

        // validate_and_box should succeed without error
        let _config = rule.validate_and_box(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = MessageTrailerHeadersValid;
        assert_eq!(rule.id(), "message_trailer_headers_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
