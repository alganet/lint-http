// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAccessControlAllowCredentialsWhenOrigin;

impl Rule for MessageAccessControlAllowCredentialsWhenOrigin {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_access_control_allow_credentials_when_origin"
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

        let headers = &resp.headers;

        // If there is no Access-Control-Allow-Origin header, nothing to check
        let acao_count = headers
            .get_all("access-control-allow-origin")
            .iter()
            .count();
        if acao_count == 0 {
            return None;
        }

        // Validate Access-Control-Allow-Origin header values (ensure UTF-8, and detect any '*')
        let mut acao_has_star = false;
        for hv in headers.get_all("access-control-allow-origin").iter() {
            let s = match hv.to_str() {
                Ok(v) => v.trim(),
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Access-Control-Allow-Origin header contains non-ASCII or control characters".into(),
                    })
                }
            };
            for token in crate::helpers::headers::parse_list_header(s) {
                if token == "*" {
                    acao_has_star = true;
                    break;
                }
            }
            if acao_has_star {
                break;
            }
        }

        let acc_count = headers
            .get_all("access-control-allow-credentials")
            .iter()
            .count();
        if acc_count == 0 {
            return None; // nothing to check
        }

        let acc_val = match crate::helpers::headers::get_header_str(headers, "access-control-allow-credentials") {
            Some(v) => v.trim(),
            None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Access-Control-Allow-Credentials header contains non-ASCII or control characters".into(),
                })
            }
        };

        // If credentials is 'true' (case-insensitive) and any AC-Allow-Origin header contains '*', violation
        if acc_val.eq_ignore_ascii_case("true") && acao_has_star {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Access-Control-Allow-Credentials must not be 'true' when Access-Control-Allow-Origin is '*'".into(),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::{make_test_rule_config, make_test_transaction};

    #[rstest]
    #[case(Some("*"), Some("true"), true)]
    #[case(Some("*"), Some("false"), false)]
    #[case(Some("https://a.example"), Some("true"), false)]
    #[case(Some("https://a.example"), None, false)]
    #[case(Some("https://a.example, *"), Some("true"), true)]
    fn check_acl_credentials_cases(
        #[case] acao: Option<&str>,
        #[case] acc: Option<&str>,
        #[case] expect_violation: bool,
    ) {
        let rule = MessageAccessControlAllowCredentialsWhenOrigin;
        let mut tx = make_test_transaction();
        let mut pairs = vec![];
        if let Some(a) = acao {
            pairs.push(("access-control-allow-origin", a));
        }
        if let Some(c) = acc {
            pairs.push(("access-control-allow-credentials", c));
        }
        if !pairs.is_empty() {
            tx = crate::test_helpers::make_test_transaction_with_response(200, &pairs);
        }

        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        if expect_violation {
            assert!(v.is_some(), "expected violation for {:?} & {:?}", acao, acc);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for {:?} & {:?}: got {:?}",
                acao,
                acc,
                v
            );
        }
    }

    #[test]
    fn non_utf8_acao_is_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageAccessControlAllowCredentialsWhenOrigin;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "*")]);
        hdrs.insert(
            "access-control-allow-origin",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn non_utf8_acc_is_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageAccessControlAllowCredentialsWhenOrigin;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "*")]);
        hdrs.insert(
            "access-control-allow-credentials",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,
            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn no_response_no_violation() {
        let rule = MessageAccessControlAllowCredentialsWhenOrigin;
        let tx = make_test_transaction();
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn credentials_header_without_origin_returns_none() {
        let rule = MessageAccessControlAllowCredentialsWhenOrigin;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-credentials", "true")],
        );
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn multiple_origins_without_star_and_credentials_true_ok() {
        let rule = MessageAccessControlAllowCredentialsWhenOrigin;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("access-control-allow-origin", "https://a, https://b"),
                ("access-control-allow-credentials", "true"),
            ],
        );
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn star_with_uppercase_true_is_violation() {
        let rule = MessageAccessControlAllowCredentialsWhenOrigin;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "TRUE"),
            ],
        );
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn star_with_whitespace_true_is_violation() {
        let rule = MessageAccessControlAllowCredentialsWhenOrigin;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "  true  "),
            ],
        );
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn acao_with_trailing_commas_and_star_is_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageAccessControlAllowCredentialsWhenOrigin;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "https://a")]);
        // append separate header value containing '*'
        hdrs.append("access-control-allow-origin", HeaderValue::from_static("*"));
        hdrs.insert(
            "access-control-allow-credentials",
            HeaderValue::from_static("true"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn acao_star_with_non_true_credentials_not_violation() {
        let rule = MessageAccessControlAllowCredentialsWhenOrigin;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "1"),
            ],
        );
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageAccessControlAllowCredentialsWhenOrigin;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageAccessControlAllowCredentialsWhenOrigin;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "message_access_control_allow_credentials_when_origin".into(),
            toml::Value::Table(table),
        );

        // validate_and_box should succeed without error
        let _config = rule.validate_and_box(&cfg)?;
        Ok(())
    }
}
