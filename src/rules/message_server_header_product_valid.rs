// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageServerHeaderProductValid;

impl Rule for MessageServerHeaderProductValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_server_header_product_valid"
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
        let check_value = |hdr: &str, val: &str| -> Option<Violation> {
            // Strip top-level parenthesized comments (allowed in Server values)
            let no_comments = match crate::helpers::headers::strip_comments(val) {
                Ok(s) => s,
                Err(e) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid {} header: {}", hdr, e),
                    })
                }
            };

            if no_comments.trim().is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("{} header is empty or contains only comments", hdr),
                });
            }

            // product *( RWS ( product / comment ) ) — after stripping comments we expect whitespace-separated products
            for part in no_comments.split_whitespace() {
                // product = token ["/" product-version]
                let mut pieces = part.splitn(2, '/');
                let prod = pieces.next().unwrap();
                if prod.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("{} header contains empty product token", hdr),
                    });
                }
                if let Some(c) = crate::helpers::token::find_invalid_token_char(prod) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "{} product token contains invalid character: '{}'",
                            hdr, c
                        ),
                    });
                }
                if let Some(ver) = pieces.next() {
                    if ver.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("{} product contains empty version", hdr),
                        });
                    }
                    if ver.contains('/') {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("{} product version contains unexpected '/'", hdr),
                        });
                    }
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(ver) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "{} product version contains invalid character: '{}'",
                                hdr, c
                            ),
                        });
                    }
                }
            }

            None
        };

        // Only validate response `Server` headers
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("server").iter() {
                if hv.to_str().is_err() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Server header contains non-UTF8 value".into(),
                    });
                }
                let s = hv.to_str().unwrap();
                if let Some(v) = check_value("Server", s) {
                    return Some(v);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case(Some("nginx/1.18.0"), false)]
    #[case(Some("nginx"), false)]
    #[case(Some("Apache/2.4.41 (Ubuntu)"), false)]
    #[case(Some("MySrv/1.0 Another/2.0"), false)]
    #[case(Some("/1.0"), true)]
    #[case(Some("Bad@Srv/1.0"), true)]
    #[case(Some("Srv/1@0"), true)]
    #[case(Some("Srv//1.0"), true)]
    #[case(None, false)]
    fn check_server_header_response(
        #[case] server: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut resp = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = server {
            resp.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("server", v)]);
        }
        tx.response = resp.response;

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn multiple_server_fields_checked() -> anyhow::Result<()> {
        let rule = MessageServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut hm = crate::test_helpers::make_headers_from_pairs(&[("server", "nginx/1.18.0")]);
        hm.append("server", HeaderValue::from_static("Bad@Srv/1.0"));
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn non_utf8_header_value_is_reported() -> anyhow::Result<()> {
        let rule = MessageServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("server", HeaderValue::from_bytes(b"\xff").unwrap());
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn unterminated_comment_reports_violation() -> anyhow::Result<()> {
        let rule = MessageServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("server", "Bad (unbalanced")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn server_only_comments_is_reported() -> anyhow::Result<()> {
        let rule = MessageServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("server", "(Apache)")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn comment_before_product_is_accepted() -> anyhow::Result<()> {
        let rule = MessageServerHeaderProductValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("server", "(test) nginx/1.18.0")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_server_header_product_valid");
        let _ = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
