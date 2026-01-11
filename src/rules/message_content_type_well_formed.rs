// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentTypeWellFormed;

impl Rule for MessageContentTypeWellFormed {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_content_type_well_formed"
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
        // Check request Content-Type
        if let Some(hv) = tx.request.headers.get("content-type") {
            if let Ok(s) = hv.to_str() {
                if let Some(v) = check_content_type("request", s, config) {
                    return Some(v);
                }
            }
        }

        // Check response Content-Type
        if let Some(resp) = &tx.response {
            if let Some(hv) = resp.headers.get("content-type") {
                if let Ok(s) = hv.to_str() {
                    if let Some(v) = check_content_type("response", s, config) {
                        return Some(v);
                    }
                }
            }
        }

        None
    }
}

fn check_content_type(
    _which: &str,
    val: &str,
    config: &crate::rules::RuleConfig,
) -> Option<Violation> {
    use crate::helpers::headers::parse_media_type;

    let parsed = match parse_media_type(val) {
        Ok(p) => p,
        Err(msg) => {
            let message = if msg == "Empty media-type" {
                "Empty Content-Type header".into()
            } else {
                msg.replace("media-type", "Content-Type")
            };
            return Some(Violation {
                rule: MessageContentTypeWellFormed.id().into(),
                severity: config.severity,
                message,
            });
        }
    };

    // Wildcards are not valid in Content-Type (they are for Accept)
    if parsed.type_ == "*" || parsed.subtype == "*" {
        return Some(Violation {
            rule: MessageContentTypeWellFormed.id().into(),
            severity: config.severity,
            message: format!(
                "Invalid Content-Type '{}': wildcard '*' not allowed in type/subtype",
                val
            ),
        });
    }

    // Validate tokens for type and subtype
    if let Some(c) = crate::helpers::token::find_invalid_token_char(parsed.type_) {
        return Some(Violation {
            rule: MessageContentTypeWellFormed.id().into(),
            severity: config.severity,
            message: format!(
                "Invalid Content-Type '{}': invalid character '{}' in type",
                val, c
            ),
        });
    }

    if let Some(c) = crate::helpers::token::find_invalid_token_char(parsed.subtype) {
        return Some(Violation {
            rule: MessageContentTypeWellFormed.id().into(),
            severity: config.severity,
            message: format!(
                "Invalid Content-Type '{}': invalid character '{}' in subtype",
                val, c
            ),
        });
    }

    // If parameters exist, do a basic validation: name=value pairs, name token, value token or quoted-string
    if let Some(params) = parsed.params {
        for raw in params.split(';') {
            let p = raw.trim();
            if p.is_empty() {
                continue;
            }
            if let Some(eq) = p.find('=') {
                let (name, value) = p.split_at(eq);
                let name = name.trim();
                let value = value[1..].trim(); // skip '='
                if name.is_empty() {
                    return Some(Violation {
                        rule: MessageContentTypeWellFormed.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Content-Type '{}': empty parameter name", val),
                    });
                }
                if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
                    return Some(Violation {
                        rule: MessageContentTypeWellFormed.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Content-Type '{}': invalid character '{}' in parameter name '{}'", val, c, name),
                    });
                }
                if value.starts_with('"') {
                    if !value.ends_with('"') || value.len() < 2 {
                        return Some(Violation {
                            rule: MessageContentTypeWellFormed.id().into(),
                            severity: config.severity,
                            message: format!("Invalid Content-Type '{}': parameter '{}' has unterminated quoted-string", val, name),
                        });
                    }
                    // We won't validate quoted-string contents further here
                } else {
                    // must be a token
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(value) {
                        return Some(Violation {
                            rule: MessageContentTypeWellFormed.id().into(),
                            severity: config.severity,
                            message: format!("Invalid Content-Type '{}': invalid character '{}' in parameter value '{}'", val, c, value),
                        });
                    }
                }
            } else {
                return Some(Violation {
                    rule: MessageContentTypeWellFormed.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Invalid Content-Type '{}': parameter '{}' missing '='",
                        val, p
                    ),
                });
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("text/plain", false)]
    #[case("application/json", false)]
    #[case("application/json; charset=utf-8", false)]
    #[case("text/html; charset=\"utf-8\"", false)]
    #[case("image/vnd.example+json; charset=utf-8; foo=bar", false)]
    #[case("text", true)]
    #[case("text/", true)]
    #[case("/plain", true)]
    #[case("*/plain", true)]
    #[case("text/*", true)]
    #[case("text/plain; badparam", true)]
    #[case("text/plain;=value", true)]
    #[case("text/plain; charset=utf 8", true)]
    #[case("text/plain; charset=\"unclosed", true)]
    fn content_type_parsing_cases(#[case] val: &str, #[case] expect_violation: bool) {
        let cfg = crate::test_helpers::make_test_rule_config();
        let res = super::check_content_type("test", val, &cfg);
        if expect_violation {
            assert!(res.is_some(), "expected violation for '{}'", val);
        } else {
            assert!(
                res.is_none(),
                "unexpected violation for '{}': {:?}",
                val,
                res
            );
        }
    }

    #[rstest]
    #[case("te@xt/plain", true)]
    #[case("text/pl@in", true)]
    #[case("text/plain; bad@=v", true)]
    #[case("", true)]
    #[case("text/plain; charset=utf-8;", false)]
    #[case("text/plain; foo=bar baz", true)]
    fn extra_content_type_cases(#[case] val: &str, #[case] expect_violation: bool) {
        let cfg = crate::test_helpers::make_test_rule_config();
        let res = super::check_content_type("test", val, &cfg);
        if expect_violation {
            assert!(res.is_some(), "expected violation for '{}'", val);
        } else {
            assert!(
                res.is_none(),
                "unexpected violation for '{}': {:?}",
                val,
                res
            );
        }
    }

    #[rstest]
    fn request_and_response_integration() -> anyhow::Result<()> {
        let rule = MessageContentTypeWellFormed;
        let cfg = crate::test_helpers::make_test_rule_config();

        // request invalid
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text")]);
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());

        // response invalid
        let tx2 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text")],
        );
        let v2 = rule.check_transaction(&tx2, None, &cfg);
        assert!(v2.is_some());

        // both valid
        let mut tx3 = crate::test_helpers::make_test_transaction();
        tx3.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset=utf-8",
        )]);
        let tx4 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/json")],
        );
        let v3 = rule.check_transaction(&tx3, None, &cfg);
        let v4 = rule.check_transaction(&tx4, None, &cfg);
        assert!(v3.is_none());
        assert!(v4.is_none());

        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageContentTypeWellFormed;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
