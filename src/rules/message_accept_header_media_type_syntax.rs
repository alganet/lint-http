// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAcceptHeaderMediaTypeSyntax;

impl Rule for MessageAcceptHeaderMediaTypeSyntax {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_accept_header_media_type_syntax"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Validate a single Accept-like header value (media-range list)
        let check_val = |hdr: &str, val: &str| -> Option<Violation> {
            for member in crate::helpers::headers::parse_list_header(val) {
                // Split token and params
                let mut parts = member.split(';').map(|s| s.trim());
                let media = parts.next().unwrap_or("").trim();
                if media.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Empty media-range in {} header", hdr),
                    });
                }

                // Accept allows "*/*", "type/*" or "type/subtype" only. A bare "*" is invalid.
                if media == "*" {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid media-range '*' in {} header", hdr),
                    });
                }

                if media == "*/*" {
                    // wildcard is valid, but still validate params
                } else {
                    // must contain '/'
                    if !media.contains('/') {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid media-range '{}' in {} header: missing '/'",
                                media, hdr
                            ),
                        });
                    }

                    if let Ok(parsed) = crate::helpers::headers::parse_media_type(media) {
                        // validate type and subtype tokens (allow '*' as subtype)
                        if let Some(c) =
                            crate::helpers::token::find_invalid_token_char(parsed.type_)
                        {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid token '{}' in media type '{}' of {}",
                                    c, parsed.type_, hdr
                                ),
                            });
                        }
                        if parsed.subtype != "*" {
                            if let Some(c) =
                                crate::helpers::token::find_invalid_token_char(parsed.subtype)
                            {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid token '{}' in media subtype '{}' of {}",
                                        c, parsed.subtype, hdr
                                    ),
                                });
                            }
                        }
                    } else {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid media-range '{}' in {} header", media, hdr),
                        });
                    }
                }

                // Validate parameters (name=value). 'q' must be a valid qvalue
                for p in parts {
                    if p.is_empty() {
                        continue;
                    }
                    let mut kv = p.splitn(2, '=');
                    let k = kv.next().unwrap().trim();
                    let v = kv.next();
                    if v.is_none() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid parameter '{}' in {} header: missing '='",
                                p, hdr
                            ),
                        });
                    }
                    let v = v.unwrap().trim();
                    // Parameter name must be a token
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(k) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid character '{}' in parameter name '{}' in {} header",
                                c, k, hdr
                            ),
                        });
                    }

                    if k.eq_ignore_ascii_case("q") {
                        if !crate::helpers::headers::valid_qvalue(v) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Invalid qvalue '{}' in {} header", v, hdr),
                            });
                        }
                    } else {
                        // value may be token or quoted-string
                        if v.starts_with('"') {
                            if let Err(e) = crate::helpers::headers::validate_quoted_string(v) {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid quoted-string parameter '{}' in {} header: {}",
                                        p, hdr, e
                                    ),
                                });
                            }
                        } else if let Some(c) = crate::helpers::token::find_invalid_token_char(v) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid token '{}' in parameter value '{}' of {} header",
                                    c, v, hdr
                                ),
                            });
                        }
                    }
                }
            }
            None
        };

        // Check request Accept header
        if let Some(val) = crate::helpers::headers::get_header_str(&tx.request.headers, "accept") {
            if let Some(v) = check_val("Accept", val) {
                return Some(v);
            }
        }

        // Also conservatively check Accept echoed in responses
        if let Some(resp) = &tx.response {
            if let Some(val) = crate::helpers::headers::get_header_str(&resp.headers, "accept") {
                if let Some(v) = check_val("Accept", val) {
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
    use rstest::rstest;

    #[rstest]
    #[case(Some("text/html"), false)]
    #[case(Some("text/*;q=0.8, application/json;q=0.9"), false)]
    #[case(Some("*/*;q=0.1"), false)]
    #[case(Some("application/json; charset=utf-8"), false)]
    #[case(Some("type/*;q=0.5"), false)]
    #[case(Some("text/html; param=token-with-hyphen"), false)]
    #[case(Some("text/html; param=\"ok\""), false)]
    #[case(Some("text/html; param=\"a\\\"b\""), false)]
    #[case(Some("text/*; param=\"ok\""), false)]
    #[case(Some("*"), true)]
    #[case(Some("text; q=0.8"), true)]
    #[case(Some("text/html; q=1.0000"), true)]
    #[case(Some("*/*; q=1.0000"), true)]
    #[case(Some("text/; q=0.8"), true)]
    #[case(Some("te@xt/html"), true)]
    #[case(Some("text/ht@ml"), true)]
    #[case(Some("text/html; charset"), true)]
    #[case(Some("text/html; param=\"unterminated"), true)]
    #[case(Some("text/html; bad name=value"), true)]
    #[case(Some("application/json; charset=bad@"), true)]
    #[case(None, false)]
    fn check_accept_request(
        #[case] accept: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageAcceptHeaderMediaTypeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = accept {
            // Some test cases include control characters; construct header value from bytes in that case
            if v.chars()
                .any(|c| c == '\x01' || c == '\x7f' || c.is_control())
            {
                let mut hm = hyper::HeaderMap::new();
                let hv = hyper::header::HeaderValue::from_bytes(v.as_bytes())
                    .expect("should construct non-utf8 header");
                hm.insert("accept", hv);
                tx.request.headers = hm;
            } else {
                tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("accept", v)]);
            }
        }

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = MessageAcceptHeaderMediaTypeSyntax;
        assert_eq!(rule.id(), "message_accept_header_media_type_syntax");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_header_media_type_syntax",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn check_accept_in_response() -> anyhow::Result<()> {
        let rule = MessageAcceptHeaderMediaTypeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "text/html; q=1.0000")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }
}
