// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageLinkHeaderValidity;

impl Rule for MessageLinkHeaderValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_link_header_validity"
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
        // Only check response headers (Link is meaningful on responses / 103 Early Hints)
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        for hv in resp.headers.get_all("link").iter() {
            let val = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Link header contains non-UTF8 value".into(),
                    })
                }
            };

            // Detect empty members such as trailing or consecutive commas
            for raw in val.split(',') {
                if raw.trim().is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message:
                            "Link header contains empty member (trailing or consecutive commas)"
                                .into(),
                    });
                }
            }

            for member in crate::helpers::headers::parse_list_header(val) {
                let m = member.trim();

                // Expect <URI-reference> at start
                if !m.starts_with('<') {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Link member missing '<uri>' at start".into(),
                    });
                }
                let close_pos = m.find('>').unwrap_or(0);
                if close_pos == 0 {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Link member missing closing '>' for URI".into(),
                    });
                }

                // Extract params after the URI
                let params = m[close_pos + 1..].trim();

                // Track whether this member has rel and as params for extra checks
                let mut has_rel = false;
                let mut rel_contains_preload = false;
                let mut has_as = false;

                if !params.is_empty() {
                    // params are semicolon-separated
                    for p in crate::helpers::headers::parse_semicolon_list(params) {
                        let mut nv = p.splitn(2, '=').map(|s| s.trim());
                        let name = nv.next().expect(
                            "splitn(2, '=') over a parameter always yields at least one segment",
                        );

                        // validate token characters in param name
                        if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Link parameter name contains invalid character: '{}'",
                                    c
                                ),
                            });
                        }

                        let value = nv.next();
                        if value.is_none() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Link parameter '{}' missing '=' or value", name),
                            });
                        }

                        let v = value.unwrap();

                        if name.eq_ignore_ascii_case("rel") {
                            has_rel = true;
                            // rel may contain space-separated relation-types or be a quoted-string
                            let rel_value_owned: Option<String> = if v.starts_with('"') {
                                match crate::helpers::headers::unescape_quoted_string(v) {
                                    Ok(u) => Some(u),
                                    Err(e) => {
                                        return Some(Violation {
                                            rule: self.id().into(),
                                            severity: config.severity,
                                            message: format!(
                                                "Link rel quoted-string invalid: {}",
                                                e
                                            ),
                                        })
                                    }
                                }
                            } else {
                                None
                            };
                            let rel_value = rel_value_owned.as_deref().unwrap_or(v);
                            for rel in rel_value.split_whitespace() {
                                if let Some(c) = crate::helpers::token::find_invalid_token_char(rel)
                                {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Link rel contains invalid character: '{}'",
                                            c
                                        ),
                                    });
                                }
                                if rel.eq_ignore_ascii_case("preload") {
                                    rel_contains_preload = true;
                                }
                            }
                        } else {
                            // value may be token or quoted-string for non-rel params
                            if v.starts_with('"') {
                                if let Err(e) = crate::helpers::headers::validate_quoted_string(v) {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Link parameter '{}' quoted-string invalid: {}",
                                            name, e
                                        ),
                                    });
                                }
                            } else if let Some(c) =
                                crate::helpers::token::find_invalid_token_char(v)
                            {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Link parameter value contains invalid character: '{}'",
                                        c
                                    ),
                                });
                            }
                        }

                        if name.eq_ignore_ascii_case("as") {
                            has_as = true;
                        }
                    }
                }

                // If rel includes preload, require as parameter
                if rel_contains_preload && !has_as {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Link rel=\"preload\" must include 'as' parameter".into(),
                    });
                }

                // Special case: Early Hints (103) are intended for preload hints; encourage rel=preload usage
                if resp.status == 103 && !has_rel {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "103 Early Hints Link member should include a 'rel' parameter (for example, 'preload' with an 'as' parameter)".into(),
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
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_resp_with_header(
        status: u16,
        header: (&str, &str),
    ) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_response(status, &[header])
    }

    #[rstest]
    #[case(None, false)]
    #[case(Some(("Link", "<https://example.com/>; rel=next")), false)]
    #[case(Some(("Link", "https://example.com/; rel=next")), true)]
    #[case(Some(("Link", "<https://example.com/>; rel=preload")), true)]
    #[case(Some(("Link", "<https://example.com/>; rel=preload; as=script")), false)]
    #[case(Some(("Link", "<https://example.com/>; rel=\"next\"; title=\"Home\"")), false)]
    #[case(Some(("Link", "<https://example.com/>; bad@=1")), true)]
    fn check_link_cases(#[case] header: Option<(&str, &str)>, #[case] expect_violation: bool) {
        let rule = MessageLinkHeaderValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let tx = if let Some(h) = header {
            make_resp_with_header(200, h)
        } else {
            crate::test_helpers::make_test_transaction()
        };

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for header={:?}: got {:?}",
                header,
                v
            );
        }
    }

    #[test]
    fn early_hints_requires_preload_and_as() {
        let rule = MessageLinkHeaderValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        // 103 with preload but missing as
        let tx = make_resp_with_header(103, ("Link", "<https://example.com/>; rel=preload"));
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());

        // 103 with no rel -> violation
        let tx2 = make_resp_with_header(103, ("Link", "<https://example.com/>; title=\"x\""));
        let v2 = rule.check_transaction(&tx2, None, &cfg);
        assert!(v2.is_some());
    }

    #[test]
    fn additional_edge_cases_report_meaningful_messages() {
        let rule = MessageLinkHeaderValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        // Non-UTF8 header
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        hm.append("link", bad);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-UTF8"));

        // Trailing comma -> empty member
        let tx2 = make_resp_with_header(200, ("Link", "<https://example/>; rel=next,"));
        let v2 = rule.check_transaction(&tx2, None, &cfg);
        assert!(v2.is_some());
        assert!(v2.unwrap().message.contains("empty member"));

        // Missing closing '>'
        let tx3 = make_resp_with_header(200, ("Link", "<https://example.com/; rel=next"));
        let v3 = rule.check_transaction(&tx3, None, &cfg);
        assert!(v3.is_some());
        assert!(v3.unwrap().message.contains("missing closing"));

        // Missing value for param
        let tx4 = make_resp_with_header(200, ("Link", "<https://example/>; rel"));
        let v4 = rule.check_transaction(&tx4, None, &cfg);
        assert!(v4.is_some());
        assert!(v4.unwrap().message.contains("missing '=' or value"));

        // Invalid quoted-string
        let tx5 = make_resp_with_header(200, ("Link", "<https://example/>; title=\"unterminated"));
        let v5 = rule.check_transaction(&tx5, None, &cfg);
        assert!(v5.is_some());
        assert!(v5.unwrap().message.contains("quoted-string"));

        // Invalid token char in param value
        let tx6 = make_resp_with_header(200, ("Link", "<https://example/>; as=bad@val"));
        let v6 = rule.check_transaction(&tx6, None, &cfg);
        assert!(v6.is_some());
        assert!(v6.unwrap().message.contains("invalid character"));

        // rel contains invalid char
        let tx7 = make_resp_with_header(200, ("Link", "<https://example/>; rel=bad@rel"));
        let v7 = rule.check_transaction(&tx7, None, &cfg);
        assert!(v7.is_some());
        let msg7 = v7.unwrap().message;
        assert!(
            msg7.contains("Link rel contains invalid character")
                || msg7.contains("invalid character")
        );
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageLinkHeaderValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_link_header_validity");
        let _ = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn additional_positive_and_multi_header_cases() {
        let rule = MessageLinkHeaderValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        // rel with multiple types (space-separated) should be OK
        let tx = make_resp_with_header(200, ("Link", "<https://example/>; rel=next prev"));
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());

        // quoted-string title with escaped quote is accepted
        let tx2 = make_resp_with_header(200, ("Link", "<https://example/>; title=\"a\\\"b\""));
        let v2 = rule.check_transaction(&tx2, None, &cfg);
        assert!(v2.is_none());

        // preload with quoted as value is accepted
        let tx3 = make_resp_with_header(
            200,
            ("Link", "<https://example/>; rel=preload; as=\"script\""),
        );
        let v3 = rule.check_transaction(&tx3, None, &cfg);
        assert!(v3.is_none());

        // trailing semicolon ignored
        let tx4 = make_resp_with_header(200, ("Link", "<https://example/>; rel=next;"));
        let v4 = rule.check_transaction(&tx4, None, &cfg);
        assert!(v4.is_none());

        // multiple Link headers where one is invalid should produce a violation
        let mut txm = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        txm.response.as_mut().unwrap().headers.append(
            "link",
            "<https://ok/>; rel=next".parse::<HeaderValue>().unwrap(),
        );
        txm.response.as_mut().unwrap().headers.append(
            "link",
            "<https://bad/>; as=bad@value"
                .parse::<HeaderValue>()
                .unwrap(),
        );
        let vm = rule.check_transaction(&txm, None, &cfg);
        assert!(vm.is_some());
    }
}
