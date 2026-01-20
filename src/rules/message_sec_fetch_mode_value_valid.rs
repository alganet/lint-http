// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Sec-Fetch-Mode` header must be one of the canonical values listed in
/// the Fetch Metadata spec: `cors`, `no-cors`, `same-origin`, `navigate`, or `websocket`.
/// Values are compared case-insensitively; token syntax is validated.
pub struct MessageSecFetchModeValueValid;

impl Rule for MessageSecFetchModeValueValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_sec_fetch_mode_value_valid"
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
        // Sec-Fetch-* are request-sent headers; check only requests
        let headers = &tx.request.headers;
        let count = headers.get_all("sec-fetch-mode").iter().count();
        if count == 0 {
            return None;
        }

        if count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Sec-Fetch-Mode header fields present".into(),
            });
        }

        let val = match crate::helpers::headers::get_header_str(headers, "sec-fetch-mode") {
            Some(v) => v.trim(),
            None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Sec-Fetch-Mode header contains non-ASCII or control characters"
                        .into(),
                })
            }
        };

        // Validate header value is not empty after trimming
        if val.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Sec-Fetch-Mode header is empty".into(),
            });
        }

        // Token must not contain invalid token chars
        if let Some(c) = crate::helpers::token::find_invalid_token_char(val) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Sec-Fetch-Mode header contains invalid token character: '{}'",
                    c
                ),
            });
        }

        let lower = val.to_ascii_lowercase();
        match lower.as_str() {
            "cors" | "no-cors" | "same-origin" | "navigate" | "websocket" => None,
            _ => Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!("Unrecognized Sec-Fetch-Mode value: '{}'", val),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("cors"), false)]
    #[case(Some("no-cors"), false)]
    #[case(Some("same-origin"), false)]
    #[case(Some("navigate"), false)]
    #[case(Some("websocket"), false)]
    #[case(Some("CORS"), false)]
    #[case(Some(""), true)]
    #[case(Some("invalid"), true)]
    #[case(None, false)]
    fn sec_fetch_mode_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageSecFetchModeValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-mode", v)]);
        }

        let v = rule.check_transaction(&tx, None, &cfg);
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
    fn non_utf8_is_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageSecFetchModeValueValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("sec-fetch-mode", bad);
        tx.request.headers = hm;

        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn invalid_token_char_reports_violation() {
        let rule = MessageSecFetchModeValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-mode", "b@d")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid token character"));
    }

    #[test]
    fn multiple_header_fields_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageSecFetchModeValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-mode", HeaderValue::from_static("cors"));
        hm.append("sec-fetch-mode", HeaderValue::from_static("invalid"));
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple Sec-Fetch-Mode"));
    }

    #[test]
    fn multiple_header_fields_both_valid_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageSecFetchModeValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-mode", HeaderValue::from_static("cors"));
        hm.append("sec-fetch-mode", HeaderValue::from_static("navigate"));
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple Sec-Fetch-Mode"));
    }

    #[test]
    fn multiple_header_fields_both_invalid_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageSecFetchModeValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-mode", HeaderValue::from_static("bad1"));
        hm.append("sec-fetch-mode", HeaderValue::from_static("bad2"));
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple Sec-Fetch-Mode"));
    }

    #[test]
    fn whitespace_around_value_is_accepted() {
        let rule = MessageSecFetchModeValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-mode", " same-origin ")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_none(),
            "whitespace around token should be trimmed and accepted"
        );
    }

    #[test]
    fn message_and_id() {
        let rule = MessageSecFetchModeValueValid;
        assert_eq!(rule.id(), "message_sec_fetch_mode_value_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_sec_fetch_mode_value_valid");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
