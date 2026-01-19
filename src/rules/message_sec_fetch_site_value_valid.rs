// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Sec-Fetch-Site` header must be one of the canonical values listed in
/// the Fetch Metadata spec: `cross-site`, `same-origin`, `same-site`, or `none`.
/// Values are compared case-insensitively; token syntax is validated.
pub struct MessageSecFetchSiteValueValid;

impl Rule for MessageSecFetchSiteValueValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_sec_fetch_site_value_valid"
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
        let count = headers.get_all("sec-fetch-site").iter().count();
        if count == 0 {
            return None;
        }

        if count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Sec-Fetch-Site header fields present".into(),
            });
        }

        let val = match crate::helpers::headers::get_header_str(headers, "sec-fetch-site") {
            Some(v) => v.trim(),
            None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Sec-Fetch-Site header contains non-ASCII or control characters"
                        .into(),
                })
            }
        };

        // Validate header value is not empty after trimming
        if val.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Sec-Fetch-Site header is empty".into(),
            });
        }

        // Token must not contain invalid token chars
        if let Some(c) = crate::helpers::token::find_invalid_token_char(val) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Sec-Fetch-Site header contains invalid token character: '{}'",
                    c
                ),
            });
        }

        let lower = val.to_ascii_lowercase();
        match lower.as_str() {
            "cross-site" | "same-origin" | "same-site" | "none" => None,
            _ => Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!("Unrecognized Sec-Fetch-Site value: '{}'", val),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("same-origin"), false)]
    #[case(Some("same-site"), false)]
    #[case(Some("cross-site"), false)]
    #[case(Some("none"), false)]
    #[case(Some("Same-Origin"), false)] // case-insensitive allowed
    #[case(Some(""), true)]
    #[case(Some("invalid"), true)]
    #[case(None, false)]
    fn sec_fetch_site_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageSecFetchSiteValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-site", v)]);
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

        let rule = MessageSecFetchSiteValueValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("sec-fetch-site", bad);
        tx.request.headers = hm;

        let cfg = crate::test_helpers::make_test_rule_config();
        // get_header_str will return None for non-utf8 and this rule treats non-UTF8 as violation
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn invalid_token_char_reports_violation() {
        let rule = MessageSecFetchSiteValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-site", "b@d")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid token character"));
    }

    #[test]
    fn whitespace_around_value_is_accepted() {
        let rule = MessageSecFetchSiteValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-site", " same-origin ")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_none(),
            "whitespace around token should be trimmed and accepted"
        );
    }

    #[test]
    fn multiple_header_fields_first_valid_second_invalid() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageSecFetchSiteValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-site", HeaderValue::from_static("same-origin"));
        hm.append("sec-fetch-site", HeaderValue::from_static("invalid"));
        tx.request.headers = hm;

        // Multiple header fields are always a violation (potential header injection)
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some(), "expected violation for multiple header fields");
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Multiple Sec-Fetch-Site"),
            "expected message to mention multiple headers, got: {}",
            msg
        );
    }

    #[test]
    fn multiple_header_fields_both_invalid_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageSecFetchSiteValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-site", HeaderValue::from_static("bad1"));
        hm.append("sec-fetch-site", HeaderValue::from_static("bad2"));
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_some(),
            "expected violation when all header field values are invalid"
        );
    }

    #[test]
    fn multiple_header_fields_both_valid_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageSecFetchSiteValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("sec-fetch-site", HeaderValue::from_static("same-origin"));
        hm.append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_some(),
            "expected violation when multiple valid header field values are present"
        );
    }

    #[test]
    fn message_and_id() {
        let rule = MessageSecFetchSiteValueValid;
        assert_eq!(rule.id(), "message_sec_fetch_site_value_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_sec_fetch_site_value_valid");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
