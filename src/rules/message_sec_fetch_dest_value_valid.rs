// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Sec-Fetch-Dest` header must be one of the canonical destination tokens
/// defined by Fetch (`empty`, `audio`, `audioworklet`, `document`, `embed`,
/// `font`, `frame`, `iframe`, `image`, `json`, `manifest`, `object`,
/// `paintworklet`, `report`, `script`, `serviceworker`, `sharedworker`,
/// `style`, `track`, `video`, `webidentity`, `worker`, `xslt`). Values are
/// compared case-insensitively; token syntax is validated.
pub struct MessageSecFetchDestValueValid;

impl Rule for MessageSecFetchDestValueValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_sec_fetch_dest_value_valid"
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
        let count = headers.get_all("sec-fetch-dest").iter().count();
        if count == 0 {
            return None;
        }

        if count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Sec-Fetch-Dest header fields present".into(),
            });
        }

        let val = match crate::helpers::headers::get_header_str(headers, "sec-fetch-dest") {
            Some(v) => v.trim(),
            None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Sec-Fetch-Dest header contains non-ASCII or control characters"
                        .into(),
                })
            }
        };

        // Validate header value is not empty after trimming
        if val.is_empty() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Sec-Fetch-Dest header is empty".into(),
            });
        }

        // Token must not contain invalid token chars
        if let Some(c) = crate::helpers::token::find_invalid_token_char(val) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Sec-Fetch-Dest header contains invalid token character: '{}'",
                    c
                ),
            });
        }

        let lower = val.to_ascii_lowercase();
        match lower.as_str() {
            "empty" | "audio" | "audioworklet" | "document" | "embed" | "font" | "frame"
            | "iframe" | "image" | "json" | "manifest" | "object" | "paintworklet" | "report"
            | "script" | "serviceworker" | "sharedworker" | "style" | "track" | "video"
            | "webidentity" | "worker" | "xslt" => None,
            _ => Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!("Unrecognized Sec-Fetch-Dest value: '{}'", val),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("audio"), false)]
    #[case(Some("audioworklet"), false)]
    #[case(Some("document"), false)]
    #[case(Some("embed"), false)]
    #[case(Some("font"), false)]
    #[case(Some("frame"), false)]
    #[case(Some("iframe"), false)]
    #[case(Some("image"), false)]
    #[case(Some("json"), false)]
    #[case(Some("manifest"), false)]
    #[case(Some("object"), false)]
    #[case(Some("paintworklet"), false)]
    #[case(Some("report"), false)]
    #[case(Some("script"), false)]
    #[case(Some("serviceworker"), false)]
    #[case(Some("sharedworker"), false)]
    #[case(Some("style"), false)]
    #[case(Some("track"), false)]
    #[case(Some("video"), false)]
    #[case(Some("webidentity"), false)]
    #[case(Some("worker"), false)]
    #[case(Some("xslt"), false)]
    #[case(Some("empty"), false)]
    #[case(Some("Image"), false)] // case-insensitive
    #[case(Some(""), true)]
    #[case(Some("invalid"), true)]
    #[case(None, false)]
    fn sec_fetch_dest_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageSecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-dest", v)]);
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

        let rule = MessageSecFetchDestValueValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("sec-fetch-dest", bad);
        tx.request.headers = hm;

        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn invalid_token_char_reports_violation() {
        let rule = MessageSecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-dest", "b@d")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid token character"));
    }

    #[test]
    fn whitespace_around_value_is_accepted() {
        let rule = MessageSecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-dest", " image ")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_none(),
            "whitespace around token should be trimmed and accepted"
        );
    }

    #[test]
    fn multiple_header_fields_first_valid_second_invalid() {
        let rule = MessageSecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("sec-fetch-dest", "image"),
            ("sec-fetch-dest", "invalid"),
        ]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some(), "expected violation for multiple header fields");
        let msg = v.unwrap().message;
        assert!(msg.contains("Multiple Sec-Fetch-Dest"));
    }

    #[test]
    fn multiple_header_fields_both_invalid_reports_violation() {
        let rule = MessageSecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("sec-fetch-dest", "bad1"),
            ("sec-fetch-dest", "bad2"),
        ]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(
            v.is_some(),
            "expected violation when all header field values are invalid"
        );
    }

    #[test]
    fn unrecognized_value_reports_unrecognized_message() {
        let rule = MessageSecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-dest", "bogus")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some(), "expected violation for unrecognized token");
        let msg = v.unwrap().message;
        assert!(msg.contains("Unrecognized Sec-Fetch-Dest value"));
        assert!(msg.contains("bogus"));
    }

    #[test]
    fn comma_in_value_reports_invalid_token_char() {
        let rule = MessageSecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-dest", "image,script")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some(), "expected violation for comma-separated value");
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid token character"));
        assert!(msg.contains(","));
    }

    #[test]
    fn message_and_id() {
        let rule = MessageSecFetchDestValueValid;
        assert_eq!(rule.id(), "message_sec_fetch_dest_value_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_sec_fetch_dest_value_valid");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
