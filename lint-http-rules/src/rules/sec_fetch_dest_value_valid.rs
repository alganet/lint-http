// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `Sec-Fetch-Dest` header must be one of the canonical destination tokens
/// defined by Fetch (`empty`, `audio`, `audioworklet`, `document`, `embed`,
/// `font`, `frame`, `iframe`, `image`, `json`, `manifest`, `object`,
/// `paintworklet`, `report`, `script`, `serviceworker`, `sharedworker`,
/// `style`, `track`, `video`, `webidentity`, `worker`, `xslt`). The match is
/// exact: destinations are lowercase tokens and the structured-field token
/// carries no case folding; token syntax is validated.
pub struct SecFetchDestValueValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const FETCH_METADATA_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
spec: "Fetch Metadata",
section: Some("2.1"),
url: "https://www.w3.org/TR/fetch-metadata/#sec-fetch-dest-header",
note: "Fetch Metadata (W3C) — `Sec-Fetch-Dest`: an sf-token whose valid values are Fetch's request destinations",
        };

impl Rule for SecFetchDestValueValid {
    fn id(&self) -> &'static str {
        "sec_fetch_dest_value_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // Sec-Fetch-* are request-sent headers; check only requests
            // cite(Fetch Metadata § 2.1): "HTTP request header exposes a request’s destination to a server"
            let headers = &tx.request.headers;
            let count = headers.get_all("sec-fetch-dest").iter().count();
            if count == 0 {
                return None;
            }

            // A single structured-field item, never a list, so a sender may not repeat
            // the field.
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            if count > 1 {
                return Some(self.violation(
                    ctx.severity,
                    "Multiple Sec-Fetch-Dest header fields present".into(),
                ));
            }

            // cite(RFC 9110 § 5.5): "newly defined fields SHOULD limit their values to visible US-ASCII octets (VCHAR), SP, and HTAB"
            let val = match crate::helpers::headers::get_header_str(headers, "sec-fetch-dest") {
                Some(v) => v.trim(),
                None => {
                    return Some(self.violation(
                        ctx.severity,
                        "Sec-Fetch-Dest header contains non-ASCII or control characters".into(),
                    ))
                }
            };

            // An empty value cannot be a token.
            // cite(Fetch Metadata § 2.1): "It is a Structured Field whose value MUST be a token."
            if val.is_empty() {
                return Some(self.cited(
                    &FETCH_METADATA_2_1,
                    ctx.severity,
                    "Sec-Fetch-Dest header is empty".into(),
                ));
            }

            // Token must not contain invalid token chars. This checks the HTTP `token`
            // grammar, slightly looser than sf-token; the closed value match below is
            // what actually gates acceptance, so the difference only picks which
            // message a bad value gets.
            // cite(Fetch Metadata § 2.1): "It is a Structured Field whose value MUST be a token."
            if let Some(c) = crate::helpers::token::find_invalid_token_char(val) {
                return Some(self.cited(
                    &FETCH_METADATA_2_1,
                    ctx.severity,
                    format!(
                        "Sec-Fetch-Dest header contains invalid token character: '{}'",
                        c
                    ),
                ));
            }

            // The value set is not Fetch Metadata's own — it defers to Fetch, which grows as
            // new destinations are defined. `"text"` was added to Fetch and missing here until
            // the citation below was written against the live document. That growth is also
            // why the spec tells servers to ignore unknown values; this rule lints the
            // *sender*, where an unknown value means a non-conforming (or non-browser)
            // origin of the header, so it flags instead.
            // cite(Fetch Metadata § 2.1): "In order to support forward-compatibility with as-yet-unknown request types, servers SHOULD ignore this header if it contains an invalid value."
            // cite(Fetch Metadata § 2.1): "Valid Sec-Fetch-Dest values include the set of valid request destinations defined by [Fetch]."
            // cite(Fetch § 2.2.5): "A destination type is one of: the empty string, "audio", "audioworklet", "document", "embed", "font", "frame", "iframe", "image", "json", "manifest", "object", "paintworklet", "report", "script", "serviceworker", "sharedworker", "style", "text", "track", "video", "webidentity", "worker", or "xslt"."
            // Fetch's "the empty string" destination is carried as the literal token
            // `empty`, which is why the arm below accepts it.
            // cite(Fetch Metadata § 2.1): "If r’s destination is the empty string, set header’s value to the string "empty""
            match val {
                "empty" | "audio" | "audioworklet" | "document" | "embed" | "font" | "frame"
                | "iframe" | "image" | "json" | "manifest" | "object" | "paintworklet"
                | "report" | "script" | "serviceworker" | "sharedworker" | "style" | "text"
                | "track" | "video" | "webidentity" | "worker" | "xslt" => None,
                _ => Some(self.violation(
                    ctx.severity,
                    format!("Unrecognized Sec-Fetch-Dest value: '{}'", val),
                )),
            }
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Validate the `Sec-Fetch-Dest` request header follows the Fetch Metadata specification: the header value must be a token matching one of the recognized request destinations (e.g., `image`, `document`, `script`, `worker`, `empty`, etc.). The match is exact — destinations are lowercase tokens and structured-field tokens carry no case folding, so `Image` is not a valid value. Token syntax is enforced. Multiple header fields are treated as a violation."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[FETCH_METADATA_2_1]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /image.png HTTP/1.1\nHost: example.com\nSec-Fetch-Dest: image",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /script.js HTTP/1.1\nHost: example.com\nSec-Fetch-Dest: script",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("destination tokens are lowercase; the match is exact"),
                snippet: "GET /script.js HTTP/1.1\nHost: example.com\nSec-Fetch-Dest: Script",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /something HTTP/1.1\nHost: example.com\nSec-Fetch-Dest: invalid-dest",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /img HTTP/1.1\nHost: example.com\nSec-Fetch-Dest: image\nSec-Fetch-Dest: script",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SecFetchDestValueValid;

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
    // A destination Fetch added after this rule was written, and rejected here until the
    // citation was checked against the live standard.
    #[case(Some("text"), false)]
    #[case(Some("track"), false)]
    #[case(Some("video"), false)]
    #[case(Some("webidentity"), false)]
    #[case(Some("worker"), false)]
    #[case(Some("xslt"), false)]
    #[case(Some("empty"), false)]
    #[case(Some("Image"), true)] // destinations are lowercase; the match is exact
    #[case(Some(""), true)]
    #[case(Some("invalid"), true)]
    #[case(None, false)]
    fn sec_fetch_dest_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = SecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_dest_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-dest", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
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

        let rule = SecFetchDestValueValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("sec-fetch-dest", bad);
        tx.request.headers = hm;

        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_dest_value_valid",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn invalid_token_char_reports_violation() {
        let rule = SecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_dest_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-dest", "b@d")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid token character"));
    }

    #[test]
    fn whitespace_around_value_is_accepted() {
        let rule = SecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_dest_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-dest", " image ")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_none(),
            "whitespace around token should be trimmed and accepted"
        );
    }

    #[test]
    fn multiple_header_fields_first_valid_second_invalid() {
        let rule = SecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_dest_value_valid",
        ]);

        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("sec-fetch-dest", "image"),
            ("sec-fetch-dest", "invalid"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some(), "expected violation for multiple header fields");
        let msg = v.unwrap().message;
        assert!(msg.contains("Multiple Sec-Fetch-Dest"));
    }

    #[test]
    fn multiple_header_fields_both_invalid_reports_violation() {
        let rule = SecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_dest_value_valid",
        ]);

        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("sec-fetch-dest", "bad1"),
            ("sec-fetch-dest", "bad2"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some(),
            "expected violation when all header field values are invalid"
        );
    }

    #[test]
    fn unrecognized_value_reports_unrecognized_message() {
        let rule = SecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_dest_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-dest", "bogus")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some(), "expected violation for unrecognized token");
        let msg = v.unwrap().message;
        assert!(msg.contains("Unrecognized Sec-Fetch-Dest value"));
        assert!(msg.contains("bogus"));
    }

    #[test]
    fn comma_in_value_reports_invalid_token_char() {
        let rule = SecFetchDestValueValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "sec_fetch_dest_value_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("sec-fetch-dest", "image,script")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some(), "expected violation for comma-separated value");
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid token character"));
        assert!(msg.contains(","));
    }

    #[test]
    fn message_and_id() {
        let rule = SecFetchDestValueValid;
        assert_eq!(rule.id(), "sec_fetch_dest_value_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "sec_fetch_dest_value_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
