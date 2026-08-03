// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageMultipartContentTypeAndBodyConsistency;

impl Rule for MessageMultipartContentTypeAndBodyConsistency {
    fn id(&self) -> &'static str {
        "message_multipart_content_type_and_body_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Check request body when Content-Type is multipart
        // cite(RFC 2046 § 5.1.1): "The Content-Type field for multipart entities requires one parameter, "boundary"."
        if let Some(hv) = tx.request.headers.get("content-type") {
            if let Ok(s) = hv.to_str() {
                if let Some(boundary) = crate::helpers::headers::extract_multipart_boundary(s) {
                    // Skip a truncated prefix (streaming): the terminating boundary
                    // sits at the body's end and would be missing from a prefix.
                    if let Some(b) = tx
                        .request_body
                        .as_ref()
                        .filter(|_| !tx.request_body_over_limit)
                    {
                        if let Some(v) =
                            check_body_contains_boundary("request", &boundary, b.as_ref(), &config)
                        {
                            return Some(v);
                        }
                    }
                }
            }
        }

        // Check response body when Content-Type is multipart
        if let Some(resp) = &tx.response {
            if let Some(hv) = resp.headers.get("content-type") {
                if let Ok(s) = hv.to_str() {
                    if let Some(boundary) = crate::helpers::headers::extract_multipart_boundary(s) {
                        if let Some(b) = tx
                            .response_body
                            .as_ref()
                            .filter(|_| !tx.response_body_over_limit)
                        {
                            if let Some(v) = check_body_contains_boundary(
                                "response",
                                &boundary,
                                b.as_ref(),
                                &config,
                            ) {
                                return Some(v);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "When a `Content-Type` header declares `multipart/*` it MUST include a `boundary` parameter and the corresponding message body (when present) MUST use that boundary to delimit parts. This rule verifies that when a `multipart/*` Content-Type provides a boundary and a captured body is available, the body contains at least one boundary marker (`--<boundary>`) and a terminating boundary (`--<boundary>--`). Missing markers indicate a malformed or truncated multipart body and may break message parsing."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 2046",
            section: Some("5.1.1"),
            url: "https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1",
            note: "Multipart common syntax and the `boundary` parameter",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Type: multipart/mixed; boundary=abc\n\n--abc\nContent-Type: text/plain\n\nhello\n--abc--",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Type: multipart/mixed; boundary=\"a b\"\n\n--a b\nContent-Type: text/plain\n\nhello\n--a b--",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(missing boundary)"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: multipart/mixed; boundary=abc\n\nno boundaries here",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(missing final boundary)"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: multipart/mixed; boundary=abc\n\n--abc\nContent-Type: text/plain\n\nhello\n--abc",
            },
        ]
    }
}

/// What the scan below found in the body: delimiter *lines*, not text.
#[derive(Default)]
struct DelimiterScan {
    /// A delimiter line that is not the closing one, so it opens a body part.
    opens_a_part: bool,
    /// The closing delimiter line, `dash-boundary` followed by two more hyphens.
    closes: bool,
    /// The `dash-boundary` text occurs somewhere, but never at the start of a
    /// line. Kept only so the finding can say which of the two is wrong.
    appears_off_line: bool,
}

fn scan_delimiter_lines(body: &[u8], boundary: &str) -> DelimiterScan {
    let dash_boundary = ["--", boundary].concat();
    let db = dash_boundary.as_bytes();
    let mut scan = DelimiterScan::default();

    if db.len() > body.len() {
        return scan;
    }
    for i in 0..=(body.len() - db.len()) {
        if &body[i..i + db.len()] != db {
            continue;
        }
        // The line break is located on LF so that a body using bare LF is still
        // read as having delimiter lines. Such a body is malformed — RFC 9110
        // §8.3.3 requires CRLF between parts — but that is a different finding
        // from "the delimiter is not there", and naming the wrong one helps
        // nobody.
        if !(i == 0 || body[i - 1] == b'\n') {
            scan.appears_off_line = true;
            continue;
        }
        // `close-delimiter := delimiter "--"`: the two extra hyphens are the
        // only thing distinguishing the closing line from one that opens a
        // part, so this is the whole classification.
        if body[i + db.len()..].starts_with(b"--") {
            scan.closes = true;
        } else {
            scan.opens_a_part = true;
        }
    }
    scan
}

fn check_body_contains_boundary(
    which: &str,
    boundary: &str,
    body: &[u8],
    config: &crate::rules::RuleConfig,
) -> Option<Violation> {
    let scan = scan_delimiter_lines(body, boundary);

    if !scan.opens_a_part && !scan.closes {
        let detail = if scan.appears_off_line {
            format!(
                "the text '--{}' occurs in the body but never at the start of a line, so it delimits nothing",
                boundary
            )
        } else {
            format!("body does not contain boundary marker '--{}'", boundary)
        };
        return Some(Violation {
            rule: MessageMultipartContentTypeAndBodyConsistency.id().into(),
            severity: config.severity,
            message: format!("Invalid multipart Content-Type in {}: {}", which, detail),
        });
    }

    if !scan.closes {
        return Some(Violation {
            rule: MessageMultipartContentTypeAndBodyConsistency.id().into(),
            severity: config.severity,
            message: format!(
                "Invalid multipart Content-Type in {}: body missing terminating boundary '--{}--'",
                which, boundary
            ),
        });
    }
    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageMultipartContentTypeAndBodyConsistency;

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rstest::rstest;

    #[test]
    fn valid_multipart_with_final_boundary_ok() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        tx.response_body = Some(Bytes::from_static(
            b"--abc\r\nContent-Type: text/plain\r\n\r\nhi\r\n--abc--\r\n",
        ));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn missing_boundary_marker_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        tx.response_body = Some(Bytes::from_static(b"no boundaries here"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("--abc"));
    }

    /// The boundary this rule hunts for has to be one the message declared. A
    /// `;` inside a quoted parameter value is not a separator, so there is no
    /// boundary parameter here — the text that reads like one is part of
    /// `foo`'s value. Reading it as a parameter made the rule demand `--abc`
    /// delimiters of a body that was never told to have them.
    #[test]
    fn a_boundary_inside_a_quoted_value_is_not_a_boundary_parameter() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[(
                "content-type",
                "multipart/mixed; foo=\"a; boundary=abc; b=1\"",
            )],
        );
        tx.response_body = Some(Bytes::from_static(b"no boundaries here"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "no boundary was declared, so there is nothing to look for: {v:?}"
        );
    }

    #[test]
    fn truncated_body_prefix_skips_boundary_scan() {
        // A truncated prefix is missing the terminating boundary (it sits at the
        // body's end); the rule must skip the scan rather than false-positive.
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        tx.response_body = Some(Bytes::from_static(b"--abc\r\nContent-Type: text/pl"));
        tx.response_body_over_limit = true;
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "truncated prefix must not be boundary-scanned");
    }

    #[test]
    fn missing_final_boundary_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        tx.response_body = Some(Bytes::from_static(b"--abc\r\nPart\r\n--abc\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("missing terminating boundary"));
    }

    #[test]
    fn non_multipart_content_type_is_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text/plain")],
        );
        tx.response_body = Some(Bytes::from_static(b"no boundaries"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn no_body_present_is_ignored() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn request_body_checked_too() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "multipart/form-data; boundary=xyz",
        )]);
        tx.request_body = Some(Bytes::from_static(b"--xyz\r\nfoo\r\n--xyz--\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_boundary_unescaped_ok() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=\"a b\"")],
        );
        tx.response_body = Some(Bytes::from_static(b"--a b\r\nx\r\n--a b--\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn malformed_content_type_is_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "not-a-media-type")],
        );
        tx.response_body = Some(Bytes::from_static(b"no boundaries"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_or_malformed_boundary_is_ignored() {
        // quoted empty -> helper should treat as missing
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=\"\"")],
        );
        tx.response_body = Some(Bytes::from_static(b"no boundaries"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());

        // malformed quoted-string -> ignored
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=\"unterminated")],
        );
        tx2.response_body = Some(Bytes::from_static(b"no boundaries"));
        let v2 = rule.check_transaction(
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v2.is_none());
    }

    #[test]
    fn request_missing_boundary_marker_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "multipart/form-data; boundary=xyz",
        )]);
        tx.request_body = Some(Bytes::from_static(b"no boundaries here"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("--xyz"));
        assert!(msg.contains("request"));
    }

    #[test]
    fn request_missing_final_boundary_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "multipart/form-data; boundary=xyz",
        )]);
        tx.request_body = Some(Bytes::from_static(b"--xyz\r\nPart\r\n--xyz\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("terminating boundary"));
    }

    #[test]
    fn response_final_marker_alone_is_accepted() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        // body contains only the final boundary marker
        tx.response_body = Some(Bytes::from_static(b"--abc--\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_escaped_boundary_unescaped_ok() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=\"a\\\"b\"")],
        );
        // unescaped boundary is: a"b
        tx.response_body = Some(Bytes::from_static(b"--a\"b\r\nx\r\n--a\"b--\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_colon_boundary_ok() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[(
                "content-type",
                "multipart/mixed; boundary=\"gc0pJq0M:08jU534c0p\"",
            )],
        );
        tx.response_body = Some(Bytes::from_static(
            b"--gc0pJq0M:08jU534c0p\r\npart\r\n--gc0pJq0M:08jU534c0p--\r\n",
        ));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    /// Binary part content must not disturb the scan. The fixture used to put
    /// the delimiters *inside* the binary run, where they delimit nothing —
    /// it passed only because the scan was a substring search, so it asserted
    /// the defect rather than the behaviour it was named for.
    #[test]
    fn binary_body_marker_ok() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=bin")],
        );
        tx.response_body = Some(Bytes::from_static(
            b"--bin\r\n\r\n\x00\x01\x02--bin\x03\r\n--bin--\r\n",
        ));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    /// The delimiter is a *line*. Text that merely contains `--abc` delimits
    /// nothing, and a body made entirely of such text used to satisfy both
    /// checks — the exact defect this rule exists to catch, passing.
    #[rstest]
    #[case(b"hello --abc-- world", true)]
    #[case(b"the text --abc appears mid-line and --abc-- too", true)]
    #[case(b"prologue\r\n--abc\r\nx\r\n--abc--\r\n", false)]
    // Bare LF is malformed per RFC 9110 §8.3.3, but the delimiters are plainly
    // there; this rule must not report them as absent.
    #[case(b"--abc\nx\n--abc--\n", false)]
    // A body shorter than the delimiter cannot contain one.
    #[case(b"--a", true)]
    #[case(b"", true)]
    fn delimiter_must_begin_a_line(#[case] body: &[u8], #[case] expect_violation: bool) {
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        tx.response_body = Some(Bytes::copy_from_slice(body));
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(
            v.is_some(),
            expect_violation,
            "{:?} -> {v:?}",
            String::from_utf8_lossy(body)
        );
    }

    /// When the text is present but never at a line start, the finding says so
    /// rather than claiming the boundary is absent — the body does carry it,
    /// just nowhere it can delimit anything.
    #[test]
    fn off_line_text_is_named_as_such() {
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        tx.response_body = Some(Bytes::from_static(b"hello --abc-- world"));
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .expect("text that delimits nothing is a violation");
        assert!(v.message.contains("never at the start of a line"), "{v:?}");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(
            &mut cfg,
            "message_multipart_content_type_and_body_consistency",
        );
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
