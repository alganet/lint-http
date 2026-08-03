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

    // Both directions carry a representation, and both carry multipart ones:
    // RFC 9110 §8.3.3 names `multipart/form-data` for requests and
    // `multipart/byteranges` for 206 responses in the same paragraph. (That
    // sentence cannot be quoted as one span — the media type name is broken
    // across a line at its slash — so the field's own definition stands here.)
    // cite(RFC 9110 § 8.3): "The "Content-Type" header field indicates the media type of the associated representation: either the representation enclosed in the message content or the selected representation, as determined by the message semantics."
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

        // Why a MIME grammar governs an HTTP body at all, and why the boundary
        // named in the header is the one the body must use: RFC 9110 adopts
        // §5.1.1 for every multipart type and makes the parameter part of the
        // media type value. The same paragraph is careful that this is a claim
        // about the *content*, not about framing — the boundary tells a
        // recipient nothing about where the message ends, so nothing here is a
        // length check.
        // cite(RFC 9110 § 8.3.3): "All multipart types share a common syntax, as defined in Section 5.1.1 of [RFC2046], and include a boundary parameter as part of the media type value."
        // cite(RFC 9110 § 8.3.3): "HTTP message framing does not use the multipart boundary as an indicator of message body length, though it might be used by implementations that generate or process the content."
        // cite(RFC 2046 § 5.1.1): "The Content-Type field for multipart entities requires one parameter, "boundary"."
        let check_message = |which: &str,
                             headers: &hyper::HeaderMap,
                             body: Option<&bytes::Bytes>|
         -> Option<Violation> {
            // A body captured only as a prefix is not scanned: the terminating
            // delimiter sits at the body's end, so every truncated capture would
            // be reported as missing one. Nothing licenses this — it is a fact
            // about the capture, not about the message. A message with no body
            // is skipped for the plainer reason that §5.1.1's grammar describes
            // content, and there is none to describe.
            let body = body?;

            // Every Content-Type field line, not just the first. `HeaderMap::get`
            // returns one value, and RFC 9110 §8.3 says recipients differ over
            // which member of a duplicated Content-Type they act on, so a
            // multipart declaration on a second line names a boundary the peer
            // may well be the one to look for. That there is more than one line
            // is `message_content_type_well_formed`'s finding, not this one's.
            for hv in headers.get_all("content-type").iter() {
                // Decoded from the raw octets rather than through `to_str`,
                // which refuses `obs-text` — legal inside a `quoted-string`, so
                // a boundary is not unreadable merely because a neighbouring
                // parameter carries one.
                // cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
                let s = String::from_utf8_lossy(hv.as_bytes());
                if let Some(boundary) = crate::helpers::headers::extract_multipart_boundary(&s) {
                    if let Some(v) = check_body_delimiters(which, &boundary, body.as_ref(), &config)
                    {
                        return Some(v);
                    }
                }
            }
            None
        };

        if let Some(v) = check_message(
            "request",
            &tx.request.headers,
            tx.request_body
                .as_ref()
                .filter(|_| !tx.request_body_over_limit),
        ) {
            return Some(v);
        }

        if let Some(resp) = &tx.response {
            if let Some(v) = check_message(
                "response",
                &resp.headers,
                tx.response_body
                    .as_ref()
                    .filter(|_| !tx.response_body_over_limit),
            ) {
                return Some(v);
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Multipart Content-Type and Body Consistency")
    }

    fn description(&self) -> &'static str {
        "When a `Content-Type` declares a `multipart/*` media type, the body it describes has to be delimited by the `boundary` the header names. This rule reads a captured body and checks that it carries at least one **boundary delimiter line** opening a part, and the terminating one — `--<boundary>--` — that says no further parts follow.\n\n**A delimiter is a line, not text.** RFC 2046 §5.1.1 requires the delimiter to occur at the beginning of a line, so a body carrying the boundary text mid-line delimits nothing: `hello --abc-- world` is reported, and the finding says the text occurs but never at a line start rather than claiming the boundary is absent. Matching is a *prefix* match against the start of each candidate line, which §5.1.1 instructs implementors to do — the rest of the line may be `transport-padding`.\n\n**A body whose only delimiter line is the closing one is reported.** The closing line is defined as the one following the last body part, so with no part to follow it the body encapsulates nothing. A single part is the documented minimum, and it passes.\n\n**RFC 9110 §8.3.3 is why a MIME grammar governs an HTTP body**, and it is also careful about what this rule is not: HTTP framing does not use the boundary as a length indicator, so nothing here says anything about where the message ends.\n\n**Known leniency: line endings.** §8.3.3 requires senders to generate only CRLF between body parts, and this rule locates line starts on LF, so a body using bare LF has its delimiters recognised rather than reported as missing. The wrong line ending is a real defect and a different one; blaming the boundary for it would name the wrong thing. No rule currently reports it.\n\n**The epilogue is not read.** A delimiter line written after the closing one is `discard-text` that implementations must ignore, so it opens no part — a body consisting of a closing line followed by something that looks like a delimiter still encapsulates nothing and is reported.\n\n**Cost:** a conforming body settles the question in its first two lines and the scan stops there. A body that never carries the delimiter is walked in full, which is inherent — the answer is only known at the end — and is bounded by `max_body_bytes`.\n\n**Scope:** every `Content-Type` field line in each message is read, since recipients differ over which one they act on; that there is more than one is `message_content_type_well_formed`'s finding. Whether the boundary *value* is syntactically legal is `message_multipart_boundary_syntax`'s. A body captured only as a prefix is skipped entirely — the terminating delimiter sits at a body's end, so a truncated capture would always look like it is missing one. Nothing before the first delimiter line or after the last is examined, which §5.1.1 requires: the preamble and epilogue are to be ignored."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 2046",
                section: Some("5.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1",
                note: "Multipart common syntax: `dash-boundary`, `delimiter` and `close-delimiter`, the requirement that a delimiter begin a line, the instruction to compare against the beginning of a candidate line rather than the whole of it, and the ignoring of preamble and epilogue",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.3",
                note: "Multipart Types: where HTTP adopts RFC 2046 §5.1.1, and the CRLF-between-parts requirement this rule tolerates rather than enforces. It also says HTTP framing does not use the boundary as a length indicator, so nothing here is a framing check",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3",
                note: "Content-Type: the field describes a representation in either direction, which is what puts request and response bodies both in scope",
            },
        ]
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
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the boundary text never begins a line, so it delimits nothing)"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: multipart/mixed; boundary=abc\n\nhello --abc-- world",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the closing delimiter has no part to follow)"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: multipart/mixed; boundary=abc\n\n--abc--",
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
    // The two hyphens are not decoration: `dash-boundary` is what the body
    // carries, and the boundary parameter is only its tail.
    // cite(RFC 2046 § 5.1.1): "dash-boundary := "--" boundary"
    // cite(RFC 2046 § 5.1.1): "The boundary delimiter line is then defined as a line consisting entirely of two hyphen characters ("-", decimal value 45) followed by the boundary parameter value from the Content-Type header field, optional linear whitespace, and a terminating CRLF."
    let dash_boundary = ["--", boundary].concat();
    let db = dash_boundary.as_bytes();
    let mut scan = DelimiterScan::default();

    if db.len() > body.len() {
        return scan;
    }

    // Only line starts are candidates, and the position is the requirement —
    // it is the whole difference between a delimiter and some bytes that look
    // like one. Offset zero counts because the preamble is optional, so the
    // first delimiter may open the body with no CRLF before it.
    //
    // The line break is located on LF rather than CRLF so that a body using
    // bare LF is still read as having delimiter lines. Such a body violates the
    // CRLF requirement below, but that is a different finding from "the
    // delimiter is not there", and naming the wrong one helps nobody. This rule
    // does not report line endings; it only declines to blame the boundary for
    // them.
    // cite(RFC 2046 § 5.1.1): "The boundary delimiter MUST occur at the beginning of a line, i.e., following a CRLF, and the initial CRLF is considered to be attached to the boundary delimiter line rather than part of the preceding part."
    // cite(RFC 9110 § 8.3.3): "The message body is itself a protocol element; a sender MUST generate only CRLF to represent line breaks between body parts."
    for i in 0..=(body.len() - db.len()) {
        // Once one delimiter line has opened a part and another has closed the
        // body, the verdict is settled and the rest cannot change it. A body
        // may be as large as `max_body_bytes` — 64 MiB by default — so this is
        // the difference between reading a delimiter and reading a file.
        // `appears_off_line` is consulted only when neither flag is set, so
        // stopping here loses nothing.
        if scan.opens_a_part && scan.closes {
            break;
        }
        // `dash-boundary` begins with a hyphen, so one byte rejects nearly
        // every position before a slice comparison is set up. Every position is
        // examined, not only line starts, because a body with no delimiter line
        // still has to be told apart from one whose boundary text is merely in
        // the wrong place — and doing that here costs a byte rather than a
        // second walk over the body.
        if body[i] != b'-' {
            continue;
        }
        // A prefix match, deliberately: the rest of the line may be
        // `transport-padding`, and §5.1.1 tells implementors in as many words
        // not to require the whole line to match. Comparing whole lines would
        // reject conforming bodies whose delimiter lines carry padding.
        // cite(RFC 2046 § 5.1.1): "Boundary string comparisons must compare the boundary value with the beginning of each candidate line."
        // cite(RFC 2046 § 5.1.1): "An exact match of the entire candidate line is not required; it is sufficient that the boundary appear in its entirety following the CRLF."
        if &body[i..i + db.len()] != db {
            continue;
        }
        if !(i == 0 || body[i - 1] == b'\n') {
            scan.appears_off_line = true;
            continue;
        }
        // `close-delimiter := delimiter "--"`: the two extra hyphens are the
        // only thing distinguishing the closing line from one that opens a
        // part, so this comparison is the whole classification.
        // cite(RFC 2046 § 5.1.1): "close-delimiter := delimiter "--""
        // cite(RFC 2046 § 5.1.1): "Such a delimiter line is identical to the previous delimiter lines, with the addition of two more hyphens after the boundary parameter value."
        if body[i + db.len()..].starts_with(b"--") {
            scan.closes = true;
        } else if !scan.closes {
            // Only before the closing line. What follows it is epilogue, and
            // the epilogue is `discard-text` that implementations must ignore —
            // so a line down there that looks like a delimiter opens nothing,
            // and counting it would let a body with no parts at all pass by
            // writing one after the end.
            scan.opens_a_part = true;
        }
    }
    scan
}

fn check_body_delimiters(
    which: &str,
    boundary: &str,
    body: &[u8],
    config: &crate::rules::RuleConfig,
) -> Option<Violation> {
    let scan = scan_delimiter_lines(body, boundary);

    // Nothing outside the delimiter lines is judged, and that is the spec's
    // instruction rather than this rule's convenience: the preamble and the
    // epilogue are to be ignored, so their content can neither satisfy a check
    // nor fail one.
    // cite(RFC 2046 § 5.1.1): "implementations must ignore anything that appears before the first boundary delimiter line or after the last one."
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

    // The closing line is defined as the one *following the last body part*, so
    // a body in which it is the only delimiter line has no part for it to
    // follow. §5.1.1 calls a single body part the useful minimum, not zero.
    // cite(RFC 2046 § 5.1.1): "The boundary delimiter line following the last body part is a distinguished delimiter that indicates that no further body parts will follow."
    // cite(RFC 2046 § 5.1.1): "The use of the "multipart" media type with only a single body part may be useful in certain contexts, and is explicitly permitted."
    if !scan.opens_a_part {
        return Some(Violation {
            rule: MessageMultipartContentTypeAndBodyConsistency.id().into(),
            severity: config.severity,
            message: format!(
                "Invalid multipart Content-Type in {}: the only boundary delimiter line is the terminating '--{}--', so the body encapsulates no part",
                which, boundary
            ),
        });
    }

    // Without the closing line nothing tells a recipient the parts have ended,
    // which is the whole function §5.1.1 gives it.
    // cite(RFC 2046 § 5.1.1): "Such a delimiter line is identical to the previous delimiter lines, with the addition of two more hyphens after the boundary parameter value."
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

    /// `multipart-body` brackets the preamble and the epilogue but not the
    /// first `dash-boundary ... body-part`, so a body whose only delimiter line
    /// is the closing one encapsulates nothing. This used to pass: the closing
    /// line starts with `--abc`, which was all the first check looked for, so
    /// that check could never fail while the second one passed.
    #[test]
    fn a_body_with_only_the_closing_delimiter_encapsulates_no_part() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        tx.response_body = Some(Bytes::from_static(b"--abc--\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .expect("a multipart body with no part is not a multipart body");
        assert!(v.message.contains("encapsulates no part"), "{v:?}");
    }

    /// A delimiter line written *after* the closing one is in the epilogue,
    /// which §5.1.1 says implementations must ignore, so it opens no part. The
    /// body below encapsulates nothing at all; counting that line would have
    /// let it pass the check added for exactly this case.
    #[test]
    fn a_delimiter_in_the_epilogue_opens_nothing() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        tx.response_body = Some(Bytes::from_static(b"--abc--\r\n--abc\r\nnot a part\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .expect("the only part-opening line is in the epilogue");
        assert!(v.message.contains("encapsulates no part"), "{v:?}");
    }

    /// The minimum RFC 2046 permits, and it must still pass: one part, opened
    /// by a delimiter line and closed by the terminating one.
    #[test]
    fn a_single_empty_part_is_permitted() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "multipart/mixed; boundary=abc")],
        );
        tx.response_body = Some(Bytes::from_static(b"--abc\r\n\r\n\r\n--abc--\r\n"));
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "one part is the documented minimum: {v:?}");
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

    /// A conforming body settles the question in its first two lines, and the
    /// scan must stop there. Without the early exit it read to the end of every
    /// well-formed multipart message — 34 ms of release-build work for a 16 MiB
    /// body whose answer was known after 150 bytes, and a body may be
    /// `max_body_bytes` large, 64 MiB by default.
    ///
    /// The bound is coarse on purpose: this guards against the scan losing its
    /// exit and walking the whole body again, which costs milliseconds, not
    /// against small changes in constant factors. The measured figure with the
    /// exit in place is tens of microseconds either way.
    #[test]
    fn a_settled_verdict_stops_the_scan() {
        let boundary = "a".repeat(70);
        let mut body = Vec::with_capacity(16 * 1024 * 1024);
        body.extend_from_slice(format!("--{boundary}\r\n\r\n\r\n--{boundary}--\r\n").as_bytes());
        body.resize(16 * 1024 * 1024, b'x');

        let started = std::time::Instant::now();
        let scan = scan_delimiter_lines(&body, &boundary);
        let elapsed = started.elapsed();

        assert!(scan.opens_a_part && scan.closes);
        assert!(
            elapsed < std::time::Duration::from_millis(50),
            "scanning 16 MiB took {elapsed:?}; the verdict was settled in the first two lines"
        );
    }

    /// Every published snippet is run through the rule, and each NonCompliant
    /// one is pinned to the finding it illustrates. Nothing in the engine does
    /// this, and a rule cannot catch a bad example of its own — the three
    /// families before this one each shipped a snippet their own rule judged
    /// differently from the label. Pinning the *specific* message matters here:
    /// every finding this rule emits mentions the boundary, so asserting that
    /// would assert nothing.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let reasons: [(&str, &str); 4] = [
            ("no boundaries here", "does not contain boundary marker"),
            (
                "--abc\nContent-Type: text/plain\n\nhello\n--abc",
                "missing terminating boundary",
            ),
            ("hello --abc-- world", "never at the start of a line"),
            ("--abc--", "encapsulates no part"),
        ];

        for ex in rule.examples() {
            let (head, body) = ex
                .snippet
                .split_once("\n\n")
                .unwrap_or_else(|| panic!("example has no body: {:?}", ex.snippet));
            let pairs: Vec<(&str, &str)> = head
                .lines()
                .filter(|l| !l.starts_with("HTTP/"))
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&pairs);
            tx.response_body = Some(Bytes::copy_from_slice(body.as_bytes()));

            let v = rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    v.is_none(),
                    "rule rejects its Compliant example {:?}: {v:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    let v = v.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    let expected = *reasons
                        .iter()
                        .find(|(b, _)| *b == body)
                        .map(|(_, reason)| reason)
                        .unwrap_or_else(|| {
                            panic!("NonCompliant example {body:?} has no expected finding here")
                        });
                    assert!(
                        v.message.contains(expected),
                        "NonCompliant example {body:?} should fail with {expected:?}: {v:?}"
                    );
                }
            }
        }
    }

    /// A recipient may act on any Content-Type line, so a multipart
    /// declaration on the second one names a boundary the body still has to
    /// use. Only the first line was ever read.
    #[test]
    fn every_content_type_line_is_read() {
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-type", "text/plain"),
            ("content-type", "multipart/mixed; boundary=abc"),
        ]);
        tx.response_body = Some(Bytes::from_static(b"no boundaries here"));
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some(), "the second line declares a boundary: {v:?}");
    }

    /// obs-text is legal in a quoted-string, so this is a well-formed
    /// media-type whose boundary is perfectly readable. `to_str` refused the
    /// whole value and the body went unchecked.
    #[test]
    fn obs_text_in_a_neighbouring_parameter_does_not_hide_the_boundary() {
        use hyper::header::HeaderValue;
        let rule = MessageMultipartContentTypeAndBodyConsistency;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers.insert(
            "content-type",
            HeaderValue::from_bytes(b"multipart/mixed; boundary=abc; foo=\"\xe4\"").unwrap(),
        );
        tx.response_body = Some(Bytes::from_static(b"no boundaries here"));
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some(), "the boundary is readable: {v:?}");
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
