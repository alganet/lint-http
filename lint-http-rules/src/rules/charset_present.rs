// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::content_type::{CONTENT_TYPE_CHARSET_MISSING, RFC_9110_8_3_2};
use crate::violations::ViolationDef;

/// One entry: a text media type that does not say which encoding it used.
static DECLARED: &[&ViolationDef] = &[&CONTENT_TYPE_CHARSET_MISSING];

pub struct CharsetPresent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_8_3_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1",
    note: "`media-type` and the case-insensitivity of its type/subtype tokens, which decides what counts as `text/*` here",
};
const HTML_SEMANTICS_4_2_5_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "HTML Semantics",
    section: Some("4.2.5.4"),
    url: "https://html.spec.whatwg.org/multipage/semantics.html#charset",
    note: "Specifying the document's character encoding — the three places an HTML page may declare it, of which this field is the only one a header reader sees",
};
const MDN_CONTENT_TYPE: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN Content-Type",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type",
    note: "Content-Type",
};

impl RuleMeta for CharsetPresent {
    fn id(&self) -> &'static str {
        "charset_present"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "This rule checks if `Content-Type` headers for text-based resources (starting with `text/`) include a `charset` parameter. Responses only, and the type is matched case-insensitively, so `TEXT/HTML` is in scope.\n\nThe parameter tells a recipient which character encoding the text was written in. Without it the recipient looks to the content itself, and where the content declares nothing either, it decodes by a default or a guess of its own — and text decoded in an encoding it was not written in is garbled. For `text/html` the finding says where else the page may declare it: HTML requires a page with no byte order mark and no `charset` here to carry a `<meta charset>`, and a header reader cannot see which of those a page has.\n\nNo specification requires the parameter — RFC 9110 defines what `charset` means and mandates nothing about sending it — so this rule is a deliberate policy rather than a conformance check. Only the parameter's presence is checked; whether its value names a registered charset is a separate rule's concern.\n\n**A response with no content to render is skipped**: `1xx`, `204`, `205` and `304`. The hazard this rule names is a recipient guessing the encoding of text it is about to render, and none of those messages carries any — the field beside them describes something the recipient is not receiving. A `304` is the case where the advice was not merely idle but contradictory, since §15.4.5 tells the sender not to generate representation metadata on one at all and `status_304_representation_metadata` reports it. **A response to `HEAD` is deliberately not skipped**: §8.2 makes its representation header fields describe the data a `GET` would have enclosed, so a charset absent there is absent from the representation.

The parameter list is read quote-aware, so a `;` inside a quoted value does not start a new parameter and text that merely looks like `charset=` inside another value does not count. If the quoting never closes, the rule declines to judge rather than report a charset missing that the value plainly carries — an unreadable parameter list is `content_type_valid`'s finding, not an absent charset."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_8_3_1,
            RFC_9110_8_3_2,
            HTML_SEMANTICS_4_2_5_4,
            MDN_CONTENT_TYPE,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/html\n# Missing charset parameter",
            },
        ]
    }
}

impl Rule for CharsetPresent {
    fn needs_response(&self) -> bool {
        true
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
            // Response-only, though Content-Type is equally a request field. The concern
            // driving this rule — a recipient guessing the encoding of text it renders —
            // is a response-side one, so a request that omits charset is left alone.
            // A scope choice, not something a sentence narrows.
            let Some(resp) = &tx.response else {
                return None;
            };

            // A message with no content has no text for a recipient to render, so
            // the hazard this rule names is not reachable from it and the advice
            // improves a field describing nothing. The sibling that reads the same
            // field for its *presence*, `content_type_present`, has asked this
            // since a 205 was reported for omitting a Content-Type it had nothing
            // to describe; this rule never asked it at all.
            // cite(RFC 9112 § 6.3): "Any response to a HEAD request and any response with a 1xx (Informational), 204 (No Content), or 304 (Not Modified) status code is always terminated by the first empty line after the header fields, regardless of the header fields present in the message, and thus cannot contain a message body or trailer section."
            // cite(RFC 9110 § 15.3.6): "Since the 205 status code implies that no additional content will be provided, a server MUST NOT generate content in a 205 response."
            //
            // **The 304 is the case that makes it a contradiction rather than
            // merely idle advice.** § 15.4.5 tells the sender not to generate
            // representation metadata on one at all, and
            // `status_304_representation_metadata` says so, so a report carrying
            // both told an operator to take the field off and to improve it.
            //
            // **A HEAD response is deliberately not in this set**, and the
            // difference is a sentence rather than a preference: § 8.2 makes the
            // representation header fields of a HEAD response describe the data a
            // GET would have enclosed, so a charset absent there is absent from
            // the representation itself and an operator can act on it. § 6.3
            // groups HEAD with these statuses for *framing*, which is a different
            // question from whether the field describes anything.
            // cite(RFC 9110 § 8.2): "In a response to a HEAD request, the representation header fields describe the representation data that would have been enclosed in the content if the same request had been a GET."
            let status = resp.status;
            if (100..200).contains(&status) || status == 204 || status == 205 || status == 304 {
                return None;
            }

            if let Some(ct_str) =
                crate::helpers::headers::get_header_str(&resp.headers, "content-type")
            {
                // Parse content-type to inspect type and parameters reliably
                // The `media-type` grammar itself is owned by the helper; what matters
                // here is that the top-level type compares case-insensitively, so
                // `TEXT/HTML` is in scope exactly as `text/html` is.
                // cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
                if let Ok(parsed) = crate::helpers::media_type::parse_media_type(ct_str) {
                    let essence = format!(
                        "{}/{}",
                        parsed.type_.to_ascii_lowercase(),
                        parsed.subtype.to_ascii_lowercase()
                    );
                    if parsed.type_.eq_ignore_ascii_case("text") {
                        // Parameter *names* are case-insensitive too, which is why the
                        // key comparison folds case. Only the name is compared — the
                        // charset value is never inspected here, so this rule takes no
                        // position on whether it is registered (that is the IANA-charset
                        // rule's job).
                        // cite(RFC 9110 § 8.3.2): "HTTP uses "charset" names to indicate or negotiate the character encoding scheme"
                        let params = parsed.params.unwrap_or("");

                        // An odd number of DQUOTEs means the quoting never closes,
                        // and then no parameter boundary after it can be trusted.
                        // Saying "missing charset" about such a value would be a
                        // false statement — `text/html; p="x; charset=utf-8` plainly
                        // carries one — so the rule declines to judge instead. The
                        // malformed value is `content_type_valid`'s
                        // finding; unreadable parameters are not an absent charset.
                        // The check lives beside the splitter it guards, so the two
                        // cannot drift apart over what counts as a quote.
                        if !crate::helpers::list::quoting_is_balanced(params) {
                            return None;
                        }

                        // Quote-aware: a `;` inside a quoted parameter value does not
                        // start a new parameter. A raw `split(';')` cut such a value
                        // apart and then read the pieces as parameters, so text that
                        // merely *looks* like `charset=` inside another value — say
                        // `boundary="x; charset=utf-8"` — satisfied this check and
                        // suppressed the finding for a response that has no charset.
                        let has_charset =
                            crate::helpers::list::split_semicolons_respecting_quotes(params)
                                .into_iter()
                                .any(|p| {
                                    let p = p.trim();
                                    p.split_once('=')
                                        .map(|(k, _)| k.trim().eq_ignore_ascii_case("charset"))
                                        .unwrap_or(false)
                                });

                        // No specification requires `charset` on a `text/*` response — searched
                        // for, not found. RFC 9110 mentions the parameter twice and mandates
                        // nothing; MDN defines it and stops there. Requiring it is this linter's
                        // policy, and the cite is the definition it rests on, not a MUST it does
                        // not have.
                        // cite(MDN Content-Type): "Indicates the character encoding standard used. The value is case insensitive but lowercase is preferred."
                        if !has_charset {
                            return Some(ctx.report_with(
                                &CONTENT_TYPE_CHARSET_MISSING,
                                missing_sentence(ct_str, &essence),
                            ));
                        }
                    }
                }
            }
            None
        };
        Vec::from_iter(finding())
    }
}

/// The finding, naming the value that drew it and what a recipient does
/// without the parameter.
///
/// **An HTML page has two other places to say it**, and HTML requires one of
/// the three: a page that starts with no byte order mark and gets no `charset`
/// here must carry a `<meta charset>`. A header reader sees only this one, so
/// the sentence names the other two rather than implying the page declares
/// nothing. For every other `text/*` type the sentence claims no more than the
/// message shows: its fields do not say, and a recipient falls back on the
/// content or on a default of its own.
// cite(HTML Semantics § 4.2.5.4): "If an HTML document does not start with a BOM, and its encoding is not explicitly given by Content-Type metadata, and the document is not an iframe srcdoc document, then the encoding must be specified using a meta element with a charset attribute or a meta element with an http-equiv attribute in the Encoding declaration state."
fn missing_sentence(value: &str, essence: &str) -> String {
    if essence == "text/html" {
        format!(
            "Content-Type '{value}' names no charset, so HTML requires the page itself to \
             declare its encoding, with a byte order mark or a `<meta charset>` element, which \
             a reader of the header fields cannot see; naming it here, as in \
             `text/html; charset=utf-8` for a UTF-8 page, declares it without relying on the \
             markup"
        )
    } else {
        format!(
            "Content-Type '{value}' names no charset, so nothing in the message says which \
             character encoding its text is in, and a recipient decodes it by what the \
             content declares, if anything, or by a default of its own"
        )
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CharsetPresent;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case("text/html; charset=utf-8", false, None)]
    #[case("text/html;charset=utf-8", false, None)]
    #[case("TEXT/HTML;CHARSET=UTF-8", false, None)]
    #[case(
        "text/html",
        true,
        Some("Content-Type 'text/html' names no charset, so HTML requires the page itself to declare its encoding, with a byte order mark or a `<meta charset>` element, which a reader of the header fields cannot see; naming it here, as in `text/html; charset=utf-8` for a UTF-8 page, declares it without relying on the markup")
    )]
    // A `;` inside a quoted parameter value is not a separator, so the text
    // `charset=` inside another value is not a charset parameter and must not
    // suppress the finding.
    #[case(
        "text/html; boundary=\"x; charset=utf-8\"",
        true,
        Some("Content-Type 'text/html; boundary=\"x; charset=utf-8\"' names no charset, so HTML requires the page itself to declare its encoding, with a byte order mark or a `<meta charset>` element, which a reader of the header fields cannot see; naming it here, as in `text/html; charset=utf-8` for a UTF-8 page, declares it without relying on the markup")
    )]
    // A real charset following a quoted value that carries a ";" is still found.
    #[case("text/html; boundary=\"a;b\"; charset=utf-8", false, None)]
    // Unbalanced quoting: no parameter boundary after the stray DQUOTE can be
    // trusted, and a charset is plainly present, so "missing charset" would be
    // a false statement. The malformed value is a sibling's finding.
    #[case("text/html; p=a\"b; charset=utf-8", false, None)]
    #[case("text/html; p=\"a\"\"; charset=utf-8", false, None)]
    #[case("text/html; p=\"x; charset=utf-8", false, None)]
    // A backslash outside a quoted-string escapes nothing, so this list is
    // readable and the charset is found.
    #[case(r"text/html; p=a\; charset=utf-8", false, None)]
    // Balanced quoting with no charset is still reported.
    #[case(
        "text/html; p=\"a;b\"",
        true,
        Some("Content-Type 'text/html; p=\"a;b\"' names no charset, so HTML requires the page itself to declare its encoding, with a byte order mark or a `<meta charset>` element, which a reader of the header fields cannot see; naming it here, as in `text/html; charset=utf-8` for a UTF-8 page, declares it without relying on the markup")
    )]
    // Every other text type is told only what the message shows: its fields do
    // not say, and the recipient falls back on the content or a default. The
    // HTML sentence is said of `text/html` in any case and of nothing else.
    #[case(
        "text/css",
        true,
        Some("Content-Type 'text/css' names no charset, so nothing in the message says which character encoding its text is in, and a recipient decodes it by what the content declares, if anything, or by a default of its own")
    )]
    #[case(
        "TEXT/HTML",
        true,
        Some("Content-Type 'TEXT/HTML' names no charset, so HTML requires the page itself to declare its encoding, with a byte order mark or a `<meta charset>` element, which a reader of the header fields cannot see; naming it here, as in `text/html; charset=utf-8` for a UTF-8 page, declares it without relying on the markup")
    )]
    #[case(
        "text/x-javascript",
        true,
        Some("Content-Type 'text/x-javascript' names no charset, so nothing in the message says which character encoding its text is in, and a recipient decodes it by what the content declares, if anything, or by a default of its own")
    )]
    #[case("application/json", false, None)]
    #[case("", false, None)]
    fn check_response_cases(
        #[case] content_type: &str,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = CharsetPresent;

        let mut tx = crate::test_helpers::make_test_transaction();
        if !content_type.is_empty() {
            tx.response = Some(crate::http_transaction::ResponseInfo {
                status: 200,
                version: "HTTP/1.1".into(),
                headers: crate::test_helpers::make_headers_from_pairs(&[(
                    "content-type",
                    content_type,
                )]),

                body_length: None,
                body_interrupted: false,
                trailers: None,
            });
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            // The absence one sentence asks about outranks the one no sentence
            // asks about, which is the whole of this subject's ranking.
            let found = violation.clone().expect("a finding");
            assert_eq!(found.violation, "content_type_charset_missing");
            assert_eq!(found.severity, crate::lint::Severity::Info);
            assert_eq!(
                violation.map(|v| v.message),
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    /// A message with no content has no text to render, so `text/html` without
    /// a charset beside it describes something the recipient is not receiving.
    ///
    /// **The `304` row is the one that was a contradiction and not merely idle
    /// advice**: § 15.4.5 tells the sender not to generate the field at all, and
    /// `status_304_representation_metadata` says so, so one report carried both
    /// "take it off" and "improve it".
    #[rstest]
    #[case(100)]
    #[case(204)]
    #[case(205)]
    #[case(304)]
    fn a_response_with_no_content_is_not_asked_for_a_charset(#[case] status: u16) {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            status,
            &[("content-type", "text/html")],
        );
        let found = crate::test_helpers::run_rule_all(
            &CharsetPresent,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["charset_present"]),
        );
        assert!(found.is_empty(), "{status}: {found:?}");
    }

    /// A response to `HEAD` is not in that set, and the difference is § 8.2
    /// rather than a preference: its representation header fields describe the
    /// data a `GET` would have enclosed, so the charset is absent from the
    /// representation and an operator can act on it. § 6.3 groups `HEAD` with
    /// those statuses for *framing*, which is a different question.
    #[test]
    fn a_head_response_is_still_asked_for_a_charset() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text/html")],
        );
        tx.request.method = "HEAD".into();
        let found = crate::test_helpers::run_rule_all(
            &CharsetPresent,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["charset_present"]),
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].violation, "content_type_charset_missing");
    }
}
