// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

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
const RFC_9110_8_3_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2",
    note: "What `charset` is for. Note it mandates nothing: no requirement to send the parameter exists, so flagging its absence is this linter's policy",
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

    fn description(&self) -> &'static str {
        "This rule checks if `Content-Type` headers for text-based resources (starting with `text/`) include a `charset` parameter. Responses only, and the type is matched case-insensitively, so `TEXT/HTML` is in scope.\n\nSpecifying the character encoding is crucial for security and correct rendering. If the charset is not explicitly defined, browsers may attempt to guess the encoding (MIME sniffing), which can lead to Cross-Site Scripting (XSS) vulnerabilities or incorrect display of characters.\n\nNo specification requires the parameter — RFC 9110 defines what `charset` means and mandates nothing about sending it — so this rule is a deliberate policy rather than a conformance check. Only the parameter's presence is checked; whether its value names a registered charset is a separate rule's concern.\n\nThe parameter list is read quote-aware, so a `;` inside a quoted value does not start a new parameter and text that merely looks like `charset=` inside another value does not count. If the quoting never closes, the rule declines to judge rather than report a charset missing that the value plainly carries — an unreadable parameter list is `content_type_valid`'s finding, not an absent charset."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_8_3_1, RFC_9110_8_3_2, MDN_CONTENT_TYPE]
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
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
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

            if let Some(ct_str) =
                crate::helpers::headers::get_header_str(&resp.headers, "content-type")
            {
                // Parse content-type to inspect type and parameters reliably
                // The `media-type` grammar itself is owned by the helper; what matters
                // here is that the top-level type compares case-insensitively, so
                // `TEXT/HTML` is in scope exactly as `text/html` is.
                // cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
                if let Ok(parsed) = crate::helpers::media_type::parse_media_type(ct_str) {
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
                            return Some(self.cited(
                                &MDN_CONTENT_TYPE,
                                ctx.severity,
                                "Text-based Content-Type header missing charset parameter.".into(),
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
        Some("Text-based Content-Type header missing charset parameter.")
    )]
    // A `;` inside a quoted parameter value is not a separator, so the text
    // `charset=` inside another value is not a charset parameter and must not
    // suppress the finding.
    #[case(
        "text/html; boundary=\"x; charset=utf-8\"",
        true,
        Some("Text-based Content-Type header missing charset parameter.")
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
        Some("Text-based Content-Type header missing charset parameter.")
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
            assert!(violation.is_some());
            assert_eq!(
                violation.map(|v| v.message),
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }
}
