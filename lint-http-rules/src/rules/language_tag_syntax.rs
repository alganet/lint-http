// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct LanguageTagSyntax;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_8_5_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.5.1",
    note: "Language Tags: the sentence that assigns a different production to each of the two fields — `language-range` for Accept-Language, `language-tag` for Content-Language",
};
const RFC_5646_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 5646",
    section: Some("2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc5646.html#section-2.1",
    note: "Syntax: the `Language-Tag` production Content-Language carries. Its prose properties are enforced; its subtag ordering and length classes are not",
};
const RFC_4647_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 4647",
    section: Some("2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc4647.html#section-2.1",
    note: "Basic Language Range: the production Accept-Language carries, including the `*` alternative and the statement that a range needs no well-formedness at all",
};
const RFC_9110_8_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.5",
    note:
        "Content-Language: `#language-tag` — a list of tags, with no wildcard and no weight in it",
};
const RFC_9110_12_5_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("12.5.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.4",
    note: "Accept-Language: where the `language-range` production is pulled in by reference. The weight beside it is `accept_language_weight_valid`'s subject",
};

impl Rule for LanguageTagSyntax {
    fn id(&self) -> &'static str {
        "language_tag_syntax"
    }

    // Content-Language describes a representation and travels in either
    // direction; Accept-Language is a request field this rule also reads in a
    // response, where §12.5.4 gives it no meaning (see
    // `accept_language_weight_valid`, which records the same
    // asymmetry). Either way both halves of a transaction are in scope.
    // cite(RFC 9110 § 8.5): "The "Content-Language" header field describes the natural language(s) of the intended audience for the representation."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
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
            // The two fields this rule reads do not use the same production, and
            // RFC 9110 says so in one sentence. `Content-Language` carries
            // `language-tag` (RFC 5646 §2.1); `Accept-Language` carries the broader
            // `language-range` (RFC 4647 §2.1, by way of §12.5.4). A range needs no
            // well-formedness at all — RFC 4647 says an ill-formed one "will
            // probably not match anything", which is a statement about matching, not
            // a licence to reject it.
            //
            // One validator serves both, and that is a choice rather than an
            // oversight: it checks the properties the two productions agree on and
            // nothing beyond. Where they differ it is lenient — `en-US-Latn` is a
            // conforming range and not a conforming tag, and `e` is a conforming
            // range whose single letter no `language` alternative admits — so a
            // Content-Language carrying either goes unreported here. Being stricter
            // would need two validators and a decision about how much of RFC 5646
            // to implement; being wrong in the other direction would report
            // conforming Accept-Language values, which is worse.
            // cite(RFC 9110 § 8.5.1): "HTTP uses language tags within the Accept-Language and Content-Language header fields.  Accept-Language uses the broader language-range production defined in Section 12.5.4, whereas Content-Language uses the language-tag production defined below."
            // cite(RFC 4647 § 2.1): "A basic language range differs from the language tags defined in [RFC4646] only in that there is no requirement that it be "well-formed" or be validated against the IANA Language Subtag Registry."
            let check_tag = |hdr: &str, tag: &str| -> Option<Violation> {
                // cite(RFC 9110 § 8.5.1): "A language tag, as defined in [RFC5646], identifies a natural language spoken, written, or otherwise conveyed by human beings for communication of information to other human beings."
                if let Err(e) = crate::helpers::language::validate_language_tag(tag) {
                    return Some(self.cited(
                        &RFC_9110_8_5_1,
                        ctx.severity,
                        format!("Invalid language tag '{}' in {}: {}", tag, hdr, e),
                    ));
                }
                None
            };

            // Both fields are lists, so a sender may spread their members over
            // several field lines and a recipient recombines them. Reading only the
            // first — `get_header_str` returns one value — left every later line
            // unchecked, and `accept_language_weight_valid` defers the
            // range's syntax to this rule, so for those lines the deferral pointed
            // at nobody.
            //
            // Each line is walked on its own rather than joined first, which for a
            // per-member syntax check is the same answer either way and keeps a
            // malformed line from being described in terms of its neighbour.
            // Decoded from the raw octets rather than through `to_str`, which
            // refuses everything outside visible US-ASCII and used to make the whole
            // field line vanish. Both productions here are ASCII throughout — no
            // quoted-string, so no `obs-text` anywhere — which means such an octet
            // is never a legal part of either, and skipping the line reported
            // nothing while hiding whatever else was on it:
            //
            //     Content-Language: en_US, <0xE4>
            //
            // has an underscore where a hyphen belongs, and said nothing at all.
            // The replacement character the decode leaves behind is not
            // alphanumeric, so the character check below reports it like any other
            // octet the grammar does not admit.
            // One `char` per octet, and not `String::from_utf8_lossy`: that decoder
            // reads the octets as UTF-8, so a sender's two `obs-text` octets arrive
            // as the one `char` they spell and an octet beginning no valid sequence
            // arrives as U+FFFD — a character no sender can write, and the one a
            // finding naming the character would then name.
            use crate::helpers::headers::field_line_as_written as decode;

            // `#language-tag`: a list of tags and nothing else. There is no
            // wildcard and no weight here, so a `*` or a `;q=` reaches the tag
            // validator and is reported as the invalid characters they are in this
            // field — which is the right verdict for the right reason.
            // cite(RFC 9110 § 8.5): "Content-Language = #language-tag"
            let content_language = |headers: &hyper::HeaderMap| -> Option<Violation> {
                for hv in headers.get_all("content-language").iter() {
                    let val = decode(hv);
                    for token in crate::helpers::headers::list_members(&val) {
                        if let Some(v) = check_tag("Content-Language", token) {
                            return Some(v);
                        }
                    }
                }
                None
            };

            let accept_language = |headers: &hyper::HeaderMap| -> Option<Violation> {
                for hv in headers.get_all("accept-language").iter() {
                    let val = decode(hv);
                    for member in crate::helpers::headers::list_members(&val) {
                        // The weight is stripped rather than checked; whether it is
                        // a weight at all is `accept_language_weight_valid`'s
                        // subject, and this rule reads only the range in front of it.
                        // `OWS` and not `str::trim`, which is what the walk above
                        // settled: the value is read one `char` per octet, so %xA0
                        // arrives as U+00A0, which `char::is_whitespace` admits —
                        // and this rule's own description says an octet outside
                        // visible US-ASCII is reported rather than skipped.
                        // cite(RFC 9110 § 12.4.2): "weight = OWS ";" OWS "q=" qvalue"
                        // cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
                        let lang =
                            crate::helpers::headers::trim_ows(member.split(';').next().unwrap());
                        // `*` is one of the two alternatives of `language-range`,
                        // not a tag — so it is skipped here and reported in
                        // Content-Language, where the production has no such
                        // alternative. The asymmetry is the two grammars', not this
                        // rule's.
                        // cite(RFC 4647 § 2.1): "language-range   = (1*8ALPHA *("-" 1*8alphanum)) / "*""
                        if lang == "*" {
                            continue;
                        }
                        if let Some(v) = check_tag("Accept-Language", lang) {
                            return Some(v);
                        }
                    }
                }
                None
            };

            if let Some(resp) = &tx.response {
                if let Some(v) = content_language(&resp.headers) {
                    return Some(v);
                }
            }
            if let Some(v) = content_language(&tx.request.headers) {
                return Some(v);
            }
            if let Some(v) = accept_language(&tx.request.headers) {
                return Some(v);
            }
            if let Some(resp) = &tx.response {
                if let Some(v) = accept_language(&resp.headers) {
                    return Some(v);
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Language Tag Format Valid")
    }

    fn description(&self) -> &'static str {
        "Check the language tags in `Content-Language` and the language ranges in `Accept-Language` for the syntax problems that are unambiguous: a non-alphanumeric character, whitespace, an empty subtag, a leading or trailing hyphen, a subtag longer than eight characters, and a first subtag that does not begin with a letter. Common forms pass — `en`, `en-US`, `zh-Hant`, `sr-Latn-RS`, `es-419`, and private-use tags like `x-custom`.\n\n**The two fields do not use the same production, and RFC 9110 §8.5.1 says so outright:** \"Accept-Language uses the broader `language-range` production defined in Section 12.5.4, whereas Content-Language uses the `language-tag` production defined below.\" A range is RFC 4647 §2.1; a tag is RFC 5646 §2.1. This rule's specifications used to claim that Accept-Language uses RFC 5646 tags, which is the opposite of what §8.5.1 says.\n\n**One validator serves both, and it checks only what the two productions agree on.** That is deliberate. RFC 4647 is explicit that a basic language range carries no well-formedness requirement at all — an ill-formed one \"will probably not match anything\", which is a statement about matching rather than a licence to reject it. So the check is set at the properties a range and a tag share, and **where they differ this rule is lenient toward Content-Language**: `en-US-Latn` is a conforming range and not a conforming tag (script must precede region), and `e` is a conforming range whose single letter no `language` alternative of RFC 5646 admits. Neither is reported. Being stricter would take two validators and a decision about how much of RFC 5646 to implement; being wrong in the other direction would report conforming `Accept-Language` values, which is worse.\n\n**`*` is skipped in Accept-Language and reported in Content-Language.** It is one of the two alternatives of `language-range` and is not a `language-tag`; `Content-Language = #language-tag` has no wildcard. The asymmetry belongs to the two grammars, not to this rule.\n\n**Weights are not read here.** In `Accept-Language` everything from the first `;` onward is stripped and left to `accept_language_weight_valid`; in `Content-Language` there is no `;` in the grammar, so one reaches the validator and is reported as the invalid character it is.\n\n**An octet outside visible US-ASCII is reported, not skipped.** Neither production has a quoted-string in it, so no such octet is ever legal here — and refusing to decode the value used to make the whole field line vanish, hiding any other defect on it.\n\n**Every field line of both fields is read**, since each is a list whose members may be spread across lines."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_8_5_1,
            RFC_5646_2_1,
            RFC_4647_2_1,
            RFC_9110_8_5,
            RFC_9110_12_5_4,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Accept-Language: en, fr-CA;q=0.8\nContent-Language: en-US",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the wildcard is a language-range, and digits are fine after the first subtag)"),
                snippet: "Accept-Language: *, es-419\nContent-Language: mi, en",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(an underscore is not a subtag separator)"),
                snippet: "Accept-Language: en_US",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a subtag is at most eight characters)"),
                snippet: "Content-Language: en-TooLongSubtag123",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(neither a tag nor a range may begin with a digit)"),
                snippet: "Accept-Language: 123-US",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(Content-Language has no wildcard alternative)"),
                snippet: "Content-Language: *",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &LanguageTagSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("en"), false)]
    #[case(Some("en-US"), false)]
    #[case(Some("zh-Hant, en;q=0.8"), false)]
    #[case(Some("*"), false)]
    #[case(Some("en_US"), true)]
    #[case(Some("en-TooLongSubtag123"), true)]
    #[case(None, false)]
    fn check_accept_language_request(
        #[case] cl: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = LanguageTagSyntax;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["language_tag_syntax"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = cl {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-language", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(Some("en, fr-CA"), false)]
    #[case(Some("en, en_US"), true)]
    fn check_content_language_response(
        #[case] cl: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = LanguageTagSyntax;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["language_tag_syntax"]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = cl {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-language", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = LanguageTagSyntax;
        assert_eq!(rule.id(), "language_tag_syntax");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    /// `to_str` refuses every octet outside visible US-ASCII, and the whole
    /// field line used to vanish with it — so a value with an obvious defect
    /// somewhere else on the line was reported by nothing. Neither production
    /// here has a quoted-string in it, so such an octet is never legal; it is
    /// reported like any other character the grammar does not admit.
    #[rstest]
    #[case("content-language", b"en_US, \xe4")]
    #[case("content-language", b"\xe4")]
    #[case("accept-language", b"en\xc2\xadus")]
    #[case("accept-language", b"\xe4, en_US")]
    fn a_non_ascii_octet_does_not_hide_the_line(#[case] header: &str, #[case] raw: &[u8]) {
        use hyper::header::HeaderValue;
        let rule = LanguageTagSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction();
        let name: hyper::header::HeaderName = header.parse().expect("valid header name");
        tx.request
            .headers
            .insert(name, HeaderValue::from_bytes(raw).unwrap());
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some(),
            "{header}: {:?} carries nothing this grammar admits",
            String::from_utf8_lossy(raw)
        );
    }

    /// Every published snippet is run through the rule, each NonCompliant one
    /// pinned to the finding it illustrates. These snippets carry two header
    /// lines apiece, so the parser has to feed both — an example that
    /// contrasts the two fields is only an example if both reach the rule.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = LanguageTagSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let reasons: [(&str, &str); 4] = [
            ("Accept-Language: en_US", "invalid character '_'"),
            ("Content-Language: en-TooLongSubtag123", "too long"),
            ("Accept-Language: 123-US", "does not begin with a letter"),
            ("Content-Language: *", "invalid character '*'"),
        ];

        for ex in rule.examples() {
            let pairs: Vec<(&str, &str)> = ex
                .snippet
                .lines()
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            let found = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule rejects its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    let found = found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    let expected = *reasons
                        .iter()
                        .find(|(s, _)| *s == ex.snippet)
                        .map(|(_, reason)| reason)
                        .unwrap_or_else(|| {
                            panic!(
                                "NonCompliant example {:?} has no expected finding here",
                                ex.snippet
                            )
                        });
                    assert!(
                        found.message.contains(expected),
                        "NonCompliant example {:?} should fail with {expected:?}: {found:?}",
                        ex.snippet
                    );
                }
            }
        }
    }

    /// Both fields are lists whose members may be spread over several field
    /// lines. Only the first was read, so a malformed tag on a later line was
    /// reported by nobody — and `accept_language_weight_valid`
    /// defers the range's syntax to this rule, so that deferral was false for
    /// exactly those lines.
    #[rstest]
    #[case("accept-language", &["en", "e n"], true)]
    #[case("accept-language", &["e n", "en"], true)]
    #[case("accept-language", &["en", "fr;q=0.5"], false)]
    #[case("content-language", &["en", "e n"], true)]
    #[case("content-language", &["en", "fr"], false)]
    fn every_field_line_is_read(
        #[case] header: &str,
        #[case] values: &[&str],
        #[case] expect_violation: bool,
    ) {
        let rule = LanguageTagSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction();
        let pairs: Vec<(&str, &str)> = values.iter().map(|v| (header, *v)).collect();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(
            v.is_some(),
            expect_violation,
            "{header} {values:?} -> {v:?}"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["language_tag_syntax"]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[rstest]
    #[case(Some("en, *;q=0.5"), false)]
    #[case(Some("en, en_US"), true)]
    fn check_accept_language_in_response(
        #[case] al: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = LanguageTagSyntax;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["language_tag_syntax"]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = al {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-language", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn check_content_language_in_request() -> anyhow::Result<()> {
        let rule = LanguageTagSyntax;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["language_tag_syntax"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-language", "en, fr")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    /// What `description()`'s *"An octet outside visible US-ASCII is reported,
    /// not skipped"* claims, on the two spellings that used to escape it. The
    /// value is read with `from_utf8_lossy` precisely so such an octet reaches
    /// `check_tag` — and %xA0 arrives as U+00A0, which `str::trim` calls
    /// whitespace, so the list walk took it off `Content-Language` and the
    /// weight split took it off `Accept-Language`. Both trims are `OWS` now, and
    /// no `language-tag` or `language-range` admits either octet.
    #[rstest]
    #[case("content-language", b"en-US\xA0")]
    #[case("accept-language", b"en-US\xA0")]
    fn an_obs_text_octet_shaped_like_a_space_is_still_reported(
        #[case] field: &str,
        #[case] value: &[u8],
    ) {
        let rule = LanguageTagSyntax;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["language_tag_syntax"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_octet_pairs(&[(field, value)]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some(), "{field} carrying %xA0 drew nothing");
    }
}
