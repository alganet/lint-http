// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MultipartBoundarySyntax;

impl Rule for MultipartBoundarySyntax {
    fn id(&self) -> &'static str {
        "multipart_boundary_syntax"
    }

    // The parameter this rule reads lives in Content-Type, and that field
    // describes a representation in either direction. RFC 9110 does not leave
    // this to inference for multipart in particular: it names a request type
    // and a response type in the same paragraph, multipart/form-data and
    // multipart/byteranges.
    // cite(RFC 9110 § 8.3): "The "Content-Type" header field indicates the media type of the associated representation: either the representation enclosed in the message content or the selected representation, as determined by the message semantics."
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
            // Every Content-Type field line, not just the first. `HeaderMap::get`
            // returns one value, and RFC 9110 §8.3 is explicit that implementations
            // differ over which member of a duplicated Content-Type they act on, so
            // no line can be dismissed as the one nobody reads. A multipart type
            // with no boundary is unusable whichever line the recipient picks.
            //
            // That there is more than one line is `content_type_valid`'s
            // finding; this rule says only what it owns.
            let check_all = |which: &str, headers: &hyper::HeaderMap| -> Option<Violation> {
                for hv in headers.get_all("content-type").iter() {
                    // Decoded from the raw octets rather than through `to_str`, which
                    // refuses anything outside visible US-ASCII and so refuses
                    // `obs-text` — legal inside a `quoted-string`. Skipping such a
                    // value meant `multipart/mixed; foo="<0xE4>"`, which has no
                    // boundary parameter at all, was reported by nothing. Where
                    // obs-text appears in the boundary itself the character check
                    // below rejects it, as `bcharsnospace` is US-ASCII throughout.
                    // cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
                    let s = crate::helpers::headers::field_line_as_written(hv);
                    if let Some(v) = check_multipart_boundary(which, &s, ctx.severity) {
                        return Some(v);
                    }
                }
                None
            };

            if let Some(v) = check_all("request", &tx.request.headers) {
                return Some(v);
            }

            if let Some(resp) = &tx.response {
                if let Some(v) = check_all("response", &resp.headers) {
                    return Some(v);
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Multipart Boundary Syntax")
    }

    fn description(&self) -> &'static str {
        "Check that a `Content-Type` naming a `multipart/*` media type carries a `boundary` parameter, and that the parameter's value is one RFC 2046 §5.1.1 allows: 1 to 70 characters drawn from `bchars` — letters, digits, `'`, `(`, `)`, `+`, `_`, `,`, `-`, `.`, `/`, `:`, `=`, `?` and space — and not ending in a space. A quoted value is judged after unescaping, since the quoted and unquoted forms name the same value.\n\n**RFC 9110 §8.3.3 is why a MIME rule applies to HTTP at all:** it adopts §5.1.1 wholesale for every multipart type and says the boundary parameter is part of the media type value. The two multipart types HTTP itself deals in run in opposite directions — `multipart/form-data` in requests, `multipart/byteranges` in 206 responses — which is why both are checked.\n\n**Quoting is often not optional.** Seven characters `bchars` permits (`(`, `)`, `,`, `/`, `:`, `=`, `?`) and space are not `tchar`, so a boundary using any of them can only be transmitted inside a quoted-string; unquoted, it is reported as an invalid token character. RFC 2046 warns implementors of exactly this.\n\n**Scope:** this rule reports only on the boundary parameter. A `Content-Type` that does not parse as a `media-type`, and the presence of more than one `Content-Type` field line, are both `content_type_valid`'s findings. Every `Content-Type` line in the header section of each message is read, since recipients differ over which one they act on; trailers are not read, as a `Content-Type` there is a framing question rather than a boundary one.\n\n**What is not checked:** this is a header rule, so the rest of RFC 2046 §5.1.1 — that the delimiter must not appear inside the encapsulated material, and that nested multipart entities must use different boundaries — is outside it. Whether the declared boundary actually delimits the body is `multipart_content_type_and_body_consistent`'s question. A conforming boundary also says nothing about message length: RFC 9110 §8.3.3 is explicit that HTTP framing does not use the boundary.\n\n**Quoting that never closes is declined, not guessed at.** After a stray `\"` no separator can be trusted, so `multipart/mixed; foo=\"unterminated; boundary=abc` is not reported as missing a boundary — whether that text is a parameter is precisely what the broken quoting makes unknowable, and the malformed value is `content_type_valid`'s finding. This applies only to the *absence* claim: a boundary the scan did find is still judged, so `boundary=\"unfinished` is reported as the malformed quoted-string it is.\n\n**Known leniency:** RFC 9110 §5.6.6 forbids whitespace around a parameter's `=`, and this rule trims it, so `boundary= abc` is accepted. It never causes a false report, only a missed one — and the missed report belongs to `content_type_valid`, which is lenient in the same place."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 2046",
                section: Some("5.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1",
                note: "Multipart common syntax: the required `boundary` parameter, the `boundary`/`bchars`/`bcharsnospace` grammar, the 1-to-70-character limit and the ban on a trailing space, and the warning that a boundary often has to be quoted",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.3",
                note: "Multipart Types: where HTTP adopts RFC 2046 §5.1.1 and makes the boundary part of the media type value. It also says HTTP framing does not use the boundary as a length indicator, so nothing here is a framing check",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6",
                note: "Parameters: the `parameters`/`parameter`/`parameter-value` grammar this walks, case-insensitive parameter names, and the equivalence of the quoted and unquoted forms",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1",
                note: "Media Type: the case-insensitivity of `type`, which is what scopes this rule to `multipart`",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Type: multipart/mixed; boundary=gc0p4Jq0M2Yt08j34c0p",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a colon is a bchars, so quoting makes it transmissible)"),
                snippet: "Content-Type: multipart/mixed; boundary=\"gc0pJq0M:08jU534c0p\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(space is a bchars everywhere but the last position)"),
                snippet: "Content-Type: multipart/mixed; boundary=\"simple boundary\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no boundary parameter)"),
                snippet: "Content-Type: multipart/mixed",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no boundary parameter: the text is inside another value)"),
                snippet: "Content-Type: multipart/mixed; foo=\"a; boundary=abc; b=1\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(nothing after the \"=\" is not a parameter-value)"),
                snippet: "Content-Type: multipart/mixed; boundary=",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(empty after unquoting)"),
                snippet: "Content-Type: multipart/mixed; boundary=\"\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(must not end in white space)"),
                snippet: "Content-Type: multipart/mixed; boundary=\"abc \"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a colon is not a tchar, so it must be quoted)"),
                snippet: "Content-Type: multipart/mixed; boundary=gc0pJq0M:08jU534c0p",
            },
        ]
    }
}

fn check_multipart_boundary(
    which: &str,
    val: &str,
    severity: crate::lint::Severity,
) -> Option<Violation> {
    // A value that is not a media-type at all has no type to compare and no
    // parameters to read. Saying so is `content_type_valid`'s
    // finding, not this one's; the `media-type` grammar is the helper's.
    let parsed = match crate::helpers::headers::parse_media_type(val) {
        Ok(p) => p,
        Err(_) => return None,
    };

    // The whole rule is scoped by this comparison: RFC 2046 §5.1.1 is the
    // syntax of multipart types and of nothing else, and RFC 9110 is where
    // HTTP adopts it — the boundary parameter is a requirement of the media
    // type, so a `text/plain; boundary=...` is simply not this rule's business.
    // The fold is the type's own matching rule, not a convenience.
    // cite(RFC 9110 § 8.3.3): "All multipart types share a common syntax, as defined in Section 5.1.1 of [RFC2046], and include a boundary parameter as part of the media type value."
    // cite(RFC 2046 § 5.1.1): "All subtypes of "multipart" must use this syntax."
    // cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
    if parsed.type_.eq_ignore_ascii_case("multipart") {
        // params must include boundary
        let mut found = false;
        // An odd number of DQUOTEs means the quoting never closes, and then no
        // parameter boundary past it can be trusted — everything after it
        // collapses into one segment. That makes the *absence* of a boundary
        // unknowable, and only the absence: a boundary parameter the scan did
        // find was legible enough to judge.
        let mut unreadable = false;
        if let Some(params) = parsed.params {
            unreadable = !crate::helpers::headers::quoting_is_balanced(params);
            // Quote-aware, because a `;` inside a quoted parameter value does not
            // start a new parameter. A raw `split(';')` cut such a value apart and
            // read the pieces as parameters of their own, in both directions: a
            // message whose only `boundary=` text sits inside another value was
            // credited with a boundary it does not have, and a fragment of a legal
            // quoted value was reported as a malformed boundary.
            //
            // The semicolon separator, the surrounding OWS this trims, and the
            // empty segment a trailing `;` leaves behind are all in the one
            // production: `[ parameter ]` is bracketed, so a parameter list may
            // end in a separator with nothing after it and still conform.
            // cite(RFC 9110 § 5.6.6): "parameters      = *( OWS ";" OWS [ parameter ] )"
            // The split, the bracketed-empty skip and the cut at the first `=`
            // are `helpers::headers::parameters`'s. A segment with no "=" is not
            // a parameter — `parameter` has both halves and the "=" is not
            // optional — but that it is malformed is
            // `content_type_valid`'s finding; this rule only needs
            // to know it is not the boundary, so it is skipped here.
            for parameter in crate::helpers::headers::parameters(params) {
                let Ok(parameter) = parameter else { continue };
                let value = parameter.value;
                // cite(RFC 9110 § 5.6.6): "Parameter names are case-insensitive."
                if parameter.name.eq_ignore_ascii_case("boundary") {
                    found = true;
                    // Nothing after the "=" is not a boundary that happens
                    // to be too short — it is not a `parameter-value` at
                    // all, since both alternatives are non-empty.
                    // cite(RFC 9110 § 5.6.6): "parameter-value = ( token / quoted-string )"
                    if value.is_empty() {
                        return Some(MultipartBoundarySyntax.violation(
                            severity,
                            format!(
                                "Invalid multipart Content-Type in {}: empty 'boundary' parameter",
                                which
                            ),
                        ));
                    }

                    // The two alternatives of `parameter-value`, each handed
                    // to the helper that owns its grammar. Which one was
                    // written decides nothing about the boundary itself:
                    // the checks below run on the unescaped value, because
                    // the two forms name the same value.
                    //
                    // The quoting is not a stylistic choice here. Seven
                    // characters `bchars` allows — "(", ")", ",", "/", ":",
                    // "=", "?" — and SP are not `tchar`, so a boundary using
                    // any of them can only be transmitted quoted, which is
                    // what RFC 2046 warns implementors about.
                    // cite(RFC 9110 § 5.6.6): "A parameter value that matches the token production can be transmitted either as a token or within a quoted-string."
                    // cite(RFC 9110 § 5.6.6): "The quoted and unquoted values are equivalent."
                    // cite(RFC 2046 § 5.1.1): "The grammar for parameters on the Content-type field is such that it is often necessary to enclose the boundary parameter values in quotes on the Content-type line."
                    let boundary_unquoted = if value.starts_with('"') {
                        // Unescape quoted-string interior using helper
                        match crate::helpers::headers::unescape_quoted_string(value) {
                            Ok(u) => u,
                            Err(e) => {
                                return Some(MultipartBoundarySyntax.violation(
                                    severity,
                                    format!(
                                        "Invalid multipart Content-Type in {}: boundary quoted-string invalid: {}",
                                        which, e
                                    ),
                                ))
                            }
                        }
                    } else {
                        // The unquoted alternative is `token`, and it is
                        // HTTP's `token` that applies: the transport decides
                        // what may be written bare in a parameter, whatever
                        // the media type's own definition of the value.
                        //
                        // RFC 2045's `token` is the wider of the two, by "{"
                        // and "}" — neither of which is a `bchars`, so both
                        // are rejected either way and only the wording of the
                        // finding differs.
                        if let Some(c) = crate::helpers::token::find_invalid_token_char(value) {
                            return Some(MultipartBoundarySyntax.violation(
                                severity,
                                format!(
                                    "Invalid multipart Content-Type in {}: boundary contains invalid token character '{}'",
                                    which, c
                                ),
                            ));
                        }
                        value.to_string()
                    };

                    // The character set is judged first, before the length,
                    // because the length is a count of characters and only a
                    // value drawn from this set has a meaningful one. A
                    // boundary of non-ASCII text was measured in bytes and
                    // reported as too long, which named a limit it might not
                    // have exceeded instead of the octets that are not
                    // `bchars` at all.
                    //
                    // The set below is `bchars` transcribed: `bcharsnospace`
                    // plus SP. It is not folded, and nothing here compares
                    // case — a boundary is matched against the delimiter
                    // lines in the content literally, which is the case-
                    // sensitive end of what §5.6.6 leaves to each parameter.
                    // cite(RFC 2046 § 5.1.1): "bchars := bcharsnospace / " ""
                    // cite(RFC 2046 § 5.1.1): "bcharsnospace := DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_" / "," / "-" / "." / "/" / ":" / "=" / "?""
                    // cite(RFC 9110 § 5.6.6): "Parameter values might or might not be case-sensitive, depending on the semantics of the parameter name."
                    for ch in boundary_unquoted.chars() {
                        if ch.is_ascii_alphanumeric()
                            || matches!(
                                ch,
                                '\'' | '('
                                    | ')'
                                    | '+'
                                    | '_'
                                    | ','
                                    | '-'
                                    | '.'
                                    | '/'
                                    | ':'
                                    | '='
                                    | '?'
                            )
                            || ch == ' '
                        {
                            continue;
                        }
                        return Some(MultipartBoundarySyntax.violation(
                            severity,
                            format!(
                                "Invalid multipart Content-Type in {}: boundary contains invalid character '{}'",
                                which, ch
                            ),
                        ));
                    }

                    // 70, not 69 and not 71: the production is 0*69 of
                    // `bchars` followed by one more character, and the prose
                    // states the same limit twice over. The zero case is
                    // what `boundary=""` leaves after unquoting, and the
                    // grammar has no empty alternative.
                    // cite(RFC 2046 § 5.1.1): "boundary := 0*69<bchars> bcharsnospace"
                    // cite(RFC 2046 § 5.1.1): "The only mandatory global parameter for the "multipart" media type is the boundary parameter, which consists of 1 to 70 characters from a set of characters known to be very robust through mail gateways, and NOT ending with white space."
                    let len = boundary_unquoted.chars().count();
                    if len == 0 || len > 70 {
                        return Some(MultipartBoundarySyntax.violation(
                            severity,
                            format!(
                                "Invalid multipart Content-Type in {}: 'boundary' must be between 1 and 70 characters",
                                which
                            ),
                        ));
                    }

                    // Space is the one whitespace character the check above
                    // lets through, so this is the grammar's "last character
                    // must be `bcharsnospace`" and nothing wider. The
                    // production says it in its shape — `bchars` may repeat,
                    // but the final character comes from the set without SP
                    // — and the prose says it in words, along with the
                    // reason: a gateway may have added that space, so a
                    // recipient cannot tell it from the delimiter's own.
                    // cite(RFC 2046 § 5.1.1): "boundary := 0*69<bchars> bcharsnospace"
                    if boundary_unquoted.ends_with(' ') {
                        return Some(MultipartBoundarySyntax.violation(
                            severity,
                            format!(
                                "Invalid multipart Content-Type in {}: 'boundary' must not end with whitespace",
                                which
                            ),
                        ));
                    }
                }
            }
        }

        // Absence is the finding here, and it is a requirement rather than a
        // default: without a boundary there is no delimiter line, so nothing in
        // the content can be told from anything else. RFC 2046 states it as a
        // requirement of the field and RFC 9110 repeats it for HTTP.
        // cite(RFC 2046 § 5.1.1): "The Content-Type field for multipart entities requires one parameter, "boundary"."
        // cite(RFC 2046 § 5.1.1): "The boundary delimiter line is then defined as a line consisting entirely of two hyphen characters ("-", decimal value 45) followed by the boundary parameter value from the Content-Type header field, optional linear whitespace, and a terminating CRLF."
        //
        // Not reported when the quoting never closed, because then this is a
        // claim the value cannot support: `foo="unterminated; boundary=abc`
        // plainly carries the text, and whether it is a parameter is exactly
        // what the broken quoting makes unknowable. An unreadable parameter
        // list is `content_type_valid`'s finding.
        if !found && !unreadable {
            return Some(MultipartBoundarySyntax.violation(
                severity,
                format!(
                    "Invalid multipart Content-Type in {}: missing required 'boundary' parameter",
                    which
                ),
            ));
        }
    }

    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MultipartBoundarySyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Every published snippet is run through this rule, and the Compliant ones
    /// through the other rules that read the same header — judged against
    /// `config_example.toml`, so the allowlists are the ones a reader has.
    /// Nothing in the engine does this, and a presence-and-syntax rule cannot
    /// catch a bad example of its own: two of the snippets here carried a
    /// trailing `# ...` comment *inside* the header value, which the rule
    /// reported for the wrong reason while the docs published it as the
    /// illustration of the right one.
    #[test]
    fn published_examples_survive_the_other_content_type_rules() {
        use crate::rules::{Compliance, Rule as _};
        let rule = MultipartBoundarySyntax;
        let toml_src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config_example.toml"),
        )
        .expect("config_example.toml must be readable");
        let cfg: crate::config::Config =
            toml::from_str(&toml_src).expect("config_example.toml must parse");
        // Rules that read Content-Type and can fire on a request. A media-type
        // allowlist is deliberately not among them: its silence is the
        // operator's policy, not a claim about whether this snippet is legal.
        let siblings: [(&str, &dyn Rule); 3] = [
            (
                "well-formed",
                &crate::rules::content_type_valid::ContentTypeValid,
            ),
            (
                "charset allowlist",
                &crate::rules::charset_registered::CharsetRegistered,
            ),
            (
                "suffix",
                &crate::rules::media_type_suffix_valid::MediaTypeSuffixValid,
            ),
        ];

        // Each NonCompliant snippet paired with the finding it is published to
        // illustrate. A snippet that reaches a different branch of the rule is
        // a broken example even though the rule reports it.
        let reasons: [(&str, &str); 6] = [
            (
                "Content-Type: multipart/mixed",
                "missing required 'boundary' parameter",
            ),
            (
                "Content-Type: multipart/mixed; foo=\"a; boundary=abc; b=1\"",
                "missing required 'boundary' parameter",
            ),
            (
                "Content-Type: multipart/mixed; boundary=",
                "empty 'boundary' parameter",
            ),
            (
                "Content-Type: multipart/mixed; boundary=\"\"",
                "must be between 1 and 70 characters",
            ),
            (
                "Content-Type: multipart/mixed; boundary=\"abc \"",
                "must not end with whitespace",
            ),
            (
                "Content-Type: multipart/mixed; boundary=gc0pJq0M:08jU534c0p",
                "invalid token character ':'",
            ),
        ];

        for ex in rule.examples() {
            let (k, v) = ex
                .snippet
                .split_once(": ")
                .unwrap_or_else(|| panic!("example is not `Name: value`: {:?}", ex.snippet));
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(k, v)]);
            let history = crate::transaction_history::TransactionHistory::empty();

            let found = crate::test_helpers::run_rule(&rule, &tx, &history, &cfg);
            match ex.compliance {
                Compliance::Compliant => {
                    assert!(
                        found.is_none(),
                        "rule rejects its Compliant example {:?}: {found:?}",
                        ex.snippet
                    );
                    for (name, sibling) in siblings {
                        let other = crate::test_helpers::run_rule(sibling, &tx, &history, &cfg);
                        assert!(
                            other.is_none(),
                            "the {name} rule rejects a Compliant example {:?}: {other:?}",
                            ex.snippet
                        );
                    }
                }
                Compliance::NonCompliant => {
                    let found = found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    // Not `found.rule == rule.id()`, which is unconditionally
                    // true, and not merely that the message says "boundary",
                    // which every message this rule emits does — that is how
                    // the two examples with a comment inside the header value
                    // passed for years while illustrating the wrong finding.
                    // Each NonCompliant example is pinned to the finding it is
                    // published to demonstrate.
                    let expected = *reasons
                        .iter()
                        .find(|(snippet, _)| *snippet == ex.snippet)
                        .map(|(_, reason)| reason)
                        .unwrap_or_else(|| {
                            panic!(
                                "NonCompliant example {:?} has no expected finding in this test",
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

    /// `boundary := 0*69<bchars> bcharsnospace` puts the limit at 70, so 70 is
    /// the longest conforming value and 71 the shortest over-long one. Only the
    /// over-long side was ever exercised, and by a test that re-implemented the
    /// parameter scan rather than running the rule — so the boundary itself, the
    /// one place an off-by-one can hide, went untested.
    #[rstest]
    #[case(69, false)]
    #[case(70, false)]
    #[case(71, true)]
    fn boundary_length_limit(#[case] len: usize, #[case] expect_violation: bool) {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "multipart_boundary_syntax",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        let header = format!("multipart/mixed; boundary={}", "a".repeat(len));
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", &header)]);
        let v = crate::test_helpers::run_rule(
            &MultipartBoundarySyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{len} characters -> {v:?}");
    }

    /// A boundary of non-ASCII characters is short and entirely outside
    /// `bchars`. Measured in bytes it also looked too long, and the rule named
    /// the length — a limit this value does not exceed — instead of the
    /// characters that are the actual problem.
    #[test]
    fn non_ascii_boundary_is_reported_as_a_character_problem() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "multipart_boundary_syntax",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        let header = format!("multipart/mixed; boundary=\"{}\"", "é".repeat(36));
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", &header)]);
        let v = crate::test_helpers::run_rule(
            &MultipartBoundarySyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let msg = v.expect("36 non-bchars characters is a violation").message;
        assert!(msg.contains("invalid character"), "{msg}");
    }

    #[rstest]
    #[case(Some("multipart/mixed; boundary=gc0p4Jq0M2Yt08j34c0p"), false)]
    #[case(
        Some("multipart/mixed; boundary=gc0p4Jq0M2Yt08j34c0p; charset=utf-8"),
        false
    )]
    #[case(Some("multipart/mixed; boundary=\"gc0pJq0M:08jU534c0p\""), false)]
    #[case(Some("multipart/mixed"), true)]
    #[case(Some("multipart/mixed; boundary="), true)]
    #[case(Some("multipart/mixed; boundary=\"\""), true)]
    #[case(Some("multipart/mixed; boundary=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabb"), true)] // >70 chars
    #[case(Some("multipart/mixed; boundary=gc0pJq0M:08jU534c0p"), true)]
    #[case(Some("multipart/mixed; boundary=\"abc \""), true)]
    // A `;` inside a quoted value is not a parameter separator. There is no
    // boundary parameter here at all — the text that looks like one is part of
    // `foo`'s value — so the missing boundary must still be reported.
    #[case(Some("multipart/mixed; foo=\"a; boundary=abc; b=1\""), true)]
    // The mirror image: a real, valid boundary alongside a quoted value whose
    // interior merely reads like a malformed boundary parameter.
    #[case(
        Some("multipart/mixed; boundary=abc; foo=\"q; boundary=in:valid\""),
        false
    )]
    // A quoted value carrying a `;` does not hide the real boundary that follows.
    #[case(Some("multipart/mixed; foo=\"a;b\"; boundary=abc"), false)]
    // Quoting that never closes makes the absence of a boundary unknowable, so
    // the rule declines rather than announce one is missing from a value that
    // plainly carries the text.
    #[case(Some("multipart/mixed; foo=\"unterminated; boundary=abc"), false)]
    #[case(Some("multipart/mixed; p=a\"b"), false)]
    // A boundary the scan did find is still judged: the parameter was legible,
    // and its own quoting is the thing that broke.
    #[case(Some("multipart/mixed; boundary=\"unfinished"), true)]
    // A valid boundary before the break is still valid.
    #[case(Some("multipart/mixed; boundary=abc; foo=\"x"), false)]
    // A backslash outside a quoted-string escapes nothing, so this list is
    // readable and the missing boundary is a real finding.
    #[case(Some("multipart/mixed; p=a\\"), true)]
    // Balanced quoting with no boundary is reported, so the gate narrows
    // nothing it should not.
    #[case(Some("multipart/mixed; foo=\"a;b\""), true)]
    #[case(None, false)]
    fn multipart_boundary_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "multipart_boundary_syntax",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(h) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", h)]);
        }

        let v = crate::test_helpers::run_rule(
            &MultipartBoundarySyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for {:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for {:?}: {:?}",
                header,
                v
            );
        }

        // Also test response
        let cfg2 = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "multipart_boundary_syntax",
        ]);
        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(h) = header {
            tx2.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", h)]);
        }
        let v2 = crate::test_helpers::run_rule(
            &MultipartBoundarySyntax,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg2,
        );
        if expect_violation {
            assert!(v2.is_some(), "expected violation for response {:?}", header);
        } else {
            assert!(
                v2.is_none(),
                "unexpected violation for response {:?}: {:?}",
                header,
                v2
            );
        }
    }

    #[test]
    fn parse_media_type_error_no_violation() {
        // malformed Content-Type that fails parse_media_type should not cause this rule to run
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "multipart_boundary_syntax",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "not-a-media-type")]);
        let v = crate::test_helpers::run_rule(
            &MultipartBoundarySyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_string_unterminated_reports_violation() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "multipart_boundary_syntax",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        // boundary quoted-string not terminated
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "multipart/mixed; boundary=\"unfinished",
        )]);
        let v = crate::test_helpers::run_rule(
            &MultipartBoundarySyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("boundary quoted-string invalid"));
    }

    #[rstest]
    // obs-text is legal inside a quoted-string, so these are well-formed
    // media-types whose boundary still has to be judged. `to_str` refused them
    // and the rule went silent, so a multipart type with no boundary at all went
    // unreported for the sake of an octet in a neighbouring parameter.
    #[case(b"multipart/mixed; foo=\"\xe4\"", true)]
    #[case(b"multipart/mixed; boundary=\"a\xe4b\"", true)]
    // obs-text elsewhere does not make a valid boundary invalid.
    #[case(b"multipart/mixed; boundary=abc; foo=\"\xe4\"", false)]
    fn obs_text_does_not_hide_the_boundary(#[case] raw: &[u8], #[case] expect_violation: bool) {
        use hyper::header::HeaderValue;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "multipart_boundary_syntax",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .insert("content-type", HeaderValue::from_bytes(raw).unwrap());
        let v = crate::test_helpers::run_rule(
            &MultipartBoundarySyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(
            v.is_some(),
            expect_violation,
            "{:?} -> {v:?}",
            String::from_utf8_lossy(raw)
        );
    }

    #[rstest]
    // A recipient may act on any of the lines, so a multipart type missing its
    // boundary is a finding wherever it sits. Only the first was ever read.
    #[case(&["text/plain", "multipart/mixed"], true)]
    #[case(&["multipart/mixed; boundary=abc", "multipart/mixed"], true)]
    #[case(&["multipart/mixed; boundary=abc", "text/plain"], false)]
    fn every_field_line_is_checked(#[case] values: &[&str], #[case] expect_violation: bool) {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "multipart_boundary_syntax",
        ]);
        let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("content-type", *v)).collect();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
        let v = crate::test_helpers::run_rule(
            &MultipartBoundarySyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{values:?} -> {v:?}");
    }

    #[test]
    fn non_multipart_ignored() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "multipart_boundary_syntax",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; boundary=abc",
        )]);
        let v = crate::test_helpers::run_rule(
            &MultipartBoundarySyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_string_invalid_char_reports_violation() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "multipart_boundary_syntax",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        // $ is not permitted in bchars set
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "multipart/mixed; boundary=\"bad$\"",
        )]);
        let v = crate::test_helpers::run_rule(
            &MultipartBoundarySyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("boundary contains invalid character"));
    }
}
