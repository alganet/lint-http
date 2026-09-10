// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::media_type::MediaTypeError;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::media_type::{
    media_type_error, MEDIA_TYPE_EMPTY, MEDIA_TYPE_MALFORMED, MEDIA_TYPE_WILDCARD_FORBIDDEN,
    RFC_9110_12_5_1, RFC_9110_8_3_1,
};
use crate::violations::parameter::{
    PARAMETER_EQUALS_MISSING, PARAMETER_VALUE_EMPTY, RFC_9110_5_6_6,
};
use crate::violations::quoted_pair::QUOTED_PAIR_MALFORMED;
use crate::violations::quoted_string::{
    QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN, QUOTED_STRING_DELIMITER_MISSING,
    QUOTED_STRING_QUOTE_ESCAPE_MISSING, RFC_9110_5_6_4,
};
use crate::violations::token::{
    RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY, TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct ContentTypeValid;

/// What this rule reports about the parts of a `media-type`, and not one of
/// them is this field's. `Content-Type = media-type` is a type, a subtype and
/// the parameters after them, so every defect below belongs to the production
/// the failing part is written in: both halves and every parameter name are
/// `token`s, a parameter value is `( token / quoted-string )`, and the `=` that
/// joins a parameter's halves is § 5.6.6's. `Accept-Patch` declares the same
/// nine, because `1#media-type` asks the same question of each of its members.
///
/// What is left over is the pair itself, and it has a subject now: the two
/// shapes `parse_media_type` refuses — no `/` and an empty half — and the
/// wildcard, which is a `tchar` the grammar admits and a *range* where one
/// media type belongs. Those three are `media_type`'s, and the duplicated field
/// line is the `field` subject's, so this rule words none of its findings.
///
/// One of the nine cannot be reached through a field line, and is declared
/// because the mapping is exhaustive rather than because this rule can report
/// it: `quoted_string_control_character_forbidden` needs an octet below SP that
/// is not HTAB, and a `HeaderValue` holds none. The same is true of every rule
/// declaring that subject, and the reachability question belongs to the
/// reading of every body rather than to this list.
static DECLARED: &[&ViolationDef] = &[
    &FIELD_LINE_DUPLICATED,
    &MEDIA_TYPE_EMPTY,
    &MEDIA_TYPE_MALFORMED,
    &MEDIA_TYPE_WILDCARD_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_EMPTY,
    &PARAMETER_EQUALS_MISSING,
    &PARAMETER_VALUE_EMPTY,
    &QUOTED_STRING_DELIMITER_MISSING,
    &QUOTED_PAIR_MALFORMED,
    &QUOTED_STRING_QUOTE_ESCAPE_MISSING,
    &QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_8_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3",
    note: "Content-Type: `Content-Type = media-type`, and the paragraph naming duplicated field lines as an error whose recipient handling differs between implementations",
};

impl RuleMeta for ContentTypeValid {
    fn id(&self) -> &'static str {
        "content_type_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Content-Type Well-Formed")
    }

    fn description(&self) -> &'static str {
        "Check that a `Content-Type` header — in a request or a response — reads as a valid `media-type`: a non-empty `type` and `subtype`, each a `token`, separated by `/`, followed by well-formed parameters if any are present. A parameter is a `name=value` pair whose name is a `token` and whose value is a `token` or a `quoted-string`; a trailing `;` with nothing after it is fine, since the grammar brackets each parameter as optional.\n\n**More than one `Content-Type` field line is reported.** RFC 9110 §8.3 calls Content-Type a singleton and says duplicated ones are handled by recipients \"using the last syntactically valid member of the list, leading to potential interoperability and security issues if different implementations have different error handling behaviors\" — so the media type a peer acts on is not the one the message states. Header and trailer sections are counted together.\n\n**A wildcard is reported**, though `*` is a legal `token` and `text/*` parses as a `media-type`. The asterisk is defined in §12.5.1 as what groups media types into *ranges* — `media-range`, which Accept takes and Content-Type does not — so a Content-Type carrying one names a set where a single media type is expected. This is the rule's judgement, not a grammar violation. (`*/plain` is rejected too, though it is not a valid `media-range` either: `media-range` allows `*/*` and `type/*`, never a wildcard type with a concrete subtype.)\n\n**Precedence:** when more than one field line is present, the duplication is reported and the individual values are not validated. A rule yields one finding, and which value applies comes before whether a value is well formed.\n\n**Known leniency:** RFC 9110 §5.6.6 forbids whitespace around a parameter's `=`, and this rule trims it, so `charset =utf-8` is accepted. It never causes a false report, only a missed one."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_8_3,
            RFC_9110_8_3_1,
            RFC_9110_5_6_6,
            RFC_9110_5_6_2,
            RFC_9110_5_6_4,
            RFC_9110_12_5_1,
            RFC_9110_5_3,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        // One media type per example. These used to be two blocks of stacked
        // `Content-Type:` lines meaning "any of these" — a reading the rule now
        // contradicts, since stacked Content-Type lines in one message are
        // themselves the defect the last example illustrates.
        &[
            // Not a bare `text/*`: `charset_present` reports a
            // text media type with no charset, so publishing one here as
            // compliant would contradict a sibling in the same catalogue.
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Type: application/octet-stream",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(token parameter)"),
                snippet: "Content-Type: application/json; charset=utf-8",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(quoted-string parameter, and a trailing `;` is conforming)"),
                snippet: "Content-Type: image/vnd.example+json; foo=\"bar\"; charset=utf-8;",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no subtype)"),
                snippet: "Content-Type: text",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(empty subtype)"),
                snippet: "Content-Type: text/",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a media-range names a set of types; Accept takes those, Content-Type does not)"),
                snippet: "Content-Type: text/*",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(parameter without a value)"),
                snippet: "Content-Type: text/plain; badparam",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(unterminated quoted-string)"),
                snippet: "Content-Type: text/plain; charset=\"unclosed",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(two field lines in one message — Content-Type is a singleton)"),
                snippet:
                    "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Type: application/json",
            },
        ]
    }
}

impl Rule for ContentTypeValid {
    // The field describes the representation a message carries, and both
    // directions carry one, so both are in scope. Nothing narrows this to
    // responses the way RFC 6266 narrows Content-Disposition.
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
            let check_message = |which: &str,
                                 headers: &hyper::HeaderMap,
                                 trailers: Option<&hyper::HeaderMap>|
             -> Option<Violation> {
                // Every field line, not just the first. `HeaderMap::get` returns one
                // value, and RFC 9110 §8.3 says recipients often resolve a duplicated
                // Content-Type by taking the *last* syntactically valid member — so
                // checking only the first validated a value the recipient may never
                // act on. Both field sections of the message are counted, since
                // §5.3's prohibition spans them.
                let vals: Vec<_> = headers
                    .get_all("content-type")
                    .iter()
                    .chain(
                        trailers
                            .into_iter()
                            .flat_map(|t| t.get_all("content-type").iter()),
                    )
                    .collect();

                // `Content-Type = media-type` is a single media-type with no list
                // form, and RFC 9110 does not leave the consequences to inference:
                // it names the duplication, names the recipient behaviour it
                // provokes, and names the security risk. This is the one field whose
                // own section spells out why a second line matters.
                // cite(RFC 9110 § 8.3): "Content-Type = media-type"
                // cite(RFC 9110 § 8.3): "Although Content-Type is defined as a singleton field, it is sometimes incorrectly generated multiple times, resulting in a combined field value that appears to be a list."
                // cite(RFC 9110 § 8.3): "Recipients often attempt to handle this error by using the last syntactically valid member of the list, leading to potential interoperability and security issues if different implementations have different error handling behaviors."
                // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
                // This returns before any value is validated, and that is the
                // choice: a rule yields one violation, and when two field lines are
                // present the question of *which value applies* comes before the
                // question of whether a value is well formed. Naming the malformed
                // one would imply the recipient reads it, which is the thing §8.3
                // says cannot be assumed.
                if vals.len() > 1 {
                    return Some(ctx.report_with(&FIELD_LINE_DUPLICATED, format!(
                            "Multiple Content-Type field lines in the {}; Content-Type is a singleton field (RFC 9110 §8.3) and recipients differ over which member wins, so the media type the peer acts on is not the one this message states. Individual values are not validated while more than one is present",
                            which
                        )));
                }

                for hv in vals {
                    // Decoded from the raw octets rather than through `to_str`, which
                    // refuses anything outside visible US-ASCII and so refuses
                    // `obs-text` — legal inside a `quoted-string`, and the reason a
                    // value like `boundary="<0xE4>"` must not be reported. Where
                    // obs-text is *not* legal, in a `token`, the checks below already
                    // reject it, so the decode decides nothing on its own.
                    // cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
                    let s = crate::helpers::headers::field_line_as_written(hv);
                    if let Some(v) = check_content_type(which, &s, ctx) {
                        return Some(v);
                    }
                }

                None
            };

            if let Some(v) =
                check_message("request", &tx.request.headers, tx.request.trailers.as_ref())
            {
                return Some(v);
            }

            if let Some(resp) = &tx.response {
                if let Some(v) = check_message("response", &resp.headers, resp.trailers.as_ref()) {
                    return Some(v);
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// The reading of one field line, converted at the site that fans out and
/// unconverted at the two that do not.
///
/// It takes the whole context rather than a severity because the two APIs
/// coexist here: the parts of the media type report declared defects and
/// resolve their own severity, while the wildcard and the two shapes
/// `parse_media_type` refuses still emit at the rule's. That is the shape every
/// partially converted rule takes, and it is cheaper than splitting the rule in
/// two.
fn check_content_type(
    _which: &str,
    val: &str,
    ctx: &crate::rules::RuleContext<'_>,
) -> Option<Violation> {
    use crate::helpers::media_type::parse_media_type;

    // `media-type = type "/" subtype parameters` is transcribed at
    // `parse_media_type`, which owns it; a second copy here would be the same
    // production stated twice. What the helper reports back is the split and the
    // two "this is not a media-type at all" shapes: no "/", or an empty half.
    let parsed = match parse_media_type(val) {
        Ok(p) => p,
        Err(defect) => {
            // The wording is this rule's because the field name is: the reader
            // answers about a `media-type` and this caller knows it was read
            // out of a `Content-Type`. The id is the catalogue's, and the two
            // structural verdicts share one — see `media_type_error`.
            let message = match defect {
                MediaTypeError::Empty => "Empty Content-Type header".into(),
                MediaTypeError::SlashMissing => format!(
                    "Invalid Content-Type '{}': missing '/' between type and subtype",
                    val
                ),
                MediaTypeError::PartEmpty => {
                    format!("Invalid Content-Type '{}': empty type or subtype", val)
                }
            };
            return Some(ctx.report_with(media_type_error(defect), message));
        }
    };

    // `*` is a perfectly good `tchar`, so this check is not the grammar
    // speaking — `*/plain` parses as a `media-type`. It is the two sentences
    // below read together: Content-Type states *the* media type of the
    // representation, while the asterisk exists to name a *range* of them, and
    // ranges belong to the `media-range` production Accept uses. A wildcard
    // here identifies nothing, so the field says nothing.
    if parsed.type_ == "*" || parsed.subtype == "*" {
        return Some(ctx.report_with(
            &MEDIA_TYPE_WILDCARD_FORBIDDEN,
            format!(
                "Content-Type '{}' uses a wildcard, which names a set of media types rather than one; a representation's Content-Type is expected to identify a single media type (wildcards belong to Accept's media-range)",
                val
            ),
        ));
    }

    // The helper split on "/" and rejected an empty half; what each half must
    // *be*, and what the parameters after them must be, is the other half of
    // `media-type` — four checks that used to stand here and now live beside the
    // split, with § 8.3.1's and § 5.6.6's productions on them. They moved when a
    // second field turned out to need the same question asked: `Accept-Patch` is
    // `1#media-type`, so `accept_patch_header_valid` measures every one of
    // its members against this production, and a copy here would have been the
    // grammar transcribed twice.
    //
    // The helper returns which part failed rather than a message, so this rule
    // still names its own field in the finding while the defect names the
    // production the part is written in — a `token`, a `quoted-string`, or the
    // `=` a parameter is joined by. The wording did not move: the `format!` is
    // still here, with the clause the reader rendered inside it.
    if let Some(defect) = crate::helpers::media_type::media_type_parts_defect(&parsed) {
        return Some(ctx.report_with(
            crate::violations::token::media_type_defect(defect),
            format!("Invalid Content-Type '{}': {}", val, defect.message()),
        ));
    }

    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentTypeValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// One field line, read the way dispatch reads it.
    ///
    /// The context is built here rather than in `test_helpers` because these
    /// cases cannot go through a `HeaderMap`: a `Content-Type` carrying a
    /// control octet inside a `quoted-string` is exactly what several of them
    /// measure, and `HeaderValue` refuses to hold one. So the reading is called
    /// directly, under a context assembled the way the engine assembles one —
    /// which is what makes a declared defect resolve its configured severity
    /// here too.
    fn check_one_value(val: &str) -> Option<Violation> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_valid"]);
        let resolved = ContentTypeValid.prepare(&cfg).expect("a preparable config");
        let severities = crate::rules::severities_for(&ContentTypeValid, &cfg);
        let ctx = crate::rules::RuleContext::new(&resolved)
            .with_violations(&ContentTypeValid, &severities);
        super::check_content_type("test", val, &ctx)
    }

    #[rstest]
    #[case("text/plain", false)]
    #[case("application/json", false)]
    #[case("application/json; charset=utf-8", false)]
    #[case("text/html; charset=\"utf-8\"", false)]
    #[case("text/plain; foo=\"a;b\"", false)]
    #[case("image/vnd.example+json; charset=utf-8; foo=bar", false)]
    #[case("text", true)]
    #[case("text/", true)]
    #[case("/plain", true)]
    #[case("*/plain", true)]
    #[case("text/*", true)]
    #[case("text/plain; badparam", true)]
    #[case("text/plain;=value", true)]
    #[case("text/plain; charset=utf 8", true)]
    #[case("text/plain; charset=\"unclosed", true)]
    // `parameter-value = ( token / quoted-string )` derives no empty string:
    // `token = 1*tchar` has a one-character floor and the shortest
    // `quoted-string` is its two DQUOTEs. This reached a `tchar` scan, which
    // finds no invalid character in the empty string and called it clean — the
    // same shape `accept_header_media_type_syntax` was corrected for,
    // living one level down in the media-type helper both rules read through.
    // `charset=""` is a different value and still conforms.
    #[case("text/plain; charset=", true)]
    #[case("text/plain; charset=\"\"", false)]
    fn content_type_parsing_cases(#[case] val: &str, #[case] expect_violation: bool) {
        let res = check_one_value(val);
        if expect_violation {
            assert!(res.is_some(), "expected violation for '{}'", val);
        } else {
            assert!(
                res.is_none(),
                "unexpected violation for '{}': {:?}",
                val,
                res
            );
        }
    }

    #[rstest]
    #[case("te@xt/plain", true)]
    #[case("text/pl@in", true)]
    #[case("text/plain; bad@=v", true)]
    #[case("", true)]
    #[case("text/plain; charset=utf-8;", false)]
    #[case("text/plain; foo=bar baz", true)]
    // The closing DQUOTE is escaped, so the string is not terminated.
    #[case("text/plain; foo=\"a\\\"", true)]
    // An unescaped DQUOTE inside the string.
    #[case("text/plain; foo=\"a\"b\"", true)]
    // A control character inside the string.
    #[case("text/plain; foo=\"a\u{1}b\"", true)]
    // Still accepted: a properly escaped quote, and an empty quoted-string.
    #[case("text/plain; foo=\"a\\\"b\"", false)]
    #[case("text/plain; foo=\"\"", false)]
    fn extra_content_type_cases(#[case] val: &str, #[case] expect_violation: bool) {
        let res = check_one_value(val);
        if expect_violation {
            assert!(res.is_some(), "expected violation for '{}'", val);
        } else {
            assert!(
                res.is_none(),
                "unexpected violation for '{}': {:?}",
                val,
                res
            );
        }
    }

    #[rstest]
    // Both individually valid: only the count can see this.
    #[case(&["text/plain", "application/json"], true)]
    // A malformed second line is reported as a duplicate, not as a bad value:
    // the count check returns first, deliberately.
    #[case(&["text/plain", "text/"], true)]
    #[case(&["text/plain"], false)]
    fn multiple_content_type_field_lines_report_violation(
        #[case] values: &[&str],
        #[case] expect_violation: bool,
    ) {
        let rule = ContentTypeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_valid"]);
        let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("content-type", *v)).collect();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&pairs);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{values:?} -> {v:?}");
    }

    #[test]
    fn a_header_line_and_a_trailer_line_are_still_two_field_lines() {
        let rule = ContentTypeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_valid"]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        {
            let resp = tx.response.as_mut().unwrap();
            resp.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/plain")]);
            resp.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "application/json",
            )]));
        }
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let msg = v.expect("must be reported").message;
        // "field lines", not "header fields": one of the two is a trailer.
        assert!(msg.contains("Multiple Content-Type field lines"), "{msg}");
    }

    #[rstest]
    // obs-text is legal inside a quoted-string, so a raw high byte in a
    // parameter value is not a defect and must not be reported.
    #[case(b"multipart/form-data; boundary=\"\xe4\"", false)]
    #[case("multipart/form-data; boundary=\"caf\u{e9}\"".as_bytes(), false)]
    // obs-text is not legal in a token, so the same octet in the type, the
    // subtype, a parameter name or an unquoted value is.
    #[case(b"te\xe4xt/plain", true)]
    #[case(b"text/pla\xe4in", true)]
    #[case(b"text/plain; char\xe4set=utf-8", true)]
    #[case(b"text/plain; charset=utf\xe4-8", true)]
    // A value `to_str` refuses outright, previously skipped in silence.
    #[case(b"\xff", true)]
    fn obs_text_is_judged_by_where_it_appears(#[case] raw: &[u8], #[case] expect_violation: bool) {
        use hyper::header::HeaderValue;
        let rule = ContentTypeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_valid"]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-type", HeaderValue::from_bytes(raw).unwrap());
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = hm;
        let v = crate::test_helpers::run_rule(
            &rule,
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

    #[test]
    fn duplicate_report_supersedes_value_validation() {
        // Two lines means the count check answers, and the malformed value is
        // not named. Pinned because it is a deliberate precedence, not an
        // accident: the earlier version of this test asserted only that the
        // word "request" appeared, which the count message satisfies, so it
        // would have passed with the value checks deleted entirely.
        let rule = ContentTypeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_valid"]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-type", "text/plain"),
            ("content-type", "*/plain"),
        ]);
        let msg = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("must be reported")
        .message;
        assert!(
            msg.contains("Multiple Content-Type field lines in the request"),
            "{msg}"
        );
        assert!(!msg.contains("wildcard"), "{msg}");
    }

    #[test]
    fn a_trailer_only_content_type_is_validated() {
        // The real gain from reading past `HeaderMap::get`: a single malformed
        // value living in the trailer section, which was invisible before.
        let rule = ContentTypeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_valid"]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().trailers = Some(
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/")]),
        );
        let msg = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("must be reported")
        .message;
        assert!(msg.contains("empty type or subtype"), "{msg}");
    }

    /// Every published snippet is run through the rule. Nothing else does this,
    /// so a `Compliant` example the rule rejects — or a `NonCompliant` one it
    /// accepts — would ship in the docs unchallenged. This family has published
    /// a wrong example twice already.
    #[test]
    fn published_examples_match_the_rules_verdict() {
        use crate::rules::Compliance;
        let rule = ContentTypeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_type_valid",
            "charset_present",
        ]);

        for ex in rule.examples() {
            let mut values: Vec<&str> = Vec::new();
            for line in ex.snippet.lines() {
                if line.starts_with("HTTP/") {
                    continue;
                }
                let v = line.strip_prefix("Content-Type: ").unwrap_or_else(|| {
                    panic!("example line is neither a start-line nor a Content-Type field line: {line:?}")
                });
                values.push(v);
            }
            assert!(
                !values.is_empty(),
                "example has no field lines: {}",
                ex.snippet
            );

            let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("content-type", *v)).collect();
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&pairs);
            let history = crate::transaction_history::TransactionHistory::empty();
            let v = crate::test_helpers::run_rule(&rule, &tx, &history, &cfg);
            match ex.compliance {
                Compliance::Compliant => {
                    assert!(
                        v.is_none(),
                        "rule rejects its Compliant example {:?}: {v:?}",
                        ex.snippet
                    );
                    // A Compliant snippet must also survive the siblings that
                    // read this header. `charset_present` reports
                    // any `text/*` carrying no charset, so a bare `text/plain`
                    // published here as good would contradict it. (The
                    // IANA-registry siblings are allowlist-driven and so depend
                    // on the operator's config, not on the example.)
                    let other = crate::test_helpers::run_rule(
                        &crate::rules::charset_present::CharsetPresent,
                        &tx,
                        &history,
                        &cfg,
                    );
                    assert!(
                        other.is_none(),
                        "the charset rule rejects a Compliant example {:?}: {other:?}",
                        ex.snippet
                    );
                }
                Compliance::NonCompliant => {
                    assert!(
                        v.is_some(),
                        "rule accepts its NonCompliant example {:?}",
                        ex.snippet
                    )
                }
            }
        }
    }

    #[rstest]
    fn request_and_response_integration() -> anyhow::Result<()> {
        let rule = ContentTypeValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_valid"]);

        // request invalid
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());

        // response invalid
        let tx2 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text")],
        );
        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v2.is_some());

        // both valid
        let mut tx3 = crate::test_helpers::make_test_transaction();
        tx3.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset=utf-8",
        )]);
        let tx4 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/json")],
        );
        let v3 = crate::test_helpers::run_rule(
            &rule,
            &tx3,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let v4 = crate::test_helpers::run_rule(
            &rule,
            &tx4,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v3.is_none());
        assert!(v4.is_none());

        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = ContentTypeValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
