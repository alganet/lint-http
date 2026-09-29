// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::conditional::{
    CONDITIONAL_DATE_IGNORED, CONDITIONAL_DATE_REDUNDANT, RFC_9110_13_1_3, RFC_9110_13_1_4,
};
use crate::violations::etag::{
    entity_tag_defect, ETAG_CHARACTER_FORBIDDEN, ETAG_DELIMITER_MISSING,
    ETAG_WEAK_INDICATOR_INVALID, RFC_9110_8_8_3,
};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::http_date::{
    http_date_defect, HTTP_DATE_DAY_NAME_CONFLICTING, HTTP_DATE_MALFORMED, HTTP_DATE_OBSOLETE,
    RFC_5322_3_3, RFC_9110_5_6_7,
};
use crate::violations::if_range::{
    IF_RANGE_EMPTY, IF_RANGE_FORBIDDEN, IF_RANGE_VALIDATOR_WEAK_FORBIDDEN, RFC_9110_13_1_5,
};
use crate::violations::ViolationDef;

/// `If-Range = entity-tag / HTTP-date`, and both alternatives are somebody
/// else's production.
///
/// The two subjects arrive together because the field imports both and adds
/// nothing to either — the same shape `Age` had with `delta-seconds`, at an
/// alternation instead of at a single production. **What makes them reachable
/// is that this alternation has a committing delimiter, and the document writes
/// the test itself**: § 13.1.5 tells a recipient to examine the first three
/// characters for a DQUOTE. So a value is measured against the alternative it
/// chose, rather than being refused for deriving from neither — which is the
/// finding 2.63's rule says the catalogue cannot name, and the one this field
/// does not have to make.
///
/// The rule keeps everything the *pairing* of these fields costs: an
/// `If-Range` with no `Range`, a weak validator where only a strong one may
/// stand, a date conditional beside an entity-tag one, and a second field line
/// where the grammar admits one.
static DECLARED: &[&ViolationDef] = &[
    &FIELD_LINE_DUPLICATED,
    &CONDITIONAL_DATE_REDUNDANT,
    &CONDITIONAL_DATE_IGNORED,
    &IF_RANGE_FORBIDDEN,
    &IF_RANGE_VALIDATOR_WEAK_FORBIDDEN,
    &IF_RANGE_EMPTY,
    &ETAG_WEAK_INDICATOR_INVALID,
    &ETAG_DELIMITER_MISSING,
    &ETAG_CHARACTER_FORBIDDEN,
    &HTTP_DATE_MALFORMED,
    &HTTP_DATE_OBSOLETE,
    &HTTP_DATE_DAY_NAME_CONFLICTING,
];

/// Validate mutual exclusivity and sanity of conditional request headers.
///
/// Checks include:
/// - `If-Modified-Since` must be ignored when `If-None-Match` is present (flagged here)
/// - `If-Unmodified-Since` must be ignored when `If-Match` is present (flagged here)
/// - `If-Range` MUST not appear without a corresponding `Range` header
/// - `If-Range` MUST NOT contain a weak entity-tag (W/"...")
/// - `If-Range`'s value is measured against the alternative it chose — an
///   entity-tag where the first three characters hold a DQUOTE, an IMF-fixdate
///   otherwise
/// - `If-Modified-Since` is only meaningful for GET/HEAD requests (flag presence on other methods)
pub struct ConditionalHeadersConsistent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_13_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1",
    note: "Preconditions",
};
const RFC_9110_13_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.2",
    note: "Evaluation of Preconditions (precedence rules)",
};
const RFC_9110_14_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("14.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2",
    note: "Range (the header If-Range depends on)",
};

impl RuleMeta for ConditionalHeadersConsistent {
    fn id(&self) -> &'static str {
        "conditional_headers_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Validate consistency and mutual exclusivity of conditional request headers. When an ETag-based conditional is present, this rule flags a redundant date-based conditional that the recipient is required to ignore (RFC 9110 §13.1.3, §13.1.4); it also ensures `If-Range` is only used with `Range` requests, disallows a weak entity-tag in `If-Range`, measures an `If-Range` value against the alternative it chose — `If-Range = entity-tag / HTTP-date`, and §13.1.5's own test is to examine the first three characters for a DQUOTE — flags `If-Modified-Since` on methods other than GET/HEAD, and flags a repeated `If-Modified-Since`/`If-Unmodified-Since` field, whose combined value is a list of dates the recipient must ignore.\n\n**An `If-Range` naming a tag the server handed this client is not measured against the alternation.** An entity tag is opaque and compared character by character (§8.8.3.2), so a client resuming a download with the `ETag` it was given sends those octets, and a malformed tag — one without its quotes reads as a date — is the server's defect, reported by `etag_syntax` on the response that carried it. The weak-tag prohibition still applies: that is a MUST NOT on the client choosing to send a weak tag here, whoever wrote it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_13_1,
            RFC_9110_13_1_3,
            RFC_9110_13_1_4,
            RFC_9110_13_1_5,
            RFC_9110_13_2,
            RFC_9110_14_2,
            RFC_9110_8_8_3,
            RFC_9110_5_6_7,
            RFC_9110_5_3,
            RFC_5322_3_3,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: \"abc\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nRange: bytes=0-99\nIf-Range: \"abc\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "POST /resource HTTP/1.1\nHost: example.com\nIf-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT   # If-Modified-Since is not meaningful for POST",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: \"abc\"\nIf-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT   # If-Modified-Since MUST be ignored when If-None-Match present",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nRange: bytes=0-99\nIf-Range: W/\"weaktag\"   # If-Range must not contain a weak entity-tag",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-Range: \"strongtag\"   # missing Range header -> invalid use of If-Range",
            },
        ]
    }
}

/// A date conditional's §5.3 defect: two field lines where the field is one
/// `HTTP-date` and has no comma-separated-list alternative.
///
/// Its subject is the field's *lines*, which is why it is read apart from what
/// §13.1.3 and §13.1.4 say about the value: an operator told the value will be
/// discarded still has two lines to merge, and merging them still leaves a
/// value that will be discarded. Two obligations, two repairs, two findings.
fn duplicated_date_line(
    req: &crate::http_transaction::RequestInfo,
    ctx: &crate::rules::RuleContext<'_>,
    name: &str,
    label: &str,
) -> Option<Violation> {
    // Neither date conditional is a list, so a second field line is a sender
    // violation — and the combined value the recipient sees is then "more than one
    // member" / "a list of dates", which it MUST ignore. The conditional silently
    // degrades to an unconditional request, which is the harm worth reporting.
    // Each line on its own may be a perfectly valid HTTP-date, so the date-format
    // rules (which validate line by line) cannot see this; only the count can.
    // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
    // Each field's own recipient consequence — the two are worded differently
    // ("more than one member" vs "appears to be a list of dates") but bite alike.
    // cite(RFC 9110 § 13.1.3): "A recipient MUST ignore the If-Modified-Since header field if the received field value is not a valid HTTP-date, the field value has more than one member, or if the request method is neither GET nor HEAD."
    // cite(RFC 9110 § 13.1.4): "A recipient MUST ignore the If-Unmodified-Since header field if the received field value is not a valid HTTP-date (including when the field value appears to be a list of dates)."
    let lines = req.headers.get_all(name).iter().count();
    if lines > 1 {
        return Some(ctx.report_with(
            &FIELD_LINE_DUPLICATED,
            format!(
                "{}. The combined value is a list of dates, which the recipient MUST ignore — so the request is conditional on nothing",
                crate::helpers::headers::singleton_field_preamble(
                    label,
                    lines,
                    &crate::helpers::headers::joined_field_lines_shown(&req.headers, name),
                    "the field is one HTTP-date and has no comma-separated-list alternative",
                )
            ),
        ));
    }
    None
}

/// What becomes of an `If-Modified-Since` a recipient is required to discard.
///
/// **At most one, and that is the one place in this rule where a first answer
/// is the whole answer.** §13.1.3 gives two reasons the same value is thrown
/// away — an `If-None-Match` beside it, or a method that is neither GET nor
/// HEAD — and both name one field line with one repair. Saying it twice under
/// two ids is one defect a reader meets twice, which is what the entries
/// beside each other are for.
fn if_modified_since_fate(
    req: &crate::http_transaction::RequestInfo,
    ctx: &crate::rules::RuleContext<'_>,
) -> Option<Violation> {
    req.headers.get("if-modified-since")?;
    // cite(RFC 9110 § 13.1.3): "A recipient MUST ignore If-Modified-Since if the request contains an If-None-Match header field"
    if req.headers.get("if-none-match").is_some() {
        return Some(ctx.report_with(&CONDITIONAL_DATE_REDUNDANT, "If-Modified-Since MUST be ignored when If-None-Match is present (RFC 9110 \u{a7}13.1.3); prefer entity-tag conditionals".into()));
    }
    // cite(RFC 9110 § 13.1.3): "A recipient MUST ignore the If-Modified-Since header field if the received field value is not a valid HTTP-date, the field value has more than one member, or if the request method is neither GET nor HEAD."
    // (The cited sentence bundles three ignore-conditions; this rule enforces the
    // method one and, above, the multiplicity one. The not-a-valid-HTTP-date clause
    // is owned by the date-format rule.)
    // Written as an `if` around the `report_with` rather than a multi-line
    // `bool::then`, and that is a measurement convention rather than a taste:
    // coverage tiers a report site by the function region covering its line, so
    // a call sitting alone inside a closure is credited only when the finding
    // fires — and "the reading ran and correctly stayed quiet" then reads
    // exactly like "nothing ever reached this".
    // Compared exactly, because the method token is case-sensitive: `Get` is
    // not one of the two methods § 13.1.3 defines the field for, so the field
    // is to be ignored on it exactly as on a POST.
    // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
    if !matches!(req.method.as_str(), "GET" | "HEAD") {
        return Some(ctx.report_with(&CONDITIONAL_DATE_IGNORED, "If-Modified-Since is only defined for GET/HEAD and MUST be ignored for other methods".into()));
    }
    None
}

/// The `If-Range` value measured against the alternative it chose.
///
/// Separate from whether the field may be here at all: §13.1.5 binds the
/// client twice over, once about generating the field without a `Range` and
/// once about what the field may contain, and adding the `Range` a request is
/// missing does not make a weak validator strong.
fn if_range_value_defect(
    line: &str,
    handed: &[String],
    ctx: &crate::rules::RuleContext<'_>,
) -> Option<Violation> {
    // Read as the octets the sender wrote: `etagc` admits `obs-text`,
    // so an octet inside a tag is a character the production
    // generates and is measured against it like any other.
    let trimmed = crate::helpers::headers::trim_ows(line);

    // The weakness indicator is read before the alternation, because
    // it is the one finding that is about *this field* rather than
    // about either production: a weak validator is a well-formed
    // entity-tag that § 13.1.5 forbids here specifically.
    // cite(RFC 9110 § 13.1.5): "A client MUST NOT generate an If-Range header field containing an entity tag that is marked as weak."
    if trimmed.starts_with("W/") {
        return Some(ctx.report_with(
            &IF_RANGE_VALIDATOR_WEAK_FORBIDDEN,
            "If-Range MUST not contain a weak entity-tag (W/...)".into(),
        ));
    }

    // `If-Range = entity-tag / HTTP-date` — an alternation whose
    // committing delimiter the document names itself, which is what
    // lets each half be measured against the production it chose.
    // A value that chose neither is this rule's own finding, because
    // *derives from none of my alternatives* is what no subject can
    // name.
    // cite(RFC 9110 § 13.1.5, label: If-Range grammar): "If-Range = entity-tag / HTTP-date"
    // cite(RFC 9110 § 13.1.5): "A valid entity-tag can be distinguished from a valid HTTP-date by examining the first three characters for a DQUOTE."
    if trimmed.is_empty() {
        return Some(ctx.report_with(
            &IF_RANGE_EMPTY,
            "If-Range is empty, which is neither an entity-tag nor an HTTP-date".into(),
        ));
    }

    // A tag the server handed this client, sent back, derives from neither
    // alternative because the server wrote it that way: the tag is opaque and
    // compared octet for octet, so the echo was the only thing a resumed
    // download could condition on, and `etag_syntax` reported it on the
    // response that carried it. Asked after the weak indicator, which is a
    // prohibition on the client's choice to send the tag here at all, and
    // before the alternation, since a tag with no DQUOTE in its first three
    // characters is read as a date.
    // cite(RFC 9110 § 8.8.3.2): "two entity tags are equivalent if both are not weak and their opaque-tags match character-by-character."
    if handed.iter().any(|tag| tag == trimmed) {
        return None;
    }
    if trimmed.chars().take(3).any(|c| c == '"') {
        let defect = crate::helpers::validator::check_entity_tag(trimmed).err()?;
        return Some(ctx.report_with(
            entity_tag_defect(defect),
            // Quoted back, the way the date branch below it
            // already quotes the value it refuses. One field,
            // read two ways, and only one of them used to say
            // what it had read.
            format!(
                "If-Range entity-tag '{}' is invalid: {}",
                crate::helpers::shown::shown_in_finding(trimmed),
                defect.message()
            ),
        ));
    }
    let defect = crate::http_date::check_imf_fixdate(trimmed).err()?;
    let shown = crate::helpers::shown::shown_in_finding(trimmed);
    Some(ctx.report_with(
        http_date_defect(defect),
        match defect {
            crate::http_date::HttpDateDefect::DayNameConflicting => format!(
                "If-Range timestamp '{shown}' names a weekday its own date does not fall on"
            ),
            // `HTTP-date = IMF-fixdate / obs-date`, so an RFC
            // 850 timestamp is one half of the alternation this
            // field offers and not a value outside it. The
            // catch-all that stood here called it invalid,
            // which is what the entry beside it says about a
            // value no format parses.
            crate::http_date::HttpDateDefect::ObsoleteFormat => format!(
                "If-Range timestamp '{shown}' is written in an obsolete date format; a recipient \
                 must read it, and a sender must generate IMF-fixdate"
            ),
            crate::http_date::HttpDateDefect::Empty
            | crate::http_date::HttpDateDefect::Unparsable
            | crate::http_date::HttpDateDefect::SurroundingWhitespace => {
                format!("If-Range timestamp '{shown}' derives from no HTTP-date")
            }
        },
    ))
}

impl Rule for ConditionalHeadersConsistent {
    /// **One finding per field this rule reads, not one per request.**
    ///
    /// The four costs named in this rule's own doc comment are four
    /// obligations over three different field values, and a request may owe
    /// several of them at once: a resumed download carries `If-None-Match`,
    /// `If-Modified-Since`, `Range` and `If-Range` together, which is the
    /// commonest revalidation a browser sends. Answered once per message, the
    /// `info` about the date pair was returned first and every reading below
    /// it — a weak `If-Range` validator, an `If-Range` with no `Range`, a
    /// second `If-Modified-Since` line, all of them `error` — was never
    /// reached. Nothing about `If-Modified-Since` standing beside
    /// `If-None-Match` makes a weak `If-Range` tag any less forbidden, so
    /// there was no argument for the silence; a rule that ends at its first
    /// answer needs one written at the site, and this one had none.
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Only applies to requests.
        let req = &tx.request;
        let mut out = Vec::new();

        // Grouped by the field each claim is about, which is the order an
        // operator repairs them in.
        out.extend(duplicated_date_line(
            req,
            ctx,
            "if-modified-since",
            "If-Modified-Since",
        ));
        out.extend(if_modified_since_fate(req, ctx));

        out.extend(duplicated_date_line(
            req,
            ctx,
            "if-unmodified-since",
            "If-Unmodified-Since",
        ));
        // cite(RFC 9110 § 13.1.4): "A recipient MUST ignore If-Unmodified-Since if the request contains an If-Match header field"
        if req.headers.get("if-unmodified-since").is_some() && req.headers.get("if-match").is_some()
        {
            out.push(ctx.report_with(&CONDITIONAL_DATE_REDUNDANT, "If-Unmodified-Since MUST be ignored when If-Match is present (RFC 9110 \u{a7}13.1.4); prefer entity-tag conditionals".into()));
        }

        if let Some(line) =
            crate::helpers::headers::field_lines_as_written(&req.headers, "if-range")
                .into_iter()
                .next()
        {
            // If-Range should only be sent in requests that contain Range.
            // cite(RFC 9110 § 13.1.5): "A client MUST NOT generate an If-Range header field in a request that does not contain a Range header field."
            if req.headers.get("range").is_none() {
                out.push(ctx.report_with(&IF_RANGE_FORBIDDEN, "If-Range present in request without Range header; If-Range MUST only be used with Range requests".into()));
            }
            out.extend(if_range_value_defect(
                &line,
                &crate::helpers::validator::tags_handed(history),
                ctx,
            ));
        }

        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ConditionalHeadersConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// **An `If-Range` naming a tag the server handed this client is the
    /// server's.** The tag is compared octet for octet, so a resumed download
    /// conditions on it as given — including one without its quotes, which the
    /// alternation reads as a date. The weak-tag prohibition is the client's
    /// either way: it chose to send a weak tag here.
    #[rstest]
    #[case::trailing_octet("\"a\"x", "\"a\"x", None)]
    #[case::unquoted_read_as_a_date("abc", "abc", None)]
    #[case::weak_is_still_forbidden(
        "W/\"a\"",
        "W/\"a\"",
        Some("if_range_validator_weak_forbidden")
    )]
    #[case::not_the_spelling_handed("\"a\"", "\"a\"x", Some("etag_delimiter_missing"))]
    fn an_if_range_tag_the_server_handed_is_not_the_clients(
        #[case] handed: &str,
        #[case] sent: &str,
        #[case] expected: Option<&str>,
    ) {
        let handing =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", handed)]);
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("range", "bytes=0-9"),
            ("if-range", sent),
        ]);
        let found = crate::test_helpers::run_rule_all(
            &ConditionalHeadersConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![handing]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_headers_consistent",
            ]),
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(
            ids,
            expected.into_iter().collect::<Vec<_>>(),
            "If-Range: {sent} after ETag: {handed}"
        );
    }

    /// **A defect in one conditional field does not silence a defect in
    /// another.** Each case carries two of this rule's readings at once, and
    /// the second is the one a single-answer body never reached — three of
    /// them `error` entries hidden behind an `info` or behind a sibling. The
    /// first case is the shape a browser resuming a download sends: an
    /// entity-tag conditional, the date conditional beside it, a `Range`, and
    /// an `If-Range` whose validator may not be weak.
    #[rstest]
    #[case::weak_if_range_behind_the_date_pair(
        "GET",
        &[
            ("if-none-match", "\"a\""),
            ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("range", "bytes=0-9"),
            ("if-range", "W/\"a\""),
        ][..],
        &["conditional_date_redundant", "if_range_validator_weak_forbidden"][..]
    )]
    #[case::a_weak_validator_survives_adding_the_range(
        "GET",
        &[("if-range", "W/\"a\"")][..],
        &["if_range_forbidden", "if_range_validator_weak_forbidden"][..]
    )]
    #[case::two_lines_and_the_pairing_are_two_repairs(
        "GET",
        &[
            ("if-none-match", "\"a\""),
            ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ][..],
        &["field_line_duplicated", "conditional_date_redundant"][..]
    )]
    #[case::each_date_field_answers_for_its_own_lines(
        "PUT",
        &[
            ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("if-unmodified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ][..],
        &["field_line_duplicated", "conditional_date_ignored", "field_line_duplicated"][..]
    )]
    fn a_finding_about_one_field_does_not_end_the_reading_of_the_next(
        #[case] method: &str,
        #[case] headers: &[(&str, &str)],
        #[case] expected: &[&str],
    ) {
        use hyper::header::HeaderValue;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(headers);
        // The two cases that need a repeated line say so here rather than in
        // the table, because `make_headers_from_pairs` is a map and a repeated
        // name in it is one line.
        if expected.contains(&"field_line_duplicated") {
            for name in ["if-modified-since", "if-unmodified-since"] {
                if headers.iter().any(|(n, _)| *n == name) {
                    tx.request.headers.append(
                        name,
                        HeaderValue::from_static("Thu, 22 Oct 2015 07:28:00 GMT"),
                    );
                }
            }
        }

        let rule = ConditionalHeadersConsistent;
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(
            ids,
            expected,
            "messages: {:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    /// The one place a first answer is still the whole answer: § 13.1.3 gives
    /// two reasons the same `If-Modified-Since` is discarded, and a `POST`
    /// carrying an `If-None-Match` beside it owes one repair, not two.
    #[test]
    fn two_reasons_to_discard_one_date_conditional_are_one_finding() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "POST".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-none-match", "\"a\""),
            ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);
        let rule = ConditionalHeadersConsistent;
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(ids, ["conditional_date_redundant"]);
    }

    /// Two field lines, each on its own a perfectly valid HTTP-date — so the
    /// line-by-line date-format rules see nothing wrong. Only the count reveals
    /// that the recipient will discard the conditional entirely.
    #[rstest]
    #[case("if-modified-since", "If-Modified-Since")]
    #[case("if-unmodified-since", "If-Unmodified-Since")]
    fn multiple_date_conditional_field_lines_are_violation(
        #[case] header: &'static str,
        #[case] label: &str,
    ) {
        use hyper::header::HeaderValue;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            header,
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        tx.request.headers.append(
            header,
            HeaderValue::from_static("Thu, 22 Oct 2015 07:28:00 GMT"),
        );

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.unwrap_or_else(|| panic!("expected violation for two {} lines", label));
        assert!(v.message.contains(label));
        assert!(v.message.contains("list of dates"));
    }

    /// One MUST-ignore predicate, two entries, split on what the request still
    /// carries afterwards. Beside its entity-tag counterpart the date field did
    /// nothing and the stronger validator decides — `_redundant`, `info`. On a
    /// method the field is not defined over there is no validator behind it,
    /// and a request the sender believed was conditional is answered as an
    /// unconditional one.
    #[rstest]
    #[case::beside_if_none_match(
        "GET",
        &[("if-none-match", "\"a\""), ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT")][..],
        "conditional_date_redundant"
    )]
    #[case::beside_if_match(
        "PUT",
        &[("if-match", "\"a\""), ("if-unmodified-since", "Wed, 21 Oct 2015 07:28:00 GMT")][..],
        "conditional_date_redundant"
    )]
    #[case::wrong_method(
        "PUT",
        &[("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT")][..],
        "conditional_date_ignored"
    )]
    fn a_discarded_date_conditional_is_two_entries(
        #[case] method: &str,
        #[case] headers: &[(&str, &str)],
        #[case] expected: &str,
    ) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(headers);
        let rule = ConditionalHeadersConsistent;
        let found = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(found.violation, expected, "{method} {headers:?}");
    }

    /// The three findings this field makes on its own, each pinned to the id
    /// it draws. What a value *is* belongs to `etag` and `http_date`; these are
    /// § 13.1.5's two client-side MUST NOTs and the alternation's own floor.
    #[rstest]
    #[case::no_range(&[("if-range", "\"a\"")][..], "if_range_forbidden")]
    #[case::weak(&[("if-range", "W/\"a\""), ("range", "bytes=0-1")][..], "if_range_validator_weak_forbidden")]
    #[case::blank(&[("if-range", ""), ("range", "bytes=0-1")][..], "if_range_empty")]
    fn the_fields_own_findings_name_the_fields_own_entries(
        #[case] headers: &[(&str, &str)],
        #[case] expected: &str,
    ) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(headers);
        let rule = ConditionalHeadersConsistent;
        let found = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(found.violation, expected, "{headers:?}");
    }

    /// The method token is case-sensitive, so `Get` is not one of the two
    /// methods § 13.1.3 defines `If-Modified-Since` over: the field is to be
    /// ignored on it exactly as on a `PUT`, and folding the comparison was what
    /// let it pass as a GET.
    #[rstest]
    #[case("Get")]
    #[case("get")]
    #[case("Head")]
    fn a_method_spelled_in_another_case_is_neither_get_nor_head(#[case] method: &str) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);

        let rule = ConditionalHeadersConsistent;
        let found = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a method nobody defined is not GET or HEAD");
        assert_eq!(found.violation, "conditional_date_ignored", "{method}");
    }

    #[rstest]
    #[case("if-modified-since")]
    #[case("if-unmodified-since")]
    fn single_date_conditional_field_line_is_fine(#[case] header: &'static str) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            header,
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[rstest]
    fn if_modified_since_ignored_when_if_none_match() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-none-match", "\"a\""),
            ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("If-Modified-Since MUST be ignored"));
    }

    #[rstest]
    fn if_unmodified_since_ignored_when_if_match() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-match", "\"a\""),
            ("if-unmodified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("If-Unmodified-Since MUST be ignored"));
    }

    /// The field is read two ways and both say what they read. The date branch
    /// quoted the value it refused from the start; the entity-tag branch beside
    /// it did not, so one half of a single field answered "which value?" and
    /// the other half did not.
    #[rstest]
    #[case("\"a\"b\"", "etag_character_forbidden")]
    #[case("\"unterminated", "etag_delimiter_missing")]
    // The date half of the alternation, which named its value from the start
    // and reported two entries under one sentence: `HTTP-date = IMF-fixdate /
    // obs-date`, so an RFC 850 timestamp is a value this field admits and a
    // recipient must read, and calling it invalid said the neighbouring
    // entry's claim about it.
    #[case("Sunday, 06-Nov-94 08:49:37 GMT", "http_date_obsolete")]
    #[case("not-a-date", "http_date_malformed")]
    fn a_refused_if_range_names_the_value_it_refused(#[case] value: &str, #[case] id: &str) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-1"),
            ("if-range", value),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(v.violation, id, "{value}");
        assert!(
            v.message
                .contains(&crate::helpers::shown::shown_in_finding(value)),
            "finding names no value: {}",
            v.message
        );
    }

    #[rstest]
    fn if_range_without_range_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("if-range", "\"a\"")]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("without Range"));
    }

    #[rstest]
    fn if_range_with_weak_etag_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-1"),
            ("if-range", "W/\"abc\""),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("MUST not contain a weak"));
    }

    #[rstest]
    fn if_range_holding_an_obs_text_octet_is_not_this_rules_finding() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.insert("range", "bytes=0-1".parse().unwrap());
        // `etagc` generates this octet, and the only question this rule asks of
        // the value is whether it opens with `W/`.
        let obs_text = HeaderValue::from_bytes(b"\"caf\xe9\"").expect("create header value");
        hm.insert("if-range", obs_text);
        tx.request.headers = hm;

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    #[rstest]
    fn if_range_with_date_is_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-1"),
            ("if-range", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    /// Each alternative is measured against the production it committed to,
    /// and the document's own three-character test is what says which.
    #[rstest]
    #[case("\"abc", "etag_delimiter_missing")]
    #[case("\"a b\"", "etag_character_forbidden")]
    #[case("w/\"abc\"", "etag_weak_indicator_invalid")]
    #[case("bogus", "http_date_malformed")]
    #[case("Sunday, 06-Nov-94 08:49:37 GMT", "http_date_obsolete")]
    fn a_committed_alternative_answers_to_its_own_production(
        #[case] if_range: &str,
        #[case] expected: &str,
    ) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-1"),
            ("if-range", if_range),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(v.violation, expected, "{}", v.message);
    }

    /// An empty value chose neither alternative, which is the one finding here
    /// that stays this rule's own.
    #[rstest]
    fn an_empty_if_range_derives_from_neither_alternative() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-1"),
            ("if-range", ""),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(
            v.message,
            "If-Range is empty, which is neither an entity-tag nor an HTTP-date"
        );
    }

    /// A strong tag holding an `obs-text` octet is a tag: `etagc` generates it.
    #[rstest]
    fn an_obs_text_octet_inside_a_tag_is_no_finding() {
        use hyper::header::HeaderValue;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.insert("range", "bytes=0-1".parse().expect("a field line"));
        hm.insert(
            "if-range",
            HeaderValue::from_bytes(b"\"caf\xe9\"").expect("a field line"),
        );
        tx.request.headers = hm;

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{v:?}");
    }

    #[rstest]
    fn if_modified_since_on_post_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "POST".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("only defined for GET/HEAD"));
    }

    #[rstest]
    fn if_modified_since_on_get_is_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn if_modified_since_on_head_is_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "HEAD".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn no_violation_for_happy_path() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-1"),
            ("if-range", "\"abc\""),
            ("if-match", "\"a\""),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn needs_no_response() {
        let r = ConditionalHeadersConsistent;
        assert!(!r.needs_response());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "conditional_headers_consistent");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
