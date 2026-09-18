// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::conditional::CONDITIONAL_DATE_CONFLICTING;
use crate::violations::date::{DATE_MISSING, RFC_9110_6_6_1};
use crate::violations::deprecation::{RFC_8594_3, SUNSET_INVALID};
use crate::violations::http_date::{
    http_date_defect, HTTP_DATE_DAY_NAME_CONFLICTING, HTTP_DATE_MALFORMED, RFC_5322_3_3,
    RFC_9110_5_6_7,
};
use crate::violations::last_modified::{LAST_MODIFIED_CONFLICTING, RFC_9110_8_8_2_1};
use crate::violations::ViolationDef;

/// Validate Date, Last-Modified, If-Modified-Since and Sunset header consistency and formats.
pub struct DateAndTimeHeadersConsistent;

/// The one defect this rule reports about a timestamp itself; everything else
/// it says is about two of them disagreeing.
///
/// This is the *recipient's* half of § 5.6.7 — `parse_http_date_to_datetime`
/// accepts all three formats, so a failure here means no recipient could read
/// the value at all, which is exactly what `http_date_malformed` names. The
/// sender's half (an obsolete spelling, a padded one) belongs to the per-field
/// format rules and is deliberately not asked here, so the two obsolete ids are
/// not declared: this rule cannot reach them.
///
/// The non-UTF-8 lines stay on the older API: the verdict names an encoding
/// where the defect is an octet the field's grammar does not admit, and the
/// right conversion for such a site is an octet-wise reader before a def.
/// Five. Three of them are one shape read three ways: two timestamps in one
/// message that cannot both be right. The fourth is the `HTTP-date` a `Sunset`
/// failed to be, which is the production's rather than any field's. The fifth
/// is the `Date` that was never written, which is the only one here that is
/// about a field's absence rather than about a value.
static DECLARED: &[&ViolationDef] = &[
    &HTTP_DATE_MALFORMED,
    &HTTP_DATE_DAY_NAME_CONFLICTING,
    &LAST_MODIFIED_CONFLICTING,
    &SUNSET_INVALID,
    &CONDITIONAL_DATE_CONFLICTING,
    &DATE_MISSING,
];

const RFC_9110_8_8_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.8.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2",
    note: "`Last-Modified` header",
};
const RFC_9110_13_1_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3",
    note: "`If-Modified-Since` (conditional requests)",
};

/// What a field defined as an `HTTP-date` carries.
///
/// The three ways a field can fail to state a time are distinct findings here —
/// nothing was written, what was written is not text, what was written is not a
/// date — and reading them off a chain of `if let`s is what made one rule spell
/// the same three readings four times, twice with different wording for the
/// same defect.
enum Timestamp {
    /// No field line by that name.
    Absent,
    /// Not a timestamp a recipient can parse. The text itself is not carried:
    /// every reader of this variant either reports the field by name or leaves
    /// the value to the rule that owns its format.
    ///
    /// **There is no `Unreadable` beside this one, and that is a reading.**
    /// Every octet an `HTTP-date` prints is visible US-ASCII in all three of
    /// its formats, so a field line the string reader refuses is a field line
    /// the *format* refuses — one defect, and the format's reader is the one
    /// that can name it. The variant that stood here reported four fields for
    /// an encoding instead.
    ///
    /// **It carries which defect, because "this parser refused it" was two
    /// verdicts wearing one word.** A timestamp naming a weekday its own date
    /// does not fall on is refused here exactly as `not-a-date` is, and it is
    /// not the same thing: it derives from the production and names its instant
    /// unambiguously. The reporting sites below choose the id from this
    /// payload, so the field they name is theirs and the verdict is the
    /// production's.
    Unparseable(crate::http_date::HttpDateDefect),
    /// A timestamp, and the text it was written as.
    At(chrono::DateTime<chrono::Utc>, String),
}

/// Read the first `name` field line as a timestamp.
///
/// This is a *recipient* parse: `parse_http_date_to_datetime` owns the § 5.6.7
/// HTTP-date grammar and the accept-all-three-formats obligation, so
/// [`Timestamp::Unparseable`] means "no recipient could read this", not "the
/// sender used the wrong one of the three formats" — that obligation belongs to
/// the per-field format rules.
///
/// Only the first line is read: every field asked here but `Sunset` is a
/// singleton, and `Sunset` is read line by line below through
/// [`Timestamp::of`], because no other rule owns its repetition.
fn timestamp(headers: &hyper::HeaderMap, name: &str) -> Timestamp {
    headers.get(name).map_or(Timestamp::Absent, Timestamp::of)
}

/// The instant a `Sunset` is measured against.
///
/// **Two anchors and not one, because the field's sentence is about the future
/// and not about the message.** RFC 8594 § 3 asks a `Sunset` to name a time
/// still to come; `Date` is the best statement of when "now" was for the
/// message that carries it, and a response that states no `Date` has not
/// thereby stopped having a shutdown time in the past. What is left is the
/// instant the exchange was observed, which is a fact about the capture rather
/// than about the message — so it is a separate variant and the finding says
/// which one it measured against.
enum Now {
    /// The response's own `Date`, and the text it was written as.
    Stated(chrono::DateTime<chrono::Utc>, String),
    /// When the transaction was seen, for a response that states no `Date`.
    Observed(chrono::DateTime<chrono::Utc>),
}

impl Now {
    fn at(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            Self::Stated(at, _) => *at,
            Self::Observed(at) => *at,
        }
    }

    /// How a finding names the yardstick, so a reader can tell a comparison
    /// against the message from a comparison against the capture.
    fn describe(&self) -> String {
        match self {
            Self::Stated(_, text) => format!("Date '{}'", text),
            Self::Observed(at) => {
                format!("the time this exchange was observed ({})", at.to_rfc3339())
            }
        }
    }
}

impl Timestamp {
    /// Read one field line, as octets. Never [`Timestamp::Absent`] — the line
    /// exists.
    fn of(value: &hyper::header::HeaderValue) -> Self {
        let text = crate::helpers::headers::field_line_as_written(value);
        match crate::http_date::parse_http_date_to_datetime(&text) {
            Ok(at) => Timestamp::At(at, text),
            // The recipient's reader says only that it could not read the
            // value; the sender-side reader says why, and the two agree about
            // which values reach here. A value the recipient's reader accepted
            // never arrives, so the answer is one of the two this arm can see:
            // no format parses it, or the weekday contradicts its own date.
            Err(_) => Timestamp::Unparseable(
                crate::http_date::check_imf_fixdate(&text)
                    .err()
                    .unwrap_or(crate::http_date::HttpDateDefect::Unparsable),
            ),
        }
    }
}

impl DateAndTimeHeadersConsistent {
    /// `Date` states a time, or states nothing at all.
    // cite(RFC 9110 § 6.6.1): "The "Date" header field represents the date and time at which the message was originated"
    fn date_is_readable(
        &self,
        headers: &hyper::HeaderMap,
        party: crate::lint::Party,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        match timestamp(headers, "date") {
            Timestamp::Absent | Timestamp::At(..) => None,
            Timestamp::Unparseable(defect) => Some(
                ctx.by(party).report_with(
                    http_date_defect(defect),
                    match defect {
                        crate::http_date::HttpDateDefect::DayNameConflicting => {
                            "Date header names a weekday its own date does not fall on"
                        }
                        _ => "Date header is not a valid HTTP-date",
                    }
                    .into(),
                ),
            ),
        }
    }

    /// A representation cannot have last changed after the message that carries
    /// it was written.
    ///
    /// An unparseable `Last-Modified` is left to the rule that owns that
    /// field's format, so this one does not report it twice.
    // cite(RFC 9110 § 8.8.2.1): "An origin server with a clock (as defined in Section 5.6.7) MUST NOT generate a Last-Modified date that is later than the server's time of message origination (Date, Section 6.6.1)."
    fn last_modified_not_after_date(
        headers: &hyper::HeaderMap,
        date: chrono::DateTime<chrono::Utc>,
        date_text: &str,
        skew: chrono::Duration,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        match timestamp(headers, "last-modified") {
            Timestamp::Absent | Timestamp::Unparseable(_) => None,
            Timestamp::At(last_modified, text) if last_modified > date + skew => {
                Some(ctx.by_server().report_with(&LAST_MODIFIED_CONFLICTING, format!(
                    "Last-Modified '{}' is later than Date '{}'; Last-Modified must not be in the future relative to Date",
                    text, date_text
                )))
            }
            Timestamp::At(..) => None,
        }
    }

    /// `Sunset` announces a shutdown, so it names a time still to come.
    ///
    /// One § 3 sentence licenses both halves — the HTTP-date format and the
    /// future check (the skew only makes the past-check lenient).
    ///
    /// Every field line is judged, not just the first: `Sunset` is a singleton
    /// the repeated-singleton rule does not list, so a second line judged
    /// nowhere would be a second line judged not at all.
    // cite(RFC 8594 § 3): "The Sunset value is an HTTP-date timestamp, as defined in Section 7.1.1.1 of [RFC7231], and SHOULD be a timestamp in the future."
    fn sunset_is_still_to_come(
        &self,
        headers: &hyper::HeaderMap,
        now: &Now,
        skew: chrono::Duration,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        headers
            .get_all("sunset")
            .iter()
            .find_map(|line| match Timestamp::of(line) {
                Timestamp::Unparseable(defect) => Some(ctx.by_server().report_with(
                    http_date_defect(defect),
                    match defect {
                        crate::http_date::HttpDateDefect::DayNameConflicting => {
                            "Sunset header names a weekday its own date does not fall on \
                             (RFC 8594 §3)"
                        }
                        _ => "Sunset header is not a valid HTTP-date (RFC 8594 §3)",
                    }
                    .into(),
                )),
                Timestamp::At(sunset, text) if sunset <= now.at() - skew => {
                    Some(ctx.by_server().report_with(&SUNSET_INVALID, format!(
                        "Sunset header '{}' is before or equal to {}; Sunset should indicate a future shutdown date",
                        text, now.describe()
                    )))
                }
                Timestamp::At(..) | Timestamp::Absent => None,
            })
    }

    /// A 2xx, 3xx or 4xx response that never says when it was written.
    ///
    /// Asked last of the response, and the ordering is the reading: every other
    /// finding here is about a value, and a value the sender wrote wrong
    /// outranks a field it did not write at all. The `MAY` for 1xx and 5xx is
    /// why the status decides whether the question is asked at all.
    // cite(RFC 9110 § 6.6.1): "An origin server with a clock (as defined in Section 5.6.7) MUST generate a Date header field in all 2xx (Successful), 3xx (Redirection), and 4xx (Client Error) responses, and MAY generate a Date header field in 1xx (Informational) and 5xx (Server Error) responses."
    fn date_states_when_the_response_was_written(
        &self,
        response: &crate::http_transaction::ResponseInfo,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        if !(200..500).contains(&response.status) {
            return None;
        }
        matches!(timestamp(&response.headers, "date"), Timestamp::Absent).then(|| {
            ctx.by_server().report_with(
                &DATE_MISSING,
                format!(
                    "Response {} carries no Date header field, so nothing downstream can say when it was written from the message itself",
                    response.status
                ),
            )
        })
    }

    /// A conditional request asking for changes since a time later than the
    /// request itself is nonsense.
    ///
    /// No sentence mandates this ordering, so it is a reasonableness heuristic,
    /// recorded in the ledger rather than cited. The format of
    /// `If-Modified-Since` is owned by its dedicated rule, so an unparseable
    /// value is skipped here.
    fn if_modified_since_not_after_date(
        headers: &hyper::HeaderMap,
        skew: chrono::Duration,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let since = match timestamp(headers, "if-modified-since") {
            Timestamp::Absent | Timestamp::Unparseable(_) => return None,
            Timestamp::At(since, text) => (since, text),
        };
        let Timestamp::At(date, date_text) = timestamp(headers, "date") else {
            return None;
        };
        if since.0 > date + skew {
            return Some(ctx.by_client().report_with(&CONDITIONAL_DATE_CONFLICTING, format!(
                "If-Modified-Since '{}' is later than Date '{}'; conditional requests should not use a future date",
                since.1, date_text
            )));
        }
        None
    }
}

impl RuleMeta for DateAndTimeHeadersConsistent {
    fn id(&self) -> &'static str {
        "date_and_time_headers_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Date and Time Headers Consistency")
    }

    fn description(&self) -> &'static str {
        "Validate that date/time related headers are well-formed and mutually consistent. Each header is parsed as an HTTP-date (a recipient accepts all three formats; the sender-only IMF-fixdate obligation is checked by the per-header format rules), then compared: `Last-Modified` MUST NOT be later than `Date` (RFC 9110 §8.8.2.1), `Sunset` SHOULD indicate a future time relative to `Date` (RFC 8594 §3), and — as a reasonableness check with no direct spec basis — a conditional-request `If-Modified-Since` should not be later than the request's own `Date`. A small clock-skew tolerance is allowed. A value that is not a parseable HTTP-date is flagged for the field this rule owns the reading of — `Date` and `Sunset` — and left to the per-field format rule otherwise. The value is read as octets: every octet an HTTP-date prints is visible US-ASCII in all three formats, so a field line no string reader accepts is one no format accepts, and it is reported as the timestamp defect it is."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_6_6_1,
            RFC_9110_8_8_2,
            RFC_9110_13_1_3,
            RFC_8594_3,
            RFC_9110_5_6_7,
            RFC_9110_8_8_2_1,
            RFC_5322_3_3,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **`Date` is read out of both halves and the three comparisons that
    /// follow it are not.** An unreadable `Date` belongs to the message that
    /// carried it; `Last-Modified` and `Sunset` are measured against the
    /// *response's* own `Date`, and `If-Modified-Since` against the request's —
    /// the other half is never the yardstick here, so every finding stays inside
    /// one message.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nLast-Modified: Wed, 21 Oct 2015 07:20:00 GMT\nSunset: Tue, 01 Jan 2030 00:00:00 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nLast-Modified: Wed, 21 Oct 2015 07:30:00 GMT  # Last-Modified after Date\nSunset: Wed, 21 Oct 2015 07:27:00 GMT        # Sunset is in the past relative to Date",
            },
        ]
    }
}

impl Rule for DateAndTimeHeadersConsistent {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        //
        // Each check below is one sentence about one pair of fields, and each
        // states its own reading of a field that is absent, unreadable or not a
        // date — which is why they are named functions rather than a ladder:
        // the ladder made those three readings look like one.
        let finding = || -> Option<Violation> {
            // Tolerate some small clock skew when comparing dates. 60s is a linter
            // heuristic — no spec licenses it; §8.8.2.1's "MUST NOT ... later than ...
            // Date" is strict, so this only makes the rule *more* lenient (recorded in
            // the audit ledger, not cited).
            const ALLOWED_SKEW_SECS: i64 = 60;
            let skew = chrono::Duration::seconds(ALLOWED_SKEW_SECS);
            if let Some(v) =
                self.date_is_readable(&tx.request.headers, crate::lint::Party::Client, ctx)
            {
                return Some(v);
            }

            if let Some(resp) = &tx.response {
                if let Some(v) =
                    self.date_is_readable(&resp.headers, crate::lint::Party::Server, ctx)
                {
                    return Some(v);
                }
                // The two comparisons below are against Date, so they are asked
                // only where Date is a timestamp; where it is not, the check
                // above has already reported it.
                // `Last-Modified` is measured against `Date` and against
                // nothing else: § 8.8.2.1 constrains it relative to the
                // server's time of message origination, which is what `Date`
                // states and what no observer can supply in its place.
                if let Timestamp::At(date, date_text) = timestamp(&resp.headers, "date") {
                    if let Some(v) = Self::last_modified_not_after_date(
                        &resp.headers,
                        date,
                        &date_text,
                        skew,
                        ctx,
                    ) {
                        return Some(v);
                    }
                }
                // `Sunset` is measured against whichever instant is available.
                // An unreadable `Date` has already been reported above, so the
                // only response reaching the fallback is one that wrote none.
                let now = match timestamp(&resp.headers, "date") {
                    Timestamp::At(date, date_text) => Now::Stated(date, date_text),
                    Timestamp::Absent | Timestamp::Unparseable(_) => Now::Observed(tx.timestamp),
                };
                if let Some(v) = self.sunset_is_still_to_come(&resp.headers, &now, skew, ctx) {
                    return Some(v);
                }
                if let Some(v) = self.date_states_when_the_response_was_written(resp, ctx) {
                    return Some(v);
                }
            }

            Self::if_modified_since_not_after_date(&tx.request.headers, skew, ctx)
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &DateAndTimeHeadersConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Three fields, three sites, one id. `Date` and `Sunset` are read here,
    /// and `Expires` by `cookie_attribute_consistent` through a cookie
    /// attribute walk. All three ask the *recipient's* question — can this
    /// value be read as a timestamp at all — so all three answer
    /// `http_date_malformed`, each naming its own field.
    ///
    /// **There was a fourth site and it was a duplicate.**
    /// `sunset_and_deprecation_consistent` parsed `Sunset` for its own
    /// comparison and said this rule's sentence, word for word, so one
    /// unreadable value drew two findings differing in nothing but the rule
    /// name. It stopped; this rule keeps the reading because it judges every
    /// field line where the other read only the first.
    /// The weekday that is not the day its date falls on, in the two fields
    /// this rule reads. `Fri, 01 Jan 1980 00:00:00 GMT` came off a real
    /// response — the first of January 1980 was a Tuesday — and it used to be
    /// reported as the value no format parses, which said the field named no
    /// instant. It names one exactly; what it does not name is the day.
    #[test]
    fn a_weekday_the_date_does_not_imply_is_not_a_value_that_names_no_instant() {
        let response = |pairs: &[(&str, &str)]| {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().expect("a response").headers =
                crate::test_helpers::make_headers_from_pairs(pairs);
            crate::test_helpers::run_rule(
                &DateAndTimeHeadersConsistent,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "date_and_time_headers_consistent",
                ]),
            )
            .expect("a finding")
        };

        let date = response(&[("date", "Fri, 01 Jan 1980 00:00:00 GMT")]);
        assert_eq!(date.violation, "http_date_day_name_conflicting");
        assert_eq!(date.severity, crate::lint::Severity::Error);
        assert!(date.message.contains("weekday"), "{}", date.message);

        let sunset = response(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("sunset", "Mon, 26 Jul 1997 05:00:00 GMT"),
        ]);
        assert_eq!(sunset.violation, "http_date_day_name_conflicting");

        // The value that really does name no instant keeps the id that says so.
        assert_eq!(
            response(&[("date", "not-a-date")]).violation,
            "http_date_malformed",
        );
    }

    #[test]
    fn a_timestamp_no_recipient_can_read_is_one_defect_in_three_fields() {
        let response = |pairs: &[(&str, &str)]| {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().expect("a response").headers =
                crate::test_helpers::make_headers_from_pairs(pairs);
            tx
        };
        let here = |pairs: &[(&str, &str)]| {
            crate::test_helpers::run_rule(
                &DateAndTimeHeadersConsistent,
                &response(pairs),
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "date_and_time_headers_consistent",
                ]),
            )
            .expect("a finding")
        };
        let readable_date = ("date", "Wed, 21 Oct 2015 07:28:00 GMT");

        assert_eq!(
            here(&[("date", "not-a-date")]).violation,
            "http_date_malformed"
        );
        let sunset_here = here(&[readable_date, ("sunset", "not-a-date")]);
        assert_eq!(sunset_here.violation, "http_date_malformed");

        // The rule named for `Sunset` no longer answers for its format: it
        // parsed the field to compare it with `Deprecation` and said the same
        // sentence this rule says, which was the last live duplicate in the
        // tree. Two rules, one reading.
        assert!(crate::test_helpers::run_rule(
            &crate::rules::sunset_and_deprecation_consistent::SunsetAndDeprecationConsistent,
            &response(&[("sunset", "not-a-date")]),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "sunset_and_deprecation_consistent",
            ]),
        )
        .is_none());

        let expires = crate::test_helpers::run_rule(
            &crate::rules::cookie_attribute_consistent::CookieAttributeConsistent,
            &response(&[("set-cookie", "id=1; Expires=not-a-date")]),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "cookie_attribute_consistent",
            ]),
        )
        .expect("a finding");
        assert_eq!(expires.violation, "http_date_malformed");

        // And a rule that reads another field still names it: one id, three
        // fields, three sentences.
        assert_ne!(sunset_here.message, expires.message);
    }

    #[rstest]
    #[case(Some(vec![("date", "not-a-date")] ), true)]
    #[case(Some(vec![("date", "Wed, 21 Oct 2015 07:28:00 GMT")] ), false)]
    #[case(None, false)]
    fn date_format_cases(
        #[case] headers: Option<Vec<(&str, &str)>>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();

        if let Some(h) = headers {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&h);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some());
            let m = v.unwrap().message;
            assert!(m.contains("Date header is not a valid HTTP-date"), "{m}");
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn last_modified_after_date_is_violation() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("last-modified", "Wed, 21 Oct 2015 07:30:00 GMT"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Last-Modified"));
        Ok(())
    }

    #[test]
    fn sunset_before_date_is_violation() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("sunset", "Wed, 21 Oct 2015 07:27:00 GMT"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Sunset"));
        Ok(())
    }

    #[test]
    fn if_modified_since_after_date_is_violation() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("if-modified-since", "Wed, 21 Oct 2015 07:30:00 GMT"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("If-Modified-Since"));
        Ok(())
    }

    #[test]
    fn non_utf8_date_header_is_violation() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();

        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("date", bad);
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn sunset_invalid_format_is_violation() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("sunset", "not-a-date"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Sunset header is not a valid HTTP-date"));
        Ok(())
    }

    #[test]
    fn an_unreadable_last_modified_is_its_own_rules_finding() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);

        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[(
            "date",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("last-modified", bad);
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        // Left to the rule that owns this field's format, exactly as an
        // unparseable value is: the octet is a defect of the timestamp, not of
        // the pair being compared.
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn an_unreadable_if_modified_since_is_its_own_rules_finding() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();

        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("if-modified-since", bad);
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        // Left to the rule that owns this field's format, as an unparseable
        // value is.
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn response_date_invalid_is_violation() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("date", "not-a-date")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Date header is not a valid HTTP-date"));
        Ok(())
    }

    /// **A response that states no `Date` is not a response with no clock to be
    /// measured against.** RFC 8594 § 3 asks a `Sunset` to name a time still to
    /// come, and "to come" is about the future rather than about the message —
    /// so where the message states no instant, the instant the exchange was
    /// observed is what is left, and the finding says which one it used.
    ///
    /// This used to assert silence, and the silence was the rule declining to
    /// ask: two of the three `Sunset`-bearing responses on the open web carry
    /// no `Date`, so the check reached one response in three.
    #[rstest]
    #[case("Tue, 01 Jan 2030 00:00:00 GMT", "date_missing")]
    #[case("Sun, 06 Nov 1994 08:49:37 GMT", "sunset_invalid")]
    fn a_sunset_without_a_date_is_measured_against_the_observation(
        #[case] sunset: &str,
        #[case] expected: &str,
    ) {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.timestamp = "2026-08-30T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .expect("a fixed observation time");
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[("sunset", sunset)]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("a finding");
        assert_eq!(v.violation, expected);
        if expected == "sunset_invalid" {
            assert!(
                v.message.contains("observed"),
                "a comparison against the capture's clock says so: {}",
                v.message
            );
        }
    }

    /// **`Date` is a `MUST` for 2xx, 3xx and 4xx and a `MAY` for the rest**, so
    /// the status decides whether the question is asked at all. A `Sunset` still
    /// gets its answer either way — the field's own sentence has no status in
    /// it.
    #[rstest]
    #[case(200, Some("date_missing"))]
    #[case(304, Some("date_missing"))]
    #[case(404, Some("date_missing"))]
    #[case(503, None)]
    #[case(101, None)]
    fn only_the_statuses_the_must_names_are_asked_for_a_date(
        #[case] status: u16,
        #[case] expected: Option<&str>,
    ) {
        let rule = DateAndTimeHeadersConsistent;
        let tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(v.map(|v| v.violation), expected.map(str::to_string));
    }

    /// A response that states a `Date` says when it was written, and the entry
    /// about the absence has nothing to report.
    #[test]
    fn a_response_that_states_its_date_draws_nothing() {
        let rule = DateAndTimeHeadersConsistent;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("date", "Wed, 21 Oct 2015 07:28:00 GMT")],
        );
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_none());
    }

    #[test]
    fn an_unreadable_date_is_a_timestamp_defect() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);

        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("date", bad);
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("a finding");
        assert_eq!(v.violation, "http_date_malformed");
        Ok(())
    }

    #[test]
    fn last_modified_invalid_format_is_ignored() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("last-modified", "not-a-date"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        // Parse error for Last-Modified should be ignored by this rule (other rule will report)
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn if_modified_since_invalid_format_is_ignored() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("if-modified-since", "not-a-date"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        // Parse error for If-Modified-Since should be ignored by this rule (other rule will report)
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn if_modified_since_without_date_is_ignored() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:30:00 GMT",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        // Without a Date header to compare against, the rule should not produce a violation
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn an_unreadable_sunset_is_a_timestamp_defect() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);

        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[(
            "date",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("sunset", bad);
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("a finding");
        assert_eq!(v.violation, "http_date_malformed");
        Ok(())
    }

    #[test]
    fn needs_no_response() {
        let rule = DateAndTimeHeadersConsistent;
        assert!(!rule.needs_response());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "date_and_time_headers_consistent");
        // Should validate and produce an engine without error
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
