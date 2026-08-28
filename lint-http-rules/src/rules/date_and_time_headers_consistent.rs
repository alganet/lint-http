// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Validate Date, Last-Modified, If-Modified-Since and Sunset header consistency and formats.
pub struct DateAndTimeHeadersConsistent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_6_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("6.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1",
    note: "`Date` header (parsed as HTTP-date for comparison)",
};
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
const RFC_8594_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 8594",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc8594.html#section-3",
    note: "`Sunset` header semantics",
};

/// What a field defined as an `HTTP-date` carries.
///
/// The three ways a field can fail to state a time are distinct findings here —
/// nothing was written, what was written is not text, what was written is not a
/// date — and reading them off a chain of `if let`s is what made one rule spell
/// the same three readings four times, twice with different wording for the
/// same defect.
enum Timestamp<'a> {
    /// No field line by that name.
    Absent,
    /// A field line whose octets are not text, so no value can be read from it.
    Unreadable,
    /// Text, but not a timestamp a recipient can parse. The text itself is not
    /// carried: every reader of this variant either reports the field by name
    /// or leaves the value to the rule that owns its format.
    Unparseable,
    /// A timestamp, and the text it was written as.
    At(chrono::DateTime<chrono::Utc>, &'a str),
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
fn timestamp<'a>(headers: &'a hyper::HeaderMap, name: &str) -> Timestamp<'a> {
    headers.get(name).map_or(Timestamp::Absent, Timestamp::of)
}

impl<'a> Timestamp<'a> {
    /// Read one field line. Never [`Timestamp::Absent`] — the line exists.
    fn of(value: &'a hyper::header::HeaderValue) -> Self {
        let Ok(text) = value.to_str() else {
            return Timestamp::Unreadable;
        };
        match crate::http_date::parse_http_date_to_datetime(text) {
            Ok(at) => Timestamp::At(at, text),
            Err(_) => Timestamp::Unparseable,
        }
    }
}

impl DateAndTimeHeadersConsistent {
    /// `Date` states a time, or states nothing at all.
    // cite(RFC 9110 § 6.6.1): "The "Date" header field represents the date and time at which the message was originated"
    fn date_is_readable(
        &self,
        headers: &hyper::HeaderMap,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        match timestamp(headers, "date") {
            Timestamp::Absent | Timestamp::At(..) => None,
            Timestamp::Unreadable => Some(self.cited(
                &RFC_9110_6_6_1,
                severity,
                "Date header contains non-UTF8 bytes and is invalid".into(),
            )),
            Timestamp::Unparseable => Some(self.cited(
                &RFC_9110_6_6_1,
                severity,
                "Date header is not a valid HTTP-date (RFC 9110 §5.6.7)".into(),
            )),
        }
    }

    /// A representation cannot have last changed after the message that carries
    /// it was written.
    ///
    /// An unparseable `Last-Modified` is left to the rule that owns that
    /// field's format, so this one does not report it twice.
    // cite(RFC 9110 § 8.8.2.1): "An origin server with a clock (as defined in Section 5.6.7) MUST NOT generate a Last-Modified date that is later than the server's time of message origination (Date, Section 6.6.1)."
    fn last_modified_not_after_date(
        &self,
        headers: &hyper::HeaderMap,
        date: chrono::DateTime<chrono::Utc>,
        date_text: &str,
        skew: chrono::Duration,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        match timestamp(headers, "last-modified") {
            Timestamp::Absent | Timestamp::Unparseable => None,
            Timestamp::Unreadable => Some(self.violation(
                severity,
                "Last-Modified header contains non-UTF8 bytes and is invalid".into(),
            )),
            Timestamp::At(last_modified, text) if last_modified > date + skew => {
                Some(self.violation(severity, format!(
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
    fn sunset_is_after_date(
        &self,
        headers: &hyper::HeaderMap,
        date: chrono::DateTime<chrono::Utc>,
        date_text: &str,
        skew: chrono::Duration,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        headers
            .get_all("sunset")
            .iter()
            .find_map(|line| match Timestamp::of(line) {
                Timestamp::Unreadable => Some(self.violation(
                    severity,
                    "Sunset header contains non-UTF8 bytes and is invalid".into(),
                )),
                Timestamp::Unparseable => Some(self.violation(
                    severity,
                    "Sunset header is not a valid HTTP-date (RFC 8594 §3)".into(),
                )),
                Timestamp::At(sunset, text) if sunset <= date - skew => {
                    Some(self.cited(&RFC_8594_3, severity, format!(
                        "Sunset header '{}' is before or equal to Date '{}'; Sunset should indicate a future shutdown date",
                        text, date_text
                    )))
                }
                Timestamp::At(..) | Timestamp::Absent => None,
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
        &self,
        headers: &hyper::HeaderMap,
        skew: chrono::Duration,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        let since = match timestamp(headers, "if-modified-since") {
            Timestamp::Absent | Timestamp::Unparseable => return None,
            Timestamp::Unreadable => {
                return Some(self.violation(
                    severity,
                    "If-Modified-Since header contains non-UTF8 bytes and is invalid".into(),
                ))
            }
            Timestamp::At(since, text) => (since, text),
        };
        let Timestamp::At(date, date_text) = timestamp(headers, "date") else {
            return None;
        };
        if since.0 > date + skew {
            return Some(self.violation(severity, format!(
                "If-Modified-Since '{}' is later than Date '{}'; conditional requests should not use a future date",
                since.1, date_text
            )));
        }
        None
    }
}

impl Rule for DateAndTimeHeadersConsistent {
    fn id(&self) -> &'static str {
        "date_and_time_headers_consistent"
    }

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
            let severity = ctx.severity;

            if let Some(v) = self.date_is_readable(&tx.request.headers, severity) {
                return Some(v);
            }

            if let Some(resp) = &tx.response {
                if let Some(v) = self.date_is_readable(&resp.headers, severity) {
                    return Some(v);
                }
                // The two comparisons below are against Date, so they are asked
                // only where Date is a timestamp; where it is not, the check
                // above has already reported it.
                if let Timestamp::At(date, date_text) = timestamp(&resp.headers, "date") {
                    if let Some(v) = self.last_modified_not_after_date(
                        &resp.headers,
                        date,
                        date_text,
                        skew,
                        severity,
                    ) {
                        return Some(v);
                    }
                    if let Some(v) =
                        self.sunset_is_after_date(&resp.headers, date, date_text, skew, severity)
                    {
                        return Some(v);
                    }
                }
            }

            self.if_modified_since_not_after_date(&tx.request.headers, skew, severity)
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Date and Time Headers Consistency")
    }

    fn description(&self) -> &'static str {
        "Validate that date/time related headers are well-formed and mutually consistent. Each header is parsed as an HTTP-date (a recipient accepts all three formats; the sender-only IMF-fixdate obligation is checked by the per-header format rules), then compared: `Last-Modified` MUST NOT be later than `Date` (RFC 9110 §8.8.2.1), `Sunset` SHOULD indicate a future time relative to `Date` (RFC 8594 §3), and — as a reasonableness check with no direct spec basis — a conditional-request `If-Modified-Since` should not be later than the request's own `Date`. A small clock-skew tolerance is allowed. Values that are not a parseable HTTP-date, or that contain non-UTF8 bytes, are flagged."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_6_6_1, RFC_9110_8_8_2, RFC_9110_13_1_3, RFC_8594_3]
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

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &DateAndTimeHeadersConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

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
            assert!(m.contains("Date header is not a valid HTTP-date") || m.contains("non-UTF8"));
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
    fn last_modified_non_utf8_is_violation() -> anyhow::Result<()> {
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
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Last-Modified header contains non-UTF8"));
        Ok(())
    }

    #[test]
    fn if_modified_since_non_utf8_is_violation() -> anyhow::Result<()> {
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
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("If-Modified-Since header contains non-UTF8"));
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

    #[test]
    fn sunset_without_date_is_ignored() -> anyhow::Result<()> {
        let rule = DateAndTimeHeadersConsistent;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "sunset",
            "Tue, 01 Jan 2030 00:00:00 GMT",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn response_date_non_utf8_is_violation() -> anyhow::Result<()> {
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
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Date header contains non-UTF8"));
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
    fn sunset_non_utf8_is_violation() -> anyhow::Result<()> {
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
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("Sunset header contains non-UTF8"));
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = DateAndTimeHeadersConsistent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
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
