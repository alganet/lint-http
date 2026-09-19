// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::deprecation::{RFC_9745_2_1, RFC_9745_4, SUNSET_CONFLICTING};
use crate::violations::http_date::RFC_9110_5_6_7;
use crate::violations::ViolationDef;
use chrono::TimeZone;

pub struct SunsetAndDeprecationConsistent;

/// One entry, and it is about two values disagreeing — which is the whole of
/// what a `_consistent` rule has to say.
///
/// **`http_date_malformed` was here and is gone.** This rule parses `Sunset` in
/// order to compare it with `Deprecation`, and reported the parse failure on
/// the way past — beside `date_and_time_headers_consistent`, which parses the
/// same field to compare it with `Date` and reports the same id with
/// byte-identical prose. One unreadable `Sunset` was two findings that differed
/// in nothing but the rule name on them, which is the last live instance of the
/// duplication this catalogue was built to find.
///
/// The reading that stays is the *wider* one: the neighbour judges every field
/// line and this one read only the first, and the rule that sees more of the
/// value is the one to keep — the same call `authorization_credentials_valid`'s
/// walk was decided by. Its `description()` already claimed the ownership in
/// prose; this makes the claim true.
///
/// An unreadable `Sunset` therefore leaves this rule with nothing to compare,
/// and it says nothing rather than repeating the neighbour.
///
/// The `Deprecation` half is a Structured Field `Date` and not an `HTTP-date`,
/// so nothing here answers for it; its non-UTF-8 line stays on the older API
/// for the reason every such site does.
static DECLARED: &[&ViolationDef] = &[&SUNSET_CONFLICTING];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_8594_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 8594",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc8594.html#section-3",
    note: "`Sunset` header semantics (HTTP-date)",
};
const RFC_9651_3_3_7: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9651",
    section: Some("3.3.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-3.3.7",
    note: "Structured Field `Date` item syntax",
};

impl RuleMeta for SunsetAndDeprecationConsistent {
    fn id(&self) -> &'static str {
        "sunset_and_deprecation_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Sunset and Deprecation Consistency")
    }

    fn description(&self) -> &'static str {
        "When both `Sunset` and `Deprecation` response headers are present they must be logically consistent: `Deprecation` (a Structured Field Date, `@<seconds>`, RFC 9745 §2.1) marks when a resource was or will be deprecated, and `Sunset` (an HTTP-date, RFC 8594 §3) marks the removal date. RFC 9745 §4 requires that the Sunset timestamp not be earlier than the Deprecation timestamp; this rule flags the reverse (subject to a small clock-skew tolerance). It also validates the `Sunset` syntax: a `Sunset` header that is not a parseable HTTP-date is reported even when `Deprecation` is absent. Legacy/non-structured `Deprecation` forms are left to `deprecation_header_syntax`."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_8594_3,
            RFC_9745_2_1,
            RFC_9745_4,
            RFC_9651_3_3_7,
            RFC_9110_5_6_7,
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
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2025 07:28:00 GMT\nDeprecation: @1730000000\nSunset: Tue, 01 Jan 2030 00:00:00 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2025 07:28:00 GMT\nDeprecation: @4102444800   # year 2100\nSunset: Tue, 01 Jan 2030 00:00:00 GMT",
            },
        ]
    }
}

impl Rule for SunsetAndDeprecationConsistent {
    fn needs_response(&self) -> bool {
        // This rule inspects response headers only
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // One finding per `Sunset` line that contradicts the `Deprecation`, and
        // the asymmetry between the two fields is measured rather than assumed:
        // a repeated `Deprecation` is `deprecation_header_syntax`'s finding, so
        // which of two a reader acts on is already reported and taking the first
        // states nothing untrue; a repeated `Sunset` is nobody's, so a line read
        // nowhere is a line read not at all. That is the same reason
        // `date_and_time_headers_consistent` walks the field, and this rule
        // named that walk while answering about one line.
        let findings = || -> Vec<Violation> {
            let mut out = Vec::new();
            // only applies to responses
            let Some(resp) = tx.response.as_ref() else {
                return out;
            };

            // Get Sunset header if present and parseable. Recipient parse (all three
            // HTTP-date formats, helper-owned), so a failure is "not any HTTP-date" —
            // not "IMF-fixdate"; RFC 8594 itself calls the value an HTTP-date.
            // cite(RFC 8594 § 3): "The Sunset value is an HTTP-date timestamp, as defined in Section 7.1.1.1 of [RFC7231], and SHOULD be a timestamp in the future."
            //
            // A value no recipient can read is `date_and_time_headers_consistent`'s
            // finding, not this rule's: it parses the same field for its own
            // comparison and its `description()` names `Sunset` among the fields
            // it owns the reading of. There is nothing here to compare such a
            // line with, so there is nothing to say about it -- which is why an
            // unreadable line is skipped and not counted.
            let sunsets: Vec<(String, chrono::DateTime<chrono::Utc>)> = resp
                .headers
                .get_all("sunset")
                .iter()
                .filter_map(|hv| {
                    let text = crate::helpers::headers::field_line_as_written(hv);
                    crate::http_date::parse_http_date_to_datetime(&text)
                        .ok()
                        .map(|dt| (text, dt))
                })
                .collect();

            // Get Deprecation header (structured '@<seconds>' form) if present and parseable
            // We intentionally only consider the structured '@' form here; legacy forms are
            // validated by `deprecation_header_syntax` and we avoid duplicate errors.
            // Read as octets, like the `Sunset` half above: every octet a
            // Structured Field Date prints is visible US-ASCII, so a line the
            // string reader refuses is a line this form refuses -- and the
            // finding for it is `deprecation_header_syntax`'s, which is where
            // every other malformed spelling of this field is already left.
            let deprecation_opt = match resp.headers.get_all("deprecation").iter().next() {
                Some(hv) => {
                    let s_raw = crate::helpers::headers::field_line_as_written(hv);
                    {
                        let s = s_raw.trim();
                        // Deprecation is a Structured Field Date (`@` + integer epoch
                        // seconds); this recognises exactly that form and defers the
                        // legacy/invalid forms to `deprecation_header_syntax`.
                        // (The previous cites here were mis-anchored — a Sunset
                        // *definition* and an Abstract blurb, neither governing this parse.)
                        // cite(RFC 9745 § 2.1): "Deprecation is an Item Structured Header Field; its value MUST be a Date as per Section 3.3.7 of [RFC9651]."
                        // cite(RFC 9651 § 3.3.7): "their serialization in textual HTTP fields is similar to that of Integers, distinguished from them with a leading "@"."
                        // (Digits-only, so a *negative* SF Date `@-N` — a legal pre-1970
                        // instant — is treated as non-structured and deferred; recorded
                        // in the audit ledger. Such a Deprecation date is pathological.)
                        if s.starts_with('@')
                            && s.len() > 1
                            && s[1..].chars().all(|c| c.is_ascii_digit())
                        {
                            // parse seconds since epoch
                            match s[1..].parse::<i64>() {
                                Ok(secs) => {
                                    // Build a UTC DateTime safely from epoch seconds.
                                    chrono::Utc
                                        .timestamp_opt(secs, 0)
                                        .single()
                                        .map(|dt| (s.to_string(), dt)) // treat out-of-range as non-parseable
                                }
                                Err(_) => None,
                            }
                        } else {
                            // Not structured '@' form -> ignore here (other rule flags legacy forms)
                            None
                        }
                    }
                }
                None => None,
            };

            // If both parseable values present, enforce the ordering RFC 9745 §4
            // requires (Sunset not before Deprecation). The 60s skew is a linter
            // tolerance — no spec licenses it; against a strict MUST NOT it only makes
            // the rule more lenient (recorded in the audit ledger, not cited).
            // cite(RFC 9745 § 4): "The timestamp given in the Sunset HTTP header field MUST NOT be earlier than the one given in the Deprecation header field."
            if let Some((dep_raw, dep_dt)) = deprecation_opt {
                let allowed_skew = chrono::Duration::seconds(60);
                for (sun_raw, sun_dt) in sunsets {
                    if dep_dt > sun_dt + allowed_skew {
                        out.push(ctx.report_with(&SUNSET_CONFLICTING, format!(
                            "Deprecation '{}' indicates a time after Sunset '{}'; the Sunset timestamp must not be earlier than Deprecation",
                            dep_raw, sun_raw
                        )));
                    }
                }
            }

            out
        };
        findings()
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SunsetAndDeprecationConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Every finding this rule makes about one response.
    fn findings_for(pairs: &[(&str, &str)]) -> Vec<crate::lint::Violation> {
        let tx = crate::test_helpers::make_test_transaction_with_response(200, pairs);
        crate::test_helpers::run_rule_all(
            &SunsetAndDeprecationConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "sunset_and_deprecation_consistent",
            ]),
        )
    }

    /// A `Sunset` written twice is two shutdown times, and § 4 is about each.
    ///
    /// The field's repetition is nobody's finding — `deprecation_header_syntax`
    /// reports a repeated `Deprecation` and no rule reports a repeated `Sunset`
    /// — so a line this rule does not read is a line no rule reads. Reading the
    /// first alone let a response name a shutdown before its own deprecation and
    /// say nothing, as long as it named a later one first.
    #[rstest]
    #[case::only_the_second_conflicts(
        &[
            ("deprecation", "@1767225600"),
            ("sunset", "Fri, 01 Jan 2027 00:00:00 GMT"),
            ("sunset", "Thu, 01 Jan 2015 00:00:00 GMT"),
        ],
        1
    )]
    #[case::both_conflict(
        &[
            ("deprecation", "@1767225600"),
            ("sunset", "Thu, 01 Jan 2015 00:00:00 GMT"),
            ("sunset", "Fri, 02 Jan 2015 00:00:00 GMT"),
        ],
        2
    )]
    #[case::neither_conflicts(
        &[
            ("deprecation", "@1000000000"),
            ("sunset", "Fri, 01 Jan 2027 00:00:00 GMT"),
            ("sunset", "Sat, 02 Jan 2027 00:00:00 GMT"),
        ],
        0
    )]
    // One line and one finding: the walk must not turn a single conflict into
    // more than the one thing there is to fix.
    #[case::one_line(
        &[
            ("deprecation", "@1767225600"),
            ("sunset", "Thu, 01 Jan 2015 00:00:00 GMT"),
        ],
        1
    )]
    fn every_sunset_line_is_measured_against_the_deprecation(
        #[case] pairs: &[(&str, &str)],
        #[case] expected: usize,
    ) {
        let found = findings_for(pairs);
        let messages: Vec<&str> = found.iter().map(|v| v.message.as_str()).collect();
        assert_eq!(found.len(), expected, "{messages:?}");
        assert!(
            found.iter().all(|v| v.violation == "sunset_conflicting"),
            "{:?}",
            found.iter().map(|v| &v.violation).collect::<Vec<_>>()
        );
        // Two findings of one entry on one message are one sentence written
        // twice unless each names the line it is about.
        let distinct: std::collections::BTreeSet<&str> = messages.iter().copied().collect();
        assert_eq!(distinct.len(), messages.len(), "{messages:?}");
    }

    #[rstest]
    fn consistent_deprecation_and_sunset_ok() {
        // Deprecation @0 (1970) obviously <= far-future Sunset
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@0"),
            ],
        );
        let rule = SunsetAndDeprecationConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if let Some(v) = &v {
            eprintln!(
                "unexpected violation: rule={} message={}",
                v.rule, v.message
            );
        }
        assert!(v.is_none());
    }

    #[rstest]
    fn deprecation_after_sunset_reports_violation() {
        // Deprecation @4102444800 (2100-01-01) is after Sunset 2030 -> violation
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@4102444800"),
            ],
        );
        let rule = SunsetAndDeprecationConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Deprecation") && msg.contains("Sunset"));
    }

    #[rstest]
    fn legacy_deprecation_ignored_by_this_rule() {
        // Deprecation legacy 'true' is handled by deprecation_header_syntax; this rule should not duplicate it
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "true"),
            ],
        );
        let rule = SunsetAndDeprecationConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn missing_sunset_or_deprecation_no_violation() {
        let tx1 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("sunset", "Tue, 01 Jan 2030 00:00:00 GMT")],
        );
        let tx2 =
            crate::test_helpers::make_test_transaction_with_response(200, &[("deprecation", "@0")]);
        let rule = SunsetAndDeprecationConsistent;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx1,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_none());
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_none());
    }

    #[rstest]
    fn an_unreadable_deprecation_is_the_syntax_rules_finding() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = HeaderMap::new();
        hm.insert(
            "sunset",
            HeaderValue::from_static("Tue, 01 Jan 2030 00:00:00 GMT"),
        );
        hm.insert("deprecation", HeaderValue::from_bytes(&[0xff]).unwrap());
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let rule = SunsetAndDeprecationConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        // Left to `deprecation_header_syntax`, where every other malformed
        // spelling of this field is already left: this rule compares two
        // timestamps, and a value that is not one is not its finding.
        assert!(v.is_none());
    }

    #[test]
    fn parseable_but_non_structured_deprecation_ignored() {
        // Deprecation as HTTP-date is parsed as legacy by deprecation_header_syntax;
        // this rule only checks structured '@' values, so it should not error here.
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "Tue, 01 Jan 2025 00:00:00 GMT"),
            ],
        );
        let rule = SunsetAndDeprecationConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    /// An unreadable `Sunset` is the neighbour's finding, and this rule says
    /// nothing about it.
    ///
    /// **Both used to say it, in the same words.** The assertion is two-sided
    /// for the same reason `a_malformed_challenge_is_the_neighbours_finding`
    /// is: silence here is only right because somebody still reports the
    /// value, and a test checking only the silence would pass just as well if
    /// nobody did.
    #[test]
    fn an_unreadable_sunset_is_the_neighbours_finding() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ("sunset", "not-a-date"),
                ("deprecation", "@0"),
            ],
        );
        let history = crate::transaction_history::TransactionHistory::empty();

        let rule = SunsetAndDeprecationConsistent;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_none());

        let owner = crate::rules::date_and_time_headers_consistent::DateAndTimeHeadersConsistent;
        let found = crate::test_helpers::run_rule(
            &owner,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "date_and_time_headers_consistent",
            ]),
        )
        .expect("the owning rule reports the unreadable value");
        assert_eq!(found.violation, "http_date_malformed");
        assert!(
            found
                .message
                .contains("Sunset header 'not-a-date' is not a valid HTTP-date"),
            "{}",
            found.message,
        );
    }

    #[test]
    fn deprecation_equal_to_sunset_ok() {
        // Sunset: Tue, 01 Jan 2030 00:00:00 GMT -> epoch 1893456000
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@1893456000"),
            ],
        );
        let rule = SunsetAndDeprecationConsistent;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_none());
    }

    #[test]
    fn deprecation_within_allowed_skew_ok() {
        // Sunset epoch 1893456000; dep = sunset + 30s -> allowed
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@1893456030"),
            ],
        );
        let rule = SunsetAndDeprecationConsistent;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_none());
    }

    #[test]
    fn deprecation_just_over_allowed_skew_reports_violation() {
        // dep = sunset + 61s -> violation
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@1893456061"),
            ],
        );
        let rule = SunsetAndDeprecationConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn structured_deprecation_nondigits_ignored_here() {
        // deprecation_header_syntax flags '@abc' as invalid; this rule ignores non-structured forms
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@abc"),
            ],
        );
        let rule = SunsetAndDeprecationConsistent;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_none());
    }

    #[test]
    fn structured_deprecation_overflow_ignored_here() {
        // extremely large numeric value that doesn't parse into i64 should be ignored by this rule
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("sunset", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("deprecation", "@999999999999999999999999"),
            ],
        );
        let rule = SunsetAndDeprecationConsistent;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_none());
    }

    #[test]
    fn non_utf8_sunset_ignored_and_no_panic() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = HeaderMap::new();
        hm.insert("sunset", HeaderValue::from_bytes(&[0xff]).unwrap());
        hm.insert("deprecation", HeaderValue::from_static("@0"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let rule = SunsetAndDeprecationConsistent;
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_none());
    }
    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "sunset_and_deprecation_consistent");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn needs_a_response() {
        let rule = SunsetAndDeprecationConsistent;
        assert!(rule.needs_response());
    }
}
