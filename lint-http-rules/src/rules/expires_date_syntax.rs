// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::http_date::HttpDateDefect;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::expires::{EXPIRES_MALFORMED, RFC_9111_5_3};
use crate::violations::http_date::{
    HTTP_DATE_DAY_NAME_CONFLICTING, HTTP_DATE_OBSOLETE, RFC_5322_3_3, RFC_9110_5_6_7,
};
use crate::violations::ViolationDef;

pub struct ExpiresDateSyntax;

/// The two ways `Expires = HTTP-date` fails at a field line, and the field is
/// the reason one of the two is not the id every other dated field draws.
///
/// `Date`, `Last-Modified`, `Sunset`, `If-Modified-Since` and
/// `If-Unmodified-Since` all report `http_date_malformed` for a value no format
/// parses, on the reading that the field then names no instant. `Expires`
/// cannot: RFC 9111 § 5.3 names the instant for it — already expired — in a
/// `MUST` on every cache, so a value this rule refuses is a value that still
/// has a defined effect, and the entry that says so is
/// [`EXPIRES_MALFORMED`]. The obsolete spellings are unaffected by that
/// sentence: `Sunday, 06-Nov-94 08:49:37 GMT` names the instant the sender
/// meant, every recipient is obliged to read it, and § 5.6.7 refuses a sender
/// both of the formats that do — the same verdict here as on `Last-Modified`,
/// drawn from the same shared entry.
///
/// **The third way a timestamp fails the production is not declared, because
/// this site cannot reach it.** `http_date_whitespace_forbidden` reports an
/// `IMF-fixdate` padded with octets the production never prints, and by § 5.5
/// the padding around a *field value* is not part of it: the reading below
/// removes it before measuring, so what is left either derives from the
/// production or does not. That entry belongs to the sites where a timestamp
/// arrives quoted inside a larger value, such as a `Warning`'s `warn-date`.
///
/// **An `Expires` with nothing on it is `expires_malformed` and not
/// `http_date_empty`.** That entry's cost is that a recipient acts as though
/// the field were absent; § 5.3 has it act as though the response were stale,
/// which is a different answer and the one this field gets.
static DECLARED: &[&ViolationDef] = &[
    &EXPIRES_MALFORMED,
    &HTTP_DATE_OBSOLETE,
    &HTTP_DATE_DAY_NAME_CONFLICTING,
];

impl RuleMeta for ExpiresDateSyntax {
    fn id(&self) -> &'static str {
        "expires_date_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Expires Date Format")
    }

    fn description(&self) -> &'static str {
        "Verifies that the `Expires` response header field (when present) derives from `HTTP-date`, and that a sender generated it in the IMF-fixdate format the specification confines senders to. A value no format parses is not silently ignored by a cache: RFC 9111 §5.3 requires every cache to read it as a time already past, so the response the field was meant to keep fresh is stale on arrival."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_5_3, RFC_9110_5_6_7, RFC_5322_3_3]
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
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nExpires: Wed, 21 Oct 2015 07:38:00 GMT\n\nHello",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a cache reads this as already expired, not as ten minutes"),
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nExpires: Wed, 21 Oct 2015 07:38:00 UTC\n\nHello",
            },
        ]
    }
}

impl Rule for ExpiresDateSyntax {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: one field line, one value, one
        // verdict. A response that writes `Expires` twice is
        // `field_line_duplicated`'s to report, and this reads the first line as
        // a recipient does.
        let finding = || -> Option<Violation> {
            let resp = tx.response.as_ref()?;
            let hv = resp.headers.get("expires")?;
            // Read as octets rather than through the string reader, for the
            // reason `last_modified_rfc1123_syntax` records: every octet
            // `HTTP-date` prints is visible US-ASCII in all three formats, so
            // the reader's refusal and the production's are one refusal, and
            // only the production's can name what is wrong with the value.
            let line = crate::helpers::headers::field_line_as_written(hv);
            // The `OWS` around a field value is not part of it, and the trim is
            // `OWS` rather than `str::trim` so that an `obs-text` octet is
            // measured rather than removed.
            //
            // cite(RFC 9111 § 5.3, label: expires): "The Expires field value is an HTTP-date timestamp, as defined in Section 5.6.7 of [HTTP]."
            // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace"
            // cite(RFC 9110 § 5.6.7): "When a sender generates a field that contains one or more timestamps defined as HTTP-date, the sender MUST generate those timestamps in the IMF-fixdate format."
            let value = crate::helpers::headers::trim_ows(line.as_str());
            let defect = crate::http_date::check_imf_fixdate(value).err()?;

            // Judge, then report. The unreadable value is the one § 5.3 speaks
            // for, so it is the one that leaves the shared entries.
            //
            // cite(RFC 9111 § 5.3): "A cache recipient MUST interpret invalid date formats, especially the value "0", as representing a time in the past (i.e., "already expired")."
            let (def, message) = match defect {
                HttpDateDefect::DayNameConflicting => (
                    &HTTP_DATE_DAY_NAME_CONFLICTING,
                    format!(
                        "Expires '{value}' names a weekday its own date does not fall on \
                         (RFC 9110 §5.6.7, RFC 5322 §3.3)"
                    ),
                ),
                HttpDateDefect::ObsoleteFormat => (
                    &HTTP_DATE_OBSOLETE,
                    format!(
                        "Expires '{value}' is written in an obsolete date format; a recipient must \
                         read it, and a sender must generate IMF-fixdate (RFC 9110 §5.6.7)"
                    ),
                ),
                // The trim above already removed the `OWS` a field line may
                // carry, so `SurroundingWhitespace` cannot arrive here — and if
                // it ever did, the sentence would still be the true one: a
                // padded timestamp derives from no `HTTP-date` either, and
                // § 5.3 reads what does not derive from it as already expired.
                HttpDateDefect::Unparsable | HttpDateDefect::SurroundingWhitespace => (
                    &EXPIRES_MALFORMED,
                    format!(
                        "Expires '{value}' derives from no HTTP-date, so every cache reads the \
                         response as already expired (RFC 9111 §5.3)"
                    ),
                ),
            };
            Some(ctx.report_with(def, message))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ExpiresDateSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn expires(value: &str) -> Option<Violation> {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[("expires", value)]);
        crate::test_helpers::run_rule(
            &ExpiresDateSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["expires_date_syntax"]),
        )
    }

    /// The values the web actually sends, and which of the three ids each one
    /// draws. Both rows in the first pair were read off real responses: `-1` is
    /// the anti-caching idiom § 5.3 names, and the `UTC` spelling is a server
    /// that meant an instant ten minutes out and will get none of them.
    #[rstest]
    #[case("-1", "expires_malformed")]
    #[case("0", "expires_malformed")]
    #[case("Sun, 30 Aug 2026 00:27:20 UTC", "expires_malformed")]
    #[case("not-a-date", "expires_malformed")]
    // Nothing on the line at all. `http_date_empty` would say a recipient acts
    // as though the field were absent; § 5.3 says it acts as though the
    // response were stale, so this field's empty value is its malformed one.
    #[case("", "expires_malformed")]
    // A recipient must read both of these, and a sender may generate neither —
    // the same verdict `Last-Modified` draws from the same entry.
    #[case("Sunday, 06-Nov-94 08:49:37 GMT", "http_date_obsolete")]
    #[case("Sun Nov  6 08:49:37 1994", "http_date_obsolete")]
    fn each_way_of_failing_the_production_draws_its_own_id(
        #[case] value: &str,
        #[case] expected: &str,
    ) {
        let finding = expires(value).expect("a finding");
        assert_eq!(finding.violation, expected, "{value:?}");
    }

    /// The level is the entry's argument and this is where it is held: an
    /// unreadable `Expires` is not the `error` an unreadable `Date` is, because
    /// § 5.3 gives a cache an answer for it.
    #[test]
    fn an_expires_a_cache_can_still_act_on_is_not_an_error() {
        let finding = expires("-1").expect("a finding");
        assert_eq!(finding.severity, crate::lint::Severity::Warn);
        let obsolete = expires("Sunday, 06-Nov-94 08:49:37 GMT").expect("a finding");
        assert_eq!(obsolete.severity, crate::lint::Severity::Error);
    }

    /// The value is in the message, and it has to be: one entry covers a server
    /// that asked for stale-on-arrival and a server that asked for ten minutes,
    /// and the value is the only thing that tells a reader which happened.
    #[test]
    fn the_message_carries_the_value_that_separates_the_two_populations() {
        assert!(expires("-1").expect("a finding").message.contains("'-1'"));
        assert!(expires("Sun, 30 Aug 2026 00:27:20 UTC")
            .expect("a finding")
            .message
            .contains("'Sun, 30 Aug 2026 00:27:20 UTC'"));
    }

    /// An `Expires` a sender may generate is silent, and so is a response
    /// without one.
    #[rstest]
    #[case("Wed, 21 Oct 2015 07:28:00 GMT")]
    #[case("Thu, 01 Jan 1970 00:00:00 GMT")]
    // The `OWS` a field line may carry around its value is not part of the
    // value, so an `IMF-fixdate` written with it is an `IMF-fixdate`. This is
    // why the rule declares no `http_date_whitespace_forbidden`: after the trim
    // the reader can no longer see the padding that entry names.
    #[case(" Wed, 21 Oct 2015 07:28:00 GMT")]
    #[case("Wed, 21 Oct 2015 07:28:00 GMT\t")]
    fn a_value_the_production_generates_draws_nothing(#[case] value: &str) {
        assert!(expires(value).is_none(), "{value:?}");
    }

    #[test]
    fn a_response_without_the_field_draws_nothing() {
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        assert!(crate::test_helpers::run_rule(
            &ExpiresDateSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["expires_date_syntax"]),
        )
        .is_none());
    }
}
