// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::status::{RFC_9110_15_4_5, STATUS_304_FIELD_MISSING};
use crate::violations::ViolationDef;

/// One entry: a field § 15.4.5 has a `304` generate and the response did not.
static DECLARED: &[&ViolationDef] = &[&STATUS_304_FIELD_MISSING];

pub struct Status304RequiredFields;

/// RFC 9111, for the one consequence the caching document spells out: what a
/// cache does with a `304` that carries no validator.
const RFC_9111_4_3_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.3.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.4",
    note: "Freshening Stored Responses upon Validation — a cache identifies what a 304 updates by the validators the 304 carries, and where it carries none while the stored response has one, no stored response is identified and the revalidation freshens nothing",
};

/// The six fields § 15.4.5's MUST names, in the order the two list items print
/// them: the header-map key, and the name a sender writes, which is what the
/// finding says.
///
/// **A closed list, and closed by one sentence rather than by judgement.** The
/// section writes the requirement once and then gives its members as two
/// bullets — `Content-Location`, `Date`, `ETag` and `Vary`, then
/// `Cache-Control` and `Expires` with a pointer at RFC 9111. Nothing else a
/// `304` may carry is on it: `Last-Modified` is named in the *next* paragraph
/// as an example of metadata the SHOULD NOT tolerates, which is a permission
/// and not a requirement, and `Content-Length` has a MAY of its own in § 8.6.
// cite(RFC 9110 § 15.4.5): "The server generating a 304 response MUST generate any of the following header fields that would have been sent in a 200 (OK) response to the same request:"
const REQUIRED_FIELDS: [(&str, &str); 6] = [
    ("content-location", "Content-Location"),
    ("date", "Date"),
    ("etag", "ETag"),
    ("vary", "Vary"),
    ("cache-control", "Cache-Control"),
    ("expires", "Expires"),
];

/// The fields whose presence is the difference between the request that was
/// answered `304` and the request that would have been answered `200`.
///
/// Everything else has to match, because "the same request" is what the MUST is
/// conditional on. These five are exactly the fields whose presence makes a
/// request conditional, and a request carrying one is the same request made
/// conditional — which is the transformation § 15.4.5 is written about, and the
/// only one this rule allows between the two messages it compares.
// cite(RFC 9110 § 13): "A conditional request is an HTTP request with one or more request header fields that indicate a precondition to be tested before applying the request method to the target resource."
const PRECONDITIONS: [&str; 5] = [
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
];

/// Whether the earlier exchange asked what this one asks, precondition aside.
///
/// **The strictest reading of "the same request", deliberately.** Anything
/// looser would have the rule guess at what a `200` to a *different* request
/// would have carried, and the fields at issue are the ones negotiation moves:
/// a `Vary` is about which request header fields select the representation, so
/// a comparison that let those differ would be reasoning about a `200` the
/// server never had occasion to send. The cost is silence wherever a client
/// varies anything at all between the two requests — a `Referer`, a `Cookie`,
/// an `Accept-Encoding` it added — and silence is the direction to be wrong in
/// here, since the finding is an `error`.
///
/// The comparison itself is [`crate::helpers::same_request`], which is shelved
/// apart because the question is not this section's alone: § 15.3.7 writes the
/// same sentence about a `206`, and only the field allowed to differ changes.
fn asks_the_same(
    earlier: &crate::http_transaction::HttpTransaction,
    conditional: &crate::http_transaction::HttpTransaction,
) -> bool {
    crate::helpers::same_request::asks_the_same(earlier, conditional, &PRECONDITIONS)
}

impl RuleMeta for Status304RequiredFields {
    fn id(&self) -> &'static str {
        "status_304_required_fields"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("The header fields a 304 owes the 200 it replaces")
    }

    fn description(&self) -> &'static str {
        "RFC 9110 §15.4.5 says two things about a `304 (Not Modified)`, and they pull in opposite directions. A sender **SHOULD NOT** generate representation metadata beyond a listed set — that is `status_304_representation_metadata`'s sentence — and, two paragraphs earlier, a server generating a 304 **MUST** generate any of `Content-Location`, `Date`, `ETag`, `Vary`, `Cache-Control` and `Expires` *\"that would have been sent in a 200 (OK) response to the same request\"*. This rule reads the MUST.\n\n**The requirement is conditional, and the condition is not in the 304.** A response that omits `Vary` violates nothing unless the `200` it stands in for would have carried one, and no single message says what that hypothetical `200` holds. So this rule answers it with an observation instead: an earlier `200`, from the same client, for the same resource, answering **the same request** — same method, same target URI, and the same header fields but for the precondition that made this one conditional. Where no such exchange was seen, nothing is reported; a proxy that joins a conversation after the representation was stored has no antecedent to read and says so by staying quiet.\n\n**\"The same request\" is read strictly.** Every request header field but the five §13.1 preconditions has to match, octet for octet. The fields at issue are the ones content negotiation moves — `Vary` is a statement about which request fields select the representation — so a looser comparison would be reasoning about a `200` the server never had occasion to send. What that costs is silence wherever a client changed anything else between the two requests, and silence is the right direction to be wrong in for a finding that ships at `error`.\n\n**One finding per field**, each naming the field and the value the `200` sent, so an operator has the line to put back rather than a list to check.\n\n**What the omission costs.** RFC 9111 §4.3.4 has a cache identify which stored responses a 304 freshens by the validators the 304 carries; where the new response carries none and the stored one has one, no stored response is identified for update at all — so a 304 that drops the `ETag` spends the round trip and freshens nothing. For the other five the loss is §15.4.5's own first paragraph: the recipient is being redirected to use its stored representation *\"as if it were the content of a 200 (OK) response\"*, and a field that response would have carried is one it does not get.\n\n**Not folded into `status_304_representation_metadata`.** That rule is decided by the status code and the fields beside it, in one message, and says so three times over; this one cannot be answered without a second exchange. Same section, same status code, opposite direction, and different evidence."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_15_4_5, RFC_9111_4_3_4]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// The 304 and the fields on it are the origin's. The request is read only
    /// to establish that the earlier exchange was the same one, which decides
    /// whether there is a finding rather than who it is about.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— the 304 repeats every listed field the 200 carried"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nDate: Mon, 01 Jan 2024 00:00:00 GMT\nETag: \"abc\"\nVary: Accept-Encoding\n\nGET /a HTTP/1.1\nHost: example.com\nIf-None-Match: \"abc\"\n\nHTTP/1.1 304 Not Modified\nDate: Mon, 01 Jan 2024 00:00:01 GMT\nETag: \"abc\"\nVary: Accept-Encoding\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a field the 200 did not send either is not one the 304 owes"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nDate: Mon, 01 Jan 2024 00:00:00 GMT\nETag: \"abc\"\n\nGET /a HTTP/1.1\nHost: example.com\nIf-None-Match: \"abc\"\n\nHTTP/1.1 304 Not Modified\nDate: Mon, 01 Jan 2024 00:00:01 GMT\nETag: \"abc\"\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— the negotiation the 200 announced, dropped from the 304"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nDate: Mon, 01 Jan 2024 00:00:00 GMT\nETag: \"abc\"\nVary: Accept-Encoding\n\nGET /a HTTP/1.1\nHost: example.com\nIf-None-Match: \"abc\"\n\nHTTP/1.1 304 Not Modified\nDate: Mon, 01 Jan 2024 00:00:01 GMT\nETag: \"abc\"\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— the validator dropped, so RFC 9111 §4.3.4 freshens no stored response",
                ),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nDate: Mon, 01 Jan 2024 00:00:00 GMT\nETag: \"abc\"\nCache-Control: max-age=60\n\nGET /a HTTP/1.1\nHost: example.com\nIf-None-Match: \"abc\"\n\nHTTP/1.1 304 Not Modified\nDate: Mon, 01 Jan 2024 00:00:01 GMT\n",
            },
        ]
    }
}

impl Rule for Status304RequiredFields {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(resp) = tx.response.as_ref() else {
            return Vec::new();
        };
        // cite(RFC 9110 § 15.4.5): "The 304 (Not Modified) status code indicates that a conditional GET or HEAD request has been received and would have resulted in a 200 (OK) response if it were not for the fact that the condition evaluated to false."
        if resp.status != 304 {
            return Vec::new();
        }

        // The antecedent, and the newest one: what the origin sends changes
        // over time, so an older `200` describes a resource that may since have
        // stopped negotiating. History arrives newest-first.
        let Some((_, answered)) = history.responses().find(|(earlier, earlier_resp)| {
            earlier_resp.status == 200 && asks_the_same(earlier, tx)
        }) else {
            return Vec::new();
        };

        REQUIRED_FIELDS
            .iter()
            .filter_map(|(key, name)| {
                // Read as written, because `Content-Location` and `ETag` both
                // admit `obs-text` and a value this cannot decode is still a
                // value the `200` sent.
                let sent = crate::helpers::headers::field_lines_as_written(&answered.headers, key)
                    .into_iter()
                    .next()?;
                // A search of the whole field section rather than a look at one
                // line: the claim this entry makes is that the sender never
                // wrote the field, and a test that could be satisfied by a
                // second line elsewhere would be making it falsely.
                if resp.headers.contains_key(*key) {
                    return None;
                }
                let shown = crate::helpers::shown::shown_in_finding(
                    crate::helpers::headers::trim_ows(&sent),
                );
                Some(ctx.report_with(
                    &STATUS_304_FIELD_MISSING,
                    format!(
                        "304 Not Modified sends no {name}, and the 200 that answered the same \
                         request sent {name}: {shown} \u{2014} RFC 9110 \u{a7} 15.4.5 has a \
                         server generate every one of Content-Location, Date, ETag, Vary, \
                         Cache-Control and Expires that the 200 would have carried"
                    ),
                ))
            })
            .collect()
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Status304RequiredFields;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// A `200` for `/a`, then a conditional request for `/a` answered `304`.
    ///
    /// The two requests are built from the same pair list and then the
    /// precondition is added to the second, because a fixture that wrote them
    /// out separately would be the one place this rule's whole question could
    /// drift without a test noticing.
    fn revalidation(
        request: &[(&str, &str)],
        first: &[(&str, &str)],
        conditional_request: &[(&str, &str)],
        second: &[(&str, &str)],
    ) -> (
        crate::http_transaction::HttpTransaction,
        crate::transaction_history::TransactionHistory,
    ) {
        let base = chrono::Utc::now();

        let mut earlier = crate::test_helpers::make_test_transaction_with_response(200, first);
        earlier.request.uri = "http://example/a".to_string();
        earlier.request.headers = crate::test_helpers::make_headers_from_pairs(request);
        earlier.timestamp = base - chrono::Duration::seconds(1);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(304, second);
        tx.request.uri = "http://example/a".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(conditional_request);
        tx.timestamp = base;

        (
            tx,
            crate::transaction_history::TransactionHistory::from_transactions(vec![earlier]),
        )
    }

    fn judge(
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
    ) -> Vec<Violation> {
        crate::test_helpers::run_rule_all(
            &Status304RequiredFields,
            tx,
            history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_304_required_fields",
            ]),
        )
    }

    const ASKED: &[(&str, &str)] = &[("accept", "*/*")];
    const ASKED_AGAIN: &[(&str, &str)] = &[("accept", "*/*"), ("if-none-match", "\"abc\"")];

    /// Both directions of each of the six fields, from one table: the `200`
    /// carries it and the `304` does not, and then the `304` carries it too.
    #[rstest]
    #[case::content_location("content-location", "/a.en.html")]
    #[case::date("date", "Mon, 01 Jan 2024 00:00:00 GMT")]
    #[case::etag("etag", "\"abc\"")]
    #[case::vary("vary", "Accept-Encoding")]
    #[case::cache_control("cache-control", "max-age=60")]
    #[case::expires("expires", "Mon, 01 Jan 2024 01:00:00 GMT")]
    fn a_field_the_200_carried_is_one_the_304_owes(#[case] name: &str, #[case] value: &str) {
        let (tx, history) = revalidation(ASKED, &[(name, value)], ASKED_AGAIN, &[]);
        let found = judge(&tx, &history);
        assert_eq!(found.len(), 1, "{name}: one field, one finding");
        assert_eq!(found[0].violation, "status_304_field_missing");
        // Compared through the same renderer the finding used: an `ETag`
        // value is a `quoted-string`, and how a DQUOTE is shown in a message is
        // one open question for the whole catalogue rather than this entry's.
        assert!(
            found[0]
                .message
                .contains(&crate::helpers::shown::shown_in_finding(value)),
            "{name}: the finding names the value the 200 sent, and said {:?}",
            found[0].message
        );

        let (tx, history) = revalidation(ASKED, &[(name, value)], ASKED_AGAIN, &[(name, value)]);
        assert!(
            judge(&tx, &history).is_empty(),
            "{name}: the 304 sent it too"
        );
    }

    /// A field neither message carried is nothing to report: the MUST is
    /// conditional on the `200` having sent it.
    #[test]
    fn a_field_the_200_did_not_send_either_is_not_owed() {
        let (tx, history) = revalidation(
            ASKED,
            &[("etag", "\"abc\"")],
            ASKED_AGAIN,
            &[("etag", "\"abc\"")],
        );
        assert!(judge(&tx, &history).is_empty());
    }

    /// Six fields absent from one `304` are six lines to put back, and the rule
    /// answers for each rather than stopping at the first.
    #[test]
    fn every_absent_field_is_its_own_finding() {
        let (tx, history) = revalidation(
            ASKED,
            &[
                ("content-location", "/a.en.html"),
                ("date", "Mon, 01 Jan 2024 00:00:00 GMT"),
                ("etag", "\"abc\""),
                ("vary", "Accept-Encoding"),
                ("cache-control", "max-age=60"),
                ("expires", "Mon, 01 Jan 2024 01:00:00 GMT"),
            ],
            ASKED_AGAIN,
            &[],
        );
        assert_eq!(judge(&tx, &history).len(), 6);
    }

    /// Nothing to compare against is nothing to say. The antecedent of
    /// § 15.4.5's MUST is a `200` to the same request, and an observer that
    /// never saw one cannot reach it.
    #[test]
    fn a_304_with_no_earlier_200_reports_nothing() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(304, &[]);
        tx.request.uri = "http://example/a".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(ASKED_AGAIN);
        assert!(judge(
            &tx,
            &crate::transaction_history::TransactionHistory::empty()
        )
        .is_empty());
    }

    /// A `200` to a *different* request says nothing about what a `200` to this
    /// one would have carried — which is the whole of the condition, and the
    /// half a rule that only matched the resource would get wrong.
    #[rstest]
    #[case::another_field_added(&[("accept", "*/*"), ("accept-encoding", "gzip"), ("if-none-match", "\"abc\"")][..])]
    #[case::a_field_with_another_value(&[("accept", "text/html"), ("if-none-match", "\"abc\"")][..])]
    #[case::a_field_dropped(&[("if-none-match", "\"abc\"")][..])]
    fn a_200_to_another_request_is_no_antecedent(#[case] conditional_request: &[(&str, &str)]) {
        let (tx, history) = revalidation(
            ASKED,
            &[("vary", "Accept-Encoding")],
            conditional_request,
            &[],
        );
        assert!(judge(&tx, &history).is_empty());
    }

    /// The five preconditions are the difference the comparison is written to
    /// allow: adding one is what made the request conditional.
    #[rstest]
    #[case::if_none_match("if-none-match", "\"abc\"")]
    #[case::if_modified_since("if-modified-since", "Mon, 01 Jan 2024 00:00:00 GMT")]
    #[case::if_match("if-match", "\"abc\"")]
    #[case::if_unmodified_since("if-unmodified-since", "Mon, 01 Jan 2024 00:00:00 GMT")]
    #[case::if_range("if-range", "\"abc\"")]
    fn a_precondition_is_the_one_field_that_may_differ(#[case] name: &str, #[case] value: &str) {
        let (tx, history) = revalidation(
            ASKED,
            &[("vary", "Accept-Encoding")],
            &[("accept", "*/*"), (name, value)],
            &[],
        );
        assert_eq!(judge(&tx, &history).len(), 1, "{name}");
    }

    /// A `200` to another *method* is not a `200` to the same request, and the
    /// method is not a precondition.
    #[test]
    fn a_200_to_another_method_is_no_antecedent() {
        let (mut tx, history) =
            revalidation(ASKED, &[("vary", "Accept-Encoding")], ASKED_AGAIN, &[]);
        tx.request.method = "HEAD".to_string();
        assert!(judge(&tx, &history).is_empty());
    }

    /// The newest antecedent, not the first one seen: what an origin sends
    /// changes, and an older `200` describes a resource that may since have
    /// stopped negotiating.
    #[test]
    fn the_newest_earlier_200_is_the_one_read() {
        let base = chrono::Utc::now();
        let mut old = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("vary", "Accept-Encoding")],
        );
        old.request.uri = "http://example/a".to_string();
        old.request.headers = crate::test_helpers::make_headers_from_pairs(ASKED);
        old.timestamp = base - chrono::Duration::seconds(2);

        let mut recent = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        recent.request.uri = "http://example/a".to_string();
        recent.request.headers = crate::test_helpers::make_headers_from_pairs(ASKED);
        recent.timestamp = base - chrono::Duration::seconds(1);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(304, &[]);
        tx.request.uri = "http://example/a".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(ASKED_AGAIN);
        tx.timestamp = base;

        // History is newest-first.
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![recent, old]);
        assert!(judge(&tx, &history).is_empty());
    }

    /// Only a `304` is answered for. A `200` that carries less than the `200`
    /// before it is nothing this sentence is about.
    #[test]
    fn a_200_that_dropped_a_field_is_not_this_rules_business() {
        let (mut tx, history) =
            revalidation(ASKED, &[("vary", "Accept-Encoding")], ASKED_AGAIN, &[]);
        tx.response.as_mut().expect("a response").status = 200;
        assert!(judge(&tx, &history).is_empty());
    }

    /// The finding is the origin's, and every site says so through the rule's
    /// one presumption.
    #[test]
    fn the_finding_is_attributed_to_the_server() {
        let (tx, history) = revalidation(ASKED, &[("vary", "Accept-Encoding")], ASKED_AGAIN, &[]);
        let found = judge(&tx, &history);
        assert_eq!(found[0].party, Some(crate::lint::Party::Server));
    }

    /// The strength this entry states is the keyword the section writes.
    #[test]
    fn the_entry_states_the_keyword_it_quotes() {
        assert_eq!(
            STATUS_304_FIELD_MISSING.strength,
            crate::lint::Strength::Must
        );
        assert_eq!(
            STATUS_304_FIELD_MISSING.default_severity,
            crate::lint::Severity::Error
        );
    }
}
