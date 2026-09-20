// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::status::{RFC_9110_15_3_7, STATUS_206_FIELD_MISSING};
use crate::violations::ViolationDef;

/// One entry: a field § 15.3.7 has a `206` generate and the response did not.
static DECLARED: &[&ViolationDef] = &[&STATUS_206_FIELD_MISSING];

pub struct Status206RequiredFields;

/// RFC 9111, for what a cache does with the partial content it is allowed to
/// keep.
const RFC_9111_3_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("3.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-3.3",
    note: "Storing Incomplete Responses — a cache may store the content of a 206 and later combine the parts, which is what makes a `Vary` dropped from one of them a stored response nothing tells the cache to key",
};

/// The six fields § 15.3.7's MUST names, in the order the sentence prints
/// them: the header-map key, and the name a sender writes, which is what the
/// finding says.
///
/// **A closed list, and closed by one sentence rather than by judgement.** The
/// section writes the requirement once and names its members inline — `Date`,
/// `Cache-Control`, `ETag`, `Expires`, `Content-Location` and `Vary` — with
/// everything else a 206 owes deferred to "the subsections below", which is
/// § 15.3.7.1's and § 15.3.7.2's `Content-Range` and `Content-Type` and is
/// `range_and_content_range_consistent`'s reading rather than this one.
///
/// **The same six § 15.4.5 names for a `304`, and kept separate on purpose.**
/// Two sections state one requirement about two status codes and each states
/// it in its own words; a single shared constant would make an edit to either
/// document silently rewrite the other rule's claim. What is genuinely shared
/// between them is the comparison, and that is
/// [`crate::helpers::same_request`].
// cite(RFC 9110 § 15.3.7): "A server that generates a 206 response MUST generate the following header fields, in addition to those required in the subsections below, if the field would have been sent in a 200 (OK) response to the same request: Date, Cache-Control, ETag, Expires, Content-Location, and Vary."
const REQUIRED_FIELDS: [(&str, &str); 6] = [
    ("date", "Date"),
    ("cache-control", "Cache-Control"),
    ("etag", "ETag"),
    ("expires", "Expires"),
    ("content-location", "Content-Location"),
    ("vary", "Vary"),
];

/// The fields whose presence is the difference between the request that was
/// answered `206` and the request that would have been answered `200`.
///
/// Everything else has to match, because "the same request" is what the MUST is
/// conditional on — and here the document says outright which request that is.
/// § 14.2 evaluates a `Range` *"only if the result in absence of the Range
/// header field would be a 200 (OK) response"*, so the `200` § 15.3.7's
/// antecedent names is this very request with the `Range` taken off it. That
/// is not an interpretation of "the same request"; it is the definition of when
/// a `206` may be sent at all.
///
/// `If-Range` joins it because a client may not write one without the other, so
/// the two are one field's worth of difference rather than two.
// cite(RFC 9110 § 14.2): "The Range header field is evaluated after evaluating the precondition header fields defined in Section 13.1, and only if the result in absence of the Range header field would be a 200 (OK) response."
// cite(RFC 9110 § 13.1.5): "A client MUST NOT generate an If-Range header field in a request that does not contain a Range header field."
const VARYING: [&str; 2] = ["range", "if-range"];

impl RuleMeta for Status206RequiredFields {
    fn id(&self) -> &'static str {
        "status_206_required_fields"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("The header fields a 206 owes the 200 it is a part of")
    }

    fn description(&self) -> &'static str {
        "RFC 9110 §15.3.7 says a server generating a `206 (Partial Content)` **MUST** generate `Date`, `Cache-Control`, `ETag`, `Expires`, `Content-Location` and `Vary` *\"if the field would have been sent in a 200 (OK) response to the same request\"*. This rule reads that sentence.\n\n**It had been quoted only to say what it does not require.** The list is the reason `Accept-Ranges` is not owed on a 206, and that is what every rule reaching for §15.3.7 reached for; whether the six named fields themselves arrived was asked by nothing.\n\n**The requirement is conditional, and the condition is not in the 206.** A response that omits `Vary` violates nothing unless the `200` it is a part of would have carried one, and no single message says what that hypothetical `200` holds. So this rule answers it with an observation instead: an earlier `200`, from the same client, for the same resource, answering **the same request** — same method, same target URI, and the same header fields but for the `Range` that asked for the part. Where no such exchange was seen, nothing is reported.\n\n**\"The same request\" is read strictly.** Every request header field but `Range` and `If-Range` has to match, octet for octet. The fields at issue are the ones content negotiation moves — `Vary` is a statement about which request fields select the representation — so a looser comparison would be reasoning about a `200` the server never had occasion to send. What that costs is silence wherever a client changed anything else between the two requests, and silence is the right direction to be wrong in for a finding that ships at `error`.\n\n**One finding per field**, each naming the field and the value the `200` sent, so an operator has the line to put back rather than a list to check.\n\n**What the omission costs.** §15.3.7 makes a 206 heuristically cacheable and RFC 9111 §3.3 lets a cache store its content, so a partial response whose `Vary` went missing is one the cache has nothing to key on — and it will be handed to a request whose `Accept-Encoding` selects a different representation. For the other five the loss is the client's: it is assembling a representation from parts, and a field the whole would have carried is one it never receives.\n\n**Not the subsections' fields.** Whether a single-part 206 carries a `Content-Range`, and whether a multipart one carries the `multipart/byteranges` `Content-Type`, are §15.3.7.1's and §15.3.7.2's requirements and `range_and_content_range_consistent` reads them. This rule reads the six the parent section names, which is the set whose condition is a `200` nobody sent.\n\n**The 304 twin.** `status_304_required_fields` reads §15.4.5's identical sentence about the other status code that stands in for a `200`, over the same six fields. The two differ only in which request field is allowed to differ between the exchanges — a precondition there, a `Range` here."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_15_3_7, RFC_9111_3_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// The 206 and the fields on it are the origin's. The request is read only
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
                label: Some("— the 206 repeats every listed field the 200 carried"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nDate: Mon, 01 Jan 2024 00:00:00 GMT\nETag: \"abc\"\nVary: Accept-Encoding\nContent-Length: 1024\n\nGET /a HTTP/1.1\nHost: example.com\nRange: bytes=0-9\n\nHTTP/1.1 206 Partial Content\nDate: Mon, 01 Jan 2024 00:00:01 GMT\nETag: \"abc\"\nVary: Accept-Encoding\nContent-Range: bytes 0-9/1024\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a field the 200 did not send either is not one the 206 owes"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nDate: Mon, 01 Jan 2024 00:00:00 GMT\nETag: \"abc\"\n\nGET /a HTTP/1.1\nHost: example.com\nRange: bytes=0-9\n\nHTTP/1.1 206 Partial Content\nDate: Mon, 01 Jan 2024 00:00:01 GMT\nETag: \"abc\"\nContent-Range: bytes 0-9/1024\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— the negotiation the 200 announced, dropped from the part, so a cache storing it has nothing to key on",
                ),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nDate: Mon, 01 Jan 2024 00:00:00 GMT\nETag: \"abc\"\nVary: Accept-Encoding\n\nGET /a HTTP/1.1\nHost: example.com\nRange: bytes=0-9\n\nHTTP/1.1 206 Partial Content\nDate: Mon, 01 Jan 2024 00:00:01 GMT\nETag: \"abc\"\nContent-Range: bytes 0-9/1024\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— the freshness the 200 stated, absent from the part"),
                snippet: "GET /a HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nDate: Mon, 01 Jan 2024 00:00:00 GMT\nETag: \"abc\"\nCache-Control: max-age=60\n\nGET /a HTTP/1.1\nHost: example.com\nRange: bytes=0-9\n\nHTTP/1.1 206 Partial Content\nDate: Mon, 01 Jan 2024 00:00:01 GMT\nETag: \"abc\"\nContent-Range: bytes 0-9/1024\n",
            },
        ]
    }
}

impl Rule for Status206RequiredFields {
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
        // cite(RFC 9110 § 15.3.7): "The 206 (Partial Content) status code indicates that the server is successfully fulfilling a range request for the target resource by transferring one or more parts of the selected representation."
        if resp.status != 206 {
            return Vec::new();
        }

        // The antecedent, and the newest one: what the origin sends changes
        // over time, so an older `200` describes a resource that may since have
        // stopped negotiating. History arrives newest-first.
        let Some((_, whole)) = history.responses().find(|(earlier, earlier_resp)| {
            earlier_resp.status == 200
                && crate::helpers::same_request::asks_the_same(earlier, tx, &VARYING)
        }) else {
            return Vec::new();
        };

        REQUIRED_FIELDS
            .iter()
            .filter_map(|(key, name)| {
                // Read as written, because `Content-Location` and `ETag` both
                // admit `obs-text` and a value this cannot decode is still a
                // value the `200` sent.
                let sent = crate::helpers::headers::field_lines_as_written(&whole.headers, key)
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
                    &STATUS_206_FIELD_MISSING,
                    format!(
                        "206 Partial Content sends no {name}, and the 200 that answered the same \
                         request without the Range sent {name}: {shown} \u{2014} RFC 9110 \
                         \u{a7} 15.3.7 has a server generate every one of Date, Cache-Control, \
                         ETag, Expires, Content-Location and Vary that the 200 would have carried"
                    ),
                ))
            })
            .collect()
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Status206RequiredFields;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// A `200` for `/a`, then a range request for `/a` answered `206`.
    ///
    /// The two requests are built from the same pair list and then the `Range`
    /// is added to the second, because a fixture that wrote them out separately
    /// would be the one place this rule's whole question could drift without a
    /// test noticing.
    fn partial(
        request: &[(&str, &str)],
        whole: &[(&str, &str)],
        range_request: &[(&str, &str)],
        part: &[(&str, &str)],
    ) -> (
        crate::http_transaction::HttpTransaction,
        crate::transaction_history::TransactionHistory,
    ) {
        let base = chrono::Utc::now();

        let mut earlier = crate::test_helpers::make_test_transaction_with_response(200, whole);
        earlier.request.uri = "http://example/a".to_string();
        earlier.request.headers = crate::test_helpers::make_headers_from_pairs(request);
        earlier.timestamp = base - chrono::Duration::seconds(1);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(206, part);
        tx.request.uri = "http://example/a".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(range_request);
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
            &Status206RequiredFields,
            tx,
            history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "status_206_required_fields",
            ]),
        )
    }

    const ASKED: &[(&str, &str)] = &[("accept", "*/*")];
    const ASKED_FOR_A_PART: &[(&str, &str)] = &[("accept", "*/*"), ("range", "bytes=0-9")];

    /// Both directions of each of the six fields, from one table: the `200`
    /// carries it and the `206` does not, and then the `206` carries it too.
    #[rstest]
    #[case::date("date", "Mon, 01 Jan 2024 00:00:00 GMT")]
    #[case::cache_control("cache-control", "max-age=60")]
    #[case::etag("etag", "\"abc\"")]
    #[case::expires("expires", "Mon, 01 Jan 2024 01:00:00 GMT")]
    #[case::content_location("content-location", "/a.en.html")]
    #[case::vary("vary", "Accept-Encoding")]
    fn a_field_the_200_sent_is_owed_by_the_206(#[case] key: &str, #[case] value: &str) {
        let (tx, history) = partial(ASKED, &[(key, value)], ASKED_FOR_A_PART, &[]);
        let found = judge(&tx, &history);
        assert_eq!(found.len(), 1, "{key} absent from the 206");

        let (tx, history) = partial(ASKED, &[(key, value)], ASKED_FOR_A_PART, &[(key, value)]);
        assert!(judge(&tx, &history).is_empty(), "{key} present on the 206");
    }

    /// A field the `200` did not send is not one the `206` owes: the MUST is
    /// conditional on the `200` having carried it.
    #[test]
    fn a_field_the_200_did_not_send_either_is_not_owed() {
        let (tx, history) = partial(
            ASKED,
            &[("etag", "\"abc\"")],
            ASKED_FOR_A_PART,
            &[("etag", "\"abc\"")],
        );
        assert!(judge(&tx, &history).is_empty());
    }

    /// Six fields absent from one `206` are six lines to put back, and the rule
    /// answers for each rather than stopping at the first.
    #[test]
    fn every_absent_field_is_its_own_finding() {
        let (tx, history) = partial(
            ASKED,
            &[
                ("date", "Mon, 01 Jan 2024 00:00:00 GMT"),
                ("cache-control", "max-age=60"),
                ("etag", "\"abc\""),
                ("expires", "Mon, 01 Jan 2024 01:00:00 GMT"),
                ("content-location", "/a.en.html"),
                ("vary", "Accept-Encoding"),
            ],
            ASKED_FOR_A_PART,
            &[],
        );
        assert_eq!(judge(&tx, &history).len(), 6);
    }

    /// Nothing to compare against is nothing to say. The antecedent of
    /// § 15.3.7's MUST is a `200` to the same request, and an observer that
    /// never saw one cannot reach it.
    #[test]
    fn a_206_with_no_earlier_200_reports_nothing() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(206, &[]);
        tx.request.uri = "http://example/a".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(ASKED_FOR_A_PART);
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
    #[case::another_field_added(&[("accept", "*/*"), ("accept-encoding", "gzip"), ("range", "bytes=0-9")][..])]
    #[case::a_field_with_another_value(&[("accept", "text/html"), ("range", "bytes=0-9")][..])]
    #[case::a_field_dropped(&[("range", "bytes=0-9")][..])]
    fn a_200_to_another_request_is_no_antecedent(#[case] range_request: &[(&str, &str)]) {
        let (tx, history) = partial(ASKED, &[("vary", "Accept-Encoding")], range_request, &[]);
        assert!(judge(&tx, &history).is_empty());
    }

    /// `If-Range` is the other half of the same asking, so a conditional range
    /// request is still the same request as the `200` that answered it whole.
    #[test]
    fn an_if_range_is_part_of_the_same_asking() {
        let (tx, history) = partial(
            ASKED,
            &[("vary", "Accept-Encoding")],
            &[
                ("accept", "*/*"),
                ("range", "bytes=0-9"),
                ("if-range", "\"abc\""),
            ],
            &[],
        );
        assert_eq!(judge(&tx, &history).len(), 1);
    }

    /// A status other than 206 is not this section's subject, whatever it omits.
    #[test]
    fn only_a_206_is_read() {
        let base = chrono::Utc::now();
        let mut earlier = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("vary", "Accept-Encoding")],
        );
        earlier.request.uri = "http://example/a".to_string();
        earlier.request.headers = crate::test_helpers::make_headers_from_pairs(ASKED);
        earlier.timestamp = base - chrono::Duration::seconds(1);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "http://example/a".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(ASKED_FOR_A_PART);
        tx.timestamp = base;

        assert!(judge(
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![earlier])
        )
        .is_empty());
    }

    /// The finding names the field and the value the `200` sent, because the
    /// repair is that line and an operator should not have to go and find it.
    #[test]
    fn the_finding_names_the_field_and_the_value() {
        let (tx, history) = partial(ASKED, &[("vary", "Accept-Encoding")], ASKED_FOR_A_PART, &[]);
        let found = judge(&tx, &history);
        assert_eq!(found.len(), 1);
        assert!(found[0].message.contains("sends no Vary"));
        assert!(found[0].message.contains("Accept-Encoding"));
    }
}
