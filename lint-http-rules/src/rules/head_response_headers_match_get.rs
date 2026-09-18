// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::method::{
    METHOD_HEAD_CONFLICTING, METHOD_HEAD_CONTENT_LENGTH_CONFLICTING, RFC_9110_8_6, RFC_9110_9_3_2,
};
use crate::violations::ViolationDef;

/// Two entries, because the section asks for two different things. § 9.3.2
/// advises which fields a `HEAD` response carries; § 8.6 requires what one of
/// those fields, once carried, says. A single entry gave the second the first
/// one's modal.
static DECLARED: &[&ViolationDef] = &[
    &METHOD_HEAD_CONFLICTING,
    &METHOD_HEAD_CONTENT_LENGTH_CONFLICTING,
];

/// Whether a difference in *presence* of this field between the two responses
/// is licensed, in either direction.
///
/// § 9.3.2 excuses omission by naming a class rather than a set of fields, and
/// the class is one no message answers: nothing on the wire says whether a
/// value was determined while the content was being generated. What can be
/// recognised is the fields a specification names as belonging to it — and the
/// section names two, of which `Vary` is the one still reaching this comparison
/// (`Content-Length` and `Transfer-Encoding` are answered above by the
/// documents that define them).
///
// cite(RFC 9110 § 9.3.2): "However, a server MAY omit header fields for which a value is determined only while generating the content."
// cite(RFC 9110 § 9.3.2): "Such a response to GET might contain Content-Length and Vary fields, for example, that are not generated within a HEAD response."
///
/// The permission runs in both directions here, which the MAY on its own does
/// not say: it excuses the HEAD response for omitting a field, not for carrying
/// one the GET lacked. The other direction is licensed by what the comparison
/// rests on — the GET is a *previously observed* response, not the counterfactual
/// one § 9.3.2 names, so a field present only on the HEAD is as easily the
/// earlier GET having exercised this same MAY.
fn presence_difference_is_permitted(name: &str) -> bool {
    matches!(name, "vary")
}

/// Whether the two responses' validator fields say the selected representation
/// changed between the observed GET and this HEAD.
///
/// § 9.3.2's sentence is a counterfactual: the same request, at the same
/// moment, with GET in place of HEAD. A previously observed GET stands in for
/// it, and a resource is free to change in between — so a difference between
/// the two responses is only evidence of a server disobeying § 9.3.2 while the
/// representation held still. Both messages say whether it did.
///
// cite(RFC 9110 § 9.2.1): "Of the request methods defined by this specification, the GET, HEAD, OPTIONS, and TRACE methods are defined to be safe."
// cite(RFC 9110 § 8.8): "In responses to safe requests, validator fields describe the selected representation chosen by the origin server while handling the response."
// cite(RFC 9110 § 8.8.1): "A "strong validator" is representation metadata that changes value whenever a change occurs to the representation data that would be observable in the content of a 200 (OK) response to GET."
// cite(RFC 9110 § 8.8.2): "The "Last-Modified" header field in a response provides a timestamp indicating the date and time at which the origin server believes the selected representation was last modified, as determined at the conclusion of handling the request."
///
/// A weak entity tag is compared the same way, and § 8.8.1 licenses that too:
/// it changes when "the origin server wants caches to invalidate old
/// responses". Only a *difference* is read here, never a match — equal weak
/// tags do not prove the data is identical, and nothing below needs them to.
fn selected_representation_changed(prev: &hyper::HeaderMap, cur: &hyper::HeaderMap) -> bool {
    let differs = |name: &str, normalize: fn(&str) -> String| {
        let a = crate::helpers::headers::combined_field_value_as_written(prev, name);
        let b = crate::helpers::headers::combined_field_value_as_written(cur, name);
        match (a, b) {
            // Only both-present decides. A validator on one response alone says
            // nothing about the other's representation, and its absence from the
            // HEAD is § 9.3.2's finding rather than a reason to stop looking.
            (Some(a), Some(b)) => normalize(&a) != normalize(&b),
            _ => false,
        }
    };

    // Entity tags compare by opaque-tag, which is `normalize_etag`'s § 8.8.3.2
    // weak comparison; `Last-Modified` is an HTTP-date and compares as written.
    differs("etag", crate::helpers::validator::normalize_etag)
        || differs("last-modified", str::to_string)
}

/// What an observed GET says about the octet count § 8.6 names.
///
/// The previous GET holds two pieces of evidence about it: what it declared,
/// and what it actually delivered. The declaration answers first, because that
/// is the number a `Content-Length` is; where the GET declared none — it was
/// chunked, or it is HTTP/2 or HTTP/3, where there is no framing field to
/// declare — the captured octets are the same count measured rather than
/// claimed, so the requirement is still decidable. A GET whose declaration and
/// delivery disagree is `response_body_length_accuracy`'s finding, not this
/// rule's, and it is left to it — that rule cites § 8.6 as the reason it
/// exempts a HEAD response from its own comparison, and hands the requirement
/// here by name: it has one transaction and this one has two.
///
// cite(RFC 9110 § 6.4): "HTTP messages often transfer a complete or partial representation as the message "content": a stream of octets sent after the header section, as delineated by the message framing."
enum ContentLengthEvidence {
    Declared(u128),
    Delivered(u64),
}

impl ContentLengthEvidence {
    fn octets(&self) -> u128 {
        match self {
            Self::Declared(n) => *n,
            Self::Delivered(n) => u128::from(*n),
        }
    }
}

fn content_length_evidence(
    prev_resp: &crate::http_transaction::ResponseInfo,
) -> Option<ContentLengthEvidence> {
    if let Some(declared) =
        crate::helpers::content_length::declared_content_length(&prev_resp.headers)
    {
        return Some(ContentLengthEvidence::Declared(declared));
    }

    // Only where the content of that response *is* the selected representation
    // the HEAD is asking about; a 304 declares the length of a 200 it did not
    // send, so its captured zero says nothing.
    // cite(RFC 9110 § 15.3.1): "The content sent in a 200 response depends on the request method."
    //
    // And only where that response was read to its end. A GET the client
    // abandoned delivered every octet the origin sent and was counted for as
    // many as arrived, so measuring a later HEAD's honest `Content-Length`
    // against that count reports the HEAD for the earlier reading's shortfall.
    // `response_body_length_accuracy` declines on the same evidence for the same
    // reason, and the sentence above hands this requirement here precisely
    // because this rule has the second transaction -- which is no help when the
    // first one was never finished.
    (prev_resp.status == 200 && !prev_resp.body_interrupted)
        .then_some(prev_resp.body_length)
        .flatten()
        .map(ContentLengthEvidence::Delivered)
}

/// The `Content-Length` half, which is the one requirement here that is not
/// § 9.3.2's SHOULD.
///
// cite(RFC 9110 § 8.6): "A server MAY send a Content-Length header field in a response to a HEAD request (Section 9.3.2); a server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a response if the same request had used the GET method."
fn content_length_finding(
    prev_resp: &crate::http_transaction::ResponseInfo,
    resp: &crate::http_transaction::ResponseInfo,
) -> Option<String> {
    let cur_len = crate::helpers::content_length::declared_content_length(&resp.headers)?;
    let evidence = content_length_evidence(prev_resp)?;
    (evidence.octets() != cur_len).then(|| match evidence {
        ContentLengthEvidence::Declared(declared) => format!(
            "Content-Length in HEAD ({}) differs from GET ({})",
            cur_len, declared
        ),
        ContentLengthEvidence::Delivered(captured) => format!(
            "Content-Length in HEAD ({}) differs from the {} octets of content the GET response delivered",
            cur_len, captured
        ),
    })
}

/// The set a `Vary` value advertises. The field value is a set of field names,
/// and field names are case-insensitive — so two spellings of one set are one
/// advertisement, and neither the order nor the case is part of what was
/// advertised.
// cite(RFC 9110 § 12.5.5): "A Vary field value is either the wildcard member "*" or a list of request field names, known as the selecting header fields, that might have had a role in selecting the representation for this response."
// cite(RFC 9110 § 5.1): "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry""
///
/// The sort is what "set" means here, and the field's first stated purpose is
/// where it comes from: what a recipient does with the value is look each
/// named field up, which no ordering changes.
// cite(RFC 9110 § 12.5.5): "To inform cache recipients that they MUST NOT use this response to satisfy a later request unless the later request has the same values for the listed header fields as the original request"
///
/// `list_members` drops empty members, which is the recipient's reading and
/// the right one for a question about what was advertised; a sender that
/// writes `Accept, , Accept-Encoding` is `vary_header_valid`'s.
fn vary_members(value: &str) -> Vec<String> {
    let mut members: Vec<String> = crate::helpers::list::list_members(value)
        .map(|s| s.to_ascii_lowercase())
        .collect();
    members.sort_unstable();
    members
}

/// What one observed GET response answers about a field, in the form the
/// comparison below reads it: the octet count for `Content-Length`, the set for
/// `Vary`, the value as written for everything else, and `None` inside for a
/// field the response does not carry. The outer `None` is a GET that answers
/// nothing — a `Content-Length` it neither declared nor could be measured for
/// — which is not the same as a GET that answers "absent".
fn field_answer(
    resp: &crate::http_transaction::ResponseInfo,
    name: &str,
) -> Option<Option<String>> {
    let written =
        |name| crate::helpers::headers::combined_field_value_as_written(&resp.headers, name);
    match name {
        "content-length" => content_length_evidence(resp).map(|e| Some(e.octets().to_string())),
        "vary" => Some(written("vary").map(|v| vary_members(&v).join(","))),
        _ => Some(written(name)),
    }
}

/// The GET response the HEAD is measured against for one field: the newest
/// that answers, and only where every other observed GET answers the same.
///
/// § 9.3.2's counterfactual is one GET at one moment, and what the history
/// holds is several at several. Where they agree the newest stands in for the
/// counterfactual and the finding rests on the assumption it always rested
/// on — that the resource held still. Where they disagree, the history has
/// already shown that it did not: a length that differs between two readings
/// of the same representation is not a number a HEAD can be held to, whether
/// the HEAD matches one of the readings or neither. Nothing is reported for
/// that field, because nothing about the server has been shown.
fn unanimous<'a>(
    gets: &[&'a crate::http_transaction::HttpTransaction],
    name: &str,
) -> Option<&'a crate::http_transaction::ResponseInfo> {
    let mut answers = gets
        .iter()
        .filter_map(|t| t.response.as_ref())
        .filter_map(|resp| field_answer(resp, name).map(|answer| (resp, answer)));
    let (newest, first) = answers.next()?;
    answers.all(|(_, answer)| answer == first).then_some(newest)
}

pub struct HeadResponseHeadersMatchGet;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_8_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.8"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8",
    note: "Why a difference between the two responses is not automatically a finding: validator fields \"describe the selected representation chosen by the origin server while handling the response\", so an ETag or Last-Modified that moved between the observed GET and this HEAD says the resource changed, and the rule declines",
};
const RFC_9111_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1",
    note: "Which observed GET is the same request: a response that varies names the request fields that selected it, and a GET whose request differs from the HEAD's in any of them was answered about another representation, so it is no yardstick for this one",
};
const RFC_9112_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9112",
    section: Some("6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1",
    note: "Transfer-Encoding is excluded outright: it \"MAY be sent in a response to a HEAD request\", the indication \"is not required\", and any recipient on the response chain \"can remove transfer codings when they are not needed\" — so neither its presence nor its value is comparable across the two messages",
};

impl RuleMeta for HeadResponseHeadersMatchGet {
    fn id(&self) -> &'static str {
        "head_response_headers_match_get"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
headers = ["etag", "content-type", "content-length"]
"#
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        // The configured names are folded once at prepare time so the rest of the
        // rule can compare them as strings; the fold is the field name's own
        // rule, not a convenience.
        // cite(RFC 9110 § 5.1): "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry""
        let headers = crate::helpers::rule_config::parse_lowercased_list(
            cfg,
            self.id(),
            "headers",
            "header field-names to check",
            "['etag','content-type','content-length']",
        )?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            state: Box::new(crate::helpers::rule_config::HeaderNameList { headers }),
        })
    }

    fn title(&self) -> Option<&'static str> {
        Some("HEAD response headers match GET")
    }

    fn description(&self) -> &'static str {
        "Ensure responses to `HEAD` carry the header fields the server would have sent for a `GET` on the same resource. RFC 9110 §9.3.2 asks this with a SHOULD, and the configured `headers` array names the fields to compare; `Content-Length` is the exception, governed by §8.6's MUST NOT unless its value equals the octet count a `GET` would have delivered.\n\n**The comparison is evidence, not the sentence.** §9.3.2 is about the response the server *would have sent* for a `GET` at that moment, and what this rule has is the `GET`s it observed earlier. It reads all of them, and a `GET` counts only where it describes the same thing the `HEAD` does — the same status code, no `ETag` or `Last-Modified` that moved, and a request that selects the same representation under the response's `Vary` (RFC 9111 §4.1) — and then, field by field, only where every `GET` that counts gives the same answer. Two `GET`s that already disagree about a length are a resource that is not holding still, and a `HEAD` matching either of them or neither shows nothing about the server, so that field is not reported. What the rule cannot see is a representation that changed with no validator to show it and no second `GET` to disagree, so every finding assumes the resource held still between the exchanges it read. Where the `GET`'s own reading did not reach the end of its body, the octets it was counted for measure the reading and not the representation, and the `Content-Length` comparison declines rather than convict the later `HEAD` of an earlier client's disconnect.\n\n**The exceptions are an open class.** §9.3.2 permits a server to omit any header field whose value is determined only while generating the content, and no field announces its membership — so the rule can only excuse the ones a specification names: `Content-Length` (§8.6), `Vary` (§9.3.2's own example) and `Transfer-Encoding` (RFC 9112 §6.1, which also makes its value incomparable). A field outside that set which the server legitimately omitted is still reported; configure `headers` accordingly."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_9_3_2,
            RFC_9110_8_6,
            RFC_9110_8_8,
            RFC_9111_4_1,
            RFC_9112_6_1,
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
            // Each snippet is the observed GET exchange followed by the HEAD
            // exchange measured against it, on one resource.
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the HEAD carries the fields the GET carried)"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nETag: \"v2\"\nContent-Type: text/plain\nContent-Length: 42\n\nHEAD /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nETag: \"v2\"\nContent-Type: text/plain\nContent-Length: 42",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "(§9.3.2's own example: a value determined while generating the content need not be generated for a HEAD)",
                ),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nETag: \"v2\"\nContent-Type: text/plain\nContent-Length: 42\nVary: Accept-Encoding\n\nHEAD /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nETag: \"v2\"\nContent-Type: text/plain",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "(the representation changed between the two exchanges, and the entity tags say so)",
                ),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nETag: \"v1\"\nContent-Type: text/plain\n\nHEAD /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nETag: \"v2\"\nContent-Type: text/html",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "(two GETs had already disagreed about the length, so the resource is not holding still and the HEAD is measured against neither)",
                ),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 1951131\n\nGET /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 1951116\n\nHEAD /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 1951131",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "(RFC 9111 §4.1: the GET asked for gzip and was answered under Vary: Accept-Encoding, so its length belongs to a representation the HEAD did not select)",
                ),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip\n\nHTTP/1.1 200 OK\nContent-Type: text/html\nContent-Encoding: gzip\nVary: Accept-Encoding\nContent-Length: 234714\n\nHEAD /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Type: text/html\nVary: Accept-Encoding\nContent-Length: 1004024",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the HEAD omits a field the GET sent)"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nETag: \"v2\"\nContent-Type: text/plain\n\nHEAD /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Type: text/plain",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "(§8.6: a Content-Length that is not the octet count a GET would have delivered)",
                ),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 100\n\nHEAD /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 50",
            },
        ]
    }
}

impl Rule for HeadResponseHeadersMatchGet {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // The sentence the whole rule enforces, and the response it is about.
            // cite(RFC 9110 § 9.3.2): "The server SHOULD send the same header fields in response to a HEAD request as it would have sent if the request method had been GET."
            //
            // Which response that is, and why the comparison is exact rather than
            // case-insensitive: a lowercase `head` is a different method token, and
            // an unrecognized method has no defined relationship to GET at all.
            // cite(RFC 9110 § 9.3.2): "The HEAD method is identical to GET except that the server MUST NOT send content in the response."
            // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
            if tx.request.method != "HEAD" {
                return None;
            }

            let resp = tx.response.as_ref()?;

            // The counterfactual the sentence names is a GET, by the same token.
            // Every one the history holds is read, newest first, because what
            // they say about each other is evidence too: `unanimous` below
            // measures the HEAD against the newest only where the rest agree
            // with it. Taking only the immediately preceding transaction would
            // leave a GET followed by two HEADs measuring the first of them and
            // nothing else.
            //
            // The request-target comparison is not a requirement of any document:
            // the engine dispatches this rule with a `ByResource` history, already
            // keyed on this client and this target, so in the proxy and in `lint` it
            // cannot fail. It guards histories assembled by hand in tests.
            let gets: Vec<&crate::http_transaction::HttpTransaction> = history
                .iter()
                .filter(|t| t.request.method == "GET" && t.request.uri == tx.request.uri)
                .filter(|t| {
                    let Some(prev_resp) = t.response.as_ref() else {
                        return false;
                    };

                    // Two responses that report different results are not each
                    // other's counterfactual: the fields of a 404 describe the
                    // explanation it encloses, and the fields of a 200 describe
                    // the selected representation. Comparing them measures the
                    // resource's state changing, not the server's answer to
                    // § 9.3.2.
                    // cite(RFC 9110 § 15): "The status code of a response is a three-digit integer code that describes the result of the request and the semantics of the response, including whether the request was successful and what content is enclosed (if any)."
                    prev_resp.status == resp.status
                        // And a resource may simply have changed between the two
                        // exchanges.
                        && !selected_representation_changed(&prev_resp.headers, &resp.headers)
                        // And a GET whose request differs from this one in a field
                        // the response varies on was answered about another
                        // representation. Its fields are that representation's —
                        // the encoded length of a gzip variant is no count of the
                        // identity one — so it is not the GET § 9.3.2 names, which
                        // is *this* request with the method changed.
                        && crate::helpers::stored_response::selecting_fields_match(
                            &t.request.headers,
                            &prev_resp.headers,
                            &tx.request.headers,
                        )
                })
                .collect();
            if gets.is_empty() {
                return None;
            }

            // Parse config only after the cheap method/response/history guards above —
            // non-HEAD transactions (the common case) skip the allocation entirely.
            let config: &crate::helpers::rule_config::HeaderNameList = ctx.state();

            let report = |message: String| Some(ctx.report_with(&METHOD_HEAD_CONFLICTING, message));

            // For each configured header, enforce presence/value equivalence between GET and HEAD
            for name in &config.headers {
                let name_str = name.as_str();

                // `Transfer-Encoding` is answered by its own document, in both
                // directions and for the value as well: it may be sent, it need not
                // be, and what it names can be taken off the message by anyone on
                // the way. Nothing about the two responses' framing is comparable.
                // cite(RFC 9112 § 6.1): "Transfer-Encoding MAY be sent in a response to a HEAD request or in a 304 (Not Modified) response (Section 15.4.5 of [HTTP]) to a GET request, neither of which includes a message body, to indicate that the origin server would have applied a transfer coding to the message body if the request had been an unconditional GET."
                // cite(RFC 9112 § 6.1): "This indication is not required, however, because any recipient on the response chain (including the origin server) can remove transfer codings when they are not needed."
                if name_str == "transfer-encoding" {
                    continue;
                }

                // The GET this field is measured against, where the observed
                // GETs agree on one.
                let Some(prev_resp) = unanimous(&gets, name_str) else {
                    continue;
                };

                // `Content-Length` is answered whole by § 8.6 and not by the
                // presence comparison below: its absence from either response is
                // permitted, and its *value* is governed whenever the HEAD carries
                // one — including when the GET declared none at all.
                // ...and reported as its own entry, because § 8.6 states it as a
                // MUST NOT. Sharing `METHOD_HEAD_CONFLICTING` handed this
                // finding § 9.3.2's SHOULD, so a broken requirement arrived as
                // declined advice — a `warn` an operator filtering for `error`
                // never saw, citing a sentence that does not state it.
                if name_str == "content-length" {
                    if let Some(m) = content_length_finding(prev_resp, resp) {
                        return Some(ctx.report_with(&METHOD_HEAD_CONTENT_LENGTH_CONFLICTING, m));
                    }
                    continue;
                }

                // Both values as their sender wrote them: every field line of the
                // section, joined, as octets. Reading one line would measure a field
                // written across two against a field written across one, and
                // decoding would refuse the `obs-text` § 5.5 admits — while equality
                // of two field values is equality of two octet strings and needs no
                // decode at all.
                let prev_val = crate::helpers::headers::combined_field_value_as_written(
                    &prev_resp.headers,
                    name_str,
                );
                let head_val = crate::helpers::headers::combined_field_value_as_written(
                    &resp.headers,
                    name_str,
                );

                match (prev_val, head_val) {
                    (Some(_), None) if !presence_difference_is_permitted(name_str) => {
                        return report(format!(
                            "HEAD response missing header field that GET had: '{}'",
                            name_str
                        ));
                    }
                    (None, Some(_)) if !presence_difference_is_permitted(name_str) => {
                        return report(format!(
                            "HEAD response includes header field not present on GET: '{}'",
                            name_str
                        ));
                    }
                    (Some(av), Some(bv)) => {
                        if name_str == "vary" {
                            if vary_members(&av) != vary_members(&bv) {
                                return report(format!(
                                    "Vary header in HEAD differs from GET: '{}' vs '{}'",
                                    bv, av
                                ));
                            }
                            continue;
                        }

                        // Every other field is compared as written. A deployment
                        // that adds a list-typed field to `headers` buys the one
                        // divergence in this comparison: § 5.3 lets a sender spell
                        // the separator `,` or `, `, and one list written across two
                        // field lines joins with the first while the same list on one
                        // line usually carries the second.
                        if av != bv {
                            return report(format!(
                                "Header '{}' value differs between HEAD and GET ('{}' vs '{}')",
                                name_str, bv, av
                            ));
                        }
                    }
                    _ => {}
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &HeadResponseHeadersMatchGet;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[test]
    fn id_and_scope() {
        let r = HeadResponseHeadersMatchGet;
        assert_eq!(r.id(), "head_response_headers_match_get");
        assert!(r.needs_response());
    }

    fn make_prev_with_headers(pairs: &[(&str, &str)]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, pairs);
        tx.request.method = "GET".to_string();
        tx
    }

    fn make_head_with_headers(pairs: &[(&str, &str)]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, pairs);
        tx.request.method = "HEAD".to_string();
        tx
    }

    fn make_cfg_with_headers(headers: Vec<&str>) -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "headers".into(),
                    toml::Value::Array(
                        headers
                            .into_iter()
                            .map(|s| toml::Value::String(s.to_string()))
                            .collect(),
                    ),
                );
                t
            }),
        );
        cfg
    }

    #[test]
    fn matching_get_and_head_ok() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[
            ("etag", "\"v1\""),
            ("content-type", "text/plain"),
            ("content-length", "5"),
        ]);
        let mut head = make_head_with_headers(&[
            ("etag", "\"v1\""),
            ("content-type", "text/plain"),
            ("content-length", "5"),
        ]);
        // ensure URIs match
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["etag", "content-type", "content-length"]),
        );
        assert!(v.is_none());
    }

    /// The cross-transaction shape of the same mistake. The GET declared no
    /// length -- it was chunked -- so the octets it delivered are the only measure
    /// of the representation, and a reading that stopped early measures the
    /// reading. A HEAD stating the resource's real length is then reported for the
    /// earlier client's disconnect.
    #[test]
    fn a_get_the_client_abandoned_does_not_convict_a_later_head() {
        let rule = HeadResponseHeadersMatchGet;
        let mut prev = make_prev_with_headers(&[("transfer-encoding", "chunked")]);
        prev.response.as_mut().expect("response").body_length = Some(1700);

        let mut head = make_head_with_headers(&[("content-length", "4000")]);
        head.request.uri = prev.request.uri.clone();

        let run = |prev: crate::http_transaction::HttpTransaction| {
            crate::test_helpers::run_rule(
                &rule,
                &head,
                &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
                &make_cfg_with_headers(vec!["content-length"]),
            )
        };

        // The GET was read to its end, so 1700 octets is what the representation
        // was, and a HEAD claiming 4000 contradicts it.
        assert!(
            run(prev.clone()).is_some(),
            "a completed GET's delivery is a measure the HEAD must match"
        );

        prev.response.as_mut().expect("response").body_interrupted = true;
        assert!(
            run(prev).is_none(),
            "octets counted before the client left are not the representation's length"
        );
    }

    #[test]
    fn missing_header_on_head_reports_violation() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("etag", "\"v1\"")]);
        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["etag"]),
        );
        // Two answers about one resource that do not agree.
        let found = v.clone().expect("a finding");
        assert_eq!(found.violation, "method_head_conflicting");
        assert!(v.unwrap().message.contains("missing header"));
    }

    #[test]
    fn extra_header_on_head_reports_violation() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[]);
        let mut head = make_head_with_headers(&[("x-foo", "bar")]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["x-foo"]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("includes header field not present"));
    }

    #[test]
    fn content_length_mismatch_reports_violation() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("content-length", "10")]);
        let mut head = make_head_with_headers(&[("content-length", "5")]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["content-length"]),
        );
        // § 8.6's MUST NOT, and not § 9.3.2's SHOULD that the sibling entry
        // carries. The two were one entry once, and every real-traffic finding
        // this rule produced was this one arriving as a `warn` an operator
        // filtering for `error` never saw.
        let found = v.expect("a finding");
        assert_eq!(found.violation, "method_head_content_length_conflicting");
        assert_eq!(found.severity, crate::lint::Severity::Error);
        assert!(found.message.contains("Content-Length"));
    }

    #[test]
    fn content_length_missing_on_head_is_allowed() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("content-length", "10")]);
        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["content-length"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn vary_missing_on_head_is_allowed() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("vary", "accept-encoding")]);
        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["vary"]),
        );
        assert!(v.is_none());
    }

    // A GET followed by two HEADs: the second HEAD's immediately preceding
    // transaction is the first HEAD, and the GET is still the evidence.
    #[test]
    fn the_most_recent_get_is_found_past_an_intervening_head() {
        let get = make_prev_with_headers(&[("etag", "\"v1\"")]);
        let mut earlier_head = make_head_with_headers(&[]);
        earlier_head.request.uri = get.request.uri.clone();
        let mut head = make_head_with_headers(&[]);
        head.request.uri = get.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &HeadResponseHeadersMatchGet,
            &head,
            // newest first
            &crate::transaction_history::TransactionHistory::from_transactions(vec![
                earlier_head,
                get,
            ]),
            &make_cfg_with_headers(vec!["etag"]),
        );
        assert!(v.is_some());
    }

    /// Run the HEAD against a history of GETs given oldest first, as they
    /// happened, on one URI.
    fn after(
        gets: Vec<crate::http_transaction::HttpTransaction>,
        head: &crate::http_transaction::HttpTransaction,
        headers: Vec<&str>,
    ) -> Option<Violation> {
        let mut head = head.clone();
        let mut gets: Vec<_> = gets
            .into_iter()
            .map(|mut g| {
                g.request.uri = "http://example.com/one".into();
                g
            })
            .collect();
        head.request.uri = "http://example.com/one".into();
        gets.reverse();
        crate::test_helpers::run_rule(
            &HeadResponseHeadersMatchGet,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(gets),
            &make_cfg_with_headers(headers),
        )
    }

    /// Two GETs that already disagree about the length are a resource that is
    /// not holding still, and a HEAD matching either of them, or neither, has
    /// shown nothing about the server. Two that agree still measure it.
    #[rstest]
    #[case(&["1951131", "1951116"], "1951131", false)]
    #[case(&["1951131", "1951116"], "1951116", false)]
    #[case(&["1951131", "1951116"], "5", false)]
    #[case(&["1951131", "1951131"], "5", true)]
    #[case(&["1951131", "1951131"], "1951131", false)]
    #[case(&["7", "1951131", "1951131"], "5", false)]
    fn gets_that_disagree_with_each_other_convict_no_head(
        #[case] gets: &[&str],
        #[case] head_len: &str,
        #[case] expect_finding: bool,
    ) {
        let gets = gets
            .iter()
            .map(|len| make_prev_with_headers(&[("content-length", len)]))
            .collect();
        let head = make_head_with_headers(&[("content-length", head_len)]);
        let found = after(gets, &head, vec!["content-length"]);
        assert_eq!(found.is_some(), expect_finding, "{found:?}");
    }

    /// The same agreement is asked of every field, and a length delivered by a
    /// chunked GET counts as that GET's answer beside another's declaration.
    #[test]
    fn the_agreement_is_asked_field_by_field() {
        let head =
            make_head_with_headers(&[("content-type", "text/html"), ("content-length", "5")]);

        // The GETs disagree about the type and agree about the length: the type
        // is not reported and the length is.
        let found = after(
            vec![
                make_prev_with_headers(&[("content-type", "text/plain"), ("content-length", "9")]),
                make_prev_with_headers(&[("content-type", "text/html"), ("content-length", "9")]),
            ],
            &head,
            vec!["content-type", "content-length"],
        )
        .expect("the length is still measured");
        assert!(found.message.contains("Content-Length"), "{found:?}");

        // A chunked GET that delivered nine octets agrees with one that declared
        // nine, and the HEAD is measured against the declaration.
        let mut chunked = make_prev_with_headers(&[("transfer-encoding", "chunked")]);
        chunked.response.as_mut().expect("response").body_length = Some(9);
        let found = after(
            vec![chunked, make_prev_with_headers(&[("content-length", "9")])],
            &head,
            vec!["content-length"],
        )
        .expect("two readings of nine octets are one answer");
        assert!(found.message.contains("differs from GET (9)"), "{found:?}");
    }

    /// RFC 9111 § 4.1: a GET answered under `Vary: Accept-Encoding` to a
    /// request that asked for gzip selected a representation the HEAD did
    /// not, so its length is no evidence about the HEAD's. A HEAD presenting
    /// the same selecting field is measured against it as before, and a GET
    /// answered under `Vary: *` selected something no request can present.
    #[rstest]
    #[case(Some("gzip"), "Accept-Encoding", None, false)]
    #[case(None, "Accept-Encoding", Some("gzip"), false)]
    #[case(Some("gzip"), "Accept-Encoding", Some("br"), false)]
    #[case(Some("gzip"), "Accept-Encoding", Some("gzip"), true)]
    #[case(None, "Accept-Encoding", None, true)]
    #[case(Some("gzip"), "Accept-Language", None, true)]
    #[case(Some("gzip"), "*", Some("gzip"), false)]
    fn a_get_that_selected_another_representation_is_no_yardstick(
        #[case] get_asked: Option<&str>,
        #[case] vary: &str,
        #[case] head_asked: Option<&str>,
        #[case] expect_finding: bool,
    ) {
        fn asked(encoding: Option<&str>) -> Vec<(&str, &str)> {
            encoding
                .map(|e| ("accept-encoding", e))
                .into_iter()
                .collect()
        }
        let mut get = make_prev_with_headers(&[("vary", vary), ("content-length", "234714")]);
        get.request.headers = crate::test_helpers::make_headers_from_pairs(&asked(get_asked));
        let mut head = make_head_with_headers(&[("vary", vary), ("content-length", "1004024")]);
        head.request.headers = crate::test_helpers::make_headers_from_pairs(&asked(head_asked));

        let found = after(vec![get], &head, vec!["content-length"]);
        assert_eq!(found.is_some(), expect_finding, "{found:?}");
    }

    #[test]
    fn no_previous_does_nothing() {
        let rule = HeadResponseHeadersMatchGet;
        let head = make_head_with_headers(&[("etag", "\"v1\"")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg_with_headers(vec!["etag"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn previous_with_different_uri_ignored() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("etag", "\"v1\"")]);
        let mut head = make_head_with_headers(&[("etag", "\"v1\"")]);
        // different URIs
        head.request.uri = "/other".parse().unwrap();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["etag"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn previous_not_get_ignored() {
        let rule = HeadResponseHeadersMatchGet;
        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        prev.request.method = "POST".to_string();
        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["etag"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_header_value_counts_as_presence() {
        // A value `to_str` refuses is still a field the GET sent, and the HEAD
        // omitting it is the finding.
        let prev = with_raw_header(&make_prev_with_headers(&[]), "etag", &[0xff]);
        let head = make_head_with_headers(&[]);

        assert!(check(&prev, &head, vec!["etag"]).is_some());
    }

    #[test]
    fn header_name_case_insensitive_is_accepted() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("ETAG", "\"v1\"")]);
        let mut head = make_head_with_headers(&[("etag", "\"v1\"")]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["etag"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn parse_config_requires_headers_array() {
        let cfg = crate::config::Config::default();
        let rule = HeadResponseHeadersMatchGet;
        let res = rule.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_empty_headers_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "head_response_headers_match_get",
        ]);
        cfg.rules.insert(
            "head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("headers".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let rule = HeadResponseHeadersMatchGet;
        let res = rule.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_headers_item() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "head_response_headers_match_get",
        ]);
        cfg.rules.insert(
            "head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "headers".into(),
                    toml::Value::Array(vec![toml::Value::Integer(1)]),
                );
                t
            }),
        );

        let rule = HeadResponseHeadersMatchGet;
        let res = rule.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_lowercases_headers_items() -> anyhow::Result<()> {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "head_response_headers_match_get",
        ]);
        cfg.rules.insert(
            "head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "headers".into(),
                    toml::Value::Array(vec![toml::Value::String("ETag".into())]),
                );
                t
            }),
        );

        let parsed = HeadResponseHeadersMatchGet.prepare(&cfg)?;
        let parsed: &crate::helpers::rule_config::HeaderNameList =
            parsed.state.downcast_ref().expect("header name list state");
        assert!(parsed.headers.contains(&"etag".to_string()));
        Ok(())
    }

    /// Run the rule over a GET/HEAD pair on one resource.
    ///
    /// Every case needs the two transactions to name the same request-target,
    /// and writing that line per test is what let one of them assert a verdict
    /// the rule reached for a reason the test never named.
    fn check(
        prev: &crate::http_transaction::HttpTransaction,
        head: &crate::http_transaction::HttpTransaction,
        headers: Vec<&str>,
    ) -> Option<Violation> {
        let mut head = head.clone();
        head.request.uri = prev.request.uri.clone();
        crate::test_helpers::run_rule(
            &HeadResponseHeadersMatchGet,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &make_cfg_with_headers(headers),
        )
    }

    /// Replace a response's headers with raw octets a `&str` cannot carry.
    fn with_raw_header(
        tx: &crate::http_transaction::HttpTransaction,
        name: &'static str,
        bytes: &[u8],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = tx.clone();
        let resp = tx.response.as_ref().unwrap();
        let mut hm = resp.headers.clone();
        hm.insert(name, HeaderValue::from_bytes(bytes).unwrap());
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: resp.status,
            version: resp.version.clone(),
            headers: hm,
            body_length: resp.body_length,
            body_interrupted: false,
            trailers: None,
        });
        tx
    }

    #[test]
    fn header_value_mismatch_reports_violation() {
        let prev = make_prev_with_headers(&[("content-type", "text/plain")]);
        let head = make_head_with_headers(&[("content-type", "text/html")]);

        let v = check(&prev, &head, vec!["content-type"]);
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("Header 'content-type' value differs"));
    }

    // The representation is free to change between the two exchanges, and both
    // validators say when it did — §8.8's sentence is why a difference in
    // anything else is then not this rule's finding.
    #[test]
    fn etag_difference_declines_the_whole_comparison() {
        let prev = make_prev_with_headers(&[("etag", "\"v1\""), ("content-type", "text/plain")]);
        let head = make_head_with_headers(&[("etag", "\"v2\""), ("content-type", "text/html")]);

        assert!(check(&prev, &head, vec!["etag", "content-type"]).is_none());
    }

    #[test]
    fn last_modified_difference_declines_the_whole_comparison() {
        let prev = make_prev_with_headers(&[
            ("last-modified", "Tue, 15 Nov 1994 12:45:26 GMT"),
            ("content-type", "text/plain"),
        ]);
        let head = make_head_with_headers(&[
            ("last-modified", "Wed, 16 Nov 1994 12:45:26 GMT"),
            ("content-type", "text/html"),
        ]);

        assert!(check(&prev, &head, vec!["content-type"]).is_none());
    }

    // A weak tag and its strong twin name one representation (§8.8.3.2's weak
    // comparison), so the comparison runs — and the field values still differ,
    // which is §9.3.2's finding.
    #[test]
    fn weak_and_strong_form_of_one_tag_is_still_compared() {
        let prev = make_prev_with_headers(&[("etag", "W/\"v1\"")]);
        let head = make_head_with_headers(&[("etag", "\"v1\"")]);

        let v = check(&prev, &head, vec!["etag"]);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Header 'etag' value differs"));
    }

    // §15: two responses reporting different results are not each other's
    // counterfactual.
    #[test]
    fn different_status_codes_decline() {
        let prev = make_prev_with_headers(&[("content-type", "text/plain")]);
        let mut head = make_head_with_headers(&[("content-type", "text/html")]);
        head.response.as_mut().unwrap().status = 404;

        assert!(check(&prev, &head, vec!["content-type"]).is_none());
    }

    // §9.1: the method token is case-sensitive, in both positions.
    #[test]
    fn lowercase_head_is_not_the_head_method() {
        let prev = make_prev_with_headers(&[("etag", "\"v1\"")]);
        let mut head = make_head_with_headers(&[]);
        head.request.method = "head".to_string();

        assert!(check(&prev, &head, vec!["etag"]).is_none());
    }

    #[test]
    fn lowercase_get_is_not_the_get_method() {
        let mut prev = make_prev_with_headers(&[("etag", "\"v1\"")]);
        prev.request.method = "get".to_string();
        let head = make_head_with_headers(&[]);

        assert!(check(&prev, &head, vec!["etag"]).is_none());
    }

    // Equality of two field values is equality of two octet strings; `to_str`
    // refusing `obs-text` is not a reason to stop comparing.
    #[test]
    fn non_utf8_values_that_differ_are_reported() {
        let prev = with_raw_header(&make_prev_with_headers(&[]), "content-type", &[0xff]);
        let head = with_raw_header(&make_head_with_headers(&[]), "content-type", &[0xfe]);

        assert!(check(&prev, &head, vec!["content-type"]).is_some());
    }

    #[test]
    fn non_utf8_values_that_match_are_not_reported() {
        let prev = with_raw_header(&make_prev_with_headers(&[]), "content-type", &[0xff]);
        let head = with_raw_header(&make_head_with_headers(&[]), "content-type", &[0xff]);

        assert!(check(&prev, &head, vec!["content-type"]).is_none());
    }

    // §5.2: several field lines are one value, so reading the first measures
    // half of it.
    #[test]
    fn field_written_across_two_lines_is_compared_whole() {
        let prev =
            make_prev_with_headers(&[("cache-control", "no-cache"), ("cache-control", "private")]);
        let head = make_head_with_headers(&[("cache-control", "no-cache")]);

        assert!(check(&prev, &head, vec!["cache-control"]).is_some());
    }

    // RFC 9112 §6.1: the indication is not required and any recipient may
    // remove the codings, so its value is not comparable either.
    #[test]
    fn transfer_encoding_value_difference_is_not_reported() {
        let prev = make_prev_with_headers(&[("transfer-encoding", "gzip, chunked")]);
        let head = make_head_with_headers(&[("transfer-encoding", "chunked")]);

        assert!(check(&prev, &head, vec!["transfer-encoding"]).is_none());
    }

    // §8.6's MUST NOT is about a count of octets, and a chunked GET declares
    // none — the octets it delivered are the same count, measured.
    #[test]
    fn content_length_compared_against_the_octets_a_chunked_get_delivered() {
        let mut prev = make_prev_with_headers(&[("transfer-encoding", "chunked")]);
        prev.response.as_mut().unwrap().body_length = Some(7);
        let head = make_head_with_headers(&[("content-length", "42")]);

        let v = check(&prev, &head, vec!["content-length"]);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("7 octets"));
    }

    #[test]
    fn content_length_matching_a_chunked_gets_octets_is_not_reported() {
        let mut prev = make_prev_with_headers(&[("transfer-encoding", "chunked")]);
        prev.response.as_mut().unwrap().body_length = Some(42);
        let head = make_head_with_headers(&[("content-length", "42")]);

        assert!(check(&prev, &head, vec!["content-length"]).is_none());
    }

    #[test]
    fn head_has_unchecked_header_is_ignored() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[]);
        let mut head = make_head_with_headers(&[("x-foo", "bar")]);
        head.request.uri = prev.request.uri.clone();

        // 'x-foo' is not in the configured headers list -> should be ignored
        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["etag"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn transfer_encoding_on_head_allowed_when_prev_missing() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[]);
        let mut head = make_head_with_headers(&[("transfer-encoding", "chunked")]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["transfer-encoding"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn transfer_encoding_missing_on_head_is_allowed() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("transfer-encoding", "chunked")]);
        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["transfer-encoding"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn content_length_prev_invalid_is_ignored() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("content-length", "abc")]);
        let mut head = make_head_with_headers(&[("content-length", "5")]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["content-length"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn vary_order_different_but_same_members_ok() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("vary", "Accept-Encoding, Accept")]);
        let mut head = make_head_with_headers(&[("vary", "accept, accept-encoding")]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["vary"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn vary_different_members_reports_violation() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("vary", "a, b")]);
        let mut head = make_head_with_headers(&[("vary", "a, c")]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["vary"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Vary"));
    }

    /// `vary_different_members_reports_violation` with the difference written as
    /// the one octet the recipient's walk used to erase. `Vary = #( "*" /
    /// field-name )` and `field-name = token`, so `b<%xA0>` is not the member
    /// `b` — the two responses advertise different sets, which is the finding.
    /// `str::trim` made them the same set, and the comparison here is over a
    /// value read one `char` per octet, so %xA0 arrives as itself.
    #[test]
    fn vary_members_differing_by_one_obs_text_octet_report() {
        let rule = HeadResponseHeadersMatchGet;
        let mut prev = make_prev_with_headers(&[]);
        prev.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_octet_pairs(&[("vary", b"a, b\xA0".as_slice())]);
        let mut head = make_head_with_headers(&[("vary", "a, b")]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &make_cfg_with_headers(vec!["vary"]),
        );
        assert!(
            v.as_ref().is_some_and(|v| v.message.contains("Vary")),
            "{v:?}"
        );
    }

    #[test]
    fn previous_response_missing_is_ignored() {
        let rule = HeadResponseHeadersMatchGet;
        let mut prev = crate::test_helpers::make_test_transaction();
        prev.request.method = "GET".to_string();
        prev.response = None;

        let mut head = make_head_with_headers(&[("etag", "\"v1\"")]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["etag"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_headers_mismatch_reports_violation() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("etag", "\"v1\""), ("content-type", "text/plain")]);
        let mut head = make_head_with_headers(&[("etag", "\"v1\""), ("content-type", "text/html")]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["etag", "content-type"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("content-type"));
    }

    #[test]
    fn accept_encoding_order_mismatch_reports_violation() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("accept-encoding", "gzip, deflate")]);
        let mut head = make_head_with_headers(&[("accept-encoding", "deflate, gzip")]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["accept-encoding"]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn validate_parses_config() -> anyhow::Result<()> {
        let mut full_cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "head_response_headers_match_get",
        ]);
        full_cfg.rules.insert(
            "head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "headers".into(),
                    toml::Value::Array(vec![toml::Value::String("etag".into())]),
                );
                t
            }),
        );

        let arc = HeadResponseHeadersMatchGet.prepare(&full_cfg)?;
        let arc: &crate::helpers::rule_config::HeaderNameList =
            arc.state.downcast_ref().expect("header name list state");
        assert!(arc.headers.contains(&"etag".to_string()));
        Ok(())
    }

    #[test]
    fn parse_config_rejects_headers_not_array() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "head_response_headers_match_get",
        ]);
        cfg.rules.insert(
            "head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("headers".into(), toml::Value::String("etag".into()));
                t
            }),
        );

        let res = HeadResponseHeadersMatchGet.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_table_rule_cfg() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "head_response_headers_match_get",
        ]);
        cfg.rules.insert(
            "head_response_headers_match_get".into(),
            toml::Value::String("not a table".into()),
        );

        let res = HeadResponseHeadersMatchGet.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn head_missing_response_is_ignored() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("etag", "\"v1\"")]);
        // create a HEAD transaction without a response
        let mut head = crate::test_helpers::make_test_transaction();
        head.request.method = "HEAD".to_string();
        head.response = None;
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["etag"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_content_length_values_in_prev_are_ignored() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[("content-length", "10"), ("content-length", "20")]);
        let mut head = make_head_with_headers(&[("content-length", "10")]);
        head.request.uri = prev.request.uri.clone();

        // validate_content_length on prev will error -> rule must be lenient
        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["content-length"]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn configured_header_missing_in_both_is_ignored() {
        let rule = HeadResponseHeadersMatchGet;
        let prev = make_prev_with_headers(&[]);
        let mut head = make_head_with_headers(&[]);
        head.request.uri = prev.request.uri.clone();

        let v = crate::test_helpers::run_rule(
            &rule,
            &head,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &make_cfg_with_headers(vec!["etag"]),
        );
        assert!(v.is_none());
    }

    /// Nothing else runs a rule's published examples through it. Each snippet
    /// is a run of exchanges, two blocks each — every observed GET's request
    /// and response in the order they happened, then the HEAD's — and the
    /// fields config_example.toml ships are what judge them.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;

        fn exchange(request: &str, response: &str) -> crate::http_transaction::HttpTransaction {
            let mut lines = request.lines();
            let request_line = lines.next().expect("a request has a request line");
            let parts: Vec<&str> = request_line.split(' ').collect();
            let [method, target, "HTTP/1.1"] = parts.as_slice() else {
                panic!("not a request line: {request_line:?}");
            };
            let request_fields: Vec<(&str, &str)> = lines
                .map(|line| {
                    line.split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {line:?}"))
                })
                .collect();

            let mut lines = response.lines();
            let status_line = lines.next().expect("a response has a status line");
            let status: u16 = status_line
                .strip_prefix("HTTP/1.1 ")
                .and_then(|rest| rest.split(' ').next())
                .and_then(|code| code.parse().ok())
                .unwrap_or_else(|| panic!("not a status line: {status_line:?}"));
            let fields: Vec<(&str, &str)> = lines
                .map(|line| {
                    line.split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {line:?}"))
                })
                .collect();

            let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &fields);
            tx.request.method = (*method).to_string();
            tx.request.uri = (*target).to_string();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&request_fields);
            tx
        }

        let mut saw_a_finding = false;
        for ex in HeadResponseHeadersMatchGet.examples() {
            let blocks: Vec<&str> = ex.snippet.split("\n\n").collect();
            let mut exchanges: Vec<crate::http_transaction::HttpTransaction> = blocks
                .chunks(2)
                .map(|pair| {
                    let [req, resp] = pair else {
                        panic!("a request without its response: {:?}", ex.snippet);
                    };
                    exchange(req, resp)
                })
                .collect();
            let head = exchanges.pop().expect("a HEAD exchange");
            assert!(
                !exchanges.is_empty(),
                "no GET before the HEAD: {:?}",
                ex.snippet
            );
            // The history is newest first.
            exchanges.reverse();

            let found = crate::test_helpers::run_rule(
                &HeadResponseHeadersMatchGet,
                &head,
                &crate::transaction_history::TransactionHistory::from_transactions(exchanges),
                &make_cfg_with_headers(vec!["etag", "content-type", "content-length"]),
            );

            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "example labelled Compliant is reported: {:?} -> {:?}",
                    ex.snippet,
                    found.map(|v| v.message)
                ),
                Compliance::NonCompliant => {
                    assert!(
                        found.is_some(),
                        "example labelled NonCompliant is not reported: {:?}",
                        ex.snippet
                    );
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "the guard ran without reaching a finding");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "head_response_headers_match_get".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "headers".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("etag".into()),
                        toml::Value::String("content-type".into()),
                    ]),
                );
                t
            }),
        );

        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
