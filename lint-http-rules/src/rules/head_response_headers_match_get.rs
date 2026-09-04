// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

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

/// The `Content-Length` half, which is the one requirement here that is not
/// § 9.3.2's SHOULD.
///
// cite(RFC 9110 § 8.6): "A server MAY send a Content-Length header field in a response to a HEAD request (Section 9.3.2); a server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a response if the same request had used the GET method."
///
/// The number the MUST NOT names is a count of octets, and the previous GET
/// holds two pieces of evidence about it: what it declared, and what it
/// actually delivered. The declaration answers first, because that is the
/// number a `Content-Length` is; where the GET declared none — it was chunked,
/// or it is HTTP/2 or HTTP/3, where there is no framing field to declare — the
/// captured octets are the same count measured rather than claimed, so the
/// requirement is still decidable. A GET whose declaration and delivery
/// disagree is `response_body_length_accuracy`'s finding, not this
/// rule's, and it is left to it — that rule cites this same sentence as the
/// reason it exempts a HEAD response from its own comparison, and hands the
/// requirement here by name: it has one transaction and this one has two.
///
// cite(RFC 9110 § 6.4): "HTTP messages often transfer a complete or partial representation as the message "content": a stream of octets sent after the header section, as delineated by the message framing."
fn content_length_finding(
    prev_resp: &crate::http_transaction::ResponseInfo,
    resp: &crate::http_transaction::ResponseInfo,
) -> Option<String> {
    let cur_len = crate::helpers::content_length::declared_content_length(&resp.headers)?;

    if let Some(declared) =
        crate::helpers::content_length::declared_content_length(&prev_resp.headers)
    {
        return (declared != cur_len).then(|| {
            format!(
                "Content-Length in HEAD ({}) differs from GET ({})",
                cur_len, declared
            )
        });
    }

    // Only where the content of that response *is* the selected representation
    // the HEAD is asking about; a 304 declares the length of a 200 it did not
    // send, so its captured zero says nothing.
    // cite(RFC 9110 § 15.3.1): "The content sent in a 200 response depends on the request method."
    let captured = (prev_resp.status == 200)
        .then_some(prev_resp.body_length)
        .flatten()?;
    (u128::from(captured) != cur_len).then(|| {
        format!(
            "Content-Length in HEAD ({}) differs from the {} octets of content the GET response delivered",
            cur_len, captured
        )
    })
}

pub struct HeadResponseHeadersMatchGet;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_9_3_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("9.3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2",
    note: "The rule's sentence, quoted whole: \"The server SHOULD send the same header fields in response to a HEAD request as it would have sent if the request method had been GET. However, a server MAY omit header fields for which a value is determined only while generating the content.\" The MAY names a class, and the section prints Content-Length and Vary as examples of it rather than as its membership",
};
const RFC_9110_8_6: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.6"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6",
    note: "Content-Length is the one requirement here that is not a SHOULD: \"a server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a response if the same request had used the GET method\". The same sentence opens with the MAY that lets a HEAD response omit it",
};
const RFC_9110_8_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.8"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8",
    note: "Why a difference between the two responses is not automatically a finding: validator fields \"describe the selected representation chosen by the origin server while handling the response\", so an ETag or Last-Modified that moved between the observed GET and this HEAD says the resource changed, and the rule declines",
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

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let severity = crate::rules::get_rule_severity_required(cfg, self.id())?;
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
            severity,
            state: Box::new(crate::helpers::rule_config::HeaderNameList { headers }),
        })
    }

    fn title(&self) -> Option<&'static str> {
        Some("HEAD response headers match GET")
    }

    fn description(&self) -> &'static str {
        "Ensure responses to `HEAD` carry the header fields the server would have sent for a `GET` on the same resource. RFC 9110 §9.3.2 asks this with a SHOULD, and the configured `headers` array names the fields to compare; `Content-Length` is the exception, governed by §8.6's MUST NOT unless its value equals the octet count a `GET` would have delivered.\n\n**The comparison is evidence, not the sentence.** §9.3.2 is about the response the server *would have sent* for a `GET` at that moment, and what this rule has is a `GET` it observed earlier. It therefore declines whenever the two responses say they describe different things — a different status code, or a different `ETag` or `Last-Modified`. What it cannot see is a representation that changed with no validator to show it, so every finding assumes the resource held still between the two exchanges.\n\n**The exceptions are an open class.** §9.3.2 permits a server to omit any header field whose value is determined only while generating the content, and no field announces its membership — so the rule can only excuse the ones a specification names: `Content-Length` (§8.6), `Vary` (§9.3.2's own example) and `Transfer-Encoding` (RFC 9112 §6.1, which also makes its value incomparable). A field outside that set which the server legitimately omitted is still reported; configure `headers` accordingly."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_9_3_2, RFC_9110_8_6, RFC_9110_8_8, RFC_9112_6_1]
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
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
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

            // The counterfactual the sentence names is a GET, by the same token —
            // the most recent one, since the further back the evidence is, the less
            // it says about what the server would send now. Taking only the
            // immediately preceding transaction would leave a GET followed by two
            // HEADs measuring the first of them and nothing else.
            //
            // The request-target comparison is not a requirement of any document:
            // the engine dispatches this rule with a `ByResource` history, already
            // keyed on this client and this target, so in the proxy and in `lint` it
            // cannot fail. It guards histories assembled by hand in tests.
            let prev = history
                .iter()
                .find(|t| t.request.method == "GET" && t.request.uri == tx.request.uri)?;

            let prev_resp = prev.response.as_ref()?;

            // Two responses that report different results are not each other's
            // counterfactual: the fields of a 404 describe the explanation it
            // encloses, and the fields of a 200 describe the selected
            // representation. Comparing them measures the resource's state changing,
            // not the server's answer to § 9.3.2.
            // cite(RFC 9110 § 15): "The status code of a response is a three-digit integer code that describes the result of the request and the semantics of the response, including whether the request was successful and what content is enclosed (if any)."
            if prev_resp.status != resp.status {
                return None;
            }

            // And a resource may simply have changed between the two exchanges.
            if selected_representation_changed(&prev_resp.headers, &resp.headers) {
                return None;
            }

            // Parse config only after the cheap method/response/history guards above —
            // non-HEAD transactions (the common case) skip the allocation entirely.
            let config: &crate::helpers::rule_config::HeaderNameList = ctx.state();

            let report = |message: String| Some(self.violation(ctx.severity, message));

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

                // `Content-Length` is answered whole by § 8.6 and not by the
                // presence comparison below: its absence from either response is
                // permitted, and its *value* is governed whenever the HEAD carries
                // one — including when the GET declared none at all.
                if name_str == "content-length" {
                    if let Some(m) = content_length_finding(prev_resp, resp) {
                        return report(m);
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
                            // The field value is a set of field names, and field
                            // names are case-insensitive — so two spellings of one
                            // set are one advertisement, and neither the order nor
                            // the case is part of what was advertised.
                            // cite(RFC 9110 § 12.5.5): "A Vary field value is either the wildcard member "*" or a list of request field names, known as the selecting header fields, that might have had a role in selecting the representation for this response."
                            // cite(RFC 9110 § 5.1): "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry""
                            //
                            // The sort is what "set" means here, and the field's
                            // first stated purpose is where it comes from: what a
                            // recipient does with the value is look each named field
                            // up, which no ordering changes.
                            // cite(RFC 9110 § 12.5.5): "To inform cache recipients that they MUST NOT use this response to satisfy a later request unless the later request has the same values for the listed header fields as the original request"
                            //
                            // `list_members` drops empty members, which is the
                            // recipient's reading and the right one for a question
                            // about what was advertised; a sender that writes
                            // `Accept, , Accept-Encoding` is `vary_header_valid`'s.
                            let members = |v: &str| {
                                let mut m: Vec<String> = crate::helpers::list::list_members(v)
                                    .map(|s| s.to_ascii_lowercase())
                                    .collect();
                                m.sort_unstable();
                                m
                            };
                            if members(&av) != members(&bv) {
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

    #[test]
    fn id_and_scope() {
        let r = HeadResponseHeadersMatchGet;
        assert_eq!(r.id(), "head_response_headers_match_get");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
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
                t.insert("severity".into(), toml::Value::String("warn".into()));
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
        assert!(v.is_some());
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
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Content-Length"));
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
                t.insert("severity".into(), toml::Value::String("warn".into()));
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
                t.insert("severity".into(), toml::Value::String("warn".into()));
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
                t.insert("severity".into(), toml::Value::String("warn".into()));
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
                t.insert("severity".into(), toml::Value::String("warn".into()));
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
                t.insert("severity".into(), toml::Value::String("warn".into()));
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
    /// is four blocks — the observed GET's request and response, then the
    /// HEAD's — and the fields config_example.toml ships are what judge them.
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
            tx
        }

        let mut saw_a_finding = false;
        for ex in HeadResponseHeadersMatchGet.examples() {
            let blocks: Vec<&str> = ex.snippet.split("\n\n").collect();
            let [get_req, get_resp, head_req, head_resp] = blocks.as_slice() else {
                panic!("not two exchanges: {:?}", ex.snippet);
            };

            let found = check(
                &exchange(get_req, get_resp),
                &exchange(head_req, head_resp),
                vec!["etag", "content-type", "content-length"],
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
                t.insert("severity".into(), toml::Value::String("warn".into()));
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
