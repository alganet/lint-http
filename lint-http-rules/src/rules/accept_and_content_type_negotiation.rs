// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct AcceptAndContentTypeNegotiation;

impl Rule for AcceptAndContentTypeNegotiation {
    fn id(&self) -> &'static str {
        "accept_and_content_type_negotiation"
    }

    // A transaction rule: it reads a request field and a response field and
    // compares them, so neither half alone is its subject. Accept is the
    // request side of proactive negotiation — the field a user agent sends to
    // state a preference — and Content-Type is what the response came back
    // with. (Accept may also appear in a response, where §12.5.1 says it
    // describes a *subsequent* request; that is a different field's job and
    // this rule does not read it.)
    // cite(RFC 9110 § 12.5.1): "The "Accept" header field can be used by user agents to specify their preferences regarding response media types."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // What this rule is, stated before anything it does: an advisory, not a
        // conformance check. RFC 9110 gives the origin server the choice
        // outright — a representation the Accept header does not cover may be
        // sent, and the header simply disregarded — so a message this rule
        // reports may be entirely conforming. §12.1 says the same from the
        // client's side. What is left is worth saying anyway, because a
        // response the client cannot use is usually not what the server meant
        // to send; it is a suggestion, and the finding is worded as one.
        // cite(RFC 9110 § 12.4.1): "If a content negotiation header field is present in a request and none of the available representations for the response can be considered acceptable according to it, the origin server can either honor the header field by sending a 406 (Not Acceptable) response or disregard the header field by treating the response as if it is not subject to content negotiation for that request header field."
        // cite(RFC 9110 § 12.1): "A user agent cannot rely on proactive negotiation preferences being consistently honored, since the origin server might not implement proactive negotiation for the requested resource or might decide that sending a response that doesn't conform to the user agent's preferences is better than sending a 406 (Not Acceptable) response."
        //
        // The whole Accept field, not its first line. `Accept` is a list field,
        // so a sender may spread its members over several field lines and a
        // recipient recombines them into one comma-separated list — reading
        // only the first announced that a response was unacceptable to a client
        // that had listed it on the second. The helper performs exactly the
        // §5.3 recombination, joining the lines with comma-SP; it returns None
        // for a value carrying obs-text, which only ever suppresses an advisory
        // finding and never produces one.
        // cite(RFC 9110 § 12.5.1): "Accept = #( media-range [ weight ] )"
        let accept = crate::helpers::headers::get_all_header_values(&tx.request.headers, "accept");
        let accept = accept.as_deref();
        let resp = tx.response.as_ref()?;

        // One Content-Type, or no opinion. With two field lines there is no
        // single media type the response sent: RFC 9110 §8.3 says recipients
        // differ over which member of a duplicated Content-Type they act on, so
        // whether the client got something it asked for depends on which one it
        // reads. Judging the first would be a guess dressed as a finding. The
        // duplication itself is `content_type_valid`'s to report.
        // cite(RFC 9110 § 8.3): "Recipients often attempt to handle this error by using the last syntactically valid member of the list, leading to potential interoperability and security issues if different implementations have different error handling behaviors."
        let mut cts = resp.headers.get_all("content-type").iter();
        let content_type = cts.next()?.to_str().ok()?;
        if cts.next().is_some() {
            return None;
        }

        // A 406 is the server taking the *other* branch of §12.4.1's choice: it
        // honoured the header rather than disregarding it, and this status is
        // how it says so. Suggesting a 406 to a response that is one would be
        // the rule arguing with itself.
        // cite(RFC 9110 § 15.5.7): "The 406 (Not Acceptable) status code indicates that the target resource does not have a current representation that would be acceptable to the user agent"
        if resp.status == 406 {
            return None;
        }

        // No Accept, no preference, nothing to be inconsistent with. §12.4.1
        // says what an absent negotiation field means, so this is a licensed
        // silence rather than a shortcut.
        // cite(RFC 9110 § 12.4.1): "For each of the content negotiation fields, a request that does not contain the field implies that the sender has no preference on that dimension of negotiation."
        let accept = accept?;

        // Parse response Content-Type media-type
        let parsed_ct = match crate::helpers::headers::parse_media_type(content_type) {
            Ok(p) => p,
            Err(_) => return None, // content-type parsing is handled by other rules
        };

        // Iterate Accept members and see if any non-zero-q member matches the response Content-Type
        let mut matched = false;
        // Whether the header expressed a preference this rule could read at
        // all. A finding here says the response is not among the media types
        // the client asked for, and that is a claim about what the client
        // asked for — so it needs at least one member that is a `media-range`.
        let mut readable_preference = false;

        // An odd number of DQUOTEs means the quoting never closes, and then no
        // separator after it is a separator — both splitters below swallow the
        // rest of the field into one member. A finding drawn from that would be
        // a false statement about the request:
        //
        //     Accept: text/html;foo="x, application/json
        //
        // plainly lists `application/json`, and the response was reported for
        // not being it. The value is malformed either way — `"` is not a
        // `tchar` in an unquoted parameter value — so nothing conforming is
        // lost, and `accept_header_media_type_syntax` is the rule that
        // reports the malformed header.
        if !crate::helpers::headers::quoting_is_balanced(accept) {
            return None;
        }
        // Quote-aware, because a comma inside a quoted parameter value is not a
        // list separator. A raw `split(',')` cut such a value apart and read the
        // pieces as members of their own, so `text/plain;foo="a,image/png,b"` —
        // which accepts `text/plain` and nothing else — was read as accepting
        // `image/png` too, and a response nobody asked for went unreported.
        for member in crate::helpers::headers::split_commas_respecting_quotes(accept) {
            if member.is_empty() {
                continue;
            }
            // Quote-aware for the same reason the comma split is: a `;` inside
            // a quoted parameter value does not start a parameter. A raw
            // `split(';')` read the pieces as parameters, so a `q=0` sitting
            // inside some other value — `foo="a;q=0;b=1"` — was taken for a
            // weight and the member declared unacceptable, when the member has
            // no weight at all and accepts everything it names.
            let mut parts =
                crate::helpers::headers::split_semicolons_respecting_quotes(member).into_iter();
            let media = match parts.next() {
                Some(m) => m,
                None => continue,
            };
            // `media-range` is one of three shapes, and a bare `*` is none of
            // them: the asterisk groups media *types* into ranges, so it stands
            // for a whole type or a whole subtype, never for the pair. A
            // wildcard type with a concrete subtype — `*/json` — is not a range
            // either, though it parses as a media-type.
            // cite(RFC 9110 § 12.5.1): "media-range    = ( "*/*" / ( type "/" "*" ) / ( type "/" subtype ) ) parameters"
            // cite(RFC 9110 § 12.5.1): "The asterisk "*" character is used to group media types into ranges, with "*/*" indicating all media types and "type/*" indicating all subtypes of that type."
            let range = match crate::helpers::headers::parse_media_type(media) {
                Ok(mr) if mr.type_ != "*" || mr.subtype == "*" => mr,
                _ => continue,
            };
            readable_preference = true;

            // Every parameter is examined for the name `q`, not just the last
            // one, and the name is matched without regard to case. Both are
            // §12.5.1's instruction to recipients: senders *should* put the
            // weight last, and a recipient should find it wherever it is.
            // cite(RFC 9110 § 12.5.1): "Recipients SHOULD process any parameter named "q" as weight, regardless of parameter ordering."
            // cite(RFC 9110 § 5.6.6): "Parameter names are case-insensitive."
            //
            // A segment with no `=` names no weight and is skipped rather than
            // judged: that it derives from no `parameter` is
            // `accept_header_media_type_syntax`'s finding, and this rule
            // is only asking whether the member refuses what the response sent.
            let mut qval: Option<&str> = None;
            for parameter in parts.filter_map(crate::helpers::headers::parameter_of) {
                let Ok(parameter) = parameter else { continue };
                if parameter.name.eq_ignore_ascii_case("q") {
                    qval = Some(parameter.value);
                }
            }

            // A weight of zero is a refusal, and that is the one thing a weight
            // tells this rule. But it says so only when it *is* a weight: the
            // meaning belongs to `qvalue`, and `q=-1` is not one. A raw
            // `parse::<f32>()` read that as less than zero and refused the
            // member on the strength of a value the grammar does not admit,
            // which turned a malformed Accept into a finding about the
            // response. Anything that is not a qvalue leaves the member at its
            // default weight of 1, which is also what a member with no `q` gets.
            // cite(RFC 9110 § 12.4.2): "The weight is normalized to a real number in the range 0 through 1, where 0.001 is the least preferred and 1 is the most preferred; a value of 0 means "not acceptable"."
            // cite(RFC 9110 § 12.4.2): "If no "q" parameter is present, the default weight is 1."
            if let Some(q) = qval {
                if crate::helpers::headers::valid_qvalue(q)
                    && q.parse::<f32>().is_ok_and(|n| n == 0.0)
                {
                    continue;
                }
            }

            // The three shapes, matched by what each one ranges over: `*/*`
            // covers every media type, `type/*` every subtype of its type, and
            // `type/subtype` only itself. The asterisks are compared literally
            // because they are literals; the type and subtype tokens are
            // compared without regard to case because they are case-insensitive.
            //
            // The range's own parameters are not compared, and that is a
            // leniency rather than a reading of the grammar: §12.5.1 says a
            // range may carry media type parameters and that a more specific
            // range takes precedence, so `text/plain;format=flowed` and
            // `text/plain;format=fixed` are different preferences. Treating
            // them as one can only make this rule quieter, never noisier, which
            // suits an advisory — but it does mean a response whose parameters
            // nobody asked for goes unmentioned.
            // cite(RFC 9110 § 12.5.1): "The media-range can include media type parameters that are applicable to that range."
            // cite(RFC 9110 § 12.5.1): "If more than one media range applies to a given type, the most specific reference has precedence."
            // cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
            let type_matches =
                range.type_ == "*" || range.type_.eq_ignore_ascii_case(parsed_ct.type_);
            let subtype_matches =
                range.subtype == "*" || range.subtype.eq_ignore_ascii_case(parsed_ct.subtype);
            if type_matches && subtype_matches {
                matched = true;
                break;
            }
        }

        // No member was a media-range, so the header states no preference this
        // rule can read — `Accept: *`, `Accept: not-a-media-range`, or an empty
        // value. Saying the response "does not match" such a header would be a
        // claim about a preference nobody expressed, and it would name the
        // response for a defect that is in the request.
        // `accept_header_media_type_syntax` reports the malformed
        // header; this rule declines.
        if !readable_preference {
            return None;
        }

        if !matched {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Response Content-Type '{}' does not match request Accept header '{}', consider returning 406 Not Acceptable",
                    content_type, accept
                ),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Accept and Content-Type Negotiation")
    }

    fn description(&self) -> &'static str {
        "Report a response whose `Content-Type` is not covered by any `media-range` the request's `Accept` header listed with a non-zero weight — `Accept: application/json` answered with `Content-Type: text/html`. The suggested remedies are the two the specification names: send a representation the client asked for, or say so with `406 (Not Acceptable)`.\n\n**This is advice, not a conformance check, and the specification is explicit about it.** RFC 9110 §12.4.1 gives the origin server the choice in as many words: when no available representation is acceptable it \"can either honor the header field by sending a 406 (Not Acceptable) response or disregard the header field by treating the response as if it is not subject to content negotiation\". §12.1 says the same from the other side — a user agent \"cannot rely on proactive negotiation preferences being consistently honored\". So **a message this rule reports may be perfectly conforming**, and the finding is worded as a suggestion because that is all it can be. It is worth having anyway: a response the client cannot use is usually not what the server meant to send.\n\n**A 406 response is never reported** — that status is the server taking the other branch of the same choice.\n\n**Weights:** a member with `q=0` is a refusal and does not count as accepting anything. `q` is read wherever it appears in the member and its name is matched case-insensitively, which is what §12.5.1 tells recipients to do. A `q` whose value is not a `qvalue` (`q=-1`, `q=0.0001`, `q=1e-9`) is not a weight at all; the member keeps the default weight of 1, and reporting the malformed value is `accept_header_media_type_syntax`'s job.\n\n**Nothing is reported when the question has no answer.** If no member of `Accept` is a `media-range` — `Accept: *`, `Accept: not-a-media-range`, an empty value — then no preference was expressed that this rule can read, and naming the response for a defect in the request would be the wrong finding about the wrong message. Likewise if the response carries more than one `Content-Type` field line: recipients differ over which one they act on, so which media type the client actually got is unknown.\n\n**Quoting that never closes is declined too.** After a stray `\"` no separator can be trusted — the rest of the field collapses into one member — so `Accept: text/html;foo=\"x, application/json` is not reported against an `application/json` response it plainly asks for.\n\n**Known leniency: media-range parameters are ignored.** §12.5.1 lets a range carry media type parameters and makes a more specific range take precedence, so `text/plain;format=flowed` and `text/plain;format=fixed` are different preferences. This rule compares only type and subtype, which can only make it quieter — a response whose *parameters* nobody asked for goes unmentioned."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.1",
                note: "Absence: what a missing negotiation field means, and — the reason this rule is advisory — the origin server's explicit choice between sending 406 and disregarding the header entirely",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1",
                note: "Accept: the `#( media-range [ weight ] )` list, the three shapes a `media-range` takes and what the asterisk ranges over, the instruction to find `q` wherever it sits, and the media-range parameters this rule does not compare",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2",
                note: "Quality Values: `qvalue`, the meaning of a zero weight, and the default weight of 1 that a member with no readable `q` keeps",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.1",
                note: "Proactive negotiation: that a user agent cannot rely on its preferences being honoured, which is the same point as §12.4.1's from the client's side",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.5.7"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.7",
                note: "406 (Not Acceptable): the status this rule suggests, and the one response it never reports",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3",
                note: "Content-Type: that recipients differ over which member of a duplicated field they act on, which is why a response with two Content-Type lines is not judged",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nAccept: application/json\n\nHTTP/1.1 200 OK\nContent-Type: application/json; charset=utf-8",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a range covers every subtype of its type)"),
                snippet: "GET /resource HTTP/1.1\nAccept: text/*\n\nHTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the server honoured the header instead of disregarding it)"),
                snippet: "GET /resource HTTP/1.1\nAccept: application/json\n\nHTTP/1.1 406 Not Acceptable\nContent-Type: text/html; charset=utf-8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nAccept: application/json\n\nHTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a weight of zero is a refusal)"),
                snippet: "GET /resource HTTP/1.1\nAccept: text/html;q=0\n\nHTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AcceptAndContentTypeNegotiation;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("application/json"), Some("application/json"), 200, false)]
    #[case(Some("application/json"), Some("text/html"), 200, true)]
    #[case(Some("text/*"), Some("text/html; charset=utf-8"), 200, false)]
    #[case(Some("*/*"), Some("image/png"), 200, false)]
    #[case(Some("application/json;q=0"), Some("application/json"), 200, true)]
    #[case(Some("application/json;q=0"), Some("application/json"), 406, false)]
    #[case(None, Some("application/json"), 200, false)]
    #[case(Some("application/json, text/html;q=0"), Some("text/html"), 200, true)]
    // A comma inside a quoted parameter value is not a list separator. This
    // header accepts `text/plain` and nothing else; reading the fragments as
    // members made it look like it accepted `image/png`.
    #[case(Some("text/plain;foo=\"a,image/png,b\""), Some("image/png"), 200, true)]
    // The real list is still split on the commas that are separators.
    #[case(
        Some("text/plain;foo=\"a,b\", image/png"),
        Some("image/png"),
        200,
        false
    )]
    // A `;` inside a quoted value does not start a parameter, so the `q=0` in
    // this member's `foo` value is not a weight and the member is acceptable.
    #[case(Some("text/html;foo=\"a;q=0;b=1\""), Some("text/html"), 200, false)]
    // A real weight of zero after a quoted value carrying one is still found.
    #[case(Some("text/html;foo=\"a;q=1\";q=0"), Some("text/html"), 200, true)]
    // The forms `qvalue` admits, at both ends of the range.
    #[case(Some("text/html;q=0"), Some("text/html"), 200, true)]
    #[case(Some("text/html;q=0.000"), Some("text/html"), 200, true)]
    #[case(Some("text/html;q=0.001"), Some("text/html"), 200, false)]
    #[case(Some("text/html;q=1"), Some("text/html"), 200, false)]
    // Not a `qvalue`, so not a weight. Refusing the member on the strength of
    // these would turn a malformed Accept into a finding about the response;
    // the member keeps the default weight of 1 instead.
    #[case(Some("text/html;q=-1"), Some("text/html"), 200, false)]
    #[case(Some("text/html;q=0.0001"), Some("text/html"), 200, false)]
    #[case(Some("text/html;q=1e-9"), Some("text/html"), 200, false)]
    #[case(Some("text/html;q=00"), Some("text/html"), 200, false)]
    fn negotiation_cases(
        #[case] accept: Option<&str>,
        #[case] content_type: Option<&str>,
        #[case] status: u16,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = AcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_and_content_type_negotiation",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        if let Some(a) = accept {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("accept", a)]);
        }
        if let Some(ct) = content_type {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", ct)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for accept={:?} ct={:?}",
                accept,
                content_type
            );
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    /// `Accept` is a list field, so its members may be spread over several
    /// field lines and are recombined into one list. Reading only the first
    /// announced that a response was unacceptable to a client that had asked
    /// for it on the second.
    #[rstest]
    #[case(&["application/json", "text/html"], "text/html", false)]
    #[case(&["application/json", "text/html"], "application/json", false)]
    #[case(&["application/json", "text/html"], "image/png", true)]
    fn every_accept_field_line_is_read(
        #[case] accepts: &[&str],
        #[case] content_type: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = AcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let pairs: Vec<(&str, &str)> = accepts.iter().map(|a| ("accept", *a)).collect();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", content_type)]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(
            v.is_some(),
            expect_violation,
            "{accepts:?} vs {content_type} -> {v:?}"
        );
    }

    /// Every published snippet is run through the rule. These carry a request
    /// and a response, so the parser has to split them — and that split is the
    /// point: an example of a *negotiation* failure is only an example if both
    /// halves reach the rule.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = AcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        for ex in rule.examples() {
            let (req, resp) = ex
                .snippet
                .split_once("\n\n")
                .unwrap_or_else(|| panic!("example has no response half: {:?}", ex.snippet));
            // One predicate for "this is a start-line", so a request-line the
            // skip missed cannot reach the header parser.
            let headers = |block: &str| -> hyper::HeaderMap {
                let pairs: Vec<(&str, &str)> = block
                    .lines()
                    .filter(|l| !l.contains("HTTP/"))
                    .map(|l| {
                        l.split_once(": ")
                            .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                    })
                    .collect();
                crate::test_helpers::make_headers_from_pairs(&pairs)
            };
            let status: u16 = resp
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("no status line: {resp:?}"));

            let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
            tx.request.headers = headers(req);
            tx.response.as_mut().unwrap().headers = headers(resp);

            let v = rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    v.is_none(),
                    "rule rejects its Compliant example {:?}: {v:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    let v = v.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    // Every message this rule emits names the Content-Type, so
                    // asserting that would assert nothing. The suggestion is
                    // what the example is published to illustrate.
                    assert!(
                        v.message.contains("consider returning 406 Not Acceptable"),
                        "NonCompliant example {:?} fails for an unrelated reason: {v:?}",
                        ex.snippet
                    );
                }
            }
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_and_content_type_negotiation",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = AcceptAndContentTypeNegotiation;
        assert_eq!(rule.id(), "accept_and_content_type_negotiation");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn invalid_response_content_type_parsing_is_ignored() {
        // If the response Content-Type cannot be parsed, the rule conservatively does nothing
        let rule = AcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_and_content_type_negotiation",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "text/plain")]);
        // invalid content-type (no slash) -> parse_media_type should fail
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    /// A finding here says the response is not among the media types the client
    /// asked for. When no member of Accept is a `media-range`, nobody asked for
    /// anything this rule can read, and the header — not the response — is the
    /// malformed thing. These used to be reported, under test names recording
    /// it as intended: an unreadable Accept produced a finding against a
    /// response that had done nothing wrong.
    #[rstest]
    #[case("not-a-media-range")]
    // A bare asterisk is not a `media-range`: the asterisk stands for a whole
    // type or a whole subtype, never for the pair.
    #[case("*")]
    // A wildcard type with a concrete subtype is not one either, though it
    // parses as a media-type.
    #[case("*/json")]
    // A zero-element list expresses no preference at all.
    #[case("")]
    #[case(",  ,")]
    fn an_unreadable_accept_is_not_a_finding_about_the_response(#[case] accept: &str) {
        let rule = AcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("accept", accept)]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/plain")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "Accept {accept:?} states no preference: {v:?}");
    }

    /// Quoting that never closes swallows every separator after it, so the
    /// member list past that point is not a member list. Both headers below
    /// plainly name `application/json`, and both were reported for a response
    /// that is exactly what was asked for.
    #[rstest]
    #[case("text/html;foo=\"x, application/json", "application/json", false)]
    #[case("text/html;foo=a\"b, application/json", "application/json", false)]
    // Balanced quoting is judged as before, so the gate narrows nothing it
    // should not.
    #[case("text/html;foo=\"x,y\"", "application/json", true)]
    // A backslash outside a quoted-string escapes nothing, so this list is
    // readable and its second member is found.
    #[case("text/html;foo=a\\, application/json", "application/json", false)]
    fn quoting_that_never_closes_is_not_a_member_list(
        #[case] accept: &str,
        #[case] content_type: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = AcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("accept", accept)]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", content_type)]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{accept:?} -> {v:?}");
    }

    /// One readable member is enough to make the question meaningful, and the
    /// unreadable ones alongside it change nothing.
    #[test]
    fn a_readable_member_beside_an_unreadable_one_is_still_judged() {
        let rule = AcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "accept",
            "not-a-media-range, application/json",
        )]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/plain")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some(), "application/json is a real preference: {v:?}");
    }

    /// With two Content-Type lines there is no single media type the response
    /// sent — recipients differ over which one they act on — so whether the
    /// client got what it asked for depends on which it reads. The rule judged
    /// the first and reported, though the second is one the client accepts.
    #[test]
    fn two_content_type_lines_leave_the_question_unanswerable() {
        let rule = AcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "application/json")]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-type", "text/html"),
            ("content-type", "application/json"),
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "which media type applies is unknown: {v:?}");
    }

    #[test]
    fn invalid_q_value_is_ignored_and_does_not_make_member_unacceptable() {
        // If q value is malformed, we conservatively treat the member as acceptable unless q parses to 0
        let rule = AcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_and_content_type_negotiation",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "text/plain;q=notnum")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/plain")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_q_value_is_ignored_and_member_is_accepted() {
        // q= with empty RHS should not make member unacceptable
        let rule = AcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_and_content_type_negotiation",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept", "application/json;q=")]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "application/json")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn no_response_is_ignored() {
        let rule = AcceptAndContentTypeNegotiation;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_and_content_type_negotiation",
        ]);

        let tx = crate::test_helpers::make_test_transaction();
        // tx.response is None
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }
}
