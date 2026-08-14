// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientAcceptRangesOnPartialContent;

/// The range unit this request asks in, or `None` when the `Range` field is not
/// something a unit may honestly be read out of.
///
/// Every reason to decline here belongs to `client_range_header_syntax_valid`,
/// which reads every field line and reports the value itself. What is wanted is
/// one construct out of a value that can be trusted, so a second, more lenient
/// reading of the production is exactly what this must not become: no trimming
/// around the unit, and no unit taken out of a value that has no `=` in it.
fn requested_unit(headers: &hyper::HeaderMap) -> Option<String> {
    let mut lines = headers.get_all("range").iter();
    let value = lines.next()?;
    // `Range` is not a list -- its entire value is one ranges-specifier -- so a
    // second field line is not a continuation of the first, and there is no
    // combined value here to read a unit out of. That the second line was sent
    // at all is a violation of the sentence below, reported by whichever rule
    // owns it and not by this one.
    //
    // cite(RFC 9110 § A): "Range = ranges-specifier"
    // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
    if lines.next().is_some() {
        return None;
    }

    // The delimiter is not optional: a `Range` value is a range unit, an "=",
    // and a range set. A value without one is not a ranges-specifier, and the
    // text before the first "=" of a value that has none is not a unit.
    //
    // cite(RFC 9110 § A): "range-unit = token ranges-specifier = range-unit "=" range-set"
    let (unit, _range_set) = value.to_str().ok()?.split_once('=')?;

    // A range unit is a `token`, so there is nothing to trim off one: the space
    // in `bytes =0-499` is part of what the client sent, and what to say about
    // it belongs to the rule that reads the whole value.
    if crate::helpers::token::find_invalid_token_char(unit).is_some() {
        return None;
    }

    // cite(RFC 9110 § 14.1): "All range unit names are case-insensitive and ought to be registered within the "HTTP Range Unit Registry", as defined in Section 16.5.1."
    Some(unit.to_ascii_lowercase())
}

impl Rule for ClientAcceptRangesOnPartialContent {
    fn id(&self) -> &'static str {
        "client_accept_ranges_on_partial_content"
    }

    /// Documentation, not a filter: in this engine only `Server` decides
    /// anything, and `Client` and `Both` dispatch identically. What keeps this
    /// rule off a message it has nothing to say about is the `Range` field it
    /// requires and the previous response it reads, both below.
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // The subject is a request that asks for a range, and presence is the
        // whole of it: the advice below is against attempting a range request at
        // all, so a value this rule cannot read is still a range request.
        //
        // The method is not filtered on, and the second sentence is why. A
        // server must ignore `Range` on a method for which range handling is not
        // defined, so such a request is answered with the whole representation
        // -- more of the wasted transfer this field exists to prevent than a GET
        // would be, not less.
        //
        // cite(RFC 9110 § 14.2): "The "Range" header field on a GET request modifies the method semantics to request transfer of only one or more subranges of the selected representation data (Section 8.1), rather than the entire selected representation."
        // cite(RFC 9110 § 14.2): "A server MUST ignore a Range header field received with a request method that is unrecognized or for which range handling is not defined."
        tx.request.headers.get_all("range").iter().next()?;

        // The engine hands this rule a history scoped to this client and this
        // request URI, which is the whole reason the advice below applies at
        // all: it is advice about the same request path. Only the most recent
        // response is read -- a later response supersedes what an earlier one
        // advised about the resource as it is now.
        //
        // cite(RFC 9110 § 14.3): "to advise the client not to attempt a range request on the same request path.  The range unit "none" is reserved for this purpose."
        let prev = history.previous()?;

        // cite(RFC 9110 § 14.3): "The "Accept-Ranges" field in a response indicates whether an upstream server supports range requests for the target resource."
        let resp = prev.response.as_ref()?;

        // What the response advertised, read by the code both readers of this
        // field share -- including its trailer section, which is part of the
        // field's definition.
        let advertised = crate::helpers::accept_ranges::read_advertisement(resp);

        // No advertisement is not a reason to say anything, and the sentences
        // below are as explicit as this specification gets. This rule used to
        // report exactly this when the previous response was a 206 -- a client
        // that had just been served a partial response, reported for asking for
        // the next part of it.
        //
        // cite(RFC 9110 § 14): "Range requests are an OPTIONAL feature of HTTP, designed so that recipients not implementing this feature (or not supporting it for the target resource) can respond as if it is a normal GET request without impacting interoperability."
        // cite(RFC 9110 § 14.3): "A client MAY generate range requests regardless of having received an Accept-Ranges field.  The information only provides advice for the sake of improving performance and reducing unnecessary network transfers."
        if !advertised.present {
            return None;
        }

        // `none` is the one thing this field says that is addressed to the
        // client's next request, and it says not to make this one.
        //
        // cite(RFC 9110 § 14.3): "A server that does not support any kind of range request for the target resource MAY send"
        if advertised.advertises("none") {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Previous response for this resource sent Accept-Ranges: none, advising against a range request on the same request path, and this request sends Range anyway (advice: nothing forbids it)".into(),
            });
        }

        // A field line that could not be read may have been the one naming this
        // request's unit, so a mismatch below would rest on nothing.
        if !advertised.complete {
            return None;
        }

        let unit = requested_unit(&tx.request.headers)?;

        // What the mismatch costs, and all it costs: an origin server must
        // ignore a `Range` field in a unit it does not understand, so the
        // request is answered with the whole representation. That is the
        // unnecessary transfer this field exists to prevent, and it is still
        // advice -- nothing makes the advertised list exhaustive, and the
        // sentence at the top of this function permits the request outright.
        //
        // cite(RFC 9110 § 14.2): "An origin server MUST ignore a Range header field that contains a range unit it does not understand."
        if !advertised.advertises(&unit) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Range asks in '{}', a unit the previous response for this resource did not advertise, so a server that does not understand it will ignore the field and send the whole representation (advice: nothing forbids it)",
                    unit
                ),
            });
        }

        // Where the rule stops, and no parser gets past it. Both sentences below
        // are requirements on a conclusion the client drew -- what it assumed,
        // what it inspected -- and nothing on the wire records a conclusion: a
        // client that assumed and a client that did not send the same bytes.
        // Their strength is not the obstacle. The first is a MUST NOT and is as
        // undecidable as the weakest advice in this file, which is why it is
        // said out loud here and in the description rather than approximated by
        // a check on something else.
        //
        // cite(RFC 9110 § 14.3): "Conversely, a client MUST NOT assume that receiving an Accept-Ranges field means that future range requests will return partial responses."
        // cite(RFC 9110 § 15.3.7): "A client MUST inspect a 206 response's Content-Type and Content-Range field(s) to determine what parts are enclosed and whether additional requests are needed."
        None
    }

    fn description(&self) -> &'static str {
        "Advice a client was given, and whether the next request took it. `Accept-Ranges` tells a client which range units a resource supports, or that it supports none — and almost everything this rule has to say about the request that follows is advice, because RFC 9110 §14.3 says the field \"only provides advice for the sake of improving performance and reducing unnecessary network transfers\".\n\n**`Accept-Ranges: none` followed by a `Range` request** is the one finding addressed to the client. The permission to send `none` is granted to a server that supports no kind of range request \"to advise the client not to attempt a range request on the same request path\", and this request attempts one. It is still advice: the same section says a client \"MAY generate range requests regardless of having received an Accept-Ranges field\".\n\n**A `Range` in a unit the previous response did not advertise** is advice about a wasted transfer. §14.2 says an origin server \"MUST ignore a Range header field that contains a range unit it does not understand\", so such a request is answered with the whole representation — which is what the advertisement exists to prevent. Nothing makes the advertised list exhaustive, so this is not a violation either.\n\n**What this rule no longer reports.** A `Range` request following a 206 that carried no `Accept-Ranges` field: §14.3's \"regardless of having received an Accept-Ranges field\" permits it in as many words, and §14 makes range requests an OPTIONAL feature of HTTP altogether. Whether the advertised value is a well-formed list of range units belongs to `server_accept_ranges_values_valid`; whether the `Range` value is a well-formed ranges-specifier belongs to `client_range_header_syntax_valid`. Where either value cannot be read as this rule needs it, it declines rather than reporting the field a second time — but a `Range` field that cannot be read is still a range request, and still takes the `none` advice.\n\n**What no rule can check.** §14.3 also says a client \"MUST NOT assume that receiving an Accept-Ranges field means that future range requests will return partial responses\", and §15.3.7 that a client \"MUST inspect a 206 response's Content-Type and Content-Range field(s)\". Both are requirements on a conclusion the client drew; nothing on the wire distinguishes a client that assumed from one that did not, so this rule stops there rather than approximating them.\n\n**What it reads, and what that assumes.** The transaction immediately preceding this one from the same client for the same request URI, which is what \"the same request path\" is measured against; a later response supersedes what an earlier one advised, so only the most recent is read. `Accept-Ranges` is read from the trailer section as well as the header section, which §14.3 permits. Two assumptions come with that and are worth knowing before enabling this rule. *The same client* is an address and a `User-Agent` string, so several user agents behind one address that send the same `User-Agent` are one client here, and advice given to one of them is measured against another's request. And the rule's name is historical: nothing it checks depends on the previous response being a `206 Partial Content`, and after the corrections above it does not read the status code at all."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3",
                note: "`Accept-Ranges`: advice, in the section's own words, about which range units a resource supports — or `none`, which advises against attempting a range request on the same request path. A client MAY send range requests regardless, and MUST NOT assume the field means future range requests will be answered with partial responses, which no parser can check",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2",
                note: "`Range`: `ranges-specifier`, and an origin server MUST ignore one whose range unit it does not understand — which is what a request in an unadvertised unit costs",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1",
                note: "Range units: `range-unit = token`, shared by `Accept-Ranges` and `Range`, and case-insensitive — which is why both sides of the comparison are folded",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.3.7"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7",
                note: "`206 Partial Content`: a client MUST inspect its `Content-Type` and `Content-Range`, which is not observable either. A 206 that advertised nothing is no longer reported here. RFC 7233 §4.1 defined the status code; RFC 9110 obsoleted RFC 7233",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— the server advertised bytes and the client asks in bytes"),
                snippet: "HTTP/1.1 200 OK\nAccept-Ranges: bytes\n\nGET /resource HTTP/1.1\nRange: bytes=0-499",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "— a client MAY generate range requests regardless of having received the field",
                ),
                snippet: "HTTP/1.1 206 Partial Content\nContent-Range: bytes 0-499/1234\n\nGET /resource HTTP/1.1\nRange: bytes=500-999",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— advice: the server advised against range requests on this path"),
                snippet: "HTTP/1.1 200 OK\nAccept-Ranges: none\n\nGET /resource HTTP/1.1\nRange: bytes=0-499",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— advice: a unit the previous response did not advertise"),
                snippet: "HTTP/1.1 200 OK\nAccept-Ranges: bytes\n\nGET /resource HTTP/1.1\nRange: pages=1-2",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientAcceptRangesOnPartialContent;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    fn config() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&[
            "client_accept_ranges_on_partial_content",
        ])
    }

    /// A field section as name/value pairs. The value is bytes rather than a
    /// `&str` because half of these tests are about a value that is not one.
    type Fields<'a> = &'a [(&'a str, &'a [u8])];

    /// What this client was told last time it asked for this resource. The
    /// two cases that are not a response are here rather than in a test of
    /// their own: they are the same fixture with less in it, and a test that
    /// builds its own history is a test that can stop agreeing with the others.
    enum Previously<'a> {
        /// No transaction for this resource at all.
        Nothing,
        /// A transaction whose response was never observed.
        ATransactionWithNoResponse,
        /// A response, as a status, a header section and a trailer section.
        AResponse(u16, Fields<'a>, Fields<'a>),
    }

    use crate::test_helpers::make_headers_from_octet_pairs as section;

    /// Every fixture is built here. The rule reads two field sections of the
    /// previous response and treats a field line it cannot decode differently
    /// from one that is absent, so a constructor that can only express a header
    /// section of valid US-ASCII cannot state what half of these tests are about.
    ///
    /// The two request URIs are equal because that is what the engine's
    /// `ByResource` query guarantees, not because the rule compares them.
    fn judge(previously: Previously<'_>, request: Fields<'_>) -> Option<Violation> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = section(request);

        let mut prev = crate::test_helpers::make_test_transaction();
        prev.request.uri = tx.request.uri.clone();

        let history = match previously {
            Previously::Nothing => crate::transaction_history::TransactionHistory::empty(),
            Previously::ATransactionWithNoResponse => {
                crate::transaction_history::TransactionHistory::from_transactions(vec![prev])
            }
            Previously::AResponse(status, headers, trailers) => {
                prev.response = Some(crate::http_transaction::ResponseInfo {
                    status,
                    version: "HTTP/1.1".into(),
                    headers: section(headers),
                    body_length: None,
                    trailers: (!trailers.is_empty()).then(|| section(trailers)),
                });
                crate::transaction_history::TransactionHistory::from_transactions(vec![prev])
            }
        };

        ClientAcceptRangesOnPartialContent.check_transaction(&tx, &history, &config())
    }

    const RANGE: &[(&str, &[u8])] = &[("range", b"bytes=0-1".as_slice())];

    #[rstest]
    #[case::advertised(200, &[("accept-ranges", b"bytes".as_slice())][..], false)]
    #[case::none(200, &[("accept-ranges", b"none".as_slice())][..], true)]
    #[case::another_unit(200, &[("accept-ranges", b"pages".as_slice())][..], true)]
    #[case::nothing_advertised(200, &[][..], false)]
    fn check_advertisement_cases(
        #[case] status: u16,
        #[case] headers: &[(&str, &[u8])],
        #[case] expect_violation: bool,
    ) {
        let found = judge(Previously::AResponse(status, headers, &[]), RANGE);
        assert_eq!(
            found.is_some(),
            expect_violation,
            "headers={headers:?} gave {found:?}"
        );
    }

    /// § 14.3 permits a client to send range requests having received no
    /// `Accept-Ranges` field, in as many words. A 206 is the case this rule used
    /// to report: a client served a partial response, reported for asking for
    /// the rest of it.
    #[rstest]
    #[case::after_a_206(206)]
    #[case::after_a_200(200)]
    #[case::after_a_416(416)]
    fn a_response_that_advertised_nothing_is_not_advice(#[case] status: u16) {
        assert!(judge(Previously::AResponse(status, &[], &[]), RANGE).is_none());
    }

    /// § 14.3 permits the field in a trailer section, so advice given there is
    /// advice.
    #[test]
    fn a_trailer_section_advises_too() {
        let found = judge(
            Previously::AResponse(200, &[], &[("accept-ranges", b"none".as_slice())]),
            RANGE,
        );
        assert!(found.is_some());
    }

    /// A `Range` field this rule cannot read is still a range request, and the
    /// `none` advice was against making one. The unit comparison is what needs a
    /// readable value.
    #[rstest]
    #[case::not_ascii(&[("range", &[0xff][..])][..])]
    #[case::not_a_ranges_specifier(&[("range", b"bytes 0-1".as_slice())][..])]
    #[case::two_field_lines(&[("range", b"bytes=0-1".as_slice()), ("range", b"bytes=2-3".as_slice())][..])]
    #[case::space_before_the_delimiter(&[("range", b"bytes =0-1".as_slice())][..])]
    fn a_range_this_rule_cannot_read_is_still_a_range_request(#[case] request: &[(&str, &[u8])]) {
        assert!(
            judge(
                Previously::AResponse(200, &[("accept-ranges", b"none".as_slice())], &[]),
                request
            )
            .is_some(),
            "the none advice does not depend on the value"
        );
        assert!(
            judge(
                Previously::AResponse(200, &[("accept-ranges", b"bytes".as_slice())], &[]),
                request
            )
            .is_none(),
            "the unit comparison has no unit to compare"
        );
    }

    /// § 14.1 says range unit names are case-insensitive, so the fold is the
    /// spec's and not a tolerance this rule chose.
    #[test]
    fn unit_names_are_compared_case_insensitively() {
        let found = judge(
            Previously::AResponse(200, &[("accept-ranges", b"BYTES".as_slice())], &[]),
            &[("range", b"Bytes=0-1".as_slice())],
        );
        assert!(found.is_none());
    }

    /// The unreadable line may have been the one naming this request's unit, so
    /// the mismatch finding has nothing to rest on...
    #[test]
    fn an_unreadable_advertisement_silences_the_unit_comparison() {
        let found = judge(
            Previously::AResponse(
                200,
                &[
                    ("accept-ranges", b"pages".as_slice()),
                    ("accept-ranges", &[0xff][..]),
                ],
                &[],
            ),
            RANGE,
        );
        assert!(found.is_none());
    }

    /// ... but a `none` that *was* read still says what it says.
    #[test]
    fn an_unreadable_advertisement_does_not_silence_none() {
        let found = judge(
            Previously::AResponse(
                200,
                &[
                    ("accept-ranges", b"none".as_slice()),
                    ("accept-ranges", &[0xff][..]),
                ],
                &[],
            ),
            RANGE,
        );
        assert!(found.is_some());
    }

    /// Whether the advertised value is a well-formed list of range units belongs
    /// to `server_accept_ranges_values_valid`, and this rule used to emit that
    /// finding itself, with a message of its own.
    #[test]
    fn an_advertisement_its_owner_reports_is_not_reported_here() {
        let found = judge(
            Previously::AResponse(200, &[("accept-ranges", b"x@bad".as_slice())], &[]),
            RANGE,
        );
        assert!(found.is_none());
    }

    /// Nothing to compare a request against. The advice this rule reports is a
    /// response's, so a resource nobody has asked for yet, and a request whose
    /// response was never observed, both leave it with nothing to say.
    #[rstest]
    #[case::no_history(Previously::Nothing)]
    #[case::no_response(Previously::ATransactionWithNoResponse)]
    fn a_previous_transaction_with_nothing_to_read_is_not_read(#[case] previously: Previously<'_>) {
        assert!(judge(previously, RANGE).is_none());
    }

    #[test]
    fn a_request_with_no_range_is_not_this_rules_subject() {
        assert!(judge(
            Previously::AResponse(200, &[("accept-ranges", b"none".as_slice())], &[]),
            &[]
        )
        .is_none());
    }

    /// Nothing else runs a rule's published examples through it, and every
    /// example here is a previous response followed by the request it advises.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};

        let mut saw_a_finding = false;
        for ex in ClientAcceptRangesOnPartialContent.examples() {
            let (response, request) = ex
                .snippet
                .split_once("\n\n")
                .unwrap_or_else(|| panic!("not a response and a request: {:?}", ex.snippet));

            let mut response = response.lines();
            let status_line = response.next().expect("a response has a status line");
            let status: u16 = status_line
                .strip_prefix("HTTP/1.1 ")
                .and_then(|rest| rest.split(' ').next())
                .and_then(|code| code.parse().ok())
                .unwrap_or_else(|| panic!("not a status line: {status_line:?}"));

            let mut request = request.lines();
            let request_line = request.next().expect("a request has a request line");
            assert!(
                request_line.ends_with(" HTTP/1.1"),
                "not a request line: {request_line:?}"
            );

            fn fields<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<(&'a str, &'a [u8])> {
                lines
                    .map(|line| {
                        let (name, value) = line
                            .split_once(": ")
                            .unwrap_or_else(|| panic!("not a field line: {line:?}"));
                        (name, value.as_bytes())
                    })
                    .collect()
            }

            let found = judge(
                Previously::AResponse(status, &fields(response), &[]),
                &fields(request),
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    assert!(
                        found.is_some(),
                        "rule accepts its NonCompliant example {:?}",
                        ex.snippet
                    );
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "the guard ran without exercising a finding");
    }

    /// This rule reads a range unit out of each field and nothing else, so every
    /// published value goes past the code that owns its syntax.
    #[test]
    fn published_examples_hold_values_their_owners_accept() {
        use crate::rules::Rule as _;

        for ex in ClientAcceptRangesOnPartialContent.examples() {
            for line in ex.snippet.lines() {
                let Some((name, value)) = line.split_once(": ") else {
                    continue;
                };
                match name.to_ascii_lowercase().as_str() {
                    "content-range" => assert!(
                        crate::helpers::content_range::parse_content_range(value).is_ok(),
                        "Content-Range {value:?} does not parse"
                    ),
                    "accept-ranges" => {
                        for token in crate::helpers::headers::list_members(value) {
                            assert!(
                                crate::helpers::token::find_invalid_token_char(token).is_none(),
                                "Accept-Ranges holds {token:?}, which is not a token"
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn scope_is_client() {
        assert_eq!(
            ClientAcceptRangesOnPartialContent.scope(),
            crate::rules::RuleScope::Client
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "client_accept_ranges_on_partial_content");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_missing_severity_errors() {
        let mut cfg = config();
        if let Some(toml::Value::Table(table)) =
            cfg.rules.get_mut("client_accept_ranges_on_partial_content")
        {
            table.remove("severity");
        }
        assert!(crate::rules::validate_rules(&cfg).is_err());
    }
}
