// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAcceptRangesAnd206Consistency;

impl Rule for MessageAcceptRangesAnd206Consistency {
    fn id(&self) -> &'static str {
        "message_accept_ranges_and_206_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // `Accept-Ranges` is a response field, which is the sentence behind
        // reading one side only -- not the scope enum, which in this engine only
        // decides when the rule is dispatched.
        //
        // cite(RFC 9110 § 14.3): "The "Accept-Ranges" field in a response indicates whether an upstream server supports range requests for the target resource."
        let resp = tx.response.as_ref()?;

        // Everything below reads the 206 as evidence about the resource, so no
        // other status has anything to contradict.
        //
        // cite(RFC 9110 § 15.3.7): "The 206 (Partial Content) status code indicates that the server is successfully fulfilling a range request for the target resource by transferring one or more parts of the selected representation."
        if resp.status != 206 {
            return None;
        }

        // What the response advertises, read by the code that both readers of
        // this field share -- including the trailer section, which is part of
        // the field's definition.
        let advertised = crate::helpers::accept_ranges::read_advertisement(resp);

        // Advice, and the sentences that keep it advice. The field is worth
        // sending -- it is what a client restarting this transfer would read --
        // and no sentence asks for it, which is what the finding says. The
        // quotation that settles it is the last one: §15.3.7 does say which
        // fields a 206 MUST carry, names six of them, and `Accept-Ranges` is
        // not among them.
        //
        // cite(RFC 9110 § 14): "Range requests are an OPTIONAL feature of HTTP, designed so that recipients not implementing this feature (or not supporting it for the target resource) can respond as if it is a normal GET request without impacting interoperability."
        // cite(RFC 9110 § 14.3): "A client MAY generate range requests regardless of having received an Accept-Ranges field.  The information only provides advice for the sake of improving performance and reducing unnecessary network transfers."
        // cite(RFC 9110 § 14.3): "to indicate that it supports byte range requests for that target resource, thereby encouraging its use by the client for future partial requests on the same request path."
        // cite(RFC 9110 § 15.3.7): "A server that generates a 206 response MUST generate the following header fields, in addition to those required in the subsections below, if the field would have been sent in a 200 (OK) response to the same request: Date, Cache-Control, ETag, Expires, Content-Location, and Vary."
        if !advertised.present {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "206 Partial Content response carries no Accept-Ranges field, so a client resuming this transfer has nothing telling it which range units the resource supports (advice: nothing requires the field)".into(),
            });
        }

        // The permission to send `none` belongs to a server that supports no kind
        // of range request for the target resource; a 206 is that same server
        // fulfilling one. `none` is reserved for saying that and nothing else, so
        // it is reported beside a real unit too.
        //
        // cite(RFC 9110 § 14.3): "A server that does not support any kind of range request for the target resource MAY send"
        // cite(RFC 9110 § 14.3): "to advise the client not to attempt a range request on the same request path.  The range unit "none" is reserved for this purpose."
        if advertised.advertises("none") {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Accept-Ranges: none says this resource supports no kind of range request, in the very response that fulfilled one (206 Partial Content)".into(),
            });
        }

        // A unit that could not be read may be the one the Content-Range names,
        // so there is nothing to conclude from a mismatch below.
        if !advertised.complete {
            return None;
        }

        // The field's syntax, and whether a 206 carries it at all, belong to
        // `message_range_and_content_range_consistency`; what is wanted here is
        // one construct out of it, the range unit, parsed by the code that owns
        // the production rather than by a second reading of it. A value this
        // rule cannot parse is that rule's finding, reported there.
        //
        // cite(RFC 9110 § 14.1): "This general notion of a "range unit" is used in the Accept-Ranges (Section 14.3) response header field to advertise support for range requests, the Range (Section 14.2) request header field to delineate the parts of a representation that are requested, and the Content-Range (Section 14.4) header field to describe which part of a representation is being transferred."
        let content_range =
            crate::helpers::headers::get_header_str(&resp.headers, "content-range")?;
        let content_range =
            crate::helpers::content_range::parse_content_range(content_range).ok()?;
        let unit = content_range.unit();

        // What makes the omission worth reporting: the 206 is the answer a server
        // sends when the request's unit is one it supports for this resource, so
        // the response is evidence about a unit its own advice leaves out. Also
        // advice -- the sentence below is about which status to send, and says
        // nothing about which units the field lists.
        //
        // cite(RFC 9110 § 14.2): "If all of the preconditions are true, the server supports the Range header field for the target resource, the received Range field-value contains a valid ranges-specifier with a range-unit supported for that target resource, and that ranges-specifier is satisfiable with respect to the selected representation, the server SHOULD send a 206 (Partial Content) response with content containing one or more partial representations that correspond to the satisfiable range-spec(s) requested."
        if !advertised.advertises(unit) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Content-Range describes a range in '{}', a unit this response's Accept-Ranges does not advertise (advice: nothing requires the two to agree)",
                    unit
                ),
            });
        }

        None
    }

    fn description(&self) -> &'static str {
        "Advice about one field, and one contradiction. `Accept-Ranges` tells a client which range units a resource supports, and a 206 (Partial Content) response is proof that it supports at least one — so what the two say together is worth reading, even though almost none of it is required.\n\n**No `Accept-Ranges` on a 206** is reported as advice rather than as a violation. RFC 9110 §14.3 says a client \"MAY generate range requests regardless of having received an Accept-Ranges field\" and that the field \"only provides advice for the sake of improving performance and reducing unnecessary network transfers\"; §14 makes range requests an OPTIONAL feature of HTTP altogether. A server that omits the field is conforming, and this rule used to describe it as a SHOULD that no sentence supports. §15.3.7 does list the header fields a 206 MUST carry — Date, Cache-Control, ETag, Expires, Content-Location and Vary — and `Accept-Ranges` is not one of them.\n\n**`Accept-Ranges: none` on a 206** is the contradiction. The permission to send `none` is granted to \"a server that does not support any kind of range request for the target resource\", and a 206 is that server successfully fulfilling one. The range unit `none` is reserved for saying that, so it is reported when it travels beside a real unit as well as when it stands alone.\n\n**A `Content-Range` unit the field does not advertise** sits on the same advisory footing as the first finding: a 206 is sent when the request's range unit is supported for the target resource (§14.2), so an advertisement that leaves that unit out is incomplete advice, not a violation.\n\n**The trailer section counts.** §14.3 permits `Accept-Ranges` in a trailer section — the rule reads both sections, so a response that advertises after its content is not reported for advertising nothing.\n\n**Not this rule's findings.** Whether the value is a well-formed list of range units belongs to `accept_ranges_values_valid`; whether a 206 carries a `Content-Range` at all, and whether that value parses, belong to `message_range_and_content_range_consistency`. Where a field line cannot be read as range units — an octet outside US-ASCII, a character `token` excludes, a list with no elements — this rule declines rather than reporting the field a second time, and stays quiet about a unit it may not have seen. A value it cannot read is still counted as present: the message on the wire carries the field."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3",
                note: "`Accept-Ranges`: `1#range-unit`, advertising which units a resource supports, or `none`. Sending it is not required — the section says so twice — and it MAY be sent in a trailer section",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.3.7"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7",
                note: "`206 Partial Content`: the server successfully fulfilling a range request, which is what makes `Accept-Ranges: none` in the same response a contradiction. The section also lists the header fields a 206 MUST carry, and `Accept-Ranges` is not among them. RFC 7233 §4.1 defined the status code; RFC 9110 obsoleted RFC 7233",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2",
                note: "`Range`: a 206 is the answer when the request's range unit is supported for the target resource, so the `Content-Range` unit is a unit the server supports",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1",
                note: "Range units: `range-unit = token`, one construct shared by `Accept-Ranges`, `Range` and `Content-Range`, and case-insensitive — which is why both sides of the comparison are folded",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 206 Partial Content\nContent-Range: bytes 0-499/1234\nAccept-Ranges: bytes",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— unit names are case-insensitive"),
                snippet: "HTTP/1.1 206 Partial Content\nContent-Range: bytes 0-499/1234\nAccept-Ranges: BYTES",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— one list split across two field lines"),
                snippet: "HTTP/1.1 206 Partial Content\nContent-Range: bytes 0-499/1234\nAccept-Ranges: pages\nAccept-Ranges: bytes",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— `none` contradicts the 206 that fulfilled a range request"),
                snippet: "HTTP/1.1 206 Partial Content\nContent-Range: bytes 0-499/1234\nAccept-Ranges: none",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— advice: no field to resume from"),
                snippet: "HTTP/1.1 206 Partial Content\nContent-Range: bytes 0-499/1234",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— advice: the unit served is not among those advertised"),
                snippet: "HTTP/1.1 206 Partial Content\nContent-Range: bytes 0-499/1234\nAccept-Ranges: pages",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageAcceptRangesAnd206Consistency;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    fn config() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_ranges_and_206_consistency",
        ])
    }

    /// Every fixture is built here. The rule reads two field sections and treats
    /// a field line it cannot decode differently from one that is absent, so a
    /// constructor that can only express a header section of valid US-ASCII
    /// cannot state what half of these tests are about.
    fn response(
        status: u16,
        headers: &[(&str, &[u8])],
        trailers: &[(&str, &[u8])],
    ) -> crate::http_transaction::HttpTransaction {
        use crate::test_helpers::make_headers_from_octet_pairs as section;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: section(headers),
            body_length: None,
            trailers: (!trailers.is_empty()).then(|| section(trailers)),
        });
        tx
    }

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        MessageAcceptRangesAnd206Consistency.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config(),
        )
    }

    #[rstest]
    #[case::not_a_206(200, &[][..], false)]
    #[case::advertised(206, &[("content-range", b"bytes 0-0/1".as_slice()), ("accept-ranges", b"bytes".as_slice())][..], false)]
    #[case::none(206, &[("content-range", b"bytes 0-0/1".as_slice()), ("accept-ranges", b"none".as_slice())][..], true)]
    #[case::nothing_advertised(206, &[][..], true)]
    #[case::unit_not_advertised(206, &[("content-range", b"bytes 0-0/1".as_slice()), ("accept-ranges", b"pages".as_slice())][..], true)]
    fn check_accept_ranges_and_206_cases(
        #[case] status: u16,
        #[case] headers: &[(&str, &[u8])],
        #[case] expect_violation: bool,
    ) {
        let found = judge(&response(status, headers, &[]));
        assert_eq!(
            found.is_some(),
            expect_violation,
            "status={status} headers={headers:?} gave {found:?}"
        );
    }

    /// § 14.1 says range unit names are case-insensitive, so the fold is the
    /// spec's and not a tolerance this rule chose.
    #[test]
    fn unit_names_are_compared_case_insensitively() {
        let tx = response(
            206,
            &[
                ("content-range", b"bytes 0-0/1".as_slice()),
                ("accept-ranges", b"BYTES".as_slice()),
            ],
            &[],
        );
        assert!(judge(&tx).is_none());
    }

    #[test]
    fn one_list_may_be_split_across_field_lines() {
        let tx = response(
            206,
            &[
                ("content-range", b"bytes 0-0/1".as_slice()),
                ("accept-ranges", b"pages".as_slice()),
                ("accept-ranges", b"bytes".as_slice()),
            ],
            &[],
        );
        assert!(judge(&tx).is_none());
    }

    #[test]
    fn none_is_reported_wherever_in_the_list_it_sits() {
        let tx = response(
            206,
            &[
                ("content-range", b"bytes 0-0/1".as_slice()),
                ("accept-ranges", b"bytes".as_slice()),
                ("accept-ranges", b"none".as_slice()),
            ],
            &[],
        );
        assert!(judge(&tx).is_some());
    }

    /// § 14.3 permits the field in a trailer section. A response that advertises
    /// there is advertising, and used to be reported for carrying no field at all.
    #[test]
    fn a_trailer_section_advertises() {
        let tx = response(
            206,
            &[("content-range", b"bytes 0-0/1".as_slice())],
            &[("accept-ranges", b"bytes".as_slice())],
        );
        assert!(judge(&tx).is_none());
    }

    #[test]
    fn none_in_a_trailer_section_contradicts_the_206_too() {
        let tx = response(
            206,
            &[("content-range", b"bytes 0-0/1".as_slice())],
            &[("accept-ranges", b"none".as_slice())],
        );
        assert!(judge(&tx).is_some());
    }

    /// A field line the rule cannot decode is still a field line. The finding it
    /// used to produce -- "carries no Accept-Ranges field" -- was false about the
    /// message on the wire, and two tests asserted it.
    #[rstest]
    #[case::not_ascii(&[("accept-ranges", &[0xff][..])][..])]
    #[case::every_line_unreadable(&[("accept-ranges", &[0xff][..]), ("accept-ranges", &[0xfe][..])][..])]
    #[case::not_a_token(&[("accept-ranges", b"x@bad".as_slice())][..])]
    #[case::no_elements(&[("accept-ranges", b",".as_slice())][..])]
    #[case::empty_value(&[("accept-ranges", b"".as_slice())][..])]
    fn a_value_this_rule_cannot_read_is_left_to_the_rule_that_owns_it(
        #[case] fields: &[(&str, &[u8])],
    ) {
        let mut headers = vec![("content-range", b"bytes 0-0/1".as_slice())];
        headers.extend_from_slice(fields);
        assert!(judge(&response(206, &headers, &[])).is_none());
    }

    /// The unreadable line may have been the one naming the unit, so the
    /// mismatch finding has nothing to rest on.
    #[test]
    fn an_unreadable_line_silences_the_unit_comparison() {
        let tx = response(
            206,
            &[
                ("content-range", b"bytes 0-0/1".as_slice()),
                ("accept-ranges", b"pages".as_slice()),
                ("accept-ranges", &[0xff][..]),
            ],
            &[],
        );
        assert!(judge(&tx).is_none());
    }

    /// ... but a `none` that *was* read still says what it says.
    #[test]
    fn an_unreadable_line_does_not_silence_none() {
        let tx = response(
            206,
            &[
                ("content-range", b"bytes 0-0/1".as_slice()),
                ("accept-ranges", b"none".as_slice()),
                ("accept-ranges", &[0xff][..]),
            ],
            &[],
        );
        assert!(judge(&tx).is_some());
    }

    /// Whether a 206 carries a `Content-Range`, and whether it parses, belongs to
    /// `message_range_and_content_range_consistency`. This rule wants one
    /// construct out of a value it can trust.
    #[rstest]
    #[case::absent(None)]
    #[case::malformed(Some(b"bytes 5-3/10".as_slice()))]
    #[case::two_spaces(Some(b"bytes  0-499/1234".as_slice()))]
    #[case::not_ascii(Some(&[0xff][..]))]
    fn a_content_range_its_owner_reports_is_not_read_here(#[case] value: Option<&[u8]>) {
        let mut headers = vec![("accept-ranges", b"pages".as_slice())];
        if let Some(value) = value {
            headers.push(("content-range", value));
        }
        assert!(judge(&response(206, &headers, &[])).is_none());
    }

    /// The multipart form of a 206 carries no `Content-Range` in its header
    /// section at all, so there is no unit here to compare.
    #[test]
    fn a_multipart_206_advertising_something_else_is_not_reported() {
        let tx = response(
            206,
            &[
                (
                    "content-type",
                    b"multipart/byteranges; boundary=THIS_STRING_SEPARATES".as_slice(),
                ),
                ("accept-ranges", b"pages".as_slice()),
            ],
            &[],
        );
        assert!(judge(&tx).is_none());
    }

    /// Nothing else runs a rule's published examples through it, and every
    /// example here is a response whose two fields are read together.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};

        let mut saw_a_finding = false;
        for ex in MessageAcceptRangesAnd206Consistency.examples() {
            let mut lines = ex.snippet.lines();
            let status_line = lines.next().expect("a response has a status line");
            let status: u16 = status_line
                .strip_prefix("HTTP/1.1 ")
                .and_then(|rest| rest.split(' ').next())
                .and_then(|code| code.parse().ok())
                .unwrap_or_else(|| panic!("not a status line: {status_line:?}"));
            let fields: Vec<(&str, &[u8])> = lines
                .map(|line| {
                    let (name, value) = line
                        .split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {line:?}"));
                    (name, value.as_bytes())
                })
                .collect();

            let found = judge(&response(status, &fields, &[]));
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

    /// This rule reads a range unit and nothing else, so every published value
    /// goes past the code that owns its syntax.
    #[test]
    fn published_examples_hold_values_their_owners_accept() {
        use crate::rules::Rule as _;

        for ex in MessageAcceptRangesAnd206Consistency.examples() {
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
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_accept_ranges_and_206_consistency");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_missing_severity_errors() {
        let mut cfg = config();
        if let Some(toml::Value::Table(table)) = cfg
            .rules
            .get_mut("message_accept_ranges_and_206_consistency")
        {
            table.remove("severity");
        }
        assert!(crate::rules::validate_rules(&cfg).is_err());
    }

    /// Two mechanisms keep this rule off a request — the scope enum, which is
    /// what the engine dispatches on, and the `?` on the response — and the enum
    /// alone has never meant anything to a rule that is handed a transaction.
    #[test]
    fn a_transaction_with_no_response_is_not_read() {
        assert!(judge(&crate::test_helpers::make_test_transaction()).is_none());
    }

    #[test]
    fn scope_is_server() {
        assert_eq!(
            MessageAcceptRangesAnd206Consistency.scope(),
            crate::rules::RuleScope::Server
        );
    }
}
