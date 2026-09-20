// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::alt_svc::RFC_7838_5;
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::uri::{
    host_and_port, PERCENT_ENCODING_DIGITS_MISSING, PERCENT_ENCODING_MALFORMED, RFC_3986_2_1,
    RFC_3986_3_2_2, RFC_3986_3_2_3, URI_HOST_BRACKET_FORBIDDEN, URI_HOST_CHARACTER_FORBIDDEN,
    URI_HOST_CLOSING_BRACKET_MISSING, URI_HOST_IP_LITERAL_DELIMITER_MISSING,
    URI_HOST_IP_LITERAL_MALFORMED, URI_PORT_CHARACTER_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct AltUsedValid;

/// The defects of `Alt-Used = uri-host [ ":" port ]`, every one of them the
/// authority's rather than the field's.
///
/// **This is `Host`'s production, written a second time by a second document**,
/// and RFC 7838 § 5 adds nothing to either half — which is why nothing below is
/// this rule's own invention and why `host_header` is this rule's
/// specification. What an operator tunes here is a bracket, a character or a
/// port: the same entries a `Host`, a `:authority`, a `Forwarded` `host` and a
/// `Via` `received-by` draw, out of the one reader all of them call.
///
/// **What `Host` has and this field does not** is the reason the two rules are
/// not one. § 7.2's MUST that a request carry the field, § 9112 § 3.2's MUST
/// that its value exclude the userinfo, and § 3.2's MUST that it be *empty*
/// when the target URI has no authority are three sentences about `Host`
/// alone; RFC 7838 § 5 writes none of them, so an absent `Alt-Used` is not a
/// finding, an `@` in one is the authority's forbidden character rather than a
/// named userinfo, and an empty value is what `reg-name = *( ... )` generates.
static DECLARED: &[&ViolationDef] = &[
    &FIELD_LINE_DUPLICATED,
    &URI_HOST_IP_LITERAL_DELIMITER_MISSING,
    &URI_HOST_CLOSING_BRACKET_MISSING,
    &URI_HOST_IP_LITERAL_MALFORMED,
    &URI_HOST_BRACKET_FORBIDDEN,
    &URI_HOST_CHARACTER_FORBIDDEN,
    &URI_PORT_CHARACTER_FORBIDDEN,
    &PERCENT_ENCODING_DIGITS_MISSING,
    &PERCENT_ENCODING_MALFORMED,
];

impl RuleMeta for AltUsedValid {
    fn id(&self) -> &'static str {
        "alt_used_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Reads the `Alt-Used` header field: whether it is there once, and whether its value is what `Alt-Used = uri-host [ \":\" port ]` generates.\n\n**RFC 7838 defines two header fields and this is the other one.** `Alt-Svc` is the advertisement a server sends and has three rules reading it; `Alt-Used` is what a client puts on a request to name the alternative service it took, and nothing read it. Two instruments could not have said so: coverage counts entries, and a field with no reader has no entry to be uncovered, while a census of field names asks only of names that appeared on some wire — and `Alt-Used` appears on none a proxy in front of an origin records, because it names the alternative the client reached instead.\n\n**Every finding below is the authority's, not this field's.** § 5 writes the value as two productions RFC 3986 defines and adds not a word to either, so a bracket in the wrong place, a character no `reg-name` admits and a port that is not `*DIGIT` are reported under the same ids a `Host` draws them under. That is deliberate: an operator who has tuned `uri_host_character_forbidden` has tuned it here too, and the message names the field so the line is findable.\n\nThree things this rule does **not** report, each because the sentence that would license it is `Host`'s and not this field's:\n\n- **An absent `Alt-Used`.** RFC 9110 §7.2 makes `Host` mandatory; RFC 7838 §5 asks for `Alt-Used` only *when using an alternative service*, which is the next point.\n- **A userinfo subcomponent.** RFC 9112 §3.2 names the `@` for `Host` in a MUST of its own, so `host_header` reports it as such. Here the `@` is simply a character `uri-host` does not admit, and it is reported as one.\n- **An empty field value.** `reg-name` is `*( unreserved / pct-encoded / sub-delims )`, so a host of no characters derives from the grammar. RFC 9112 §3.2 goes further for `Host` and *requires* the empty value in one case; RFC 7838 neither requires nor forbids it, and inventing a prohibition because the field would identify nothing is a requirement no document states.\n\n**The SHOULD in §5 is declined, and the antecedent is why.** \"When using an alternative service, clients SHOULD include an Alt-Used header field in all requests\" is a real obligation on a real sender, and a captured exchange does not record whether the connection it arrived on was an alternative service rather than the origin. The requirement is unobservable from a message, which is a different thing from absent; a rule that reported every request without the field would report every client that never used an alternative at all.\n\n**Both directions are read and nothing is claimed about direction.** §5 describes a field used in requests and forbids one in a response nowhere, exactly as §12.5.2 does for `Accept-Charset`. A response carrying an `Alt-Used` has its value checked, because a malformed authority is malformed wherever it appears, and the finding is attributed to the server that wrote it.\n\n**The value is read as the octets the sender wrote**, one `char` per octet: nothing in this grammar is a quoted-string, so no octet outside visible US-ASCII is legal anywhere in it, and every one of them lands inside a production that already has an id for it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_7838_5,
            RFC_9110_5_3,
            RFC_3986_3_2_2,
            RFC_3986_3_2_3,
            RFC_3986_2_1,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// The field is the client's — § 5 describes a request field — but a
    /// response carrying one was written by the server, and naming the client
    /// for a value it did not write names the wrong peer to fix it. The party
    /// is therefore the side the value was read from, as
    /// `accept_charset_valid` does for the same asymmetry.
    ///
    // cite(RFC 7838 § 5): "The Alt-Used header field is used in requests to identify the alternative service in use, just as the Host header field"
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The alternative's host, as RFC 7838 §5's own example writes it"),
                snippet: "GET /thing HTTP/1.1\nHost: origin.example.com\nAlt-Used: alternate.example.net",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A port follows the one colon that delimits one"),
                snippet: "GET /thing HTTP/1.1\nHost: origin.example.com\nAlt-Used: alternate.example.net:443",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("An IPv6 literal, inside the brackets that identify it"),
                snippet: "GET /thing HTTP/1.1\nHost: origin.example.com\nAlt-Used: [2001:db8::1]:443",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("An IPv6 address with nothing marking where it stopped"),
                snippet: "GET /thing HTTP/1.1\nHost: origin.example.com\nAlt-Used: 2001:db8::1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A space is in no host production"),
                snippet: "GET /thing HTTP/1.1\nHost: origin.example.com\nAlt-Used: alternate example.net",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`port = *DIGIT`, and these are not digits"),
                snippet: "GET /thing HTTP/1.1\nHost: origin.example.com\nAlt-Used: alternate.example.net:https",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The field is not a list, so two lines are not one value"),
                snippet: "GET /thing HTTP/1.1\nHost: origin.example.com\nAlt-Used: a.example\nAlt-Used: b.example",
            },
        ]
    }
}

impl Rule for AltUsedValid {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let validate = |headers: &hyper::HeaderMap, party: crate::lint::Party| -> Vec<Violation> {
            let lines = headers.get_all("alt-used");
            let count = lines.iter().count();
            if count == 0 {
                return Vec::new();
            }

            // Two lines of a field can only be read as one value when the field
            // is a list, and `Alt-Used = uri-host [ ":" port ]` has no `#` in
            // it -- so there is no combined value to measure, and the sender is
            // forbidden from writing the second line at all.
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            // cite(RFC 7838 § 5, label: Alt-Used grammar): "Alt-Used     = uri-host [ ":" port ]"
            if count > 1 {
                return vec![ctx.by(party).report_with(&FIELD_LINE_DUPLICATED, format!(
                    "{count} Alt-Used header field lines: the field is not defined as a list, so they are not one value"
                ))];
            }

            // Every octet of the one field line as the `char` of the same
            // value. The mapping is a bijection over what the productions are
            // built from -- every character in them is ASCII and crosses
            // unchanged -- and every octet none of them admits arrives as a
            // `char` none of them admits either, at the check that owns it.
            // Refusing to decode would name the encoding where the honest
            // finding is that %x80-FF appears in no `uri-host` alternative.
            let Some(line) = lines.iter().next() else {
                return Vec::new();
            };
            let value: String = line.as_bytes().iter().map(|&b| b as char).collect();

            // `OWS` is SP and HTAB and nothing else. `str::trim` is Unicode
            // whitespace, and on a value read octet-per-`char` U+00A0 is the
            // octet %xA0 -- `obs-text`, which no host production admits -- so
            // trimming it would drop the finding rather than the whitespace.
            // cite(RFC 9110 § 5.6.3): "OWS            = *( SP / HTAB )"
            // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace."
            let s = value.trim_matches(|c| c == ' ' || c == '\t');

            // An empty field value is a `uri-host` of no characters --
            // `reg-name` is `*( ... )`. RFC 9112 §3.2 requires exactly that of
            // a `Host` in one case; RFC 7838 §5 neither requires nor forbids
            // it, and reporting it would state a rule no document does.
            // cite(RFC 3986 § 3.2.2, label: reg-name): "reg-name    = *( unreserved / pct-encoded / sub-delims )"
            if s.is_empty() {
                return Vec::new();
            }

            // Asked before the grammar so the answer names what is wrong.
            // Without the brackets nothing marks where the address stopped, so
            // the generic reader splits at the first colon and reports a port
            // full of colons; `fe80::1` has no colon it could call a delimiter
            // at all and would pass entirely.
            // cite(RFC 3986 § 3.2.2): "A host identified by an Internet Protocol literal address, version 6 [RFC3513] or later, is distinguished by enclosing the IP literal within square brackets ("[" and "]")."
            if s.parse::<std::net::Ipv6Addr>().is_ok()
                || crate::helpers::ipv6::looks_like_unbracketed_ipv6_with_port(s)
            {
                return vec![ctx.by(party).report_with(
                    &URI_HOST_IP_LITERAL_DELIMITER_MISSING,
                    format!(
                        "IPv6 literal '{s}' in an Alt-Used field value must be enclosed in square brackets"
                    ),
                )];
            }

            // The field's grammar, which is `Host`'s grammar:
            // `validate_host_and_optional_port` is both productions, and the
            // port it admits is `*DIGIT`, the whole of what RFC 3986 §3.2.3
            // says a port looks like. The finding is named after the authority
            // and not after the field that carried it, because what each
            // production *is* belongs to the defects rather than here.
            if let Err(defect) = crate::helpers::authority::validate_host_and_optional_port(s) {
                return vec![ctx.by(party).report_with(
                    host_and_port(defect),
                    format!(
                        "Alt-Used field value '{s}' is not a host and port: {}",
                        defect.message()
                    ),
                )];
            }

            Vec::new()
        };

        let mut out = validate(&tx.request.headers, crate::lint::Party::Client);

        // §5 describes a field used in requests and forbids one in a response
        // nowhere -- the same asymmetry §12.5.2 has for `Accept-Charset`. The
        // value is still read, because a malformed authority is malformed
        // wherever it appears, and it is the server's.
        if let Some(resp) = &tx.response {
            out.extend(validate(&resp.headers, crate::lint::Party::Server));
        }

        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AltUsedValid;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    fn judge(headers: &[(&str, &str)]) -> Vec<Violation> {
        let tx = crate::test_helpers::make_test_transaction_with_headers(headers);
        crate::test_helpers::run_rule_all(
            &AltUsedValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["alt_used_valid"]),
        )
    }

    fn message(headers: &[(&str, &str)]) -> Option<String> {
        let found = judge(headers);
        // A one-value fixture that takes the first of however many hides a
        // second finding; this rule answers once per side, and the assert is
        // what holds that.
        assert!(found.len() <= 1, "one finding per side: {found:?}");
        found.into_iter().next().map(|v| v.message)
    }

    /// The production is `Host`'s, so what it accepts is `Host`'s too --
    /// including the three shapes that look wrong and derive: a dotted quad out
    /// of range (every `IPv4address` is a `reg-name`), every `sub-delim`, and a
    /// port outside the TCP range, since `port = *DIGIT` bounds nothing.
    #[rstest]
    #[case("alternate.example.net")]
    #[case("alternate.example.net:443")]
    #[case("  alternate.example.net  ")]
    #[case("[2001:db8::1]")]
    #[case("[2001:db8::1]:443")]
    #[case("[v7.fe80::a+en1]")]
    #[case("1.2.3.4:80")]
    #[case("999.999.999.999")]
    #[case("a!$&'()*+,;=.example")]
    #[case("%41.example.net")]
    #[case("alternate.example.net:0")]
    #[case("alternate.example.net:65536")]
    #[case("alternate.example.net:")]
    fn a_value_the_production_generates_is_not_a_finding(#[case] value: &str) {
        assert_eq!(message(&[("alt-used", value)]), None);
    }

    /// Each value reported for the reason its message names, not merely
    /// reported: an assertion on `is_some()` alone is satisfied by a finding
    /// reached for any other reason.
    #[rstest]
    #[case(
        "alternate.example.net:https",
        "Alt-Used field value 'alternate.example.net:https' is not a host and port: invalid character 'h' in port 'https'"
    )]
    #[case(
        "alternate example.net",
        "Alt-Used field value 'alternate example.net' is not a host and port: invalid character ' ' in host 'alternate example.net'"
    )]
    #[case(
        "alt<ernate>.example.net",
        "Alt-Used field value 'alt<ernate>.example.net' is not a host and port: invalid character '<' in host 'alt<ernate>.example.net'"
    )]
    #[case(
        "alt[ernate.example.net",
        "Alt-Used field value 'alt[ernate.example.net' is not a host and port: 'alt[ernate.example.net' holds a bracket, which appears in no host form but an IP literal"
    )]
    #[case(
        "%zz.example.net",
        "Alt-Used field value '%zz.example.net' is not a host and port: Invalid percent-encoding '%zz'"
    )]
    #[case(
        "[2001:db8::1",
        "Alt-Used field value '[2001:db8::1' is not a host and port: IP literal '[2001:db8::1' is missing its ']'"
    )]
    #[case(
        "[not-an-address]",
        "Alt-Used field value '[not-an-address]' is not a host and port: 'not-an-address' is not an IPv6 address"
    )]
    #[case(
        "2001:db8::1",
        "IPv6 literal '2001:db8::1' in an Alt-Used field value must be enclosed in square brackets"
    )]
    #[case(
        "fe80::abcd:8080",
        "IPv6 literal 'fe80::abcd:8080' in an Alt-Used field value must be enclosed in square brackets"
    )]
    fn each_reported_value_says_what_is_wrong_with_it(#[case] value: &str, #[case] expected: &str) {
        assert_eq!(message(&[("alt-used", value)]), Some(expected.to_string()));
    }

    /// The four ids that are not the grammar's happy path, each pinned to the
    /// entry rather than to a message, so a rename of either is caught.
    #[rstest]
    #[case::two_lines(vec![("alt-used", "a.example"), ("alt-used", "b.example")], "field_line_duplicated")]
    #[case::bare_ipv6(vec![("alt-used", "fe80::1")], "uri_host_ip_literal_delimiter_missing")]
    #[case::bad_port(vec![("alt-used", "a.example:ab")], "uri_port_character_forbidden")]
    #[case::bad_char(vec![("alt-used", "a b.example")], "uri_host_character_forbidden")]
    fn each_finding_names_its_entry(#[case] headers: Vec<(&str, &str)>, #[case] id: &str) {
        let found = judge(&headers);
        assert_eq!(found.len(), 1, "{headers:?}");
        assert_eq!(found[0].violation, id, "{headers:?}");
    }

    /// The three sentences `Host` has and this field does not, asserted as
    /// silences. Each would be a finding if this rule had been written by
    /// copying `host_header` rather than by reading RFC 7838 §5.
    #[rstest]
    #[case::absent(vec![])]
    #[case::empty(vec![("alt-used", "")])]
    fn a_requirement_written_only_for_host_is_not_read_here(#[case] headers: Vec<(&str, &str)>) {
        assert_eq!(message(&headers), None);
    }

    /// The `@` is reported, and as the authority's forbidden character rather
    /// than under `host_userinfo_forbidden` -- that entry exists because RFC
    /// 9112 §3.2 names the delimiter for `Host` in a MUST of its own, and RFC
    /// 7838 §5 writes no such sentence.
    #[test]
    fn a_userinfo_is_a_forbidden_character_and_not_a_named_userinfo() {
        let found = judge(&[("alt-used", "user@alternate.example.net")]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].violation, "uri_host_character_forbidden");
    }

    /// A response has no business carrying the field and §5 forbids one
    /// nowhere, so the value is read for syntax and attributed to the peer that
    /// wrote it. Attributing it to the client would name the wrong peer to fix
    /// it.
    #[test]
    fn a_response_value_is_read_and_is_the_servers() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-used", "alternate example.net")],
        );
        let found = crate::test_helpers::run_rule_all(
            &AltUsedValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["alt_used_valid"]),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].violation, "uri_host_character_forbidden");
        assert_eq!(found[0].party, Some(crate::lint::Party::Server));
    }

    /// Both halves are read, so a defective value on each side is two findings
    /// and not one: a single-finding body would have answered for the request
    /// and stopped.
    #[test]
    fn a_defective_value_on_both_sides_is_answered_about_both() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-used", "other example.net")],
        );
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("alt-used", "alternate example.net")]);
        let found = crate::test_helpers::run_rule_all(
            &AltUsedValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["alt_used_valid"]),
        );
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(
            found.iter().map(|v| v.party).collect::<Vec<_>>(),
            vec![
                Some(crate::lint::Party::Client),
                Some(crate::lint::Party::Server)
            ]
        );
    }

    /// The value is octets, and %x80-FF appears in no `uri-host` alternative.
    /// A reader that refused to decode the line would name the encoding and
    /// take the finding that is actually there out of reach.
    #[test]
    fn an_octet_above_ascii_lands_in_the_production_that_refuses_it() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.insert(
            "alt-used",
            hyper::header::HeaderValue::from_bytes(b"alt\xe9rnate.example.net")
                .expect("field-content"),
        );
        let found = crate::test_helpers::run_rule_all(
            &AltUsedValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["alt_used_valid"]),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].violation, "uri_host_character_forbidden");
    }

    /// Every entry the rule can report is declared. A reachable id missing from
    /// `DECLARED` is invisible to the declarer table and to every config that
    /// names the rule.
    #[test]
    fn the_declared_list_holds_every_entry_the_authority_reader_can_return() {
        for value in [
            "a b.example",
            "a.example:ab",
            "alt[ernate.example.net",
            "[2001:db8::1",
            "[not-an-address]",
            "%zz.example.net",
            "%4.example.net",
            "fe80::1",
        ] {
            let found = judge(&[("alt-used", value)]);
            assert_eq!(found.len(), 1, "{value}");
            assert!(
                DECLARED.iter().any(|d| d.id == found[0].violation),
                "{value} reported {} which DECLARED does not hold",
                found[0].violation
            );
        }
    }
}
