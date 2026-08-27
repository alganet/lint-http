// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, sender_list_members, trim_ows};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct ConnectionHeaderTokensValid;

impl ConnectionHeaderTokensValid {
    /// One field section's `Connection` value, measured against the production the
    /// section that defines the field prints.
    ///
    /// The value is read as the sender wrote it: all of that section's `Connection`
    /// lines joined into the one list they are, every octet reaching the check that
    /// owns it. The recipient's reader would drop the empty elements § 5.6.1.1
    /// forbids the sender from generating, and `to_str` would turn a value carrying
    /// `obs-text` into "this message has no `Connection` field" — a claim about the
    /// message rather than about the member that is wrong.
    ///
    /// cite(RFC 9110 § 7.6.1): "The "Connection" header field allows the sender to list desired control options for the current connection."
    /// cite(RFC 9110 § 7.6.1, label: Connection grammar): "Connection        = #connection-option connection-option = token"
    fn check_field_section(
        &self,
        headers: &hyper::HeaderMap,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        let violation = |message: String| Some(self.violation(severity, message));

        let value = combined_field_value_as_written(headers, "connection")?;

        // The field's own production, in the form the collected grammar gives a
        // sender, and the two things it says about emptiness. The outer `[ ]` is why
        // a `Connection:` carrying nothing is not reported: the field is
        // `#connection-option` and not `1#connection-option`, so a list of no options
        // is a list this production generates — the sender declared no control
        // options, which is what almost every message does by leaving the field out.
        // What the production never generates is a *member* that is empty: every
        // position in it holds a `connection-option`, which is `token`, which is
        // `1*tchar`.
        //
        // The trim is not the same trim as the one inside the loop, and it is not the
        // same sentence either. A member is surrounded by the `OWS` the production
        // prints between its commas; the *value* is not, and what licenses trimming it
        // is § 5.5's MUST on the parser — so a `Connection:` written with a space in it
        // is a value of no options rather than a value of one empty one.
        //
        // cite(RFC 9110 § A, label: Connection grammar, sender-expanded): "Connection = [ connection-option *( OWS "," OWS connection-option ) ]"
        // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
        if trim_ows(&value).is_empty() {
            return None;
        }

        let mut saw_an_empty_element = false;

        for member in sender_list_members(&value) {
            if member.is_empty() {
                // Reported after the members that are present, and reported as the
                // list's defect rather than the element's: there is no such thing as
                // an empty `connection-option`, so what the sender generated is a
                // member that contributes nothing to the list.
                //
                // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                saw_an_empty_element = true;
                continue;
            }

            // A connection-option is a `token`; `tchar` is transcribed once, on the
            // helper that answers this. An octet at or above %x80 is `obs-text`,
            // which `field-content` admits and this production does not — so it
            // arrives here as a `char` outside the `tchar` set and is reported as
            // the member's defect.
            //
            // cite(RFC 9110 § 5.6.2): "Tokens are short textual identifiers that do not include whitespace or delimiters."
            if let Some(ch) = crate::helpers::token::find_invalid_token_char(member) {
                // Both the character and the member are escaped on the way out. The
                // character that stopped the parse is by definition one the grammar
                // did not admit — often a control octet, which written through would
                // corrupt the finding rather than describe it.
                return violation(format!(
                    "Connection header holds invalid character '{}' in member '{}'; a member is a connection-option, which is a token",
                    ch.escape_debug(),
                    member.escape_debug()
                ));
            }

            // The one field the section names, and the whole of what this rule decides
            // about that sentence: whether some *other* field is intended for all
            // recipients of the content is a property of that field's definition and
            // not of anything the message carries. `description()` says so, because a
            // name's absence from this finding is otherwise read as a verdict that
            // listing it is allowed.
            //
            // The fold is what the section asks for and not a convenience.
            //
            // cite(RFC 9110 § 7.6.1): "Connection options are case-insensitive."
            // cite(RFC 9110 § 7.6.1): "A sender MUST NOT send a connection option corresponding to a field that is intended for all recipients of the content.  For example, Cache-Control is never appropriate as a connection option (Section 5.2 of [CACHING])."
            if member.eq_ignore_ascii_case("cache-control") {
                return violation(
                    "Connection header lists 'Cache-Control' as a connection option; the field is intended for all recipients of the content, and RFC 9110 §7.6.1 names it as one a sender MUST NOT list".to_string(),
                );
            }
        }

        if saw_an_empty_element {
            return violation(format!(
                "Connection header holds an empty member: '{}'",
                value.escape_debug()
            ));
        }

        None
    }
}

impl Rule for ConnectionHeaderTokensValid {
    fn id(&self) -> &'static str {
        "connection_header_tokens_valid"
    }

    /// The field is what a sender says about the connection it is speaking over,
    /// and either party is a sender.
    ///
    /// cite(RFC 9110 § 7.6.1): "The "Connection" header field allows the sender to list desired control options for the current connection."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            if let Some(v) = self.check_field_section(&tx.request.headers, ctx.severity) {
                return Some(v);
            }

            if let Some(resp) = &tx.response {
                if let Some(v) = self.check_field_section(&resp.headers, ctx.severity) {
                    return Some(v);
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Validates the `Connection` header field's own value — the list of control options a sender declares for the current connection.\n\nThe field is `Connection = [ connection-option *( OWS \",\" OWS connection-option ) ]` (RFC 9110 §A), and a `connection-option` is a `token` (§7.6.1). So every member must be `1*tchar`: `Connection: a/b` names no option, because `/` is one of the delimiters a token excludes (§5.6.2). No member may be empty — `Connection: keep-alive,,close` is a list a sender MUST NOT generate (§5.6.1.1) — while an **empty value** is a different thing and is not reported: the production's outer brackets make a list of no options a list, so `Connection:` declares nothing rather than declaring badly.\n\nWhere the field appears on several lines in one section, the lines are one value (§5.2), so an empty member written at a line boundary is an empty member. A value carrying an octet outside US-ASCII is measured rather than skipped; `obs-text` is an octet `field-content` admits and `token` does not, so the member is reported for not being a token, which is what is wrong with it.\n\nOne name is reported as a name. RFC 9110 §7.6.1 says a sender MUST NOT send a connection option corresponding to a field that is intended for all recipients of the content, and gives `Cache-Control` as a field that is never appropriate as one. **That example is the whole of what this rule decides about that sentence.** Whether some other field is intended for all recipients of the content is a property of that field's definition, not of anything the message carries, so a rule reading a `Connection` value cannot answer it in general — and a name's absence from this rule's findings is therefore not a verdict that listing it is permitted. Connection options are case-insensitive, and the comparison is too.\n\nAn option is not required to name a field that is present: §7.6.1 says a connection-specific field might not be needed when no parameter is associated with an option, and `close` names no field at all. The converse — a connection-specific field arriving without an option naming it — is the direction §7.6.1 does state a requirement in, and it is not asked here: it is asked of `Upgrade` by `upgrade_and_connection_consistent`, of `TE` by `te_header_valid`, and of `Keep-Alive` by `keep_alive_header_valid`, each with the sentence its own field's section writes — the last of them out of RFC 2068 §19.7.1.1, which is the section §7.6.1 itself names for that field. **Those are the three of §7.6.1's five connection-specific fields that have such a sentence, and the silence about the other two is a decision rather than an omission.** Across RFC 9110 and RFC 9112 the *a sender of X MUST also send an X connection option* form is written for `Upgrade` (§7.8) and `TE` (§10.1.4, restated in RFC 9112 §7.4) and for nothing else; `Keep-Alive`'s comes out of RFC 2068 §19.7.1.1. Neither `Transfer-Encoding` nor `Proxy-Connection` is named by any such sentence.\n\nWhat is *not* claimed here is that they fall outside §7.6.1's general MUST, which names no field at all: it asks the option of any field *used to supply control information for or about the current connection*. **Whether a given field is one of those is a property of that field's definition, not of anything the message carries** — the same reason this rule cannot decide the converse sentence, one paragraph up. For `Transfer-Encoding` no document answers it, so the antecedent is not decidable from a capture and the question is left open rather than guessed in either direction. Membership in §7.6.1's bullet list does not settle it either: that list belongs to the *removal* sentence, which asks intermediaries to strip these fields *whether or not they appear as a connection-option* — so it is a list of fields to remove, and being on it is neither a source of the option requirement nor an exemption from it. `Proxy-Connection` has a sentence of its own instead: RFC 9112 Appendix C.2.2 encourages clients not to send it at all, which `proxy_connection_discouraged` reports as the advice it is.\n\nScope: this rule reads header sections — a request's and a response's — and measures the value whatever protocol version carried it. Some versions of HTTP do not allow the field at all (§7.6.1); `no_connection_specific_fields` is the rule that reports its presence over HTTP/2 and HTTP/3. Whether `Connection` may appear in a *trailer* section is §6.5.1's question and `trailer_fields_valid`'s. Whether an `Upgrade` field is backed by an `upgrade` option is `upgrade_and_connection_consistent`'s."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1",
                note: "The field itself: its grammar, the case-insensitivity of its options, the note that an option need not correspond to a field present in the message, and the MUST NOT this rule implements for the one field the section names",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("A"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A",
                note: "The collected grammar, where the list construct is expanded for a sender — the form that shows both that the whole value may be empty and that a member may not",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1",
                note: "The sender's half of the list construct. The recipient's half (§5.6.1.2, ignore empty elements) is a different party's requirement, which is why the shared list reader is not used here",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2",
                note: "`token` and `tchar`: what a connection-option is made of, and the delimiters it excludes",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2",
                note: "Several `Connection` lines in one field section are one field value, so the members are counted after the lines are joined",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Two options; neither has to name a field that is present"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection: keep-alive, close",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("An option that does name a field, and the field it names"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection: upgrade\nUpgrade: websocket",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "A list of no options is a list; the field is `#connection-option`, not `1#connection-option`",
                ),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("An empty member — the list construct's sender requirement"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection: keep-alive,,close",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`/` is a delimiter, so the member is not a token"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection: a/b",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A field intended for all recipients of the content"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection: Cache-Control",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ConnectionHeaderTokensValid;

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[derive(Clone, Copy, Debug)]
    enum Section {
        Request,
        Response,
    }

    /// Every fixture in this module is built here, from raw octets.
    ///
    /// Two reasons for the one constructor. A `Connection` value is a list however
    /// many lines carry it, so a fixture that can only write one line cannot state
    /// the case where the join is what creates the finding — the earlier tests here
    /// each built their own `HeaderMap` and none of them could. And the octets go in
    /// as octets: `HeaderValue::from_str` would refuse the `obs-text` the field is
    /// measured against, which is exactly the input this rule used to skip.
    fn connection(section: Section, lines: &[&[u8]]) -> Option<Violation> {
        let rule = ConnectionHeaderTokensValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        for line in lines {
            hm.append(
                hyper::header::CONNECTION,
                HeaderValue::from_bytes(line).expect("field value"),
            );
        }
        match section {
            Section::Request => tx.request.headers = hm,
            Section::Response => tx.response.as_mut().expect("response").headers = hm,
        }
        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[rstest]
    #[case("close")]
    #[case("keep-alive")]
    #[case("transfer-encoding")]
    #[case("upgrade")]
    #[case("keep-alive, close")]
    #[case("TE")]
    fn a_list_of_tokens_is_a_list_of_connection_options(
        #[case] value: &str,
        #[values(Section::Request, Section::Response)] section: Section,
    ) {
        let v = connection(section, &[value.as_bytes()]);
        assert!(v.is_none(), "{value:?}: {v:?}");
    }

    /// `Connection = [ connection-option *( OWS "," OWS connection-option ) ]`, so a
    /// value with no options is a value this production generates. The rule reported
    /// it as an "empty token" and two of its own cases asserted that.
    #[rstest]
    #[case(b"")]
    #[case(b" ")]
    #[case(b"\t")]
    fn a_list_of_no_options_is_a_list(
        #[case] value: &[u8],
        #[values(Section::Request, Section::Response)] section: Section,
    ) {
        let v = connection(section, &[value]);
        assert!(v.is_none(), "{value:?}: {v:?}");
    }

    #[rstest]
    #[case(b"keep-alive,,close")]
    #[case(b"close,")]
    #[case(b",close")]
    #[case(b",")]
    #[case(b", ,")]
    fn an_empty_member_is_a_list_a_sender_must_not_generate(
        #[case] value: &[u8],
        #[values(Section::Request, Section::Response)] section: Section,
    ) {
        let v = connection(section, &[value]).expect("violation");
        assert!(v.message.contains("empty member"), "{}", v.message);
    }

    /// The one case that exists only after the lines are joined: neither line holds
    /// an empty member, and the value they make together does.
    #[rstest]
    #[case(&[b"keep-alive," as &[u8], b"close"])]
    #[case(&[b"" as &[u8], b"close"])]
    #[case(&[b"close" as &[u8], b""])]
    fn an_empty_member_written_at_a_line_boundary_is_an_empty_member(#[case] lines: &[&[u8]]) {
        let v = connection(Section::Request, lines).expect("violation");
        assert!(v.message.contains("empty member"), "{}", v.message);
    }

    #[test]
    fn two_lines_of_options_are_one_list_and_not_a_finding() {
        let v = connection(Section::Request, &[b"keep-alive" as &[u8], b"close"]);
        assert!(v.is_none(), "{v:?}");
    }

    #[rstest]
    #[case(b"a/b", '/')]
    #[case(b"close;q=1", ';')]
    #[case(b"\"close\"", '"')]
    #[case(b"keep alive", ' ')]
    fn a_member_that_is_not_a_token_is_reported_with_the_character_that_stopped_it(
        #[case] value: &[u8],
        #[case] expected: char,
    ) {
        let v = connection(Section::Request, &[value]).expect("violation");
        assert!(v.message.contains("invalid character"), "{}", v.message);
        assert!(
            v.message
                .contains(&format!("'{}'", expected.escape_debug())),
            "{}",
            v.message
        );
    }

    /// `obs-text` is an octet `field-content` admits and `token` does not. The rule
    /// skipped any line `to_str` refused, so a value carrying one was not measured at
    /// all — the message on the wire went unreported rather than reported.
    #[rstest]
    #[case(b"clo\xffse")]
    #[case(b"\xff")]
    #[case(b"close, \xc3\xa9")]
    fn an_octet_outside_us_ascii_reaches_the_production_that_excludes_it(#[case] value: &[u8]) {
        let v = connection(Section::Request, &[value]).expect("violation");
        assert!(v.message.contains("invalid character"), "{}", v.message);
    }

    /// %xA0 is `obs-text`, not whitespace: it is a member no production admits, and
    /// trimming it would turn that member into an empty one and report the list for a
    /// defect the element has. `str::trim` does exactly that, which is why the shared
    /// `trim_ows` is what runs here.
    #[test]
    fn a_no_break_space_is_an_octet_and_not_whitespace() {
        let v = connection(Section::Request, &[b"\xa0"]).expect("violation");
        assert!(v.message.contains("invalid character"), "{}", v.message);
    }

    /// § 7.6.1 names one field as never appropriate, and options are case-insensitive.
    #[rstest]
    #[case(b"cache-control")]
    #[case(b"Cache-Control")]
    #[case(b"CACHE-CONTROL")]
    #[case(b"close, cache-control")]
    fn the_one_field_the_section_names_is_reported(
        #[case] value: &[u8],
        #[values(Section::Request, Section::Response)] section: Section,
    ) {
        let v = connection(section, &[value]).expect("violation");
        assert!(v.message.contains("Cache-Control"), "{}", v.message);
        assert!(
            v.message.contains("all recipients of the content"),
            "{}",
            v.message
        );
    }

    /// The values § 5.6.1.2 prints, run through the rule.
    ///
    /// The section prints them as what a *recipient* must accept, and this rule
    /// measures the sender — so the two lists do not line up, and that is the point
    /// of keeping them: `"foo ,bar,"` is a value a recipient MUST parse and a value a
    /// sender MUST NOT generate. The one adjustment is the empty value, which the
    /// section calls invalid for its `1#example-list-elmt` and which `Connection`,
    /// being `#connection-option`, permits.
    #[rstest]
    #[case(b"foo,bar", false)]
    #[case(b"foo ,bar,", true)]
    #[case(b"foo , ,bar,charlie", true)]
    #[case(b"", false)]
    #[case(b",", true)]
    #[case(b",   ,", true)]
    fn the_sections_own_list_examples(#[case] value: &[u8], #[case] expect_violation: bool) {
        let v = connection(Section::Request, &[value]);
        assert_eq!(v.is_some(), expect_violation, "{value:?} -> {v:?}");
    }

    #[test]
    fn a_message_with_no_connection_field_is_not_measured() {
        let v = connection(Section::Request, &[]);
        assert!(v.is_none(), "{v:?}");
    }

    /// Every published snippet is run through the rule, and every Compliant one is
    /// also run through the neighbour that owns the pairing of the two fields:
    /// `upgrade_and_connection_consistent` asks for the `upgrade` option whenever the
    /// `Upgrade` field is there, and this rule — which reads syntax only — cannot see
    /// that in its own file. The example carrying both is here so that guard has
    /// something to measure; it runs in the direction the sentence is written, so what
    /// it would catch is a published snippet that names the field and drops the option.
    #[test]
    fn published_examples_are_judged_by_this_rule_and_by_the_one_that_owns_the_upgrade_option() {
        use crate::rules::{Compliance, Rule as _};
        let rule = ConnectionHeaderTokensValid;
        let neighbour =
            crate::rules::upgrade_and_connection_consistent::UpgradeAndConnectionConsistent;
        let neighbour_cfg = crate::test_helpers::make_test_config_with_severity(
            "upgrade_and_connection_consistent",
            "warn",
        );
        let mut saw_an_upgrade_field = false;

        for ex in rule.examples() {
            let mut pairs: Vec<(&str, &str)> = Vec::new();
            for (i, line) in ex.snippet.lines().enumerate() {
                if i == 0 {
                    assert!(
                        line.ends_with(" HTTP/1.1") && !line.contains(':'),
                        "the first line of an example is its request line: {line:?}"
                    );
                    continue;
                }
                let (name, value) = line.split_once(':').unwrap_or_else(|| {
                    panic!("example header line is not `Name: value`: {line:?}")
                });
                pairs.push((name, value.trim()));
            }
            assert!(
                pairs
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("connection")),
                "example carries no Connection field: {}",
                ex.snippet
            );

            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            let v = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            );
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => assert!(v.is_some(), "{}", ex.snippet),
            }

            if !matches!(ex.compliance, Compliance::Compliant) {
                continue;
            }
            if pairs.iter().any(|(k, _)| k.eq_ignore_ascii_case("upgrade")) {
                saw_an_upgrade_field = true;
            }
            let v = crate::test_helpers::run_rule(
                &neighbour,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &neighbour_cfg,
            );
            assert!(
                v.is_none(),
                "a Compliant example is rejected by the rule that owns the option: {v:?}\n{}",
                ex.snippet
            );
        }

        assert!(
            saw_an_upgrade_field,
            "no Compliant example carries an `Upgrade` field, so the neighbour's guard measured \
             nothing"
        );
    }

    #[test]
    fn scope_is_both() {
        use crate::rules::Rule as _;
        assert_eq!(
            ConnectionHeaderTokensValid.scope(),
            crate::rules::RuleScope::Both
        );
    }
}
