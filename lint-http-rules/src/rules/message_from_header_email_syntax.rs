// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::domain::preferred_name_syntax_defect;
use crate::helpers::headers::{combined_field_value_as_written, shown_in_finding, trim_ows};
use crate::helpers::mailbox::{parse_mailbox, MailboxDefect};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageFromHeaderEmailSyntax;

impl Rule for MessageFromHeaderEmailSyntax {
    fn id(&self) -> &'static str {
        "message_from_header_email_syntax"
    }

    /// `From` is defined in § 10.1, *Request Context Fields* — the section is
    /// about the party the field names, and there is no response half of it for
    /// a server to write.
    ///
    /// cite(RFC 9110 § 10.1): "The request header fields below provide additional information about the request context, including information about the user, user agent, and resource behind the request."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let req = &tx.request;

        // The field probe first and the config after it. `parse_rule_config` is
        // several map lookups and a hash of the rule id; a request with no `From`
        // — which is nearly all of them, since § 10.1.2 says the field is rarely
        // sent — should not pay for them.
        //
        // Read as the sender wrote it, one `char` per octet. The `to_str` this
        // replaced answered "From header value is not valid UTF-8" for any octet
        // above %x7E: a claim about an encoding where the truth is about a value,
        // and the octets it hid are exactly the ones no production here admits,
        // since RFC 5322 writes every character class as a range stopping at
        // %x7E.
        //
        // The header section only. Whether *any* field may appear in a trailer
        // section is § 6.5.1's deny-by-default question and
        // `message_trailer_fields_validity`'s finding, and an address identifying
        // the user who sent a request cannot arrive after the request's content.
        //
        // cite(RFC 9110 § 10.1.2): "The "From" header field contains an Internet email address for a human user who controls the requesting user agent."
        // cite(RFC 9110 § 10.1.2): "The address ought to be machine-usable, as defined by "mailbox" in Section 3.4 of [RFC5322]"
        // cite(RFC 9110 § 10.1.2): "mailbox = <mailbox, see [RFC5322], Section 3.4>"
        let value = combined_field_value_as_written(&req.headers, "from")?;
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let violation = |message: String| {
            Some(Violation {
                rule: self.id().to_string(),
                severity: config.severity,
                message,
            })
        };

        let lines = req.headers.get_all("from").iter().count();
        if lines > 1 {
            // `From`'s value is one `mailbox`, and neither of that production's
            // alternatives is a comma-separated list — so § 5.3's exception does
            // not apply and one message carries at most one `From` line.
            //
            // The count has to be taken before the value is parsed, because the
            // recombination is not detectable afterwards in the way it is for
            // most singletons: RFC 5322 § 3.4 defines `mailbox-list` two lines
            // under `mailbox` with a comma as its separator, so what a recipient
            // joins two `From` lines into is a well-formed production of the same
            // document — just not the one this field imports.
            //
            // The preamble is `helpers::headers::singleton_field_preamble`'s.
            // What is appended is the sharpest of the five: the other four join
            // into something malformed or into a reference naming the wrong
            // resource, and this one joins into a *well-formed production of the
            // same document* — `mailbox-list`, two lines below `mailbox` in
            // RFC 5322 § 3.4 and not imported by this field.
            return violation(format!(
                "{}. The comma a recipient joins them with is `mailbox-list`'s separator (RFC 5322 §3.4), a production this field does not import, so the joined value names no one address",
                crate::helpers::headers::singleton_field_preamble(
                    "From",
                    lines,
                    &shown_in_finding(&value),
                    "its value is a single RFC 5322 `mailbox`, which has no comma-separated-list alternative",
                )
            ));
        }

        // `OWS` and only `OWS`. The value carries one `char` per octet, so U+00A0
        // in it is the octet %xA0 — `obs-text`, which is whitespace in no
        // document and which `str::trim` removed before any check saw it.
        //
        // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
        let value = trim_ows(&value);

        if value.is_empty() {
            // Both of `mailbox`'s alternatives contain an `addr-spec`, and
            // `addr-spec` writes a literal `"@"` — so the shortest value the
            // field's grammar generates is not the empty one, whichever
            // alternative each half takes. That is the whole argument, and it is
            // deliberately about the at-sign rather than about a `1*atext` floor:
            // a `quoted-string` local-part has no such floor (`""` derives), and
            // neither does a `domain-literal` (`[]` derives).
            //
            // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
            return violation(
                "From is present with an empty value. `From = mailbox`, both of that production's alternatives contain an `addr-spec`, and `addr-spec = local-part \"@\" domain` writes an at-sign the value does not have — so no empty value derives from the field's grammar (RFC 5322 §3.4.1)"
                    .to_string(),
            );
        }

        match parse_mailbox(value) {
            Ok(parsed) => {
                // Both `?`s below are "there is nothing to report" and not a
                // failure: the first is a sender who wrote a `domain-literal`,
                // the second a host name already in the preferred syntax. Said
                // here because the operator reads the same three characters as
                // an error path everywhere else in this file, and because
                // `clippy::question_mark` refuses the `let ... else` spelling
                // that would have said it in code.
                let domain = parsed.domain_name?;
                let defect = preferred_name_syntax_defect(&domain)?;
                // The weakest finding here, and it is worded as the weaker thing
                // it is. A `dot-atom` domain outside the preferred name syntax —
                // `alice@my_host.example`, where `_` is an `atext` — derives from
                // the field's grammar perfectly well, so §2.2's MUST NOT does not
                // reach it. What reaches it is that RFC 5322 hands the domain to
                // the documents that define host names and says so, and RFC 9110
                // asks for an address that is machine-usable. That is advice, and
                // it is separated from the syntax findings rather than flattened
                // into one "invalid domain" message with them, because a reader
                // who is told a value is malformed will go and change it.
                //
                // A `domain-literal` reaches none of this: `[192.0.2.1]` is an
                // address, not a name, so the helper is asked only for the
                // `dot-atom` form.
                //
                // cite(RFC 5322 § 3.4.1): "In the dot-atom form, this is interpreted as an Internet domain name (either a host name or a mail exchanger name) as described in [RFC1034], [RFC1035], and [RFC1123]."
                // cite(RFC 5322 § 3.4.1): "It is therefore incumbent upon implementations to conform to the syntax of addresses for the context in which they are used."
                violation(format!(
                    "From names the domain '{}', which is a conforming `dot-atom` but not an Internet domain name in RFC 1035 §2.3.1's preferred syntax: {}. This is advice, not a violation — RFC 5322 §3.4.1 hands the domain to the host-name documents rather than restricting it itself, and RFC 9110 §10.1.2 asks only that the address be machine-usable",
                    shown_in_finding(&domain),
                    defect
                ))
            }
            Err(MailboxDefect::ListSeparator) => {
                // The rule's premise. RFC 9110 imports `mailbox`, and RFC 5322
                // § 3.4 prints `mailbox-list` two lines below it — so a
                // comma-separated `From` is a value from the neighbouring
                // production, and the field has room for one address.
                //
                // The previous rule validated a `mailbox-list`, published
                // `From: Alice <alice@example.com>, bob@example.org` to operators
                // as a compliant example, and so had nothing to report here.
                //
                // cite(RFC 5322 § 3.4): "mailbox = name-addr / addr-spec"
                // cite(RFC 5322 § 3.4): "mailbox-list = (mailbox *("," mailbox)) / obs-mbox-list"
                violation(format!(
                    "From value '{}' carries a comma outside every quoted-string, comment and angle-addr — `mailbox-list`'s separator, in a field whose value is one `mailbox`. RFC 5322 §3.4 defines the list form two lines below the one RFC 9110 §10.1.2 imports, so a request that means to name two people has no way to say so in this field",
                    shown_in_finding(value)
                ))
            }
            Err(MailboxDefect::Syntax(defect)) => {
                // Everything else the grammar refuses, including every `obs-`
                // alternative — `obs-phrase`'s bare `.` in a display-name,
                // `obs-angle-addr`'s source route, `obs-domain`'s whitespace
                // around the dots. § 4 admits them for a *receiver* and forbids
                // generating them in the same sentence, which is the half that
                // applies to the party this rule reports on.
                //
                // cite(RFC 5322 § 4): "Though these syntactic forms MUST NOT be generated according to the grammar in section 3, they MUST be accepted and parsed by a conformant receiver."
                violation(format!(
                    "From value '{}' is not an RFC 5322 §3.4 `mailbox`: {} (RFC 9110 §10.1.2)",
                    shown_in_finding(value),
                    defect
                ))
            }
        }
    }

    fn description(&self) -> &'static str {
        "This rule measures the `From` request header against the one production RFC 9110 §10.1.2 gives it: `From = mailbox`, imported by reference from RFC 5322 §3.4. It is a single mailbox and not a list — `mailbox-list` is defined two lines below it in the same section and is not what the field imports — so a comma outside every `quoted-string`, `comment` and `angle-addr` is reported, and so is a second `From` field line, which a recipient recombines into exactly that comma-separated shape (RFC 9110 §5.3). The value is read one `char` per octet, so an octet above %x7E is named at the character class that excludes it rather than folded into a claim about UTF-8; RFC 5322 writes `atext`, `qtext`, `ctext` and `dtext` as ranges that all stop at %x7E. Parenthesised comments and folding whitespace are part of the grammar and are accepted wherever `CFWS` may appear — `alice@example.com (Alice)` is one conforming mailbox. Only §3's grammar is accepted: §4's obsolete alternatives must be accepted by a receiver and must not be generated, and this rule reports on senders. One finding is weaker than the rest and says so in its own text: a `dot-atom` domain outside RFC 1035 §2.3.1's preferred name syntax (an `_`, a label opening or closing on `-`, a label over 63 characters) is a conforming `dot-atom` and is reported as advice. §10.1.2's three other requirements are declined and none of them is about syntax: the user agent SHOULD NOT that turns on whether the user configured the field, the SHOULD on a *robotic* user agent, and the SHOULD NOT on a server *using* the field for access control are each about a party or an intent no captured message states. RFC 5322's own advice to its generators — prefer a `dot-atom` local-part over a quoted one (§3.4.1), keep comments out of address fields (§3.4) — is likewise not enforced: RFC 9110 imports a production, not the document's style guidance."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.1.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.2",
                note: "`From = mailbox` — one address, imported by reference from RFC 5322 §3.4; the section's three other requirements are about parties and intents a capture does not state",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1",
                note: "Request context fields — the sentence behind the scope, since there is no response half of this field",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
                note: "A sender MUST NOT write a second field line for a field whose value is not a comma-separated list",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5",
                note: "Singleton fields, and the `OWS` a parser must exclude before evaluating a field value",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
                note: "The MUST NOT that makes a value outside the field's ABNF a finding",
            },
            crate::rules::SpecRef {
                spec: "RFC 5322",
                section: Some("3.4"),
                url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4",
                note: "`mailbox = name-addr / addr-spec`, and `mailbox-list` beside it — the production this field does *not* import",
            },
            crate::rules::SpecRef {
                spec: "RFC 5322",
                section: Some("3.4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4.1",
                note: "`addr-spec = local-part \"@\" domain`, `domain-literal`, and the sentence handing a `dot-atom` domain to the host-name documents",
            },
            crate::rules::SpecRef {
                spec: "RFC 5322",
                section: Some("3.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.2",
                note: "`CFWS` — folding whitespace and nested parenthesised comments, admitted around nearly every token of a mailbox",
            },
            crate::rules::SpecRef {
                spec: "RFC 5322",
                section: Some("3.2.3"),
                url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.3",
                note: "`atext`, `atom` and `dot-atom-text` — the `1*atext` floors either side of every dot",
            },
            crate::rules::SpecRef {
                spec: "RFC 5322",
                section: Some("3.2.4"),
                url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.4",
                note: "`quoted-string` and `qtext`, the alternative a local-part or a display-name word may take",
            },
            crate::rules::SpecRef {
                spec: "RFC 5322",
                section: Some("4"),
                url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-4",
                note: "Obsolete syntax: MUST NOT be generated, MUST be accepted by a receiver — this rule reports on the generator",
            },
            crate::rules::SpecRef {
                spec: "RFC 1035",
                section: Some("2.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.1",
                note: "Preferred name syntax for the `dot-atom` form of a domain — advisory, and the one finding here that is reported as advice",
            },
            // The URL carries no `#section-2.1`, and that is not an omission:
            // RFC 1123's HTML rendering anchors its top-level sections only, so
            // the fragment the other twelve rows spell would resolve to nothing.
            // The section number is still stated in `section`, which is what a
            // reader needs; a link that scrolls nowhere is worse than none.
            crate::rules::SpecRef {
                spec: "RFC 1123",
                section: Some("2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc1123.html",
                note: "Relaxes RFC 1035's first-character rule to a letter or a digit",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the section's own example)"),
                snippet: "GET / HTTP/1.1\nFrom: spider-admin@example.org",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(display-name and angle-addr)"),
                snippet: "GET / HTTP/1.1\nFrom: Alice <alice@example.com>",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a comma inside a quoted display-name is data)"),
                snippet: "GET / HTTP/1.1\nFrom: \"Doe, John\" <john@example.com>",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a parenthesized comment is part of the grammar)"),
                snippet: "GET / HTTP/1.1\nFrom: alice@example.com (Alice)",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(domain-literal)"),
                snippet: "GET / HTTP/1.1\nFrom: alice@[192.0.2.1]",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(two addresses — the field holds one mailbox, not a mailbox-list)"),
                snippet: "GET / HTTP/1.1\nFrom: Alice <alice@example.com>, bob@example.org",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(two field lines, which a recipient recombines with a comma)"),
                snippet: "GET / HTTP/1.1\nFrom: alice@example.com\nFrom: bob@example.org",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no at-sign)"),
                snippet: "GET / HTTP/1.1\nFrom: not-an-email",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(empty domain)"),
                snippet: "GET / HTTP/1.1\nFrom: alice@",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(unbalanced angle-brackets)"),
                snippet: "GET / HTTP/1.1\nFrom: Alice <alice@example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(obs-phrase — a bare dot in a display-name)"),
                snippet: "GET / HTTP/1.1\nFrom: John Q. Public <jqp@example.com>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a dot-atom domain outside the preferred name syntax)"),
                snippet: "GET / HTTP/1.1\nFrom: alice@my_host.example",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageFromHeaderEmailSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn judge(headers: hyper::HeaderMap) -> Option<Violation> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = headers;
        let config = crate::test_helpers::make_test_config_with_severity(
            "message_from_header_email_syntax",
            "warn",
        );
        MessageFromHeaderEmailSyntax.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
    }

    fn judge_value(from: &str) -> Option<Violation> {
        judge(crate::test_helpers::make_headers_from_pairs(&[(
            "from", from,
        )]))
    }

    #[rstest]
    #[case("spider-admin@example.org")]
    #[case("Alice <alice@example.com>")]
    #[case("<alice@example.com>")]
    #[case("\"Doe, John\" <john@example.com>")]
    #[case("alice@example.com (Alice)")]
    #[case("alice@[192.0.2.1]")]
    #[case("first.last@sub.example.com")]
    fn conforming_mailboxes_are_silent(#[case] from: &str) {
        assert_eq!(judge_value(from).map(|v| v.message), None);
    }

    /// The premise. Both halves are asserted on the exact sentence, because the
    /// two findings a comma can produce — a list where one address goes, and a
    /// second field line — are written in different branches and read alike.
    #[test]
    fn a_comma_separated_from_is_a_mailbox_list() {
        let v = judge_value("Alice <alice@example.com>, bob@example.org")
            .expect("a mailbox-list is a finding");
        assert!(
            v.message
                .contains("`mailbox-list`'s separator, in a field whose value is one `mailbox`"),
            "{}",
            v.message
        );
    }

    #[test]
    fn a_second_from_line_is_the_same_defect_arriving_by_recombination() {
        let v = judge(crate::test_helpers::make_headers_from_pairs(&[
            ("from", "alice@example.com"),
            ("from", "bob@example.org"),
        ]))
        .expect("two field lines are a finding");
        // Pinned whole. The finding is written in two functions now -- the shared
        // preamble and this field's own second sentence -- and an assertion that
        // stops at the preamble would still pass if the half naming
        // `mailbox-list` went missing, which is the half that says what is
        // actually wrong here.
        assert_eq!(
            v.message,
            "From is written on 2 header lines, which recombine into the one value \
             'alice@example.com,bob@example.org'; the field is a singleton — its value is a \
             single RFC 5322 `mailbox`, which has no comma-separated-list alternative — so a \
             sender must not generate more than one field line for it (RFC 9110 §5.3). The comma \
             a recipient joins them with is `mailbox-list`'s separator (RFC 5322 §3.4), a \
             production this field does not import, so the joined value names no one address"
        );
    }

    #[rstest]
    #[case("", "is present with an empty value")]
    #[case("   ", "is present with an empty value")]
    #[case("not-an-email", "ends where the addr-spec has its \"@\"")]
    #[case("alice@", "ends where the addr-spec has a domain")]
    #[case("@example.com", "local-part holds '@'")]
    #[case("Alice <alice@example.com", "ends where the angle-addr has its \">\"")]
    #[case(
        "John Q. Public <jqp@example.com>",
        "'.' where the mailbox has the \"<\""
    )]
    fn malformed_values_name_the_construct_that_stopped(
        #[case] from: &str,
        #[case] expected: &str,
    ) {
        let v = judge_value(from).unwrap_or_else(|| panic!("expected a finding for {from:?}"));
        assert!(v.message.contains(expected), "{}", v.message);
    }

    /// A whitespace-only value is the empty one: §5.5 makes excluding that
    /// whitespace a MUST on the parser, so the two spellings are one value and
    /// the `str::trim` this replaced would also have removed %xA0.
    #[test]
    fn a_whitespace_only_value_is_the_empty_value() {
        let v = judge_value(" \t ").expect("a finding");
        assert!(v.message.contains("empty value"), "{}", v.message);
        let v = judge(crate::test_helpers::make_headers_from_octet_pairs(&[(
            "from", b"\xa0",
        )]))
        .expect("a finding");
        assert!(
            !v.message.contains("empty value"),
            "%xA0 is obs-text, not whitespace: {}",
            v.message
        );
    }

    /// The `obs-text` class. The reader this replaced answered "not valid UTF-8"
    /// — a claim about an encoding, made about a message, where the truth is one
    /// octet in one value.
    #[test]
    fn an_obs_text_octet_is_named_at_the_production_that_excludes_it() {
        let v = judge(crate::test_helpers::make_headers_from_octet_pairs(&[(
            "from",
            b"alic\xe9@example.com",
        )]))
        .expect("a finding");
        assert!(v.message.contains("0xE9"), "{}", v.message);
        assert!(!v.message.contains("UTF-8"), "{}", v.message);
    }

    /// The weakest finding says which document it comes from and that it is
    /// advice, because `_` is an `atext` and the value derives from the field's
    /// grammar.
    #[test]
    fn a_dot_atom_domain_outside_the_preferred_syntax_is_advice() {
        let v = judge_value("alice@my_host.example").expect("a finding");
        assert!(
            v.message.contains("advice, not a violation"),
            "{}",
            v.message
        );
        assert!(v.message.contains("preferred syntax"), "{}", v.message);
        // And the bracketed form is not asked the question at all.
        assert_eq!(judge_value("alice@[192.0.2.1]").map(|v| v.message), None);
    }

    #[test]
    fn a_request_with_no_from_is_silent() {
        assert!(judge(crate::test_helpers::make_headers_from_pairs(&[])).is_none());
    }

    #[test]
    fn scope_is_client() {
        assert_eq!(
            MessageFromHeaderEmailSyntax.scope(),
            crate::rules::RuleScope::Client
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_from_header_email_syntax",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    /// Nothing runs a rule's own `examples()` through the engine, so a
    /// `Compliant` value the rule rejects is published as guidance.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;
        let mut saw_a_finding = false;
        for ex in MessageFromHeaderEmailSyntax.examples() {
            let mut lines = ex.snippet.lines();
            let start = lines.next().expect("an example has a start line");
            assert!(
                start.ends_with(" HTTP/1.1"),
                "this guard files an example's fields onto the request: {start:?}"
            );
            let fields: Vec<(&str, &str)> = lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();
            let found = judge(crate::test_helpers::make_headers_from_pairs(&fields));
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no published example produced a finding");
    }
}
