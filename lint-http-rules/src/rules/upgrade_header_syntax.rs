// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, trim_ows};
use crate::helpers::list::sender_list_members;
use crate::helpers::shown::{describe_char, shown_in_finding};
use crate::helpers::token::{find_invalid_token_char, token_run_end};
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

pub struct UpgradeHeaderSyntax;

/// Why one member of the list derives from no `protocol`.
///
/// The two halves are consumed in the order the production writes them, so the
/// character that stopped each one is reported against the half it interrupted
/// rather than against the member as a whole. `member` is already trimmed of
/// the `OWS` the list prints around its commas and is not empty; the empty
/// member is the *list's* defect and the caller reports it as one.
///
/// **`received-protocol` is not this production and the two are not folded.**
/// `via_header_syntax` reads `[ protocol-name "/" ] protocol-version`
/// — the same two tokens with the *other* half optional, so a lone token is a
/// version there and a name here, and a value ending on its slash is a defect of
/// a different half. What the two genuinely share is `token`, which they both
/// import from § 5.6.2 unchanged and both take from `helpers::token`.
///
/// cite(RFC 9110 § 7.8, label: protocol grammar): "protocol = protocol-name ["/" protocol-version] protocol-name = token protocol-version = token"
fn protocol_defect(member: &str) -> Option<String> {
    // A `protocol-name` is `token`, which is `1*tchar`, so a run of no `tchar`
    // is not a name however the member goes on. The slash is worth its own
    // sentence: a member beginning with one was written as if the name were
    // optional, and it is the `protocol-version` that is.
    let name_end = token_run_end(member);
    if name_end == 0 {
        // An empty member has no defect of its own -- there is no such thing as
        // an empty `protocol`, so what the sender generated is a member that
        // contributes nothing to the list, which is the *list's* defect and the
        // caller's finding. Nothing reaches here with one; the `?` says what the
        // answer would be rather than asserting it cannot happen.
        let first = member.chars().next()?;
        return Some(if first == '/' {
            format!(
                "member '{}' begins with the slash of a protocol version and names no protocol; \
                 a protocol is a protocol-name that a \"/\" and a protocol-version may follow, and \
                 the name is the half that is not optional",
                shown_in_finding(member)
            )
        } else {
            format!(
                "member '{}' does not begin with a protocol name, but with {}",
                shown_in_finding(member),
                describe_char(first)
            )
        });
    }

    // Everything after the name is either nothing — `protocol-name` alone, which
    // is what `websocket` and `h2c` are — or the optional group, which begins
    // with the one character the production prints between the halves.
    let rest = &member[name_end..];
    let mut rest_chars = rest.chars();
    match rest_chars.next() {
        None => None,
        Some('/') => {
            let version = rest_chars.as_str();
            if version.is_empty() {
                return Some(format!(
                    "member '{}' ends with the slash of its protocol; a protocol-version is a \
                     token, which is at least one character",
                    shown_in_finding(member)
                ));
            }
            // A second slash arrives here as a character no `token` admits,
            // which is what it is: the group the production writes is one
            // slash and one version, not a path of them.
            find_invalid_token_char(version).map(|c| {
                format!(
                    "member '{}' has a protocol version holding {}; a protocol-version is a token",
                    shown_in_finding(member),
                    describe_char(c)
                )
            })
        }
        // The production writes no whitespace inside a member and no delimiter
        // other than the slash, so whatever stopped the name is simply a
        // character the name may not hold -- `web socket` is one member and not
        // two, because only a comma separates members.
        Some(c) => Some(format!(
            "member '{}' has a protocol name holding {}; a protocol-name is a token",
            shown_in_finding(member),
            describe_char(c)
        )),
    }
}

impl UpgradeHeaderSyntax {
    /// One field section's `Upgrade` value, measured against the production the
    /// section that defines the field prints.
    ///
    /// The value is read as the sender wrote it: all of that section's `Upgrade`
    /// lines joined into the one list they are, every octet reaching the check
    /// that owns it. `to_str` would turn a value carrying `obs-text` into "this
    /// message has no `Upgrade` field", and `obs-text` is exactly the octet class
    /// no `token` admits — so the value that most needs measuring is the one that
    /// read would drop.
    ///
    /// **The walk is [`sender_list_members`]: naive and empty-preserving**,
    /// which is what a `protocol` wants of a `#rule` walk's two axes. Naive,
    /// because the production is two tokens and a slash and admits no
    /// `quoted-string` anywhere inside it; preserving, because this rule
    /// measures the sender. The two reasons — and why the other two shared
    /// readers each answer a different question — are written at the helper,
    /// which this rule's own audit opened the row for (RULECITES P47) after
    /// writing the walk out inline as the fifth site.
    ///
    /// cite(RFC 9110 § 5.5): "HTTP field values consist of a sequence of characters in a format defined by the field's grammar."
    /// cite(RFC 9110 § A, label: Upgrade grammar, sender-expanded): "Upgrade = [ protocol *( OWS "," OWS protocol ) ]"
    fn defect(headers: &hyper::HeaderMap, direction: &str) -> Option<String> {
        let value = combined_field_value_as_written(headers, "upgrade")?;

        // The two things the production says about emptiness, and they are not
        // the same thing. The outer brackets of the sender-expanded form are why
        // an `Upgrade:` carrying nothing is not reported: the field is
        // `#protocol` and not `1#protocol`, so a list of no protocols is a list
        // this production generates. What it never generates is a *member* that
        // is empty: every position in it holds a `protocol`, whose first half is
        // `token`, which is `1*tchar`.
        //
        // This trim is not the trim inside the loop and does not rest on the same
        // sentence. A member is surrounded by the `OWS` the list prints around
        // its commas; the *value* is not, and what licenses trimming it is
        // § 5.5's MUST on the parser.
        //
        // cite(RFC 9110 § 5.6.1.1): "#element => [ 1#element ]"
        // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
        if trim_ows(&value).is_empty() {
            return None;
        }

        let mut saw_an_empty_member = false;

        for member in sender_list_members(&value) {
            if member.is_empty() {
                // Reported after the members that are present, and reported as
                // the list's defect rather than the element's: there is no such
                // thing as an empty `protocol`, so what the sender generated is a
                // member that contributes nothing to the list.
                //
                // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                saw_an_empty_member = true;
                continue;
            }

            if let Some(defect) = protocol_defect(member) {
                return Some(format!("{direction} Upgrade header {defect}"));
            }
        }

        if saw_an_empty_member {
            return Some(format!(
                "{direction} Upgrade header holds an empty member: '{}'",
                shown_in_finding(&value)
            ));
        }

        None
    }
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_7_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("7.8"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8",
    note: "Upgrade — the field's own section, where `protocol`, `protocol-name` and \
           `protocol-version` are printed, both directions are licensed to carry the \
           field, and the registry is named as advice",
};
const RFC_9110_A: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("A"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A",
    note: "The collected grammar, where the list construct is expanded for a sender — \
           the form that shows both that the whole value may be empty and that a \
           member may not",
};
const RFC_9110_5_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5",
    note: "Field Values — that a value is in the format its field's grammar defines, \
           which is what makes a malformed member a finding at all, and that the \
           value's own ends carry no whitespace",
};
const RFC_9110_5_6_1_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1",
    note: "The sender's half of the list construct: the empty member is its MUST NOT, \
           and the `#element` expansion is why an empty value is not",
};
const RFC_9110_5_6_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2",
    note: "`token` and `tchar`: what both halves of a protocol are made of, and the \
           delimiters they exclude",
};
const RFC_9110_16_7: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("16.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-16.7",
    note: "The Upgrade Token Registry — First Come First Served, which is why no \
           protocol name is compared against a list here",
};
const RFC_9110_5_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2",
    note: "Several `Upgrade` lines in one field section are one field value, so the \
           members are counted after the lines are joined",
};

impl RuleMeta for UpgradeHeaderSyntax {
    fn id(&self) -> &'static str {
        "upgrade_header_syntax"
    }

    fn description(&self) -> &'static str {
        "Parses the `Upgrade` header field of a request and of a response — every field line of one section joined into the single list they are — against RFC 9110 §7.8's grammar: `Upgrade = #protocol`, where `protocol = protocol-name [\"/\" protocol-version]` and both halves are `token`.\n\nSo a member is one token, or two tokens with a single `/` between them: `websocket`, `h2c`, `HTTP/1.1`, `IRC/6.9`. `Upgrade: web socket` names no protocol, because the production writes no whitespace inside a member and only a comma separates members; `Upgrade: /1.1` begins with the slash of a version and names none either, since the *name* is the half that is not optional; `Upgrade: HTTP/` ends on its slash, and a `protocol-version` is at least one character; `Upgrade: HTTP/1.1/2` has a version holding a `/`, which no token admits.\n\n**Empty member and empty value are different things.** `Upgrade: websocket,,h2c` is a list a sender MUST NOT generate (§5.6.1.1) and is reported, after any member that is present, as the list's defect rather than the element's — there is no such thing as an empty `protocol`. `Upgrade:` is not reported at all: the field is `#protocol` and not `1#protocol`, so a list of no protocols is a list this production generates. That such a field still owes an `upgrade` connection option is `upgrade_and_connection_consistent`'s finding, not this rule's.\n\n**The grammar is the whole requirement, and §7.8 states it with no keyword of its own.** The section's thirteen BCP 14 keywords are about who may send the field, what must accompany it, what a server does with one it receives, and which protocol it may switch to — none of them says a value must derive from the production. What does is §5.5: *HTTP field values consist of a sequence of characters in a format defined by the field's grammar.* The one modal this rule carries is §5.6.1.1's MUST NOT, for the empty member.\n\n**No name is compared against a registry, and that is a decision rather than an omission.** RFC 9110 §16.7 creates the *Hypertext Transfer Protocol (HTTP) Upgrade Token Registry* for exactly these tokens, and §7.8 says additional protocol names *ought to be registered* — advice, not a requirement, in a registry whose policy is First Come First Served. A protocol registered tomorrow is conforming today, so an allowlist would report senders for the registry's latency and a config key would ask an operator to maintain one. Case is left alone for the same kind of reason: the preferred case is a property of the *registration*, and §7.8 asks recipients to compare case-insensitively.\n\n**Four of the section's requirements are declined, each because a capture cannot answer it.** That the protocols are listed *in order of descending preference* is what a sender means by the order, and nothing in the message says what it preferred. That a `101` switching several layers lists them *in layer-ascending order* needs the layer each protocol sits at, which no field carries. That a server *MUST NOT switch protocols unless the received message semantics can be honored* is a fact about the new protocol, not about these octets. And the MUST to answer an `Upgrade` carrying a `100-continue` expectation with a `100 (Continue)` *before* the `101` is about a message the capture has no slot for: a transaction holds one response and it is the final one, so an interim `100` recorded there would be the answer the exchange ended on rather than the interim it was.\n\n**Every version is measured, and the neighbours are why.** Over HTTP/2 and HTTP/3 the field's *presence* is already a finding — `no_connection_specific_fields` reports it with each version's own sentence, and reads no value, because whether a value derives from its field's own production is that field's rule's question. This is that rule; declining the value there and here would leave it asked by nobody. `connection_header_tokens_valid` reads `Connection` the same way for the same reason. What each transport does to a connection-specific field before it reaches a capture — which decides whether these findings are live on proxied traffic or only on captures written elsewhere — is published there as well, and it differs by version.\n\n**What the neighbours own.** Whether an `Upgrade` field is named by an `upgrade` connection option is `upgrade_and_connection_consistent`'s. Whether a `101` response carries the field at all, and whether the protocol it names was one the client offered, is `status_101_switching_protocols`'s — it reads the members of both values through the *recipient's* list reader and compares them, which is a different question from whether the sender generated them; a `101` exchange whose `Upgrade` is `, ,` draws a finding from both rules, each naming its own sentence. That a `426 (Upgrade Required)` response must carry the field at all, and must name a protocol in it, is §7.8's and §15.5.22's and is `status_426_upgrade_valid`'s — including the empty value this rule deliberately passes, which that requirement's object clause is what reports.\n\nScope: this rule reads header sections — a request's and a response's — and each finding names which. Where the field appears on several lines in one section they are one value (§5.2), so an empty member written at a line boundary is an empty member. A value carrying an octet outside US-ASCII is measured rather than skipped: `obs-text` is an octet `field-content` admits and `token` does not, so the member is reported for not being a protocol, which is what is wrong with it. The members are split on commas without regard to quoting, because a `protocol` admits no `quoted-string` anywhere inside it — a DQUOTE here is a character no member may hold. Whether `Upgrade` may appear in a *trailer* section is §6.5.1's question and `trailer_fields_valid`'s, which holds the table `Upgrade` is listed in."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_7_8,
            RFC_9110_A,
            RFC_9110_5_5,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_2,
            RFC_9110_16_7,
            RFC_9110_5_2,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The section's own hypothetical request"),
                snippet: "GET /hello HTTP/1.1\nHost: www.example.com\nConnection: upgrade\nUpgrade: websocket, IRC/6.9, RTA/x11",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A list of no protocols is a list; the field is `#protocol`"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection: upgrade\nUpgrade:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("An empty member — the list construct's sender requirement"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection: upgrade\nUpgrade: websocket,,h2c",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The name is the half that is not optional"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection: upgrade\nUpgrade: /1.1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A protocol-version is at least one character"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection: upgrade\nUpgrade: HTTP/",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("No whitespace appears inside a member, and only a comma separates two"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nConnection: upgrade\nUpgrade: web socket",
            },
        ]
    }
}

impl Rule for UpgradeHeaderSyntax {
    /// Both directions carry the field by name in this section: a client offers
    /// protocols in a request, and a server names them in a response — in the
    /// `101` and `426` its own MUSTs are about, and in any other response it
    /// chooses to advertise in.
    ///
    /// cite(RFC 9110 § 7.8): "A client MAY send a list of protocol names in the Upgrade header field of a request to invite the server to switch to one or more of the named protocols, in order of descending preference, before sending the final response."
    /// cite(RFC 9110 § 7.8): "A server MAY send an Upgrade header field in any other response to advertise that it implements support for upgrading to the listed protocols, in order of descending preference, when appropriate for a future request."
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
            // No version gate, and the sibling that reports presence is why. A
            // grammar is what a value is measured against whatever carried it, and
            // over HTTP/2 and HTTP/3 the field's *presence* is already the finding —
            // `no_connection_specific_fields` makes it, and says in as many
            // words that it reads no value because whether one derives from its
            // field's own production is that field's rule's question. This is that
            // rule, and declining the value there and here would leave the question
            // asked by nobody. `connection_header_tokens_valid` reads its own
            // connection-specific field the same way for the same reason.
            let message = Self::defect(&tx.request.headers, "Request").or_else(|| {
                let resp = tx.response.as_ref()?;
                Self::defect(&resp.headers, "Response")
            })?;

            // Read last: a message about to be reported is the only one that pays
            // for the map probes and the two lookups of the rule id.
            Some(self.violation(ctx.severity, message))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &UpgradeHeaderSyntax;

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
    /// The value is a list however many lines carry it, so a fixture that can
    /// only write one line cannot state the case where the join is what creates
    /// the finding. And the octets go in as octets: `HeaderValue::from_str`
    /// would refuse the `obs-text` this rule is supposed to measure.
    fn upgrade(section: Section, lines: &[&[u8]]) -> Option<Violation> {
        let rule = UpgradeHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        for line in lines {
            hm.append(
                hyper::header::UPGRADE,
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

    /// `protocol-name` alone and `protocol-name "/" protocol-version`, including
    /// the three the section's own hypothetical request lists.
    #[rstest]
    #[case("websocket")]
    #[case("h2c")]
    #[case("HTTP/1.1")]
    #[case("IRC/6.9")]
    #[case("RTA/x11")]
    #[case("websocket, IRC/6.9, RTA/x11")]
    #[case("TLS/1.0, HTTP/1.1")]
    // Every `tchar` in one name, and a version that is one too.
    #[case("a!#$%&'*+-.^_`|~0Z/b!#$%&'*+-.^_`|~9Y")]
    fn a_list_of_protocols_is_a_list_of_protocols(
        #[case] value: &str,
        #[values(Section::Request, Section::Response)] section: Section,
    ) {
        let v = upgrade(section, &[value.as_bytes()]);
        assert!(v.is_none(), "{value:?}: {v:?}");
    }

    /// `Upgrade = [ protocol *( OWS "," OWS protocol ) ]`, so a value naming no
    /// protocol is a value this production generates. That such a field still
    /// owes a connection option is the neighbour's finding.
    #[rstest]
    #[case(b"")]
    #[case(b" ")]
    #[case(b"\t")]
    fn a_list_of_no_protocols_is_a_list(
        #[case] value: &[u8],
        #[values(Section::Request, Section::Response)] section: Section,
    ) {
        let v = upgrade(section, &[value]);
        assert!(v.is_none(), "{value:?}: {v:?}");
    }

    #[rstest]
    #[case(b"websocket,,h2c")]
    #[case(b"websocket,")]
    #[case(b",websocket")]
    #[case(b",")]
    #[case(b", ,")]
    fn an_empty_member_is_a_list_a_sender_must_not_generate(
        #[case] value: &[u8],
        #[values(Section::Request, Section::Response)] section: Section,
    ) {
        let v = upgrade(section, &[value]).expect("violation");
        assert!(v.message.contains("empty member"), "{}", v.message);
    }

    /// The case that exists only after the lines are joined: neither line holds
    /// an empty member, and the value they make together does.
    #[rstest]
    #[case(&[b"websocket," as &[u8], b"h2c"])]
    #[case(&[b"" as &[u8], b"h2c"])]
    #[case(&[b"h2c" as &[u8], b""])]
    fn an_empty_member_written_at_a_line_boundary_is_an_empty_member(#[case] lines: &[&[u8]]) {
        let v = upgrade(Section::Request, lines).expect("violation");
        assert!(v.message.contains("empty member"), "{}", v.message);
    }

    #[test]
    fn two_lines_of_protocols_are_one_list_and_not_a_finding() {
        let v = upgrade(Section::Request, &[b"h2c" as &[u8], b"websocket"]);
        assert!(v.is_none(), "{v:?}");
    }

    /// One member per defect the production has, each pinned by the half the
    /// finding names — the halves are what a member is made of, so a message
    /// naming the wrong one sends an operator to the wrong character.
    #[rstest]
    #[case(b"/1.1", "begins with the slash")]
    #[case(b"/", "begins with the slash")]
    #[case(b"HTTP/", "ends with the slash")]
    #[case(b"HTTP/1.1/2", "protocol version holding '/'")]
    #[case(b"HTTP/1 1", "protocol version holding ' '")]
    #[case(b"web socket", "protocol name holding ' '")]
    #[case(b"websocket;q=1", "protocol name holding ';'")]
    #[case(b"\"websocket\"", "does not begin with a protocol name, but with '\"'")]
    #[case(b"(websocket)", "does not begin with a protocol name, but with '('")]
    fn a_member_that_derives_from_no_protocol_is_reported_against_the_half_that_stopped(
        #[case] value: &[u8],
        #[case] expected: &str,
    ) {
        let v = upgrade(Section::Request, &[value]).expect("violation");
        assert!(v.message.contains(expected), "{}", v.message);
    }

    /// `obs-text` is an octet `field-content` admits and `token` does not. Read
    /// back through a UTF-8 decoder this message would have had no `Upgrade`
    /// field at all, and the value on the wire would go unmeasured.
    #[rstest]
    #[case(b"websock\xe9t", "protocol name holding 0xE9")]
    #[case(b"HTTP/1.\xff", "protocol version holding 0xFF")]
    #[case(b"\xff", "does not begin with a protocol name, but with 0xFF")]
    fn an_octet_outside_us_ascii_reaches_the_production_that_excludes_it(
        #[case] value: &[u8],
        #[case] expected: &str,
    ) {
        let v = upgrade(Section::Request, &[value]).expect("violation");
        assert!(v.message.contains(expected), "{}", v.message);
    }

    /// %xA0 is `obs-text`, not whitespace: it is a member no production admits,
    /// and trimming it would turn that member into an empty one and report the
    /// list for a defect the element has.
    #[test]
    fn a_no_break_space_is_an_octet_and_not_whitespace() {
        let v = upgrade(Section::Request, &[b"\xa0"]).expect("violation");
        assert!(
            v.message.contains("does not begin with a protocol name"),
            "{}",
            v.message
        );
    }

    /// A DQUOTE opens nothing here, so the comma after it is still the list's
    /// separator: two members, and the first is reported for the character it
    /// holds rather than the value being read as one quoted member.
    #[test]
    fn a_dquote_does_not_make_the_next_comma_data() {
        let v = upgrade(Section::Request, &[b"\"web,socket\""]).expect("violation");
        assert!(v.message.contains("'\"'"), "{}", v.message);
        assert!(!v.message.contains("web,socket"), "{}", v.message);
    }

    /// The finding names the section it came from, which is the only thing that
    /// distinguishes two identical values in one transaction.
    #[rstest]
    #[case(Section::Request, "Request Upgrade header")]
    #[case(Section::Response, "Response Upgrade header")]
    fn the_finding_names_the_direction(#[case] section: Section, #[case] expected: &str) {
        let v = upgrade(section, &[b"web socket"]).expect("violation");
        assert!(v.message.starts_with(expected), "{}", v.message);
    }

    /// No version gate: a grammar is what a value is measured against whatever
    /// carried it. Over these two versions the *presence* of the field is
    /// `no_connection_specific_fields`'s finding, and that rule reads no
    /// value at all — so declining the value here as well would leave the
    /// question asked by nobody.
    #[rstest]
    #[case("HTTP/1.1")]
    #[case("HTTP/1.0")]
    #[case("HTTP/2.0")]
    #[case("HTTP/3.0")]
    fn the_value_is_measured_whatever_version_carried_it(#[case] version: &str) {
        let rule = UpgradeHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = version.into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("upgrade", "/1.1")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some(), "{version}: {v:?}");
    }

    #[test]
    fn a_message_with_no_upgrade_field_is_not_measured() {
        let v = upgrade(Section::Request, &[]);
        assert!(v.is_none(), "{v:?}");
    }

    /// Every published snippet is run through the rule, and the Compliant ones
    /// are also run through the neighbour that owns the pairing of the two
    /// fields — a published `Upgrade` with no `upgrade` connection option beside
    /// it would be an example this rule calls clean and the catalogue reports.
    #[test]
    fn published_examples_are_judged_by_this_rule_and_by_the_one_that_owns_the_option() {
        use crate::rules::{Compliance, RuleMeta as _};
        let rule = UpgradeHeaderSyntax;
        let neighbour =
            crate::rules::upgrade_and_connection_consistent::UpgradeAndConnectionConsistent;
        let neighbour_cfg = crate::test_helpers::make_test_config_with_severity(
            "upgrade_and_connection_consistent",
            "warn",
        );

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
                pairs.iter().any(|(k, _)| k.eq_ignore_ascii_case("upgrade")),
                "example carries no Upgrade field: {}",
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

            let v = crate::test_helpers::run_rule(
                &neighbour,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &neighbour_cfg,
            );
            assert!(
                v.is_none(),
                "a published example is rejected by the rule that owns the option: {v:?}\n{}",
                ex.snippet
            );
        }
    }

    #[test]
    fn scope_is_both() {
        use crate::rules::Rule as _;
        assert_eq!(UpgradeHeaderSyntax.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "upgrade_header_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
