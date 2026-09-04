// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::structured_fields::{
    is_boolean, is_integer, parse_dictionary, sf_field_bytes_invalid,
};
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

pub struct PriorityHeaderSyntax;

/// Which message the field was read from.
///
/// Not a label on the finding: what an ignored priority parameter costs is not
/// the same in the two directions, and § 8 is explicit that the asymmetry is
/// deliberate. In a request, omission means the default, so an ignored
/// parameter is quietly replaced by it. In a response there is no default to
/// fall back to -- absence there means the server does not wish to change what
/// the client asked for -- so an ignored parameter loses the server's opinion
/// altogether rather than substituting a value.
///
// cite(RFC 9218 § 8): "The absence of a priority parameter in an HTTP response indicates the server's disinterest in changing the client-provided value."
// cite(RFC 9218 § 8): "This is different from the request header field, in which omission of a priority parameter implies the use of its default value (see Section 4)."
#[derive(Copy, Clone)]
enum Section {
    Request,
    Response,
}

impl Section {
    fn name(self) -> &'static str {
        match self {
            Section::Request => "request",
            Section::Response => "response",
        }
    }

    /// What happens to the parameter's slot once the parameter is ignored.
    ///
    // cite(RFC 9218 § 4): "When receiving an HTTP request that does not carry these priority parameters, a server SHOULD act as if their default values were specified."
    fn instead(self, default: &str) -> String {
        match self {
            Section::Request => format!("and use the default, {}", default),
            Section::Response => {
                "and keep whatever the client asked for, so this signal is lost".into()
            }
        }
    }
}

impl PriorityHeaderSyntax {
    /// Judge the `Priority` field of one message, from its joined value.
    ///
    /// Not one field line at a time, which is what this used to do -- and it
    /// read only the *first* line, so a second `Priority` header was invisible.
    /// A Dictionary is a structure over the whole field and its members may be
    /// spread across lines; § 4.2 of Structured Fields makes the combining a
    /// MUST and says why.
    ///
    // cite(RFC 9651 § 4.2): "When generating input_bytes, parsers MUST combine all field lines in the same section (header or trailer) that case-insensitively match the field name into one comma-separated field-value, as per Section 5.2 of [HTTP]; this assures that the entire field value is processed correctly."
    fn check_section(
        &self,
        headers: &hyper::HeaderMap,
        section: Section,
        severity: crate::lint::Severity,
    ) -> Vec<Violation> {
        let mut lines: Vec<&str> = Vec::new();
        for hv in headers.get_all("priority").iter() {
            // Not "not valid UTF-8", which this used to claim and is a weaker
            // statement: a well-formed multi-byte character passes a UTF-8
            // check and still fails here, because a Structured Field is ASCII
            // and step 1 fails before any type is considered.
            //
            // The one finding this section can have: nothing below it parsed,
            // so there are no members to say anything else about.
            let Ok(v) = hv.to_str() else {
                return vec![self.violation(
                    severity,
                    whole_field(section, "contains a byte outside ASCII"),
                )];
            };
            lines.push(v);
        }
        if lines.is_empty() {
            return Vec::new();
        }
        validate_priority(&lines.join(", "), section)
            .into_iter()
            .map(|message| self.violation(severity, message))
            .collect()
    }
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9218_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9218",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc9218.html#section-4",
    note: "Priority Parameters — the Dictionary encoding, and the MUST to ignore an unknown parameter, an out-of-range value or a value of unexpected type rather than treat it as an error",
};
const RFC_9218_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9218",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9218.html#section-4.1",
    note: "Urgency — an Integer between 0 and 7 inclusive, defaulting to 3",
};
const RFC_9218_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9218",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9218.html#section-4.2",
    note: "Incremental — a Boolean, defaulting to false",
};
const RFC_9218_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9218",
    section: Some("8"),
    url: "https://www.rfc-editor.org/rfc/rfc9218.html#section-8",
    note: "Why an ignored parameter costs different things in a request and in a response: only in a request does omission imply the default",
};
const RFC_9218_4_3_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9218",
    section: Some("4.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9218.html#section-4.3.1",
    note: "The \"HTTP Priority\" registry — open, and holding only u and i, which is why an unrecognised key is not a finding",
};
const RFC_9651_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9651",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2",
    note: "Structured Fields parsing — the MUST to join field lines, and the discard rule that makes one malformed parameter cost the whole field",
};

impl RuleMeta for PriorityHeaderSyntax {
    fn id(&self) -> &'static str {
        "priority_header_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Reports a `Priority` header field (RFC 9218) carrying a priority parameter that will not take effect. Nothing here is \"invalid\": §4 defines **ignore** semantics, so the finding is always that the sender wrote a signal a recipient will discard, at one of two scopes.\n\n**The whole field, or one parameter.** `Priority` is a Structured Fields Dictionary and §4 says receivers parse it as one, so a parse failure discards everything — RFC 9651 §4.2, \"If parsing fails, either the entire field value MUST be ignored … or alternatively the complete HTTP message MUST be treated as malformed\". One uppercase letter in a key, or `i=?2` where `?2` is not a Boolean, costs every parameter in the field. A parameter that parses but says something unusable costs only itself: §4, \"unknown priority parameters, priority parameters with out-of-range values, or values of unexpected types MUST be ignored\". The messages say which.\n\n**What each of the two defined parameters must be.** `u` is an Integer between 0 and 7 inclusive (§4.1); `i` is a Boolean (§4.2), and a bare `i` is that Boolean's `true`, which is why `u=5, i` is the RFC's own example. A bare `u` is *also* Boolean true, and therefore a value of unexpected type — the one place where leaving a value out is a defect rather than a shorthand. Leading zeros are not: RFC 9651 §3.3.1 permits `u=03`.\n\n**Being ignored costs different things in the two directions.** §8: in a request, omitting a parameter means its default, so an ignored `u` becomes 3 and an ignored `i` becomes false. In a response, absence means the server does not wish to change the client's value, so an ignored parameter loses the server's view entirely with nothing substituted.\n\n**Every field line is joined first**, as RFC 9651 §4.2 requires — this rule used to read only the first `Priority` header of a message.\n\n**A repeated key is reported.** RFC 9651 §4.2.2 keeps only the last instance and says nothing about it, so `u=1, u=5` looks like two urgencies and is one; the earlier parameter is dead text no recipient will see.\n\n**Not reported:** an unknown parameter key. The \"HTTP Priority\" registry (§4.3.1) is open by design and holds only `u` and `i` today, so a key this rule does not know is an extension doing what §4.3 contemplates, and §4's MUST to ignore it is what makes sending one safe. Nor an empty field value, which RFC 9651 §4.2.2 parses into an empty Dictionary: it expresses no preference rather than failing."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9218_4,
            RFC_9218_4_1,
            RFC_9218_4_2,
            RFC_9218_8,
            RFC_9218_4_3_1,
            RFC_9651_4_2,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a bare i is the Boolean true — RFC 9218's own example)"),
                snippet: "GET /image.jpg HTTP/1.1\nPriority: u=5, i",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nPriority: u=1",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(an unregistered key is an extension, and MUST be ignored rather than rejected)"),
                snippet: "GET /style.css HTTP/1.1\nPriority: u=0, visible=?1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(an urgency outside 0-7 is ignored, so the request gets the default 3)"),
                snippet: "GET /script.js HTTP/1.1\nPriority: u=8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a bare u is Boolean true, not an Integer)"),
                snippet: "GET /script.js HTTP/1.1\nPriority: u",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(?2 is not a Boolean, and the parse failure discards the urgency beside it)"),
                snippet: "GET /image.jpg HTTP/1.1\nPriority: u=5, i=?2",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(u given twice is one urgency, not two: all but the last are ignored)"),
                snippet: "GET /image.jpg HTTP/1.1\nPriority: u=1, u=5",
            },
        ]
    }
}

impl Rule for PriorityHeaderSyntax {
    /// Both directions, because the field is defined for both.
    ///
    // cite(RFC 9218 § 5): "The Priority HTTP header field is a Dictionary that carries priority parameters (see Section 4)."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // The two sections are judged separately and never joined across the
        // pair: the sentence on `check_section` gathers the lines "in the same
        // section", and § 8 has an intermediary combine the two afterwards as
        // two signals rather than reading them as one field.
        //
        // Two sections, so two sets of findings. They are also two signals with
        // two costs -- § 8 says an ignored request parameter falls back to its
        // default while an ignored response parameter loses the server's view
        // outright -- and returning at the request's finding described one
        // signal and left the other unmeasured.
        let mut out = self.check_section(&tx.request.headers, Section::Request, ctx.severity);
        if let Some(resp) = &tx.response {
            out.extend(self.check_section(&resp.headers, Section::Response, ctx.severity));
        }
        out
    }
}

/// The finding when the whole field is gone, framed as what that costs.
fn whole_field(section: Section, msg: &str) -> String {
    format!(
        "the {} Priority field fails Structured Fields parsing, so a recipient discards every \
         priority parameter in it and prioritizes as if the field were absent: {}",
        section.name(),
        msg
    )
}

/// The finding when the field parsed and one parameter of it will be dropped.
fn ignored(section: Section, key: &str, name: &str, reason: &str, default: &str) -> String {
    format!(
        "the {} Priority field's {} ({}) {}, so a recipient MUST ignore it {}",
        section.name(),
        name,
        key,
        reason,
        section.instead(default)
    )
}

/// Every way the joined field value will not be honoured.
///
/// A whole-field failure is one message and the only one: nothing parsed, so
/// there are no members left to describe. Past that point the messages are
/// per-member and independent -- § 4's requirement is to ignore *a* parameter --
/// so a field with two unusable parameters is two findings rather than one
/// finding and a silence.
fn validate_priority(s: &str, section: Section) -> Vec<String> {
    // The byte-level half of § 4.2's step 1, which precedes any type.
    if let Some(msg) = sf_field_bytes_invalid(s) {
        return vec![whole_field(section, msg)];
    }

    // One reading, not three: unlike a rule pointed at a configured header
    // name, this one knows the field_type § 4.2 asks for, because RFC 9218
    // states it. That is what lets everything below say something -- a
    // Dictionary told it is an invalid Item has been told nothing.
    // cite(RFC 9218 § 4): "For both the Priority header field and the PRIORITY_UPDATE frame, the set of priority parameters is encoded as a Dictionary (see Section 3.2 of [STRUCTURED-FIELDS])."
    // cite(RFC 9218 § 4): "Receivers parse the Dictionary as described in Section 4.2 of [STRUCTURED-FIELDS]."
    let members = match parse_dictionary(s) {
        Ok(members) => members,
        // A parse failure is the whole field, and RFC 9651 forbids a field
        // definition from softening that. RFC 9218 does not try: its own
        // ignore-this-parameter requirement is scoped to a Dictionary that
        // parsed, which is the sentence that separates the two findings here.
        // cite(RFC 9651 § 4.2): "If parsing fails, either the entire field value MUST be ignored (i.e., treated as if the field were not present in the section), or alternatively the complete HTTP message MUST be treated as malformed."
        Err(msg) => return vec![whole_field(section, &msg)],
    };

    let mut out: Vec<String> = Vec::new();

    // Duplicates first, and in their own pass, because a repeated key is a fact
    // about the field rather than about either copy: reporting that `u=8` is out
    // of range when a later `u=3` has already superseded it would name the wrong
    // problem. Keys are compared byte for byte, which § 4.2.2 says outright and
    // which the key grammar makes moot anyway.
    //
    // Not a parse failure and not an error -- the parser keeps the last one
    // silently, and the header still looks like it says both things, which is
    // what makes this worth saying out loud.
    // cite(RFC 9651 § 4.2.2): "Note that when duplicate Dictionary keys are encountered, all but the last instance are ignored."
    let mut seen: Vec<&str> = Vec::new();
    let mut reported: Vec<&str> = Vec::new();
    for m in &members {
        if seen.contains(&m.key) {
            // Once per key, however many times it is repeated: `u=1, u=2, u=3`
            // is one dead-text fact about `u`, not two.
            if !reported.contains(&m.key) {
                reported.push(m.key);
                out.push(format!(
                    "the {} Priority field gives '{}' more than once; all but the last are \
                     ignored, so the earlier one has no effect",
                    section.name(),
                    m.key
                ));
            }
            continue;
        }
        seen.push(m.key);
    }

    // Everything below is one sentence's worth of work. RFC 9218 adds exactly
    // one requirement on top of a Dictionary that parsed, it is addressed to
    // receivers, and it is to ignore -- so a member this rule objects to is
    // never a syntax error, it is a signal that will not arrive.
    // cite(RFC 9218 § 4): "Where the Dictionary is successfully parsed, this document places the additional requirement that unknown priority parameters, priority parameters with out-of-range values, or values of unexpected types MUST be ignored."
    //
    // Only the member a receiver acts on is judged, which is the *last* instance
    // of its key: saying `u=8` is out of range when a later `u=3` has already
    // superseded it names a value nothing will read. The duplication is what was
    // reported above. This pass used to be skipped entirely once any key
    // repeated, so `u=1, u=2, i=5` said nothing about `i=5`.
    for (index, m) in members.iter().enumerate() {
        if members[index + 1..].iter().any(|later| later.key == m.key) {
            continue;
        }
        match m.key {
            "u" => {
                // Both halves of one sentence, and they fail differently: a
                // Decimal or a Token is a value of unexpected type, while `9`
                // is an Integer that is out of range. § 4 lists the two
                // separately, so the message does too.
                //
                // The range test parses rather than looking at the digit,
                // because an SF Integer may carry leading zeros and a signed
                // zero -- `u=03` and `u=-0` are 3 and 0. `is_integer` has
                // already bounded the value at fifteen digits and a sign, so
                // the parse cannot overflow.
                // cite(RFC 9218 § 4.1): "The urgency (u) parameter value is Integer (see Section 3.3.1 of [STRUCTURED-FIELDS]), between 0 and 7 inclusive, in descending order of priority."
                // cite(RFC 9651 § 3.3.1): "While it is possible to serialize Integers with leading zeros (e.g., "0002", "-01") and signed zero ("-0"), these distinctions may not be preserved by implementations."
                let reason = match m.value {
                    // The one parameter for which a missing value is a defect.
                    // § 4.2.2 reads a bare key as the Boolean true, which is a
                    // perfectly good Dictionary member and not an Integer.
                    // cite(RFC 9651 § 4.2.2): "Let value be Boolean true."
                    None => {
                        Some("has no value, which is the Boolean true and not an Integer".into())
                    }
                    Some(v) if !is_integer(v) => {
                        Some(format!("is '{}', which is not an Integer", v))
                    }
                    Some(v) if !matches!(v.parse::<i64>(), Ok(n) if (0..=7).contains(&n)) => {
                        Some(format!("is '{}', which is outside 0 to 7 inclusive", v))
                    }
                    Some(_) => None,
                };
                if let Some(reason) = reason {
                    // The default is the second sentence below; the first is
                    // carried with it only because "The default is 3." alone is
                    // three characters short of being quotable evidence.
                    // cite(RFC 9218 § 4.1): "between 0 and 7 inclusive, in descending order of priority. The default is 3."
                    out.push(ignored(section, "u", "urgency", &reason, "3"));
                }
            }
            "i" => {
                // A bare `i` is not checked, and that is the sentence above at
                // work rather than a tolerance: § 4.2.2 makes a keyless member
                // the Boolean true, which is exactly the type `i` is defined
                // as. `Priority: u=5, i` is the RFC's own spelling of "true".
                // cite(RFC 9218 § 4.2): "The incremental (i) parameter value is Boolean (see Section 3.3.6 of [STRUCTURED-FIELDS])."
                if let Some(v) = m.value {
                    if !is_boolean(v) {
                        // cite(RFC 9218 § 4.2): "The default value of the incremental parameter is false (0)."
                        out.push(ignored(
                            section,
                            "i",
                            "incremental",
                            &format!("is '{}', which is not a Boolean", v),
                            "false",
                        ));
                    }
                }
            }
            _ => {
                // Silence here is a decision, not a gap. The registry is open
                // by design, it holds only `u` and `i` at the time of writing,
                // and § 4.3 has new parameters arrive precisely by being
                // ignored where they are not understood -- so a key this rule
                // does not know is an extension working as intended. Reporting
                // it would report the mechanism.
                // cite(RFC 9218 § 4.3.1): "New priority parameters can be defined by registering them in the "HTTP Priority" registry."
                // cite(RFC 9218 § 4.3): "Since unknown priority parameters are ignored, new priority parameters should not change the interpretation of, or modify, the urgency (see Section 4.1) or incremental (see Section 4.2) priority parameters in a way that is not backwards compatible or fallback safe."
            }
        }
    }

    out
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &PriorityHeaderSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&["priority_header_syntax"])
    }

    fn check_req(values: &[&str]) -> Option<Violation> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(
            &values.iter().map(|v| ("priority", *v)).collect::<Vec<_>>(),
        );
        crate::test_helpers::run_rule(
            &PriorityHeaderSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
    }

    fn check_resp(value: &str) -> Option<Violation> {
        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("priority", value)]);
        crate::test_helpers::run_rule(
            &PriorityHeaderSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
    }

    fn check_all(tx: &crate::http_transaction::HttpTransaction) -> Vec<Violation> {
        crate::test_helpers::run_rule_all(
            &PriorityHeaderSyntax,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
    }

    /// The two sections are two signals with two costs -- § 8 substitutes a
    /// default for an ignored request parameter and substitutes nothing for an
    /// ignored response one -- so each answers for itself. The request's finding
    /// used to be the whole answer.
    #[test]
    fn each_section_is_its_own_finding() {
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("priority", "u=9")]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("priority", "i=5")]);

        let all = check_all(&tx);
        assert_eq!(all.len(), 2, "{all:?}");
        assert!(all[0].message.contains("request"), "{}", all[0].message);
        assert!(all[1].message.contains("response"), "{}", all[1].message);
    }

    /// § 4's requirement is to ignore *a* parameter, so two unusable parameters
    /// are two signals that will not arrive. One of them used to hide the other.
    #[test]
    fn each_unusable_parameter_is_its_own_finding() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("priority", "u=9, i=5")]);

        let all = check_all(&tx);
        assert_eq!(all.len(), 2, "{all:?}");
        assert!(all[0].message.contains("urgency (u)"), "{}", all[0].message);
        assert!(
            all[1].message.contains("incremental (i)"),
            "{}",
            all[1].message
        );
    }

    /// A whole-field failure is the only finding a section can have: nothing
    /// parsed, so there are no members left to say anything about.
    #[test]
    fn a_parse_failure_stays_one_finding() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("priority", "U=1, i=5")]);

        let all = check_all(&tx);
        assert_eq!(all.len(), 1, "{all:?}");
        assert!(
            all[0].message.contains("whole") || all[0].message.contains("every"),
            "{}",
            all[0].message
        );
    }

    /// A repeated key is one fact about the key however many copies there are,
    /// and it no longer silences the rest of the field: the `i=5` here is a
    /// second, independent signal that will not arrive.
    #[test]
    fn a_repeated_key_is_reported_once_and_silences_nothing() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("priority", "u=1, u=2, u=3, i=5")]);

        let all = check_all(&tx);
        assert_eq!(all.len(), 2, "{all:?}");
        assert!(
            all[0].message.contains("more than once"),
            "{}",
            all[0].message
        );
        assert!(
            all[1].message.contains("incremental (i)"),
            "{}",
            all[1].message
        );
    }

    /// Only the member a receiver acts on is judged. `u=8` is out of range and
    /// superseded, so naming it would name a value nothing reads; the surviving
    /// `u=3` is fine, and the duplication is the finding.
    #[test]
    fn a_superseded_value_is_not_judged() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("priority", "u=8, u=3")]);

        let all = check_all(&tx);
        assert_eq!(all.len(), 1, "{all:?}");
        assert!(
            all[0].message.contains("more than once"),
            "{}",
            all[0].message
        );
    }

    /// The surviving instance *is* judged, which is the other half of the same
    /// reading: `u=3` was superseded by an `u=8` a receiver will act on.
    #[test]
    fn the_surviving_value_is_judged() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("priority", "u=3, u=8")]);

        let all = check_all(&tx);
        assert_eq!(all.len(), 2, "{all:?}");
        assert!(
            all[0].message.contains("more than once"),
            "{}",
            all[0].message
        );
        assert!(
            all[1].message.contains("outside 0 to 7"),
            "{}",
            all[1].message
        );
    }

    /// Every `Priority` field value RFC 9218 prints, fed through the rule.
    #[rstest]
    #[case("u=0")]
    #[case("u=1")]
    #[case("u=7")]
    #[case("u=5, i")]
    fn the_rfcs_own_examples_are_accepted(#[case] value: &str) {
        assert!(
            check_req(&[value]).is_none(),
            "rejects RFC 9218's own example {value:?}: {:?}",
            check_req(&[value])
        );
    }

    #[rstest]
    // Both defined parameters, in every spelling the two specs allow.
    #[case("u=0", false)]
    #[case("u=7", false)]
    #[case("i", false)]
    #[case("i=?1", false)]
    #[case("i=?0", false)]
    #[case("u=3;i", false)]
    // A member's parameters are not part of its value, and RFC 9218 defines
    // none, so the urgency here is 3 and the parameter is only Structured
    // Fields' business.
    #[case("u=3;foo=bar", false)]
    #[case("u=3;foo=\"a,b\"", false)]
    // An SF Integer may carry leading zeros and a signed zero (§ 3.3.1).
    #[case("u=03", false)]
    #[case("u=-0", false)]
    // An empty field value is an empty Dictionary, not a failure (§ 4.2.2).
    #[case("", false)]
    // Out of range, or of the wrong type: the parameter alone is ignored.
    #[case("u=8", true)]
    #[case("u=-1", true)]
    #[case("u=3.0", true)]
    #[case("u=abc", true)]
    #[case("u", true)]
    #[case("i=5", true)]
    #[case("i=yes", true)]
    // Parse failures: the whole field goes.
    #[case("u=+1", true)]
    #[case("U=3", true)]
    #[case("i=?2", true)]
    #[case("u=1, ,i", true)]
    #[case("u=3;;i", true)]
    #[case("u=3;x=)))", true)]
    // A repeated key is one parameter written twice.
    #[case("u=1, u=5", true)]
    fn request_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let v = check_req(&[value]);
        assert_eq!(
            v.is_some(),
            expect_violation,
            "for {value:?}, got {:?}",
            v.map(|v| v.message)
        );
    }

    /// The two scopes are two different findings, and the message says which.
    #[test]
    fn a_parse_failure_costs_the_field_and_a_bad_value_costs_itself() {
        let whole = check_req(&["u=+1"]).unwrap().message;
        assert!(
            whole.contains("discards every priority parameter"),
            "{whole}"
        );

        let one = check_req(&["u=8"]).unwrap().message;
        assert!(
            one.contains("MUST ignore it and use the default, 3"),
            "{one}"
        );
        assert!(!one.contains("discards every"), "{one}");
    }

    /// § 8: only a request has a default to fall back to.
    #[test]
    fn an_ignored_parameter_costs_different_things_in_the_two_directions() {
        let req = check_req(&["u=8"]).unwrap().message;
        assert!(req.contains("use the default, 3"), "{req}");

        let resp = check_resp("u=8").unwrap().message;
        assert!(
            resp.contains("keep whatever the client asked for"),
            "{resp}"
        );
        assert!(!resp.contains("default"), "{resp}");
    }

    /// § 4.2 of RFC 9651: all the field's lines, not the first one.
    #[test]
    fn every_field_line_is_read() {
        let v = check_req(&["i", "u=8"]).expect("a second Priority line is part of the field");
        assert!(v.message.contains("urgency"), "{}", v.message);

        // And a member split across two lines is one member, not two broken
        // halves: joined with ", " these are `u=3, i`.
        assert!(check_req(&["u=3", "i"]).is_none());
    }

    /// A key that names nothing this rule knows is the extension mechanism.
    #[rstest]
    #[case("visible=?1")]
    #[case("u=3, visible")]
    #[case("mycorp-hint=\"a\"")]
    fn an_unregistered_key_is_not_a_finding(#[case] value: &str) {
        assert!(check_req(&[value]).is_none(), "for {value:?}");
    }

    #[test]
    fn a_non_ascii_byte_costs_the_whole_field() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        tx.request
            .headers
            .append("priority", HeaderValue::from_bytes(&[0xff])?);
        let v = crate::test_helpers::run_rule(
            &PriorityHeaderSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
        .expect("a non-ASCII byte fails § 4.2 step 1");
        assert!(v.message.contains("outside ASCII"), "{}", v.message);
        Ok(())
    }

    /// A well-formed multi-byte character passes a UTF-8 check and still fails
    /// § 4.2's step 1, which is the distinction the old message got wrong.
    #[test]
    fn a_valid_utf8_non_ascii_character_also_costs_the_field() {
        let v = check_req(&["u=\u{e9}"]).expect("a Structured Field is ASCII");
        assert!(v.message.contains("outside ASCII"), "{}", v.message);
    }

    #[test]
    fn the_response_side_is_checked_too() {
        assert!(check_resp("u=1").is_none());
        assert!(check_resp("U=1").is_some());
    }

    #[test]
    fn scope_is_both() {
        assert_eq!(PriorityHeaderSyntax.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, RuleMeta as _};
        let rule = PriorityHeaderSyntax;

        let mut saw_a_finding = false;
        for ex in rule.examples() {
            let mut lines = ex.snippet.lines();
            let start = lines.next().expect("an example has a start line");
            let pairs: Vec<(&str, &str)> = lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();

            let found = if start.starts_with("HTTP/") {
                let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
                tx.response.as_mut().unwrap().headers =
                    crate::test_helpers::make_headers_from_pairs(&pairs);
                crate::test_helpers::run_rule(
                    &rule,
                    &tx,
                    &crate::transaction_history::TransactionHistory::empty(),
                    &cfg(),
                )
            } else {
                let mut tx = crate::test_helpers::make_test_transaction();
                tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
                crate::test_helpers::run_rule(
                    &rule,
                    &tx,
                    &crate::transaction_history::TransactionHistory::empty(),
                    &cfg(),
                )
            };

            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule rejects its Compliant example {:?}: {found:?}",
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
        assert!(saw_a_finding, "the guard never produced a finding");
    }

    #[test]
    fn validate_accepts_a_well_formed_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert("priority_header_syntax".into(), toml::Value::Table(table));
        PriorityHeaderSyntax.prepare(&cfg)?;
        Ok(())
    }
}
