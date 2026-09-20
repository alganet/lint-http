// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::nel::{
    JFV_4, NEL_4_1, NEL_4_1_1, NEL_4_1_2, NEL_4_1_4, NEL_4_1_5, NEL_4_1_6, NEL_4_2, NEL_MALFORMED,
    NEL_MAX_AGE_MISSING, NEL_MEMBER_INVALID, NEL_REPORT_TO_MISSING,
};
use crate::violations::ViolationDef;

/// The `NEL` response field carries the network error logging policy an origin
/// registers for itself, and this rule reads it.
pub struct NelPolicyValid;

/// The four ways § 4.2 abandons the policy, and no more. Every one of them
/// leaves the origin with no network error logging registered at all, which is
/// what the entries say and what makes them one severity.
static DECLARED: &[&ViolationDef] = &[
    &NEL_MALFORMED,
    &NEL_MAX_AGE_MISSING,
    &NEL_REPORT_TO_MISSING,
    &NEL_MEMBER_INVALID,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const NEL_4_1_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "Network Error Logging",
    section: Some("4.1.3"),
    url: "https://www.w3.org/TR/network-error-logging/#the-include_subdomains-member",
    note: "The include_subdomains member — the one member with no parse error attached, which is why a non-boolean there is not a finding",
};
const RFC_9110_5_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
    note: "Why several field lines are one value here: HTTP-JFV § 4 combines them before parsing, which is this section's list rule",
};

/// What one member of the policy object turned out to be, where that is not
/// what its section requires.
///
/// A struct rather than a tuple because both halves reach the message and the
/// order of two `&str`s is exactly the kind of thing a later edit swaps.
struct MemberDefect {
    /// The member's name, as the sender wrote it and the specification prints
    /// it.
    member: &'static str,
    /// What the member's own section requires, in that section's words — the
    /// half of the sentence only this reading knows.
    requires: &'static str,
}

impl RuleMeta for NelPolicyValid {
    fn id(&self) -> &'static str {
        "nel_policy_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("NEL Policy Value")
    }

    fn description(&self) -> &'static str {
        "This rule reads the `NEL` response header — the network error logging policy an origin registers for itself — and reports the ways Network Error Logging §4.2 throws the whole policy away.\n\n**Every finding here costs the entire policy.** §4.2 is a sequence of *abort these steps*: one member of the wrong type and the user agent registers nothing, so the origin's error reporting is silently off and no report ever says so. That is the same harm `structured_field_malformed` states for a Structured Field a parse refuses, and the commonest real defect is the same one — JSON writes a string with DQUOTE, so a policy written `{'report_to':'default'}` is refused entire.\n\n**The syntax is not NEL's own.** §4.2 hands parsing to Section 4 of HTTP-JFV, which combines the field lines, wraps them in `[` and `]` and runs a JSON parser: the value is a *list* of objects, and a bare object — which is what every origin sends — is that list with one element.\n\n**Which element the user agent reads is a question the document answers twice**, and a finding here has to be true under both. §4.2's fourth step is \"let item be the first element of list\"; §4.1 says the user agent \"MUST process the first *valid* policy in the array and ignore any additional policies\". They disagree exactly where an early element is defective and a later one is not — §4.2 aborts, §4.1 registers the good one. So this rule is silent the moment any element reads clean, and reports the first element's defects otherwise. With the single element every real value carries, the two readings are the same reading.\n\n**`max_age: 0` is a withdrawal, not a defective policy.** §4.2 removes any cached policy for the origin at that point and skips every remaining step, so `report_to` — REQUIRED to register — is expressly optional beside it, as §4.1.1 says in its own words. A rule asking for it unconditionally would report the documented way to withdraw a policy.\n\n**`max_age` is read more strictly than a recipient reads it, on purpose.** §4.2 aborts only where the value \"is not a number\", which `1.5` is; §4.1.2 binds the *sender* to a non-negative integer, and the sender is who this catalogue reports.\n\n**Not reported:** `include_subdomains` with a value that is not a boolean. §4.1.3 says such a value simply does not enable the policy for subdomains — no step aborts and nothing is discarded, so it is not a finding however wrong it looks beside the others. Nor is a well-formed list of two policy objects, for the reason above."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            NEL_4_1,
            NEL_4_2,
            JFV_4,
            NEL_4_1_1,
            NEL_4_1_2,
            NEL_4_1_3,
            NEL_4_1_4,
            NEL_4_1_5,
            NEL_4_1_6,
            RFC_9110_5_3,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// The field is defined on a response and nothing defines it on a request,
    /// so the peer answerable for every finding is the server. The reader below
    /// is handed the response's headers and nothing else.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a policy that registers)"),
                snippet: "HTTP/1.1 200 OK\nNEL: {\"report_to\":\"default\",\"max_age\":2592000,\"include_subdomains\":true}",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(max_age 0 withdraws the policy, and needs no report_to)"),
                snippet: "HTTP/1.1 200 OK\nNEL: {\"max_age\":0}",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the sampling rates at both ends of their inclusive range)"),
                snippet: "HTTP/1.1 200 OK\nNEL: {\"report_to\":\"g\",\"max_age\":604800,\"success_fraction\":0.0,\"failure_fraction\":1.0}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(JSON writes a string with DQUOTE, so this policy is discarded whole)"),
                snippet: "HTTP/1.1 200 OK\nNEL: {'report_to':'default','max_age':604800}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no max_age, which §4.1.2 makes REQUIRED)"),
                snippet: "HTTP/1.1 200 OK\nNEL: {\"report_to\":\"default\"}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a lifetime that registers a policy, and no endpoint group to report to)"),
                snippet: "HTTP/1.1 200 OK\nNEL: {\"max_age\":3600}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a sampling rate outside 0.0 to 1.0)"),
                snippet: "HTTP/1.1 200 OK\nNEL: {\"report_to\":\"g\",\"max_age\":3600,\"success_fraction\":1.5}",
            },
        ]
    }
}

impl Rule for NelPolicyValid {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(resp) = tx.response.as_ref() else {
            return Vec::new();
        };

        // The header section, which is where § 4.2 reads the field from: the
        // policy is registered as the response is processed, and a trailer
        // arrives after that.
        //
        // The lines are joined with comma SP before anything parses them,
        // because that is HTTP-JFV § 4's own first step and § 5.3's list rule
        // is what makes it lawful. A rule reading only the first line would
        // measure half a JSON array.
        //
        // cite(draft-reschke-http-jfv-07 § 4): "combine all header field instances into a single field as per"
        // cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3).  For consistency, use comma SP."
        let mut lines: Vec<String> = Vec::new();
        for hv in resp.headers.get_all("nel").iter() {
            lines.push(crate::helpers::headers::field_line_as_written(hv).to_string());
        }
        if lines.is_empty() {
            return Vec::new();
        }
        let value = lines.join(", ");

        // § 4's other two steps, in its order: bracket the value, then run a
        // JSON parser over it. The brackets are not decoration — the field is a
        // list of objects, so a bare object is a one-element list and the comma
        // form is two. Parsing the value as an object directly would refuse
        // every well-formed multi-policy field.
        //
        // cite(draft-reschke-http-jfv-07 § 4): "run the resulting octet sequence through a JSON parser."
        let bracketed = format!("[{}]", value);
        let malformed = |why: &str| {
            vec![ctx.report_with(
                &NEL_MALFORMED,
                format!(
                    "NEL '{}' {}, so the user agent registers no network error logging for this \
                     origin at all and nothing downstream reports that it did not",
                    crate::helpers::shown::shown_in_finding(&value),
                    why
                ),
            )]
        };

        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&bracketed) else {
            return malformed("is not JSON once bracketed as a list of policy objects");
        };
        let Some(list) = parsed.as_array() else {
            // Unreachable through the caller above -- a value wrapped in `[` and
            // `]` that parses at all parses as an array -- and kept because the
            // shape of the algorithm is what this reading transcribes, and a
            // caller that ever bracketed differently would land here rather
            // than on an `unwrap`.
            return malformed("does not parse as a list of policy objects");
        };

        // cite(Network Error Logging § 4.2): "Let list be the result of executing the algorithm defined in Section 4 of [HTTP-JFV] on header. If that algorithm results in an error, or if list is empty, abort these steps."
        let Some(first) = list.first() else {
            return malformed("states no policy object");
        };

        // **The document names two different elements, and a finding has to be
        // true of both.** § 4.2's fourth step is "let item be the first element
        // of list"; § 4.1 says the user agent "MUST process the first *valid*
        // policy in the array and ignore any additional policies". Those
        // disagree exactly where an early element is defective and a later one
        // is not — § 4.2 aborts, § 4.1 registers the good one — so a rule
        // reading element 0 alone would report an origin whose policy a
        // conforming user agent has installed.
        //
        // So the array is silent the moment ANY element reads clean, and what
        // is reported otherwise is the first element's defects: that is the one
        // § 4.2 names, and with the single element every value in this corpus
        // carries the two readings are the same reading.
        //
        // cite(Network Error Logging § 4.2): "Let item be the first element of list."
        // cite(Network Error Logging § 4.1): "policy for the origin. The user agent MUST process the first valid"
        for element in list {
            if self.policy_findings(element, &value, ctx).is_empty() {
                return Vec::new();
            }
        }
        self.policy_findings(first, &value, ctx)
    }
}

impl NelPolicyValid {
    /// Read one element of the array as a NEL policy object, answering with
    /// every defect it holds.
    ///
    /// Follows § 4.2's steps in its order, and the order is load-bearing twice:
    /// `max_age` is asked before `report_to`, and the 0 that removes the policy
    /// sits between them.
    fn policy_findings(
        &self,
        element: &serde_json::Value,
        value: &str,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let malformed = |why: &str| {
            vec![ctx.report_with(
                &NEL_MALFORMED,
                format!(
                    "NEL '{}' {}, so the user agent registers no network error logging for this \
                     origin at all and nothing downstream reports that it did not",
                    crate::helpers::shown::shown_in_finding(value),
                    why
                ),
            )]
        };
        let Some(item) = element.as_object() else {
            return malformed("names something that is not a policy object");
        };

        let mut out: Vec<Violation> = Vec::new();
        // Answers with the finding rather than pushing it, so the pushes stay
        // where the steps are and `out` is borrowed once.
        let wrong = |d: MemberDefect, got: &serde_json::Value| {
            ctx.report_with(
                &NEL_MEMBER_INVALID,
                format!(
                    "NEL member '{}' is {}, and {}; the policy is discarded and this origin \
                     registers no network error logging",
                    d.member,
                    crate::helpers::shown::shown_in_finding(&got.to_string()),
                    d.requires
                ),
            )
        };

        // § 4.1.2's MUST, which is stricter than § 4.2's abort: the algorithm
        // asks only whether the value is a number, and the sentence binding the
        // sender asks for a non-negative integer. `serde_json`'s `as_u64`
        // answers exactly that -- it refuses a sign and a fraction alike -- so
        // the two ways to be a number and not a non-negative integer land here
        // together.
        //
        // cite(Network Error Logging § 4.2): "If item has no member named max_age, or that member's value is not a number, abort these steps."
        let max_age = match item.get("max_age") {
            None => {
                return vec![ctx.report_with(
                    &NEL_MAX_AGE_MISSING,
                    format!(
                        "NEL '{}' states no max_age, which § 4.1.2 makes REQUIRED, so the policy \
                         is discarded rather than given a default lifetime",
                        crate::helpers::shown::shown_in_finding(value)
                    ),
                )]
            }
            Some(v) => match v.as_u64() {
                Some(n) => Some(n),
                None => {
                    out.push(wrong(
                        MemberDefect {
                            member: "max_age",
                            requires: "§ 4.1.2 requires a non-negative integer number of seconds",
                        },
                        v,
                    ));
                    None
                }
            },
        };

        // The step between the two required members, and the reason
        // `nel_report_to_missing` is conditional: a policy being withdrawn
        // names no endpoint group because there is nothing left to report to.
        // § 4.1.1 writes the exception into the member's own definition.
        //
        // cite(Network Error Logging § 4.2): "If the value of item's max_age member is 0, then remove any NEL policy from the policy cache whose origin is"
        // cite(Network Error Logging § 4.1.1): "and OPTIONAL if the intent is to remove a previous registration – see"
        let removing = max_age == Some(0);

        match item.get("report_to") {
            None if !removing => out.push(ctx.report_with(
                &NEL_REPORT_TO_MISSING,
                format!(
                    "NEL '{}' registers a policy and names no report_to endpoint group, which \
                     § 4.1.1 makes REQUIRED to register one; a max_age of 0 would be the way to \
                     withdraw a policy without naming one",
                    crate::helpers::shown::shown_in_finding(value)
                ),
            )),
            None => {}
            Some(v) if !v.is_string() => out.push(wrong(
                MemberDefect {
                    member: "report_to",
                    requires: "§ 4.1.1 requires a string naming an endpoint group",
                },
                v,
            )),
            Some(_) => {}
        }

        // The two sampling rates, whose interval is closed at both ends: an
        // exclusive comparison here would report the `success_fraction` of 0.0
        // that real origins send, and treating 0.0 as absent would do the same.
        //
        // cite(Network Error Logging § 4.1.4): "its value MUST be a number between 0.0 and"
        // cite(Network Error Logging § 4.1.5): "value MUST be a number between 0.0 and 1.0,"
        for member in ["success_fraction", "failure_fraction"] {
            let Some(v) = item.get(member) else { continue };
            let ok = v.as_f64().is_some_and(|f| (0.0..=1.0).contains(&f));
            if !ok {
                let requires = match member {
                    "success_fraction" => {
                        "§ 4.1.4 requires a number between 0.0 and 1.0, inclusive"
                    }
                    _ => "§ 4.1.5 requires a number between 0.0 and 1.0, inclusive",
                };
                out.push(wrong(MemberDefect { member, requires }, v));
            }
        }

        // The two header-name lists. Both halves of the sentence are checked --
        // that the value is a list, and that every element of it is a string --
        // because § 4.2 aborts on either, and a rule asking only the first
        // would accept a list of numbers as a list of header names.
        //
        // cite(Network Error Logging § 4.2): "If item has a member named request_headers, whose value is not a list, or if any element of that list is not a string, abort these steps."
        // cite(Network Error Logging § 4.1.7): "about this origin. If present, its value MUST be a list of"
        for member in ["request_headers", "response_headers"] {
            let Some(v) = item.get(member) else { continue };
            let ok = v
                .as_array()
                .is_some_and(|a| a.iter().all(serde_json::Value::is_string));
            if !ok {
                let requires = match member {
                    "request_headers" => {
                        "§ 4.1.6 requires a list of strings naming request header fields"
                    }
                    _ => "§ 4.1.7 requires a list of strings naming response header fields",
                };
                out.push(wrong(MemberDefect { member, requires }, v));
            }
        }

        // `include_subdomains` is deliberately unread, and the sentence is the
        // reason rather than an oversight: a value that is not `true` does not
        // enable the policy for subdomains, and no step of § 4.2 aborts on it.
        // Nothing is discarded, so there is nothing to report.
        //
        // cite(Network Error Logging § 4.1.3): "include_subdomains is present in the object, or its value"
        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &NelPolicyValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn findings_for(lines: &[&str]) -> Vec<Violation> {
        let headers: Vec<(&str, &str)> = lines.iter().map(|v| ("nel", *v)).collect();
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &headers);
        let rule = NelPolicyValid;
        crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    fn ids(lines: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = findings_for(lines)
            .iter()
            .map(|f| f.violation.clone())
            .collect();
        v.sort();
        v
    }

    /// The shape the counted web writes wrong: JSON has one string delimiter
    /// and it is not the apostrophe.
    #[test]
    fn an_apostrophe_is_not_a_json_string_delimiter() {
        assert_eq!(
            ids(&["{'report_to':'default','max_age': 604800,'include_subdomains':true}"]),
            vec!["nel_malformed"]
        );
    }

    /// The conforming shapes, and each is a way a reader written the obvious
    /// way goes wrong. The list of two is legal because § 4 brackets the value;
    /// the fractions sit on the ends of a *closed* interval; `include_subdomains`
    /// has no parse error attached at all.
    #[rstest]
    #[case(r#"{"report_to":"default","max_age":2592000,"include_subdomains":true}"#)]
    #[case(r#"{"max_age":0}"#)]
    #[case(r#"{"report_to":"g","max_age":604800,"success_fraction":0.0,"failure_fraction":1.0}"#)]
    #[case(r#"{"report_to":"a","max_age":3600}, {"report_to":"b","max_age":7200}"#)]
    #[case(r#"{"report_to":"d","max_age":3600,"include_subdomains":"yes"}"#)]
    #[case(r#"{"report_to":"heroku-nel","response_headers":["Via"],"max_age":3600}"#)]
    fn a_conforming_policy_draws_nothing(#[case] value: &str) {
        assert!(
            ids(&[value]).is_empty(),
            "`{}` is a policy § 4.2 registers, and drew {:?}",
            value,
            ids(&[value])
        );
    }

    /// `max_age: 0` removes the policy and skips the remaining steps, so the
    /// member § 4.1.1 calls REQUIRED is not required beside it. Without this
    /// the rule reports the documented way to withdraw a policy.
    #[test]
    fn a_withdrawal_needs_no_endpoint_group() {
        assert!(ids(&[r#"{"max_age":0}"#]).is_empty());
        assert_eq!(
            ids(&[r#"{"max_age":3600}"#]),
            vec!["nel_report_to_missing"],
            "a lifetime that is not 0 registers a policy, and that does need one"
        );
    }

    /// The two REQUIRED members, absent. `_missing` is absence and nothing
    /// else.
    #[test]
    fn a_required_member_that_is_absent_is_a_missing_finding() {
        assert_eq!(
            ids(&[r#"{"report_to":"default"}"#]),
            vec!["nel_max_age_missing"]
        );
        assert_eq!(ids(&[r#"{"max_age":3600}"#]), vec!["nel_report_to_missing"]);
    }

    /// Present and wrong is the other entry, never the `_missing` one: a
    /// `_missing` id firing on any of these would name a member the sender did
    /// write.
    #[rstest]
    #[case(r#"{"report_to":"d","max_age":-1}"#)]
    #[case(r#"{"report_to":"d","max_age":1.5}"#)]
    #[case(r#"{"report_to":"d","max_age":"3600"}"#)]
    #[case(r#"{"report_to":7,"max_age":3600}"#)]
    #[case(r#"{"report_to":"d","max_age":3600,"success_fraction":1.5}"#)]
    #[case(r#"{"report_to":"d","max_age":3600,"success_fraction":-0.1}"#)]
    #[case(r#"{"report_to":"d","max_age":3600,"failure_fraction":"0.5"}"#)]
    #[case(r#"{"report_to":"d","max_age":3600,"request_headers":["Via",7]}"#)]
    #[case(r#"{"report_to":"d","max_age":3600,"response_headers":"Via"}"#)]
    fn a_member_present_and_wrong_is_the_member_entry(#[case] value: &str) {
        assert_eq!(
            ids(&[value]),
            vec!["nel_member_invalid"],
            "`{}` writes a member and gets its value wrong",
            value
        );
    }

    /// § 4.1.2 binds the sender to a non-negative integer where § 4.2 asks only
    /// for a number, and the two disagree on exactly these values. Reading the
    /// recipient's condition instead would accept both.
    #[rstest]
    #[case(r#"{"report_to":"d","max_age":-1}"#)]
    #[case(r#"{"report_to":"d","max_age":1.5}"#)]
    fn a_max_age_that_is_a_number_and_not_an_integer_is_still_wrong(#[case] value: &str) {
        assert_eq!(ids(&[value]), vec!["nel_member_invalid"]);
    }

    /// A value that is not JSON at all, one that is JSON and not an object, and
    /// one that states no object — all of them are the whole policy gone.
    #[rstest]
    #[case("")]
    #[case("not json")]
    #[case(r#""a string""#)]
    #[case("{")]
    fn a_value_that_yields_no_policy_object_is_malformed(#[case] value: &str) {
        assert_eq!(
            ids(&[value]),
            vec!["nel_malformed"],
            "`{}` yields no policy object",
            value
        );
    }

    /// § 4 combines the field lines before parsing, so two lines are one JSON
    /// array. Reading the first line alone would refuse this well-formed value.
    #[test]
    fn two_field_lines_are_combined_before_parsing() {
        assert!(ids(&[
            r#"{"report_to":"a","max_age":3600}"#,
            r#"{"report_to":"b","max_age":7200}"#
        ])
        .is_empty());
    }

    /// The two readings of "which element", and the value that tells them
    /// apart. § 4.2 takes element 0 and aborts; § 4.1 has the user agent
    /// process the first *valid* policy. A rule reading element 0 alone would
    /// report an origin whose policy a conforming user agent has installed.
    #[test]
    fn a_valid_policy_later_in_the_array_silences_the_defective_one_before_it() {
        assert!(
            ids(&[r#"{"max_age":"soon"}, {"report_to":"g","max_age":3600}"#]).is_empty(),
            "§ 4.1 installs the second policy, so nothing here is answerable"
        );
    }

    /// The other half of the same claim: where NO element reads clean, the
    /// array configures nothing under either reading, and what is reported is
    /// the first element's defects — the one § 4.2 names.
    ///
    /// Two of them, and both are true of it: a `max_age` that is not a
    /// non-negative integer is one edit, and the endpoint group it then needs
    /// (because a lifetime that is not 0 registers rather than withdraws) is
    /// another. The second element's absent `max_age` is not reported at all,
    /// which is the half this test is really pinning.
    #[test]
    fn an_array_whose_every_element_fails_is_reported_as_its_first() {
        assert_eq!(
            ids(&[r#"{"max_age":"soon"}, {"report_to":"g"}"#]),
            vec!["nel_member_invalid", "nel_report_to_missing"],
            "the first element's own defects, not the second's"
        );
    }

    /// A response with no `NEL` reaches none of this. The header is optional.
    #[test]
    fn an_absent_field_is_not_a_finding() {
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let rule = NelPolicyValid;
        assert!(crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_empty());
    }

    /// Every finding names the member or the value it is about, which is what
    /// makes it answerable.
    #[test]
    fn a_member_finding_names_the_member_and_what_it_should_be() {
        let v = findings_for(&[r#"{"report_to":"d","max_age":3600,"success_fraction":1.5}"#]);
        assert_eq!(v.len(), 1);
        assert!(
            v[0].message.contains("success_fraction"),
            "{}",
            v[0].message
        );
        assert!(v[0].message.contains("0.0 and 1.0"), "{}", v[0].message);
    }

    /// Two wrong members are two findings: they are two edits, and stopping at
    /// the first would state one and withhold the other.
    #[test]
    fn every_wrong_member_is_reported() {
        assert_eq!(
            ids(&[r#"{"report_to":7,"max_age":3600,"success_fraction":2}"#]),
            vec!["nel_member_invalid", "nel_member_invalid"]
        );
    }
}
