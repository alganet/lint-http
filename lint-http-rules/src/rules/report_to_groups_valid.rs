// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::nel::JFV_4;
use crate::violations::nel::NEL_4_1_1;
use crate::violations::report_to::{JFV_2, MDN_REPORT_TO, REPORT_TO_MALFORMED, REPORT_TO_OBSOLETE};
use crate::violations::ViolationDef;

/// The `Report-To` response field declares the named endpoint groups an origin
/// sends its reports to, and this rule reads it.
pub struct ReportToGroupsValid;

/// Two entries about one field: that it has been replaced, and that its value
/// does not parse. Both are about the field rather than about a member of it,
/// which is the whole depth of this reading — see the subject's module doc for
/// why there is no third.
static DECLARED: &[&ViolationDef] = &[&REPORT_TO_OBSOLETE, &REPORT_TO_MALFORMED];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_5_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
    note: "Why several field lines are one value here: HTTP-JFV § 4 combines them before parsing, which is this section's list rule",
};

impl RuleMeta for ReportToGroupsValid {
    fn id(&self) -> &'static str {
        "report_to_groups_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Report-To Endpoint Groups")
    }

    fn description(&self) -> &'static str {
        "This rule reads the `Report-To` response header — the named endpoint groups an origin declares as the destination for its CSP violation reports, network errors and deprecation reports — and reports two things about it.\n\n**No specification defines the field any more.** The W3C Reporting API once did; the document at that URL now defines `Reporting-Endpoints` and no longer contains the string `Report-To` at all. So there is no current specification to read the field against and no superseded one that says what replaced it, and MDN's page — which marks the field Deprecated and Non-standard and says in as many words that `Reporting-Endpoints` replaced it — is the document this rule cites. That is the footing `x_xss_protection_value_valid` already stands on: a field deployments send in quantity and no standards document defines.\n\n**The finding is a move, not a deletion — and the destination depends on what else the response carries.** The group names declared here are exactly the names a `Content-Security-Policy` `report-to` directive and a `NEL` policy's `report_to` member point at, so an origin that simply drops the field loses the reporting it still has. `Reporting-Endpoints` serves the first of those two: it declares *endpoints*, a name against a single URL, where this field declares *endpoint groups*, and a `NEL` policy sends its reports to an endpoint group. Network Error Logging names no field other than this one to declare a group in — the document does not contain the string `Reporting-Endpoints`, and its own worked example writes `Report-To` and `NEL` in the same response. So the message reads the response first: it names `Reporting-Endpoints` as where the `Content-Security-Policy` groups go, and where a `NEL` is beside the field it says the field stays.\n\n**The syntax is `NEL`'s syntax.** MDN writes the value as one or more endpoint-group definitions \"defined as a JSON array that omits the surrounding `[` and `]` markers\", which is HTTP-JFV §4: combine the field lines, add the brackets back, run a JSON parser. A value that does not survive that is `report_to_malformed`, and it costs the origin every group in the field rather than the malformed one — the array is one JSON document, so a parser that refuses it declares nothing.\n\n**Joining the lines is not a nicety.** A response declaring two groups commonly writes them on two field lines — major CDNs do — and a rule reading only the first line would report half a well-formed array as a broken one. The lines are joined before anything parses them, as HTTP-JFV §4's own first step requires and RFC 9110 §5.3 licenses.\n\n**The delimiter is what real origins get wrong, and they get it wrong twice.** JSON writes a string with DQUOTE, so `{'group':'default','max_age':3600}` is refused entire — and an origin whose templating wrote `Report-To` with apostrophes wrote its `NEL` the same way. `nel_malformed` reports that one. Both findings are needed for either to be actionable: repairing the policy alone leaves it naming a group that a still-unparseable `Report-To` never declared.\n\n**Members are not read.** MDN names `group`, `max_age` and `endpoints` and marks none of them required, and the draft that did state requirements is a snapshot the W3C has replaced. An entry claiming a member is REQUIRED would rest on no document in force, so the reading stops at the parse."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[MDN_REPORT_TO, NEL_4_1_1, JFV_2, JFV_4, RFC_9110_5_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// The field is defined on a response and nothing has ever defined it on a
    /// request, so the peer answerable for every finding is the server. The
    /// reader below is handed the response's headers and nothing else.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the field the groups move to)"),
                snippet: "HTTP/1.1 200 OK\nReporting-Endpoints: csp-endpoint=\"https://example.com/csp-reports\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a well-formed value, in a field that has been replaced)"),
                snippet: "HTTP/1.1 200 OK\nReport-To: {\"group\":\"csp-endpoint\",\"max_age\":10886400,\"endpoints\":[{\"url\":\"https://example.com/csp-reports\"}]}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(NEL beside it sends to an endpoint group, so the field stays)"),
                snippet: "HTTP/1.1 200 OK\nReport-To: {\"group\":\"network-errors\",\"max_age\":2592000,\"endpoints\":[{\"url\":\"https://example.com/upload-reports\"}]}\nNEL: {\"report_to\":\"network-errors\",\"max_age\":2592000}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(JSON writes a string with DQUOTE, so no group is declared at all)"),
                snippet: "HTTP/1.1 200 OK\nReport-To: {'group':'default','max_age':3600,'endpoints':[{'url':'https://example.com/reports'}]}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(two groups on two field lines are one array, and it parses)"),
                snippet: "HTTP/1.1 200 OK\nReport-To: {\"group\":\"a\",\"max_age\":3600,\"endpoints\":[{\"url\":\"https://example.com/a\"}]}\nReport-To: {\"group\":\"b\",\"max_age\":3600,\"endpoints\":[{\"url\":\"https://example.com/b\"}]}",
            },
        ]
    }
}

impl Rule for ReportToGroupsValid {
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

        // The header section. A reporting configuration is installed as the
        // response is processed and a trailer arrives after that, so a
        // `Report-To` written into a trailer declares nothing whenever it
        // arrives -- which is a different claim from this rule's, and not one
        // MDN's page states.
        //
        // The lines are joined before anything parses them, because that is
        // HTTP-JFV § 4's own first step and § 5.3's list rule is what makes it
        // lawful. An origin declaring two endpoint groups routinely writes one
        // per field line, and a rule reading only the first would measure half a
        // JSON array.
        //
        // cite(draft-reschke-http-jfv-07 § 4): "combine all header field instances into a single field as per"
        // cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3).  For consistency, use comma SP."
        let Some(value) =
            crate::helpers::headers::combined_field_value_as_written(&resp.headers, "report-to")
        else {
            return Vec::new();
        };

        let mut out: Vec<Violation> = Vec::new();

        // The field is here, and that is the whole of this entry's evidence.
        // It is reported before the value is parsed and whatever the parse
        // says: a value nobody can read is still declared in a field that has
        // been replaced, and an origin repairing the delimiter would otherwise
        // have to be told about the move on a second run.
        //
        // cite(MDN Report-To): "This header has been replaced by the"
        // cite(MDN Report-To): "It is a deprecated part of an earlier iteration of the"
        // Which destination the sentence may name is a question about this
        // response, not about the field. `Reporting-Endpoints` declares
        // endpoints -- a name against one URL -- and a `NEL` policy sends its
        // reports to an endpoint *group*, which only this field declares. So a
        // `NEL` beside the field makes "move the groups and drop this" the one
        // repair that would leave the sender worse off than it is, and the
        // reading that decides it is the presence of the field, which is all
        // this seam can see.
        //
        // cite(Network Error Logging § 4.1.1): "The report_to member specifies the endpoint group that reports for this NEL policy will be sent to."
        let nel_beside_it = resp.headers.contains_key("nel");
        out.push(ctx.report_with(
            &REPORT_TO_OBSOLETE,
            if nel_beside_it {
                format!(
                    "Report-To '{}' declares this origin's endpoint groups in a field that has \
                     been replaced by Reporting-Endpoints; a Content-Security-Policy report-to \
                     directive's groups move to that field, but the NEL beside it sends its \
                     reports to an endpoint group and Network Error Logging names no field other \
                     than this one to declare a group in, so dropping this field would leave that \
                     policy pointing at nothing",
                    crate::helpers::shown::shown_in_finding(&value)
                )
            } else {
                format!(
                    "Report-To '{}' declares this origin's endpoint groups in a field that has \
                     been replaced by Reporting-Endpoints; the group names are what a Content-\
                     Security-Policy report-to directive points at, so they move to that field \
                     rather than being dropped",
                    crate::helpers::shown::shown_in_finding(&value)
                )
            },
        ));

        // § 4's other two steps, in its order: bracket the value, then run a
        // JSON parser over it. The brackets are not decoration -- MDN writes
        // the value as a JSON array with them omitted, so a bare object is a
        // one-element array and the comma form is two. Parsing the value as an
        // object directly would refuse every well-formed multi-group field,
        // which is a shape deployed CDNs write.
        //
        // cite(MDN Report-To): "One or more endpoint-group definitions, defined as a JSON array that omits the surrounding"
        // cite(draft-reschke-http-jfv-07 § 4): "run the resulting octet sequence through a JSON parser."
        let malformed = |why: &str| {
            ctx.report_with(
                &REPORT_TO_MALFORMED,
                format!(
                    "Report-To '{}' {}, so this origin declares no endpoint group at all and every \
                     Content-Security-Policy report-to directive and NEL report_to member naming \
                     one of its groups points at a name nothing defines",
                    crate::helpers::shown::shown_in_finding(&value),
                    why
                ),
            )
        };

        let bracketed = format!("[{}]", value);
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&bracketed) else {
            out.push(malformed(
                "is not JSON once bracketed as an array of endpoint-group objects",
            ));
            return out;
        };
        let Some(list) = parsed.as_array() else {
            // Unreachable through the caller above -- a value wrapped in `[`
            // and `]` that parses at all parses as an array -- and kept
            // because the shape of the algorithm is what this reading
            // transcribes, and a caller that ever bracketed differently would
            // land here rather than on an `unwrap`.
            out.push(malformed(
                "does not parse as an array of endpoint-group objects",
            ));
            return out;
        };

        // An empty array declares nothing, and it is reachable from a value a
        // sender can write: a field line carrying only OWS brackets to `[ ]`.
        // The parse succeeded and the origin still has no group.
        if list.is_empty() {
            out.push(malformed("declares no endpoint-group object"));
            return out;
        }

        // An element that is not an object is not an endpoint-group
        // definition. Reported as the parse defect it is rather than as a
        // member defect, because there is no member: nothing in the array
        // element names a group, a lifetime or a URL.
        if list.iter().any(|element| !element.is_object()) {
            out.push(malformed(
                "names something in its array that is not an endpoint-group object",
            ));
        }

        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ReportToGroupsValid;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    /// Run the rule over a response carrying the given `Report-To` field lines
    /// and answer with the ids it drew, in order.
    ///
    /// Takes a slice rather than one value because the join is half of what
    /// this rule does: a test that could only ever pass one line could not
    /// tell a reader of the combined value from a reader of the first.
    fn ids_for(lines: &[&str]) -> Vec<String> {
        let headers: Vec<(&str, &str)> = lines.iter().map(|v| ("report-to", *v)).collect();
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &headers);
        let rule = ReportToGroupsValid;
        crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .iter()
        .map(|f| f.violation.clone())
        .collect()
    }

    /// A response with no `Report-To` is not a response with an empty one: the
    /// rule reads nothing and says nothing.
    #[test]
    fn a_response_without_the_field_draws_nothing() {
        assert!(ids_for(&[]).is_empty());
    }

    /// The `report_to_obsolete` sentence for one `Report-To` line, with or
    /// without a `NEL` in the same header section.
    fn obsolete_message(value: &str, nel: Option<&str>) -> String {
        let mut headers: Vec<(&str, &str)> = vec![("report-to", value)];
        if let Some(nel) = nel {
            headers.push(("nel", nel));
        }
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &headers);
        let rule = ReportToGroupsValid;
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let said: Vec<&crate::lint::Violation> = found
            .iter()
            .filter(|f| f.violation == "report_to_obsolete")
            .collect();
        assert_eq!(said.len(), 1, "one field, one finding: {found:?}");
        said[0].message.clone()
    }

    /// **The repair the sentence names is not the same repair for both of the
    /// fields that point here, and this is the pair that holds it.**
    ///
    /// `Reporting-Endpoints` declares endpoints; a `NEL` policy sends its
    /// reports to an endpoint *group*, which no field but `Report-To`
    /// declares. So the sentence an origin reads has to depend on whether a
    /// `NEL` is beside the field: told to move the groups and drop this, an
    /// origin sending `NEL` would be left with a policy pointing at nothing.
    ///
    /// Both directions, because a branch tested one way is a branch that
    /// cannot be seen to branch.
    #[test]
    fn the_destination_the_sentence_names_depends_on_a_nel_beside_the_field() {
        let value = r#"{"group":"network-errors","max_age":2592000,"endpoints":[{"url":"https://e.example/r"}]}"#;

        let alone = obsolete_message(value, None);
        assert!(alone.contains("move to that field"), "{alone}");
        assert!(
            !alone.contains("NEL"),
            "no NEL here, so the sentence may not reason about one: {alone}"
        );

        let beside = obsolete_message(
            value,
            r#"{"report_to":"network-errors","max_age":2592000}"#.into(),
        );
        assert!(
            beside.contains("endpoint group") && beside.contains("NEL"),
            "{beside}"
        );
        assert!(
            !beside.contains("move to that field rather than being dropped"),
            "the field stays when a NEL is beside it: {beside}"
        );
        assert_ne!(alone, beside);
    }

    /// The field being present is the whole of `report_to_obsolete`'s
    /// evidence, so a value nothing is wrong with still draws it — and draws
    /// only it.
    #[rstest]
    #[case::one_group(&[r#"{"group":"csp","max_age":10886400,"endpoints":[{"url":"https://e.example/r"}]}"#])]
    #[case::no_group_member_defaults(&[r#"{"max_age":3600,"endpoints":[{"url":"https://e.example/r"}]}"#])]
    #[case::two_groups_one_line(&[
        r#"{"group":"a","max_age":3600,"endpoints":[{"url":"https://e.example/a"}]}, {"group":"b","max_age":3600,"endpoints":[{"url":"https://e.example/b"}]}"#
    ])]
    fn a_well_formed_value_draws_the_replacement_and_nothing_else(#[case] lines: &[&str]) {
        assert_eq!(ids_for(lines), vec!["report_to_obsolete".to_string()]);
    }

    /// **The join, tested as the behaviour it is.** A CDN declaring two groups
    /// writes one per field line; each line parses alone and so does the pair,
    /// so a reader of the first line looks correct here — what this pins is
    /// that the whole value is one array and neither line is dropped, which
    /// the malformed-second-line case below is what actually discriminates.
    #[test]
    fn two_groups_on_two_lines_are_one_well_formed_array() {
        let ids = ids_for(&[
            r#"{"group":"a","max_age":3600,"endpoints":[{"url":"https://e.example/a"}]}"#,
            r#"{"group":"b","max_age":3600,"endpoints":[{"url":"https://e.example/b"}]}"#,
        ]);
        assert_eq!(ids, vec!["report_to_obsolete".to_string()]);
    }

    /// A defect on the *second* line is what a reader of the first cannot see.
    /// This is the test that fails for a rule that does not join.
    #[test]
    fn a_second_line_that_does_not_parse_is_reached() {
        let ids = ids_for(&[
            r#"{"group":"a","max_age":3600,"endpoints":[{"url":"https://e.example/a"}]}"#,
            r#"{'group':'b'}"#,
        ]);
        assert_eq!(
            ids,
            vec![
                "report_to_obsolete".to_string(),
                "report_to_malformed".to_string()
            ]
        );
    }

    /// The delimiter mistake a real origin makes, and the three other ways the
    /// value declares no group. Each draws the replacement entry too, because
    /// the field is still the field.
    #[rstest]
    #[case::apostrophes_for_dquote(
        r#"{'group':'default','max_age':3600,'endpoints':[{'url':'https://e.example/r'}]}"#
    )]
    #[case::trailing_comma_leaves_an_empty_element(
        r#"{"group":"a","max_age":3600,"endpoints":[{"url":"https://e.example/a"}]},"#
    )]
    #[case::not_an_object(r#""default""#)]
    #[case::unterminated(r#"{"group":"a""#)]
    fn a_value_that_declares_no_group_draws_both(#[case] value: &str) {
        assert_eq!(
            ids_for(&[value]),
            vec![
                "report_to_obsolete".to_string(),
                "report_to_malformed".to_string()
            ]
        );
    }

    /// A field line carrying only whitespace brackets to an empty array: the
    /// parse succeeds and the origin has declared nothing, which is the entry's
    /// own claim and not a JSON error.
    #[test]
    fn a_blank_value_parses_and_still_declares_no_group() {
        let ids = ids_for(&[" "]);
        assert_eq!(
            ids,
            vec![
                "report_to_obsolete".to_string(),
                "report_to_malformed".to_string()
            ]
        );
    }

    /// Every entry this rule can report is one it declares. The engine has no
    /// second list, so a report site reaching for a def the rule does not name
    /// is a defect only an assertion like this one catches.
    #[test]
    fn the_declared_list_holds_both_entries() {
        let declared: Vec<&str> = ReportToGroupsValid
            .violations()
            .iter()
            .map(|d| d.id)
            .collect();
        assert_eq!(declared, vec!["report_to_obsolete", "report_to_malformed"]);
    }
}
