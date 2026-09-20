// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::list::{
    LIST_MEMBER_EMPTY, LIST_MEMBER_MISSING, RFC_9110_5_6_1_1, RFC_9110_5_6_1_2,
};
use crate::violations::referrer_policy::{
    REFERRER_POLICY_11_1, REFERRER_POLICY_4_1, REFERRER_POLICY_8_1, REFERRER_POLICY_INVALID,
};
use crate::violations::ViolationDef;

/// The `Referrer-Policy` response field names which parts of a URL travel in
/// the `Referer` of requests made from the resource it was served with, and
/// this rule reads it.
pub struct ReferrerPolicyValid;

/// `"Referrer-Policy:" 1#policy-token`, so the reading has exactly two halves:
/// the `1#` construct's, shared with every list-valued field in the tree, and
/// the closed alternation of eight literals, which is this field's own.
///
/// No token-alphabet entry among them, and that is the production's doing.
/// Every `policy-token` § 4.1 prints is lowercase ASCII letters and hyphens, so
/// an octet outside `token` cannot make a member *fail differently* — the
/// member is not one of the eight either way, and the field's own entry already
/// says so about the whole field. Adding the alphabet check would report a
/// second id for the same repair.
static DECLARED: &[&ViolationDef] = &[
    &REFERRER_POLICY_INVALID,
    &LIST_MEMBER_EMPTY,
    &LIST_MEMBER_MISSING,
];

/// Every `policy-token` § 4.1 prints, in the order it prints them.
///
/// The set is the grammar's and not the enum's: § 3 lists the same eight
/// *plus* the empty string, because a referrer policy is a value a `Document`
/// can hold and "" is how it holds none. § 4.1 is the header's alphabet, and
/// nothing a sender writes on this field line derives the empty string —
/// § 8.1's walk skips it explicitly. Reading the enum instead would make
/// `Referrer-Policy: ,` a field naming a policy.
///
// cite(Referrer Policy § 4.1, label: policy-token grammar): "policy-token = "no-referrer" / "no-referrer-when-downgrade" / "strict-origin" / "strict-origin-when-cross-origin" / "same-origin" / "origin" / "origin-when-cross-origin" / "unsafe-url""
// cite(Referrer Policy § 8.1): "For each token in policy-tokens, if token is a referrer"
const POLICY_TOKENS: [&str; 8] = [
    "no-referrer",
    "no-referrer-when-downgrade",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "same-origin",
    "origin",
    "origin-when-cross-origin",
    "unsafe-url",
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_5_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
    note: "Why several field lines are one list here rather than a duplication: the exception turns on the field being a comma-separated list, and `1#policy-token` is one",
};
const RFC_5234_2_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 5234",
    section: Some("2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc5234.html#section-2.3",
    note: "ABNF string literals are case-insensitive, which is why `NO-REFERRER` derives from `policy-token` where a Structured Field token would not",
};

impl RuleMeta for ReferrerPolicyValid {
    fn id(&self) -> &'static str {
        "referrer_policy_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Referrer-Policy Value")
    }

    fn description(&self) -> &'static str {
        "This rule reads the `Referrer-Policy` response header as the `1#policy-token` list Referrer Policy §4.1 defines it to be, and reports a field that names **no** referrer policy at all.\n\n**The finding is about the field, never about a member, and the specification is what decides that.** §8.1 walks the tokens, sets the policy to the last one it recognises and ignores every other, and §11.1 makes that the documented way to deploy a new policy value with a fallback for older user agents: `Referrer-Policy: origin, unsafe-url` is a pattern the document tells authors to write. So a token outside the eight is reported only when *every* token is, which is the one case where the grammar and the algorithm agree — the field derives from no `1#policy-token`, §8.1 returns the empty string, and §8.2 leaves the request's referrer policy exactly where the header had never been sent.\n\n**What that costs is the whole header.** A site that meant `no-referrer` and wrote `no-referer` still serves a well-formed field, and still leaks the full URL of every page to every cross-origin destination it links to. Nothing on the wire distinguishes it from a site that set no policy on purpose.\n\n**Case is not a defect.** §4.1 writes `policy-token` as bare ABNF string literals, and RFC 5234 §2.3 makes those case-insensitive, so `NO-REFERRER` derives from the production. This is the difference from the `Sec-Fetch-*` family, whose values are RFC 9651 structured-field tokens and fold no case.\n\n**Several field lines are one list**, as RFC 9110 §5.3's exception for comma-separated fields provides, so a response writing the field twice is not reported for repeating it — the lines are joined in order and read as the single list a recipient acts on. The header section only: §8.1 parses `Referrer-Policy` in the response's *header list*, and a trailer arrives after a user agent has already determined the policy for the requests this one governs.\n\n**The list construct's own two defects are reported under the ids every list-valued field uses**: a stray comma is `list_member_empty` and a field with no member at all is `list_member_missing`, the `1#` floor."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            REFERRER_POLICY_4_1,
            REFERRER_POLICY_8_1,
            REFERRER_POLICY_11_1,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_1_2,
            RFC_9110_5_3,
            RFC_5234_2_3,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// The field is defined on a response and nothing defines it on a request,
    /// so the peer answerable for every finding here is the server. The reader
    /// below is handed the response's headers and nothing else, which is what
    /// makes the presumption safe rather than a guess about a shared reader.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a policy the eight literals print)"),
                snippet: "HTTP/1.1 200 OK\nReferrer-Policy: strict-origin-when-cross-origin",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(§11.1's fallback idiom: an older user agent takes the first)"),
                snippet: "HTTP/1.1 200 OK\nReferrer-Policy: origin, unsafe-url",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(an ABNF string literal is case-insensitive)"),
                snippet: "HTTP/1.1 200 OK\nReferrer-Policy: NO-REFERRER",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(one letter short of a policy, and the header does nothing)"),
                snippet: "HTTP/1.1 200 OK\nReferrer-Policy: no-referer",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a stray comma is an element the sender must not generate)"),
                snippet: "HTTP/1.1 200 OK\nReferrer-Policy: no-referrer,,origin",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a `1#` list needs at least one non-empty element)"),
                snippet: "HTTP/1.1 200 OK\nReferrer-Policy: ",
            },
        ]
    }
}

impl Rule for ReferrerPolicyValid {
    /// A request carrying this field name is carrying something no document
    /// defines, and reading it here would report a server's grammar against a
    /// client. `field_name_unregistered` is where that belongs.
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

        // The header section and not the trailer, which is § 8.1's own scope:
        // it parses `Referrer-Policy` in the response's *header list*. A
        // trailer arrives after the content, by which time a user agent has
        // already determined the policy for the requests this response
        // governs, so a value there is not one any recipient acts on — and
        // reporting it would measure a field against an algorithm that never
        // reads it.
        //
        // cite(Referrer Policy § 8.1): "Given a Response response, the following steps return a referrer policy according to response’s `Referrer-Policy` header:"
        let mut lines: Vec<String> = Vec::new();
        for hv in resp.headers.get_all("referrer-policy").iter() {
            // `field_line_as_written` and `trim_ows`, for the reason
            // `accept_ranges_values_valid` gives: `str::trim` removes %xA0 and
            // %x85, which `OWS` does not, so a token ending in either would
            // lose it here and then be compared against the eight literals as
            // though the sender had not written it.
            //
            // cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
            lines.push(
                crate::helpers::headers::trim_ows(&crate::helpers::headers::field_line_as_written(
                    hv,
                ))
                .to_string(),
            );
        }
        if lines.is_empty() {
            return Vec::new();
        }

        // Comma SP, in the order the lines arrived, because that is the value a
        // recipient acts on: § 5.3's exception turns on whether the field is a
        // comma-separated list, and `1#policy-token` is one — so two lines here
        // are a single list to read and not a duplication to report.
        //
        // cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3).  For consistency, use comma SP."
        let value = lines.join(", ");

        let mut out: Vec<Violation> = Vec::new();

        // Split here rather than through `list_members`, which drops empty
        // elements: that is the reading § 8.1 requires of a *recipient* and the
        // wrong one for a rule measuring what the sender generated. By the time
        // that function answers, the element § 5.6.1.1 forbids is gone.
        //
        // The split stays naive for the reason `range-unit`'s does: every
        // `policy-token` is lowercase ASCII letters and hyphens, so this
        // production admits no DQUOTE at all and a quote-aware walk would make
        // the comma after one into data.
        //
        // cite(RFC 9110 § 5.6.1.1, label: 1#element expansion): "1#element => element *( OWS "," OWS element )"
        //
        // The empty element belongs to the field rather than to a member:
        // `a,,,b` is one hole to close however many commas ran together, and
        // the sentence names no element because there is no element to name.
        let mut saw_an_empty_element = false;
        let mut named_a_policy = false;
        let mut members = 0usize;
        for element in value.split(',') {
            let element = crate::helpers::headers::trim_ows(element);

            // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
            if element.is_empty() {
                saw_an_empty_element = true;
                continue;
            }
            members += 1;

            // `eq_ignore_ascii_case`, because § 4.1 writes the eight as bare
            // ABNF string literals and RFC 5234 § 2.3 makes those
            // case-insensitive. The `Sec-Fetch-*` family beside this one
            // compares byte for byte, and the difference is which document
            // wrote the value's type: a structured-field token folds no case.
            //
            // cite(RFC 5234 § 2.3): "ABNF strings are case insensitive and the character set for these strings is US-ASCII."
            if POLICY_TOKENS
                .iter()
                .any(|t| element.eq_ignore_ascii_case(t))
            {
                named_a_policy = true;
            }
        }

        // The `1` in `1#`, asked of the count § 5.6.1.2 says to take it from:
        // empty elements do not contribute, so `Referrer-Policy: ,` is a list
        // of none exactly as an empty field line is. Reading the floor off
        // `value.is_empty()` instead — which is what stood here — answered `,`
        // with the empty-element entry and then, because a walk that finds no
        // member finds none outside the eight either, with the field entry as
        // well: *every member of this field is not a policy* is vacuously true
        // of a field with no members, and it was the second sentence about one
        // repair.
        //
        // This is the branch order `warning_header_syntax` takes and
        // `accept_ranges_values_valid` does not; the catalogue records that the
        // two are both true of such a value rather than resolving it, and what
        // decides it here is that the floor's sentence is the one an operator
        // can act on — write a policy — while the comma is a detail of a value
        // that has nothing in it.
        //
        // cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
        // cite(RFC 9110 § 5.6.1.2): "In contrast, the following values would be invalid, since at least one non-empty element is required by the example-list production"
        if members == 0 {
            return vec![ctx.report_with(
                &LIST_MEMBER_MISSING,
                format!(
                    "Referrer-Policy is `1#policy-token` and names no policy; the response's \
                     field lines combine to '{}'",
                    crate::helpers::shown::shown_in_finding(&value)
                ),
            )];
        }

        if saw_an_empty_element {
            out.push(ctx.report_with(
                &LIST_MEMBER_EMPTY,
                format!(
                    "Referrer-Policy '{}' runs two commas together, and a sender must not \
                     generate an empty list element",
                    crate::helpers::shown::shown_in_finding(&value)
                ),
            ));
        }

        // The whole field, and only the whole field. A member outside the eight
        // beside one inside them is § 11.1's fallback idiom, which configures a
        // policy in every user agent: reporting it would name the pattern the
        // document tells authors to write. What is left is the field that names
        // nothing, where § 8.1 returns the empty string and § 8.2 declines to
        // set anything from it.
        //
        // cite(Referrer Policy § 11.1): "As described in §8.1 Parse a referrer policy from a Referrer-Policy header and in the meta referrer algorithm, unknown"
        // cite(Referrer Policy § 8.2): "If policy is not the empty string, then set request’s"
        if !named_a_policy {
            out.push(ctx.report_with(
                &REFERRER_POLICY_INVALID,
                format!(
                    "Referrer-Policy '{}' names no referrer policy: no member of it is one of \
                     the eight `policy-token` spellings, so a user agent sets no policy from \
                     this response and every request it makes carries whatever referrer it \
                     would have carried with no header at all",
                    crate::helpers::shown::shown_in_finding(&value)
                ),
            ));
        }

        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ReferrerPolicyValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn findings_for(lines: &[&str]) -> Vec<Violation> {
        let headers: Vec<(&str, &str)> = lines.iter().map(|v| ("referrer-policy", *v)).collect();
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &headers);
        let rule = ReferrerPolicyValid;
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

    /// Every one of the eight, spelled as § 4.1 prints it. A closed set is a
    /// claim about eight strings, and a typo in the array is a rule that
    /// reports the policy it was written to accept.
    #[rstest]
    #[case("no-referrer")]
    #[case("no-referrer-when-downgrade")]
    #[case("strict-origin")]
    #[case("strict-origin-when-cross-origin")]
    #[case("same-origin")]
    #[case("origin")]
    #[case("origin-when-cross-origin")]
    #[case("unsafe-url")]
    fn a_policy_token_is_accepted(#[case] value: &str) {
        assert!(
            ids(&[value]).is_empty(),
            "`{}` is one of § 4.1's eight and drew a finding",
            value
        );
    }

    /// The other direction, and the one the field is silent about today: a
    /// value that looks exactly like a policy and is not one.
    #[rstest]
    #[case("no-referer")]
    #[case("strict-origin-if-cross-origin")]
    #[case("none")]
    #[case("no_referrer")]
    fn a_field_naming_no_policy_is_reported(#[case] value: &str) {
        assert_eq!(
            ids(&[value]),
            vec!["referrer_policy_invalid"],
            "`{}` names no policy and must be reported as the field it is",
            value
        );
    }

    /// § 11.1's fallback idiom, which is the whole reason this rule judges the
    /// field rather than its members. Both members here are policies, and a
    /// per-member reading would still pass this — the row below is the one that
    /// holds the shape.
    #[test]
    fn the_documented_fallback_idiom_is_not_a_finding() {
        assert!(ids(&["origin, unsafe-url"]).is_empty());
    }

    /// The row that fails if the reading is ever moved off the field onto its
    /// members. `some-future-policy` derives from no `policy-token` this
    /// document prints, and the field beside it names one every user agent
    /// applies, so § 8.1 sets a policy and there is nothing to report.
    #[test]
    fn an_unknown_token_beside_a_known_one_is_silent() {
        assert!(ids(&["strict-origin-when-cross-origin, some-future-policy"]).is_empty());
        assert!(ids(&["some-future-policy, no-referrer"]).is_empty());
    }

    /// RFC 5234 § 2.3. The `Sec-Fetch-*` family compares byte for byte and this
    /// one must not, because the two documents wrote the value's type
    /// differently.
    #[rstest]
    #[case("NO-REFERRER")]
    #[case("Strict-Origin-When-Cross-Origin")]
    fn an_abnf_literal_is_case_insensitive(#[case] value: &str) {
        assert!(
            ids(&[value]).is_empty(),
            "`{}` derives from a case-insensitive string literal",
            value
        );
    }

    /// The `1#` floor and the empty element, and that they are two findings
    /// rather than one: the second value below breaks the list construct *and*
    /// names a policy, so only the list entry is true of it.
    #[test]
    fn the_list_construct_is_read_as_every_other_field_reads_it() {
        assert_eq!(ids(&[""]), vec!["list_member_missing"]);
        assert_eq!(ids(&["no-referrer,,origin"]), vec!["list_member_empty"]);
    }

    /// A value of nothing but commas is a list of none, because § 5.6.1.2 says
    /// empty elements do not contribute to the count — so the floor answers it
    /// alone.
    ///
    /// **This is the vacuous-truth guard and not a wording preference.** A walk
    /// that finds no member finds none outside the eight either, so
    /// *every member of this field is not a policy* is true of a field with no
    /// members, and the version of this rule that read the floor off
    /// `value.is_empty()` reported the field entry beside the comma on all
    /// three values below.
    #[rstest]
    #[case(",")]
    #[case(",,")]
    #[case(" , ")]
    #[case("")]
    fn a_value_with_no_member_is_answered_by_the_floor_alone(#[case] value: &str) {
        assert_eq!(
            ids(&[value]),
            vec!["list_member_missing"],
            "`{}` states no element, so the `1#` floor is the whole finding",
            value
        );
    }

    /// § 5.3's exception: the field is a comma-separated list, so two lines are
    /// one list and not a repetition. A rule reading only the first line would
    /// report the second value here, where the joined field names a policy.
    #[test]
    fn two_field_lines_are_one_list() {
        assert!(ids(&["origin", "unsafe-url"]).is_empty());
        assert_eq!(
            ids(&["no-referer", "also-not-a-policy"]),
            vec!["referrer_policy_invalid"]
        );
    }

    /// A response with no field at all reaches none of this. The header is
    /// optional and its absence is another rule's question if it is anyone's.
    #[test]
    fn an_absent_field_is_not_a_finding() {
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let rule = ReferrerPolicyValid;
        assert!(crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .is_empty());
    }

    /// The finding names the value it is about, which is what makes it
    /// answerable: an operator reading the sentence has to be able to find the
    /// line and see the spelling that is wrong.
    #[test]
    fn the_finding_names_the_value() {
        let v = findings_for(&["no-referer"]);
        assert_eq!(v.len(), 1);
        assert!(
            v[0].message.contains("no-referer"),
            "the message must carry the value: {}",
            v[0].message
        );
    }
}
