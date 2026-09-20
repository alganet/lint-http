// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::combined_field_value_as_written;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::p3p::{P3P_2_2_2, P3P_OBSOLETE, P3P_STATUS};
use crate::violations::ViolationDef;

/// One entry, and it claims no prohibition: the specification that defines the
/// field is itself marked obsolete, which is a status and not a requirement.
static DECLARED: &[&ViolationDef] = &[&P3P_OBSOLETE];

/// The `P3P` response field advertises a compact privacy policy to a user agent
/// that would gate third-party cookies on it. There is no such user agent left,
/// and this rule reads the field's presence.
pub struct P3pFieldObsolete;

impl RuleMeta for P3pFieldObsolete {
    fn id(&self) -> &'static str {
        "p3p_field_obsolete"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
# The evidence is a document status rather than a keyword addressed to a
# sender, so the finding is advice and the severity says so. The comment sits
# *below* the line it explains: the generated file runs these sections
# together, and a comment above a key reads as introducing everything under it.
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("P3P Field Obsolete")
    }

    fn description(&self) -> &'static str {
        "Reports a response carrying a `P3P` header field.\n\n**The field's own specification is the evidence, which is unusual for an `_obsolete` finding.** The Platform for Privacy Preferences 1.0 became a W3C Recommendation in April 2002 and was obsoleted on 30 August 2018; the document at that URL is the obsoletion notice, and its Status section says the specification \"is obsolete and should no longer be used as a basis for implementation\". Compare `report_to_groups_valid`, where the W3C removed the field from the Reporting API and left no sentence behind, so the fact had to be cited to MDN; and `x_xss_protection_value_valid`, where no standards body ever defined the field at all. Here the document being cited is the one that defined the header.\n\n**What the field bought, and why nothing reads it now.** §2.2.2 defines the header as where a site points at its policy reference file and, through the `compact-policy-field`, states a performance-optimised summary of its privacy practices so a user agent need not fetch the full policy. Exactly one user agent ever acted on it: Internet Explorer used the presence of a compact policy as a broad gate on whether to accept third-party cookies. That is why the field was deployed at the scale it was, and it is why nothing reads it today.\n\n**The value is deliberately not graded, and W3C's own account of the failure is the reason.** The Status section explains that when Internet Explorer made a compact policy the gate, \"web site administrators chose to copy general policies rather than encode specific policies that reflected their sites' own privacy practices\", and that no enforcement followed where a policy misdescribed a site. So a compact policy on the wire is evidence about a template somebody copied rather than about the site sending it, and measuring one against §4's compact vocabulary would report the template's author. The value is printed in the finding rather than parsed.\n\n**The repair is a deletion, and that is not true of every retired field.** `Report-To`'s group names are pointed at by a `Content-Security-Policy` `report-to` directive and by a `NEL` policy, so dropping it breaks reporting that still works; a compact policy is named by nothing else in the message, so there is nothing to move first.\n\n**Advice, not a violation.** Nothing prohibits sending the field, no recipient behaves differently, and the message is well-formed. What the finding tells an operator is that a header on every response is buying the cookie acceptance it was configured for from a browser that no longer exists.\n\nScope: this rule reads a response's header section. Several field lines are read as one value (RFC 9110 §5.2), and a value carrying an octet outside US-ASCII is measured rather than skipped — reading it back through a UTF-8 decoder would turn a field the sender wrote into a response that has none."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[P3P_STATUS, P3P_2_2_2]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **The server, and the field's definition names the direction.** § 2.2.2
    /// defines `P3P` as a response header a *site* sends to describe its own
    /// privacy practices; no document has ever defined it on a request, and a
    /// compact policy is a statement only the origin can make. So the peer
    /// answerable for every finding of this rule is the one that answered, and
    /// the reader below is handed the response's headers and nothing else.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(no compact policy, and nothing asks for one)"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/html",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a compact policy, in a specification obsoleted in 2018)"),
                snippet: "HTTP/1.1 200 OK\nP3P: CP=\"NOI DSP COR ADMa DEVa OUR IND\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the policy reference half is as unread as the compact one)"),
                snippet: "HTTP/1.1 200 OK\nP3P: policyref=\"/w3c/p3p.xml\", CP=\"NOI DSP ADM DEV\"",
            },
        ]
    }
}

impl Rule for P3pFieldObsolete {
    fn needs_response(&self) -> bool {
        true
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
            let resp = tx.response.as_ref()?;

            // The header section. A compact policy was read to decide whether
            // to accept a cookie the same response was setting, so it had to
            // arrive before the content did; a `P3P` written into a trailer
            // could never have gated anything, and that is a different claim
            // from this one rather than a quieter version of it.
            //
            // Several lines are read as one value because § 5.2 says what a
            // repeated field name recombines into. The field's value is a list
            // of directives, so a site writing its `policyref` and its `CP` on
            // two lines has written one value, and reading only the first would
            // report half of it.
            //
            // cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
            let value = combined_field_value_as_written(&resp.headers, "p3p")?;

            // Presence is the whole of the evidence, and the value is printed
            // rather than measured. § 4's compact vocabulary would grade it,
            // but the Status section says what those values are: general
            // policies copied rather than practices encoded, with no
            // enforcement where the two diverged. A finding about the tokens
            // would be a finding about whoever wrote the template.
            //
            // cite(P3P): "This specification is obsolete and should no longer be used as a basis for implementation."
            // cite(P3P): "web site administrators chose to copy general policies rather than encode specific policies that reflected their sites' own privacy practices"
            Some(ctx.report_with(
                &P3P_OBSOLETE,
                format!(
                    "Response carries a P3P header field: '{}'. The Platform for Privacy \
                     Preferences 1.0 was obsoleted by W3C on 30 August 2018 and should no longer \
                     be used as a basis for implementation, and the one user agent that acted on a \
                     compact policy — Internet Explorer, which gated third-party cookies on its \
                     presence — is gone, so nothing reads this field. Nothing else in the message \
                     names the policy, so the repair is to delete the line",
                    crate::helpers::shown::shown_in_finding(&value)
                ),
            ))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &P3pFieldObsolete;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const RULE: P3pFieldObsolete = P3pFieldObsolete;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&["p3p_field_obsolete"])
    }

    /// Every finding, not the first: the reading returns at most one, and
    /// `run_rule` would hide a second if it ever grew one.
    fn response(headers: &[(&str, &str)]) -> Vec<Violation> {
        let tx = crate::test_helpers::make_test_transaction_with_response(200, headers);
        crate::test_helpers::run_rule_all(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
    }

    /// Both halves of the field and neither of them: the compact policy, the
    /// policy reference, and a response that carries no `P3P` at all.
    #[rstest]
    #[case::compact_policy(&[("p3p", "CP=\"NOI DSP COR\"")], true)]
    #[case::policy_reference(&[("p3p", "policyref=\"/w3c/p3p.xml\"")], true)]
    #[case::both(&[("p3p", "policyref=\"/w3c/p3p.xml\", CP=\"NOI DSP\"")], true)]
    #[case::absent(&[("content-type", "text/html")], false)]
    fn presence_is_the_whole_reading(#[case] headers: &[(&str, &str)], #[case] fires: bool) {
        let out = response(headers);
        assert_eq!(out.len(), usize::from(fires), "{headers:?}");
        if fires {
            assert_eq!(out[0].violation, "p3p_obsolete");
        }
    }

    /// **A value the specification's own Status section describes.** Google
    /// sends a compact policy whose text is a sentence saying it is not a
    /// policy, which is the copied-general-policy behaviour W3C names — and it
    /// must draw the same one finding as a well-formed one, because this entry
    /// grades the field and not the tokens.
    #[test]
    fn a_value_that_is_not_a_policy_draws_the_same_one_finding() {
        let out = response(&[(
            "p3p",
            "CP=\"This is not a P3P policy! See g.co/p3phelp for more info.\"",
        )]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].violation, "p3p_obsolete");
    }

    /// The two field lines a site writes its `policyref` and its `CP` on are
    /// one value, and the finding shows both. Reading only the first line would
    /// print half of what the response said.
    #[test]
    fn the_finding_shows_every_field_line() {
        let out = response(&[
            ("p3p", "policyref=\"/w3c/p3p.xml\""),
            ("p3p", "CP=\"NOI DSP ADM DEV\""),
        ]);
        assert_eq!(out.len(), 1, "one field, however many lines carry it");
        assert!(out[0].message.contains("policyref"), "{}", out[0].message);
        assert!(out[0].message.contains("NOI DSP"), "{}", out[0].message);
    }

    /// A value carrying an octet `to_str` refuses is still a `P3P` field, and
    /// the finding is about the field. Measured rather than skipped: a decoder
    /// that refuses the value would turn a header the sender wrote into a
    /// response that has none.
    #[test]
    fn an_unreadable_octet_does_not_stand_the_reading_down() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let resp = tx.response.as_mut().expect("the response just built");
        resp.headers.append(
            hyper::header::HeaderName::from_static("p3p"),
            hyper::header::HeaderValue::from_bytes(b"CP=\"caf\xe9\"").expect("a test value"),
        );
        let out = crate::test_helpers::run_rule_all(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].violation, "p3p_obsolete");
    }
}
