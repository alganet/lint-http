// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::combined_field_value_as_written;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::expect_ct::{EXPECT_CT_OBSOLETE, MDN_EXPECT_CT, RFC_9163_1};
use crate::violations::ViolationDef;

/// One entry, and it claims no prohibition: RFC 9163 is in force and permits
/// the field. What withdrew it was the only implementation of it.
static DECLARED: &[&ViolationDef] = &[&EXPECT_CT_OBSOLETE];

/// The `Expect-CT` response field opts a site in to Certificate Transparency
/// reporting or enforcement, in a browser that no longer reads it. This rule
/// reads the field's presence.
pub struct ExpectCtFieldObsolete;

impl RuleMeta for ExpectCtFieldObsolete {
    fn id(&self) -> &'static str {
        "expect_ct_field_obsolete"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
# The evidence is what implementations did rather than a keyword addressed to a
# sender, so the finding is advice and the severity says so. The comment sits
# *below* the line it explains: the generated file runs these sections
# together, and a comment above a key reads as introducing everything under it.
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Expect-CT Field Obsolete")
    }

    fn description(&self) -> &'static str {
        "Reports a response carrying an `Expect-CT` header field.\n\n**A live specification and a dead field, which is a third footing and not either of the two this catalogue already had.** RFC 9163 defines `Expect-CT` and nothing has superseded it, so unlike `Report-To` there is a current document to read the field against; and unlike `X-XSS-Protection` a standards body did write it down. What withdrew the field was its only implementation. Chromium — the sole engine that ever implemented `Expect-CT` — removed the header in version 107 \"because Chromium now enforces CT by default\", so the opt-in the field expresses is both unread and redundant. That is a fact about deployment, which an RFC does not revise itself to record, so the sentence cited for it is MDN's. IANA's HTTP Field Name Registry agrees, and lists the name `deprecated`.\n\n**Why the field is pointless and not merely quiet.** It asked a browser to check that certificates for the site appear in public Certificate Transparency logs. Since May 2018 every new publicly-trusted certificate is expected to carry signed certificate timestamps, and the last certificates issued before that — which were allowed 39-month lifetimes — expired in June 2021. So there is no certificate left for the check to fail on, and a browser that did read the field would find nothing the platform had not already enforced.\n\n**The value is deliberately not graded.** RFC 9163 §2.1 gives the field a grammar and the `max-age`, `report-uri` and `enforce` directives it takes, so a malformed `max-age` or a `report-uri` that is no URI is a defect that could be reported. It is not, because it is a claim about how a dead field is spelled: no recipient reads the value, so whether it parses changes nothing for anyone. What an operator can act on is that the line does nothing at all, and that is one finding. The value is printed rather than parsed, because a `report-uri` in it names a collector the deployment probably still believes is receiving reports.\n\n**The repair is a deletion.** No other field in a message names an `Expect-CT` policy, so unlike `Report-To` — whose group names a `Content-Security-Policy` directive and a `NEL` policy point at — there is nothing to move first. An operator wanting the guarantee the field was for already has it: the platform enforces CT for every certificate.\n\n**Advice, not a violation.** Nothing prohibits sending the field, no recipient behaves differently, and the message is well-formed. What the finding tells an operator is that a security control they believe they have configured is not in effect anywhere.\n\nScope: this rule reads a response's header section. Several field lines are read as one value (RFC 9110 §5.2), and a value carrying an octet outside US-ASCII is measured rather than skipped — reading it back through a UTF-8 decoder would turn a field the sender wrote into a response that has none."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[MDN_EXPECT_CT, RFC_9163_1]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **The server, and RFC 9163 names the direction.** § 1 defines
    /// `Expect-CT` as a response header a *host* uses to opt itself in; no
    /// document defines it on a request, and the policy is a statement only the
    /// origin can make. So the peer answerable for every finding of this rule
    /// is the one that answered, and the reader below is handed the response's
    /// headers and nothing else.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the transport guarantee, which the platform now enforces itself)"),
                snippet: "HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=63072000",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(enforcement asked of a browser that removed the field)"),
                snippet: "HTTP/1.1 200 OK\nExpect-CT: max-age=86400, enforce",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a collector nothing will report to)"),
                snippet: "HTTP/1.1 200 OK\nExpect-CT: max-age=3600, report-uri=\"https://example.com/ct-report\"",
            },
        ]
    }
}

impl Rule for ExpectCtFieldObsolete {
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

            // The header section. The policy was installed as the connection's
            // certificate was being judged, which happens before any trailer
            // can arrive, so an `Expect-CT` in a trailer could never have
            // applied -- a different claim from this one rather than a quieter
            // version of it.
            //
            // Several lines are read as one value because § 5.2 says what a
            // repeated field name recombines into: the value is a directive
            // list, so a host writing `max-age` and `report-uri` on two lines
            // has written one value and reading the first alone would print
            // half of it.
            //
            // cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
            let value = combined_field_value_as_written(&resp.headers, "expect-ct")?;

            // Presence is the whole of the evidence. § 2.1's grammar would
            // grade the directives, and a defect in them is a claim about how a
            // field nothing reads is spelled -- true, and of no consequence to
            // any recipient. The value is printed instead, because a
            // `report-uri` in it names a collector the deployment still
            // believes is receiving reports.
            //
            // cite(MDN Expect-CT): "and Chromium has deprecated the header from version 107, because Chromium now enforces CT by default"
            // cite(RFC 9163 § 1): "enables UAs to identify web hosts that expect the presence of Signed Certificate Timestamps (SCTs)"
            Some(ctx.report_with(
                &EXPECT_CT_OBSOLETE,
                format!(
                    "Response carries an Expect-CT header field: '{}'. Chromium was the only \
                     engine that implemented it and removed the header in version 107, because it \
                     now enforces Certificate Transparency by default — so no browser reads this \
                     field and the enforcement or reporting it asks for is not in effect anywhere. \
                     Nothing else in the message names the policy, so the repair is to delete the \
                     line",
                    crate::helpers::shown::shown_in_finding(&value)
                ),
            ))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ExpectCtFieldObsolete;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const RULE: ExpectCtFieldObsolete = ExpectCtFieldObsolete;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&["expect_ct_field_obsolete"])
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

    /// The two shapes the wild sends — a reporting policy and an enforcing one
    /// — and a response that carries no `Expect-CT` at all.
    #[rstest]
    #[case::reporting(&[("expect-ct", "max-age=3600, report-uri=\"https://x.example/r\"")], true)]
    #[case::enforcing(&[("expect-ct", "max-age=86400, enforce")], true)]
    #[case::absent(&[("strict-transport-security", "max-age=63072000")], false)]
    fn presence_is_the_whole_reading(#[case] headers: &[(&str, &str)], #[case] fires: bool) {
        let out = response(headers);
        assert_eq!(out.len(), usize::from(fires), "{headers:?}");
        if fires {
            assert_eq!(out[0].violation, "expect_ct_obsolete");
        }
    }

    /// **The value is not graded, and this is the case that pins it.** A
    /// `max-age` that derives from no `delta-seconds` is a defect RFC 9163
    /// § 2.1 would catch, and it must draw the same one finding as a
    /// well-formed value: no recipient reads the field, so how it is spelled
    /// changes nothing, and a second entry about the spelling would be a claim
    /// with no consequence.
    #[test]
    fn a_malformed_directive_draws_the_same_one_finding() {
        let out = response(&[("expect-ct", "max-age=soon, enforce")]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].violation, "expect_ct_obsolete");
    }

    /// The two field lines a host writes its directives on are one value, and
    /// the finding shows both — a `report-uri` on a second line names a
    /// collector the deployment believes in just as much as one on the first.
    #[test]
    fn the_finding_shows_every_field_line() {
        let out = response(&[
            ("expect-ct", "max-age=3600"),
            ("expect-ct", "report-uri=\"https://x.example/r\""),
        ]);
        assert_eq!(out.len(), 1, "one field, however many lines carry it");
        assert!(
            out[0].message.contains("max-age=3600"),
            "{}",
            out[0].message
        );
        assert!(out[0].message.contains("x.example"), "{}", out[0].message);
    }

    /// A value carrying an octet `to_str` refuses is still an `Expect-CT`
    /// field, and the finding is about the field. Measured rather than skipped,
    /// for the reason the sibling rule's own case gives.
    #[test]
    fn an_unreadable_octet_does_not_stand_the_reading_down() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let resp = tx.response.as_mut().expect("the response just built");
        resp.headers.append(
            hyper::header::HeaderName::from_static("expect-ct"),
            hyper::header::HeaderValue::from_bytes(b"max-age=1, report-uri=\"caf\xe9\"")
                .expect("a test value"),
        );
        let out = crate::test_helpers::run_rule_all(
            &RULE,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].violation, "expect_ct_obsolete");
    }
}
