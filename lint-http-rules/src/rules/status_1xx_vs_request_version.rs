// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! An interim response answering a client whose version defined none.
//!
//! RFC 9110 § 15.2 states one MUST NOT about the whole `1xx` class, and it is
//! the sentence this file exists for. **The subject is the class**: not one
//! status code, not the ones a particular document happens to define, but any
//! response whose status falls in `100..=199`.
// cite(RFC 9110 § 15.2): "Since HTTP/1.0 did not define any 1xx status codes, a server MUST NOT send a 1xx response to an HTTP/1.0 client."
//!
//! **Why a rule of its own.** The entry this reports has existed for as long as
//! the `103` rule has, declared there and reported from inside that rule's scope
//! gate — so the sentence was applied to `103` alone, and a `100 (Continue)`
//! answering an HTTP/1.0 request, which is the shape the sentence most plainly
//! covers, drew nothing at all. A rule named for one status code cannot honestly
//! widen to a class; the class needs a reading whose scope *is* the class, and
//! this is it. `status_103_early_hints_before_final` keeps the one finding that
//! is genuinely about `103` — an interim response standing where the single
//! final response goes — and no longer declares this entry.
//!
//! **Both digits decide it, and only for the request.** HTTP/1.1 is the version
//! that defines `1xx`, so the minor digit is the whole gate; and the client's
//! version is what the sentence names, since it is the client that cannot place
//! the response. A `1xx` on an HTTP/1.1 or later exchange is ordinary.
//!
//! **The `101` is here too, and it used to be answered elsewhere.**
//! `status_101_switching_protocols` reported a `101` answering an HTTP/1.0
//! request as `status_101_unsolicited`, on § 7.8 — a sentence addressed to what
//! a server does with an `Upgrade` *field*, which is why that entry is
//! `_unsolicited` rather than `_forbidden` and ships at `warn` with no keyword
//! claimed. § 15.2 prohibits the message itself, in a MUST NOT about the status
//! code, so it is both the stronger claim and the one that names what is wrong.
//! Reporting it from here and from there would be two findings for one response
//! with one repair, so that rule now declines the version instead — and the two
//! arms it keeps, HTTP/2 and HTTP/3, are the ones whose sections genuinely
//! withhold a definition rather than state a prohibition.
// cite(RFC 9110 § 7.8): "A server that receives an Upgrade header field in an HTTP/1.0 request MUST ignore that Upgrade field."
//!
//! **What this rule does not ask.** Whether the response should have been
//! recorded as a final one at all is § 15's question and
//! `status_103_early_hints_before_final`'s finding; whether a `1xx` carries
//! content, a trailer section, a `Content-Length` or a `Transfer-Encoding` is
//! `no_body_for_1xx_204_304`'s. Nothing here reads a field.

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::status::{RFC_9110_15_2, STATUS_1XX_FORBIDDEN};
use crate::violations::ViolationDef;

/// One entry, and the class is its subject: the id names `1xx` because § 15.2's
/// MUST NOT does.
static DECLARED: &[&ViolationDef] = &[&STATUS_1XX_FORBIDDEN];

/// Report a `1xx` response answering an HTTP/1.0 request.
pub struct Status1xxVsRequestVersion;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_15: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15",
    note: "What the class is: a request's interim responses are the 1xx ones, and exactly one final response follows them — the definition the range in this rule comes from",
};
const RFC_9110_7_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("7.8"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8",
    note: "The other sentence about an HTTP/1.0 client and an upgrade: a server MUST ignore an Upgrade field in such a request. It binds the field rather than the status code, which is why the 101 is reported here on §15.2 and not there on this",
};

impl RuleMeta for Status1xxVsRequestVersion {
    fn id(&self) -> &'static str {
        "status_1xx_vs_request_version"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("The interim response a client's version defined none of")
    }

    fn description(&self) -> &'static str {
        "RFC 9110 §15.2 states one MUST NOT about the whole informational class: \"Since HTTP/1.0 did not define any 1xx status codes, a server MUST NOT send a 1xx response to an HTTP/1.0 client.\" This rule reports a response whose status falls in `100..=199` answering a request whose version is exactly `HTTP/1.0`.\n\n**The subject is the class, not a status code.** Every member is reported — `100 (Continue)`, `101 (Switching Protocols)`, `102`, `103 (Early Hints)`, and any code in the range a future document defines — because the sentence names the range and not its members. The entry was previously reported only for `103`, from inside a rule scoped to that status, so a `100` answering an HTTP/1.0 request drew nothing.\n\n**Both digits are the gate, and it is the request's version.** HTTP/1.1 is the version that defines `1xx`, so the minor digit is the whole difference; and the sentence names the *client*, because it is the client that has no way to place an interim response. A `1xx` in an HTTP/1.1, HTTP/2 or HTTP/3 exchange is ordinary and is not reported.\n\n**A `101` is reported here rather than as `status_101_unsolicited`.** That entry's HTTP/1.0 arm rested on §7.8 — \"A server that receives an Upgrade header field in an HTTP/1.0 request MUST ignore that Upgrade field\" — which binds what a server does with a *field*, and is why the entry is `_unsolicited` rather than `_forbidden` and carries no keyword. §15.2 prohibits the message itself. `status_101_switching_protocols` now declines an HTTP/1.0 request rather than reporting one, so such a response draws one finding and not two; the two arms it keeps, HTTP/2 and HTTP/3, rest on sections that withhold a definition rather than state a prohibition.\n\n**Nothing here reads a field.** Whether an interim response was recorded where the single final response should be is `status_103_early_hints_before_final`'s finding, and whether a `1xx` carries content, a trailer section, a `Content-Length` or a `Transfer-Encoding` is `no_body_for_1xx_204_304`'s."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_15_2, RFC_9110_15, RFC_9110_7_8]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "— the client speaks HTTP/1.1, which is the version that defines the class",
                ),
                snippet: "> POST /upload HTTP/1.1\n> Expect: 100-continue\n\n< 100 Continue",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— HTTP/1.0 defined no 1xx status codes, so this client has no way to place the response and reads it as the final one",
                ),
                snippet: "> POST /upload HTTP/1.0\n> Expect: 100-continue\n\n< 100 Continue",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— the same sentence, and the member another entry used to answer for on §7.8's weaker one",
                ),
                snippet: "> GET /chat HTTP/1.0\n> Upgrade: websocket\n\n< 101 Switching Protocols\n< Upgrade: websocket",
            },
        ]
    }
}

impl Rule for Status1xxVsRequestVersion {
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

            // The class, read as a range because the sentence is written about
            // one. No member is named here and none is excluded: a code in
            // `100..=199` that no document this crate cites defines is still an
            // interim response, and § 15 requires a recipient to treat an
            // unrecognized code as the `x00` of its class — which for this class
            // is `100`.
            // cite(RFC 9110 § 15): "However, a client MUST understand the class of any status code, as indicated by the first digit, and treat an unrecognized status code as being equivalent to the x00 status code of that class."
            if !(100..200).contains(&resp.status) {
                return None;
            }

            // Both digits, and the *request's* version: HTTP/1.1 is the version
            // that defines the class, so the minor digit is the whole gate, and
            // the sentence names the client because it is the client that cannot
            // place the response. A request whose version does not parse states
            // no version for the sentence to be about, and is not reported.
            // cite(RFC 9110 § 15.2): "Since HTTP/1.0 did not define any 1xx status codes, a server MUST NOT send a 1xx response to an HTTP/1.0 client."
            if !matches!(
                crate::http_version::parse(&tx.request.version),
                Ok(crate::http_version::HttpVersion { major: 1, minor: 0 })
            ) {
                return None;
            }

            // The status is in the message because the class has members an
            // operator has to tell apart: the repair for a `100` is to stop
            // sending it to this client, and for a `101` it is to answer the
            // upgrade some other way.
            Some(ctx.report_with(
                &STATUS_1XX_FORBIDDEN,
                format!(
                    "{status} answering an HTTP/1.0 request: HTTP/1.0 defined no 1xx status \
                     codes, so a server must not send an interim response to that client — this \
                     one has no way to read it as interim and takes it for the final response",
                    status = resp.status,
                ),
            ))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Status1xxVsRequestVersion;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&["status_1xx_vs_request_version"])
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        crate::test_helpers::run_rule(
            &Status1xxVsRequestVersion,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg(),
        )
    }

    fn tx_with(status: u16, version: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        tx.request.uri = "/resource".to_string();
        tx.request.version = version.to_string();
        tx
    }

    #[test]
    fn id_and_scope() {
        let r = Status1xxVsRequestVersion;
        assert_eq!(r.id(), "status_1xx_vs_request_version");
        assert!(r.needs_response());
        assert_eq!(r.violations().len(), 1);
        assert_eq!(r.violations()[0].id, "status_1xx_forbidden");
    }

    /// The whole point of the rule, and the reason it exists apart from
    /// `status_103_early_hints_before_final`: the sentence is about the class,
    /// so every member of it is reported. `100` is first because it is the
    /// interim response a server sends unprompted, and the one that drew
    /// nothing for as long as the reading was gated on `103`.
    #[rstest]
    #[case(100)]
    #[case(101)]
    #[case(102)]
    #[case(103)]
    #[case(150)]
    #[case(199)]
    fn every_member_of_the_class_is_reported(#[case] status: u16) {
        let v = run(&tx_with(status, "HTTP/1.0")).expect("§ 15.2's MUST NOT");
        assert_eq!(v.violation, "status_1xx_forbidden");
        assert_eq!(v.severity, crate::lint::Severity::Error);
        // A finding names its value: the class has members whose repairs
        // differ, so the status is in the sentence.
        assert!(v.message.starts_with(&status.to_string()));
        assert!(v.message.contains("HTTP/1.0"));
    }

    /// The two edges of the range, from outside. `99` is not a status a
    /// response can carry and `200` is the first final one; neither is an
    /// interim response, and the sentence is about interim responses.
    #[rstest]
    #[case(99)]
    #[case(200)]
    #[case(204)]
    #[case(304)]
    #[case(404)]
    #[case(500)]
    fn a_status_outside_the_class_is_not_reported(#[case] status: u16) {
        assert!(run(&tx_with(status, "HTTP/1.0")).is_none());
    }

    /// Both digits, and only HTTP/1.0. HTTP/1.1 is the version that defines the
    /// class, so a `100` on it is the ordinary Expect/continue exchange.
    #[rstest]
    #[case("HTTP/1.1")]
    #[case("HTTP/2.0")]
    #[case("HTTP/3.0")]
    fn a_version_that_defines_the_class_is_clean(#[case] version: &str) {
        for status in [100u16, 101, 103, 199] {
            assert!(
                run(&tx_with(status, version)).is_none(),
                "{status} on {version} is ordinary",
            );
        }
    }

    /// The request's version is what the sentence names — it is the client that
    /// cannot place the response — so a response labelled HTTP/1.0 beside a
    /// request that is not says nothing here.
    #[test]
    fn it_is_the_requests_version_that_decides() {
        let mut tx = tx_with(100, "HTTP/1.1");
        tx.response.as_mut().expect("a response").version = "HTTP/1.0".to_string();
        assert!(run(&tx).is_none());
    }

    /// A version that does not parse names no version for § 15.2 to be about.
    /// Reporting one would put the finding on `http_version_syntax`'s value,
    /// and the repair it names — stop sending interim responses to this client
    /// — is not the repair for a request-line nobody can read.
    #[rstest]
    #[case("HTTP/1.0.0")]
    #[case("http/1.0")]
    #[case("1.0")]
    #[case("HTTP/1")]
    #[case("")]
    fn an_unparseable_version_is_not_an_http_1_0_one(#[case] version: &str) {
        assert!(run(&tx_with(100, version)).is_none());
    }

    #[test]
    fn no_response_is_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/1.0".to_string();
        assert!(run(&tx).is_none());
    }

    #[test]
    fn published_examples_match_the_rules_verdicts() {
        // "The guard is green" and "the guard ran" are separate claims.
        let mut reported_count = 0;
        for ex in Status1xxVsRequestVersion.examples() {
            let status: u16 = if ex.snippet.contains("< 101 ") {
                101
            } else {
                100
            };
            let version = if ex.snippet.contains("HTTP/1.0") {
                "HTTP/1.0"
            } else {
                "HTTP/1.1"
            };
            let reported = run(&tx_with(status, version)).is_some();
            assert_eq!(
                reported,
                matches!(ex.compliance, crate::rules::Compliance::NonCompliant),
                "example {:?} does not match the rule's verdict",
                ex.label,
            );
            reported_count += usize::from(reported);
        }
        assert_eq!(
            reported_count, 2,
            "both NonCompliant examples must actually produce a finding"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "status_1xx_vs_request_version");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
