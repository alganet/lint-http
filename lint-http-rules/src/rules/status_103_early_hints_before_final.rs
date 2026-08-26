// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! A `103 (Early Hints)` response, and the one thing a capture can say about it.
//!
//! RFC 8297 defines the status code and **states no requirement on the server
//! at all**. Every BCP 14 keyword in the document is either addressed to the
//! client — three of them — or a `MAY` handed to the server; the declines below
//! quote all five, which is every one the document contains. So a rule reporting a server's use of
//! `103` has to take its requirement from the document that defines what an
//! informational response *is*, which is RFC 9110 § 15, and the two sentences
//! this file rests on were cited nowhere in this tree.
//!
//! **What the model can hold.** A `103` is interim, and the requirement about it
//! is a relation between two responses to **one** request. An
//! [`HttpTransaction`](crate::http_transaction::HttpTransaction) has one
//! `response` field, so a capture in this format never holds both. That is what
//! makes the finding below the only one available — and it is why the check that
//! used to be here, comparing this transaction against the previous one for the
//! same client and target, could not have been about this requirement: two
//! transactions are two *requests*, and a second request to a URI answered with
//! a `103` is the document's ordinary case, not a defect.
// cite(RFC 9110 § 15): "A single request can have multiple associated responses: zero or more "interim" (non-final) responses with status codes in the "informational" (1xx) range, followed by exactly one "final" response with a status code in one of the other ranges."
//!
//! **Where the input comes from.** On the two upstream legs this proxy serves
//! through hyper, a `103` is discarded before anything here could see it — the
//! HTTP/1.x client returns `Ok(None)` for `100 | 102..=199` and reads on for the
//! final response, and the HTTP/2 client polls `h2`'s `poll_response`, which
//! skips interim headers to find the main response. On the HTTP/3 leg `h3`'s
//! `recv_response` returns the **first** HEADERS frame with no status-class test
//! of any kind, so a `103` from an HTTP/3 origin is taken for the response,
//! recorded as one, and relayed to the client as one. A capture recording a
//! `103` therefore comes either from that leg or from a tool other than this
//! proxy, and in both cases it records an exchange whose final response is not
//! in the capture. `lint` over such a file is the other reader.
//!
//! **Declines.** RFC 8297's three client requirements are about what a client
//! does with the fields it received, which no captured message states:
// cite(RFC 8297 § 2): "Aside from performance optimizations, such evaluation of the 103 (Early Hints) response's header fields MUST NOT affect how the final response is processed."
// cite(RFC 8297 § 2): "A client MUST NOT interpret the 103 (Early Hints) response header fields as if they applied to the informational response itself (e.g., as metadata about the 103 (Early Hints) response)."
// cite(RFC 8297 § 2): "A client SHOULD NOT interpret the nonexistence of a header field in a 103 (Early Hints) response as a speculation that the header field is unlikely to be part of the final response."
//!
//! Its two server sentences are permissions, so neither a partial set of fields
//! nor a run of several `103`s is a finding:
// cite(RFC 8297 § 2): "A server MAY use a 103 (Early Hints) response to indicate only some of the header fields that are expected to be found in the final response."
// cite(RFC 8297 § 2): "A server MAY emit multiple 103 (Early Hints) responses with additional header fields as new information becomes available while the request is being processed."
//!
//! And comparing a `103`'s fields against the final response's is declined at
//! the source: the document says the repetition is typical and then says in the
//! next breath that not repeating is legitimate.
// cite(RFC 8297 § 2): "Typically, a server will include the header fields sent in a 103 (Early Hints) response in the final response as well."
// cite(RFC 8297 § 2): "However, there might be cases when this is not desirable, such as when the server learns that the header fields in the 103 (Early Hints) response are not correct before the final response is sent."

use crate::lint::Violation;
use crate::rules::Rule;

/// Report a `103 (Early Hints)` recorded as a request's response.
pub struct Status103EarlyHintsBeforeFinal;

impl Rule for Status103EarlyHintsBeforeFinal {
    fn id(&self) -> &'static str {
        "status_103_early_hints_before_final"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        // Deliberately unread, and the rule is no longer in `STATEFUL_RULES`.
        // The requirement relates two responses to one request; a history entry
        // is a different request, so every question this rule can ask is
        // answered by the transaction in hand. Registering it anyway would make
        // the engine build a `ByResource` history nothing looks at.
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let resp = tx.response.as_ref()?;

        // The scope gate. The sentence is the status code's definition, quoted
        // to its end: the clause after "final response" is what makes the
        // fields a *hint* about a message still to come, which is the whole
        // reason a `103` standing alone as an answer is worth a finding.
        // cite(RFC 8297 § 2): "The 103 (Early Hints) informational status code indicates to the client that the server is likely to send a final response with the header fields included in the informational response."
        if resp.status != 103 {
            return None;
        }

        // Read last: `parse_rule_config` is several map probes and a hash over
        // the id, and the gate above ends the rule for all but one status.
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // ── The HTTP/1.0 client ──
        // Reported first because it is the narrower fact and the only sentence
        // in reach that is a MUST NOT on the sender. Both digits, not the major
        // one: HTTP/1.1 is the version that has 1xx, so the minor digit is the
        // whole gate. RFC 8297 § 3 spends its Security Considerations on what
        // goes wrong when a client cannot place an informational response, and
        // it worries about HTTP/1.1 clients — RFC 9110 turns the same concern
        // into a requirement one version down, where the client cannot have
        // learned about 1xx at all.
        // cite(RFC 9110 § 15.2): "Since HTTP/1.0 did not define any 1xx status codes, a server MUST NOT send a 1xx response to an HTTP/1.0 client."
        if matches!(
            crate::http_version::parse(&tx.request.version),
            Ok(crate::http_version::HttpVersion { major: 1, minor: 0 })
        ) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "103 (Early Hints) answering an HTTP/1.0 request: HTTP/1.0 defined no \
                          1xx status codes, so a server must not send one to that client"
                    .into(),
            });
        }

        // ── The interim response standing where the final one goes ──
        // § 15 is the requirement: interim responses are followed by exactly one
        // final response. This model records one response per request, so a
        // `103` in that slot is a capture of an exchange whose final response is
        // not there. RFC 8297 § 3 names the second reading of the same bytes and
        // is why the message states both: a recipient that took the interim
        // response for the final one records exactly this.
        // cite(RFC 9110 § 15.2): "The 1xx (Informational) class of status code indicates an interim response for communicating connection status or request progress prior to completing the requested action and sending a final response."
        // cite(RFC 8297 § 3): "In particular, an HTTP/1.1 client that mishandles an informational response as a final response is likely to consider all responses to the succeeding requests sent over the same connection to be part of the final response."
        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!(
                "103 (Early Hints) is recorded as the response to '{}', and a 103 is an interim \
                 response that exactly one final response has to follow: either the final \
                 response never arrived, or the interim one was taken for it",
                tx.request.uri
            ),
        })
    }

    fn description(&self) -> &'static str {
        "A `103 (Early Hints)` response is *interim*: RFC 9110 §15 gives a single request zero or more interim responses \"followed by exactly one final response\", and RFC 8297 §2 defines the status as telling the client that a final response is still likely to come. This rule reports a capture in which the response recorded for a request **is** the `103` — an exchange whose final response is not in the capture, or an interim response that some recipient took for the final one (RFC 8297 §3 describes exactly that mishandling). It also reports a `103` answering an HTTP/1.0 request, which RFC 9110 §15.2 makes a MUST NOT because HTTP/1.0 defined no `1xx` status codes at all.\n\n**What this rule does not report, and why.** A conforming `103` followed by a final response is not a defect and is not visible either: a transaction in this capture format has one response field, so a `103` and the final response for the same request are never both recorded. The check this rule used to make — a `103` for a client and target whose *previous* transaction had ended in a final response — was therefore not about RFC 9110 §15's requirement at all. Two transactions are two requests, and a repeat request to a URI answered with a `103` is the document's ordinary case; that finding is retired.\n\n**RFC 8297 states no requirement on a server.** Its three BCP 14 requirements — two MUST NOTs and a SHOULD NOT — are addressed to the client and concern what it does with the fields, which no captured message states. Its two server sentences are MAYs: a `103` may carry only some of the fields expected in the final response, and a server may emit several of them. Comparing a `103`'s fields against a final response's is declined at the source, since §2 calls the repetition typical and then names cases where omitting it is right.\n\n**Where a `103` in a capture comes from.** On the HTTP/1.x and HTTP/2 upstream legs this proxy discards interim responses before recording anything — hyper's HTTP/1.x client skips `100` and `102..=199` outright, and its HTTP/2 client reads `h2`'s main response, which steps over interim headers. The HTTP/3 leg does not: `h3`'s `recv_response` returns the first HEADERS frame whatever its status, so a `103` from an HTTP/3 origin becomes the recorded response. That leg and `lint` over capture files written elsewhere are where this rule's findings live."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15",
                note: "The requirement this rule rests on: a single request's interim responses are followed by exactly one final response — the sentence RFC 8297 never states, and the reason the finding is about one request rather than two transactions",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2",
                note: "What makes a 103 interim, and the only MUST NOT in reach that is addressed to the sender: HTTP/1.0 defined no 1xx status codes, so a server must not send one to an HTTP/1.0 client",
            },
            crate::rules::SpecRef {
                spec: "RFC 8297",
                section: Some("2"),
                url: "https://www.rfc-editor.org/rfc/rfc8297.html#section-2",
                note: "The status code's definition, which is the scope gate — and every one of the document's BCP 14 keywords: three requirements addressed to the client and two MAYs addressed to the server, so nothing here is a requirement this rule could enforce",
            },
            crate::rules::SpecRef {
                spec: "RFC 8297",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc8297.html#section-3",
                note: "Why an interim response recorded as the answer is worth reporting rather than shrugging at: the document's Security Considerations are about a recipient mishandling an informational response as a final one",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "— the response recorded for the request is the final one; a 103 that preceded it is not something this capture format holds",
                ),
                snippet: "> GET /resource HTTP/1.1\n\n< 200 OK\n< Content-Type: text/html; charset=utf-8\n< Link: </static/style.css>; rel=preload; as=style",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— the interim response is what the capture records as this request's answer, and no final response follows it",
                ),
                snippet: "> GET /resource HTTP/1.1\n\n< 103 Early Hints\n< Link: </static/style.css>; rel=preload; as=style",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— HTTP/1.0 defined no 1xx status codes, so this one may not be sent at all"),
                snippet: "> GET /resource HTTP/1.0\n\n< 103 Early Hints\n< Link: </static/style.css>; rel=preload; as=style",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Status103EarlyHintsBeforeFinal;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&[
            "status_103_early_hints_before_final",
        ])
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        Status103EarlyHintsBeforeFinal.check_transaction(
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
        let r = Status103EarlyHintsBeforeFinal;
        assert_eq!(r.id(), "status_103_early_hints_before_final");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn a_103_recorded_as_the_response_is_reported() {
        let v = run(&tx_with(103, "HTTP/1.1")).expect("a 103 in the response slot is the finding");
        assert!(v.message.contains("interim response"));
        assert!(v.message.contains("/resource"));
    }

    /// The `103` reaches this rule on every version, because § 15 is not a
    /// sentence about a messaging syntax. The HTTP/1.0 case is the one that
    /// answers differently, and it has its own test below.
    #[rstest]
    #[case("HTTP/1.1")]
    #[case("HTTP/2.0")]
    #[case("HTTP/3.0")]
    fn a_103_is_reported_on_every_version_that_has_1xx(#[case] version: &str) {
        assert!(run(&tx_with(103, version)).is_some());
    }

    #[test]
    fn a_103_answering_http_1_0_names_the_must_not() {
        let v = run(&tx_with(103, "HTTP/1.0")).expect("RFC 9110 § 15.2's MUST NOT");
        assert!(v.message.contains("HTTP/1.0"));
        assert!(v.message.contains("1xx"));
        // The narrower fact wins: reporting this one as "the final response
        // never arrived" would name the wrong sentence for a response that may
        // not be sent under any circumstances.
        assert!(!v.message.contains("interim"));
    }

    /// The retired finding. Two transactions are two requests, and a repeat
    /// request answered with a `103` is RFC 8297's ordinary case — so this
    /// history, which the old check reported, now decides nothing. The current
    /// finding still fires, on the transaction in hand and for its own reason.
    #[test]
    fn a_103_after_a_previous_final_response_is_not_a_cross_transaction_finding() {
        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        prev.request.uri = "/resource".to_string();

        let tx = tx_with(103, "HTTP/1.1");
        let with_history = Status103EarlyHintsBeforeFinal.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &cfg(),
        );
        assert_eq!(
            with_history.map(|v| v.message),
            run(&tx).map(|v| v.message),
            "history must not change the verdict"
        );
    }

    /// The other direction of the same retirement: a final response is what the
    /// model is *supposed* to hold, whatever preceded it.
    #[rstest]
    #[case(200)]
    #[case(204)]
    #[case(404)]
    #[case(500)]
    fn a_final_response_is_clean(#[case] status: u16) {
        assert!(run(&tx_with(status, "HTTP/1.1")).is_none());
    }

    /// This rule's id names one status, and the others are not its business.
    /// `101` has an owner (`status_101_switching_protocols`, which reports one
    /// answering an HTTP/1.0 request via RFC 9110 § 7.8's Upgrade sentence
    /// rather than via § 15.2's MUST NOT above). `100` and `102` have none —
    /// that is a gap, not something to answer from here.
    #[rstest]
    #[case(100)]
    #[case(101)]
    #[case(102)]
    fn other_informational_statuses_are_left_to_their_owners(#[case] status: u16) {
        assert!(run(&tx_with(status, "HTTP/1.1")).is_none());
    }

    /// A malformed version is not an HTTP/1.0 one, and must not silence the
    /// § 15 finding — `parse` failing is `http_version_syntax`'s
    /// report to make, not a reason for this rule to say nothing.
    #[rstest]
    #[case("HTTP/1.0.0")]
    #[case("http/1.0")]
    #[case("1.0")]
    #[case("")]
    fn an_unparseable_version_still_leaves_the_interim_finding(#[case] version: &str) {
        let v = run(&tx_with(103, version)).expect("the § 15 finding does not depend on a version");
        assert!(v.message.contains("interim response"));
    }

    #[test]
    fn no_response_is_ignored() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = "/resource".to_string();
        assert!(run(&tx).is_none());
    }

    /// The published examples are messages this rule can actually see, which is
    /// the thing the old pair got wrong: both of them printed two responses to
    /// one request, and this format records one.
    #[test]
    fn published_examples_match_the_rules_verdicts() {
        // "The guard is green" and "the guard ran" are separate claims.
        let mut reported_count = 0;
        for ex in Status103EarlyHintsBeforeFinal.examples() {
            let status: u16 = if ex.snippet.contains("< 103 ") {
                103
            } else {
                200
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
        crate::test_helpers::enable_rule(&mut cfg, "status_103_early_hints_before_final");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_missing_severity_errors() {
        // When rule is enabled but missing required 'severity', validation should fail
        let mut cfg = cfg();
        if let Some(toml::Value::Table(table)) =
            cfg.rules.get_mut("status_103_early_hints_before_final")
        {
            table.remove("severity");
        }

        assert!(crate::rules::validate_rules(&cfg).is_err());
    }
}
