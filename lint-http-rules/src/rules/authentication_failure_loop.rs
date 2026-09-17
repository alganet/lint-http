// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::status::{RFC_9110_15_5_2, STATUS_401_IGNORED};
use crate::violations::ViolationDef;

/// One entry, and the threshold below is not part of it: the catalogue says the
/// loop happened, this rule says how many rounds it takes to call one.
static DECLARED: &[&ViolationDef] = &[&STATUS_401_IGNORED];

/// Detects repeated 401 challenges for the same protection space (origin),
/// which indicates an authentication failure loop.
pub struct AuthenticationFailureLoop;

// The one reference this rule names lives on the entry it reports through and
// is imported back for `specifications()`, so the citation and the documented
// reading are the same value rather than two copies of it.

impl RuleMeta for AuthenticationFailureLoop {
    fn id(&self) -> &'static str {
        "authentication_failure_loop"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Detects repeated `401 Unauthorized` challenges for the same protection space (origin), which strongly indicates an authentication failure loop. When a client continuously retries authentication and repeatedly fails with a 401 across the same origin, it could imply a broken client, misconfigured credentials, or a flawed authentication handshake.\n\nThis rule tracks the transaction history by origin and flags if a client receives 4 or more consecutive `401 Unauthorized` challenges without a successful (or other non-401) response in between."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_15_5_2]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **Neither peer, and the rule's own description says so before this
    /// field existed to record it**: a run of 401s "could imply a broken
    /// client, misconfigured credentials, or a flawed authentication
    /// handshake", and the rule declines to choose between the three.
    ///
    /// The evidence is not in a message at all. Four transactions read
    /// together are what a loop is, and no single one of them is the defect —
    /// the client re-presenting credentials is doing what §15.5.2 invites, and
    /// each 401 answering them is correct on its own terms. `Neither` is the
    /// value that says a reader narrowing to one end still wants this, because
    /// it is about the exchange they are in rather than about the half they
    /// wrote.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Neither)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "> GET /protected HTTP/1.1\n> Host: example.com\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Basic realm=\"Access\"\n\n> GET /protected HTTP/1.1\n> Host: example.com\n> Authorization: Basic ...\n\n< 200 OK HTTP/1.1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— Authentication Loop"),
                snippet: "> GET /api/v1/data HTTP/1.1\n> Host: example.com\n\n< 401 Unauthorized HTTP/1.1\n< WWW-Authenticate: Bearer realm=\"API\"\n\n> GET /api/v1/data HTTP/1.1\n> Host: example.com\n> Authorization: Bearer INVALID\n\n< 401 Unauthorized HTTP/1.1\n\n> GET /api/v1/data HTTP/1.1\n> Host: example.com\n> Authorization: Bearer INVALID\n\n< 401 Unauthorized HTTP/1.1\n\n> GET /api/v1/data HTTP/1.1\n> Host: example.com\n> Authorization: Bearer INVALID\n\n< 401 Unauthorized HTTP/1.1",
            },
        ]
    }
}

impl Rule for AuthenticationFailureLoop {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // Only 401 responses matter — the status that means credentials were missing
            // or rejected, i.e. an authentication attempt that did not succeed.
            // cite(RFC 9110 § 15.5.2): "The 401 (Unauthorized) status code indicates that the request has not been applied because it lacks valid authentication credentials for the target resource."
            let resp = tx.response.as_ref()?;
            if resp.status != 401 {
                return None;
            }

            // History is scoped to this origin by the rule's ByOrigin query, so a "run" of
            // 401s here is one protection space's failures, not a mix across hosts.
            let mut consecutive_401s = 0;

            for prev_tx in history.iter() {
                if let Some(prev_resp) = &prev_tx.response {
                    if prev_resp.status == 401 {
                        consecutive_401s += 1;
                    } else {
                        // Break on first non-401 response for this origin
                        break;
                    }
                }
            }

            // Loop = more than 3 consecutive 401s *before* this one (4th and up).
            // The exact count of 4 is this rule's heuristic threshold and stays
            // here rather than moving onto the entry with the sentence: no
            // sentence fixes a number, §15.5.2 says "at least once" and stops,
            // so a linter that picked one owns it. Four sits comfortably past
            // the single sanctioned retry-and-re-present.
            if consecutive_401s >= 3 {
                Some(ctx.report_with(&STATUS_401_IGNORED, format!(
                        "Authentication failure loop detected: client has received {} consecutive 401 Unauthorized challenges for this origin.",
                        consecutive_401s + 1
                    )))
            } else {
                None
            }
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AuthenticationFailureLoop;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_loop_detected() {
        let rule = AuthenticationFailureLoop;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.request.uri = "https://example.com/protected".to_string();

        let mut tx1 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx1.request.uri = "https://example.com/login".to_string();

        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx2.request.uri = "https://example.com/api".to_string();

        let mut tx3 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx3.request.uri = "https://example.com/admin".to_string();

        // supply history newest-first; tx3 is most recent
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![tx3, tx2, tx1]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "authentication_failure_loop",
            ]),
        );
        let v = v.expect("a finding");
        assert_eq!(v.violation, "status_401_ignored");
        assert!(v.message.contains("4 consecutive"), "{}", v.message);
    }

    #[test]
    fn test_auth_loop_broken_by_200() {
        let rule = AuthenticationFailureLoop;

        let tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);

        let tx1 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let tx2 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let tx3 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let tx4 = crate::test_helpers::make_test_transaction_with_response(401, &[]);

        // put newest transaction first (tx4) to satisfy TransactionHistory
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            tx4, tx3, tx2, tx1,
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "authentication_failure_loop",
            ]),
        );
        // Only 2 consecutive 401s before the 200, so no loop
        assert!(v.is_none());
    }

    #[test]
    fn test_non_401_ignored() {
        let rule = AuthenticationFailureLoop;

        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let tx1 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let tx2 = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let tx3 = crate::test_helpers::make_test_transaction_with_response(401, &[]);

        // newest-first history
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![tx3, tx2, tx1]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "authentication_failure_loop",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "authentication_failure_loop");
        crate::rules::validate_rules(&cfg).unwrap();
    }
}
