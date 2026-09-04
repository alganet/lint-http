// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

pub struct RetryAfterStatusValid;

/// Whether some sentence says what `Retry-After` means on `status`.
///
/// Four contexts have one, and each test below carries its own. The set is open
/// in principle — a future status definition can name the field the way §15.5.14
/// does — so this is what is written down today, not a grammar.
fn status_defines_retry_after(status: u16) -> bool {
    // One of the two contexts the field's own section names, and it names the
    // whole class rather than any particular redirect status.
    // cite(RFC 9110 § 10.2.3): "When sent with any 3xx (Redirection) response, Retry-After indicates the minimum time that the user agent is asked to wait before issuing the redirected request."
    if crate::helpers::status::is_redirection_status(status) {
        return true;
    }

    // The other one, with the permission to send it written in the status's own
    // definition rather than in §10.2.3.
    // cite(RFC 9110 § 10.2.3): "When sent with a 503 (Service Unavailable) response, Retry-After indicates how long the service is expected to be unavailable to the client."
    // cite(RFC 9110 § 15.6.4): "The server MAY send a Retry-After header field (Section 10.2.3) to suggest an appropriate amount of time for the client to wait before retrying the request."
    if status == 503 {
        return true;
    }

    // A 413 asks for the field by name, in its own status definition and with a
    // SHOULD — so a temporary 413 carrying `Retry-After` is a server doing what
    // the same RFC told it to do.
    // cite(RFC 9110 § 15.5.14): "If the condition is temporary, the server SHOULD generate a Retry-After header field to indicate that it is temporary and after what time the client MAY try again."
    if status == 413 {
        return true;
    }

    // 429 is defined outside RFC 9110, which never mentions that status.
    // cite(RFC 6585 § 4): "The response representations SHOULD include details explaining the condition, and MAY include a Retry-After header indicating how long to wait before making a new request."
    status == 429
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_10_2_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("10.2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3",
    note: "Defines Retry-After generally, with no condition on the status code, then says what it indicates on a 503 and on any 3xx",
};
const RFC_9110_15_5_14: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.5.14"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.14",
    note: "413 Content Too Large: when the condition is temporary the server SHOULD generate a Retry-After header field",
};
const RFC_9110_15_6_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.6.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6.4",
    note: "503 Service Unavailable: the server MAY send a Retry-After header field",
};
const RFC_6585_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6585",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc6585.html#section-4",
    note: "429 Too Many Requests: the response MAY include a Retry-After header",
};

impl RuleMeta for RetryAfterStatusValid {
    fn id(&self) -> &'static str {
        "retry_after_status_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Retry-After Status Validity")
    }

    fn description(&self) -> &'static str {
        "`Retry-After` tells a user agent how long to wait before making a follow-up request. Four contexts give it a defined behaviour — one of them a whole status class — and this rule reports the field arriving anywhere else.\n\n- any `3xx` redirection — the minimum time to wait before issuing the redirected request (RFC 9110 §10.2.3)\n- `503 Service Unavailable` — how long the service is expected to be unavailable (RFC 9110 §10.2.3, §15.6.4)\n- `413 Content Too Large` — when the condition is temporary, §15.5.14 **asks for the field by name**, with a SHOULD\n- `429 Too Many Requests` — RFC 6585 §4, a status RFC 9110 never mentions\n\n**No requirement is violated by a response this rule reports.** §10.2.3 defines the field with no condition on the status code, and its two \"When sent with\" sentences elaborate two cases rather than closing the set; neither RFC 9110 nor RFC 6585 prohibits `Retry-After` anywhere. The finding is advisory: on a status neither document pairs with the field, what a client does with the value is unspecified, so the instruction is unlikely to be acted on. Configure the severity accordingly.\n\nA `Retry-After` in a **request** is not reported either. §10.2 places the field among response fields and §10.2.3 names the server as its sender, but no sentence forbids a client from sending one.\n\nThe list is what is written down, not a grammar — a future status definition can name the field the way §15.5.14 does, and this rule would have to learn it.\n\nThe status the field arrived on is all this rule reads. The value's syntax (`Retry-After = HTTP-date / delay-seconds`) and a repeated `Retry-After` field line belong to `retry_after_date_or_delay`, which reports both."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_10_2_3,
            RFC_9110_15_5_14,
            RFC_9110_15_6_4,
            RFC_6585_4,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("503: how long the service is expected to be unavailable"),
                snippet: "HTTP/1.1 503 Service Unavailable\nRetry-After: 120",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "Any 3xx: the minimum wait before issuing the redirected request",
                ),
                snippet: "HTTP/1.1 301 Moved Permanently\nLocation: /new-path\nRetry-After: 30",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "429: defined by RFC 6585, which RFC 9110 does not cover. Status line and fields as §4 prints them",
                ),
                snippet: "HTTP/1.1 429 Too Many Requests\nContent-Type: text/html\nRetry-After: 3600",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "413 with a temporary condition: §15.5.14 asks for this field with a SHOULD",
                ),
                snippet: "HTTP/1.1 413 Content Too Large\nRetry-After: 120",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "Nothing pairs the field with a 200, so a user agent is not told what to do with it",
                ),
                snippet: "HTTP/1.1 200 OK\nRetry-After: 10",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The nearest defined status is 503, and its sentence says 503"),
                snippet: "HTTP/1.1 500 Internal Server Error\nRetry-After: 120",
            },
        ]
    }
}

impl Rule for RetryAfterStatusValid {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
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
            // `Retry-After` is defined among §10.2's response context fields and its
            // own sentence names the server as the sender, which is why this rule
            // reads the response and never the request. A request carrying the field
            // is not reported: §10.2 places it among response fields but no sentence
            // forbids a client from sending it, and this rule reports only what a
            // sentence measures.
            // cite(RFC 9110 § 10.2.3): "Servers send the "Retry-After" header field to indicate how long the user agent ought to wait before making a follow-up request."
            let resp = tx.response.as_ref()?;

            // Presence is the entire input: this rule asks which status the field
            // arrived on and never what the value says. `retry_after_date_or_delay`
            // owns `Retry-After = HTTP-date / delay-seconds` and the repeated-field-line
            // check, so neither is transcribed here — and for the same reason nothing is
            // joined across field lines: a value spread over two lines, or written twice,
            // is still one presence on one status.
            resp.headers.get_all("retry-after").iter().next()?;

            let status = resp.status;
            if status_defines_retry_after(status) {
                return None;
            }

            // No sentence makes this a violation, and the cited one is why. §10.2.3
            // defines the field generally — a server saying how long to wait before a
            // follow-up request — with no condition on the status code, and its two
            // "When sent with" sentences elaborate two cases rather than closing the
            // set. So the finding is advisory: it reports a field arriving where
            // neither RFC 9110 nor RFC 6585 says what a user agent should do with
            // it, which is an interoperability observation and not a requirement.
            // `description()` says the same where an operator reads it.
            // cite(RFC 9110 § 10.2.3): "Servers send the "Retry-After" header field to indicate how long the user agent ought to wait before making a follow-up request."
            Some(self.cited(&RFC_9110_10_2_3, ctx.severity, format!(
                    "Retry-After arrived on status {status}, which neither RFC 9110 nor RFC 6585 pairs with \
                     this field; the two documents pair it with any 3xx redirection, 413 Content Too Large, \
                     429 Too Many Requests, and 503 Service Unavailable. No requirement forbids sending it \
                     here — the field's own definition puts no condition on the status code — so a client is \
                     simply not told what to do with it"
                )))
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &RetryAfterStatusValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Every fixture is a response on some status, carrying the field or not.
    fn response_with(
        status: u16,
        retry_after: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let pairs: Vec<(&str, &str)> = retry_after
            .into_iter()
            .map(|v| ("retry-after", v))
            .collect();
        crate::test_helpers::make_test_transaction_with_response(status, &pairs)
    }

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = RetryAfterStatusValid;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[rstest]
    #[case(503, true, false)]
    #[case(429, true, false)]
    #[case(301, true, false)]
    #[case(308, true, false)]
    #[case(300, true, false)]
    #[case(399, true, false)]
    // §15.5.14 asks a temporary 413 for this field by name; reporting it reported a
    // server following a SHOULD in the same document.
    #[case(413, true, false)]
    #[case(200, true, true)]
    #[case(500, true, true)]
    // 414 is 413's neighbour in §15.5 and says nothing about the field.
    #[case(414, true, true)]
    #[case(200, false, false)]
    #[case(413, false, false)]
    fn retry_after_status_semantics(
        #[case] status: u16,
        #[case] with_retry_after: bool,
        #[case] expect_violation: bool,
    ) {
        let tx = response_with(status, with_retry_after.then_some("120"));
        let v = judge(&tx);
        assert_eq!(v.is_some(), expect_violation, "{status} -> {v:?}");
    }

    /// The 3xx arm is a class, not a list of the redirect statuses anyone remembers.
    #[rstest]
    #[case(299, true)]
    #[case(300, false)]
    #[case(304, false)]
    #[case(399, false)]
    #[case(400, true)]
    fn the_3xx_arm_covers_the_class(#[case] status: u16, #[case] expect_violation: bool) {
        let v = judge(&response_with(status, Some("30")));
        assert_eq!(v.is_some(), expect_violation, "{status} -> {v:?}");
    }

    #[test]
    fn no_response_no_violation() {
        let rule = RetryAfterStatusValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn id_and_scope() {
        let rule = RetryAfterStatusValid;
        assert_eq!(rule.id(), "retry_after_status_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["retry_after_status_valid"]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    /// The message is derived data: it names the status it was reached for and the
    /// four statuses the rule accepts. Both are claims, so both are pinned.
    #[test]
    fn violation_message_names_the_status_and_the_defined_set() {
        let v = judge(&response_with(500, Some("60"))).expect("expected violation");
        assert!(v.message.contains("status 500"), "{}", v.message);
        for named in ["3xx", "413", "429", "503"] {
            assert!(v.message.contains(named), "{named} missing: {}", v.message);
        }
    }

    /// Every published snippet is run through the rule.
    #[test]
    fn published_examples_are_judged_by_this_rule() {
        use crate::rules::{Compliance, RuleMeta as _};
        let rule = RetryAfterStatusValid;

        for ex in rule.examples() {
            let mut status = None;
            let mut pairs: Vec<(&str, &str)> = Vec::new();
            for (i, line) in ex.snippet.lines().enumerate() {
                if i == 0 {
                    let code = line
                        .strip_prefix("HTTP/1.1 ")
                        .and_then(|rest| rest.split_whitespace().next())
                        .and_then(|code| code.parse::<u16>().ok())
                        .unwrap_or_else(|| {
                            panic!("the first line of an example is its status line: {line:?}")
                        });
                    status = Some(code);
                    continue;
                }
                let (name, value) = line.split_once(':').unwrap_or_else(|| {
                    panic!("example header line is not `Name: value`: {line:?}")
                });
                pairs.push((name, value.trim()));
            }
            let status = status.expect("example has a status line");
            assert!(
                pairs
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("retry-after")),
                "example carries no Retry-After field, so this rule cannot judge it: {}",
                ex.snippet
            );

            let tx = crate::test_helpers::make_test_transaction_with_response(status, &pairs);
            let v = judge(&tx);
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => assert!(v.is_some(), "{}", ex.snippet),
            }
        }
    }
}
