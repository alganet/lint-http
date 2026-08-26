// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct UserAgentPresent;

impl Rule for UserAgentPresent {
    fn id(&self) -> &'static str {
        "user_agent_present"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // The field describes the originator of a request, so a response has no
        // occasion to carry one. The sentence that asks for it asks a *user
        // agent*, and in this specification that is any client program at all --
        // a command-line tool and a firmware update script are inside the
        // requirement exactly as a browser is, which is the first thing an
        // operator asks when an API client is reported.
        // cite(RFC 9110 § 10.1.5): "The "User-Agent" header field contains information about the user agent originating the request"
        // cite(RFC 9110 § 3.5): "The term "user agent" refers to any of the various client programs that initiate a request."
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // A sentence does ask for the field, and it is a SHOULD -- but it ends
        // in a condition about the sender's configuration, and a request that
        // omits the field because it was told to is byte-for-byte a request that
        // omits it. The exception is therefore not decidable here, and it is not
        // approximated either: the finding is reported for both, and the
        // description tells the operator which two cases it cannot separate.
        // cite(RFC 9110 § 10.1.5): "A user agent SHOULD send a User-Agent header field in each request unless specifically configured not to do so."
        //
        // Only the header section answers that sentence. A `User-Agent` arriving
        // in `tx.request.trailers` would be a violation of the sentence below --
        // §10.1.5 nowhere permits the field in trailers -- rather than a way to
        // satisfy this one, so the trailer section is deliberately not consulted.
        // cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
        //
        // Presence is the whole question. A field line that is present and empty
        // is not a missing field; it is a field that fails the production below,
        // and `message_user_agent_token_valid` -- which owns that grammar and
        // ships enabled -- reports it as one. Answering "missing" here would name
        // the wrong defect and report one field twice.
        // cite(RFC 9110 § 10.1.5): "The User-Agent field value consists of one or more product identifiers, each followed by zero or more comments (Section 5.6.5), which together identify the user agent software and its significant subproducts."
        if !tx.request.headers.contains_key("user-agent") {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request missing User-Agent header".into(),
            })
        } else {
            None
        }
    }

    fn title(&self) -> Option<&'static str> {
        Some("Client User-Agent Present")
    }

    fn description(&self) -> &'static str {
        "Report a request that carries no `User-Agent` header field. RFC 9110 §10.1.5 makes sending one a `SHOULD`, in each request, and it asks it of a *user agent* — which in that specification is any client program that initiates a request, so a command-line tool or a firmware update script is inside the requirement and not only a browser.\n\nThe requirement ends in an exception: *unless specifically configured not to do so*. That condition is a property of the client's configuration, and a request that omits the field on purpose is indistinguishable from one that omits it by oversight, so both are reported. A deployment that suppresses the field deliberately — §17.13 describes what a `User-Agent` can contribute to identifying a specific device — is conforming, and should turn this rule off rather than read the finding as a defect.\n\nOnly the header section is examined. A `User-Agent` field line that is present but empty is not reported here: it is a field that fails the field's own grammar, and `message_user_agent_token_valid` owns and reports that."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("10.1.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5",
                note: "`A user agent SHOULD send a User-Agent header field in each request unless specifically configured not to do so.` The exception is a fact about the sender's configuration rather than about the request, so a conforming suppression and a plain omission are the same absence here and both are reported",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("3.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-3.5",
                note: "a user agent is any client program that initiates a request — browsers, spiders, command-line tools, appliances, firmware update scripts — so the requirement is not a browser requirement",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("17.13"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-17.13",
                note: "why a client is configured not to send the field: a `User-Agent` might carry enough information to identify a specific device, usually combined with other characteristics, and reducing that fingerprint is a deliberate choice this rule cannot see",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("a product identifier, with a comment after it"),
                snippet: "GET /api/data HTTP/1.1\nHost: example.com\nUser-Agent: MyClient/1.0 (Linux; x64)",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("the value RFC 9110 prints for the field"),
                snippet: "GET /api/data HTTP/1.1\nHost: example.com\nUser-Agent: CERN-LineMode/2.15 libwww/2.17b3",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("no User-Agent field line"),
                snippet: "GET /api/data HTTP/1.1\nHost: example.com\nAccept: application/json",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &UserAgentPresent;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(vec![], true, Some("Request missing User-Agent header"))]
    #[case(vec![("user-agent", "curl/7.68.0")], false, None)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = UserAgentPresent;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&header_pairs);
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            assert!(violation.is_some());
            assert_eq!(
                violation.map(|v| v.message),
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = UserAgentPresent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    /// The decline recorded at the check: an empty field line is present, so it
    /// is not this rule's finding — and it is not silence either, because the
    /// rule that owns the grammar reports it. Both halves are asserted, since
    /// the first is only defensible while the second holds.
    #[test]
    fn an_empty_field_line_is_left_to_the_rule_that_owns_the_grammar() {
        use crate::rules::message_user_agent_token_valid::MessageUserAgentTokenValid;

        let tx = crate::test_helpers::make_test_transaction_with_headers(&[("user-agent", "")]);
        let history = crate::transaction_history::TransactionHistory::empty();

        let presence = UserAgentPresent;
        assert!(
            presence
                .check_transaction(
                    &tx,
                    &history,
                    &crate::test_helpers::make_test_config_with_enabled_rules(&[presence.id()]),
                )
                .is_none(),
            "an empty field line is present, not missing"
        );

        let grammar = MessageUserAgentTokenValid;
        let found = grammar.check_transaction(
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[grammar.id()]),
        );
        assert!(
            found.is_some(),
            "the grammar owner must report what this rule declines"
        );
    }

    /// The field lines of an example, with its start line dropped — and the
    /// drop is load-bearing, so it is checked rather than assumed. Every example
    /// here is a request, and the fields below the start line are filed onto the
    /// request for that reason. A response-shaped example added later would have
    /// its status line discarded in the same silence and its fields put where
    /// this rule cannot see them, which would let a `NonCompliant` example
    /// satisfy a guard by being invisible to it. Both guards parse through here
    /// so neither can be the one that forgets.
    fn published_fields(snippet: &str) -> Vec<(&str, &str)> {
        let mut lines = snippet.lines();
        let start = lines.next().expect("an example has a start line");
        assert!(
            !start.starts_with("HTTP/"),
            "a response-shaped example cannot be checked by these guards: {start:?}"
        );
        lines
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                l.split_once(": ")
                    .unwrap_or_else(|| panic!("not a header line: {l:?}"))
            })
            .collect()
    }

    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = UserAgentPresent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut saw_a_finding = false;
        for ex in rule.examples() {
            let pairs = published_fields(ex.snippet);
            let tx = crate::test_helpers::make_test_transaction_with_headers(&pairs);
            let found = rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );

            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
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
        assert!(saw_a_finding, "no published example produced a finding");
    }

    /// A presence-only rule cannot catch a bad value in its own example: every
    /// value it publishes is invisible to it beyond being there at all. So the
    /// published values are judged by the rule that owns the grammar.
    #[test]
    fn published_values_satisfy_the_rule_that_owns_the_grammar() {
        use crate::rules::message_user_agent_token_valid::MessageUserAgentTokenValid;
        use crate::rules::{Compliance, Rule as _};

        let grammar = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[grammar.id()]);

        for ex in UserAgentPresent.examples() {
            if ex.compliance != Compliance::Compliant {
                continue;
            }
            let pairs = published_fields(ex.snippet);
            let tx = crate::test_helpers::make_test_transaction_with_headers(&pairs);
            let found = grammar.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            assert!(
                found.is_none(),
                "a Compliant example publishes a value the grammar rejects {:?}: {found:?}",
                ex.snippet
            );
        }
    }
}
