// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::status::RFC_9110_15_3_1;
use crate::violations::validator::{
    RFC_9110_3_2, RFC_9110_8_8_2_1, RFC_9110_8_8_3_1, VALIDATOR_MISSING,
};
use crate::violations::ViolationDef;

/// One entry: a response that hands a later request nothing to condition on.
static DECLARED: &[&ViolationDef] = &[&VALIDATOR_MISSING];

pub struct EtagOrLastModifiedPresent;

// The sections this rule names now live on the subject beside the entries that
// quote them, and are imported back for `specifications()`.

impl RuleMeta for EtagOrLastModifiedPresent {
    fn id(&self) -> &'static str {
        "etag_or_last_modified_present"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server ETag or Last-Modified Present")
    }

    fn description(&self) -> &'static str {
        "This rule checks if `200 OK` responses to `GET` and `HEAD` include either an `ETag` or a `Last-Modified` header.\n\nThese headers act as validators, allowing clients to perform conditional requests (`If-None-Match` or `If-Modified-Since`). This enables efficient caching and revalidation, significantly reducing bandwidth when resources haven't changed.\n\nOnly a `GET` or a `HEAD` is asked, because both sentences the rule rests on are about the *selected representation* — what RFC 9110 §3.2 defines as the representation a `GET` would select, and the thing a conditional request is evaluated against. §15.3.1 tabulates what a `200`'s content is for every other method: the status of an action for `POST`, `PUT` and `DELETE`, the communication options for `OPTIONS`, the request echoed back for `TRACE`. None of those is a representation a later request could validate, and a `200` to `OPTIONS` or `TRACE` is not cacheable at all (§9.3.7, §9.3.8), so no validator was owed on them. A `POST` response that names its own target in `Content-Location` is the one cacheable exception (§9.3.3) and is not read; it stays silent here."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_8_8_2_1,
            RFC_9110_8_8_3_1,
            RFC_9110_3_2,
            RFC_9110_15_3_1,
        ]
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
                label: Some("Response (ETag)"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: image/png\nETag: \"33a64df551425fcc55e4d42a148795d9f25f89d4\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response (Last-Modified)"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/html\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: image/png\n# Missing both ETag and Last-Modified",
            },
        ]
    }
}

impl Rule for EtagOrLastModifiedPresent {
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
            let Some(resp) = &tx.response else {
                return None;
            };
            let status = resp.status;
            // Both sentences below are about the *selected representation*: the one a
            // GET would select, and the thing a conditional request is evaluated
            // against. A 200 carries it only when it answers a GET or a HEAD; § 15.3.1
            // tabulates what the content is for every other method — the status of an
            // action, the communication options, the request echoed back — and none of
            // those is something a later request could validate, so no validator was
            // owed. A 200 to OPTIONS or TRACE is not even cacheable, so the full
            // transfer the finding warns of was never avoidable there.
            // cite(RFC 9110 § 3.2): "This "selected representation" provides the data and metadata for evaluating conditional requests (Section 13)"
            // cite(RFC 9110 § 15.3.1): "The content sent in a 200 response depends on the request method."
            // cite(RFC 9110 § 9.3.7): "Responses to the OPTIONS method are not cacheable."
            // cite(RFC 9110 § 9.3.8): "Responses to the TRACE method are not cacheable."
            if !matches!(tx.request.method.as_str(), "GET" | "HEAD") {
                return None;
            }
            // A 200 with no validator cannot be revalidated: every later request for it is a
            // full transfer, and a conditional request has nothing to be conditional on. The rule
            // accepts *either* validator, so it rests on both parallel SHOULD-send sentences.
            // (It flags every validator-less 200, not only those where a modification date /
            // change detection "can be reasonably and consistently determined" — a stricter
            // default than the conditioned SHOULDs, recorded in the tracker.)
            // cite(RFC 9110 § 8.8.2.1): "An origin server SHOULD send Last-Modified for any selected representation for which a last modification date can be reasonably and consistently determined"
            // cite(RFC 9110 § 8.8.3.1): "An origin server SHOULD send an ETag for any selected representation for which detection of changes can be reasonably and consistently determined"
            if status == 200
                && !resp.headers.contains_key("etag")
                && !resp.headers.contains_key("last-modified")
            {
                Some(ctx.report(&VALIDATOR_MISSING))
            } else {
                None
            }
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &EtagOrLastModifiedPresent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// The two methods whose 200 carries the selected representation are
    /// asked; a 200 answering anything else carries the status of an action,
    /// the communication options, or the request echoed back, and none of
    /// those has a validator to send.
    #[rstest]
    #[case("GET", 200, &[], true)]
    #[case("HEAD", 200, &[], true)]
    #[case("GET", 200, &[("etag", "\"12345\"")], false)]
    #[case("GET", 200, &[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")], false)]
    #[case("GET", 404, &[], false)]
    #[case("OPTIONS", 200, &[], false)]
    #[case("POST", 200, &[], false)]
    #[case("TRACE", 200, &[], false)]
    #[case("PUT", 200, &[], false)]
    #[case("DELETE", 200, &[], false)]
    fn check_response_validation(
        #[case] method: &str,
        #[case] status: u16,
        #[case] headers: &[(&str, &str)],
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = EtagOrLastModifiedPresent;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(headers),

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            // `info`: the conforming case and the defect are the same bytes,
            // because the exception the sentence carries is not on the wire.
            let found = violation.clone().expect("a finding");
            assert_eq!(found.violation, "validator_missing");
            assert_eq!(found.severity, crate::lint::Severity::Warn);
            assert_eq!(
                violation.map(|v| v.message),
                Some("Response 200 without ETag or Last-Modified validator".to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn check_missing_response() {
        let rule = EtagOrLastModifiedPresent;
        let tx = crate::test_helpers::make_test_transaction();
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(violation.is_none());
    }
}
