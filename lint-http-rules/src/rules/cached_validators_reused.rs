// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::conditional::CONDITIONAL_MISSING;
use crate::violations::ViolationDef;

/// One entry: a repeat request that declined the validator it was given.
static DECLARED: &[&ViolationDef] = &[&CONDITIONAL_MISSING];

pub struct CachedValidatorsReused;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_13_1_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2",
    note: "If-None-Match — a client SHOULD send it for stored responses that have entity tags when making a GET request",
};
const RFC_9110_13_1_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3",
    note: "If-Modified-Since — typically used for efficient cache updates (no client obligation to send; the Last-Modified path here is a heuristic)",
};

impl RuleMeta for CachedValidatorsReused {
    fn id(&self) -> &'static str {
        "cached_validators_reused"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "This rule checks if the client correctly uses conditional headers (`If-None-Match`, `If-Modified-Since`, or `If-Range`) when re-requesting a resource it has previously fetched.\n\nIf a server provides validators (like `ETag` or `Last-Modified`) in a response, a well-behaved client should use them in subsequent requests for the same resource to allow the server to return a `304 Not Modified` response, saving bandwidth and processing time.\n\n**An offer no cache was allowed to accept is not one that was declined.** RFC 9111 §3 decides whether the earlier exchange left a stored response at all, and a `no-store` on either of its two messages — the response's (§5.2.2.5) or the request's (§5.2.1.5) — answers no. The `ETag` beside such a directive reached no store, so the round trip this rule calls avoidable could not have been a `304`, and the rule stays silent."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_13_1_2, RFC_9110_13_1_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// The SHOULD is on the client's request; the prior response is read only
    /// to learn whether a validator was offered.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Request"),
                snippet: "GET /image.png HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Request"),
                snippet: "HTTP/1.1 200 OK\nETag: \"abcdef12345\"\nContent-Length: 1024",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Request"),
                snippet:
                    "GET /image.png HTTP/1.1\nHost: example.com\nIf-None-Match: \"abcdef12345\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Request"),
                snippet: "GET /image.png HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Request"),
                snippet: "HTTP/1.1 200 OK\nETag: \"abcdef12345\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Request"),
                snippet:
                    "GET /image.png HTTP/1.1\nHost: example.com\n# Missing If-None-Match header!",
            },
        ]
    }
}

impl Rule for CachedValidatorsReused {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // Only GET/HEAD re-requests are in scope. If-None-Match / If-Modified-Since
            // are the cache-revalidation preconditions, and RFC 9110 §13.1.2's client
            // SHOULD is written "when making a GET request". On other methods a validator
            // is carried by If-Match / If-Unmodified-Since instead, so a POST/PUT that
            // omits If-None-Match is not the omission this rule is about.
            let method = tx.request.method.to_ascii_uppercase();
            if method != "GET" && method != "HEAD" {
                return None;
            }

            // Use the previous transaction passed by the linter (if any). History is
            // scoped to this (client, resource) pair by the rule's ByResource query.
            let previous_tx = history.previous()?;
            let resp = previous_tx.response.as_ref()?;

            // A validator is an offer, and § 3 decides whether it was ever
            // taken up. A response carrying `no-store` is one no cache was
            // permitted to hold, so its `ETag` reached no store and the round
            // trip this rule calls avoidable could not have been a `304`. The
            // entry reads "a repeat request declines a validator the server
            // provided"; on such a response nothing was provided to decline.
            // cite(RFC 9111 § 3): "A cache MUST NOT store a response to a request unless:"
            if !crate::helpers::stored_response::storage_allowed(
                &previous_tx.request.headers,
                &resp.headers,
            ) {
                return None;
            }

            // The rule only has a case to make if the prior response gave the client a
            // validator to revalidate with: an ETag (If-None-Match) or a Last-Modified
            // date (If-Modified-Since). Without one there is nothing to omit. This also
            // assumes the client stored that response — the linter cannot see its cache,
            // so a validator on the most recent response for this resource is the proxy.
            let has_validators =
                resp.headers.contains_key("etag") || resp.headers.contains_key("last-modified");

            if !has_validators {
                return None;
            }

            // Check if client is using conditional headers
            let has_if_none_match = tx.request.headers.contains_key("if-none-match");
            let has_if_modified_since = tx.request.headers.contains_key("if-modified-since");

            // `If-Range` is the third field a stored entity tag goes back in, and on a
            // range request it is the only one that can carry it: RFC 9110 §13.1.5 bars
            // the field from a request with no `Range`, and `If-None-Match` on a range
            // request asks for a `304` instead of the bytes, which is not what a client
            // resuming a download is asking for. So a resumed download conditioned on
            // the validator it was given spells that with `If-Range` and cannot spell it
            // any other way. This rule read only the two cache-revalidation fields and
            // called that request unconditional, which named a client that used the
            // validator as one that declined it -- the same reasoning the method gate
            // above already makes for `If-Match`/`If-Unmodified-Since`, one axis over.
            // cite(RFC 9111 § 4.3.1): "MUST send the relevant entity tags (using If-Match, If-None-Match, or If-Range) if the entity tags were provided in the stored response(s) being validated."
            let has_if_range = tx.request.headers.contains_key("if-range");

            // The governing SHOULD, on the ETag/GET path. The Last-Modified-only case is
            // an efficiency heuristic rather than a SHOULD: §13.1.3 describes
            // If-Modified-Since as "typically used" to allow efficient cache updates but
            // states no client obligation to send it (its SHOULDs are all on the origin
            // server). HEAD rides the same efficiency argument, one method past §13.1.2's
            // literal "GET request".
            // cite(RFC 9110 § 13.1.2): "When a client desires to update one or more stored responses that have entity tags, the client SHOULD generate an If-None-Match header field containing a list of those entity tags when making a GET request"
            // cite(RFC 9110 § 13.1.3): "If-Modified-Since is typically used for two distinct purposes: 1) to allow efficient updates of a cached representation that does not have an entity tag"
            if !has_if_none_match && !has_if_modified_since && !has_if_range {
                Some(ctx.report_with(
                    &CONDITIONAL_MISSING,
                    format!(
                        "Client re-requesting resource without conditional headers. \
                         Server provided validators (ETag: {}, Last-Modified: {}) but client \
                         is not using If-None-Match or If-Modified-Since headers.",
                        resp.headers
                            .get("etag")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("none"),
                        resp.headers
                            .get("last-modified")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("none")
                    ),
                ))
            } else {
                None
            }
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CachedValidatorsReused;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ClientIdentifier;
    use crate::state::StateStore;
    use rstest::rstest;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_client() -> ClientIdentifier {
        ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "test-client/1.0".to_string(),
        )
    }

    #[rstest]
    #[case(None, vec![], false)]
    #[case(Some(vec![("etag", "\"abc123\"")]), vec![("if-none-match","\"abc123\"")], false)]
    #[case(Some(vec![("etag", "\"abc123\"")]), vec![], true)]
    #[case(Some(vec![("last-modified", "Mon, 01 Jan 2020 00:00:00 GMT")]), vec![], true)]
    #[case(Some(vec![]), vec![], false)]
    // A resumed download conditioned on the entity tag it was given. `If-Range`
    // is the only field that can carry it here, so this is the conditional
    // request the entry asks for and not the omission it names.
    #[case(
        Some(vec![("etag", "\"abc123\"")]),
        vec![("range", "bytes=100-199"), ("if-range", "\"abc123\"")],
        false
    )]
    // The same request with the validator left off is still the omission: what
    // the gate above turns on is the precondition, never the `Range` beside it.
    #[case(Some(vec![("etag", "\"abc123\"")]), vec![("range", "bytes=100-199")], true)]
    // `If-Range` carrying a date, the other half of `entity-tag / HTTP-date`.
    #[case(
        Some(vec![("last-modified", "Mon, 01 Jan 2020 00:00:00 GMT")]),
        vec![("range", "bytes=0-99"), ("if-range", "Mon, 01 Jan 2020 00:00:00 GMT")],
        false
    )]
    // § 3 is asked before the offer. A response carrying `no-store` reached no
    // store, so the `ETag` on it was never in the client's hands and the round
    // trip this entry calls avoidable could not have been a `304`.
    #[case(
        Some(vec![("etag", "\"abc123\""), ("cache-control", "no-store")]),
        vec![],
        false
    )]
    #[case(
        Some(vec![
            ("etag", "\"abc123\""),
            ("cache-control", "no-cache, no-store, must-revalidate"),
        ]),
        vec![],
        false
    )]
    // The boundary: the same offer with `no-store` taken out is declined
    // exactly as before, so the reading is about storage and not about the
    // length of a `Cache-Control` line.
    #[case(
        Some(vec![
            ("etag", "\"abc123\""),
            ("cache-control", "no-cache, must-revalidate"),
        ]),
        vec![],
        true
    )]
    fn check_request_cases(
        #[case] prev_resp_headers: Option<Vec<(&str, &str)>>,
        #[case] req_headers_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = CachedValidatorsReused;
        let store = StateStore::new(300, 10);
        let client = make_client();
        let resource = "http://example.com/api/data";

        // Record previous response if provided
        if let Some(pairs) = prev_resp_headers {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &pairs);
            tx.client = client.clone();
            tx.request.uri = resource.to_string();
            store.record_transaction(&tx);
        }

        // build request headers from pairs when needed (assigned later into transaction)
        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.client = client.clone();
        tx.request.uri = resource.to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(req_headers_pairs.as_slice());
        let history = crate::queries::by_resource::by_resource(&store, &client, resource);
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            let v = violation.ok_or_else(|| anyhow::anyhow!("expected violation"))?;
            assert_eq!(v.rule, "cached_validators_reused");
            // The entry names no sentence and defaults to `info`: nothing
            // requires a client to make a request conditional, and an `ETag` is
            // an offer rather than an instruction.
            assert_eq!(v.violation, "conditional_missing");
            assert_eq!(v.severity, crate::lint::Severity::Info);
            assert!(v.message.contains("conditional headers"));
        } else {
            assert!(violation.is_none());
        }

        Ok(())
    }

    /// The directive on the earlier *request* has the same effect, one section
    /// over: § 5.2.1.5 keeps a cache from storing any part of that request or
    /// any response to it, so the validator the response offered reached no
    /// store either.
    #[test]
    fn a_request_that_forbade_storing_leaves_no_validator_to_decline() -> anyhow::Result<()> {
        let rule = CachedValidatorsReused;
        let store = StateStore::new(300, 10);
        let client = make_client();
        let resource = "http://example.com/api/no_store_request";

        let mut prev = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("etag", "\"abc123\"")],
        );
        prev.client = client.clone();
        prev.request.uri = resource.to_string();
        prev.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("cache-control", "no-store")]);
        store.record_transaction(&prev);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client.clone();
        tx.request.uri = resource.to_string();
        let history = crate::queries::by_resource::by_resource(&store, &client, resource);
        assert!(
            crate::test_helpers::run_rule(
                &rule,
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .is_none(),
            "no cache held that response, so its ETag was never on offer"
        );
        Ok(())
    }

    #[test]
    fn previous_without_response_returns_none() -> anyhow::Result<()> {
        let rule = CachedValidatorsReused;
        let store = StateStore::new(300, 10);
        let client = make_client();
        let resource = "http://example.com/api/no_resp";

        // Record a previous transaction that has no response
        let mut prev_tx = crate::test_helpers::make_test_transaction();
        prev_tx.client = client.clone();
        prev_tx.request.uri = resource.to_string();
        store.record_transaction(&prev_tx);

        // Build a fresh request transaction
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client.clone();
        tx.request.uri = resource.to_string();

        let history = crate::queries::by_resource::by_resource(&store, &client, resource);
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        assert!(violation.is_none());
        Ok(())
    }

    #[test]
    fn non_get_rerequest_is_not_flagged() -> anyhow::Result<()> {
        // A POST re-request of a resource whose prior response carried an ETag is
        // not expected to carry If-None-Match — that is not the validation this
        // rule is about, so it must not fire.
        let rule = CachedValidatorsReused;
        let store = StateStore::new(300, 10);
        let client = make_client();
        let resource = "http://example.com/api/data";

        let mut prev = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("etag", "\"abc123\"")],
        );
        prev.client = client.clone();
        prev.request.uri = resource.to_string();
        store.record_transaction(&prev);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client.clone();
        tx.request.uri = resource.to_string();
        tx.request.method = "POST".to_string();

        let history = crate::queries::by_resource::by_resource(&store, &client, resource);
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(violation.is_none(), "POST re-request must not be flagged");
        Ok(())
    }

    #[test]
    fn needs_no_response() {
        let r = CachedValidatorsReused;
        assert!(!crate::rules::Rule::needs_response(&r));
    }
}
