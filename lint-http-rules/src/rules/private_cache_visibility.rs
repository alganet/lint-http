// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure responses marked `Cache-Control: private` are not reused by a
/// different client, which would indicate a shared cache has stored the
/// representation in violation of RFC 9111 §5.2.2.7.
///
/// The rule watches conditional requests and looks back through the history
/// for the same resource across all clients.  If the current request carries a
/// validator (ETag or Last-Modified) that was previously seen in the response
/// to a *different* client and that response included a `private` directive,
/// we report a violation.  Such a conditional request is strong evidence that
/// a shared cache has handed off a private response to another client.
pub struct PrivateCacheVisibility;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_5_2_2_7: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("5.2.2.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.7",
    note: "`private` — a shared cache MUST NOT store an unqualified-private response",
};

impl Rule for PrivateCacheVisibility {
    fn id(&self) -> &'static str {
        "private_cache_visibility"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // need to observe both the current request and past responses
        crate::rules::RuleScope::Both
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
            // Only conditional requests are evidence: a precondition header carries a validator a
            // client could only have from a prior response.
            // cite(RFC 9111 § 4.3.1): "It then updates that request with one or more precondition header fields."
            let has_if_none_match = tx.request.headers.contains_key("if-none-match");
            let has_if_modified_since = tx.request.headers.contains_key("if-modified-since");
            if !has_if_none_match && !has_if_modified_since {
                return None;
            }

            // The validators other clients were handed under an *unqualified*
            // `private` — the exact-name match excludes the qualified
            // `private="field"` form, which lets a shared cache store the rest,
            // matching the cite's "unqualified" wording.
            //
            // Collecting them up front is what makes each validator the request
            // presents one comparison below, rather than a walk of the history
            // nested inside a walk of the members inside a walk of the field
            // lines.
            let private_responses = || {
                history
                    .responses()
                    .filter(|(past, _)| past.client != tx.client)
                    .filter(|(_, resp)| {
                        crate::helpers::cache_control::has_unqualified(&resp.headers, "private")
                    })
            };
            let private_etags: Vec<String> = private_responses()
                .filter_map(|(_, resp)| {
                    crate::helpers::headers::get_header_str(&resp.headers, "etag")
                })
                .map(crate::helpers::validator::normalize_etag)
                .collect();
            let private_last_modified: Vec<chrono::DateTime<chrono::Utc>> = private_responses()
                .filter_map(|(_, resp)| {
                    crate::http_date::header_timestamp(&resp.headers, "last-modified")
                })
                .collect();

            // Heuristic: a validator from a `private` response turning up in a
            // *different* client's request suggests a shared cache stored what only
            // one user was to hold. The cite grounds *why that is forbidden*; the
            // inference is the linter's — an ETag identifies a representation, not a
            // user, so two clients that fetched the same private representation
            // directly from the origin share it legitimately.
            // cite(RFC 9111 § 5.2.2.7): "The unqualified private response directive indicates that a shared cache MUST NOT store the response (i.e., the response is intended for a single user)."
            for member in tx
                .request
                .headers
                .get_all("if-none-match")
                .iter()
                .filter_map(|hv| hv.to_str().ok())
                .flat_map(crate::helpers::list::list_members)
            {
                if private_etags.contains(&crate::helpers::validator::normalize_etag(member)) {
                    return Some(self.cited(
                        &RFC_9111_5_2_2_7,
                        ctx.severity,
                        format!(
                            "Validator '{}' from a private response seen by a different client",
                            member
                        ),
                    ));
                }
            }

            // Same heuristic and cite as the ETag branch above, compared as
            // timestamps so two spellings of one instant still match.
            // cite(RFC 9111 § 5.2.2.7): "The unqualified private response directive indicates that a shared cache MUST NOT store the response (i.e., the response is intended for a single user)."
            for candidate in tx
                .request
                .headers
                .get_all("if-modified-since")
                .iter()
                .filter_map(|hv| hv.to_str().ok())
                .map(str::trim)
            {
                let Ok(candidate_dt) = crate::http_date::parse_http_date_to_datetime(candidate)
                else {
                    continue;
                };
                if private_last_modified.contains(&candidate_dt) {
                    return Some(self.cited(
                        &RFC_9111_5_2_2_7,
                        ctx.severity,
                        format!(
                            "Validator '{}' from a private response seen by a different client",
                            candidate
                        ),
                    ));
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Stateful private cache visibility")
    }

    fn description(&self) -> &'static str {
        "Responses with `Cache-Control: private` are intended for a single user agent's private cache and **must not be stored or served** by shared caches (RFC 9111 §5.2.2.7).  If a shared cache accidentally retains such a response, other clients may later receive the representation, violating privacy and correctness expectations.\n\nThis stateful rule examines a sequence of transactions for the same resource across **all clients**.  When a request includes a conditional validator (ETag or Last-Modified) that matches a value previously seen in a response carrying the `private` directive **and** that earlier response was sent to a **different** client, we infer that some intermediate cache reused the private entry.  A warning is emitted in that case.\n\nThe rule relies on a cross-client history; the engine handles this by scoping the query to all clients for the resource rather than the default per-client history.  Only conditional requests trigger the check, since they provide tangible evidence that a particular validator value was reused."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_5_2_2_7]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— another client revalidates using a private response"),
                snippet: "> GET /secret HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: private\n< ETag: \"s1\"\n\n# later, a different client sends a conditional request using that ETag\n> GET /secret HTTP/1.1\n> Host: example.com\n> If-None-Match: \"s1\"   # value originated in private response for another client",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— only same client reuses the validator"),
                snippet: "> GET /secret HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: private\n< ETag: \"s1\"\n\n# the same client later revalidates\n> GET /secret HTTP/1.1\n> Host: example.com\n> If-None-Match: \"s1\"   # acceptable, private cache may retain its own entry",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &PrivateCacheVisibility;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_prev(
        client: crate::state::ClientIdentifier,
        cc: Option<&str>,
        etag: Option<&str>,
        last_mod: Option<&str>,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        prev.request.method = "GET".to_string();
        prev.request.uri = "/resource".to_string();
        prev.client = client;
        prev.timestamp = ts;
        if let Some(ccv) = cc {
            prev.response
                .as_mut()
                .unwrap()
                .headers
                .append("cache-control", ccv.parse().unwrap());
        }
        if let Some(et) = etag {
            prev.response
                .as_mut()
                .unwrap()
                .headers
                .append("etag", et.parse().unwrap());
        }
        if let Some(lm) = last_mod {
            prev.response
                .as_mut()
                .unwrap()
                .headers
                .append("last-modified", lm.parse().unwrap());
        }
        prev
    }

    #[test]
    fn no_violation_without_history() {
        let rule = PrivateCacheVisibility;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("if-none-match", "\"a\"".parse().unwrap());
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "private_cache_visibility"
            ]),
        )
        .is_none());
    }

    #[test]
    fn same_client_private_not_flagged() {
        let rule = PrivateCacheVisibility;
        let ts = Utc::now();
        let client = crate::test_helpers::make_test_client();

        let prev = make_prev(client.clone(), Some("private"), Some("\"a\""), None, ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client.clone();
        tx.request
            .headers
            .append("if-none-match", "\"a\"".parse().unwrap());
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "private_cache_visibility"
            ]),
        )
        .is_none());
    }

    #[test]
    fn private_from_other_client_flagged_etag() {
        let rule = PrivateCacheVisibility;
        let ts = Utc::now();
        let client1 = crate::test_helpers::make_test_client();
        let mut client2 = client1.clone();
        client2.user_agent = "other".to_string();

        let prev = make_prev(client2.clone(), Some("private"), Some("\"a\""), None, ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client1.clone();
        tx.request
            .headers
            .append("if-none-match", "\"a\"".parse().unwrap());
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "private_cache_visibility",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Validator '"));
    }

    #[test]
    fn private_from_other_client_flagged_last_modified() {
        let rule = PrivateCacheVisibility;
        let ts = Utc::now();
        let client1 = crate::test_helpers::make_test_client();
        let mut client2 = client1.clone();
        client2.user_agent = "other".to_string();

        let lm = "Wed, 21 Oct 2015 07:28:00 GMT";
        let prev = make_prev(client2.clone(), Some("private"), None, Some(lm), ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client1.clone();
        tx.request
            .headers
            .append("if-modified-since", lm.parse().unwrap());
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "private_cache_visibility",
            ]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn non_private_from_other_client_not_flagged() {
        let rule = PrivateCacheVisibility;
        let ts = Utc::now();
        let client1 = crate::test_helpers::make_test_client();
        let mut client2 = client1.clone();
        client2.user_agent = "other".to_string();

        let prev = make_prev(client2.clone(), None, Some("\"a\""), None, ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client1.clone();
        tx.request
            .headers
            .append("if-none-match", "\"a\"".parse().unwrap());
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "private_cache_visibility"
            ]),
        )
        .is_none());
    }
}
