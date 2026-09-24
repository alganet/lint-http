// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cache_control::{CACHE_CONTROL_PRIVATE_IGNORED, RFC_9111_5_2_2_7};
use crate::violations::ViolationDef;

/// One entry: a validator from a response meant for one user, arriving from
/// a second.
static DECLARED: &[&ViolationDef] = &[&CACHE_CONTROL_PRIVATE_IGNORED];

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

// The one section this rule names now lives on the `cache_control` subject
// beside the entry that quotes it, and is imported back for `specifications()`.

impl RuleMeta for PrivateCacheVisibility {
    fn id(&self) -> &'static str {
        "private_cache_visibility"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Stateful private cache visibility")
    }

    fn description(&self) -> &'static str {
        "Responses with `Cache-Control: private` are intended for a single user agent's private cache and **must not be stored or served** by shared caches (RFC 9111 §5.2.2.7).  If a shared cache accidentally retains such a response, other clients may later receive the representation, violating privacy and correctness expectations.\n\nThis stateful rule examines a sequence of transactions for the same resource across **all clients**.  When a request includes a conditional validator (ETag or Last-Modified) that matches a value previously seen in a response carrying the `private` directive **and** that earlier response was sent to a **different** client, we infer that some intermediate cache reused the private entry.  A warning is emitted in that case.\n\n**A validator the requesting client was handed itself is not a leak.** An entity tag names a representation, not a user, so two clients that each fetched the private resource from the origin are handed the same tag, and each revalidating with it is its own private cache doing its job. The finding needs the validator to have reached this client from nowhere it could see: only a tag or date that some other client was handed under `private`, and that no response to this client carried, is reported.\n\nThe rule relies on a cross-client history; the engine handles this by scoping the query to all clients for the resource rather than the default per-client history.  Only conditional requests trigger the check, since they provide tangible evidence that a particular validator value was reused."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_5_2_2_7]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **The forbidden storage is a cache's, and the peer that sent the
    /// request is the one holding it.** §5.2.2.7 addresses a shared cache, and
    /// a shared cache is not one of the three values here — but it does not
    /// have to be. What this rule sees is a request presenting a validator
    /// only another user was to hold, and the peer that wrote that request is
    /// the client, whether it is a browser or the cache in front of one. The
    /// `private` directive it disregarded is the yardstick, and the yardstick
    /// is the server's.
    ///
    /// need to observe both the current request and past responses
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
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
                compliance: Compliance::NonCompliant,
                label: Some("— another client resumes a download with that validator"),
                snippet: "> GET /secret HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: private\n< ETag: \"s1\"\n< Accept-Ranges: bytes\n\n# later, a different client resumes using that ETag\n> GET /secret HTTP/1.1\n> Host: example.com\n> Range: bytes=0-9\n> If-Range: \"s1\"   # value originated in private response for another client",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— only same client reuses the validator"),
                snippet: "> GET /secret HTTP/1.1\n> Host: example.com\n\n< HTTP/1.1 200 OK\n< Cache-Control: private\n< ETag: \"s1\"\n\n# the same client later revalidates\n> GET /secret HTTP/1.1\n> Host: example.com\n> If-None-Match: \"s1\"   # acceptable, private cache may retain its own entry",
            },
        ]
    }
}

impl Rule for PrivateCacheVisibility {
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
            //
            // `If-Range` is a third such field and carries the same two kinds of
            // validator — § 13.1.5 writes it as `entity-tag / HTTP-date` — so a
            // second client resuming a download shows a leaked tag exactly as
            // `If-None-Match` does. The evidence this entry rests on is the
            // validator arriving at a client that was never handed it, and the
            // field it arrives in is not part of that.
            // cite(RFC 9111 § 4.3.1): "It then updates that request with one or more precondition header fields."
            // cite(RFC 9110 § 13.1.5): "If-Range = entity-tag / HTTP-date"
            let has_if_none_match = tx.request.headers.contains_key("if-none-match");
            let has_if_modified_since = tx.request.headers.contains_key("if-modified-since");
            let has_if_range = tx.request.headers.contains_key("if-range");
            if !has_if_none_match && !has_if_modified_since && !has_if_range {
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

            // The validators *this* client was handed, by any response. An entity
            // tag names a representation and not a user, so a client that
            // fetched the private resource itself holds the same tag every other
            // client was given, and revalidating with it is its own cache doing
            // its job. What the entry rests on is a validator arriving at a
            // client that was never handed it; one this client was handed is
            // accounted for, whoever else was handed it too.
            let own = || {
                history
                    .responses()
                    .filter(|(past, _)| past.client == tx.client)
            };
            let own_etags: Vec<String> = own()
                .filter_map(|(_, resp)| {
                    crate::helpers::headers::get_header_str(&resp.headers, "etag")
                })
                .map(crate::helpers::validator::normalize_etag)
                .collect();
            let own_last_modified: Vec<chrono::DateTime<chrono::Utc>> = own()
                .filter_map(|(_, resp)| {
                    crate::http_date::header_timestamp(&resp.headers, "last-modified")
                })
                .collect();
            let leaked_etag = |member: &str| {
                let tag = crate::helpers::validator::normalize_etag(member);
                private_etags.contains(&tag) && !own_etags.contains(&tag)
            };
            let leaked_date = |dt: &chrono::DateTime<chrono::Utc>| {
                private_last_modified.contains(dt) && !own_last_modified.contains(dt)
            };

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
                if leaked_etag(member) {
                    return Some(ctx.report_with(
                        &CACHE_CONTROL_PRIVATE_IGNORED,
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
                if leaked_date(&candidate_dt) {
                    return Some(ctx.report_with(
                        &CACHE_CONTROL_PRIVATE_IGNORED,
                        format!(
                            "Validator '{}' from a private response seen by a different client",
                            candidate
                        ),
                    ));
                }
            }

            // The same heuristic and cite once more, for § 13.1.5's single value.
            // It is `entity-tag / HTTP-date`, and the alternative is settled by
            // asking each list rather than by transcribing § 13.1.5's
            // first-three-characters test a second time: a date normalizes to no
            // entity tag we handed out and an entity tag parses as no date, so
            // the value can answer at most one of the two and the question
            // asked is the one this entry is about — was this validator handed
            // to somebody else.
            // cite(RFC 9111 § 5.2.2.7): "The unqualified private response directive indicates that a shared cache MUST NOT store the response (i.e., the response is intended for a single user)."
            // Walked rather than read once: `If-Range` is a singleton, but a
            // sender that repeats it has written a second value, and the leak
            // this entry is about may be the one on the second line.
            for candidate in tx
                .request
                .headers
                .get_all("if-range")
                .iter()
                .filter_map(|hv| hv.to_str().ok())
                .map(str::trim)
            {
                let tag = leaked_etag(candidate);
                let date = crate::http_date::parse_http_date_to_datetime(candidate)
                    .is_ok_and(|dt| leaked_date(&dt));
                if tag || date {
                    return Some(ctx.report_with(
                        &CACHE_CONTROL_PRIVATE_IGNORED,
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
        tx.client = client;
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

    /// § 13.1.5's field carries the same two validators, so a second client
    /// resuming a download shows a leaked one exactly as `If-None-Match` does.
    /// Both kinds are here, and so is the value nobody was handed: the entry is
    /// about the validator having reached a client that was never given it, not
    /// about the field it arrived in.
    #[rstest::rstest]
    #[case(Some("\"a\""), None, "\"a\"", true)]
    #[case(
        None,
        Some("Sun, 06 Nov 1994 08:49:37 GMT"),
        "Sun, 06 Nov 1994 08:49:37 GMT",
        true
    )]
    #[case(Some("\"a\""), None, "\"b\"", false)]
    #[case(
        None,
        Some("Sun, 06 Nov 1994 08:49:37 GMT"),
        "Mon, 07 Nov 1994 08:49:37 GMT",
        false
    )]
    fn a_leak_carried_in_if_range_is_the_same_leak(
        #[case] etag: Option<&str>,
        #[case] last_mod: Option<&str>,
        #[case] if_range: &str,
        #[case] reports: bool,
    ) {
        let rule = PrivateCacheVisibility;
        let ts = Utc::now();
        let client1 = crate::test_helpers::make_test_client();
        let mut client2 = client1.clone();
        client2.user_agent = "other".to_string();

        let prev = make_prev(client2, Some("private"), etag, last_mod, ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client1;
        tx.request
            .headers
            .append("range", "bytes=0-9".parse().unwrap());
        tx.request
            .headers
            .append("if-range", if_range.parse().unwrap());
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![prev]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "private_cache_visibility",
            ]),
        );
        assert_eq!(v.is_some(), reports, "If-Range {if_range}: {v:?}");
    }

    #[test]
    fn private_from_other_client_flagged_etag() {
        let rule = PrivateCacheVisibility;
        let ts = Utc::now();
        let client1 = crate::test_helpers::make_test_client();
        let mut client2 = client1.clone();
        client2.user_agent = "other".to_string();

        let prev = make_prev(client2, Some("private"), Some("\"a\""), None, ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client1;
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
        // The entry an operator configures, and the ending that says who is
        // at fault: the response stated the directive correctly and a cache
        // did not honour it.
        let v = v.expect("a finding");
        assert_eq!(v.violation, "cache_control_private_ignored");
        assert_eq!(v.severity, crate::lint::Severity::Warn);
        assert!(v.message.contains("Validator '"));
    }

    /// A validator this client was handed too is its own, whoever else holds
    /// it: an entity tag names a representation, and two clients that each
    /// fetched the private resource are handed the same one. Every field the
    /// rule reads, each with the value both clients were given.
    #[rstest::rstest]
    #[case::if_none_match("if-none-match", "\"a\"")]
    #[case::if_modified_since("if-modified-since", "Mon, 01 Jan 2024 00:00:00 GMT")]
    #[case::if_range_tag("if-range", "\"a\"")]
    #[case::if_range_date("if-range", "Mon, 01 Jan 2024 00:00:00 GMT")]
    fn a_validator_this_client_was_handed_is_its_own(#[case] field: &str, #[case] value: &str) {
        let ts = Utc::now();
        let client1 = crate::test_helpers::make_test_client();
        let mut client2 = client1.clone();
        client2.user_agent = "other".to_string();
        let lm = Some("Mon, 01 Jan 2024 00:00:00 GMT");

        let theirs = make_prev(
            client2,
            Some("private"),
            Some("\"a\""),
            lm,
            ts - chrono::Duration::seconds(2),
        );
        let mine = make_prev(
            client1.clone(),
            Some("private"),
            Some("\"a\""),
            lm,
            ts - chrono::Duration::seconds(1),
        );
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client1;
        tx.request.headers.append(
            hyper::header::HeaderName::from_bytes(field.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        let config =
            crate::test_helpers::make_test_config_with_enabled_rules(&["private_cache_visibility"]);

        let both = crate::transaction_history::TransactionHistory::from_transactions(vec![
            mine,
            theirs.clone(),
        ]);
        let v = crate::test_helpers::run_rule_all(&PrivateCacheVisibility, &tx, &both, &config);
        assert!(v.is_empty(), "{field}: {v:?}");

        // And the control: without the response to this client, the same
        // request is the leak.
        let only_theirs =
            crate::transaction_history::TransactionHistory::from_transactions(vec![theirs]);
        let v =
            crate::test_helpers::run_rule_all(&PrivateCacheVisibility, &tx, &only_theirs, &config);
        assert_eq!(v.len(), 1, "{field}: {v:?}");
    }

    #[test]
    fn private_from_other_client_flagged_last_modified() {
        let rule = PrivateCacheVisibility;
        let ts = Utc::now();
        let client1 = crate::test_helpers::make_test_client();
        let mut client2 = client1.clone();
        client2.user_agent = "other".to_string();

        let lm = "Wed, 21 Oct 2015 07:28:00 GMT";
        let prev = make_prev(client2, Some("private"), None, Some(lm), ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client1;
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

        let prev = make_prev(client2, None, Some("\"a\""), None, ts);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.client = client1;
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
