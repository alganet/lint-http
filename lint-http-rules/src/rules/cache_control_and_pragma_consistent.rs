// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::pragma::{PRAGMA_CONFLICTING, PRAGMA_OBSOLETE, RFC_9111_5_4};
use crate::violations::ViolationDef;

/// Two entries, and only one of them is about a contradiction. The deprecation
/// is about the field being there at all, in either direction; the conflict is
/// about a request asking for two opposite things.
static DECLARED: &[&ViolationDef] = &[&PRAGMA_OBSOLETE, &PRAGMA_CONFLICTING];

pub struct CacheControlAndPragmaConsistent;

// The sections this rule names now live on the subject beside the entries that
// quote them, and are imported back for `specifications()`.

impl RuleMeta for CacheControlAndPragmaConsistent {
    fn id(&self) -> &'static str {
        "cache_control_and_pragma_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Reports the deprecated `Pragma` field wherever it appears, and one contradiction it takes part in.\n\n**The deprecation is not direction-specific.** RFC 9111 § 5.4 opens by naming the `Pragma` *request* header field and closes with \"this specification deprecates Pragma\"; the field registry in § 11 records its status as `deprecated` with no direction attached. So a request carrying one is reported, which is the deprecated thing being done, and a response carrying one is reported too — there the field was never given a meaning at all, which § 5.4's Note states when it says `Pragma: no-cache` cannot stand in for `Cache-Control: no-cache` in a response. One entry, one retired field, and the message names which side wrote it.\n\n**The contradiction is a heuristic and says so.** `Pragma: no-cache` asks a cache to validate with the origin and `Cache-Control: only-if-cached` asks it to answer from what it holds or fail, so a request carrying both asks for opposite things. No sentence forbids the combination.\n\nWhat a `Pragma` value may contain is `pragma_token_valid`'s question, not this rule's."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_5_4]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **One sender per site, and the field is written by both of them.** The
    /// conflict is between a request's `Pragma` and its own `Cache-Control`,
    /// which is the client's; the deprecation is about whichever section the
    /// field arrived in, so it answers against the client for a request and the
    /// origin for a response.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nCache-Control: no-cache, max-age=0\n\nHTTP/1.1 200 OK\nCache-Control: no-cache",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a request carries the deprecated field"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nPragma: no-cache\n\n# The direction § 5.4 defines, and the one it deprecates",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— and the two directives ask for opposite things"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nPragma: no-cache\nCache-Control: only-if-cached\n\n# Contradictory directives: 'no-cache' requests should not force 'only-if-cached'",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nPragma: no-cache\n\n# 'Pragma' in responses has unspecified semantics; use 'Cache-Control' instead",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nPragma: foo\n\n# Any Pragma in responses is discouraged; prefer Cache-Control",
            },
        ]
    }
}

impl Rule for CacheControlAndPragmaConsistent {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // One finding per section. The two entries are about two senders — the
        // client that wrote a `Pragma` its own `Cache-Control` contradicts, and
        // the origin that wrote one into a response where the field never had a
        // meaning — so neither answers for the other.
        let mut out = Vec::new();

        // Check requests: Pragma: no-cache vs Cache-Control: only-if-cached contradiction
        // `Pragma` is the HTTP/1.0 spelling of a request `no-cache`, and `Cache-Control`
        // is the one that means anything now. A message carrying both is asking to be
        // read by two generations of cache and had better say the same thing to each.
        // cite(RFC 9111 § 5.4): "The "Pragma" request header field was defined for HTTP/1.0 caches, so that clients could specify a "no-cache" request"
        for hv in tx.request.headers.get_all("pragma").iter() {
            let Ok(s) = hv.to_str() else {
                // Ignore non-UTF8 header values here and let dedicated
                // syntax/token rules (e.g., `pragma_token_valid`) handle encoding errors.
                continue;
            };
            // The members are searched rather than walked, and the
            // difference is what the finding is about. This one is not a
            // member's defect -- it is the disagreement between two
            // *fields*, and a `Pragma: no-cache, no-cache` states the same
            // disagreement once. So the question asked of the list is
            // whether it holds the directive at all.
            //
            // if request also contains Cache-Control: only-if-cached, that's contradictory
            // No sentence says this combination is illegal; it is a
            // heuristic — Pragma: no-cache asks a cache to revalidate,
            // only-if-cached asks it to serve from cache or fail. Recorded
            // in the tracker.
            let asks_for_revalidation =
                crate::helpers::list::list_members(s).any(|m| m.eq_ignore_ascii_case("no-cache"));
            if asks_for_revalidation
                && crate::helpers::cache_control::has(&tx.request.headers, "only-if-cached")
            {
                out.push(ctx.by_client().report(&PRAGMA_CONFLICTING));
                break;
            }
        }

        // The field is deprecated wherever it arrives, and for as long as this
        // site asked only about the response, the direction § 5.4 is written
        // about drew nothing at all. The section opens by naming the *request*
        // header field — that is the sentence quoted here — and closes by
        // deprecating it; the registry table in § 11 records the field's status
        // as `deprecated` with no direction attached. A request carrying a
        // `Pragma` is the deprecated thing being done, and three on the counted
        // web do it (two browser reloads and a `git` fetch) with nothing said.
        //
        // `pragma_token_valid` reads the value on both sides and defers the
        // question of whether the field belongs at all to this rule, so a
        // direction missing here was a direction nothing asked about.
        //
        // cite(RFC 9111 § 5.4): "The "Pragma" request header field was defined for HTTP/1.0 caches, so that clients could specify a "no-cache" request"
        // cite(RFC 9111 § 5.4): "However, support for Cache-Control is now widespread.  As a result, this specification deprecates Pragma."
        if tx.request.headers.contains_key("pragma") {
            out.push(ctx.by_client().report_with(
                &PRAGMA_OBSOLETE,
                "Request contains a 'Pragma' header field; the field was defined so an HTTP/1.0 \
                 client could ask for 'no-cache' before 'Cache-Control' existed, and RFC 9111 \
                 § 5.4 deprecates it — send the request directive in 'Cache-Control' instead"
                    .into(),
            ));
        }

        // The same deprecation on the other side, where a second argument sits
        // on top of it: § 5.4 defines the field for requests, so a response
        // carrying one is not merely deprecated but undefined in the direction
        // it arrived in. § 5.4's gutter Note says so — it cannot be
        // machine-cited, because the `|` gutter markers break extraction, so it
        // is paraphrased in the message rather than quoted.
        if let Some(resp) = &tx.response {
            if resp.headers.contains_key("pragma") {
                out.push(ctx.by_server().report_with(&PRAGMA_OBSOLETE, "Response contains 'Pragma' header; its meaning in responses was never specified and Pragma is deprecated — use 'Cache-Control' instead".into()));
            }
        }

        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CacheControlAndPragmaConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// A request carrying `Pragma` and what the rule says about it, entry by
    /// entry.
    ///
    /// **The case for `Pragma` alone used to assert silence**, and that was the
    /// belief this rule was built on: that the field is reportable only where a
    /// `Cache-Control` contradicts it. § 5.4 names the request field and
    /// deprecates it, so the field alone is the finding, and the contradiction
    /// is a second one on top.
    ///
    /// The entries are compared as a set rather than through a single finding:
    /// this rule answers per requirement and a request can break both at once,
    /// so a helper that takes the first of however many cannot tell the two
    /// apart.
    #[rstest]
    #[case(Some("no-cache"), Some("only-if-cached"), &["pragma_obsolete", "pragma_conflicting"][..])]
    #[case(Some("no-cache"), Some("no-cache"), &["pragma_obsolete"][..])]
    #[case(Some("no-cache"), None, &["pragma_obsolete"][..])]
    #[case(Some("private"), None, &["pragma_obsolete"][..])]
    #[case(None, Some("only-if-cached"), &[][..])]
    #[case(None, None, &[][..])]
    fn request_pragma_and_cache_control_cases(
        #[case] pragma_val: Option<&str>,
        #[case] cc_val: Option<&str>,
        #[case] expected: &[&str],
    ) -> anyhow::Result<()> {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = None;
        // Build headers map and append values so both headers can coexist
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        if let Some(p) = pragma_val {
            hm.append(
                "pragma",
                hyper::header::HeaderValue::from_str(p).expect("valid header value"),
            );
        }
        if let Some(cc) = cc_val {
            hm.append(
                "cache-control",
                hyper::header::HeaderValue::from_str(cc).expect("valid header value"),
            );
        }
        tx.request.headers = hm;

        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let mut got: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        got.sort_unstable();
        let mut want: Vec<&str> = expected.to_vec();
        want.sort_unstable();
        assert_eq!(got, want, "pragma={pragma_val:?} cache-control={cc_val:?}");
        // Every finding about the request names the peer that wrote it.
        assert!(found
            .iter()
            .all(|v| v.party == Some(crate::lint::Party::Client)));
        Ok(())
    }

    /// The field arrives in both sections and the entry answers for both, so a
    /// transaction carrying one each is two findings and not one -- which is
    /// also the only place the two parties can be told apart.
    #[test]
    fn a_pragma_in_each_section_is_two_findings_and_two_senders() {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("pragma", "no-cache")],
        );
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("pragma", "no-cache")]);

        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().all(|v| v.violation == "pragma_obsolete"));
        assert_eq!(
            found
                .iter()
                .filter(|v| v.party == Some(crate::lint::Party::Client))
                .count(),
            1
        );
        assert_eq!(
            found
                .iter()
                .filter(|v| v.party == Some(crate::lint::Party::Server))
                .count(),
            1
        );
        // The two sentences are not interchangeable: an operator reading the
        // report has to know which section to edit.
        assert_ne!(found[0].message, found[1].message);
    }

    #[test]
    fn response_with_pragma_reports_violation() {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("pragma", "no-cache")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // The rarest ending in the vocabulary, on the direction that makes the
        // clearest case: § 5.4 defines `Pragma` as a request header field, so a
        // response carrying one is a field with no definition here at all.
        let v = v.expect("a finding");
        assert_eq!(v.violation, "pragma_obsolete");
        assert_eq!(v.severity, crate::lint::Severity::Info);
        assert!(v.message.contains("Pragma"));
    }

    /// The other entry: the client asked for a fresh copy in the field a cache
    /// stops reading once `Cache-Control` is there, and for a cached copy in
    /// the field it does read.
    #[test]
    fn the_request_contradiction_names_its_entry() {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("pragma", "no-cache"),
            ("cache-control", "only-if-cached"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("a finding");
        assert_eq!(v.violation, "pragma_conflicting");
        assert_eq!(v.severity, crate::lint::Severity::Warn);
    }

    /// A value no recipient can read is still a field that arrived.
    ///
    /// The deprecation entry is about the field's *presence*, so it answers for
    /// this one; the contradiction entry has to read `no-cache` out of the
    /// value and cannot, so it declines. The encoding itself is
    /// `pragma_token_valid`'s finding and is not reported twice here.
    #[test]
    fn non_utf8_pragma_is_the_field_arriving_and_not_a_contradiction() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff])?;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("pragma", bad);
        tx.request.headers = hm;

        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(ids, vec!["pragma_obsolete"]);
        Ok(())
    }

    #[test]
    fn request_multiple_cache_control_headers_detection() -> anyhow::Result<()> {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append(
            "pragma",
            hyper::header::HeaderValue::from_static("no-cache"),
        );
        hm.append(
            "cache-control",
            hyper::header::HeaderValue::from_static("public"),
        );
        hm.append(
            "cache-control",
            hyper::header::HeaderValue::from_static("only-if-cached"),
        );
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    /// A request `Pragma` naming something other than `no-cache`.
    ///
    /// The contradiction needs the `no-cache` directive and this value has
    /// none, so that entry stays silent; the deprecation does not read the
    /// value at all, and the field is here. **This case asserted silence
    /// outright** and was the second place the old reading was written down.
    #[test]
    fn request_non_no_cache_pragma_is_the_deprecation_and_not_the_conflict() {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("pragma", hyper::header::HeaderValue::from_static("foo"));
        hm.append(
            "cache-control",
            hyper::header::HeaderValue::from_static("only-if-cached"),
        );
        tx.request.headers = hm;

        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(ids, vec!["pragma_obsolete"]);
    }

    #[test]
    fn response_non_no_cache_pragma_reports_violation() -> anyhow::Result<()> {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("pragma", "foo")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn pragma_with_multiple_members_triggers_on_no_cache() {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append(
            "pragma",
            hyper::header::HeaderValue::from_static("no-cache, foo"),
        );
        hm.append(
            "cache-control",
            hyper::header::HeaderValue::from_static("only-if-cached"),
        );
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn multiple_pragma_headers_trigger_on_response() {
        let rule = CacheControlAndPragmaConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "cache_control_and_pragma_consistent",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("pragma", hyper::header::HeaderValue::from_static("foo"));
        hm.append("pragma", hyper::header::HeaderValue::from_static("bar"));
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }
}
