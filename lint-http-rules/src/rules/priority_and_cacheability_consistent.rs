// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::priority::{PRIORITY_CACHEABILITY_MISSING, RFC_9218_5};
use crate::violations::ViolationDef;

pub struct PriorityAndCacheabilityConsistent;

/// One entry, on the subject `priority_header_syntax` opened. The two rules do
/// not overlap: that one reads a `Priority` that was written and asks what it
/// says, this one reads a `Priority` that was written and asks what the rest of
/// the response says about caching it.
static DECLARED: &[&ViolationDef] = &[&PRIORITY_CACHEABILITY_MISSING];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: None,
    url: "https://www.rfc-editor.org/rfc/rfc9111.html",
    note: "HTTP caching and `Cache-Control`/`Vary`/`Expires` semantics (informative)",
};

impl RuleMeta for PriorityAndCacheabilityConsistent {
    fn id(&self) -> &'static str {
        "priority_and_cacheability_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Priority and Cacheability Consistency")
    }

    fn description(&self) -> &'static str {
        "Reports a response that carries a `Priority` field and none of `Cache-Control`, `Vary` or `Expires`, so an operator can check whether a cache may hand a per-request signal to a different request. **Nothing is being violated.** RFC 9218 §5 says the server *\"is expected to\"* control the cacheability or applicability of the cached response with fields that control caching — a modal weaker than SHOULD — and it says so of a server that generated the field *\"based on properties of an HTTP request it receives\"*, a condition no field on the wire records. This rule cannot tell the case the sentence is about from the case it is not, and it reports both; the finding names the condition so the operator can settle it. A `Priority` stamped identically on every response an origin serves, which is the shape a CDN edge commonly emits, satisfies the condition in no way at all. The `Cache-Control`/`Vary` pair is §5's own parenthesis and not a tolerance: it asks for *\"header fields that control the caching behavior\"* and names those two as examples, so either answers. `Expires` answers as well: it states the lifetime a cache reuses the response for, exactly as `Cache-Control: max-age` does, and it is one of the fields RFC 9111 §3 lets license storing a response at all. **The expectation's subject is the *cached* response, so only an exchange a cache was permitted to store is reported.** RFC 9110 §9.2.3 says a method has to define caching semantics to be cached at all and names `GET`, `HEAD` and `POST`; §9.3.7 ends by saying of one of the others that *\"Responses to the OPTIONS method are not cacheable\"*, which is the case an operator meets most often, because a `Priority` is commonly stamped on every response an edge serves. RFC 9111 §3's conjunction has to hold besides: a `302` that advertises no freshness is not stored and so is not reported, while a `404` is reported, because §15.1 defines it as heuristically cacheable. `POST` is left out although §9.2.3 names it — §9.3.3 makes a POST response cacheable only where it carries explicit freshness *and* a `Content-Location` equal to the target URI, and a reader that asked only the first term would report a response no cache could have kept. The three caching fields are read by presence alone; the `Priority` value feeds the message and is never parsed as a Dictionary, which is `priority_header_syntax`'s reading."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9218_5, RFC_9111]
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
                label: None,
                snippet:
                    "HTTP/1.1 200 OK\nCache-Control: public, max-age=60\nPriority: u=3\n\n<body...>",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(Vary is present)"),
                snippet: "HTTP/1.1 200 OK\nVary: Accept-Encoding\nPriority: u=1\n\n<body...>",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(Expires is present \u{2014} a lifetime, stated as max-age would)"),
                snippet: "HTTP/1.1 200 OK\nExpires: Thu, 01 Jan 2099 00:00:00 GMT\nPriority: u=3\n\n<body...>",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(OPTIONS — §9.3.7: responses to OPTIONS are not cacheable)"),
                snippet: "OPTIONS /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nAllow: GET, HEAD, OPTIONS\nPriority: u=3, i=?0\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(302 — advertises no freshness, and §15.1 does not name it)"),
                snippet: "HTTP/1.1 302 Found\nLocation: https://example.com/elsewhere\nPriority: u=3\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nPriority: u=2\n\n<body...>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(404 — §15.1 defines it as heuristically cacheable)"),
                snippet: "HTTP/1.1 404 Not Found\nPriority: u=3\n\n<body...>",
            },
        ]
    }
}

impl Rule for PriorityAndCacheabilityConsistent {
    fn needs_response(&self) -> bool {
        // The expectation is scoped by its own opening clause, which is what
        // this rule reads to decide it inspects responses and nothing else: a
        // request carrying a `Priority` is asked for nothing here. The other
        // half of the sentence -- what such a server is expected to do -- is
        // the entry's, and sits on it beside its reference.
        // cite(RFC 9218 § 5): "When an origin server generates the Priority response header field based on properties of an HTTP request it receives"
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

            // Only consider responses that include a Priority header field (§5: the
            // field "can appear in requests and responses"). This is a presence test
            // only — the value feeds the message, never a Dictionary parse — so the
            // first non-empty ASCII field line is taken; a Priority header that is
            // empty or non-ASCII on every line is treated as absent and skipped.
            let mut priority_val: Option<&str> = None;
            for s in crate::helpers::headers::field_lines(&resp.headers, "priority") {
                let s = s.trim();
                if !s.is_empty() {
                    priority_val = Some(s);
                    break;
                }
            }
            let priority = priority_val?;

            // The expectation has a subject, and it is the *cached* response.
            // Where no cache was permitted to store this one there is nothing
            // whose cacheability or applicability a field could control, so the
            // sentence does not reach the exchange at all -- it is not an
            // expectation this response has failed to meet.
            //
            // This replaced a status range of `200..400`, whose own comment
            // said no sentence licensed it. The range admitted an `OPTIONS`
            // response, which § 9.3.7 says outright is not cacheable, and every
            // `302`, `303` and `307`, which advertise no freshness and are not
            // among § 15.1's heuristically cacheable statuses; and it excluded
            // `404`, `405`, `410`, `414` and `501`, which are. The question the
            // helper asks is the one the sentence asks, so the imprecision goes
            // in both directions at once.
            // cite(RFC 9218 § 5): "the server is expected to control the cacheability or the applicability of the cached response by using header fields that control the caching behavior (e.g., Cache-Control, Vary)"
            if !crate::helpers::stored_response::response_is_storable(
                &tx.request.method,
                &tx.request.headers,
                resp.status,
                &resp.headers,
            ) {
                return None;
            }

            let has_cache_control = resp.headers.contains_key("cache-control");
            let has_vary = resp.headers.contains_key("vary");
            // `Expires` is the third, because it does what `Cache-Control:
            // max-age` does and that already answers here: it states the
            // lifetime a cache reuses the response for, and it is one of the
            // fields § 3 lets license storing it at all. A response carrying it
            // has said something about caching, and the entry's claim is that
            // it said nothing.
            // cite(RFC 9111 § 5.3): "The "Expires" response header field gives the date/time after which the response is considered stale."
            let has_expires = resp.headers.contains_key("expires");

            // Either field answers, which is § 5's own parenthesis rather than a
            // tolerance: it asks for "header fields that control the caching
            // behavior" and names these two as examples. So the entry is named
            // for the class and the message names the two that would have done.
            // (This replaced a mis-anchored RFC 9111 § 4.2.2 heuristic-freshness
            // MAY, which spoke to neither the Priority expectation nor the Vary
            // half of the check.)
            if !has_cache_control && !has_vary && !has_expires {
                // The premise is stated in the finding because it cannot be
                // tested in the reading. § 5's expectation binds a server that
                // generated the field from properties of the request, and
                // nothing on the wire says whether this one did or whether the
                // same value is stamped on every response the origin serves.
                // So the operator is told what would have to be true for the
                // advice to apply to them, which is the one thing they can
                // check and this reader cannot.
                // cite(RFC 9218 § 5): "When an origin server generates the Priority response header field based on properties of an HTTP request it receives"
                return Some(ctx.report_with(&PRIORITY_CACHEABILITY_MISSING, format!(
                        "Response carries Priority: {priority} and no field that controls its caching (no Cache-Control, Vary or Expires), and a cache is permitted to store it. RFC 9218 §5 expects such a field where the server generated the Priority from properties of the request; whether this one did is not recorded on the wire, so this is advice: a Priority that is the same on every response makes the response no more request-dependent than one without the field"
                    )));
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &PriorityAndCacheabilityConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    fn priority_without_cache_control_or_vary_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("priority", "u=3")]);

        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.violation, "priority_cacheability_missing");
        // The value, and the premise the reading cannot settle. A message that
        // named neither would be identical for every response that triggers it.
        assert!(v.message.contains("Priority: u=3"), "{}", v.message);
        assert!(
            v.message.contains("properties of the request"),
            "{}",
            v.message
        );
    }

    #[rstest]
    fn priority_with_cache_control_is_ok() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("priority", "u=1"), ("cache-control", "public, max-age=60")],
        );
        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn priority_with_vary_is_ok() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("priority", "u=1"), ("vary", "Accept-Encoding")],
        );
        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn no_priority_is_ignored() {
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn priority_non_utf8_is_ignored() -> anyhow::Result<()> {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert("priority", HeaderValue::from_bytes(&[0xff])?);
        tx.response.as_mut().unwrap().headers = hm;

        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[rstest]
    fn priority_multiple_fields_prefers_ascii_value() -> anyhow::Result<()> {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        // Non-UTF8 first, ASCII second
        hm.insert("priority", HeaderValue::from_bytes(&[0xff])?);
        hm.append("priority", HeaderValue::from_static("u=2"));
        tx.response.as_mut().unwrap().headers = hm;

        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[rstest]
    fn priority_on_non_cacheable_status_is_ignored() {
        let tx =
            crate::test_helpers::make_test_transaction_with_response(503, &[("priority", "u=1")]);
        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    /// The gate the status range got wrong, in both directions and in one
    /// table. § 5's subject is the cached response, so the row's answer is the
    /// answer to "could a cache have stored this" and never to "is the status
    /// between 200 and 400": a `404` is inside the sentence and outside the old
    /// range, and an `OPTIONS` 200, a `302` and a `POST` are the other way
    /// round.
    #[rstest]
    // § 15.1's heuristically cacheable statuses, on a method that stores.
    #[case("GET", 200, true)]
    #[case("HEAD", 200, true)]
    #[case("GET", 404, true)]
    #[case("GET", 410, true)]
    #[case("GET", 501, true)]
    // § 9.3.7: "Responses to the OPTIONS method are not cacheable."
    #[case("OPTIONS", 200, false)]
    #[case("OPTIONS", 204, false)]
    // § 9.2.3 names three methods; the rest define no caching semantics.
    #[case("TRACE", 200, false)]
    #[case("PUT", 200, false)]
    #[case("DELETE", 200, false)]
    // § 9.3.3 conditions the POST half on freshness this response has not
    // stated and a `Content-Location` this reader does not resolve.
    #[case("POST", 200, false)]
    // Inside the old range and outside § 3's last term: no freshness, and a
    // status § 15.1 does not name.
    #[case("GET", 302, false)]
    #[case("GET", 307, false)]
    #[case("GET", 304, false)]
    fn only_a_response_a_cache_could_have_kept_is_reported(
        #[case] method: &str,
        #[case] status: u16,
        #[case] reported: bool,
    ) {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            status,
            &[("priority", "u=3")],
        );
        tx.request.method = method.to_string();
        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(v.is_some(), reported, "{method} {status}");
    }

    /// The storability terms a response can carry rather than inherit from its
    /// status are all fields that control caching, so a `302` is never
    /// reported: what could license storing it — `Expires`, or a
    /// `Cache-Control` directive — is itself the answer the entry asks for, and
    /// without one no cache keeps it. `Vary` alone answers too, and is not a
    /// licence to store.
    #[rstest]
    #[case(&[("priority", "u=3"), ("expires", "Thu, 01 Jan 2026 00:00:00 GMT")])]
    #[case(&[("priority", "u=3"), ("cache-control", "max-age=60")])]
    #[case(&[("priority", "u=3"), ("vary", "Accept-Encoding")])]
    #[case(&[("priority", "u=3")])]
    fn a_302_is_stored_only_by_a_field_that_answers(#[case] resp_headers: &[(&str, &str)]) {
        let tx = crate::test_helpers::make_test_transaction_with_response(302, resp_headers);
        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "{resp_headers:?}: {v:?}");
    }

    /// `Expires` states a lifetime as `max-age` does, so a stored `200`
    /// carrying it has said something about caching; the same `200` with
    /// neither it nor the two named fields has not.
    #[rstest]
    #[case(&[("priority", "u=3"), ("expires", "Thu, 01 Jan 2099 00:00:00 GMT")], false)]
    #[case(&[("priority", "u=3"), ("expires", "0")], false)]
    #[case(&[("priority", "u=3")], true)]
    fn expires_answers_the_expectation(
        #[case] resp_headers: &[(&str, &str)],
        #[case] reported: bool,
    ) {
        let tx = crate::test_helpers::make_test_transaction_with_response(200, resp_headers);
        let rule = PriorityAndCacheabilityConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(v.is_some(), reported, "{resp_headers:?}");
    }

    #[rstest]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "priority_and_cacheability_consistent");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn needs_a_response() {
        let rule = PriorityAndCacheabilityConsistent;
        assert!(rule.needs_response());
    }
}
