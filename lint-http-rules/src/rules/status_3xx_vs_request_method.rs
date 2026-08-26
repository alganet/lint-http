// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// A `301` or a `302` answering a `POST` leaves the method undetermined.
///
/// RFC 9110 §15.4.2 and §15.4.3 each permit a user agent to change the method from
/// `POST` to `GET` before following the `Location`, and each names the status that
/// says the same thing without the ambiguity: `308` for the permanent redirect,
/// `307` for the temporary one. The server cannot tell which method the redirect
/// will arrive with, so the choice of status is the only thing that can say.
pub struct Status3xxVsRequestMethod;

/// The status RFC 9110 names as the unambiguous alternative to `status`, and the
/// section that names it — `None` for every other status.
///
/// The pairing is per status and each half comes from that status's own definition,
/// not from one shared sentence: §15.4.2 answers a `301` with `308` and §15.4.3
/// answers a `302` with `307`, so the *permanence* of the redirect survives the
/// advice. Offering "307/308" for either one, which this rule used to do, tells half
/// of the servers it reports to change what their redirect means.
fn unambiguous_alternative(status: u16) -> Option<(&'static str, &'static str)> {
    match status {
        // Both notes are set in the RFC's gutter block, so the `|` line markers are
        // part of the extracted passage and part of the quote. §15.4.2's passage also
        // starts one word later than §15.4.3's — the extractor keeps "For" with the
        // note marker there — which is why the two quotes are not symmetric.
        // cite(RFC 9110 § 15.4.2): "historical reasons, a user agent MAY change the | request method from POST to GET for the subsequent request. If | this behavior is undesired, the 308 (Permanent Redirect) status | code can be used instead."
        301 => Some(("308 (Permanent Redirect)", "§15.4.2")),
        // cite(RFC 9110 § 15.4.3): "For historical reasons, a user agent MAY change the | request method from POST to GET for the subsequent request. If | this behavior is undesired, the 307 (Temporary Redirect) status | code can be used instead."
        302 => Some(("307 (Temporary Redirect)", "§15.4.3")),
        // No other status is in the same position, and every §15.4.x subsection was
        // read to say so rather than only the two above. 307 says the method is kept
        // with a MUST NOT of its own; 303 says it changes, by being defined as a
        // redirection the user agent retrieves. 300, 304 and the deprecated 305/306
        // say nothing about the method at all, and neither does 308's own section —
        // what makes 308 method-preserving is §15.4's history, which is also the
        // sentence that says what the 301/302 adjustment was for. Reaching this arm is
        // not a judgement about the response.
        // cite(RFC 9110 § 15.4): "307 | (Temporary Redirect) and 308 (Permanent Redirect) [RFC7538] | were later added to unambiguously indicate method-preserving | redirects, and status codes 301 and 302 have been adjusted to | allow a POST request to be redirected as GET."
        // cite(RFC 9110 § 15.4.8): "The 307 (Temporary Redirect) status code indicates that the target resource resides temporarily under a different URI and the user agent MUST NOT change the request method if it performs an automatic redirection to that URI."
        // cite(RFC 9110 § 15.4.4): "The 303 (See Other) status code indicates that the server is redirecting the user agent to a different resource, as indicated by a URI in the Location header field, which is intended to provide an indirect response to the original request."
        _ => None,
    }
}

impl Rule for Status3xxVsRequestMethod {
    fn id(&self) -> &'static str {
        "status_3xx_vs_request_method"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // Both halves of the question are on the transaction: the status the server
        // chose and the method the client sent. `RuleScope::Server` only means the
        // engine skips a transaction that has no response yet.
        let resp = tx.response.as_ref()?;

        let (alternative, section) = unambiguous_alternative(resp.status)?;

        // A method is only rewritten by a user agent that *follows* the redirect, and
        // what it follows is the `Location`. Presence is the whole question here:
        // whether the value is a usable `URI-reference` is
        // `location_header_uri_valid`'s, and a 301 or a 302 carrying no
        // `Location` at all is `location_on_redirect_present`'s, against the
        // SHOULD in the same two sections this rule reads.
        // cite(RFC 9110 § 15.4): "If a Location header field (Section 10.2.2) is provided, the user agent MAY automatically redirect its request to the URI referenced by the Location field value, even if the specific status code is not understood."
        resp.headers.get_all("location").iter().next()?;

        // POST is the method the two notes name, and the only one they name. §15.4's
        // history says which methods the adjustment was made for — a POST redirected
        // as GET — so a user agent following a 301 with any other method changes
        // nothing and there is no ambiguity to report. This rule used to exempt the
        // four safe methods and report everything else, which measured every PUT,
        // PATCH, DELETE and CONNECT against a sentence about POST.
        //
        // The comparison is exact because the method token is case-sensitive: a
        // request whose method is `post` is not a POST request, and what is wrong with
        // *that* is `request_method_token_valid`'s to report.
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        if tx.request.method != "POST" {
            return None;
        }

        // No cite of its own: what makes this worth saying is the note matched by
        // `unambiguous_alternative`, cited at the arm that matched it and carried into
        // the message from there. The 303 clause is §9.3.3's MAY, and it travels with
        // the condition that sentence puts on it.
        // cite(RFC 9110 § 9.3.3): "If the result of processing a POST would be equivalent to a representation of an existing resource, an origin server MAY redirect the user agent to that resource by sending a 303 (See Other) response with the existing resource's identifier in the Location field."
        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!(
                "{status} response to a POST request: for historical reasons a user agent MAY \
                 change the method to GET before following this redirect (RFC 9110 {section}), so \
                 the response does not say which method reaches the Location. Send {alternative} \
                 to keep the method, or 303 (See Other) where the result of the POST is an \
                 existing resource the user agent should retrieve",
                status = resp.status,
            ),
        })
    }

    fn title(&self) -> Option<&'static str> {
        Some("The two redirects that let the user agent pick the method")
    }

    fn description(&self) -> &'static str {
        "`301 Moved Permanently` and `302 Found` are the two redirect statuses whose own definitions permit a user agent to change the request method, and the method they name is `POST`. This rule reports a `301` or a `302` that answers a `POST` request and carries a `Location` for the user agent to follow — the response does not determine whether the redirected request arrives as a `POST` or as a `GET`.\n\n**This is advice, not a violation.** The sentence it rests on is a note carrying a `MAY` addressed to user agents (RFC 9110 §15.4.2, §15.4.3); no sentence forbids a server from answering a `POST` with a `301` or a `302`, and a server that knows its clients may have nothing to fix. What the finding buys is that the ambiguity is a choice, not an accident.\n\n**The alternative is per status, and they are not interchangeable:**\n\n- `301` → `308 Permanent Redirect` — §15.4.2 names it, and it keeps the redirect permanent\n- `302` → `307 Temporary Redirect` — §15.4.3 names it, and it keeps the redirect temporary\n- either → `303 See Other`, where the change to `GET` is what the server wants. §9.3.3 permits this with a `MAY`, under a condition this rule cannot see: that the result of processing the `POST` is equivalent to a representation of an existing resource.\n\n**No method other than `POST` is reported.** The two notes name `POST`, and §15.4's history records that `301` and `302` \"have been adjusted to allow a POST request to be redirected as GET\" — a `PUT`, `PATCH` or `DELETE` following one of them keeps its method, so there is nothing ambiguous to report. This rule previously reported every method not known to be safe.\n\n**The method is compared exactly**, because §9.1 says the method token is case-sensitive: a request whose method is `post` is not a `POST` request. `request_method_token_valid` is the rule that reports it.\n\n**Not reported:** a `301` or `302` carrying no `Location`. With nothing to follow there is no redirected request whose method could differ, and the missing field is `location_on_redirect_present`'s finding."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.2",
                note: "301 Moved Permanently: a user agent MAY change the method from POST to GET, and 308 is the status named for a server that does not want that",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.4.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.3",
                note: "302 Found: the same permission, answered by 307 rather than by 308 — the alternative is per status",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4",
                note: "Why only these two: 307 and 308 were added to indicate method-preserving redirects, and 301 and 302 were adjusted to allow a POST to be redirected as GET. This is also the only sentence that says 308 preserves the method — §15.4.9 does not repeat it. Also what a provided Location buys: a user agent MAY follow it automatically",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.4.8"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.8",
                note: "307 Temporary Redirect: the user agent MUST NOT change the request method when it redirects automatically — the unambiguous half of the 302 pair, and never reported by this rule",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.4.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.4",
                note: "303 See Other: defined as a redirection to a resource the user agent retrieves, so the change of method is what the status means rather than something left open",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1",
                note: "The method token is case-sensitive, so the rule compares it exactly rather than folding case",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.3",
                note: "The 303 alternative: an origin server MAY redirect a POST with a 303, if the result of processing it is equivalent to a representation of an existing resource",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("308 keeps the method, and keeps the redirect permanent"),
                snippet: "POST /submit HTTP/1.1\nHost: example.com\n\nHTTP/1.1 308 Permanent Redirect\nLocation: /submit-new",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("307 is the temporary one"),
                snippet: "POST /submit HTTP/1.1\nHost: example.com\n\nHTTP/1.1 307 Temporary Redirect\nLocation: /submit-new",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("303 asks for the change to GET rather than leaving it open"),
                snippet: "POST /submit HTTP/1.1\nHost: example.com\n\nHTTP/1.1 303 See Other\nLocation: /status",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A PUT is not reported: no sentence lets a user agent rewrite it"),
                snippet: "PUT /doc HTTP/1.1\nHost: example.com\n\nHTTP/1.1 301 Moved Permanently\nLocation: /doc-new",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("301: the redirected request may arrive as POST or as GET"),
                snippet: "POST /submit HTTP/1.1\nHost: example.com\n\nHTTP/1.1 301 Moved Permanently\nLocation: /submit-new",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("302: the same ambiguity, and 307 is its alternative"),
                snippet: "POST /submit HTTP/1.1\nHost: example.com\n\nHTTP/1.1 302 Found\nLocation: /submit-elsewhere",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Status3xxVsRequestMethod;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Every fixture is one exchange: a method, a status, and a `Location` or not.
    /// Both halves are supplied here so that no test can assert a verdict for a reason
    /// it never named — a status without a method is not a fixture for this rule.
    fn exchange(
        method: &str,
        status: u16,
        location: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let pairs: Vec<(&str, &str)> = location.map(|l| vec![("location", l)]).unwrap_or_default();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &pairs);
        tx.request.method = method.to_string();
        tx
    }

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = Status3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
    }

    /// The two statuses whose notes permit the rewrite, each with the alternative its
    /// own section names. The message is derived data, so the pairing is pinned: a
    /// 301 answered with "use 307" would turn a permanent redirect into a temporary
    /// one.
    #[rstest]
    #[case(301, "308 (Permanent Redirect)", "§15.4.2")]
    #[case(302, "307 (Temporary Redirect)", "§15.4.3")]
    fn a_post_is_reported_with_the_alternative_its_own_section_names(
        #[case] status: u16,
        #[case] alternative: &str,
        #[case] section: &str,
    ) {
        let v = judge(&exchange("POST", status, Some("/new"))).expect("expected a finding");
        assert_eq!(v.rule, "status_3xx_vs_request_method");
        assert!(v.message.contains(&status.to_string()), "{}", v.message);
        assert!(v.message.contains("POST"), "{}", v.message);
        assert!(v.message.contains(alternative), "{}", v.message);
        assert!(v.message.contains(section), "{}", v.message);
        assert!(v.message.contains("303 (See Other)"), "{}", v.message);
    }

    /// Every other status a `Location` can appear on. 307 and 308 exist to say the
    /// method is kept, 303 to say it changes, and neither 300 nor 304 is about the
    /// method at all — so a POST answered by any of them is not ambiguous.
    #[rstest]
    #[case(300)]
    #[case(303)]
    #[case(304)]
    #[case(305)]
    #[case(306)]
    #[case(307)]
    #[case(308)]
    #[case(309)]
    #[case(399)]
    #[case(200)]
    #[case(201)]
    fn a_post_answered_by_any_other_status_is_not_reported(#[case] status: u16) {
        assert!(judge(&exchange("POST", status, Some("/new"))).is_none());
    }

    /// The notes name POST. Nothing lets a user agent rewrite the other methods, so
    /// reporting them measured a PUT against a sentence about a POST — which is what
    /// this rule did, on both statuses, with a test for each.
    #[rstest]
    #[case("GET")]
    #[case("HEAD")]
    #[case("OPTIONS")]
    #[case("TRACE")]
    #[case("PUT")]
    #[case("PATCH")]
    #[case("DELETE")]
    #[case("CONNECT")]
    fn no_method_other_than_post_is_reported(#[case] method: &str) {
        for status in [301u16, 302] {
            let v = judge(&exchange(method, status, Some("/new")));
            assert!(v.is_none(), "{method} {status} -> {v:?}");
        }
    }

    /// §9.1: the method token is case-sensitive. `post` is not `POST`, and neither is
    /// an empty method — measuring either against POST's note reports a request the
    /// note is not about. `request_method_token_valid` reports the lowercase
    /// one (verified by running it: *"Method token should be uppercase"*); the empty
    /// method it returns `None` for, and no rule in the tree reports it.
    #[rstest]
    #[case("post")]
    #[case("Post")]
    #[case("pOsT")]
    #[case("")]
    fn a_method_that_is_not_post_exactly_is_not_reported(#[case] method: &str) {
        assert!(judge(&exchange(method, 301, Some("/new"))).is_none());
    }

    /// With no `Location` there is no redirected request whose method could differ.
    /// The missing field is a finding, but it is `location_on_redirect_present`'s.
    #[rstest]
    #[case(301)]
    #[case(302)]
    fn a_post_with_no_location_is_not_reported(#[case] status: u16) {
        assert!(judge(&exchange("POST", status, None)).is_none());
    }

    /// Presence is the whole read, so a value this rule cannot decode still counts:
    /// the user agent that follows it is not decoding it as UTF-8 either.
    #[test]
    fn a_location_that_is_not_utf8_still_counts_as_present() {
        use hyper::header::HeaderValue;
        let mut tx = exchange("POST", 301, None);
        let mut hm = hyper::HeaderMap::new();
        hm.insert("location", HeaderValue::from_bytes(b"\xff").unwrap());
        tx.response.as_mut().unwrap().headers = hm;
        assert!(judge(&tx).is_some());
    }

    /// Two `Location` field lines, and an empty value, are both a field the user agent
    /// was given. Whether either is usable belongs to the rule that reads the value.
    #[test]
    fn several_location_lines_and_an_empty_value_both_count() {
        use hyper::header::HeaderValue;
        let mut tx = exchange("POST", 302, None);
        let mut hm = hyper::HeaderMap::new();
        hm.append("location", HeaderValue::from_static("/first"));
        hm.append("location", HeaderValue::from_static("/second"));
        tx.response.as_mut().unwrap().headers = hm;
        assert!(judge(&tx).is_some());

        let mut tx = exchange("POST", 302, None);
        let mut hm = hyper::HeaderMap::new();
        hm.insert("location", HeaderValue::from_static(""));
        tx.response.as_mut().unwrap().headers = hm;
        assert!(judge(&tx).is_some());
    }

    #[test]
    fn a_transaction_with_no_response_is_ignored() {
        assert!(judge(&crate::test_helpers::make_test_transaction()).is_none());
    }

    #[test]
    fn the_configured_severity_is_carried() {
        let rule = Status3xxVsRequestMethod;
        let cfg = crate::test_helpers::make_test_config_with_severity(rule.id(), "error");
        let v = crate::test_helpers::run_rule(
            &rule,
            &exchange("POST", 302, Some("/new")),
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("expected a finding");
        assert_eq!(v.severity, crate::lint::Severity::Error);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "status_3xx_vs_request_method");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope() {
        let rule = Status3xxVsRequestMethod;
        assert_eq!(rule.id(), "status_3xx_vs_request_method");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    /// Every published snippet is run through the rule that publishes it. Each is a
    /// request line, then a blank line, then a response — the method matters as much
    /// as the status, so both are parsed rather than assumed.
    #[test]
    fn published_examples_are_judged_by_this_rule() {
        use crate::rules::{Compliance, Rule as _};
        let rule = Status3xxVsRequestMethod;
        let mut non_compliant_seen = 0;

        for ex in rule.examples() {
            let (req, resp) = ex.snippet.split_once("\n\n").unwrap_or_else(|| {
                panic!("example is not a request/response pair: {}", ex.snippet)
            });

            let method = req
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().next())
                .unwrap_or_else(|| panic!("example has no request line: {req:?}"));

            let mut lines = resp.lines();
            let status = lines
                .next()
                .and_then(|line| line.strip_prefix("HTTP/1.1 "))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|code| code.parse::<u16>().ok())
                .unwrap_or_else(|| panic!("example has no status line: {resp:?}"));

            let pairs: Vec<(&str, &str)> = lines
                .map(|line| {
                    let (name, value) = line.split_once(':').unwrap_or_else(|| {
                        panic!("example header line is not `Name: value`: {line:?}")
                    });
                    (name, value.trim())
                })
                .collect();

            let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &pairs);
            tx.request.method = method.to_string();
            let v = judge(&tx);

            match ex.compliance {
                Compliance::Compliant => {
                    assert!(v.is_none(), "compliant example reported: {}", ex.snippet)
                }
                Compliance::NonCompliant => {
                    assert!(
                        v.is_some(),
                        "non-compliant example not reported: {}",
                        ex.snippet
                    );
                    non_compliant_seen += 1;
                }
            }
        }

        assert!(
            non_compliant_seen >= 2,
            "both reported statuses should be published"
        );
    }
}
