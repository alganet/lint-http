// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Stateful check ensuring that caches (and caching clients) treat `Vary`
/// dimensions as part of their cache key.
///
/// When a response includes a `Vary` header, a cache MUST only match a stored
/// representation for a new request if the values of *all* listed request
/// headers are identical to the values that produced the stored response
/// (see RFC 9111 §4.1).  A client that reuses a cached entry by issuing a
/// conditional request (If-None-Match / If-Modified-Since) should therefore
/// preserve the same set of header values; otherwise the cache key is
/// incomplete and the server may be asked to validate the wrong representation.
///
/// This rule examines conditional requests and attempts to locate the prior
/// transaction whose validator (ETag or Last-Modified) is being reused.  If
/// that earlier response carried a `Vary` header, the rule compares the values
/// of the listed request fields between the two requests.  Any mismatch
/// triggers a warning, because it suggests the cache key omitted one of the
/// necessary dimensions.
///
/// The rule is permissive in several respects:
///
/// * If no previous response matching the current validator is found,
///   nothing useful can be checked.
/// * `Vary: *` is ignored since it prevents reuse altogether and offers no
///   concrete fields to compare.
/// * Weak ETags are treated the same as strong tags for the purpose of
///   locating a prior transaction; the rule does not attempt to revalidate
///   semantics.
pub struct VaryHeaderCacheValid;

impl Rule for VaryHeaderCacheValid {
    fn id(&self) -> &'static str {
        "vary_header_cache_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // rule inspects both request and response history
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
            let req = &tx.request;
            // Only a conditional request reuses a stored validator — the precondition header ties
            // the request to a specific stored representation whose Vary key we can check.
            // cite(RFC 9111 § 4.3.1): "It then updates that request with one or more precondition header fields."
            // One value, however many field lines carry it: `#entity-tag` is a list,
            // so § 5.2's join applies here exactly as it does to the `Vary` the walk
            // below reads. Octet-level, for the reason that reader gives — `to_str`
            // folds an `obs-text` octet into "no such field", which is a claim about
            // the message where the truth is about the value.
            let inm_value = crate::helpers::headers::combined_field_value_as_written(
                &req.headers,
                "if-none-match",
            );
            let has_inm = inm_value.is_some();

            // The same sentence, and the opposite consequence, because
            // `If-Modified-Since = HTTP-date` is not a list. A second field line does
            // not extend this value: § 5.2 joins the lines with a comma and no
            // `HTTP-date` holds one, so such a message names no stored validator
            // rather than either of two — the branch below asked each line in turn
            // and took whichever matched, which is picking a validator by position.
            // The duplication itself is a sender defect that no rule in the
            // catalogue reports, and it is not this rule's question either way.
            //
            // cite(RFC 9110 § 13.1.3): "If-Modified-Since = HTTP-date"
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            let ims_value = crate::helpers::headers::combined_field_value_as_written(
                &req.headers,
                "if-modified-since",
            );
            let has_ims = ims_value.is_some();
            if !has_inm && !has_ims {
                // nothing to check when client is not reusing a cached validator
                return None;
            }

            // `If-None-Match: *` names no specific stored representation (it matches any existing
            // one), so there is no single Vary key to trace — skip it.
            //
            // **The wildcard is the whole field value, not a member.** The grammar is
            // an alternation and § 13.1.2's own sentence says *when the field value
            // is "*"* — so a `*` sought among the members stood this rule down on
            // two values that are not the wildcard: `"etag1", *`, which derives from
            // neither alternative, and the pair of field lines `If-None-Match:
            // "etag1,` / `If-None-Match: *`, where the join leaves an unterminated
            // quoted-string holding one member and no `*` at all.
            //
            // cite(RFC 9110 § 13.1.2): "If-None-Match = "*" / #entity-tag"
            // cite(RFC 9110 § 13.1.2): "The "If-None-Match" header field makes the request method conditional on a recipient cache or origin server either not having any current representation of the target resource, when the field value is "*""
            if inm_value.as_deref().map(crate::helpers::headers::trim_ows) == Some("*") {
                return None;
            }

            // find the prior transaction that supplied the validator
            let mut matched_past: Option<&crate::http_transaction::HttpTransaction> = None;
            let mut matched_validator: Option<String> = None;

            for past in history.iter() {
                if let Some(resp) = &past.response {
                    // check ETag first
                    if has_inm {
                        if let Some(etag) = resp.headers.get("etag").and_then(|hv| hv.to_str().ok())
                        {
                            // Does current request present an If-None-Match that
                            // matches this etag? Asked of the same joined value the
                            // gate above read, so the field is read one way: a
                            // per-line walk here would have made the pair of lines
                            // `If-None-Match: "eta` / `If-None-Match: g1"` two
                            // members where § 5.2 makes them one entity-tag.
                            if let Some(inm) = inm_value.as_deref() {
                                if crate::helpers::headers::inm_matches_known(inm, etag) {
                                    matched_past = Some(past);
                                    matched_validator = Some(etag.trim().to_string());
                                    break;
                                }
                            }
                        }
                    }
                    // The ETag branch above breaks this loop the moment it matches,
                    // so `matched_past` is `None` at every evaluation of this line —
                    // the `matched_past.is_none() &&` it used to carry could not be
                    // false, before this iteration or after it. The precedence it
                    // reads as is real and is the `break`'s.
                    if has_ims {
                        if let Some(lm) = resp
                            .headers
                            .get("last-modified")
                            .and_then(|hv| hv.to_str().ok())
                        {
                            let lm_trimmed = lm.trim();
                            if let Some(ims_str) = ims_value.as_deref().map(str::trim) {
                                // only compare if both look like valid HTTP dates
                                if crate::http_date::is_valid_http_date(ims_str) {
                                    // simple string equality is acceptable here; the
                                    // canonicalization rules are handled in other
                                    // rules and our goal is just to locate the
                                    // matching transaction.
                                    if ims_str == lm_trimmed {
                                        matched_past = Some(past);
                                        matched_validator = Some(lm_trimmed.to_string());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let past = matched_past?; // no validator candidate found

            // The field names that past response nominated. A `*` never matches any
            // request, so there is nothing to compare and the rule stops.
            //
            // The walk this replaced read the field lines one at a time, skipped the
            // whole rule when `to_str` refused one, and did not join them — so a `*`
            // on a second field line was not a `*` here, and one `obs-text` octet in
            // any line stood the comparison down. `helpers::headers::vary_nomination`
            // is the one answer all three rules that ask this now share.
            //
            // cite(RFC 9111 § 4.1): "A stored response with a Vary header field value containing a member "*" always fails to match."
            let crate::helpers::headers::VaryNomination::Fields(vary_fields) =
                crate::helpers::headers::vary_nomination(&past.response.as_ref().unwrap().headers)
            else {
                return None;
            };

            if vary_fields.is_empty() {
                return None;
            }

            for field in vary_fields {
                let past_val =
                    crate::helpers::headers::get_all_header_values(&past.request.headers, &field)
                        .unwrap_or_default();
                let curr_val = crate::helpers::headers::get_all_header_values(&req.headers, &field)
                    .unwrap_or_default();
                // Exact value comparison. §4.1's "match" definition additionally permits whitespace,
                // line-combining, and semantic normalization (ordering/case where insignificant); this
                // rule does not apply those, so it can over-report when the values differ only in a
                // §4.1-permitted normalization — a deliberate simplification.
                // cite(RFC 9111 § 4.1): "the cache MUST NOT use that stored response without revalidation unless all the presented request header fields nominated by that Vary field value match those fields in the original request"
                if past_val != curr_val {
                    let reported_validator = matched_validator.as_deref().unwrap_or("<unknown>");
                    return Some(self.violation(ctx.severity, format!(
                            "Conditional request with validator '{}' differs in Vary field '{}'; cache key must incorporate all Vary dimensions",
                            reported_validator, field
                        )));
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Caches use the response's `Vary` header to decide which request header values must be incorporated into their cache key.  When a cached representation is reused (for example via conditional requests using `If-None-Match` or `If-Modified-Since`), the values of *all* headers listed in `Vary` **must** be identical to those that produced the stored response.  Otherwise the cache is effectively using an incomplete key and may send a stale or incorrect representation to the server or client.\n\nThis rule inspects conditional requests and attempts to pair them with the prior response whose validator is being reused.  If that earlier response included a `Vary` header, the rule compares the request header values from the two transactions.  Any difference is reported as a violation because it indicates the cache key omitted a required dimension.\n\nThe rule is intentionally forgiving:\n\n* It only applies when a previous validator matching the current conditional header can be located.\n* `Vary: *` is ignored, since it precludes reuse and offers no explicit fields to compare.\n* When no `Vary` header is present on the candidate response, no check is performed."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9111",
            section: Some("4.1"),
            url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1",
            note: "Calculating Cache Keys with the Vary Header Field (all Vary-nominated request fields must match for reuse)",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n> Accept-Encoding: gzip\n>\n< HTTP/1.1 200 OK\n< Vary: Accept-Encoding\n< ETag: \"v1\"\n\n> GET /resource HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"\n> Accept-Encoding: gzip",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— Vary dimension changed on revalidation"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n> Accept-Encoding: gzip\n>\n< HTTP/1.1 200 OK\n< Vary: Accept-Encoding\n< ETag: \"v1\"\n\n> GET /resource HTTP/1.1\n> Host: example.com\n> If-None-Match: \"v1\"\n> Accept-Encoding: deflate    # mismatch from original request",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— non-conditional request"),
                snippet: "> GET /resource HTTP/1.1\n> Host: example.com\n> Accept-Encoding: gzip",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— non-conditional request"),
                snippet: "< HTTP/1.1 200 OK\n< Vary: Accept-Encoding\n< ETag: \"v1\"",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &VaryHeaderCacheValid;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx_with_req(uri: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = uri.to_string();
        tx
    }

    fn make_resp_tx(
        req_uri: &str,
        vary: Option<&str>,
        validator: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = make_tx_with_req(req_uri);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        if let Some(v) = vary {
            headers.append("vary", v.parse().unwrap());
        }
        if let Some(val) = validator {
            // choose header based on prefix
            if val.starts_with('"') || val.starts_with("W/") {
                headers.append("etag", val.parse().unwrap());
            } else {
                headers.append("last-modified", val.parse().unwrap());
            }
        }
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers,
            body_length: None,
            trailers: None,
        });
        tx
    }

    #[test]
    fn no_violation_without_conditional() {
        let rule = VaryHeaderCacheValid;
        let tx = make_tx_with_req("https://example.com/foo");
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        )
        .is_none());
    }

    #[test]
    fn inm_wildcard_skips() {
        let rule = VaryHeaderCacheValid;

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"etag1\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "*"),
            ("Accept-Encoding", "deflate"),
        ]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        )
        .is_none());
    }

    /// The two ways the walk this rule used to hold could not read its `Vary`.
    /// Both fixtures are the `mismatch_on_vary_field_triggers` exchange below
    /// with the past response's `Vary` written differently — so the finding is
    /// the same one, and what changes is whether the rule can see the field.
    #[test]
    fn the_past_responses_vary_is_read_across_its_lines_and_past_an_obs_text_octet() {
        use hyper::header::{HeaderName, HeaderValue};
        let judge = |vary: &[&[u8]]| {
            let mut past = make_resp_tx("https://example.com/foo", None, Some("\"etag1\""));
            let headers = &mut past.response.as_mut().expect("a response").headers;
            for line in vary {
                headers.append(
                    HeaderName::from_static("vary"),
                    HeaderValue::from_bytes(line).expect("a test Vary value"),
                );
            }
            past.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

            let mut tx = make_tx_with_req("https://example.com/foo");
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
                ("If-None-Match", "\"etag1\""),
                ("Accept-Encoding", "deflate"),
            ]);
            let history =
                crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
            crate::test_helpers::run_rule(
                &VaryHeaderCacheValid,
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "vary_header_cache_valid",
                ]),
            )
        };

        // The nominated field is on the second line. §5.3 makes the lines one
        // value; read one at a time the rule saw two one-member lists and this
        // one still reports, so the case that proves the join is the `*`.
        assert!(judge(&[b"accept-encoding"]).is_some());
        assert!(judge(&[b"accept", b"accept-encoding"]).is_some());
        // A `*` on the second field line is a member of the value, and a `*`
        // stops the comparison outright. Read line by line it was not one, and
        // this exchange was reported.
        assert!(judge(&[b"accept-encoding", b"*"]).is_none());
        // `to_str` refuses %xE9, and refusing it used to end the rule — so a
        // nominated field beside an `obs-text` octet drew nothing at all.
        assert!(judge(&[b"caf\xe9, accept-encoding"]).is_some());
        assert!(judge(&[b"caf\xe9", b"accept-encoding"]).is_some());
    }

    /// The three ways the walk this rule used to hold could not read its
    /// `If-None-Match`. Every fixture is the `mismatch_on_vary_field_triggers`
    /// exchange below with the conditional header written differently — so the
    /// finding is the same one, and what changes is whether the rule believes
    /// the client wrote the wildcard.
    #[test]
    fn the_requests_if_none_match_is_one_value_and_the_wildcard_is_all_of_it() {
        use hyper::header::{HeaderName, HeaderValue};
        let judge_against = |etag: &str, inm: &[&[u8]]| {
            let mut past = make_resp_tx(
                "https://example.com/foo",
                Some("Accept-Encoding"),
                Some(etag),
            );
            past.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

            let mut tx = make_tx_with_req("https://example.com/foo");
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "deflate")]);
            for line in inm {
                tx.request.headers.append(
                    HeaderName::from_static("if-none-match"),
                    HeaderValue::from_bytes(line).expect("a test If-None-Match value"),
                );
            }
            let history =
                crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
            crate::test_helpers::run_rule(
                &VaryHeaderCacheValid,
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "vary_header_cache_valid",
                ]),
            )
        };
        let judge = |inm: &[&[u8]]| judge_against("\"etag1\"", inm);

        // The baseline, and the wildcard the gate is for. `OWS` around a whole
        // field value is not part of it, which is why the comparison trims.
        assert!(judge(&[b"\"etag1\""]).is_some());
        assert!(judge(&[b"*"]).is_none());
        assert!(judge(&[b"  *  "]).is_none());

        // `"etag1", *` derives from neither alternative of `"*" / #entity-tag`,
        // so the client did not write the wildcard and this exchange is
        // reportable. Sought as a member, the `*` stood the whole rule down.
        assert!(judge(&[b"\"etag1\", *"]).is_some());
        // § 5.2 makes these the same value as the line above, so they get the
        // same answer. Read line by line the second line *was* the wildcard.
        assert!(judge(&[b"\"etag1\"", b"*"]).is_some());

        // Here the gate also stops firing — the quoted-string opened on the
        // first line is still open when the comma the join writes arrives, so
        // the value holds one member and no wildcard — and the answer does not
        // change, because the same join that removes the `*` also makes the
        // member stop matching the stored `"etag1"`. **The member search had two
        // consequences at this rule and only one of them is observable**; this
        // case is pinned so the next reader does not take it for the first.
        assert!(judge(&[b"\"etag1,", b"*"]).is_none());

        // The other half of the join, on the read that traces the validator: a
        // quoted-string split across two field lines is one entity-tag, and the
        // per-line walk made it two members that matched nothing. The separator
        // § 5.2 writes is the comma alone, so the tag is `"eta,g1"`.
        assert!(judge_against("\"eta,g1\"", &[b"\"eta", b"g1\""]).is_some());

        // `to_str` refuses %xE9. The skip was per line rather than per rule, so
        // this one always reported — it is pinned because the octet-level read
        // is what keeps that true now that the lines are joined before the
        // members are counted.
        assert!(judge(&[b"\xe9", b"\"etag1\""]).is_some());
    }

    /// `If-Modified-Since` is the same sentence with the opposite consequence:
    /// `HTTP-date` is not a list, so a second field line does not extend the
    /// value, and the branch that read it asked each line in turn and took
    /// whichever matched — choosing a stored representation by position.
    #[test]
    fn a_second_if_modified_since_line_names_no_validator() {
        use hyper::header::{HeaderName, HeaderValue};
        let judge = |ims: &[&str]| {
            let mut past = make_resp_tx(
                "https://example.com/foo",
                Some("Accept-Encoding"),
                Some("Wed, 21 Oct 2015 07:28:00 GMT"),
            );
            past.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

            let mut tx = make_tx_with_req("https://example.com/foo");
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "deflate")]);
            for line in ims {
                tx.request.headers.append(
                    HeaderName::from_static("if-modified-since"),
                    HeaderValue::from_str(line).expect("a test If-Modified-Since value"),
                );
            }
            let history =
                crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
            crate::test_helpers::run_rule(
                &VaryHeaderCacheValid,
                &tx,
                &history,
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "vary_header_cache_valid",
                ]),
            )
        };

        // One line, naming the stored validator: the exchange is reported.
        assert!(judge(&["Wed, 21 Oct 2015 07:28:00 GMT"]).is_some());
        // Two lines are one value. An `IMF-fixdate` carries a comma of its own,
        // so the joined value reads as a date followed by more date, and
        // `is_valid_http_date` is what says it derives from no `HTTP-date` —
        // which is why the second line cannot be the one that was meant.
        assert!(judge(&[
            "Wed, 21 Oct 2015 07:28:00 GMT",
            "Thu, 22 Oct 2015 07:28:00 GMT"
        ])
        .is_none());
    }

    #[test]
    fn mismatch_on_vary_field_triggers() {
        let rule = VaryHeaderCacheValid;

        // past response had Vary: Accept-Encoding, and request used gzip
        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"etag1\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        // current request uses conditional with same ETag but different
        // Accept-Encoding value
        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "deflate"),
        ]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .to_lowercase()
            .contains("accept-encoding"));
    }

    #[test]
    fn match_on_vary_field_ok() {
        let rule = VaryHeaderCacheValid;

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"etag1\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "gzip"),
        ]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        )
        .is_none());
    }

    #[test]
    fn missing_vary_header_in_past_skips() {
        let rule = VaryHeaderCacheValid;

        let mut past = make_resp_tx("https://example.com/foo", None, Some("\"etag1\""));
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "deflate"),
        ]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        )
        .is_none());
    }

    #[test]
    fn vary_wildcard_ignored() {
        let rule = VaryHeaderCacheValid;

        let mut past = make_resp_tx("https://example.com/foo", Some("*"), Some("\"etag1\""));
        past.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "gzip"),
        ]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        )
        .is_none());
    }

    #[test]
    fn case_insensitive_vary_name() {
        let rule = VaryHeaderCacheValid;

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("aCcEpT-enCoDiNg"),
            Some("\"etag1\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "deflate"),
        ]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("accept-encoding"));
    }

    #[test]
    fn missing_current_header_is_mismatch() {
        let rule = VaryHeaderCacheValid;

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"etag1\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            // no Accept-Encoding header
        ]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .to_lowercase()
            .contains("accept-encoding"));
    }

    #[test]
    fn multiple_vary_fields_one_mismatch_reports() {
        let rule = VaryHeaderCacheValid;

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding, X-Foo"),
            Some("\"etag1\""),
        );
        past.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("Accept-Encoding", "gzip"),
            ("X-Foo", "bar"),
        ]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "gzip"),
            ("X-Foo", "baz"),
        ]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("x-foo"));
    }

    #[test]
    fn ims_based_validation_respects_vary() {
        let rule = VaryHeaderCacheValid;

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("X-Foo"),
            Some("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        past.request.headers = crate::test_helpers::make_headers_from_pairs(&[("X-Foo", "a")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("X-Foo", "b"),
        ]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn different_validator_skips() {
        let rule = VaryHeaderCacheValid;

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"etag1\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag2\""),
            ("Accept-Encoding", "deflate"),
        ]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
        assert!(crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        )
        .is_none());
    }

    #[test]
    fn weak_etag_matches_and_respects_vary() {
        let rule = VaryHeaderCacheValid;

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("W/\"weak\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "W/\"weak\""),
            ("Accept-Encoding", "deflate"),
        ]);

        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![past]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .to_lowercase()
            .contains("accept-encoding"));
    }

    #[test]
    fn finds_match_in_later_history_entry() {
        let rule = VaryHeaderCacheValid;

        // first past entry has a different etag
        let mut old = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"old\""),
        );
        old.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        // second entry matches validator but has Vary header
        let mut good = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"etag1\""),
        );
        good.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "deflate"),
        ]);

        // newest-first: later matching entry (good) must come first
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![good, old]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["vary_header_cache_valid"]),
        );
        assert!(v.is_some(), "should inspect later matching entry");
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "vary_header_cache_valid");
        crate::rules::validate_rules(&cfg).unwrap();
    }
}
