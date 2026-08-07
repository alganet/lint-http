// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Stateful check on the preconditions a client sends with a `Range` request
/// after it has been given a partial (206) copy of the same resource.
///
/// The requirement is RFC 9111 §4.3.1's first bullet, and it is a **MUST**: when
/// the stored response being validated provided entity tags, the cache must send
/// them — *"using If-Match, If-None-Match, or If-Range"*. Three fields satisfy
/// it, not one. §4.3.1's other two bullets cover the case where the stored
/// response carries only a `Last-Modified` date, and neither is a requirement:
/// the SHOULD is explicitly for a request that is **not** for a subrange, and the
/// bullet that does name subranges is a MAY. A stored partial with no entity tag
/// therefore asks nothing of this request, and the rule is silent there.
///
/// The premise — that this client is the one holding the partial copy — is the
/// one thing no sentence supplies. The capture cannot tell a cache from a user
/// agent that simply asked for another range. What it can see is that this client
/// was sent a 206 for this resource and is ranging over it again, which is the
/// situation RFC 9111 §3.3 and RFC 9110 §15.3.7.3 describe.
///
/// The validator the client holds is the one from the **most recent** response
/// carrying any, not from the most recent 206: a later 200 replaces the stored
/// representation and a 304 freshens its metadata (§4.3.4), so a 206's entity tag
/// can be two representations out of date. `stateful_cache_validation_chain`
/// walks history the same way, against the same §4.3.1 sentence.
///
/// Weak entity tags are skipped, and not as a tolerance: a weak tag cannot be
/// placed in `If-Range` at all (§13.1.5), `If-Match` compares strongly and would
/// never match one, and ranges that do not share a *strong* validator cannot be
/// combined however the request is phrased (§15.3.7.3).
pub struct StatefulRangeRequestAndCaching;

impl Rule for StatefulRangeRequestAndCaching {
    fn id(&self) -> &'static str {
        "stateful_range_request_and_caching"
    }

    /// The rule judges a request against earlier responses and never reads the
    /// current one. In this engine only `Server` filters dispatch, so this is
    /// documentation — but the reader who assumed a response was in hand would
    /// be wrong about every branch below.
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let req = &tx.request;

        // `Range` asks something of a GET and of nothing else. On any other
        // method the server discards the field, so the request is not a
        // re-request of a stored partial copy and there is no stored response
        // being validated. A resumable upload naming its range in the *request's*
        // `Content-Range` reaches here as a PUT and leaves here.
        // cite(RFC 9110 § 14.2): "A server MUST ignore a Range header field received with a request method that is unrecognized or for which range handling is not defined.  For this specification, GET is the only method for which range handling is defined."
        if req.method != "GET" {
            return None;
        }

        // cite(RFC 9110 § 14.2): "The "Range" header field on a GET request modifies the method semantics to request transfer of only one or more subranges of the selected representation data (Section 8.1), rather than the entire selected representation."
        req.headers.get("range")?;

        // The premise. `history` is scoped to this (client, resource) pair by the
        // rule's `ByResource` query, so a 206 anywhere in it is a partial copy of
        // the representation this request is ranging over.
        // cite(RFC 9111 § 3.3): "A cache MAY complete a stored incomplete response by making a subsequent range request (Section 14.2 of [HTTP]) and combining the successful response with the stored response, as defined in Section 3.4."
        // cite(RFC 9110 § 15.3.7.3): "A client that has received multiple partial responses to GET requests on a target resource MAY combine those responses into a larger continuous range if they share the same strong validator."
        let holds_a_partial_copy = history
            .iter()
            .any(|past| past.response.as_ref().is_some_and(|r| r.status == 206));
        if !holds_a_partial_copy {
            return None;
        }

        // What the client holds *now*. Newest first, stopping at the first
        // response that carried any validator at all: that response's metadata is
        // what a stored entry would have been updated to, whether it was the 206,
        // a later 200, or a 304 that freshened it.
        // cite(RFC 9111 § 4.3.1): "It then updates that request with one or more precondition header fields.  These contain validator metadata sourced from a stored response(s) that has the same URI."
        let mut newest_validators: Option<(Option<String>, Option<String>)> = None;
        for past in history.iter() {
            if let Some(resp) = &past.response {
                let (etag, last_modified) =
                    crate::helpers::headers::extract_validators_from_response(&resp.headers);
                if etag.is_some() || last_modified.is_some() {
                    newest_validators = Some((etag, last_modified));
                    break;
                }
            }
        }
        let (stored_etag, _stored_last_modified) = newest_validators?;

        // No entity tag: every sentence that would put a validator in *this*
        // request is weaker than a requirement. The SHOULD excludes subranges by
        // name, and the bullet written for subranges is a MAY — so a date-only
        // stored response leaves the client free to send nothing, and a rule that
        // reported the silence would be inventing the modal.
        // cite(RFC 9111 § 4.3.1): "SHOULD send the Last-Modified value (using If-Modified-Since) if the request is not for a subrange, a single stored response is being validated, and that response contains a Last-Modified value."
        // cite(RFC 9111 § 4.3.1): "MAY send the Last-Modified value (using If-Unmodified-Since or If-Range) if the request is for a subrange, a single stored response is being validated, and that response contains only a Last-Modified value (not an entity tag)."
        let stored_etag = stored_etag?;

        // A weak tag names a representation that cannot be recombined with
        // anything, so no phrasing of this request would help.
        // cite(RFC 9110 § 15.3.7.3): "These ranges can only be safely combined if they all have in common the same strong validator (Section 8.8.1)."
        // cite(RFC 9111 § 3.4): "A cache MAY combine these ranges into a single stored response, and reuse that response to satisfy later requests, if they all share the same strong validator"
        if stored_etag.starts_with("W/") {
            return None;
        }

        // A malformed stored tag is the server's defect and `message_etag_syntax`
        // reports it there. Asking the client to echo it would be this rule
        // charging one party for another's field. (`validate_entity_tag` admits
        // the `*` of a request-side conditional, which is not an ETag value.)
        if stored_etag == "*" || crate::helpers::headers::validate_entity_tag(&stored_etag).is_err()
        {
            return None;
        }

        // The MUST names three fields. A request carrying `If-Match` or
        // `If-None-Match` has put the entity tag where the sentence allows it,
        // and whether the value it carries matches history is
        // `stateful_cache_validation_chain`'s question, asked there against this
        // same sentence. Reporting here would report a conforming request and
        // double-report a non-conforming one.
        // cite(RFC 9111 § 4.3.1): "MUST send the relevant entity tags (using If-Match, If-None-Match, or If-Range) if the entity tags were provided in the stored response(s) being validated."
        if req.headers.contains_key("if-match") || req.headers.contains_key("if-none-match") {
            return None;
        }

        let Some(raw_if_range) = req.headers.get("if-range") else {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Range request for a resource this client holds a 206 of, whose stored entity tag is {stored_etag}, carries none of If-Range, If-Match or If-None-Match; the entity tags of the stored response being validated have to be sent in one of those three"
                ),
            });
        };

        // Present and unreadable is not absent. `message_conditional_headers_consistency`
        // reports a non-ASCII `If-Range`; a "carries none of them" finding here
        // would be false about the message on the wire.
        let Ok(if_range) = raw_if_range.to_str() else {
            return None;
        };
        let if_range = if_range.trim();

        // A weak tag in `If-Range` violates §13.1.5 outright, and the rule that
        // owns the field's syntax says so. Declining keeps the two findings from
        // landing on one field; the precondition for the decline is that an owner
        // exists, and here it does.
        if if_range.starts_with("W/") {
            return None;
        }

        // cite(RFC 9110 § 13.1.5): "A valid entity-tag can be distinguished from a valid HTTP-date by examining the first three characters for a DQUOTE."
        if !if_range.chars().take(3).any(|c| c == '"') {
            // Neither a tag nor a date is a syntax defect, and this rule holds no
            // sentence about the shape of the field — only about which validator
            // belongs in it.
            if !crate::http_date::is_valid_http_date(if_range) {
                return None;
            }

            // The client was given an entity tag for this representation, so the
            // date is the one validator it was not permitted to choose.
            // cite(RFC 9110 § 13.1.5): "Range header field containing an HTTP-date unless the client has no entity tag for the corresponding representation and the date is a strong validator in the sense defined by Section 8.8.2.2."
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "If-Range carries the date '{if_range}' although entity tag {stored_etag} was provided for this representation; a date is only permitted there when the client has no entity tag"
                ),
            });
        }

        // cite(RFC 9110 § 13.1.5): "Note that the If-Range comparison is by exact match, including when the validator is an HTTP-date, and so it differs from the "earlier than or equal to" comparison used when evaluating an If-Unmodified-Since conditional."
        if if_range != stored_etag {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "If-Range entity tag {if_range} is not {stored_etag}, the tag most recently provided for this representation; the server will ignore Range and send the whole representation"
                ),
            });
        }

        None
    }

    fn description(&self) -> &'static str {
        "A client that has been given a 206 (Partial Content) response holds a fragment of a representation, and the fragments can only be combined if they share the same strong validator.  When the stored response provided an entity tag, a cache validating it has to send that tag back — RFC 9111 §4.3.1 makes it a MUST, and names three fields that satisfy it: `If-Match`, `If-None-Match` or `If-Range`.\n\nThis rule tracks earlier transactions for the same client and resource.  After a 206, it reports a later `Range` request that carries none of those three fields, an `If-Range` holding a tag other than the one most recently provided for the resource, and an `If-Range` holding a date when an entity tag was provided (RFC 9110 §13.1.5 forbids the date in that case).  The validator compared against is the one from the most recent response carrying any, since a later 200 or 304 replaces what the client stores.\n\nWhere the stored response carried only a `Last-Modified` date the rule is silent: §4.3.1 asks for that date with a SHOULD that excludes subrange requests and a MAY that covers them, and neither makes its absence a defect.  Weak entity tags are skipped, because `If-Range` may not carry one and ranges sharing only a weak validator cannot be combined at all."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("4.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.1",
                note: "The requirement, and it is a MUST: send the stored response's entity tags, using `If-Match`, `If-None-Match` **or** `If-Range`. The `Last-Modified` bullets are a SHOULD that excludes subranges and a MAY that covers them",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("13.1.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5",
                note: "`If-Range` precondition to `Range` requests, its exact-match comparison, and the MUST NOT against putting a date there while holding an entity tag. RFC 7233 §3.2 defined the field; RFC 9110 obsoleted RFC 7233, and this reference had not moved",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.3.7.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7.3",
                note: "Partial responses combine only when they share the same strong validator — the client-side premise, and the reason a weak tag is skipped",
            },
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("3.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-3.4",
                note: "Combining partial content requires a shared strong validator",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2",
                note: "GET is the only method for which range handling is defined, which is what bounds this rule to GET",
            },
        ]
    }

    /// Each snippet is a two-message sequence in the order it happened: the
    /// earlier response this client was given, then the later request the rule
    /// judges. A single message could not illustrate a stateful rule at all.
    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— the stored tag comes back in `If-Range`"),
                snippet: "HTTP/1.1 206 Partial Content\nETag: \"etag123\"\nContent-Range: bytes 0-99/1000\n\nGET /resource HTTP/1.1\nRange: bytes=100-199\nIf-Range: \"etag123\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— or in `If-None-Match`, which the same sentence allows"),
                snippet: "HTTP/1.1 206 Partial Content\nETag: \"etag123\"\nContent-Range: bytes 0-99/1000\n\nGET /resource HTTP/1.1\nRange: bytes=100-199\nIf-None-Match: \"etag123\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a date-only stored response asks for nothing"),
                snippet: "HTTP/1.1 206 Partial Content\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\nContent-Range: bytes 0-99/1000\n\nGET /resource HTTP/1.1\nRange: bytes=100-199",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— no precondition at all after a 206 that provided a tag"),
                snippet: "HTTP/1.1 206 Partial Content\nETag: \"etag123\"\nContent-Range: bytes 0-99/1000\n\nGET /resource HTTP/1.1\nRange: bytes=100-199",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— `If-Range` holds a tag that was never provided"),
                snippet: "HTTP/1.1 206 Partial Content\nETag: \"etag123\"\nContent-Range: bytes 0-99/1000\n\nGET /resource HTTP/1.1\nRange: bytes=100-199\nIf-Range: \"other\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a date in `If-Range` while holding an entity tag"),
                snippet: "HTTP/1.1 206 Partial Content\nETag: \"etag123\"\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\nContent-Range: bytes 0-99/1000\n\nGET /resource HTTP/1.1\nRange: bytes=100-199\nIf-Range: Wed, 21 Oct 2015 07:28:00 GMT",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &StatefulRangeRequestAndCaching;

#[cfg(test)]
mod tests {
    use super::*;

    /// One constructor for every fixture in this module.
    ///
    /// `earlier` is the sequence of responses this client was given for the
    /// resource, oldest first, and it is reversed and stamped here so the history
    /// is newest-first as the engine builds it. Both messages name one resource
    /// and one client because the `ByResource` query is what puts them in the
    /// same history — a fixture that skips that is not a fixture for this rule,
    /// and neither is one whose request lacks the `Range` the whole rule is about.
    fn sequence(
        earlier: &[(u16, &[(&str, &str)])],
        request: &[(&str, &str)],
    ) -> (
        crate::http_transaction::HttpTransaction,
        crate::transaction_history::TransactionHistory,
    ) {
        assert!(
            request.iter().any(|(name, _)| *name == "range"),
            "a fixture for this rule sends a Range"
        );

        let base = chrono::Utc::now();
        let mut entries = Vec::new();
        for (age, (status, headers)) in earlier.iter().rev().enumerate() {
            let mut past =
                crate::test_helpers::make_test_transaction_with_response(*status, headers);
            past.request.method = "GET".to_string();
            past.request.uri = "/resource".to_string();
            past.client = crate::test_helpers::make_test_client();
            past.timestamp = base - chrono::Duration::seconds(age as i64 + 1);
            entries.push(past);
        }

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = "/resource".to_string();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(request);
        tx.timestamp = base;

        (
            tx,
            crate::transaction_history::TransactionHistory::from_transactions(entries),
        )
    }

    fn judge(
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
    ) -> Option<Violation> {
        StatefulRangeRequestAndCaching.check_transaction(
            tx,
            history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_range_request_and_caching",
            ]),
        )
    }

    #[test]
    fn range_without_if_range_with_no_history_is_ok() {
        let (tx, history) = sequence(&[], &[("range", "bytes=0-0")]);
        assert!(judge(&tx, &history).is_none());
    }

    #[test]
    fn range_without_any_precondition_after_partial_reports() {
        let (tx, history) = sequence(&[(206, &[("etag", "\"a\"")])], &[("range", "bytes=0-0")]);
        let v = judge(&tx, &history).expect("the stored tag has nowhere to have been sent");
        assert!(v.message.contains("carries none of If-Range"));
    }

    #[test]
    fn range_with_matching_if_range_is_ok() {
        let (tx, history) = sequence(
            &[(206, &[("etag", "\"a\"")])],
            &[("range", "bytes=0-0"), ("if-range", "\"a\"")],
        );
        assert!(judge(&tx, &history).is_none());
    }

    /// The MUST names three fields. Carrying the tag in `If-None-Match` satisfies
    /// it, and whether the value matches is the validation-chain rule's question.
    #[test]
    fn the_tag_may_travel_in_if_none_match_instead() {
        let (tx, history) = sequence(
            &[(206, &[("etag", "\"a\"")])],
            &[("range", "bytes=0-0"), ("if-none-match", "\"a\"")],
        );
        assert!(judge(&tx, &history).is_none());
    }

    #[test]
    fn the_tag_may_travel_in_if_match_instead() {
        let (tx, history) = sequence(
            &[(206, &[("etag", "\"a\"")])],
            &[("range", "bytes=0-0"), ("if-match", "\"a\"")],
        );
        assert!(judge(&tx, &history).is_none());
    }

    #[test]
    fn range_with_mismatched_if_range_reports() {
        let (tx, history) = sequence(
            &[(206, &[("etag", "\"a\"")])],
            &[("range", "bytes=0-0"), ("if-range", "\"b\"")],
        );
        let v = judge(&tx, &history).expect("\"b\" was never provided for this resource");
        assert!(v.message.contains("is not \"a\""));
    }

    /// §4.3.1's date bullets are a SHOULD that excludes subranges and a MAY that
    /// covers them. Neither makes a missing `If-Range` a defect, so the absence
    /// and a mismatching date are both silence — the earlier version of this rule
    /// reported both.
    #[test]
    fn a_date_only_stored_response_asks_for_nothing() {
        let stored: &[(&str, &str)] = &[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")];

        let (tx, history) = sequence(&[(206, stored)], &[("range", "bytes=0-0")]);
        assert!(judge(&tx, &history).is_none(), "absence is not a defect");

        let (tx, history) = sequence(
            &[(206, stored)],
            &[
                ("range", "bytes=0-0"),
                ("if-range", "Wed, 20 Oct 2015 07:28:00 GMT"),
            ],
        );
        assert!(judge(&tx, &history).is_none(), "nor is a stale date");
    }

    /// §13.1.5's second MUST NOT: the date is permitted only to a client that has
    /// no entity tag, and this one was handed one.
    #[test]
    fn a_date_in_if_range_while_holding_a_tag_reports() {
        let (tx, history) = sequence(
            &[(
                206,
                &[
                    ("etag", "\"a\""),
                    ("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ],
            )],
            &[
                ("range", "bytes=0-0"),
                ("if-range", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ],
        );
        let v = judge(&tx, &history).expect("the client holds an entity tag");
        assert!(v.message.contains("only permitted there when"));
    }

    /// The validator is not the 206's — it is the newest one the client was given.
    /// A 200 delivered after the 206 replaces the representation, and a request
    /// echoing the 206's tag is the one asking about something that is gone.
    #[test]
    fn a_later_response_replaces_the_partial_copys_validator() {
        let earlier: &[(u16, &[(&str, &str)])] =
            &[(206, &[("etag", "\"a\"")]), (200, &[("etag", "\"b\"")])];

        let (tx, history) = sequence(earlier, &[("range", "bytes=0-0"), ("if-range", "\"b\"")]);
        assert!(judge(&tx, &history).is_none(), "\"b\" is what it holds");

        let (tx, history) = sequence(earlier, &[("range", "bytes=0-0"), ("if-range", "\"a\"")]);
        let v = judge(&tx, &history).expect("\"a\" was superseded by the 200");
        assert!(v.message.contains("is not \"b\""));
    }

    /// A 304 carries no content and refreshes the stored metadata, so its
    /// validator is the current one even though the partial copy came from a 206.
    #[test]
    fn a_304_refreshes_the_validator_without_replacing_the_copy() {
        let (tx, history) = sequence(
            &[(206, &[("etag", "\"a\"")]), (304, &[("etag", "\"c\"")])],
            &[("range", "bytes=0-0"), ("if-range", "\"c\"")],
        );
        assert!(judge(&tx, &history).is_none());
    }

    #[test]
    fn partial_without_validator_skips() {
        let (tx, history) = sequence(&[(206, &[])], &[("range", "bytes=0-0")]);
        assert!(judge(&tx, &history).is_none());
    }

    #[test]
    fn previous_not_206_ignored() {
        let (tx, history) = sequence(&[(200, &[("etag", "\"a\"")])], &[("range", "bytes=0-0")]);
        assert!(judge(&tx, &history).is_none());
    }

    /// Not a tolerance: a weak tag may not be sent in `If-Range`, `If-Match`
    /// compares strongly and would never match it, and §15.3.7.3 will not let the
    /// ranges be combined on it anyway.
    #[test]
    fn weak_etag_in_prev_does_not_count_as_validator() {
        let (tx, history) = sequence(
            &[(206, &[("etag", "W/\"weak\"")])],
            &[("range", "bytes=0-0")],
        );
        assert!(judge(&tx, &history).is_none());
    }

    /// The client cannot be asked to echo a tag the server malformed;
    /// `message_etag_syntax` reports it where it was generated.
    #[test]
    fn a_malformed_stored_etag_is_not_this_rules_finding() {
        for bad in ["unquoted", "*", "\"unterminated"] {
            let (tx, history) = sequence(&[(206, &[("etag", bad)])], &[("range", "bytes=0-0")]);
            assert!(
                judge(&tx, &history).is_none(),
                "reported the client for the server's ETag {bad:?}"
            );
        }
    }

    /// `Range` is defined for GET alone. A partial PUT names its range in the
    /// request's own `Content-Range`, but one that also sends `Range` must not be
    /// read as a client re-requesting a stored fragment.
    #[test]
    fn a_range_on_another_method_is_not_a_range_request() {
        let (mut tx, history) = sequence(&[(206, &[("etag", "\"a\"")])], &[("range", "bytes=0-0")]);
        tx.request.method = "PUT".to_string();
        assert!(judge(&tx, &history).is_none());
    }

    /// A present-but-unreadable `If-Range` is not a missing one, and saying it is
    /// would make the finding false about the message on the wire.
    #[test]
    fn a_non_utf8_if_range_is_not_an_absent_one() {
        let (mut tx, history) = sequence(&[(206, &[("etag", "\"a\"")])], &[("range", "bytes=0-0")]);
        tx.request.headers.insert(
            "if-range",
            hyper::header::HeaderValue::from_bytes(&[0xff, 0xfe]).expect("header value"),
        );
        assert!(judge(&tx, &history).is_none());
    }

    /// A weak tag in `If-Range` breaks §13.1.5 and
    /// `message_conditional_headers_consistency` owns that sentence; two findings
    /// on one field would be this rule copying its neighbour's check.
    #[test]
    fn a_weak_tag_in_if_range_belongs_to_the_rule_that_owns_the_field() {
        let (tx, history) = sequence(
            &[(206, &[("etag", "\"a\"")])],
            &[("range", "bytes=0-0"), ("if-range", "W/\"a\"")],
        );
        assert!(judge(&tx, &history).is_none());
    }

    /// Neither an entity tag nor a date: this rule has a sentence about which
    /// validator belongs in the field, none about the field's shape.
    #[test]
    fn a_malformed_if_range_is_left_to_syntax_rules() {
        let (tx, history) = sequence(
            &[(206, &[("etag", "\"a\"")])],
            &[("range", "bytes=0-0"), ("if-range", "not-a-validator")],
        );
        assert!(judge(&tx, &history).is_none());
    }

    /// Every published snippet is the sequence the rule needs: the earlier
    /// response, then the later request. Nothing else runs them through the rule,
    /// and a stateful rule's examples are the easiest ones to get wrong, since a
    /// reader cannot tell from the page which message came first.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = StatefulRangeRequestAndCaching;

        let mut saw_a_finding = false;
        for ex in rule.examples() {
            let (earlier, later) = ex
                .snippet
                .split_once("\n\n")
                .expect("an example is an earlier response then a later request");

            let mut response_lines = earlier.lines();
            let status_line = response_lines.next().expect("a response has a status line");
            let status: u16 = status_line
                .strip_prefix("HTTP/1.1 ")
                .and_then(|rest| rest.split(' ').next())
                .and_then(|code| code.parse().ok())
                .unwrap_or_else(|| panic!("not a status line: {status_line:?}"));
            let stored: Vec<(&str, &str)> = response_lines
                .map(|line| {
                    line.split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {line:?}"))
                })
                .collect();

            let mut request_lines = later.lines();
            let request_line = request_lines.next().expect("a request has a request line");
            let method = request_line
                .strip_suffix(" HTTP/1.1")
                .and_then(|rest| rest.split(' ').next())
                .unwrap_or_else(|| panic!("not a request line: {request_line:?}"));
            let sent: Vec<(String, &str)> = request_lines
                .map(|line| {
                    let (name, value) = line
                        .split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {line:?}"));
                    (name.to_ascii_lowercase(), value)
                })
                .collect();
            let sent: Vec<(&str, &str)> = sent.iter().map(|(n, v)| (n.as_str(), *v)).collect();

            let (mut tx, history) = sequence(&[(status, &stored)], &sent);
            tx.request.method = method.to_string();

            let found = judge(&tx, &history);
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    assert!(
                        found.is_some(),
                        "rule accepts its NonCompliant example {:?}",
                        ex.snippet
                    );
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "the guard ran without exercising a finding");
    }

    /// A rule that only asks which validator a request carries sees nothing in
    /// its own examples beyond that, so every other field in them is published
    /// unread. Each goes past the code that owns its syntax.
    #[test]
    fn published_examples_hold_values_their_owners_accept() {
        use crate::rules::Rule as _;

        for ex in StatefulRangeRequestAndCaching.examples() {
            for line in ex.snippet.lines() {
                let Some((name, value)) = line.split_once(": ") else {
                    continue;
                };
                let tag_ok = crate::helpers::headers::validate_entity_tag(value).is_ok();
                let date_ok = crate::http_date::is_valid_imf_fixdate(value);
                match name.to_ascii_lowercase().as_str() {
                    "etag" | "if-none-match" => {
                        assert!(tag_ok, "{name} value {value:?} is not an entity-tag")
                    }
                    // The whole point of the field: one or the other, never both.
                    "if-range" => assert!(
                        tag_ok != date_ok,
                        "If-Range value {value:?} is not an entity-tag or an HTTP-date"
                    ),
                    "last-modified" => {
                        assert!(date_ok, "{name} value {value:?} is not an IMF-fixdate")
                    }
                    "content-range" => assert!(
                        crate::helpers::content_range::parse_content_range(value).is_ok(),
                        "Content-Range {value:?} does not parse"
                    ),
                    "range" => assert!(
                        crate::helpers::content_range::split_ranges_specifier(value).is_some(),
                        "Range {value:?} is not a ranges-specifier"
                    ),
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_range_request_and_caching");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_missing_severity_errors() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "stateful_range_request_and_caching",
        ]);
        if let Some(toml::Value::Table(table)) =
            cfg.rules.get_mut("stateful_range_request_and_caching")
        {
            table.remove("severity");
        }

        let res = crate::rules::validate_rules(&cfg);
        assert!(res.is_err());
    }
}
