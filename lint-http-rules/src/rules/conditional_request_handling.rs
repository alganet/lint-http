// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::conditional::{
    CONDITIONAL_VALIDATOR_MISSING, RFC_9110_13_1_3, RFC_9110_13_1_4,
};
use crate::violations::etag::RFC_9110_8_8_3;
use crate::violations::status::{
    RFC_9110_13_1_1, RFC_9110_13_1_2, STATUS_304_MISSING, STATUS_412_AMBIGUOUS, STATUS_412_MISSING,
};
use crate::violations::ViolationDef;

/// Stateful checks for conditional requests and their responses.
///
/// - Conditional request headers (`If-None-Match`, `If-Match`, `If-Modified-Since`,
///   `If-Unmodified-Since`) should only be used when the client previously
///   observed a validator (ETag or Last-Modified) for the same resource.
/// - For `If-None-Match` / `If-Modified-Since` on `GET`/`HEAD`, a response that
///   matches the validator SHOULD be `304 Not Modified` rather than a `200`.
/// - For any other method, a precondition that evaluated false against the
///   validators the resource was last seen with must not have been performed:
///   a `2xx` to a false `If-None-Match` owes a `412`, and a `2xx` to a false
///   `If-Match` / `If-Unmodified-Since` whose validator moved was performed.
pub struct ConditionalRequestHandling;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_13_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1",
    note: "Preconditions",
};
const RFC_9110_13_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.2",
    note: "Evaluation of Preconditions (precedence rules)",
};
const RFC_9110_8_8_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.8.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2",
    note: "Last-Modified header field",
};

/// Which preconditions a request carried.
///
/// The four fields are asked in three different groupings — the two entity-tag
/// ones together, the two date ones together, and `If-None-Match` alone, which
/// § 13.2.2 makes govern whether `If-Modified-Since` is evaluated at all — and
/// naming the groupings is what keeps a check from testing the wrong pair.
struct Preconditions {
    if_none_match: bool,
    if_match: bool,
    if_modified_since: bool,
    if_unmodified_since: bool,
}

impl Preconditions {
    fn of(headers: &hyper::HeaderMap) -> Self {
        Self {
            if_none_match: headers.contains_key("if-none-match"),
            if_match: headers.contains_key("if-match"),
            if_modified_since: headers.contains_key("if-modified-since"),
            if_unmodified_since: headers.contains_key("if-unmodified-since"),
        }
    }

    /// Whether the request is conditional at all.
    fn any(&self) -> bool {
        self.if_none_match || self.if_match || self.if_modified_since || self.if_unmodified_since
    }

    /// Whether a precondition compares against an entity-tag validator.
    fn entity_tag(&self) -> bool {
        self.if_none_match || self.if_match
    }

    /// Whether a precondition compares against a modification date.
    fn date(&self) -> bool {
        self.if_modified_since || self.if_unmodified_since
    }
}

/// The two methods whose failed precondition is answered with 304 rather than
/// 412, which is what makes the checks below about a `200` at all.
// cite(RFC 9110 § 13.1.2): "the 304 (Not Modified) status code if the request method is GET or HEAD"
fn is_get_or_head(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

/// The methods on which a false precondition is answered with `412` rather
/// than `304` — and on which one is evaluated at all: everything but the two
/// § 13.1.2 answers with `304`, and not the three § 13.2.1 has a server ignore
/// preconditions on, since those select no representation to condition on.
// cite(RFC 9110 § 13.2.1): "Likewise, a server MUST ignore the conditional request header fields defined by this specification when received with a request method that does not involve the selection or modification of a selected representation, such as CONNECT, OPTIONS, or TRACE."
fn is_state_changing(method: &str) -> bool {
    !is_get_or_head(method)
        && !["CONNECT", "OPTIONS", "TRACE"]
            .iter()
            .any(|m| method.eq_ignore_ascii_case(m))
}

/// A response that describes the resource's current representation: a `2xx`
/// or a `304`, to a method that selects one. A `404` describes its absence,
/// a `412` describes the precondition, and an `OPTIONS` describes the server.
fn describes_representation(tx: &crate::http_transaction::HttpTransaction) -> bool {
    tx.response.as_ref().is_some_and(|resp| {
        ((200..300).contains(&resp.status) || resp.status == 304)
            && is_state_changing(&tx.request.method) != is_get_or_head(&tx.request.method)
    })
}

/// What the resource was last seen with, which is the state a precondition is
/// evaluated against: the validators of the newest earlier response that
/// carried them, and whether the newest earlier answer said a representation
/// was current at all.
struct LastSeen {
    etag: Option<String>,
    last_modified: Option<String>,
    /// `Some(true)` where the newest answer describing the resource was a
    /// `2xx` or `304` to anything but a `DELETE`; `Some(false)` where it said
    /// there was nothing there; `None` where nothing was answered.
    representation_current: Option<bool>,
}

impl LastSeen {
    fn of(history: &crate::transaction_history::TransactionHistory) -> Self {
        let describing = || {
            history.responses().filter(|(tx, _)| {
                is_get_or_head(&tx.request.method) || is_state_changing(&tx.request.method)
            })
        };
        let seen_with = |name: &str| {
            describing()
                .filter(|(tx, _)| describes_representation(tx))
                .find_map(|(_, resp)| {
                    crate::helpers::headers::field_lines_as_written(&resp.headers, name)
                        .into_iter()
                        .next()
                        .map(|line| crate::helpers::headers::trim_ows(&line).to_string())
                })
        };
        Self {
            etag: seen_with("etag"),
            last_modified: seen_with("last-modified"),
            representation_current: describing().next().map(|(tx, _)| {
                describes_representation(tx) && !tx.request.method.eq_ignore_ascii_case("DELETE")
            }),
        }
    }
}

/// A precondition that evaluated false, with the reading that made it so.
struct Failed {
    field: &'static str,
    value: String,
    reason: String,
    /// The section whose MUST NOT the answer offends.
    section: &'static str,
    /// Whether that section lets a `2xx` stand for a change already applied.
    /// § 13.1.2 does not; § 13.1.1 and § 13.1.4 do.
    permits_2xx: bool,
}

/// The entity tags a precondition lists, as written, `*` included.
fn listed_tags(headers: &hyper::HeaderMap, name: &str) -> Vec<String> {
    crate::helpers::headers::field_lines_as_written(headers, name)
        .into_iter()
        .flat_map(|line| {
            crate::helpers::list::split_commas_respecting_quotes(&line)
                .into_iter()
                .map(|member| crate::helpers::headers::trim_ows(member).to_string())
                .collect::<Vec<_>>()
        })
        .filter(|member| !member.is_empty())
        .collect()
}

fn is_weak(tag: &str) -> bool {
    tag.len() >= 2 && tag[..2].eq_ignore_ascii_case("W/")
}

/// § 13.1.1's evaluation, with the strong comparison it mandates: a weak tag
/// on either side matches nothing. Declined on `*`, which asks about existence
/// rather than a validator, and where the resource was never seen with a tag.
// cite(RFC 9110 § 13.1.1): "If the field value is a list of entity tags, the condition is true if any of the listed tags match the entity tag of the selected representation."
// cite(RFC 9110 § 13.1.1): "An origin server MUST use the strong comparison function when comparing entity tags for If-Match (Section 8.8.3.2), since the client intends this precondition to prevent the method from being applied if there have been any changes to the representation data."
// cite(RFC 9110 § 8.8.3.2): "two entity tags are equivalent if both are not weak and their opaque-tags match character-by-character."
fn if_match_failed(headers: &hyper::HeaderMap, seen: &LastSeen) -> Option<Failed> {
    let listed = listed_tags(headers, "if-match");
    if listed.iter().any(|t| t == "*") {
        return None;
    }
    let current = seen.etag.as_deref()?;
    let value = listed.join(", ");
    let reason = if is_weak(current) {
        format!(
            "the resource's entity tag was the weak {current}, which the strong comparison \
             § 13.1.1 requires of If-Match can never match"
        )
    } else if listed.iter().any(|t| !is_weak(t) && t == current) {
        return None;
    } else {
        format!("the resource's entity tag was {current} when the request was made")
    };
    Some(Failed {
        field: "If-Match",
        value,
        reason,
        section: "13.1.1",
        permits_2xx: true,
    })
}

/// § 13.1.4's evaluation, asked only where no `If-Match` was sent, and
/// declined wherever the section has the recipient ignore the field: a value
/// that is no HTTP-date, or a resource that was never seen with a
/// modification date.
// cite(RFC 9110 § 13.1.4): "A recipient MUST ignore If-Unmodified-Since if the request contains an If-Match header field"
// cite(RFC 9110 § 13.1.4): "A recipient MUST ignore the If-Unmodified-Since header field if the resource does not have a modification date available."
// cite(RFC 9110 § 13.1.4): "If the selected representation's last modification date is earlier than or equal to the date provided in the field value, the condition is true."
fn if_unmodified_since_failed(headers: &hyper::HeaderMap, seen: &LastSeen) -> Option<Failed> {
    let since = crate::http_date::header_timestamp(headers, "if-unmodified-since")?;
    let last_modified = seen.last_modified.as_deref()?;
    let modified = crate::http_date::parse_http_date_to_datetime(last_modified).ok()?;
    (modified > since).then(|| Failed {
        field: "If-Unmodified-Since",
        value: crate::helpers::headers::get_header_str(headers, "if-unmodified-since")
            .unwrap_or_default()
            .trim()
            .to_string(),
        reason: format!("the resource was last modified {last_modified}, which is later"),
        section: "13.1.4",
        permits_2xx: true,
    })
}

/// § 13.1.2's evaluation: `*` is false where a representation is current,
/// and a list is false where a member weakly matches the current tag.
// cite(RFC 9110 § 13.1.2): "If the field value is "*", the condition is false if the origin server has a current representation for the target resource."
// cite(RFC 9110 § 13.1.2): "If the field value is a list of entity tags, the condition is false if one of the listed tags matches the entity tag of the selected representation."
fn if_none_match_failed(headers: &hyper::HeaderMap, seen: &LastSeen) -> Option<Failed> {
    let listed = listed_tags(headers, "if-none-match");
    let failed = |reason: String| Failed {
        field: "If-None-Match",
        value: listed.join(", "),
        reason,
        section: "13.1.2",
        permits_2xx: false,
    };
    if listed.iter().any(|t| t == "*") {
        return (seen.representation_current == Some(true))
            .then(|| failed("a representation was current: the resource had answered the earlier request with one".into()));
    }
    let current = seen.etag.as_deref()?;
    let matched = listed
        .iter()
        .find(|t| crate::helpers::validator::inm_matches_known(t, current))?;
    Some(failed(format!(
        "{matched} matches the entity tag the resource was last seen with, {current}"
    )))
}

/// The precondition the request failed, in the order § 13.2.2 evaluates them:
/// `If-Match` before `If-Unmodified-Since` (which it displaces), and
/// `If-None-Match` after either held.
// cite(RFC 9110 § 13.2.2): "A recipient cache or origin server MUST evaluate the request preconditions defined by this specification in the following order:"
fn failed_precondition(headers: &hyper::HeaderMap, seen: &LastSeen) -> Option<Failed> {
    let first = if headers.contains_key("if-match") {
        if_match_failed(headers, seen)
    } else {
        if_unmodified_since_failed(headers, seen)
    };
    first.or_else(|| if_none_match_failed(headers, seen))
}

/// A validator the `2xx` carries, beside the one the resource was last seen
/// with.
struct Compared {
    kind: &'static str,
    now: String,
    then: String,
    moved: bool,
}

/// Whether the `2xx` shows the representation moved: a validator on the
/// response that differs from the one the resource was last seen with.
/// `None` where the response carries nothing to compare.
fn state_moved(resp: &crate::http_transaction::ResponseInfo, seen: &LastSeen) -> Option<Compared> {
    let (etag, last_modified) =
        crate::helpers::validator::extract_validators_from_response(&resp.headers);
    if let (Some(now), Some(then)) = (etag, seen.etag.as_deref()) {
        let moved = crate::helpers::validator::normalize_etag(&now)
            != crate::helpers::validator::normalize_etag(then);
        return Some(Compared {
            kind: "ETag",
            now,
            then: then.to_string(),
            moved,
        });
    }
    let (now, then) = (last_modified?, seen.last_modified.as_deref()?);
    let moved = match (
        crate::http_date::parse_http_date_to_datetime(&now),
        crate::http_date::parse_http_date_to_datetime(then),
    ) {
        (Ok(a), Ok(b)) => a != b,
        _ => now.trim() != then.trim(),
    };
    Some(Compared {
        kind: "Last-Modified",
        now,
        then: then.to_string(),
        moved,
    })
}

impl ConditionalRequestHandling {
    /// A precondition carries validator metadata from a stored response, so a
    /// client sending one should have been given that validator.
    ///
    /// Requiring the client to have *previously observed* the validator is a
    /// stateful heuristic with no governing MUST/SHOULD in RFC 9110 (recorded
    /// §4.1) — `If-None-Match: *` legitimately needs no prior tag — so none of
    /// these findings carries a cite.
    /// Whether any response this exchange holds for the resource actually
    /// carried the validator the precondition names.
    ///
    /// **The question this whole function is named for is about a value, and
    /// the tests below never ask it.** They ask whether the *immediately
    /// previous* response happened to carry a validator of the right kind,
    /// which is a different question with a different answer: one unrelated
    /// response between the store and the revalidation — a `503`, a redirect,
    /// anything an origin emits without an `ETag` — makes a client conditioning
    /// on exactly the tag it was given read as a client that invented one.
    /// History is already scoped to this (client, resource) pair by the rule's
    /// `ByResource` query, so every response here is one for this resource.
    fn entity_tag_was_provided(
        headers: &hyper::HeaderMap,
        history: &crate::transaction_history::TransactionHistory,
    ) -> bool {
        let lines: Vec<String> = ["if-none-match", "if-match"]
            .iter()
            .flat_map(|name| crate::helpers::headers::field_lines_as_written(headers, name))
            .collect();
        !lines.is_empty()
            && history.responses().any(|(_, resp)| {
                crate::helpers::validator::extract_validators_from_response(&resp.headers)
                    .0
                    .is_some_and(|known| {
                        lines
                            .iter()
                            .any(|line| crate::helpers::validator::inm_matches_known(line, &known))
                    })
            })
    }

    /// [`Self::entity_tag_was_provided`]'s other half. Two spellings of one
    /// instant are one validator, so the comparison is on parsed instants where
    /// both sides parse and on the text where either does not.
    fn last_modified_was_provided(
        headers: &hyper::HeaderMap,
        history: &crate::transaction_history::TransactionHistory,
    ) -> bool {
        let sent: Vec<String> = ["if-modified-since", "if-unmodified-since"]
            .iter()
            .filter_map(|name| crate::helpers::headers::get_header_str(headers, name))
            .map(|v| v.trim().to_string())
            .collect();
        !sent.is_empty()
            && history.responses().any(|(_, resp)| {
                crate::helpers::validator::extract_validators_from_response(&resp.headers)
                    .1
                    .is_some_and(|known| {
                        let known = known.trim();
                        sent.iter().any(|s| {
                            match (
                                crate::http_date::parse_http_date_to_datetime(s),
                                crate::http_date::parse_http_date_to_datetime(known),
                            ) {
                                (Ok(a), Ok(b)) => a == b,
                                _ => s == known,
                            }
                        })
                    })
            })
    }

    /// Whether the entity-tag preconditions the request carried name an entity
    /// tag at all.
    ///
    /// **`*` is an existence condition, not a validator.** It asks whether the
    /// origin holds any current representation, and a client that has never
    /// been handed a tag may write it and be right — which is why the entry
    /// below has nothing to say about a request whose only entity-tag
    /// precondition is `*`. A field written with nothing in it names no tag
    /// either; that absence is `conditional_empty`'s finding, not this one's.
    // cite(RFC 9110 § 13.1.1): "If-Match = "*" / #entity-tag"
    // cite(RFC 9110 § 13.1.2): "If-None-Match = "*" / #entity-tag"
    fn names_an_entity_tag(headers: &hyper::HeaderMap) -> bool {
        ["if-none-match", "if-match"]
            .iter()
            .flat_map(|name| crate::helpers::headers::field_lines_as_written(headers, name))
            .flat_map(|line| {
                crate::helpers::list::split_commas_respecting_quotes(&line)
                    .into_iter()
                    .map(|member| crate::helpers::headers::trim_ows(member).to_string())
                    .collect::<Vec<_>>()
            })
            .any(|member| !member.is_empty() && member != "*")
    }

    /// A precondition naming a validator no response for this resource carried.
    ///
    /// **The claim is about a value, so the whole history answers it and the
    /// most recent response does not.** Asking whether the immediately previous
    /// response happened to carry a field of the right kind answers a different
    /// question from where an unrelated exchange landed in the history: one
    /// `TRACE` answered `405` between the store and the revalidation turned a
    /// client holding exactly the tag it was given into a client that invented
    /// one, and — in the other direction — let a client that really did invent
    /// a tag pass unremarked whenever the response before it happened to carry
    /// some other `ETag`. Both are decided here by the tag the request wrote.
    fn validator_was_observed(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        sent: &Preconditions,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let names_tag = sent.entity_tag() && Self::names_an_entity_tag(&tx.request.headers);

        // A validator this exchange did provide is not one it never provided,
        // whatever the most recent response happens to carry.
        if (names_tag && Self::entity_tag_was_provided(&tx.request.headers, history))
            || (sent.date() && Self::last_modified_was_provided(&tx.request.headers, history))
        {
            return None;
        }

        // Nothing but an existence condition was written, so no validator was
        // named and none can be unaccounted for.
        if !names_tag && !sent.date() {
            return None;
        }

        // The one statement here about the observer rather than the sender:
        // nothing was recorded for this resource, so there was nothing for a
        // validator to have come from.
        if history.responses().next().is_none() {
            return Some(ctx.by_client().report_with(
                &CONDITIONAL_VALIDATOR_MISSING,
                "Conditional request sent but no previous response recorded for this resource (no ETag/Last-Modified to validate against)".into(),
            ));
        }

        if names_tag {
            return Some(ctx.by_client().report_with(
                &CONDITIONAL_VALIDATOR_MISSING,
                "Request conditions on an entity-tag (If-Match/If-None-Match) that no response for this resource carried".into(),
            ));
        }
        Some(ctx.by_client().report_with(
            &CONDITIONAL_VALIDATOR_MISSING,
            "Request conditions on a modification date (If-Modified-Since/If-Unmodified-Since) that no response for this resource carried".into(),
        ))
    }

    /// A GET or HEAD whose `If-None-Match` condition is false is answered with
    /// 304, not 200.
    ///
    /// The members are compared exactly rather than by the weak comparison
    /// § 8.8.3.2 mandates: a deliberate narrowing that only ever under-flags,
    /// since an exact match is also a weak match.
    // cite(RFC 9110 § 13.1.2): "An origin server that evaluates an If-None-Match condition MUST NOT perform the requested method if the condition evaluates to false; instead, the origin server MUST respond with either a) the 304 (Not Modified) status code if the request method is GET or HEAD or b) the 412 (Precondition Failed) status code for all other request methods."
    fn if_none_match_was_evaluated(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        sent: &Preconditions,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        if !sent.if_none_match || !is_get_or_head(&tx.request.method) {
            return None;
        }
        let resp = tx.response.as_ref()?;
        if resp.status != 200 {
            return None;
        }
        let etag = crate::helpers::headers::get_header_str(&resp.headers, "etag")?.trim();
        let condition_was_false =
            crate::helpers::headers::field_lines(&tx.request.headers, "if-none-match")
                .flat_map(crate::helpers::list::list_members)
                .any(|member| member == etag || member == "*");

        condition_was_false.then(|| ctx.by_server().report_with(&STATUS_304_MISSING, "Conditional GET/HEAD: the If-None-Match condition was not met (response ETag matched) but the server returned 200; RFC 9110 \u{a7}13.1.2 requires a 304 (Not Modified) for GET/HEAD".into()))
    }

    /// A GET or HEAD whose `If-Modified-Since` condition is false should be
    /// answered with 304 — a SHOULD here, unlike § 13.1.2's MUST.
    ///
    /// Asked only where `If-None-Match` is absent: § 13.2.2 evaluates
    /// `If-Modified-Since` only then, so with both present the check above
    /// governs and a 200 may be perfectly legal.
    // cite(RFC 9110 § 13.1.3): "An origin server that evaluates an If-Modified-Since condition SHOULD NOT perform the requested method if the condition evaluates to false; instead, the origin server SHOULD generate a 304 (Not Modified) response"
    // cite(RFC 9110 § 13.2.2): "When the method is GET or HEAD, If-None-Match is not present, and If-Modified-Since is present, evaluate the If-Modified-Since precondition"
    fn if_modified_since_was_evaluated(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        sent: &Preconditions,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        if !sent.if_modified_since || sent.if_none_match || !is_get_or_head(&tx.request.method) {
            return None;
        }
        let resp = tx.response.as_ref()?;
        if resp.status != 200 {
            return None;
        }
        let since = crate::http_date::header_timestamp(&tx.request.headers, "if-modified-since")?;
        let last_modified = crate::http_date::header_timestamp(&resp.headers, "last-modified")?;

        (last_modified <= since).then(|| ctx.by_server().report_with(&STATUS_304_MISSING, "Conditional GET/HEAD used If-Modified-Since but server returned 200 even though Last-Modified indicates the resource was not modified; RFC 9110 \u{a7}13.1.3 says such a response SHOULD be a 304 (Not Modified)".into()))
    }

    /// A state-changing request whose precondition evaluated false, answered
    /// with a `2xx`.
    ///
    /// The precondition is evaluated here against the validators the resource
    /// was last seen with, in § 13.2.2's order. A false `If-None-Match` is
    /// decided by the `2xx` alone, since § 13.1.2 leaves it no answer but
    /// `412`. A false `If-Match` or `If-Unmodified-Since` is decided by what
    /// the response carries: a validator that moved says the method was
    /// performed, one that held says the change was already in place — the
    /// answer § 13.1.1 permits — and none at all leaves the two apart only by
    /// the ambiguity, which is what the second entry reports.
    fn precondition_on_state_change_was_evaluated(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        if !is_state_changing(&tx.request.method) {
            return None;
        }
        let resp = tx.response.as_ref()?;
        if !(200..300).contains(&resp.status) {
            return None;
        }
        let seen = LastSeen::of(history);
        let failed = failed_precondition(&tx.request.headers, &seen)?;
        let method = tx.request.method.as_str();
        let status = resp.status;
        let Failed {
            field,
            value,
            reason,
            section,
            permits_2xx,
        } = failed;
        if !permits_2xx {
            return Some(ctx.by_server().report_with(
                &STATUS_412_MISSING,
                format!(
                    "{method} carried {field}: {value}, and {reason}, so the condition was \
                     false; RFC 9110 \u{a7}{section} requires a 412 for any method other than \
                     GET or HEAD, and the server answered {status}"
                ),
            ));
        }
        match state_moved(resp, &seen) {
            Some(Compared {
                kind,
                now,
                then,
                moved: true,
            }) => Some(ctx.by_server().report_with(
                &STATUS_412_MISSING,
                format!(
                    "{method} carried {field}: {value}, and {reason}, so the condition was \
                     false; the server answered {status} with {kind} {now}, so the method was \
                     performed \u{2014} RFC 9110 \u{a7}{section} says an origin server MUST NOT \
                     perform it, and the 2xx it allows for a change already applied would have \
                     left the {kind} at {then}"
                ),
            )),
            Some(Compared { moved: false, .. }) => None,
            None => Some(ctx.by_server().report_with(
                &STATUS_412_AMBIGUOUS,
                format!(
                    "{method} carried {field}: {value}, and {reason}, so the condition was \
                     false, and the server answered {status} with no validator: either the \
                     origin performed a method RFC 9110 \u{a7}{section} says it MUST NOT, or the \
                     change had already been applied and a 2xx was permitted \u{2014} nothing in \
                     the response says which"
                ),
            )),
        }
    }
}

/// The heuristic half of this rule, and the only entry it declares that no
/// sentence supports.
///
/// A precondition built from a validator this exchange never provided is a
/// stateful guess — legitimate explanations exist for every one of the four
/// situations it covers — so the entry names no section and defaults to `info`.
/// The rest of what this rule reports is a *status code* answering a false
/// precondition, which is the `status` subject's: the defect is that a `200`
/// was sent, and it is read out of two messages the way every entry there is.
static DECLARED: &[&ViolationDef] = &[
    &CONDITIONAL_VALIDATOR_MISSING,
    &STATUS_304_MISSING,
    &STATUS_412_MISSING,
    &STATUS_412_AMBIGUOUS,
];

impl RuleMeta for ConditionalRequestHandling {
    fn id(&self) -> &'static str {
        "conditional_request_handling"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Warn when a conditional request names a validator (ETag / Last-Modified) that no response for the same resource and client ever carried. **The question is about the value, not about the response that happened to arrive last**: a tag an earlier response handed out is accounted for however many validator-less responses have followed it, and a tag no response ever carried is unaccounted for however recently some *other* tag was sent. `If-None-Match: *` and `If-Match: *` are not reported at all — `*` is an existence condition, names no validator, and is a legitimate thing for a client holding nothing to send. Also flag obvious cases where a server returns a `200` for a conditional `GET`/`HEAD` when the validator clearly matches (the server should return `304 Not Modified`)."
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **Two questions of two peers, which is why no presumption fits.**
    /// `validator_was_observed` reports a request built from a validator this
    /// exchange never handed out — the client's precondition, and the
    /// client's defect. The two `if_*_was_evaluated` checks report a `200`
    /// where the precondition the client sent evaluated false, which §13.1.2
    /// addresses to the origin server: there the request is the yardstick and
    /// the status line is the evidence.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_13_1,
            RFC_9110_13_1_1,
            RFC_9110_13_1_2,
            RFC_9110_13_1_3,
            RFC_9110_13_1_4,
            RFC_9110_13_2,
            RFC_9110_8_8_3,
            RFC_9110_8_8_2,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— the tag the request names is the one the resource handed over"),
                snippet: "> GET /resource HTTP/1.1\n\n< 200 OK  HTTP/1.1\n< ETag: \"abc\"\n\n> GET /resource HTTP/1.1\n> If-None-Match: \"abc\"\n\n< 304 Not Modified  HTTP/1.1\n< ETag: \"abc\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— conditional request with no prior validator recorded"),
                snippet: "> GET /resource HTTP/1.1\n> If-None-Match: \"abc\"\n\n< 200 OK  HTTP/1.1\n< ETag: \"abc\"\n\n< (body)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— client used conditional header without previously seeing an ETag/Last-Modified"),
                snippet: "> GET /resource HTTP/1.1\n> If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT\n\n< 200 OK  HTTP/1.1\n< Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— the condition was not met, so the response owed is 304 and not a second copy"),
                snippet: "> GET /resource HTTP/1.1\n\n< 200 OK  HTTP/1.1\n< ETag: \"abc\"\n\n> GET /resource HTTP/1.1\n> If-None-Match: \"abc\"\n\n< 200 OK  HTTP/1.1\n< ETag: \"abc\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— the tag the PUT conditioned on was the current one, so the method was performed"),
                snippet: "> GET /doc HTTP/1.1\n\n< 200 OK  HTTP/1.1\n< ETag: \"v2\"\n\n> PUT /doc HTTP/1.1\n> If-Match: \"v2\"\n\n< 200 OK  HTTP/1.1\n< ETag: \"v3\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— the PUT conditioned on a tag the resource no longer had, and the tag moved anyway: the lost update went through"),
                snippet: "> GET /doc HTTP/1.1\n\n< 200 OK  HTTP/1.1\n< ETag: \"v2\"\n\n> PUT /doc HTTP/1.1\n> If-Match: \"v1\"\n\n< 200 OK  HTTP/1.1\n< ETag: \"v3\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a create-only PUT on a resource that already had a representation owes a 412"),
                snippet: "> GET /doc HTTP/1.1\n\n< 200 OK  HTTP/1.1\n< ETag: \"v2\"\n\n> PUT /doc HTTP/1.1\n> If-None-Match: *\n\n< 200 OK  HTTP/1.1\n< ETag: \"v2\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— the same false If-Match answered 204 with nothing to say whether the change had already been applied"),
                snippet: "> GET /doc HTTP/1.1\n\n< 200 OK  HTTP/1.1\n< ETag: \"v2\"\n\n> PUT /doc HTTP/1.1\n> If-Match: \"v1\"\n\n< 204 No Content  HTTP/1.1",
            },
        ]
    }
}

impl Rule for ConditionalRequestHandling {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let sent = Preconditions::of(&tx.request.headers);
        if !sent.any() {
            return Vec::new();
        }
        // Two peers, two findings, and neither stands in for the other. The
        // client's precondition is judged against what this exchange handed
        // it; the origin's answer is judged against the precondition as sent,
        // whatever the client built it from. A tag no response for this
        // resource carried is the client's defect, and a `200` returned to
        // that same tag when the response's own `ETag` matches it is the
        // origin's — and answering the first used to end the reading before
        // the second was asked, so the server's finding existed only on
        // exchanges where the client had done nothing wrong.
        let mut out = Vec::new();
        out.extend(self.validator_was_observed(tx, &sent, history, ctx));
        // The two `304` readings are exclusive by § 13.2.2, which evaluates
        // `If-Modified-Since` only where `If-None-Match` is absent.
        // The three origin readings are exclusive: the two `304` ones by
        // § 13.2.2, which evaluates `If-Modified-Since` only where
        // `If-None-Match` is absent, and the `412` one by method.
        out.extend(
            self.if_none_match_was_evaluated(tx, &sent, ctx)
                .or_else(|| self.if_modified_since_was_evaluated(tx, &sent, ctx))
                .or_else(|| self.precondition_on_state_change_was_evaluated(tx, history, ctx)),
        );
        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ConditionalRequestHandling;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    fn make_prev_with_headers(
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, headers);
        prev.request.method = "GET".to_string();
        prev
    }

    /// `TransactionHistory` is newest-first and debug-asserts it, while the
    /// fixtures above stamp themselves at construction — so a two-entry history
    /// has to say which one is older rather than rely on the order it was
    /// written in.
    fn aged(
        mut tx: crate::http_transaction::HttpTransaction,
        seconds: i64,
    ) -> crate::http_transaction::HttpTransaction {
        tx.timestamp -= chrono::Duration::seconds(seconds);
        tx
    }

    /// Four situations, one entry, because the claim is the same in all four:
    /// the precondition names a validator this exchange cannot account for.
    /// Two of them are about what the proxy observed and two about what the
    /// server sent, and the message is where that difference belongs.
    #[test]
    fn every_unaccountable_validator_draws_one_id() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "conditional_request_handling",
        ]);

        // Nothing stored at all.
        let found = crate::test_helpers::run_rule(
            &ConditionalRequestHandling,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("a finding");
        assert_eq!(found.violation, "conditional_validator_missing");

        // A stored response that carried no ETag for the tag conditional to
        // have come from.
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            make_prev_with_headers(&[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")]),
        ]);
        let found = crate::test_helpers::run_rule(&ConditionalRequestHandling, &tx, &history, &cfg)
            .expect("a finding");
        assert_eq!(found.violation, "conditional_validator_missing");
    }

    /// A validator this exchange *did* provide is not one it never provided.
    ///
    /// The entry's claim is about the value, so one unrelated response between
    /// the store and the revalidation must not change the answer: an origin
    /// that emits a `503` — or anything else without a validator — leaves the
    /// client holding exactly the tag it was given, and it is still that tag.
    #[test]
    fn a_validator_an_earlier_response_carried_is_not_one_that_was_never_provided() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "conditional_request_handling",
        ]);
        // Newest first: the blip, then the response that handed out the tag.
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            aged(make_prev_with_headers(&[("cache-control", "no-store")]), 1),
            aged(make_prev_with_headers(&[("etag", "\"v1\"")]), 2),
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v1\"")]);
        assert!(
            crate::test_helpers::run_rule(&ConditionalRequestHandling, &tx, &history, &cfg)
                .is_none(),
            "the exchange provided \"v1\"; a later response without an ETag does not unprovide it"
        );

        // The same shape on the date half of the entry.
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            aged(make_prev_with_headers(&[("cache-control", "no-store")]), 1),
            aged(
                make_prev_with_headers(&[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")]),
                2,
            ),
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        assert!(
            crate::test_helpers::run_rule(&ConditionalRequestHandling, &tx, &history, &cfg)
                .is_none(),
            "the exchange provided that Last-Modified"
        );
    }

    /// The narrowing above turns on the value and on nothing else: a tag no
    /// response ever carried is still unaccountable, however many responses
    /// carried some other one.
    #[test]
    fn a_tag_no_response_carried_is_still_unaccountable() {
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            aged(make_prev_with_headers(&[("cache-control", "no-store")]), 1),
            aged(make_prev_with_headers(&[("etag", "\"v2\"")]), 2),
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v1\"")]);
        let found = crate::test_helpers::run_rule(
            &ConditionalRequestHandling,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        )
        .expect("a finding");
        assert_eq!(found.violation, "conditional_validator_missing");
    }

    /// The response that happened to arrive last does not decide it in the
    /// other direction either.
    ///
    /// A client conditioning on a tag nothing ever handed it is the case this
    /// entry exists for, and it stayed silent whenever the newest response
    /// carried some *other* `ETag` — the field was there, of the right kind,
    /// belonging to a different representation, and the positional test asked
    /// only whether the field was there.
    #[test]
    fn a_tag_no_response_carried_is_reported_even_when_the_newest_one_carried_another() {
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            make_prev_with_headers(&[("etag", "\"v2\"")]),
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-match", "\"v1\"")]);
        let found = crate::test_helpers::run_rule(
            &ConditionalRequestHandling,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        )
        .expect("a finding");
        assert_eq!(found.violation, "conditional_validator_missing");
    }

    /// The message is a claim about the resource's history, so it has to be one
    /// the history bears out.
    ///
    /// "The previous response did not include an ETag" was true only of the one
    /// response it looked at, and false of the exchange: six earlier responses
    /// for the resource had carried tags, and the client's was still none of
    /// them.
    #[test]
    fn the_message_names_the_history_and_not_the_response_before_it() {
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            aged(make_prev_with_headers(&[("cache-control", "no-store")]), 1),
            aged(make_prev_with_headers(&[("etag", "\"v2\"")]), 2),
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"v1\"")]);
        let found = crate::test_helpers::run_rule(
            &ConditionalRequestHandling,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        )
        .expect("a finding");
        assert!(
            found
                .message
                .contains("no response for this resource carried"),
            "the claim is about every response for the resource: {}",
            found.message
        );
    }

    /// `*` names no validator, so there is none this exchange failed to
    /// provide.
    ///
    /// An existence condition asks whether the origin holds any current
    /// representation. A client that has never been handed a tag may write it
    /// and be right, whatever the responses before it carried.
    #[rstest]
    #[case("if-none-match", "*")]
    #[case("if-match", "*")]
    #[case("if-none-match", " * ")]
    fn an_existence_condition_names_no_validator_to_be_missing(
        #[case] field: &str,
        #[case] value: &str,
    ) {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "conditional_request_handling",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(field, value)]);

        for history in [
            crate::transaction_history::TransactionHistory::empty(),
            crate::transaction_history::TransactionHistory::from_transactions(vec![
                make_prev_with_headers(&[("cache-control", "no-store")]),
            ]),
        ] {
            assert!(
                crate::test_helpers::run_rule(&ConditionalRequestHandling, &tx, &history, &cfg)
                    .is_none(),
                "`*` is an existence condition and names no validator"
            );
        }
    }

    #[test]
    fn conditional_request_without_previous_is_reported() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);

        let rule = ConditionalRequestHandling;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("no previous response recorded"));
    }

    #[test]
    fn conditional_request_requires_matching_previous_validator() {
        let rule = ConditionalRequestHandling;

        // If-None-Match without previous ETag -> violation
        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let prev_empty = make_prev_with_headers(&[]);
        let v1 = crate::test_helpers::run_rule(
            &rule,
            &tx1,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![
                prev_empty.clone()
            ]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v1.is_some());

        // If-Modified-Since without previous Last-Modified -> violation
        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![
                prev_empty.clone()
            ]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v2.is_some());

        // If-Match without previous ETag -> violation
        let mut tx3 = crate::test_helpers::make_test_transaction();
        tx3.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-match", "\"a\"")]);
        let v3 = crate::test_helpers::run_rule(
            &rule,
            &tx3,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![
                prev_empty.clone()
            ]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v3.is_some());

        // If-Unmodified-Since without previous Last-Modified -> violation
        let mut tx4 = crate::test_helpers::make_test_transaction();
        tx4.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-unmodified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let v4 = crate::test_helpers::run_rule(
            &rule,
            &tx4,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev_empty]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v4.is_some());
    }

    #[test]
    fn conditional_request_with_prev_etag_or_lm_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);

        // previous response with ETag
        let prev = make_prev_with_headers(&[("etag", "\"a\"")]);

        let rule = ConditionalRequestHandling;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v.is_none());

        // time-based conditional with Last-Modified
        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let prev2 = make_prev_with_headers(&[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")]);
        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev2]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v2.is_none());
    }

    #[test]
    fn inm_response_matching_etag_reports_violation_for_get() {
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"a\"")]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.request.method = "GET".to_string();

        let prev = make_prev_with_headers(&[("etag", "\"a\"")]);

        let rule = ConditionalRequestHandling;
        // previous satisfies validator check
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("304"));
        assert!(msg.contains("§13.1.2"));
    }

    #[test]
    fn if_modified_since_response_matching_lm_reports_violation_for_get() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")],
        );
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        tx.request.method = "GET".to_string();

        let prev = make_prev_with_headers(&[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")]);

        let rule = ConditionalRequestHandling;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        let v = v.expect("a finding");
        assert_eq!(v.violation, "status_304_missing");
        // The entry names two sections and governs by neither, so the message
        // carries the one it was read from.
        assert!(v.message.contains("\u{a7}13.1.3"), "{}", v.message);
    }

    #[test]
    fn ims_304_not_flagged_when_if_none_match_present() {
        // Both If-None-Match and If-Modified-Since present. Per RFC 9110 §13.2.2, only
        // If-None-Match is evaluated; its condition is TRUE here (response ETag "b" does not
        // match the request tag "a"), so the 200 is legal and the If-Modified-Since→304
        // check must NOT fire even though Last-Modified is not more recent than the IMS value.
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("etag", "\"b\""),
                ("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ],
        );
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-none-match", "\"a\""),
            ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);
        tx.request.method = "GET".to_string();

        let prev = make_prev_with_headers(&[
            ("etag", "\"a\""),
            ("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);

        let rule = ConditionalRequestHandling;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(
            v.is_none(),
            "IMS→304 must not fire when If-None-Match is present: {v:?}"
        );
    }

    #[test]
    fn if_none_match_non_matching_etag_is_ok() {
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"b\"")]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.request.method = "GET".to_string();

        let prev = make_prev_with_headers(&[("etag", "\"a\"")]);

        let rule = ConditionalRequestHandling;
        // response ETag doesn't match request conditional -> allowed
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v.is_none());
    }

    /// A history of transactions none of which was answered holds no response,
    /// which is the same statement as an empty one — so it draws the same
    /// message. The stored request that went unanswered is not a response that
    /// withheld a validator.
    #[test]
    fn a_history_whose_transactions_were_never_answered_holds_no_response() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);

        // previous transaction exists but has no response
        let prev = crate::test_helpers::make_test_transaction();

        let rule = ConditionalRequestHandling;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v
            .expect("a finding")
            .message
            .contains("no previous response recorded for this resource"));
    }

    /// The client's finding does not stand in for the origin's. A tag no
    /// response for this resource handed out is the client's defect, and a
    /// `200` whose own `ETag` matches that same tag is the origin's; one
    /// exchange can carry both, and reporting the first used to end the
    /// reading before the second was asked.
    #[test]
    fn the_clients_invented_tag_does_not_hide_the_origins_missing_304() {
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"a\"")]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.request.method = "GET".to_string();
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![
            make_prev_with_headers(&[("etag", "\"v2\"")]),
        ]);
        let ids: Vec<String> = crate::test_helpers::run_rule_all(
            &ConditionalRequestHandling,
            &tx,
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        )
        .into_iter()
        .map(|v| v.violation)
        .collect();
        assert_eq!(
            ids,
            vec!["conditional_validator_missing", "status_304_missing"],
            "both peers erred on this exchange, and both are reported"
        );
    }

    /// One earlier response for the resource, then the request under test;
    /// what comes back is every id the exchange drew, in order.
    fn story(
        prev: &[(&str, &str)],
        prev_method: &str,
        prev_status: u16,
        method: &str,
        req: &[(&str, &str)],
        status: u16,
        resp: &[(&str, &str)],
    ) -> Vec<String> {
        let mut earlier =
            crate::test_helpers::make_test_transaction_with_response(prev_status, prev);
        earlier.request.method = prev_method.to_string();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, resp);
        tx.request.method = method.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(req);
        crate::test_helpers::run_rule_all(
            &ConditionalRequestHandling,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![aged(
                earlier, 1,
            )]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        )
        .into_iter()
        .map(|v| v.violation)
        .collect()
    }

    const LM: &str = "Wed, 21 Oct 2015 07:28:00 GMT";
    const EARLIER: &str = "Tue, 20 Oct 2015 07:28:00 GMT";
    const LATER: &str = "Thu, 22 Oct 2015 07:28:00 GMT";

    /// A false precondition on a state-changing request, and what the answer
    /// showed. The tag moving is the method performed; the tag holding is the
    /// change § 13.1.1 lets a `2xx` acknowledge; no tag at all is the
    /// ambiguity; and a false `If-None-Match` needs no such evidence.
    #[rstest]
    #[case::if_match_tag_moved("PUT", &[("if-match", "\"v1\"")], 200, &[("etag", "\"v3\"")], Some("status_412_missing"))]
    #[case::if_match_answered_created("POST", &[("if-match", "\"v1\"")], 201, &[("etag", "\"v3\"")], Some("status_412_missing"))]
    #[case::if_match_no_validator("PUT", &[("if-match", "\"v1\"")], 204, &[], Some("status_412_ambiguous"))]
    #[case::if_match_tag_held("PUT", &[("if-match", "\"v1\"")], 200, &[("etag", "\"v2\"")], None)]
    #[case::if_match_true("PUT", &[("if-match", "\"v2\"")], 200, &[("etag", "\"v3\"")], None)]
    #[case::if_match_true_among_several("PUT", &[("if-match", "\"v1\", \"v2\"")], 200, &[("etag", "\"v3\"")], None)]
    #[case::if_match_answered_412("PUT", &[("if-match", "\"v1\"")], 412, &[], None)]
    #[case::if_match_star_is_not_a_validator("PUT", &[("if-match", "*")], 200, &[("etag", "\"v3\"")], None)]
    #[case::if_match_on_get_is_a_caches_to_ignore("GET", &[("if-match", "\"v1\"")], 200, &[("etag", "\"v2\"")], None)]
    #[case::options_ignores_preconditions("OPTIONS", &[("if-match", "\"v1\"")], 200, &[], None)]
    #[case::if_none_match_star_on_a_current_representation("PUT", &[("if-none-match", "*")], 200, &[("etag", "\"v2\"")], Some("status_412_missing"))]
    #[case::if_none_match_matching_weakly("PUT", &[("if-none-match", "W/\"v2\"")], 204, &[], Some("status_412_missing"))]
    #[case::if_none_match_true("PUT", &[("if-none-match", "\"v1\"")], 200, &[("etag", "\"v3\"")], None)]
    #[case::if_match_true_then_if_none_match_false("PUT", &[("if-match", "\"v2\""), ("if-none-match", "\"v2\"")], 200, &[], Some("status_412_missing"))]
    #[case::if_unmodified_since_displaced_by_if_match("PUT", &[("if-match", "\"v2\""), ("if-unmodified-since", EARLIER)], 200, &[("etag", "\"v3\"")], None)]
    fn a_false_precondition_on_a_state_changing_request(
        #[case] method: &str,
        #[case] req: &[(&str, &str)],
        #[case] status: u16,
        #[case] resp: &[(&str, &str)],
        #[case] expected: Option<&str>,
    ) {
        let ids = story(
            &[("etag", "\"v2\""), ("last-modified", LM)],
            "GET",
            200,
            method,
            req,
            status,
            resp,
        );
        let drawn: Vec<&str> = ids
            .iter()
            .map(String::as_str)
            .filter(|id| id.starts_with("status_412_"))
            .collect();
        assert_eq!(drawn, Vec::from_iter(expected), "{ids:?}");
    }

    /// The date form: `If-Unmodified-Since` is false where the resource was
    /// modified after the date, declined where it never carried one, and
    /// decided by the `Last-Modified` the answer carries.
    #[rstest]
    #[case::modified_after_and_moved(&[("last-modified", LM)], EARLIER, 200, &[("last-modified", LATER)], Some("status_412_missing"))]
    #[case::modified_after_no_validator(&[("last-modified", LM)], EARLIER, 204, &[], Some("status_412_ambiguous"))]
    #[case::modified_after_and_held(&[("last-modified", LM)], EARLIER, 200, &[("last-modified", LM)], None)]
    #[case::not_modified_since(&[("last-modified", LM)], LATER, 200, &[("last-modified", LATER)], None)]
    #[case::no_modification_date_available(&[("etag", "\"v2\"")], EARLIER, 200, &[("etag", "\"v3\"")], None)]
    #[case::not_an_http_date(&[("last-modified", LM)], "yesterday", 200, &[("last-modified", LATER)], None)]
    fn a_false_if_unmodified_since_on_a_state_changing_request(
        #[case] prev: &[(&str, &str)],
        #[case] since: &str,
        #[case] status: u16,
        #[case] resp: &[(&str, &str)],
        #[case] expected: Option<&str>,
    ) {
        let ids = story(
            prev,
            "GET",
            200,
            "PUT",
            &[("if-unmodified-since", since)],
            status,
            resp,
        );
        let drawn: Vec<&str> = ids
            .iter()
            .map(String::as_str)
            .filter(|id| id.starts_with("status_412_"))
            .collect();
        assert_eq!(drawn, Vec::from_iter(expected), "{ids:?}");
    }

    /// § 13.1.1 has `If-Match` compared strongly, and a weak tag satisfies no
    /// strong comparison: a resource seen only under `W/"v2"` fails every
    /// `If-Match`, the one spelling `W/"v2"` included, and a `2xx` whose tag
    /// then moved was a method performed.
    #[test]
    fn a_weak_tag_satisfies_no_if_match() {
        let ids = story(
            &[("etag", "W/\"v2\"")],
            "GET",
            200,
            "PUT",
            &[("if-match", "W/\"v2\"")],
            200,
            &[("etag", "W/\"v3\"")],
        );
        assert!(ids.iter().any(|id| id == "status_412_missing"), "{ids:?}");
    }

    /// What the resource was last seen with is read off the newest answer that
    /// describes it: after a `DELETE` there is no current representation for
    /// `If-None-Match: *` to be false against, and a resource never seen with
    /// a tag is one no `If-Match` can be evaluated on.
    #[rstest]
    #[case::deleted("DELETE", 204, &[], &[("if-none-match", "*")], None)]
    #[case::never_tagged("GET", 200, &[("content-type", "text/plain")], &[("if-match", "\"v1\"")], None)]
    #[case::absent("GET", 404, &[], &[("if-none-match", "*")], None)]
    #[case::created_by_a_put("PUT", 201, &[("etag", "\"v2\"")], &[("if-none-match", "*")], Some("status_412_missing"))]
    fn the_last_seen_state_is_the_newest_answer_describing_the_resource(
        #[case] prev_method: &str,
        #[case] prev_status: u16,
        #[case] prev: &[(&str, &str)],
        #[case] req: &[(&str, &str)],
        #[case] expected: Option<&str>,
    ) {
        let ids = story(prev, prev_method, prev_status, "PUT", req, 200, &[]);
        let drawn: Vec<&str> = ids
            .iter()
            .map(String::as_str)
            .filter(|id| id.starts_with("status_412_"))
            .collect();
        assert_eq!(drawn, Vec::from_iter(expected), "{ids:?}");
    }

    /// The message names the field, the value it carried, the state it was
    /// judged against, and the answer.
    #[test]
    fn the_finding_names_what_it_read() {
        let mut earlier =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"v2\"")]);
        earlier.request.method = "GET".to_string();
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"v3\"")]);
        tx.request.method = "PUT".to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-match", "\"v1\"")]);
        let found = crate::test_helpers::run_rule_all(
            &ConditionalRequestHandling,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![aged(
                earlier, 1,
            )]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        )
        .into_iter()
        .find(|v| v.violation == "status_412_missing")
        .expect("a finding");
        for needle in [
            "PUT",
            "If-Match: \"v1\"",
            "\"v2\"",
            "\"v3\"",
            "200",
            "13.1.1",
        ] {
            assert!(
                found.message.contains(needle),
                "{needle} in {}",
                found.message
            );
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "conditional_request_handling");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
