// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Whether a response held from an earlier exchange could have answered the
//! request now presented.
//!
//! Every stateful rule about cache reuse asks this before it asks anything
//! else, because reuse of an entry that was never a candidate is not reuse at
//! all: the origin answered, and the finding is about a message that was never
//! served. Two rules ask it — `must_revalidate_enforced` and
//! `no_cache_revalidation` — and only one of them had transcribed the answer.
//!
//! This is shelved apart from [`cache_control`](super::cache_control) on
//! purpose. That module reads a field and answers what it says; this one reads
//! the *pairing* of two exchanges and asks that module whatever it needs to
//! know about a value. § 4 lists several conditions on the pairing — the URI,
//! the method, the selecting header fields — and a linter that already scopes
//! history by client and target has the last two left to check:
//! [`method_allows`] is the method, [`selecting_fields_match`] the fields.
//!
//! **§ 3 comes before § 4, and it is the other half of the question.** § 4
//! decides which stored response answers the request now presented, and it
//! presumes there is one. § 3 decides whether the earlier exchange left one at
//! all, and a rule that skips it reports a reuse of an entry that never
//! existed. [`storage_allowed`] is that question; [`method_allows`] is § 4's.
//!
//! **§ 4.4 is deliberately not a third question here, and the reason is in
//! the definition rather than in the requirement.** A non-error response to an
//! unsafe method makes a cache invalidate the target URI, so it is tempting to
//! read a `POST` between the offer and the refusal as having taken the entry
//! away. But § 4.4 defines "invalidate" as *either* removing the stored
//! responses *or* marking them as needing mandatory validation before they can
//! be sent — and a client holding a marked entry is holding the validator, and
//! § 4.3.1 still asks it to send that validator when it revalidates. So a
//! conforming client can act on the finding, which is the whole test these
//! filters are applied under: `no-store` is filtered because *no* conforming
//! client held anything, and an invalidated entry does not meet that bar.
//! Written down because the question comes up on every reading of this module
//! and the answer is not in the `MUST`.
// cite(RFC 9111 § 4.4): "in need of a mandatory validation before they can be sent in response to a subsequent request"

/// Whether a stored response recorded against `stored` may be used to answer a
/// request that presents `presented`.
///
/// Two conditions, and both belong here rather than in the caller's staleness
/// arithmetic, because both decide whether there is an entry to reason about.
///
/// A method that defines no caching semantics leaves nothing stored behind, so
/// an `OPTIONS` is not a reuse even of an earlier `OPTIONS` — there was never a
/// stored response for the second one to have reused. That is why the check on
/// `stored` comes first and is not symmetric with the one below it.
///
/// Then § 4 leaves the pairing deliberately looser than equality — "allows it
/// to be used for" rather than "matches" — because a stored `GET` response is
/// the documented source for a `HEAD` reply, and § 4.3.5 has a `HEAD`
/// freshening a stored `GET` for the same reason. Everything else is equality:
/// a stored `GET` is no candidate for an `OPTIONS`, a `TRACE`, or an unsafe
/// method, which invalidates a stored response rather than reusing one.
// cite(RFC 9110 § 9.2.3): "This specification defines caching semantics for GET, HEAD, and POST"
// cite(RFC 9111 § 4): "the request method associated with the stored response allows it to be used for the presented request"
pub fn method_allows(stored: &str, presented: &str) -> bool {
    if !matches!(stored, "GET" | "HEAD" | "POST") {
        return false;
    }
    stored == presented || (stored == "GET" && presented == "HEAD")
}

/// Whether the earlier exchange left a stored response behind at all.
///
/// [`method_allows`] answers § 4's question — could *that* entry have answered
/// *this* request. This answers § 3's, which comes before it: was there an
/// entry. § 3 is a conjunction, and this reads one term of it, `no-store`, on
/// both of the messages that can carry the directive. The rest of the list is
/// either already asked or unanswerable from here: the request method is
/// [`method_allows`]'s first test, and whether the cache is shared is what
/// decides the `private` and `Authorization` terms — nothing on the wire says
/// which side of that a reader is on, so a linter that assumed one would be
/// reporting its own guess.
///
/// **The term earns a function because three rules were reasoning past it.**
/// Each finds the earlier response by what it says about *reuse* —
/// `must-revalidate`, `no-cache`, a validator on offer — and then reports the
/// client for asking again without a precondition. Where the response carried
/// `no-store` the client held nothing, so the validator it is named for
/// declining was never in its hands. The catalogue already says so from the
/// other side: a client that sends such a validator draws
/// `cache_control_no_store_ignored`, and with both readings live there was no
/// request left that a client could make and draw nothing.
///
/// Both messages are read because the directive is defined twice, once for
/// each. § 3 lists the response's; § 5.2.1.5 gives the request the same power
/// over the response it provokes.
// cite(RFC 9111 § 3): "the no-store cache directive is not present in the response"
// cite(RFC 9111 § 5.2.1.5): "The no-store request directive indicates that a cache MUST NOT store any part of either this request or any response to it."
pub fn storage_allowed(request: &hyper::HeaderMap, response: &hyper::HeaderMap) -> bool {
    !super::cache_control::has_unqualified(response, "no-store")
        && !super::cache_control::has_unqualified(request, "no-store")
}

/// Whether the request now presented selects the representation the earlier
/// exchange stored, under the `Vary` that response carried.
///
/// § 4's condition after the method. A response that varies names the request
/// fields that chose it, and it answers a later request only where those
/// fields match — so a response served under `Vary: Accept-Encoding` to a
/// request that asked for gzip is no entry for a request that asked for
/// nothing, and the other way round.
///
/// The comparison is § 4.1's, as far as a reader with no knowledge of the
/// individual fields can take it: the field lines are joined and the value is
/// trimmed, which are the combining transformation and the whitespace one.
/// The third — normalising each value the way its own specification defines —
/// needs the field's grammar, and this reads any field a response cares to
/// nominate. So two values that differ only in a way their field calls
/// insignificant read here as different, and a field is absent from both
/// requests or from neither. Stricter than the section, and strict in the
/// one direction that costs nothing: a pairing this refuses is an entry a
/// reader does not find, and a reader that finds no entry reports nothing,
/// where one that pairs two representations reports the wrong one.
///
/// `*` never matches, which is § 4.1's own sentence and not a simplification
/// of it.
// cite(RFC 9111 § 4.1): "the cache MUST NOT use that stored response without revalidation unless all the presented request header fields nominated by that Vary field value match those fields in the original request (i.e., the request that caused the cached response to be stored)."
// cite(RFC 9111 § 4.1): "adding or removing whitespace, where allowed in the header field's syntax"
// cite(RFC 9111 § 4.1): "If (after any normalization that might take place) a header field is absent from a request, it can only match another request if it is also absent there."
// cite(RFC 9111 § 4.1): "A stored response with a Vary header field value containing a member "*" always fails to match."
pub fn selecting_fields_match(
    stored_request: &hyper::HeaderMap,
    stored_response: &hyper::HeaderMap,
    presented_request: &hyper::HeaderMap,
) -> bool {
    let value = |headers: &hyper::HeaderMap, name: &str| {
        super::headers::combined_field_value_as_written(headers, name).map(|v| v.trim().to_string())
    };
    match super::vary::vary_nomination(stored_response) {
        super::vary::VaryNomination::Wildcard => false,
        super::vary::VaryNomination::Fields(names) => names
            .iter()
            .all(|name| value(stored_request, name) == value(presented_request, name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    // The same method is the ordinary candidate.
    #[case("GET", "GET", true)]
    #[case("HEAD", "HEAD", true)]
    #[case("POST", "POST", true)]
    // § 4's one asymmetry: a stored GET answers a HEAD, never the reverse.
    #[case("GET", "HEAD", true)]
    #[case("HEAD", "GET", false)]
    // A method with no caching semantics stores nothing, so it is no entry
    // even against a later request of its own method.
    #[case("OPTIONS", "OPTIONS", false)]
    #[case("TRACE", "TRACE", false)]
    // A stored GET is no candidate for a method a cache does not serve from it.
    #[case("GET", "OPTIONS", false)]
    #[case("GET", "TRACE", false)]
    #[case("GET", "PUT", false)]
    #[case("GET", "DELETE", false)]
    #[case("GET", "POST", false)]
    fn a_stored_response_answers_only_what_its_method_allows(
        #[case] stored: &str,
        #[case] presented: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(method_allows(stored, presented), expected);
    }

    /// Each of § 4.1's answers: a nominated field that agrees, one that does
    /// not, one absent from one side, a field the response does not nominate,
    /// no `Vary` at all, and `*`.
    #[rstest]
    #[case(&[("accept-encoding", "gzip")], "Accept-Encoding", &[("accept-encoding", "gzip")], true)]
    #[case(&[("accept-encoding", "gzip")], "Accept-Encoding", &[("accept-encoding", "br")], false)]
    #[case(&[("accept-encoding", "gzip")], "Accept-Encoding", &[], false)]
    #[case(&[], "Accept-Encoding", &[("accept-encoding", "gzip")], false)]
    #[case(&[], "Accept-Encoding", &[], true)]
    #[case(&[("accept-encoding", "gzip")], "Accept-Language", &[("accept-encoding", "br")], true)]
    #[case(&[("accept-encoding", "gzip")], "", &[], true)]
    #[case(&[], "*", &[], false)]
    #[case(&[("accept", "text/html")], "Accept, Accept-Encoding", &[("accept", "text/html")], true)]
    #[case(&[("accept", "text/html")], "Accept, Accept-Encoding", &[("accept", "text/html"), ("accept-encoding", "gzip")], false)]
    // The whitespace transformation, and only that one: the ends are trimmed,
    // and a difference inside the value is a difference.
    #[case(&[("accept-encoding", " gzip ")], "Accept-Encoding", &[("accept-encoding", "gzip")], true)]
    #[case(&[("accept-encoding", "gzip, br")], "Accept-Encoding", &[("accept-encoding", "gzip,br")], false)]
    fn a_stored_response_answers_only_a_request_that_selects_it(
        #[case] stored: &[(&str, &str)],
        #[case] vary: &str,
        #[case] presented: &[(&str, &str)],
        #[case] expected: bool,
    ) {
        let response = if vary.is_empty() {
            headers(&[])
        } else {
            headers(&[("vary", vary)])
        };
        assert_eq!(
            selecting_fields_match(&headers(stored), &response, &headers(presented)),
            expected
        );
    }

    fn headers(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut hm = hyper::HeaderMap::new();
        for (k, v) in pairs {
            hm.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        hm
    }

    #[rstest]
    // Nothing said about storage, so nothing forbids it.
    #[case(&[], &[], true)]
    #[case(&[], &[("cache-control", "no-cache, must-revalidate")], true)]
    // § 3's term, on the response, in every spelling the corpus writes.
    #[case(&[], &[("cache-control", "no-store")], false)]
    #[case(&[], &[("cache-control", "no-cache, no-store, must-revalidate")], false)]
    #[case(&[], &[("cache-control", "NO-STORE")], false)]
    // § 5.2.1.5's, on the request that provoked it.
    #[case(&[("cache-control", "no-store")], &[], false)]
    // A directive that merely names the token in an argument is not the
    // directive: `private="no-store"` says which field a shared cache must
    // drop, and a substring search read it as a refusal to store anything.
    #[case(&[], &[("cache-control", "private=\"no-store\"")], true)]
    fn a_response_no_cache_may_hold_leaves_no_entry(
        #[case] request: &[(&str, &str)],
        #[case] response: &[(&str, &str)],
        #[case] expected: bool,
    ) {
        assert_eq!(
            storage_allowed(&headers(request), &headers(response)),
            expected
        );
    }
}
