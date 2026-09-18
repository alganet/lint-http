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
//! the method, the selecting header fields — and the method is the first of
//! them a linter that already scopes history by client and target has left to
//! check.
//!
//! **§ 3 comes before § 4, and it is the other half of the question.** § 4
//! decides which stored response answers the request now presented, and it
//! presumes there is one. § 3 decides whether the earlier exchange left one at
//! all, and a rule that skips it reports a reuse of an entry that never
//! existed. [`storage_allowed`] is that question; [`method_allows`] is § 4's.

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
