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
//! purpose. That module reads a field; this one reads the *pairing* of two
//! exchanges, and never looks at `Cache-Control` at all. § 4 lists several
//! conditions on the pairing — the URI, the method, the selecting header
//! fields — and the method is the first of them a linter that already scopes
//! history by client and target has left to check.

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
}
