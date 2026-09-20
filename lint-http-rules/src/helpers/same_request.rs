// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Whether an earlier exchange asked what this one asks, so that its answer
//! stands in for a response nobody sent.
//!
//! Two of RFC 9110's status codes carry a requirement conditioned on a message
//! that does not exist: § 15.4.5 has a `304` generate the fields that *"would
//! have been sent in a 200 (OK) response to the same request"*, and § 15.3.7
//! says the same of a `206`. Neither antecedent is in the message being read,
//! and a rule that guessed at it would be inventing the `200` it then judged
//! against. What makes the sentence answerable is an observation: an earlier
//! `200`, for the same resource, answering the same request — where the only
//! difference is the field that turned this request into the variant the
//! status code is about.
//!
//! **The comparison is strict, and that is the whole design.** Every request
//! header field but the named variants has to match octet for octet. The
//! fields at issue on the response side are the ones content negotiation
//! moves — a `Vary` states which request fields select the representation — so
//! a looser comparison would be reasoning about a `200` the server never had
//! occasion to send. What strictness costs is silence wherever a client
//! changed anything else between the two requests, and silence is the
//! direction to be wrong in for findings that ship at `error`.
//!
//! **This is shelved apart from [`stored_response`](super::stored_response),
//! which asks a question that looks the same and is not.** That module asks
//! whether a response held from an earlier exchange *could have answered* the
//! request now presented — a cache's question, decided by RFC 9111 § 3 and
//! § 4, and answered leniently enough to cover the selecting header fields a
//! `Vary` names. This one asks whether the earlier exchange *was the same
//! request*, which is a counterfactual's antecedent rather than a reuse
//! candidate, and is answered by equality.
//!
//! The list of fields allowed to differ is the caller's, because it is what
//! each section is about: § 15.4.5's variant is a precondition (§ 13.1), and
//! § 15.3.7's is a `Range`.
// cite(RFC 9110 § 15.4.5): "The server generating a 304 response MUST generate any of the following header fields that would have been sent in a 200 (OK) response to the same request:"
// cite(RFC 9110 § 15.3.7): "A server that generates a 206 response MUST generate the following header fields, in addition to those required in the subsections below, if the field would have been sent in a 200 (OK) response to the same request: Date, Cache-Control, ETag, Expires, Content-Location, and Vary."

/// One request's header fields as they compare: every name it carries but for
/// `varying`, each with the field lines under it, sorted so two requests that
/// wrote the same fields in a different order are the same request.
///
/// Read as octets. A comparison that decoded first would answer *these two
/// requests differ* about a pair of identical values whenever either carries an
/// `obs-text` octet, which is a difference the sender did not make.
fn comparable_fields<'h>(
    headers: &'h hyper::HeaderMap,
    varying: &[&str],
) -> Vec<(&'h str, Vec<&'h [u8]>)> {
    let mut fields: Vec<(&str, Vec<&[u8]>)> = headers
        .keys()
        .map(hyper::header::HeaderName::as_str)
        .filter(|name| !varying.contains(name))
        .map(|name| {
            (
                name,
                headers
                    .get_all(name)
                    .iter()
                    .map(hyper::header::HeaderValue::as_bytes)
                    .collect(),
            )
        })
        .collect();
    fields.sort_by(|a, b| a.0.cmp(b.0));
    fields
}

/// Whether `earlier` asked what `later` asks, allowing only `varying` to
/// differ between them.
///
/// `varying` holds lowercase field names — the ones whose presence is what
/// makes `later` the variant its status code is about, and the only difference
/// the caller's section is written across.
pub fn asks_the_same(
    earlier: &crate::http_transaction::HttpTransaction,
    later: &crate::http_transaction::HttpTransaction,
    varying: &[&str],
) -> bool {
    earlier.request.method == later.request.method
        && earlier.request.uri == later.request.uri
        && comparable_fields(&earlier.request.headers, varying)
            == comparable_fields(&later.request.headers, varying)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn asking(
        uri: &str,
        method: &str,
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = uri.to_string();
        tx.request.method = method.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(headers);
        tx
    }

    /// The variant field is the only difference the comparison forgives, and it
    /// is forgiven in both directions: an earlier request that carried it and a
    /// later one that does not are still the same request.
    #[rstest]
    #[case::added(&[("accept", "*/*")], &[("accept", "*/*"), ("range", "bytes=0-1")], true)]
    #[case::dropped(&[("accept", "*/*"), ("range", "bytes=0-1")], &[("accept", "*/*")], true)]
    #[case::reordered(&[("accept", "*/*"), ("host", "e")], &[("host", "e"), ("accept", "*/*")], true)]
    #[case::other_field_added(&[("accept", "*/*")], &[("accept", "*/*"), ("referer", "/x")], false)]
    #[case::other_field_changed(&[("accept", "*/*")], &[("accept", "text/html")], false)]
    fn only_the_named_field_may_differ(
        #[case] earlier: &[(&str, &str)],
        #[case] later: &[(&str, &str)],
        #[case] same: bool,
    ) {
        let a = asking("http://example/a", "GET", earlier);
        let b = asking("http://example/a", "GET", later);
        assert_eq!(asks_the_same(&a, &b, &["range", "if-range"]), same);
    }

    /// The target and the method are part of the request whatever the variant
    /// is, so neither is ever forgiven.
    #[rstest]
    #[case::other_target("http://example/b", "GET")]
    #[case::other_method("http://example/a", "HEAD")]
    fn the_target_and_the_method_are_never_forgiven(#[case] uri: &str, #[case] method: &str) {
        let a = asking("http://example/a", "GET", &[("accept", "*/*")]);
        let b = asking(uri, method, &[("accept", "*/*")]);
        assert!(!asks_the_same(&a, &b, &["range", "if-range"]));
    }

    /// A field is compared by its octets, not by what a decoder makes of them:
    /// two `obs-text` values that differ are a difference the sender made, and
    /// two that agree are not a difference at all.
    #[test]
    fn values_compare_as_octets() {
        let a = asking("http://example/a", "GET", &[("accept", "*/*")]);
        let mut b = asking("http://example/a", "GET", &[("accept", "*/*")]);
        b.request.headers.insert(
            "x-obs",
            hyper::header::HeaderValue::from_bytes(b"\xe9").unwrap(),
        );
        assert!(!asks_the_same(&a, &b, &["range"]));

        let mut c = asking("http://example/a", "GET", &[("accept", "*/*")]);
        c.request.headers.insert(
            "x-obs",
            hyper::header::HeaderValue::from_bytes(b"\xe9").unwrap(),
        );
        assert!(asks_the_same(&b, &c, &["range"]));
    }
}
