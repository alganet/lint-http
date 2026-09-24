// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Which content codings a message's representation carries.
//!
//! The question two rules ask of `Content-Encoding` when they compare it with
//! something else — another response's coding, or the `Vary` beside it — and
//! not the question of whether the value is well formed, which is
//! `content_encoding_registered`'s and `content_encoding_and_type_consistent`'s.

use hyper::HeaderMap;

/// The content codings applied, in the order they were applied: lowercased,
/// `OWS`-trimmed, with empty members and `identity` dropped. An absent field,
/// an empty one and `identity` are all the unencoded representation, and so
/// all answer an empty list.
///
/// `Content-Encoding = #content-coding` and a coding is a `token`, which is
/// case-insensitive. `identity` is reserved for `Accept-Encoding`, so a sender
/// that writes it here is reported elsewhere; what it applied is nothing.
///
/// The order is kept because it is meaningful: the field lists the codings in
/// the order they were applied, so `gzip, br` and `br, gzip` are two
/// representations.
// cite(RFC 9110 § 8.4): "Content-Encoding = #content-coding"
// cite(RFC 9110 § 8.4): "If one or more encodings have been applied to a representation, the sender that applied the encodings MUST generate a Content-Encoding header field that lists the content codings in the order in which they were applied."
// cite(RFC 9110 § 8.4.1): "All content codings are case-insensitive and ought to be registered within the "HTTP Content Coding Registry","
// cite(RFC 9110 § 8.4): "Note that the coding named "identity" is reserved for its special role in Accept-Encoding and thus SHOULD NOT be included."
pub fn applied_codings(headers: &HeaderMap) -> Vec<String> {
    super::headers::combined_field_value_as_written(headers, "content-encoding")
        .map(|value| {
            super::list::list_members(&value)
                .map(|member| member.to_ascii_lowercase())
                .filter(|member| member != "identity")
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::absent(&[], &[])]
    #[case::empty(&[""], &[])]
    #[case::identity(&["identity"], &[])]
    #[case::identity_uppercase(&["IDENTITY"], &[])]
    #[case::one(&["gzip"], &["gzip"])]
    #[case::folded(&[" GZip "], &["gzip"])]
    #[case::order_kept(&["gzip, br"], &["gzip", "br"])]
    #[case::two_lines(&["gzip", "br"], &["gzip", "br"])]
    #[case::empty_member(&["gzip,,br"], &["gzip", "br"])]
    fn applied_codings_reads_the_list(#[case] lines: &[&str], #[case] expected: &[&str]) {
        let mut h = HeaderMap::new();
        for l in lines {
            h.append("content-encoding", l.parse().expect("a test value"));
        }
        assert_eq!(applied_codings(&h), expected);
    }
}
