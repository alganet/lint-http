// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Which content codings a message's representation carries.
//!
//! The question two rules ask of `Content-Encoding` when they compare it with
//! something else — another response's coding, or the `Vary` beside it — and
//! not the question of whether the value is well formed, which is
//! `content_encoding_registered`'s and `content_encoding_and_type_consistent`'s.
//!
//! And the question a rule reading content *as* its media type asks before it
//! reads an octet: whether the captured octets are still under a coding,
//! content or transfer, and so not data in that media type at all.

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

/// Whether the octets a capture holds for a message are still coded, and so not
/// data in the media type its `Content-Type` names.
///
/// Two codings leave them so. A content coding is a property of the
/// representation and stays on the octets end to end. A transfer coding is one
/// hop's, and the capture undoes only `chunked`, which is framing; any other
/// transfer coding the sender applied, `gzip` beneath `chunked` included, is
/// still on the octets it retained. A rule that reads content *as* its media
/// type asks this first, and reads nothing when the answer is yes: nothing in
/// the crate decodes.
///
/// A transfer coding's name is taken from in front of its parameters and folded,
/// since transfer coding names are case-insensitive. The walk does not respect
/// quotes, so a parameter whose quoted value holds a comma leaves a fragment
/// that names no coding. That answers *coded*, which declines the reading and
/// reports nothing, and it is not this function's to judge the value:
/// `transfer_coding_registered` does.
// cite(RFC 9110 § 8.4): "The "Content-Encoding" header field indicates what content codings have been applied to the representation, beyond those inherent in the media type, and thus what decoding mechanisms have to be applied in order to obtain data in the media type referenced by the Content-Type header field."
// cite(RFC 9112 § 7): "Transfer coding names are used to indicate an encoding transformation that has been, can be, or might need to be applied to a message's content in order to ensure "safe transport" through the network."
// cite(RFC 9112 § 7): "This differs from a content coding in that the transfer coding is a property of the message rather than a property of the representation that is being transferred."
// cite(RFC 9110 § A): "transfer-coding = token *( OWS ";" OWS transfer-parameter )"
// cite(RFC 9112 § 7): "All transfer-coding names are case-insensitive and ought to be registered within the HTTP Transfer Coding registry, as defined in Section 7.3."
pub fn captured_octets_coded(headers: &HeaderMap) -> bool {
    let transfer_coded =
        super::headers::combined_field_value_as_written(headers, "transfer-encoding").is_some_and(
            |value| {
                super::list::list_members(&value).any(|member| {
                    let name = member.split(';').next().unwrap_or_default();
                    !super::headers::trim_ows(name).eq_ignore_ascii_case("chunked")
                })
            },
        );
    transfer_coded || !applied_codings(headers).is_empty()
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

    #[rstest]
    #[case::absent(&[], false)]
    #[case::content_coded(&[("content-encoding", "gzip")], true)]
    #[case::identity(&[("content-encoding", "identity")], false)]
    #[case::chunked(&[("transfer-encoding", "chunked")], false)]
    #[case::chunked_folded(&[("transfer-encoding", " Chunked ")], false)]
    #[case::chunked_twice(&[("transfer-encoding", "chunked, chunked")], false)]
    #[case::gzip_under_chunked(&[("transfer-encoding", "gzip, chunked")], true)]
    #[case::gzip_alone(&[("transfer-encoding", "gzip")], true)]
    #[case::gzip_on_its_own_line(&[("transfer-encoding", "gzip"), ("transfer-encoding", "chunked")], true)]
    #[case::parameter_on_a_coding(&[("transfer-encoding", "x-custom;a=1, chunked")], true)]
    #[case::both(&[("content-encoding", "br"), ("transfer-encoding", "gzip, chunked")], true)]
    fn captured_octets_coded_reads_both_codings(
        #[case] fields: &[(&str, &str)],
        #[case] expected: bool,
    ) {
        let mut h = HeaderMap::new();
        for (name, value) in fields {
            h.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).expect("a test name"),
                value.parse().expect("a test value"),
            );
        }
        assert_eq!(captured_octets_coded(&h), expected);
    }
}
