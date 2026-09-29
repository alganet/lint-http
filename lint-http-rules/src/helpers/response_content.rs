// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! What a response's content is, by the exchange it answers: none at all, one
//! range of the representation its `Content-Type` names, or the octets that
//! `Content-Type` labels.
//!
//! **The method and the status decide it before any octet is read.** A response
//! to `HEAD`, a `1xx`, `204` or `304` ends at its header section whatever those
//! fields say, a `205` is forbidden content by its own definition, and a `2xx`
//! to `CONNECT` is followed by a tunnel. None of those carries anything a media
//! type could describe, so a capture's empty body there is not an empty
//! document: it is the absence the exchange requires. And a single-part `206`
//! encloses one range of the selected representation, so its `Content-Type`
//! names the format of a whole the message does not carry.
//!
//! A rule that reads content *against* its media type asks this before it reads
//! a byte, and so does a rule whose condition is "a message containing content".
//! A rule reading representation metadata does not: § 8.2 makes a HEAD
//! response's metadata describe what a GET would have enclosed, which is why
//! `charset_present` keeps HEAD in scope and is not a caller.

use hyper::HeaderMap;

/// What the content of a response is, as far as its `Content-Type` goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseContent {
    /// The exchange gives the response no content: a response to `HEAD`, a
    /// `1xx`, `204`, `205` or `304`, or a `2xx` to `CONNECT`.
    Absent,
    /// A single-part `206` whose range is not the whole representation: the
    /// octets are a slice of the format `Content-Type` names, not a document in
    /// it.
    Range,
    /// The octets are what `Content-Type` labels: the selected representation,
    /// or for a `multipart/byteranges` `206` the multipart document enclosing
    /// the ranges.
    Labelled,
}

/// Which of the three a response's content is. `method` is the request's
/// method token, compared exactly.
pub fn response_content(method: &str, status: u16, headers: &HeaderMap) -> ResponseContent {
    // cite(RFC 9112 § 6.3): "Any response to a HEAD request and any response with a 1xx (Informational), 204 (No Content), or 304 (Not Modified) status code is always terminated by the first empty line after the header fields, regardless of the header fields present in the message, and thus cannot contain a message body or trailer section."
    let bodiless_status = (100..200).contains(&status) || status == 204 || status == 304;

    // 205 is not in § 6.3's item 1, and is bodiless all the same -- its own
    // status definition says so in a MUST NOT. A 205 that carries octets anyway
    // breaks that sentence, which is not a question about their format.
    // cite(RFC 9110 § 15.3.6): "Since the 205 status code implies that no additional content will be provided, a server MUST NOT generate content in a 205 response."
    let reset_content = status == 205;

    // Both methods are compared exactly, because the method token is
    // case-sensitive: `Head` and `Connect` name no method, so neither brings the
    // semantics that would take the content away.
    // cite(RFC 9110 § 9.3.2): "The HEAD method is identical to GET except that the server MUST NOT send content in the response."
    // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
    let head_request = method == "HEAD";

    // cite(RFC 9112 § 6.3): "Any 2xx (Successful) response to a CONNECT request implies that the connection will become a tunnel immediately after the empty line that concludes the header fields."
    let tunnelling = method == "CONNECT" && (200..300).contains(&status);

    if bodiless_status || reset_content || head_request || tunnelling {
        return ResponseContent::Absent;
    }
    if status == 206 && !encloses_what_content_type_names(headers) {
        return ResponseContent::Range;
    }
    ResponseContent::Labelled
}

/// Whether a `206`'s octets are what its `Content-Type` names.
///
/// Two ways they are. A `multipart/byteranges` `206` labels the content itself:
/// the ranges are inside it, each part saying which. And a single part whose
/// range starts at zero and ends one short of the complete length is the whole
/// representation, however it was asked for. Anything else -- a smaller range,
/// a range with no complete length, a `Content-Range` that does not parse or is
/// not there -- leaves the octets a slice, or leaves nothing saying they are
/// not one, and the format is not read.
// cite(RFC 9110 § 15.3.7.1): "If a single part is being transferred, the server generating the 206 response MUST generate a Content-Range header field, describing what range of the selected representation is enclosed, and a content consisting of the range."
// cite(RFC 9110 § 15.3.7.2): "If multiple parts are being transferred, the server generating the 206 response MUST generate "multipart/byteranges" content, as defined in Section 14.6, and a Content-Type header field containing the "multipart/byteranges" media type and its required boundary parameter."
fn encloses_what_content_type_names(headers: &HeaderMap) -> bool {
    let byteranges = crate::helpers::headers::get_header_str(headers, "content-type")
        .and_then(|ct| crate::helpers::media_type::parse_media_type(ct).ok())
        .is_some_and(|mt| {
            // cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
            mt.type_.eq_ignore_ascii_case("multipart")
                && mt.subtype.eq_ignore_ascii_case("byteranges")
        });
    if byteranges {
        return true;
    }
    // cite(RFC 9110 § 14.4): "range-resp = incl-range "/" ( complete-length / "*" )"
    // cite(RFC 9110 § 14.4): "incl-range = first-pos "-" last-pos"
    matches!(
        crate::helpers::headers::get_header_str(headers, "content-range")
            .map(crate::helpers::content_range::parse_content_range),
        Some(Ok(crate::helpers::content_range::ContentRange::Satisfied {
            first: 0,
            last,
            instance_length: Some(n),
            ..
        })) if last.checked_add(1) == Some(n)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn headers(fields: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in fields {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[rstest]
    #[case::head("HEAD", 200, &[], ResponseContent::Absent)]
    #[case::head_error("HEAD", 404, &[], ResponseContent::Absent)]
    #[case::head_partial("HEAD", 206, &[("content-range", "bytes 0-1/10")], ResponseContent::Absent)]
    #[case::continue_("GET", 100, &[], ResponseContent::Absent)]
    #[case::early_hints("GET", 103, &[], ResponseContent::Absent)]
    #[case::no_content("GET", 204, &[], ResponseContent::Absent)]
    #[case::reset_content("GET", 205, &[], ResponseContent::Absent)]
    #[case::not_modified("GET", 304, &[], ResponseContent::Absent)]
    #[case::tunnel("CONNECT", 200, &[], ResponseContent::Absent)]
    #[case::refused_tunnel("CONNECT", 407, &[], ResponseContent::Labelled)]
    #[case::head_is_case_sensitive("Head", 200, &[], ResponseContent::Labelled)]
    #[case::connect_is_case_sensitive("connect", 200, &[], ResponseContent::Labelled)]
    #[case::ok("GET", 200, &[], ResponseContent::Labelled)]
    #[case::error("POST", 500, &[], ResponseContent::Labelled)]
    #[case::unsatisfiable("GET", 416, &[("content-range", "bytes */10")], ResponseContent::Labelled)]
    #[case::one_range("GET", 206, &[("content-range", "bytes 0-4/10")], ResponseContent::Range)]
    #[case::tail_range("GET", 206, &[("content-range", "bytes 5-9/10")], ResponseContent::Range)]
    #[case::unknown_length("GET", 206, &[("content-range", "bytes 0-9/*")], ResponseContent::Range)]
    #[case::whole_range("GET", 206, &[("content-range", "bytes 0-9/10")], ResponseContent::Labelled)]
    #[case::no_content_range("GET", 206, &[], ResponseContent::Range)]
    #[case::unreadable_content_range("GET", 206, &[("content-range", "bytes 0-4")], ResponseContent::Range)]
    #[case::byteranges("GET", 206, &[("content-type", "multipart/byteranges; boundary=B")], ResponseContent::Labelled)]
    #[case::byteranges_folded("GET", 206, &[("content-type", "Multipart/ByteRanges; boundary=B")], ResponseContent::Labelled)]
    #[case::multipart_mixed_range("GET", 206, &[("content-type", "multipart/mixed; boundary=B"), ("content-range", "bytes 0-4/10")], ResponseContent::Range)]
    fn the_exchange_decides_what_the_content_is(
        #[case] method: &str,
        #[case] status: u16,
        #[case] fields: &[(&str, &str)],
        #[case] expected: ResponseContent,
    ) {
        assert_eq!(response_content(method, status, &headers(fields)), expected);
    }
}
