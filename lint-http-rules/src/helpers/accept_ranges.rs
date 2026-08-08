// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Reading `Accept-Ranges` out of a response.
//!
//! Two rules ask a response what it advertises: the one that reads a 206 beside
//! its own advertisement, and the one that reads a client's `Range` beside the
//! advertisement it was answered with. They had a byte-identical copy of this
//! walk each, down to the message the second one built out of it, so the
//! question every caller actually asks lives here once.
//!
//! What makes it worth a function rather than a loop is the shape of the
//! answer: "the field said `bytes`" and "the field said something this code
//! could not read" are different facts, and a caller that folds them reports a
//! response for advertising nothing when it advertised something unreadable.

/// What a response says about range support, read from every `Accept-Ranges`
/// field line it carries.
pub struct Advertisement {
    /// A field line named `Accept-Ranges` was there, whatever it held. This is
    /// the only thing an "advertises nothing" finding may rest on: a value the
    /// reader cannot read is still a value on the wire, and announcing its
    /// absence would be a claim about the message that is simply false.
    pub present: bool,
    /// Every field line read as a list of range units. False once one of them
    /// held something that is not one -- an octet outside US-ASCII, a character
    /// `token` excludes, or no element at all -- in which case `units` is a
    /// lower bound on what the response said and nothing may be concluded from
    /// a unit's absence from it.
    pub complete: bool,
    /// The advertised units, lowercased.
    pub units: Vec<String>,
}

impl Advertisement {
    /// Whether the response advertised this range unit. The argument is
    /// lowercased by the caller, as `units` is.
    pub fn advertises(&self, unit: &str) -> bool {
        self.units.iter().any(|u| u == unit)
    }
}

/// The field sections of a response that may carry `Accept-Ranges`, in the order
/// they arrive on the wire.
///
/// There are two, and which of them a reader looks in is not a detail any caller
/// should be deciding for itself: a response that advertises its units after the
/// content is advertising them, and a reader that opens the header section alone
/// reports it for saying nothing. The rule that owns the field's syntax needs the
/// same two sections and the raw lines inside them, so the sentence lives here
/// and the walk over it is shared.
///
// cite(RFC 9110 § 14.3): "The Accept-Ranges field MAY be sent in a trailer section, but is preferred to be sent as a header field because the information is particularly useful for restarting large information transfers that have failed in mid-content (before the trailer section is received)."
pub fn field_sections(
    resp: &crate::http_transaction::ResponseInfo,
) -> impl Iterator<Item = &hyper::HeaderMap> {
    [Some(&resp.headers), resp.trailers.as_ref()]
        .into_iter()
        .flatten()
}

/// Read `Accept-Ranges` out of both of the response's field sections.
///
/// What makes this a function rather than one loop is the shape of its answer,
/// described on `Advertisement`: a caller that folds "said nothing" into "said
/// something unreadable" reports a response for the first when it did the second.
pub fn read_advertisement(resp: &crate::http_transaction::ResponseInfo) -> Advertisement {
    let mut advertised = Advertisement {
        present: false,
        complete: true,
        units: Vec::new(),
    };

    for section in field_sections(resp) {
        for hv in section.get_all("accept-ranges").iter() {
            advertised.present = true;

            // `to_str` rejects every octet outside visible US-ASCII, which is
            // wider than this field's production allows in the first place, so
            // the failure is never a false alarm here -- but it is also not a
            // finding either caller reports: `server_accept_ranges_values_valid`
            // owns the field's syntax.
            //
            // cite(RFC 9110 § 14.3, label: Accept-Ranges grammar): "Accept-Ranges     = acceptable-ranges acceptable-ranges = 1#range-unit"
            let Ok(value) = hv.to_str() else {
                advertised.complete = false;
                continue;
            };

            let mut saw_a_unit = false;
            // cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
            for token in crate::helpers::headers::parse_list_header(value) {
                // A range unit is a token and nothing narrower: the set is open
                // by design, so a name this code has never heard of is a name it
                // has to carry rather than reject.
                //
                // cite(RFC 9110 § 14.1): "Range units are intended to be extensible, as described in Section 16.5."
                if crate::helpers::token::find_invalid_token_char(token).is_some() {
                    advertised.complete = false;
                    continue;
                }
                saw_a_unit = true;
                // cite(RFC 9110 § 14.1): "All range unit names are case-insensitive and ought to be registered within the "HTTP Range Unit Registry", as defined in Section 16.5.1."
                advertised.units.push(token.to_ascii_lowercase());
            }

            // A list whose elements are all empty is a list of no range units,
            // and the production asks for at least one. That is
            // `server_accept_ranges_values_valid`'s finding; here it only means
            // the line advertised nothing.
            //
            // cite(RFC 9110 § 5.6.1.2): "In contrast, the following values would be invalid, since at least one non-empty element is required by the example-list production"
            if !saw_a_unit {
                advertised.complete = false;
            }
        }
    }

    advertised
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use rstest::rstest;

    fn section(pairs: &[(&str, &[u8])]) -> hyper::HeaderMap {
        let mut hm = hyper::HeaderMap::new();
        for (name, value) in pairs {
            hm.append(
                name.parse::<HeaderName>().expect("a field name"),
                HeaderValue::from_bytes(value).expect("a field value"),
            );
        }
        hm
    }

    fn response(
        headers: &[(&str, &[u8])],
        trailers: &[(&str, &[u8])],
    ) -> crate::http_transaction::ResponseInfo {
        crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: section(headers),
            body_length: None,
            trailers: (!trailers.is_empty()).then(|| section(trailers)),
        }
    }

    #[test]
    fn a_response_with_no_field_advertises_nothing() {
        let read = read_advertisement(&response(&[], &[]));
        assert!(!read.present);
        assert!(read.complete);
        assert!(read.units.is_empty());
    }

    #[test]
    fn one_list_may_be_split_across_field_lines() {
        let read = read_advertisement(&response(
            &[
                ("accept-ranges", b"pages".as_slice()),
                ("accept-ranges", b"bytes".as_slice()),
            ],
            &[],
        ));
        assert!(read.present && read.complete);
        assert!(read.advertises("bytes") && read.advertises("pages"));
    }

    /// § 14.1 says range unit names are case-insensitive, so the fold is the
    /// spec's and not a tolerance this code chose.
    #[test]
    fn unit_names_are_folded() {
        let read = read_advertisement(&response(&[("accept-ranges", b"BYTES".as_slice())], &[]));
        assert!(read.advertises("bytes"));
    }

    /// § 14.3 permits the field in a trailer section, and a response that
    /// advertises there is advertising.
    #[test]
    fn a_trailer_section_advertises() {
        let read = read_advertisement(&response(&[], &[("accept-ranges", b"bytes".as_slice())]));
        assert!(read.present && read.complete);
        assert!(read.advertises("bytes"));
    }

    /// Present and unreadable is neither absent nor a list of units: `present`
    /// says the field was on the wire, `complete` says nothing may be concluded
    /// from a unit's absence from what was read.
    #[rstest]
    #[case::not_ascii(&[("accept-ranges", &[0xff][..])][..])]
    #[case::not_a_token(&[("accept-ranges", b"x@bad".as_slice())][..])]
    #[case::no_elements(&[("accept-ranges", b",".as_slice())][..])]
    #[case::empty_value(&[("accept-ranges", b"".as_slice())][..])]
    fn a_line_that_is_not_a_list_of_units_is_present_and_incomplete(
        #[case] fields: &[(&str, &[u8])],
    ) {
        let read = read_advertisement(&response(fields, &[]));
        assert!(read.present, "the field was on the wire");
        assert!(!read.complete);
    }

    /// A unit read from one line survives an unreadable line beside it, which
    /// is what lets a caller act on what it did read.
    #[test]
    fn what_was_read_is_kept_beside_what_was_not() {
        let read = read_advertisement(&response(
            &[
                ("accept-ranges", b"none".as_slice()),
                ("accept-ranges", &[0xff][..]),
            ],
            &[],
        ));
        assert!(read.advertises("none"));
        assert!(!read.complete);
    }
}
