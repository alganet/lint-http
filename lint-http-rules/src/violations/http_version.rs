// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `HTTP-version` defects — the protocol element both start-lines carry.
//!
//! One production, `HTTP-name "/" DIGIT "." DIGIT`, written at the end of a
//! request-line and at the beginning of a status-line — and one entry, because
//! a value failing it fails it the same way in either place. Which message it
//! came from is in the finding's wording, not in its id.
//!
//! **The subject exists although two of the three versions never put it on the
//! wire.** HTTP/2 and HTTP/3 carry no start-line, and a capture records a
//! version for them anyway, so this element is as much a fact about the record
//! as about the message — which is why the entry is careful to say that the
//! value reached a reader at all.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The production, its case-sensitivity, and where it appears.
pub const RFC_9112_2_3: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-2.3",
    note: "The production, the sentence saying it is case-sensitive, and the sentence saying only an HTTP/1.x message carries it in a start-line",
};

defects! {
    /// A version deriving from no reading of `HTTP-version`: a name that is not
    /// the case-sensitive `HTTP`, a digit position holding something that is
    /// not a `DIGIT`, or more than one digit on either side of the dot.
    ///
    /// **One entry for both start-lines**, because the production is one and a
    /// value fails it identically wherever it was written. The message names
    /// the direction, since that is what a sender needs and it is the only
    /// thing that differs.
    ///
    /// **`_malformed` in its plainest sense** — the value derives from no
    /// reading of the grammar — and the modal behind it is § 2.2's MUST NOT
    /// against generating an element that does not match its ABNF, reached
    /// from RFC 9112 § 1.1.
    ///
    // cite(RFC 9112 § 2.3): "HTTP-version  = HTTP-name "/" DIGIT "." DIGIT"
    HTTP_VERSION_MALFORMED = {
        id: "http_version_malformed",
        title: "A protocol version derives from no reading of HTTP-version",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9112_2_3],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One production, one entry, and the direction lives in the message —
    /// splitting by start-line would be two ids for one grammar.
    #[test]
    fn the_entry_does_not_split_by_which_start_line_carried_it() {
        assert!(!HTTP_VERSION_MALFORMED.id.contains("request"));
        assert!(!HTTP_VERSION_MALFORMED.id.contains("response"));
        assert!(HTTP_VERSION_MALFORMED.message.is_empty());
    }
}
