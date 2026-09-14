// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Clear-Site-Data` defects — a field nothing asks for, on a request nothing
//! identifies.
//!
//! The one entry here is the catalogue's furthest-out heuristic and the subject
//! exists to say so: the specification's own sign-out example is what this
//! encodes, and both halves of the guess — that the request is a sign-out, and
//! that a sign-out ought to clear storage — are this crate's.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field: what signal it sends, and the sign-out example the finding is
/// modelled on.
pub const CLEAR_SITE_DATA_3_1: SpecRef = SpecRef {
    spec: "Clear-Site-Data",
    section: Some("3.1"),
    url: "https://www.w3.org/TR/clear-site-data/#header",
    note: "The `Clear-Site-Data` HTTP response header field (its purpose; §1.1.1 is the sign-out example this finding encodes)",
};

defects! {
    /// A response to what looks like a sign-out, carrying no
    /// `Clear-Site-Data`.
    ///
    /// **Two guesses, and the entry owns both.** The first is that the request
    /// was a sign-out at all — read off the path, which no document gives any
    /// meaning to. The second is that a sign-out ought to clear client-side
    /// storage, which is the specification's *example* rather than a
    /// requirement: nothing anywhere asks for this field.
    ///
    /// `info`, and it would be hard to argue for more: an operator who has
    /// decided their sign-out leaves storage in place is not doing anything
    /// wrong, and this rule cannot tell that decision from an oversight.
    ///
    // cite(Clear-Site-Data § 3.1): "The Clear-Site-Data HTTP response header field sends a signal to the user agent that it ought to remove all data of a certain set of types."
    CLEAR_SITE_DATA_MISSING = {
        id: "clear_site_data_missing",
        title: "A sign-out response does not ask the client to clear its storage",
        message: "",
        default_severity: Severity::Info,
        spec: &[CLEAR_SITE_DATA_3_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry rests on two guesses and no requirement, which is as far out
    /// as this catalogue goes — and it is ranked accordingly.
    #[test]
    fn the_furthest_out_heuristic_is_ranked_lowest() {
        assert_eq!(CLEAR_SITE_DATA_MISSING.default_severity, Severity::Info);
    }
}
