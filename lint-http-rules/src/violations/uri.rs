// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! URI defects — today, the two ways a percent-encoded triplet is not one.
//!
//! A `%` obliges two hexadecimal digits wherever it is written, and this crate
//! reads escapes in a request target, a `Location`, a cookie `Path`, an
//! `Alt-Svc` parameter and a dozen other places. The sentence answering all of
//! them is the same one, so the defect is too: naming it after the field that
//! happened to carry it would give an operator one name per field for one
//! mistake.
//!
//! That is a correction to this campaign's first subject, made while the
//! catalogue was small enough for corrections to be free. `cookie_path` shipped
//! a `cookie_path_percent_encoding_malformed` of its own, which was the same
//! reasoning error the rule-shaped catalogue is being split to fix.

use crate::helpers::uri::PercentEncodingDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The triplet a `%` obliges, and the only sentence either defect here needs.
pub const RFC_3986_2_1: SpecRef = SpecRef {
    spec: "RFC 3986",
    section: Some("2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1",
    note: "Percent-Encoding — `pct-encoded = \"%\" HEXDIG HEXDIG`, the two digits every `%` still owes",
};

defects! {
    /// A `%` with fewer than two characters after it, because the value ended.
    /// Kept apart from the malformed triplet because the fix differs: this one
    /// is a value that was cut, most often by something that truncated it.
    ///
    // cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
    PERCENT_ENCODING_DIGITS_MISSING = {
        id: "percent_encoding_digits_missing",
        title: "Percent-encoding stops before its two hexadecimal digits",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_3986_2_1),
    }

    /// Two characters after the `%` that are not both `HEXDIG` — a literal
    /// percent that was never escaped, most often.
    ///
    // cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
    PERCENT_ENCODING_MALFORMED = {
        id: "percent_encoding_malformed",
        title: "Percent-encoding is not two hexadecimal digits",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_3986_2_1),
    }
}

/// The defect a parsed [`PercentEncodingDefect`] reports as.
pub fn percent_encoding(defect: PercentEncodingDefect<'_>) -> &'static ViolationDef {
    match defect {
        PercentEncodingDefect::Incomplete => &PERCENT_ENCODING_DIGITS_MISSING,
        PercentEncodingDefect::NotHexDigits(_) => &PERCENT_ENCODING_MALFORMED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_percent_encoding_defect_maps_to_its_own_id() {
        assert_eq!(
            percent_encoding(PercentEncodingDefect::Incomplete).id,
            "percent_encoding_digits_missing",
        );
        assert_eq!(
            percent_encoding(PercentEncodingDefect::NotHexDigits("%ZZ")).id,
            "percent_encoding_malformed",
        );
    }
}
