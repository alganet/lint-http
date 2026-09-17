// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `ext-value` defects — the parameter value that carries a charset.
//!
//! RFC 8187 § 3.2.1 writes `ext-value = charset "'" [ language ] "'"
//! value-chars`, the form a parameter whose name ends in an asterisk takes.
//! It is not [`parameter`](crate::violations::parameter)'s: § 5.6.6's
//! `parameter-value` is `( token / quoted-string )` and neither of those
//! derives an `ext-value`, which is why a field defining one has to say so in
//! its own grammar.
//!
//! **One entry, and it is coarser than the reader behind it.**
//! [`crate::helpers::parameter::validate_ext_value`] distinguishes seven ways
//! the value can fail — no charset separator, no language separator, an empty
//! or non-ASCII charset, an incomplete or non-hex percent-escape, an octet no
//! `attr-char` admits — and returns them as prose. Typing that reader is what
//! would split this entry, and until it is typed a finer catalogue here would
//! be a claim the code cannot support: the ids would exist and no site could
//! choose between them.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The production, its three parts and the two separators between them.
pub const RFC_8187_3_2_1: SpecRef = SpecRef {
    spec: "RFC 8187",
    section: Some("3.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc8187.html#section-3.2.1",
    note: "`ext-value = charset \"'\" [ language ] \"'\" value-chars` — the charset that may not be empty, the language that may be, and the `value-chars` made of `pct-encoded` and `attr-char`. Obsoletes RFC 5987, which older references named; the production is unchanged",
};

defects! {
    /// A value in a `name*` parameter that is no `ext-value`: no charset
    /// separator, no language separator, an empty or non-ASCII charset, a
    /// percent-escape that is incomplete or not hexadecimal, or an octet
    /// `attr-char` does not admit.
    ///
    /// **One entry over the reader's seven verdicts**, because the reader
    /// returns prose rather than a type and a caller cannot tell them apart to
    /// report them separately. The message carries the reader's own words, so
    /// nothing an operator reads is lost; what is not yet available is
    /// configuring the parts of the production against each other, and that
    /// arrives when the reader is typed and not before.
    ///
    /// `warn`. A `filename*` a recipient cannot decode falls back to the plain
    /// `filename` where the field carries one and to the recipient's own
    /// default where it does not, so the download is named badly rather than
    /// not at all.
    ///
    // cite(RFC 8187 § 3.2.1): "ext-value     = charset  "'" [ language ] "'" value-chars"
    EXT_VALUE_MALFORMED = {
        id: "ext_value_malformed",
        title: "An extended parameter value is no ext-value",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_8187_3_2_1],
        strength: Strength::Grammar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::parameter::PARAMETER_VALUE_EMPTY;

    /// The claim that keeps this subject separate from `parameter`: an
    /// `ext-value` is not a `parameter-value`, so the two productions'
    /// defects are two ids even where a field writes both.
    #[test]
    fn an_ext_value_is_not_a_parameter_value() {
        let [ext] = EXT_VALUE_MALFORMED.spec else {
            panic!("one sentence")
        };
        let [plain] = PARAMETER_VALUE_EMPTY.spec else {
            panic!("one sentence")
        };
        assert_ne!(ext.spec, plain.spec);
    }
}
