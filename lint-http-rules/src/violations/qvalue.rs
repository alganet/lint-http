// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `qvalue` production — one entry, and four fields asking for it.
//!
//! A weight is how a request says which of several acceptable things it would
//! rather have, and RFC 9110 § 12.4.2 writes the number once for all of them:
//! `Accept`, `Accept-Encoding`, `Accept-Language` and `TE` each carry
//! `weight = OWS ";" OWS "q=" qvalue` and none of them restates what a
//! `qvalue` is. So a `q=1.5` in an `Accept` and a `q=1.5` in a `TE` are the
//! same defect, and before this subject existed they were four sentences with
//! four severities — one per rule, whichever the operator had configured for
//! everything else that rule says.
//!
//! **What the subject does not hold is the *assembly* around the weight.** A
//! `;` with no weight after it, a second weight in one member, a parameter that
//! is not `q` at a field admitting no other: those are statements about how a
//! member is put together, they belong to the fields that make them, and each
//! is read by one rule.
//!
//! **The weight's own spelling is a different question and is here**, under a
//! `weight_` prefix rather than a `qvalue_` one — the file stem groups a
//! subject and does not have to prefix its ids, the way
//! [`uri`](crate::violations::uri) holds the `percent_encoding_*` entries.
//! `weight = OWS ";" OWS "q=" qvalue` prints `q=` as a single literal with
//! nothing optional inside it, so whitespace written into that literal is not
//! bad whitespace a recipient parses out: it is characters the production does
//! not generate, in the one place this construct has no `OWS` to spare.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Quality Values, whole: the production, its two alternatives, the bound on
/// its fraction and the parameter that carries it. One section, and five rules
/// had written five notes for it.
pub const RFC_9110_12_4_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("12.4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2",
    note: "Quality Values — `weight = OWS \";\" OWS \"q=\" qvalue`, the `qvalue` production and its three-digit fraction, the case-insensitive `q` parameter name, and what a weight of zero means",
};

defects! {
    /// A weight that derives from neither alternative of the production.
    ///
    /// The two alternatives are asymmetric on purpose — anything from `0` to
    /// `0.999` on one side, and on the other a `1` that may only be followed by
    /// zeroes — so `1.5` and `0.1234` fail for different arithmetic and the
    /// same reason: the value names no quality between none and all of it. Both
    /// are one fix, which is why they are one entry.
    ///
    /// `warn` rather than `error`: the member is still a member and a recipient
    /// that cannot read the weight has a default to fall back on, so what is
    /// lost is the preference the sender meant to express rather than the
    /// message. It sits above nothing and below the invisible-octet defects the
    /// same rules report, which is the ranking those rules could not make while
    /// this shared one scalar with them.
    ///
    // cite(RFC 9110 § 12.4.2): "qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )"
    QVALUE_MALFORMED = {
        id: "qvalue_malformed",
        title: "Weight is not a qvalue",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_12_4_2],
    }

    /// Whitespace beside the weight's `=`: `q =0.5`, `q= 0.5`. The three
    /// characters of `"q="` are one ABNF string literal, and the two `OWS` the
    /// production does print are both before it — so a recipient matching the
    /// literal finds no weight here, and the preference the sender wrote is
    /// lost rather than misread.
    ///
    /// **Not [`BWS_FORBIDDEN`](crate::violations::bws::BWS_FORBIDDEN), and the
    /// distinction is the whole reason this entry exists.** A
    /// `transfer-parameter` prints `BWS` around its `=`, so whitespace there is
    /// admitted-for-historical-reasons and answers to § 5.6.3's sentence about
    /// a sender who generates it. Nothing of the kind is written into `weight`.
    /// The same three characters, two productions, and only one of them has a
    /// sentence about bad whitespace to quote — which is why reporting this as
    /// `bws_forbidden` would name a requirement about a construct that is not
    /// here.
    ///
    /// Nor is it
    /// [`PARAMETER_EQUALS_WHITESPACE_FORBIDDEN`](crate::violations::parameter::PARAMETER_EQUALS_WHITESPACE_FORBIDDEN),
    /// which is `info` because § 5.6.6's Note acknowledges the habit and six
    /// rules in this tree trim it on the record. No sentence acknowledges this
    /// one, and no reader here trims it, so it ranks with the malformed number
    /// above it: in both cases the member arrives and its weight does not.
    ///
    // cite(RFC 9110 § 12.4.2, label: the weight production): "weight = OWS ";" OWS "q=" qvalue"
    WEIGHT_EQUALS_WHITESPACE_FORBIDDEN = {
        id: "weight_equals_whitespace_forbidden",
        title: "Whitespace is written beside the weight's '='",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_12_4_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one thing a single-entry subject can get wrong on its own: the
    /// default, which is what four rules stop imposing on this defect.
    #[test]
    fn a_weight_that_is_not_one_is_a_warning() {
        assert_eq!(QVALUE_MALFORMED.default_severity, Severity::Warn);
    }
}
