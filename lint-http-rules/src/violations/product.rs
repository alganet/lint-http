// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `product` defects — how `Server` and `User-Agent` put their parts together.
//!
//! `product = token [ "/" product-version ]` and the two fields are
//! `product *( RWS ( product / comment ) )`, written identically and defined
//! once. **Nothing inside a part is here**: both halves of a `product` are a
//! [`token`](crate::violations::token) unmodified, a comment is § 5.6.5's
//! [`comment`](crate::violations::comment), and the escape inside one is
//! [`quoted_pair`](crate::violations::quoted_pair)'s. What is left is the
//! assembly — that the value opens with a product, and that the elements after
//! it are separated — and that is what this subject holds.
//!
//! **Two rules declare both entries and each names its own section**, § 10.1.5
//! for `User-Agent` and § 10.2.4 for `Server`, which is the arrangement a
//! shared entry cannot cite: a def may only name a sentence *every* declarer
//! states, and neither rule states the other's field. **Appendix A is the
//! answer and it is a new one** — the collected ABNF prints the two productions
//! in the same words, so the section where the shared production is written
//! down as shared is a section both declarers state. *An entry with too many
//! sentences is not always an entry with none.*

use crate::helpers::product::{Part, ProductDefect};
use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::comment::comment_defect;
use crate::violations::token::{token_character, TOKEN_EMPTY};
use crate::violations::{defects, ViolationDef};

/// The collected ABNF: the one section printing both fields' productions, in
/// the same words, which is what makes it citable by an entry either field
/// reports.
pub const RFC_9110_A: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("A"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A",
    note: "Collected ABNF, where `Server` and `User-Agent` are printed as the same production — `product *( RWS ( product / comment ) )` — and neither field's own section restates the other's",
};

/// The whitespace the repetition requires between its elements.
pub const RFC_9110_5_6_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3",
    note: "Whitespace — `RWS = 1*( SP / HTAB )`, used where at least one linear whitespace octet is *required* to separate field tokens, as opposed to the `OWS` a sender may omit",
};

defects! {
    /// A value that does not open with a product identifier: one left empty,
    /// or one beginning with a comment.
    ///
    /// **The comment is only reachable through the repetition**, which follows
    /// a product — so `Server: (Ubuntu)` is not a value describing its software
    /// parenthetically, it is a value with no product in it. The two shapes are
    /// one entry because they are one absence: the field names no software, and
    /// the repair is to name some.
    ///
    /// **`_missing` and not `_empty`**, including for the blank value. `_empty`
    /// is for a thing a sender wrote and left with nothing in it, and what the
    /// sender wrote here is the *field*; the product is the thing that was
    /// never written. The distinction pays for itself at the second shape,
    /// where the value is not empty at all.
    ///
    /// `warn`, with the separator below. A recipient learns nothing about the
    /// software, which is the whole of what these fields carry — and nothing
    /// else in the message changes.
    ///
    // cite(RFC 9110 § A): "Server = product *( RWS ( product / comment ) )"
    // cite(RFC 9110 § A): "User-Agent = product *( RWS ( product / comment ) )"
    PRODUCT_MISSING = {
        id: "product_missing",
        title: "A product list opens with something that is not a product",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_A],
        strength: Strength::Grammar,
    }

    /// Two elements with nothing between them: `nginx/1.0(Ubuntu)`, or
    /// `nginx/1.0Ubuntu/2`, or an octet after a comment that closed.
    ///
    /// **`RWS` is required and that is the word the production uses**, against
    /// the `OWS` a sender may leave out everywhere else — § 5.6.3 draws the
    /// line and this is the field where it bites. A recipient splitting on
    /// whitespace reads `nginx/1.0(Ubuntu)` as one product identifier whose
    /// version is `1.0(Ubuntu)`, so what the value states is not what the
    /// sender wrote.
    ///
    /// **Three of the reader's verdicts land here and the third is the one
    /// worth naming**: an octet after a closed comment opens no element and
    /// separates nothing, so it is not the comment's octet — the comment ended
    /// at its `)`. The reader used to file it as a character *inside* the
    /// comment, which sent an operator looking in the wrong construct.
    ///
    /// `warn`, level with the absence above. Neither is ranked by any sentence,
    /// and both leave a recipient reading a product identifier the sender did
    /// not write.
    ///
    // cite(RFC 9110 § 5.6.3): "The RWS rule is used when at least one linear whitespace octet is required to separate field tokens."
    // cite(RFC 9110 § 5.6.3): "RWS = 1*( SP / HTAB )"
    PRODUCT_SEPARATOR_MISSING = {
        id: "product_separator_missing",
        title: "A product list writes no whitespace between two elements",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_5_6_3],
        strength: Strength::Grammar,
    }
}

/// The defect a [`ProductDefect`] reports as.
///
/// **Total, and the arms are sorted by ownership rather than by severity.**
/// Both halves of a `product` are a `token`, so an empty one and an octet that
/// stopped one report with [`token`](crate::violations::token)'s ids and the
/// field adds nothing to either; a comment's four verdicts are § 5.6.5's
/// construct and § 5.6.4's escape, delegated the way every nested mapping in
/// this catalogue delegates. What is left over — the value that opens with no
/// product, the elements with no `RWS` between them — is this subject's, which
/// is why the subject exists.
pub fn product_defect(defect: ProductDefect) -> &'static ViolationDef {
    match defect {
        ProductDefect::NameEmpty(_) | ProductDefect::VersionEmpty => &TOKEN_EMPTY,
        // A `product` ends where its `token` does, so an octet the run stopped
        // on is the octet the sender wrote into a name — which is what the
        // message has always said. An octet after a *comment* is a different
        // variant now, precisely because that reading does not hold there.
        ProductDefect::Character { part, byte } => match part {
            Part::Comment => &PRODUCT_SEPARATOR_MISSING,
            _ => token_character(byte as char),
        },
        ProductDefect::Comment(defect) => comment_defect(defect),
        ProductDefect::ValueEmpty | ProductDefect::DoesNotOpenWithProduct => &PRODUCT_MISSING,
        ProductDefect::SeparatorMissingBeforeComment(_)
        | ProductDefect::SeparatorMissingBeforeProduct(_)
        | ProductDefect::OctetAfterComment(_) => &PRODUCT_SEPARATOR_MISSING,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping is total and it is the ownership split that decides each
    /// arm: the parts report as the productions they are written in, and only
    /// the assembly is this subject's.
    #[test]
    fn every_verdict_reports_as_the_production_it_broke() {
        use crate::helpers::comment::CommentDefect;
        for (defect, id) in [
            (ProductDefect::ValueEmpty, "product_missing"),
            (ProductDefect::DoesNotOpenWithProduct, "product_missing"),
            (ProductDefect::NameEmpty(None), "token_empty"),
            (ProductDefect::VersionEmpty, "token_empty"),
            (
                ProductDefect::Character {
                    part: Part::Name,
                    byte: b'@',
                },
                "token_character_forbidden",
            ),
            (
                ProductDefect::SeparatorMissingBeforeComment(Part::Name),
                "product_separator_missing",
            ),
            (
                ProductDefect::SeparatorMissingBeforeProduct(Part::Version),
                "product_separator_missing",
            ),
            (
                ProductDefect::OctetAfterComment(b'@'),
                "product_separator_missing",
            ),
            (
                ProductDefect::Comment(CommentDefect::Unterminated),
                "comment_delimiter_missing",
            ),
        ] {
            assert_eq!(product_defect(defect).id, id, "{defect:?}");
        }
    }

    /// The subject is level with itself: no sentence ranks the absence against
    /// the separator, and both leave a recipient reading a product identifier
    /// the sender did not write.
    #[test]
    fn the_assembly_entries_rank_together() {
        assert_eq!(
            PRODUCT_MISSING.default_severity,
            PRODUCT_SEPARATOR_MISSING.default_severity
        );
    }
}
