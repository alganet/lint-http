// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `X-Frame-Options` defects — the two values the field has, and the third one
//! it used to have.
//!
//! **Two entries for a field with a two-literal grammar, and the second is not
//! a special case of the first.** A value outside `"DENY" / "SAMEORIGIN"` is
//! one the processing model reads and moves past; `ALLOW-FROM` is a value that
//! *was* this field's, in a document a later one superseded, and that no
//! browser implements. The consequence is the same and the repair is not — one
//! sender misspelled a value that exists, the other has to leave this field
//! behind entirely.
//!
//! **The `_obsolete` entry ranks level with its sibling rather than below it,
//! which is where this catalogue's other retired spellings sit.**
//! `pragma_obsolete` and `http_date_obsolete` name a spelling recipients still
//! honour — an `obs-date` a recipient MUST accept, a `Pragma` an HTTP/1.0 cache
//! still obeys — so the finding is about tidiness. Nothing honours an
//! `ALLOW-FROM`: the deployment that wrote it has no framing protection at all,
//! which is exactly where the misspelling leaves it.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The definition in force: the conformance ABNF, the lowercasing the
/// processing model does before comparing, and the sentence retiring the third
/// variant.
pub const HTML_SPECULATIVE_LOADING_7_7: SpecRef = SpecRef {
    spec: "HTML Speculative Loading",
    section: Some("7.7"),
    url: "https://html.spec.whatwg.org/multipage/speculative-loading.html#the-x-frame-options-header",
    note: "Governing definition: conformance ABNF `\"DENY\" / \"SAMEORIGIN\"`, case-insensitive processing, `ALLOW-FROM` not to be implemented",
};

defects! {
    /// A value that is neither `DENY` nor `SAMEORIGIN`, compared without
    /// regard to case.
    ///
    /// **`_invalid` and not `_malformed`**, the reading
    /// [`crate::violations::x_content_type_options`] settled for a field of the
    /// same shape: the grammar is two literals and the comparison is a match
    /// against them, so there is no production to break. What the value does is
    /// fail to be either of the things the field can say.
    ///
    /// The comparison folds case because the processing model does, not because
    /// the ABNF says so — each raw value is converted to ASCII lowercase before
    /// anything looks at it, so `sameorigin` protects a resource exactly as
    /// `SAMEORIGIN` does and reporting it would report a spelling nothing reads.
    ///
    /// `error`, from the production, which generates two values and no others.
    /// A server that wrote this field meant to refuse being framed, and a value
    /// the algorithm does not recognise leaves the resource embeddable by
    /// anyone — the deployment believes it has a protection it does not
    /// have.
    ///
    // cite(HTML Speculative Loading § 7.7): "X-Frame-Options = "DENY" / "SAMEORIGIN""
    // cite(HTML Speculative Loading § 7.7): "For each value of rawXFrameOptions, append value, converted to ASCII lowercase, to xFrameOptions."
    X_FRAME_OPTIONS_INVALID = {
        id: "x_frame_options_invalid",
        title: "X-Frame-Options carries neither DENY nor SAMEORIGIN",
        message: "",
        default_severity: Severity::Error,
        spec: &[HTML_SPECULATIVE_LOADING_7_7],
        strength: Strength::Grammar,
    }

    /// The `ALLOW-FROM` variant, whatever origin follows it.
    ///
    /// **`_obsolete` because a later document retired it, and that is the whole
    /// of what separates it from the entry above.** RFC 7034 § 2.1 defined
    /// three values; the HTML Standard supersedes that document, prints two,
    /// and says in a sentence that the third is not to be implemented. So a
    /// sender writing it is not guessing — it is reading a document that was
    /// once the definition.
    ///
    /// **Level with [`X_FRAME_OPTIONS_INVALID`], and this catalogue's other
    /// `_obsolete` entries are why the level has to be argued for.**
    /// `pragma_obsolete` and `http_date_obsolete` rank below their siblings
    /// because a recipient still *honours* what they report. Nothing honours
    /// this one: every browser treats it as an unrecognised value, so the
    /// resource is as embeddable as it would be after a typo.
    ///
    /// It earns its own id anyway, because the repair is not the sibling's. A
    /// misspelling is fixed in this field; an `ALLOW-FROM` cannot be — the
    /// thing it was trying to say is only sayable in a Content-Security-Policy
    /// `frame-ancestors` directive, and the message says so.
    ///
    // cite(HTML Speculative Loading § 7.7): "In particular, HTTP Header Field X-Frame-Options specified an `ALLOW-FROM` variant of the header, but that is not to be implemented."
    X_FRAME_OPTIONS_ALLOW_FROM_OBSOLETE = {
        id: "x_frame_options_allow_from_obsolete",
        title: "X-Frame-Options carries the retired ALLOW-FROM variant",
        message: "",
        default_severity: Severity::Error,
        spec: &[HTML_SPECULATIVE_LOADING_7_7],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The argument on the retired variant, asserted: it does not rank below
    /// its sibling the way this catalogue's other `_obsolete` entries once
    /// ranked below theirs, because no recipient honours what it reports.
    ///
    /// **The comparison against `http_date_obsolete` used to show that** and no
    /// longer can: that entry moved up to its own siblings for the same kind of
    /// reason, so the two now agree instead of contrasting. The claim that
    /// survives is the one inside this subject.
    #[test]
    fn the_retired_variant_ranks_with_the_value_that_was_never_one() {
        assert_eq!(
            X_FRAME_OPTIONS_ALLOW_FROM_OBSOLETE.default_severity,
            X_FRAME_OPTIONS_INVALID.default_severity
        );
        assert_eq!(
            crate::violations::http_date::HTTP_DATE_OBSOLETE.default_severity,
            X_FRAME_OPTIONS_ALLOW_FROM_OBSOLETE.default_severity,
        );
    }
}
