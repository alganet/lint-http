// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Validator defects — what a response gives a later request to condition on.
//!
//! § 8.8 calls `ETag` and `Last-Modified` the validator fields, and the subject
//! is that pair rather than either field: a response that carries one of them
//! has given a cache something to work with, and only a response carrying
//! neither is the finding.
//!
//! **Not to be confused with
//! [`conditional`](crate::violations::conditional)**, which is about the
//! *request* side — a precondition naming a validator this exchange cannot
//! place, or declining one it was given. This subject is about the response
//! that hands one over.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Last-Modified, Generation: the SHOULD and the condition written into it.
pub const RFC_9110_8_8_2_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.8.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2.1",
    note: "Generation: an origin server SHOULD send Last-Modified for any selected representation whose last modification date can be reasonably and consistently determined",
};

/// ETag, Generation: the same shape, one field over.
pub const RFC_9110_8_8_3_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.8.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3.1",
    note: "Generation: an origin server SHOULD send an ETag for any selected representation for which detection of changes can be reasonably and consistently determined",
};

defects! {
    /// A `200` carrying neither `ETag` nor `Last-Modified`.
    ///
    /// **Two sections, one entry, and no citation on the finding.** § 8.8.2.1
    /// asks for one field and § 8.8.3.1 for the other; either one satisfies a
    /// later conditional request, so no single sentence governs a response that
    /// sent neither, and the message names what was looked for.
    ///
    /// **Both SHOULDs carry a condition that is not on the wire** — the
    /// representation's last modification date, or detection of changes, being
    /// *reasonably and consistently determinable*. A server that cannot
    /// determine either is conforming, and produces the same response as one
    /// that never tried.
    ///
    /// `info`, for the same reason [`user_agent_missing`](crate::violations::user_agent)
    /// is: the conforming case and the defect are indistinguishable from here,
    /// and what the finding buys is that every later request for this resource
    /// has to be answered in full.
    ///
    /// Both sentences are quoted here, where neither is claimed as the one:
    ///
    // cite(RFC 9110 § 8.8.2.1): "An origin server SHOULD send Last-Modified for any selected representation for which a last modification date can be reasonably and consistently determined"
    // cite(RFC 9110 § 8.8.3.1): "An origin server SHOULD send an ETag for any selected representation for which detection of changes can be reasonably and consistently determined"
    VALIDATOR_MISSING = {
        id: "validator_missing",
        title: "A response gives a later request nothing to validate against",
        message: "Response 200 without ETag or Last-Modified validator",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_8_8_2_1, RFC_9110_8_8_3_1],
        strength: Strength::Should,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Either field satisfies the finding, so no one section governs it and the
    /// entry names both — which is what keeps the finding uncited.
    #[test]
    fn the_entry_names_both_sections_because_either_field_answers_it() {
        assert_eq!(VALIDATOR_MISSING.spec.len(), 2);
        assert_eq!(VALIDATOR_MISSING.default_severity, Severity::Warn);
    }
}
