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

/// The selected representation: the thing both SHOULDs are about, and which a
/// 200 carries only when it answers a GET or a HEAD.
pub const RFC_9110_3_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-3.2",
    note: "Representations — the \"selected representation\" is what a GET would select, and it is what conditional requests are evaluated against; a 200 answering any other method carries no such thing",
};

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
    /// `warn`, and the reason [`user_agent_missing`](crate::violations::user_agent)
    /// is `info` is the reason this one is not: both have a conforming case
    /// indistinguishable from the defect, and only this one has a sentence
    /// telling the sender to do it. § 8.8.2.1 and § 8.8.3.1 each say an origin
    /// server SHOULD send the field for any representation where the answer can
    /// reasonably be determined. What the finding buys is that every later
    /// request for this resource has to be answered in full.
    ///
    /// **Only a `200` answering a `GET` or a `HEAD` is asked.** Both sentences
    /// are about the *selected representation*, which § 3.2 defines as the one
    /// a GET would select and the thing a conditional request is evaluated
    /// against; § 15.3.1 tabulates what a 200's content is for every other
    /// method — the status of an action, the communication options, the
    /// request echoed back — and none of those is a representation a later
    /// request could validate. A `200` to an `OPTIONS` or a `TRACE` is not
    /// cacheable at all (§ 9.3.7, § 9.3.8), so the "every later request is a
    /// full transfer" this entry warns of was never avoidable there. The one
    /// shape not read is a `POST` response that names its own target in
    /// `Content-Location` and so is cacheable (§ 9.3.3); that reads as silence
    /// here, which is the cheaper mistake.
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
