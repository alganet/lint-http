// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Accept-Patch` defects — one entry, and two sentences asking for it.
//!
//! `Accept-Patch = 1#media-type`, so the value's own reading belongs to
//! [`list`](crate::violations::list) and
//! [`media_type`](crate::violations::media_type) and nothing about the syntax
//! is here. What is here is the field's *absence*, which RFC 5789 asks about
//! twice in two sections, for two different responses, in the same words.
//!
//! **The two SHOULDs are one entry, and the reason is not that they say the
//! same thing — it is that a sender fixes them the same way.** § 2.2 asks a
//! `415` answering a `PATCH` to carry the field; § 3.1 asks the `OPTIONS`
//! response of a resource that supports `PATCH` to carry it. Different
//! responses, one omission, one repair: name the patch document formats. So the
//! entry holds both references and no finding of it carries a citation, which
//! is the shape a requirement stated once per *occasion* has — the mirror of a
//! requirement stated once per protocol version, where the same rule declares
//! both sections too. Each message names the section it was read from, as both
//! already did.
//!
//! **`warn`, and the contrast with
//! [`accept_ranges_missing`](crate::violations::accept_ranges::ACCEPT_RANGES_MISSING)
//! is the argument.** That entry is `info` because nothing asks for the field
//! at all — the finding is a suggestion with a sentence behind it. Here two
//! SHOULDs ask, which is as close to a requirement as an advisory field gets,
//! and the client is left unable to retry a request the server has just told it
//! to change.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field's own section: the grammar, and the SHOULD asking for it in an
/// `OPTIONS` response from a resource that supports `PATCH`.
pub const RFC_5789_3_1: SpecRef = SpecRef {
    spec: "RFC 5789",
    section: Some("3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc5789.html#section-3.1",
    note: "`Accept-Patch`: `1#media-type`, defined as a response header, and the SHOULD that asks for it in the OPTIONS response of any resource supporting PATCH",
};

/// Error handling, and the second SHOULD: a `415` answering a `PATCH` is asked
/// to say which patch document formats it would have accepted.
pub const RFC_5789_2_2: SpecRef = SpecRef {
    spec: "RFC 5789",
    section: Some("2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc5789.html#section-2.2",
    note: "Error handling: a 415 (Unsupported Media Type) answering a PATCH SHOULD carry an Accept-Patch naming the patch document media types the resource supports",
};

defects! {
    /// A response that owes the client a list of patch document formats and
    /// carries none: a `415` answering a `PATCH`, or an `OPTIONS` response
    /// whose `Allow` advertises `PATCH`.
    ///
    /// **Two occasions, one entry.** Both are the same omission with the same
    /// repair, and neither section is *the* one that governs a finding — so the
    /// def names both and carries a citation onto neither, which is what this
    /// catalogue does with a requirement written more than once. The message
    /// says which response was in front of it.
    ///
    /// **The `415` case has a condition worth keeping in view**: RFC 9110
    /// § 15.5.16 defines the status over the content's *coding* as well as its
    /// media type, and a server refusing a coding has no patch format to name.
    /// The rule reading this stands the finding down when the response carries
    /// an `Accept-Encoding`, which is the tell that status definition supplies.
    ///
    /// `warn` — two SHOULDs, and a client that cannot retry.
    ///
    /// Both sentences are quoted here, where neither is claimed as the one:
    ///
    // cite(RFC 5789 § 2.2): "Such a response SHOULD include an Accept-Patch response header as described in Section 3.1 to notify the client what patch document media types are supported."
    // cite(RFC 5789 § 3.1): "Accept-Patch SHOULD appear in the OPTIONS response for any resource that supports the use of the PATCH method."
    ACCEPT_PATCH_MISSING = {
        id: "accept_patch_missing",
        title: "A response that should name the patch formats names none",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_5789_2_2, RFC_5789_3_1],
        strength: Strength::Should,
    }
    /// A `PATCH` whose `Content-Type` names a format no `Accept-Patch` for this
    /// resource has advertised.
    ///
    /// **`_ignored` because the server stated what it accepts and the client
    /// sent something else** — the field is an advertisement, and this is a
    /// request that did not read it. § 3.1 says the presence of a specific
    /// format in the header indicates that that format is allowed, so a format
    /// the advertisement does not mention is one the resource has not said it
    /// takes, and `415 (Unsupported Media Type)` is the answer RFC 5789 offers.
    ///
    /// **The evidence is an earlier response**, which is what keeps this on the
    /// advertisement's subject rather than on the method's: the finding needs a
    /// stored `Accept-Patch`, and without one there is nothing to disagree with.
    ///
    // cite(RFC 5789 § 3.1): "The presence of a specific patch document format in this header indicates that that specific format is allowed on the resource identified by the Request-URI."
    ACCEPT_PATCH_IGNORED = {
        id: "accept_patch_ignored",
        title: "A PATCH sends a format the resource never advertised",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_5789_3_1],
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::accept_ranges::ACCEPT_RANGES_MISSING;

    /// Two entries about a field that is not there, ranked apart by what asks
    /// for it. Nothing asks for an `Accept-Ranges`; two sections ask for this
    /// one. If the ranking ever collapses, this is where the argument was.
    #[test]
    fn a_should_outranks_a_suggestion() {
        assert!(ACCEPT_RANGES_MISSING.default_severity < ACCEPT_PATCH_MISSING.default_severity);
    }

    /// The entry names two sections on purpose, which is what keeps its
    /// findings uncited — a message governed by two sentences names its own.
    #[test]
    fn the_entry_names_both_occasions_and_neither_governs() {
        assert_eq!(ACCEPT_PATCH_MISSING.spec.len(), 2);
    }
}
