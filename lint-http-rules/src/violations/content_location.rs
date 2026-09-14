// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Content-Location` defects — a field that names a resource and claims one.
//!
//! `Content-Location = absolute-URI / partial-URI`, so the alphabet and the
//! percent-triplets are [`uri`](crate::violations::uri)'s and a second field
//! line is [`field`](crate::violations::field)'s. What is here is the three
//! things left over, and they are three different kinds of finding — which is
//! why the subject is worth reading end to end rather than entry by entry.
//!
//! **One is grammatical**: neither alternative generates a fragment, because
//! each is a URI rule with the `[ "#" fragment ]` group dropped.
//!
//! **One is this crate's own strictness**: an empty value is a *legal*
//! `partial-URI`, since `relative-part` admits `path-empty` and reference
//! resolution then yields the target URI. No sentence complains, and the entry
//! says so rather than reaching for one.
//!
//! **And one is about a claim rather than a value.** § 8.7 attaches no
//! requirement to a `Content-Location` that differs from the target URI — it
//! gives the difference three meanings, the first of them the field's primary
//! use — and then says the claim "can only be trusted if both identifiers share
//! the same resource owner, which cannot be programmatically determined via
//! HTTP". So the finding is about an identity nothing in the exchange resolves.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field: its two alternatives, and what a value equal to or different
/// from the target URI means.
pub const RFC_9110_8_7: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.7",
    note: "Content-Location — `absolute-URI / partial-URI`, the three meanings a value differing from the target URI carries, and the sentence saying such a claim can only be trusted between identifiers with one resource owner, which HTTP cannot determine",
};

/// URI References: the `partial-URI` rule, and what it is for.
pub const RFC_9110_4_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1",
    note: "URI References — `partial-URI` is the rule for protocol elements carrying a relative URI but no fragment, and an element's own ABNF says which forms of reference it allows",
};

defects! {
    /// A `Content-Location` carrying a fragment: `/a/b#section`.
    ///
    /// Neither alternative generates one. `partial-URI` exists precisely for
    /// elements that take a relative URI *and not a fragment*, and
    /// `absolute-URI` is RFC 3986's URI with the `[ "#" fragment ]` group
    /// dropped — so a value with a `#` in it derives from no reading of this
    /// field's grammar.
    ///
    /// **The sentence quoted is the one that names the component**, not the
    /// generic MUST NOT about matching an ABNF rule: § 4.1 says what
    /// `partial-URI` is for, and that is the fact a sender needs. Unlike
    /// `Referer`, whose own section names the fragment and forbids it, this
    /// field's section says nothing about one — so the finding rests on the
    /// production and on nothing else.
    ///
    /// `warn`: a recipient resolving the reference gets a URI it can use, and
    /// what is lost is that the fragment names something the field was never
    /// able to say.
    ///
    // cite(RFC 9110 § 4.1): "A "partial-URI" rule is defined for protocol elements that can contain a relative URI but not a fragment component."
    CONTENT_LOCATION_FRAGMENT_FORBIDDEN = {
        id: "content_location_fragment_forbidden",
        title: "Content-Location carries a fragment component",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_4_1],
    }

    /// A `Content-Location` written and left blank.
    ///
    /// **Uncited, and the reason is that the grammar has no complaint.** An
    /// empty value is a legal `partial-URI` — `relative-part` admits
    /// `path-empty` — and reference resolution against the target URI then
    /// yields the target URI, so a recipient gets a perfectly good answer. What
    /// the entry reports is that the answer is the one the field was there to
    /// avoid: a sender that emits the field means to state an identifier, and
    /// this states the one the recipient already had.
    ///
    /// `info`, for a finding the document permits outright.
    CONTENT_LOCATION_EMPTY = {
        id: "content_location_empty",
        title: "Content-Location is written with nothing in it",
        message: "",
        default_severity: Severity::Info,
        spec: &[],
    }

    /// A `2xx` whose `Content-Location` names a URI other than the target.
    ///
    /// **`_ambiguous`, which is the ending for a report that makes no verdict
    /// about the message**, and this is the second entry to carry it. Nothing
    /// here is malformed and nothing is prohibited: § 8.7 gives the difference
    /// three meanings and the first of them — a negotiated variant, with the
    /// field naming the more specific identifier — is the field's primary use.
    /// What the section then says is that the claim can only be trusted where
    /// both identifiers share a resource owner, and that HTTP cannot determine
    /// that. So two URIs name one representation and nothing in the exchange
    /// says whether they may.
    ///
    /// **`info` rather than the `warn` that ending usually takes**, and the
    /// difference from
    /// [`request_target_form_ambiguous`](crate::violations::request_target::REQUEST_TARGET_FORM_AMBIGUOUS)
    /// is the argument: there two recipients on one chain may *route* the
    /// message two ways, so the ambiguity changes what happens to it. Here
    /// nothing any recipient does depends on the answer — the representation is
    /// the same either way — and what is left is a claim a human may want to
    /// confirm.
    ///
    // cite(RFC 9110 § 8.7): "Such a claim can only be trusted if both identifiers share the same resource owner, which cannot be programmatically determined via HTTP."
    CONTENT_LOCATION_AMBIGUOUS = {
        id: "content_location_ambiguous",
        title: "Content-Location names a resource other than the request target",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_8_7],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three entries and three kinds of finding, which is the subject's whole
    /// shape: a production refuses one, a document permits another outright,
    /// and the third is a claim rather than a value. The ranking follows.
    #[test]
    fn only_the_grammatical_finding_outranks_the_permitted_ones() {
        assert!(
            CONTENT_LOCATION_EMPTY.default_severity
                < CONTENT_LOCATION_FRAGMENT_FORBIDDEN.default_severity
        );
        assert_eq!(
            CONTENT_LOCATION_AMBIGUOUS.default_severity,
            CONTENT_LOCATION_EMPTY.default_severity
        );
        assert!(CONTENT_LOCATION_EMPTY.spec.is_empty());
    }
}
