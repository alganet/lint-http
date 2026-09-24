// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `entity-tag` defects — the three ways a validator is not one.
//!
//! One production, three fields: an `ETag` a response sends, and the
//! `If-Match` and `If-None-Match` lists a request sends back. RFC 9110 § 8.8.3
//! writes `entity-tag = [ weak ] opaque-tag` once and the conditional fields
//! take it by name, so a tag that never opened its quotes is the same defect
//! whichever direction it travelled in — which is worth saying out loud here,
//! because the two conditional rules are the pair Phase 4 will look at first
//! and this is the part of them that was never each rule's own.
//!
//! **The interior is not a `quoted-string`, and reading it as one is what the
//! reader beneath these entries had been doing.** `etagc` admits the backslash
//! as an ordinary character and admits no DQUOTE at all: there is no escape
//! inside an opaque-tag, so `"a\"` is a tag ending in a backslash and `"a\"b"`
//! is a tag that closed early with `b"` left over. The quoted-string reader
//! answered the opposite on both.
//!
//! **One entry is not about the production.** A strong tag is a claim about
//! the octets it names — that no other representation of the resource carries
//! it unless its data is identical — and a well-formed tag can make that claim
//! falsely. [`ETAG_CONFLICTING`] is the one case the wire shows: the same
//! strong tag on two responses whose content codings differ.

use crate::helpers::validator::EntityTagDefect;
use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The whole production and its character class, which is one section: the
/// weakness indicator, the two delimiters and `etagc`.
pub const RFC_9110_8_8_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.8.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3",
    note: "Entity Tags — `entity-tag = [ weak ] opaque-tag`, `weak = %s\"W/\"` (case-sensitive by the `%s` prefix), `opaque-tag = DQUOTE *etagc DQUOTE`, and `etagc` as VCHAR minus the DQUOTE plus obs-text",
};

/// Validator strength, and the one example § 8.8.1 gives of a validator that
/// is weak whatever it is labelled.
pub const RFC_9110_8_8_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.8.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.1",
    note: "Weak versus Strong — a validator shared by two representations of a resource at the same time is weak unless their data is identical, and a gzip-coded and an unencoded representation are the example",
};

defects! {
    /// A weakness indicator in any spelling but `W/`.
    ///
    /// `weak = %s"W/"`, and the `%s` is the whole of why this is a defect
    /// rather than a preference: RFC 5234 § 2.3 makes an unprefixed ABNF string
    /// case-insensitive, so the prefix is the author saying the case matters.
    /// A `w/"abc"` is a sender who meant a weak validator and wrote a value the
    /// production does not generate — which is a different finding from a tag
    /// with no quotes at all, and was reported as one before this subject
    /// existed.
    ///
    // cite(RFC 9110 § 8.8.3, label: weak indicator): "entity-tag = [ weak ] opaque-tag weak       = %s"W/""
    ETAG_WEAK_INDICATOR_INVALID = {
        id: "etag_weak_indicator_invalid",
        title: "Weakness indicator is not written W/",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_8_8_3],
        strength: Strength::Grammar,
    }

    /// No opening DQUOTE, or nothing closing it.
    ///
    /// The `opaque-tag` *is* its two delimiters and what they enclose, so a
    /// value missing one of them has no interior to examine rather than a bad
    /// one — the same shape `quoted_string_delimiter_missing` has, at a
    /// production that shares the delimiters and nothing else.
    ///
    // cite(RFC 9110 § 8.8.3, label: opaque-tag): "opaque-tag = DQUOTE *etagc DQUOTE"
    ETAG_DELIMITER_MISSING = {
        id: "etag_delimiter_missing",
        title: "Entity-tag is not quoted",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_8_8_3],
        strength: Strength::Grammar,
    }

    /// A character `etagc` does not admit.
    ///
    /// One entry over the whole class, and the reason is the class: `%x21 /
    /// %x23-7E / obs-text` is one line refusing the DQUOTE, the controls and
    /// DEL together, and an operator who wants the tag re-quoted wants it
    /// re-quoted whichever of them arrived. The DQUOTE is the reachable one —
    /// a control octet cannot enter a `HeaderValue` — and it is also the
    /// interesting one, because a tag holding a DQUOTE closed somewhere its
    /// sender did not mean it to.
    ///
    // cite(RFC 9110 § 8.8.3): "etagc      = %x21 / %x23-7E / obs-text ; VCHAR except double quotes, plus obs-text"
    ETAG_CHARACTER_FORBIDDEN = {
        id: "etag_character_forbidden",
        title: "Entity-tag holds a character etagc does not admit",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_8_8_3],
        strength: Strength::Grammar,
    }

    /// An `ETag` whose whole value is `*`.
    ///
    /// **Worth an id of its own although [`ETAG_DELIMITER_MISSING`] would
    /// catch it**, and the reason is which mistake it is: `*` is the one
    /// non-tag an `ETag` plausibly holds, written by a server copying the shape
    /// of the conditional fields that *do* take it. `If-Match: *` and
    /// `If-None-Match: *` are conforming values with meanings of their own, and
    /// a server that has read those and not § 8.8.3 writes this.
    ///
    /// **`_forbidden` rather than `_malformed`** for the same reason: reporting
    /// it as a quoted string with no DQUOTEs describes the octets and not the
    /// mistake, and a sender reading that finding would go looking for a
    /// missing quote instead of a wildcard that this field has no place for.
    ///
    // cite(RFC 9110 § 8.8.3): "An entity tag consists of an opaque quoted string, possibly prefixed by a weakness indicator."
    ETAG_WILDCARD_FORBIDDEN = {
        id: "etag_wildcard_forbidden",
        title: "An ETag carries the wildcard the conditional fields take",
        message: "ETag header value '*' is invalid for responses; ETag must be an entity-tag",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_8_8_3],
    }

    /// One strong entity tag on two responses for the same resource whose
    /// content codings differ.
    ///
    /// **A content coding is part of the representation data**, so a `gzip`
    /// response and an unencoded one are two sequences of octets, and a strong
    /// tag says its octets are the only ones that carry it. § 8.8.1 gives this
    /// pairing as *the* example of a validator that is weak — the `W/` is what
    /// the sender left off — and § 8.8.3's note says why the difference is
    /// worth keeping: a cache updating a stored response from a `304`, and a
    /// client resuming with `If-Range`, both take a matching strong tag to mean
    /// the bytes they hold are the bytes the server would send. A client that
    /// fetched the first half of the `br` body and asks for the rest under the
    /// tag gets the rest of the unencoded one.
    ///
    /// **`_conflicting`: two responses, each well formed, that cannot both be
    /// telling the truth.** Nothing in either message is wrong on its own, and
    /// which one to change — a distinct tag per coding, or `W/` on both — is
    /// the operator's choice, so the finding names both codings and the tag.
    ///
    /// **Two media types under one tag are not this.** § 8.8.1 says outright
    /// that two representations differing only in metadata may share a strong
    /// validator, and the content coding is the one difference it names as not
    /// metadata.
    ///
    /// `warn`, and `Unstated`: neither sentence carries a keyword, and the
    /// level is the consequence — a spliced range or a stored response
    /// freshened with the other coding's metadata is corrupt content, delivered
    /// by a cache or client that did everything right.
    ///
    // cite(RFC 9110 § 8.8.1): "if the origin server sends the same validator for a representation with a gzip content coding applied as it does for a representation with no content coding, then that validator is weak."
    // cite(RFC 9110 § 8.8.3.3): "Content codings are a property of the representation data, so a strong entity tag for a content-encoded representation has to be distinct from the entity tag of an unencoded representation to prevent potential conflicts during cache updates and range requests."
    ETAG_CONFLICTING = {
        id: "etag_conflicting",
        title: "One strong entity tag names two content codings",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_8_8_1, RFC_9110_8_8_3],
        strength: Strength::Unstated,
    }
}

/// The defect a parsed [`EntityTagDefect`] reports as.
pub fn entity_tag_defect(defect: EntityTagDefect) -> &'static ViolationDef {
    match defect {
        EntityTagDefect::WeakIndicatorInvalid => &ETAG_WEAK_INDICATOR_INVALID,
        EntityTagDefect::DelimiterMissing => &ETAG_DELIMITER_MISSING,
        EntityTagDefect::BadCharacter(_) => &ETAG_CHARACTER_FORBIDDEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three variants, three ids: the prefix, the delimiters, the class.
    #[test]
    fn each_entity_tag_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (
                EntityTagDefect::WeakIndicatorInvalid,
                "etag_weak_indicator_invalid",
            ),
            (EntityTagDefect::DelimiterMissing, "etag_delimiter_missing"),
            (
                EntityTagDefect::BadCharacter('"'),
                "etag_character_forbidden",
            ),
        ] {
            assert_eq!(entity_tag_defect(defect).id, id);
        }
    }

    /// The severities came out flat, and that is a finding rather than an
    /// omission: nothing here is invisible (a control octet cannot reach a
    /// field value), nothing parses into something impossible, and every one of
    /// the three is one sender writing one value the production does not
    /// generate.
    #[test]
    fn the_three_defects_rank_together() {
        for def in [
            &ETAG_WEAK_INDICATOR_INVALID,
            &ETAG_DELIMITER_MISSING,
            &ETAG_CHARACTER_FORBIDDEN,
        ] {
            assert_eq!(def.default_severity, Severity::Error);
        }
    }
}
