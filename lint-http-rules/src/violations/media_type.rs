// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `media-type` defects — what a type/subtype pair can be wrong about once it
//! is well formed.
//!
//! Most of the grammar is spoken for elsewhere and deliberately not here: the
//! halves of `type "/" subtype parameters` are built from `token`, `parameter`
//! and `quoted-string`, so a mangled octet or a parameter with no `=` answers
//! under those subjects wherever the value is read — `Content-Type`, `Accept`,
//! `Accept-Patch`, a multipart body's part. **What is here is the pair
//! itself**: the `/` that separates it, the two halves that must not be empty,
//! and what the pair can be wrong about once both are well formed.
//!
//! Two of the four entries are about the pair failing to exist — nothing
//! written, or nothing on one side of the `/` — and the other two are about a
//! well-formed pair saying something it may not: a *range* where one type
//! belongs, and a name the deployment does not expect. That last one is the
//! second registry entry of the catalogue, after
//! [`auth_scheme_unregistered`](crate::violations::auth_scheme::AUTH_SCHEME_UNREGISTERED):
//! an `ought to` addressed to whoever defines the name, measured against a list
//! the operator wrote, with the id naming the sentence rather than the list so
//! that an operator's configuration survives the list changing.

use crate::helpers::media_type::MediaTypeError;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The production, the case-insensitivity of its two tokens, and the
/// registration guidance the entry below carries.
pub const RFC_9110_8_3_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1",
    note: "Media Type: `media-type = type \"/\" subtype parameters`, both halves `token` and both case-insensitive, and the \"ought to be registered with IANA\" guidance — guidance rather than a requirement, and not something this crate verifies",
};

/// The wider `media-range` the request side uses, where the asterisk means
/// what it means.
pub const RFC_9110_12_5_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("12.5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1",
    note: "Accept and its `media-range` — where the asterisk groups media types into ranges, which is the reason it names nothing in a Content-Type",
};

/// Naming requirements: `restricted-name`, where a suffix starts, and what a
/// name must begin with.
pub const RFC_6838_4_2: SpecRef = SpecRef {
    spec: "RFC 6838",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2",
    note: "Naming Requirements: `restricted-name`, which decides where a suffix starts (\"characters after last plus\") and that a name must begin with ALPHA or DIGIT — so a subtype that is only a suffix has no base name",
};

/// Structured syntax name suffixes: what a `+suffix` claims about the payload,
/// and the caution about using one nobody has registered.
pub const RFC_6838_4_2_8: SpecRef = SpecRef {
    spec: "RFC 6838",
    section: Some("4.2.8"),
    url: "https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2.8",
    note: "Structured Syntax Name Suffixes: that an unregistered `+suffix` SHOULD NOT be used, and — the sharper half — that a suffix MUST NOT name a syntax the type does not employ",
};

defects! {
    /// A field written with no media type on it at all, once the `OWS` its own
    /// production prints comes off. The field states the media type of the
    /// representation, so an empty one states none — and a recipient that has
    /// to guess is exactly what the field exists to prevent.
    ///
    // cite(RFC 9110 § 8.3.1, label: media-type grammar): "media-type = type "/" subtype parameters"
    MEDIA_TYPE_EMPTY = {
        id: "media_type_empty",
        title: "Media type is written with nothing in it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_8_3_1],
    }

    /// A value that is not a `type "/" subtype` pair: no `/` anywhere, or a `/`
    /// with nothing on one side of it. One id for both, because the two are the
    /// same failure seen from either side of the separator — `text` names no
    /// subtype and `text/` names no subtype either — and the message says which
    /// was written.
    ///
    /// This is the entry every other reader of a media type *gates* on: a
    /// dozen rules call the shared reader and return `None` here, because a
    /// value that is not a media type cannot be asked whether it is registered,
    /// whether its suffix is known, or what its charset says.
    ///
    // cite(RFC 9110 § 8.3.1, label: media-type grammar): "media-type = type "/" subtype parameters"
    MEDIA_TYPE_MALFORMED = {
        id: "media_type_malformed",
        title: "Media type is not a type/subtype pair",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_8_3_1],
    }

    /// An asterisk in either half of a `Content-Type`. `*` is a `tchar`, so
    /// `*/plain` derives from the production and nothing about the grammar
    /// refuses it — what refuses it is that the field states *the* media type
    /// of a representation while the asterisk exists to name a *range* of them.
    ///
    /// The same shape as
    /// [`content_coding_wildcard_forbidden`](crate::violations::content_coding::CONTENT_CODING_WILDCARD_FORBIDDEN),
    /// and for the same reason: a word that belongs to the field expressing
    /// preferences, written in the field stating what was done. Both entries
    /// quote the field that gives the word its meaning, because the field that
    /// forbids it says nothing about it at all.
    ///
    // cite(RFC 9110 § 12.5.1): "The asterisk "*" character is used to group media types into ranges, with "*/*" indicating all media types and "type/*" indicating all subtypes of that type."
    MEDIA_TYPE_WILDCARD_FORBIDDEN = {
        id: "media_type_wildcard_forbidden",
        title: "A media range is written where one media type belongs",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_12_5_1],
    }

    /// A well-formed `type/subtype` that the deployment does not expect. The
    /// tokens parse, the pair is comparable, and a recipient still has nothing
    /// telling it what the bytes are.
    ///
    /// **Measured against the operator's `allowed` list rather than against
    /// IANA's table**, which this crate does not carry — the same stand-in
    /// `auth_scheme_unregistered` makes, and worth the same caution: an entry
    /// may be an exact pair, a `type/*`, `*/*`, or a `+suffix`, and those three
    /// wildcard forms are configuration conveniences with no basis in any
    /// document. So a finding here means "not on the list", and the list is the
    /// operator's answer to the sentence quoted below.
    ///
    /// `warn`: registration is an *ought to* addressed to whoever defines the
    /// type, and an unregistered type between two parties that agree on it
    /// breaks nothing on the wire.
    ///
    // cite(RFC 9110 § 8.3.1): "Media types ought to be registered with IANA according to the procedures defined in [BCP13]."
    MEDIA_TYPE_UNREGISTERED = {
        id: "media_type_unregistered",
        title: "Media type is not one the deployment recognises",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_8_3_1],
    }

    /// A subtype ending in a bare `+`: `application/vnd.example+`.
    ///
    /// **The `+` is not the suffix, what follows it is** — § 4.2's own comment
    /// on the production says the characters after the last plus specify the
    /// structured syntax — so a subtype ending on one appends nothing and names
    /// no syntax at all. The grammar permits the shape, since
    /// `restricted-name-chars` admits `+` anywhere past the first character;
    /// what refuses it is what the construct is *for*.
    ///
    /// `_empty` and not `_malformed` for that reason: the name derives, and the
    /// slot the `+` opened was left with nothing in it.
    ///
    // cite(RFC 6838 § 4.2): "restricted-name-chars =/ "+" ; Characters after last plus always ; specify a structured syntax suffix"
    MEDIA_TYPE_SUFFIX_EMPTY = {
        id: "media_type_suffix_empty",
        title: "A media type subtype ends in a bare plus",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6838_4_2],
    }

    /// A subtype that is *only* a suffix: `application/+json`.
    ///
    /// **[`MEDIA_TYPE_SUFFIX_EMPTY`]'s mirror**, and the two are two entries
    /// because they are two senders: one wrote a name and forgot the syntax it
    /// is written in, the other named a syntax and forgot what is written in
    /// it. A `+suffix` qualifies a base name, and here there is none to
    /// qualify.
    ///
    /// **The grammar refuses this one outright**, which the mirror's does not:
    /// `restricted-name-first` is `ALPHA / DIGIT`, so a subtype opening on `+`
    /// derives from nothing. It is still `_empty` rather than `_malformed`,
    /// because what the sender left out is the part before the `+` and the
    /// message can say so — where `media_type_malformed` would say only that
    /// the pair did not parse.
    ///
    // cite(RFC 6838 § 4.2): "restricted-name = restricted-name-first *126restricted-name-chars restricted-name-first  = ALPHA / DIGIT"
    MEDIA_TYPE_NAME_EMPTY = {
        id: "media_type_name_empty",
        title: "A media type subtype is a suffix with no base name",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6838_4_2],
    }

    /// A `+suffix` the deployment does not recognise: `application/foo+xmls`.
    ///
    /// **A claim about the payload's structure, which is why it is worth
    /// reporting at all.** § 4.2.8's sharper sentence forbids a media type from
    /// incorporating a suffix for a structured syntax it does not actually
    /// employ, so a recipient that reads `+json` and finds something else has
    /// been told a falsehood about the bytes — and the entry stands on the
    /// milder sentence beside it, which is the one about registration and
    /// therefore the one a *linter* can measure.
    ///
    /// **Measured against the operator's list, like
    /// [`MEDIA_TYPE_UNREGISTERED`]**, and with the same caution: this crate
    /// carries no IANA table, so a finding means "not on the list".
    ///
    /// **The comparison folds case**, because the subtype the suffix lives in
    /// is case-insensitive: `+JSON` is `+json`.
    ///
    /// `warn`, with the type-level entry above it: two parties that agree on a
    /// suffix break nothing on the wire.
    ///
    // cite(RFC 6838 § 4.2.8): ""+suffix" constructs for as-yet unregistered structured syntaxes SHOULD NOT be used, given the possibility of conflicts with future suffix definitions."
    MEDIA_TYPE_SUFFIX_UNREGISTERED = {
        id: "media_type_suffix_unregistered",
        title: "A structured syntax suffix is not one the deployment recognises",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6838_4_2_8],
    }
}

/// The defect a [`MediaTypeError`] reports as.
///
/// Exhaustive, so a new way for the pair to fail does not compile until the
/// catalogue names it — and two of the three collapse deliberately, which is
/// the kind of decision that belongs on the page rather than in a `match` arm
/// nobody re-read.
pub fn media_type_error(defect: MediaTypeError) -> &'static ViolationDef {
    match defect {
        MediaTypeError::Empty => &MEDIA_TYPE_EMPTY,
        MediaTypeError::SlashMissing | MediaTypeError::PartEmpty => &MEDIA_TYPE_MALFORMED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two of the reader's three verdicts share an id and the third does not,
    /// which is the split written down: an empty field says nothing, and a
    /// value with a `/` in the wrong place or missing says the wrong thing.
    #[test]
    fn the_readers_verdicts_collapse_where_the_defect_is_one() {
        assert_eq!(
            media_type_error(MediaTypeError::Empty).id,
            "media_type_empty"
        );
        assert_eq!(
            media_type_error(MediaTypeError::SlashMissing).id,
            "media_type_malformed"
        );
        assert_eq!(
            media_type_error(MediaTypeError::PartEmpty).id,
            "media_type_malformed"
        );
    }

    /// The registry entry carries the registration sentence and not the suffix
    /// one. Before it existed, the finding cited RFC 6838 § 4.2.8 — the
    /// sentence defining `+json` as a structured syntax suffix, which is how
    /// one *allowlist entry* is matched and says nothing about whether a type
    /// is registered.
    #[test]
    fn the_entry_quotes_the_registration_sentence() {
        assert_eq!(MEDIA_TYPE_UNREGISTERED.spec, [RFC_9110_8_3_1]);
        let [only] = MEDIA_TYPE_UNREGISTERED.spec else {
            panic!("one sentence")
        };
        assert_eq!(only.spec, "RFC 9110");
    }
}
