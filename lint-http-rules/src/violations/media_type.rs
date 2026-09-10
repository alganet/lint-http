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
        spec: Some(RFC_9110_8_3_1),
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
        spec: Some(RFC_9110_8_3_1),
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
        spec: Some(RFC_9110_12_5_1),
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
        spec: Some(RFC_9110_8_3_1),
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
        assert_eq!(MEDIA_TYPE_UNREGISTERED.spec, Some(RFC_9110_8_3_1));
        assert_eq!(
            MEDIA_TYPE_UNREGISTERED.spec.map(|s| s.spec),
            Some("RFC 9110")
        );
    }
}
