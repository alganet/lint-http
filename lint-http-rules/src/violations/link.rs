// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Link` defects — how a `link-value` is put together, and what its
//! parameters say.
//!
//! `link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )` names four
//! things and defines two of them. The list around the members is
//! [`list`](crate::violations::list)'s, a parameter's name is a
//! [`token`](crate::violations::token) and its value a `token` or a
//! [`quoted_string`](crate::violations::quoted_string), the whitespace beside
//! the `=` is [`bws`](crate::violations::bws)'s, and what goes between the
//! angle brackets is a [`uri`](crate::violations::uri). **What is RFC 8288's
//! own is the brackets, the repetition, and everything the parameters mean.**
//!
//! **The brackets are one entry for two delimiters**, which is the answer
//! [`quoted_string`](crate::violations::quoted_string) gives for its DQUOTEs: a
//! production written as a delimiter, a value and a delimiter is broken the
//! same way whichever end is missing, and the message says which.
//!
//! **The repetition is not the list**, and the distinction is the one this
//! field is most likely to be read wrong on. § 5.6.1.1's sentence about empty
//! elements is about the `#` construct and its commas; the parameters hang off
//! `*( OWS ";" OWS link-param )`, which RFC 8288 writes itself with no bracket
//! around the `link-param` inside it. So a comma with nothing beside it is
//! `list_member_empty` and a semicolon with nothing beside it is this
//! subject's — two sentences from two documents about two separators.
//!
//! **Flat at `warn`.** A `Link` is metadata about relationships: a member a
//! recipient cannot read costs a link it would have followed, and no exchange
//! turns on it. Nothing here is `error`, and nothing is `info` either, because
//! every one of these leaves a member that does not derive at all.
//
// cite(RFC 8288 § 3, label: link-value assembly): "link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )"

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The serialisation: the member, its brackets, and the parameter repetition.
pub const RFC_8288_3: SpecRef = SpecRef {
    spec: "RFC 8288",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc8288.html#section-3",
    note: "The serialisation: `Link = #link-value`, the angle-bracketed \
           `URI-Reference`, and `link-param = token BWS [ \"=\" BWS ( token / \
           quoted-string ) ]` — whose optional group is what makes a valueless \
           parameter conforming. Also the sentence equating the token and \
           quoted-string forms, which is why a value is judged after unquoting",
};

/// The `rel` parameter: that a member has one, and what its value derives from.
pub const RFC_8288_3_3: SpecRef = SpecRef {
    spec: "RFC 8288",
    section: Some("3.3"),
    url: "https://www.rfc-editor.org/rfc/rfc8288.html#section-3.3",
    note: "`rel` MUST be present and MUST NOT appear more than once; its value is \
           `relation-type *( 1*SP relation-type )`; `relation-type = reg-rel-type / \
           ext-rel-type` with `ext-rel-type = URI`, required to be absolute. The \
           section that makes a URI-shaped relation type conforming and a capital \
           letter in a registered one not",
};

defects! {
    /// A `link-value` with no `rel` parameter at all: `</a>; title="Home"`.
    ///
    /// **The one parameter this serialisation requires**, and the reason is
    /// what a link *is*: a target, a context and a relation type. A member
    /// naming a target and no relation says which document is there and
    /// nothing about why, so a recipient has nothing to file it under.
    ///
    /// Reached by two paths that are one defect — a member with no parameters
    /// at all, and a member whose parameters do not include this one — because
    /// what is absent is the same thing and the fix is the same.
    ///
    // cite(RFC 8288 § 3.3, label: rel presence): "The rel parameter MUST be present but MUST NOT appear more than once in a given link-value; occurrences after the first MUST be ignored by parsers."
    LINK_REL_MISSING = {
        id: "link_rel_missing",
        title: "Link member carries no rel parameter",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_8288_3_3],
    }

    /// A `rel` that is present and says nothing: a bare `rel`, or `rel=""`.
    ///
    /// **Distinct from a parameter with an open `=` and nothing after it**,
    /// which is [`LINK_PARAM_VALUE_EMPTY`] and is about the *grammar* of any
    /// parameter. This entry is about `rel` in particular: the optional group
    /// makes a valueless parameter derive, and `""` is a `quoted-string` that
    /// derives too, so both spellings are conforming `link-param`s carrying no
    /// relation type — which § 3.3's own value production does not admit,
    /// since it opens on a `relation-type`.
    ///
    /// **Two spellings, one entry**: a sender that wrote `rel` and one that
    /// wrote `rel=""` both named a link with no relation, and a recipient
    /// cannot tell the two apart once the value is unquoted.
    ///
    // cite(RFC 8288 § 3.3, label: rel value production): "relation-type *( 1*SP relation-type )"
    LINK_REL_EMPTY = {
        id: "link_rel_empty",
        title: "Link member writes a rel with no relation type in it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_8288_3_3],
    }

    /// A `rel` value that opens or closes on a space: `rel=" next"`.
    ///
    /// The value is `relation-type *( 1*SP relation-type )` — it opens on a
    /// type, closes on a type, and prints the separator only between two of
    /// them. A leading or trailing space is admitted nowhere, and a recipient
    /// splitting on `1*SP` finds an element that is not a relation type at all.
    ///
    /// **The value's shape rather than a value's**: what fails here is how the
    /// types are arranged, where
    /// [`LINK_RELATION_TYPE_MALFORMED`] is one of them failing on its own.
    ///
    // cite(RFC 8288 § 3.3, label: rel value separator): "relation-type *( 1*SP relation-type )"
    LINK_REL_MALFORMED = {
        id: "link_rel_malformed",
        title: "Link rel value opens or closes on a space",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_8288_3_3],
    }

    /// A relation type deriving from neither alternative: `Next`, `foo bar` —
    /// anything that is not a `reg-rel-type` and has no scheme to be a URI
    /// with.
    ///
    /// **The alternation is the whole of the check, and each half is stricter
    /// and looser than a `token` at once.** `reg-rel-type` admits less — a
    /// leading lowercase letter, then lowercase letters, digits, `.` and `-`,
    /// so no capital and no `_` — and `ext-rel-type` admits far more, since a
    /// URI holds `:` and `/`. A scan against `tchar` would pass `Next` and
    /// report `http://example.net/foo`, which the section prints as a
    /// conforming example.
    ///
    /// **The `:` is what commits a value to one half**, which is why this entry
    /// is reached only where there is none: once a colon is written, the value
    /// can only have been meant as a URI, and every octet of it is
    /// [`uri`](crate::violations::uri)'s to judge — the scheme's spelling and
    /// the alphabet both. **A value with no colon is neither production's, and
    /// that is this entry**: the verdict belongs to `relation-type` itself,
    /// which is what an alternation can own when the reading cannot commit.
    ///
    // cite(RFC 8288 § 3.3, label: relation-type alternation): "relation-type  = reg-rel-type / ext-rel-type"
    LINK_RELATION_TYPE_MALFORMED = {
        id: "link_relation_type_malformed",
        title: "Link names a relation type that is neither registered-shaped nor a URI",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_8288_3_3],
    }

    /// A member whose target is not between angle brackets: `http://x>`, or
    /// `<http://x` with nothing closing it.
    ///
    /// **One entry for both delimiters.** The production writes `"<"
    /// URI-Reference ">"`, and a member missing either one is the same member:
    /// a recipient has no way to tell where the target begins or ends, so the
    /// whole `link-value` is unreadable rather than partly wrong. That is the
    /// answer `quoted_string_delimiter_missing` gives for its DQUOTEs, and the
    /// message says which bracket was the missing one.
    ///
    /// `warn`, with the subject: the member is dropped and the exchange is
    /// untouched.
    ///
    // cite(RFC 8288 § 3.1): "Each link-value conveys one target IRI as a URI-Reference (after conversion to one, if necessary; see [RFC3987], Section 3.1) inside angle brackets ("<>")."
    LINK_TARGET_DELIMITER_MISSING = {
        id: "link_target_delimiter_missing",
        title: "Link member's target is not inside angle brackets",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_8288_3],
    }

    /// A member that goes on past its target with something other than the
    /// parameters' `;`: `<http://x> rel=next`, where the semicolon was never
    /// written.
    ///
    /// After the closing bracket the production admits exactly one thing, and
    /// it is a repetition that opens on a `;`. Anything else derives from
    /// nothing — and, as with a `Via` member that does not end where the
    /// production ends it, the catalogue cannot say whether the sender lost a
    /// delimiter or ran two members together. **What the finding claims is the
    /// only thing both readings share**: from here on the member is not
    /// derivable.
    ///
    // cite(RFC 8288 § 3, label: link-param repetition): "link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )"
    LINK_MEMBER_MALFORMED = {
        id: "link_member_malformed",
        title: "Link member carries content the production does not continue with",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_8288_3],
    }

    /// A semicolon with no parameter behind it: `<http://x>; rel=next;;`.
    ///
    /// `*( OWS ";" OWS link-param )` repeats a group holding one parameter and
    /// brackets nothing inside it, so every semicolon the repetition generates
    /// owes a `link-param`. **Not
    /// [`list_member_empty`](crate::violations::list)**: that entry carries RFC
    /// 9110 § 5.6.1.1's requirement about a `#rule`'s commas, and this
    /// repetition is RFC 8288's own — the same distinction `Prefer` draws from
    /// the other side, where `*( OWS ";" [ OWS parameter ] )` brackets the
    /// parameter and a bare `;` conforms.
    ///
    /// `_empty` rather than `_missing`: the semicolon is the repetition's
    /// delimiter, so a sender that wrote one knew a parameter was due.
    ///
    // cite(RFC 8288 § 3, label: link-param repetition group): "link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )"
    LINK_PARAM_EMPTY = {
        id: "link_param_empty",
        title: "Link member writes a semicolon with no link-param behind it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_8288_3],
    }

    /// A parameter whose `=` is written with nothing after it: `rel=`.
    ///
    /// **The optional group is what makes this a finding rather than the
    /// opposite.** `link-param = token BWS [ "=" BWS ( token / quoted-string )
    /// ]` brackets the `=` *and* the value together, so a bare `rel` derives
    /// perfectly well — it is a parameter with no value, which this field
    /// admits. A member that writes the `=` has entered the group and owes a
    /// `token` or a `quoted-string`, neither of which derives the empty string.
    ///
    /// **This entry is the field's answer to a `None` in a mapping.** The
    /// shared reader of `token BWS [ "=" BWS word ]` returns no id for an empty
    /// value, because what one means is the field's to say and its readers
    /// answered differently; here it means a parameter that opened its value
    /// and wrote none.
    ///
    // cite(RFC 8288 § 3, label: link-param optional group): "link-param = token BWS [ "=" BWS ( token / quoted-string ) ]"
    LINK_PARAM_VALUE_EMPTY = {
        id: "link_param_value_empty",
        title: "Link parameter writes an '=' with no value after it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_8288_3],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::list::LIST_MEMBER_EMPTY;

    /// The subject is flat and every entry names the section that prints the
    /// production it fails.
    #[test]
    fn every_entry_ranks_with_its_siblings() {
        for def in [
            &LINK_TARGET_DELIMITER_MISSING,
            &LINK_MEMBER_MALFORMED,
            &LINK_PARAM_EMPTY,
            &LINK_PARAM_VALUE_EMPTY,
        ] {
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
            assert_eq!(def.spec.len(), 1, "{}", def.id);
        }
    }

    /// The two separators a `Link` writes answer to two documents: the comma to
    /// the list construct's sentence, the semicolon to this field's own
    /// repetition. They look alike on the wire and are not one entry.
    #[test]
    fn the_semicolon_is_not_the_lists_comma() {
        assert_ne!(LINK_PARAM_EMPTY.id, LIST_MEMBER_EMPTY.id);
        assert_ne!(
            LINK_PARAM_EMPTY.spec[0].spec,
            LIST_MEMBER_EMPTY.spec[0].spec
        );
    }
}
