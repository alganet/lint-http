// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Structured Fields defects — the productions RFC 9651 defines for every
//! field written in it.
//!
//! This is a subject of the same kind as [`token`](crate::violations::token)
//! and [`quoted_string`](crate::violations::quoted_string): nothing here
//! belongs to a field, and every entry answers for whichever field imported the
//! production. What makes it worth opening is that a Structured Field's
//! grammar is *shared by construction* — a document that says "this field is a
//! Dictionary" has said everything about its shape, and what is left for the
//! field to state is what its keys mean and what its values must be.
//!
//! **A parse failure costs the field, not the member.** RFC 9651 gives a
//! recipient two answers and no third: ignore the whole field value as though
//! it were not in the section, or treat the entire message as malformed. So a
//! single bad key does not degrade a Dictionary — it deletes it, together with
//! every member the sender wrote correctly, and the strict reading is worse
//! than that. That is what the entry below ranks on, and it is why the finding
//! is worth making at all where a lenient parser would have found the other
//! members.
//
// cite(RFC 9651 § 4.2): "If parsing fails, either the entire field value MUST be ignored (i.e., treated as if the field were not present in the section), or alternatively the complete HTTP message MUST be treated as malformed."

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The `key` production, and the parsing algorithm that reads one.
pub const RFC_9651_4_2_3_3: SpecRef = SpecRef {
    spec: "RFC 9651",
    section: Some("4.2.3.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.3",
    note: "Parsing a Key: a `key` opens with `lcalpha` or `*` and continues with `lcalpha`, DIGIT, `_`, `-`, `.` or `*` — the production every Dictionary member name and every parameter name is written in, and the one an uppercase letter fails",
};

/// Parsing a Dictionary: the loop that reads member after member, and the two
/// steps a comma with nothing beside it fails.
pub const RFC_9651_4_2_2: SpecRef = SpecRef {
    spec: "RFC 9651",
    section: Some("4.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.2",
    note: "Parsing a Dictionary: a member is a key and, optionally, an `=` and a value — a bare key carries the Boolean true rather than being a member without one — and the loop fails on a comma with nothing after it",
};

/// The parsing algorithm every Structured Field is read by: the byte
/// conversion that precedes any type, the MUST to join a field's lines before
/// running it, and the discard rule that makes one failure cost the whole
/// field.
pub const RFC_9651_4_2: SpecRef = SpecRef {
    spec: "RFC 9651",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2",
    note: "Parsing — the algorithm a recipient runs over a joined field value, the `field_type` it is given, the ASCII conversion it does before choosing one, and the two answers it offers when parsing fails",
};

defects! {
    /// An octet at or above %x80 anywhere in the field value — a name or a
    /// word written in something other than US-ASCII and handed to a field
    /// that has no room for one.
    ///
    /// **The one failure a reader can name without knowing the field's type.**
    /// § 4.2 is given a `field_type` and chooses an algorithm from it, but the
    /// conversion to ASCII happens before that choice and fails for all three
    /// alike — so a rule pointed at a field whose Structured Type it does not
    /// know can still say this much, where everything past it can only say
    /// that nothing parsed.
    ///
    /// **`_character_forbidden`, the second half of the pair, and there is no
    /// first half here.** A control octet is the other spelling wherever a
    /// subject splits the octets nobody typed from the ones a sender chose,
    /// and this catalogue reaches a Structured Field through
    /// `HeaderValue::to_str`, which refuses %x00–%x1F and %x7F before any rule
    /// sees them. What arrives is the sender's own text in the sender's own
    /// encoding, which is exactly what this half is for.
    ///
    /// `warn`, with the rest of the subject: what it costs is the field.
    ///
    // cite(RFC 9651 § 4.2): "Convert input_bytes into an ASCII string input_string; if conversion fails, fail parsing."
    STRUCTURED_FIELD_CHARACTER_FORBIDDEN = {
        id: "structured_field_character_forbidden",
        title: "Structured field holds an octet outside US-ASCII",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9651_4_2],
    }

    /// A Dictionary written with a comma and no member beside it:
    /// `a=1,,b=2`, or a value ending on its separator.
    ///
    /// The parsing loop fails twice over: a trailing comma is named in a step
    /// of its own, and a comma in the middle leaves the *next* iteration
    /// reading a key that does not start where a key starts. **One entry,
    /// because what the sender wrote is one thing** — a separator with nothing
    /// to separate — and because the outcome is identical: the field is not
    /// parsed, so it is not there.
    ///
    /// **This is not [`list_member_empty`](crate::violations::list).** That
    /// entry carries RFC 9110 § 5.6.1.1's requirement on a sender writing a
    /// `#rule` list, and a Dictionary is not a list construct: it has no
    /// `#element` expansion to generate a null element and no leniency to
    /// spend. The two look alike on the wire and answer to different documents.
    ///
    /// `warn`, with the key: what it costs is the field.
    ///
    // cite(RFC 9651 § 4.2.2): "If input_string is empty, there is a trailing comma; fail parsing."
    STRUCTURED_FIELD_MEMBER_EMPTY = {
        id: "structured_field_member_empty",
        title: "Structured field writes a comma with no member beside it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9651_4_2_2],
    }

    /// One Dictionary key written twice in one field: `u=1, u=5`.
    ///
    /// **Not a parse failure, and that is what makes it worth saying.** § 4.2.2
    /// resolves the collision silently in favour of the last member, so the
    /// field parses, the recipient acts on one value, and the header still
    /// reads as though it said both things. The earlier member is dead text
    /// nobody will see, and nothing on the wire marks it as such.
    ///
    /// **`_duplicated` against a grammar that permits the repetition.** Every
    /// other entry with this ending stands on a sentence forbidding the second
    /// occurrence — `link_rel_duplicated` on RFC 8288's MUST NOT, and
    /// `strict_transport_security_directive_duplicated` on § 6.1's *appear only
    /// once* — and RFC 9651 writes no such prohibition. What it writes is the
    /// resolution, and the ending still holds: the *parsed* Dictionary carries
    /// one member per key, so a key written twice appears more times than the
    /// structure can hold, whatever the serialization admits.
    ///
    /// **The keys are compared byte for byte**, which § 4.2.2 says outright and
    /// which the `key` production makes moot anyway — there is no case to fold.
    ///
    /// `warn`, with `link_rel_duplicated`: what is lost is one member of the
    /// field rather than the field.
    ///
    // cite(RFC 9651 § 4.2.2): "Note that when duplicate Dictionary keys are encountered, all but the last instance are ignored."
    STRUCTURED_FIELD_KEY_DUPLICATED = {
        id: "structured_field_key_duplicated",
        title: "Structured field gives one Dictionary key more than once",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9651_4_2_2],
    }

    /// A Dictionary member name or a parameter name that is not a `key`:
    /// `SHA-256`, `Report-To`, `2fa`.
    ///
    /// **The uppercase letter is the case worth knowing**, because it is the
    /// one a working deployment produces. A field defined in RFC 9651 that
    /// replaces an older `token`-based one inherits the older field's registry
    /// spellings, and those registries are full of names like `SHA-256` and
    /// `MD5`; carried across unchanged they make a field no structured-field
    /// parser will read. A `key` has no uppercase in it at all — § 3.1.2 says
    /// so in a note, in as many words — so this is not a value that will be
    /// matched case-insensitively somewhere later.
    ///
    /// `_malformed`: the name derives from no `key`, which is a grammar
    /// failure and not a name outside some registry.
    ///
    /// **`warn`, and the ceiling is what keeps it there.** What a bad key costs
    /// is the whole field — § 4.2 offers a recipient the choice of ignoring the
    /// field value entirely or treating the message as malformed, so the
    /// members written correctly go with the one that was not — and that is
    /// more than any octet-level entry costs. The lenient answer is the one
    /// deployments take, and under it a request or a response missing a field
    /// it meant to send is still answerable, so `error` would claim something
    /// the finding cannot show.
    ///
    // cite(RFC 9651 § 3.1.2): "Note that parameters are ordered, and parameter keys cannot contain uppercase letters."
    STRUCTURED_FIELD_KEY_MALFORMED = {
        id: "structured_field_key_malformed",
        title: "Structured field key is not a key production",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9651_4_2_3_3],
    }

    /// A field value that derives from no Structured Fields type at all: not
    /// an Item, not a List, not a Dictionary.
    ///
    /// **The coarse entry, and it is what a reader that does not know the
    /// field's type is left with.** § 4.2 takes a `field_type` and nothing on
    /// the wire carries one: the registry publishes a Structured Type column
    /// for the fields that have been given one, and a rule pointed at a bare
    /// field name has only the value. Such a reader can try all three and
    /// report that none of them parsed; it cannot say *which* member, because
    /// naming one would be naming a type the field may well not have been
    /// defined as.
    ///
    /// **So it sits beside the finer entries rather than instead of them.**
    /// A rule that knows the field is a Dictionary reports
    /// [`STRUCTURED_FIELD_KEY_MALFORMED`] or
    /// [`STRUCTURED_FIELD_MEMBER_EMPTY`] for the same octets and says more
    /// while doing it — the shape [`base64`](crate::violations::base64)
    /// settled, where a coarse entry and the three that name a specific
    /// failure all belong to one production.
    ///
    /// `warn`, with the rest of the subject: what it costs is the field.
    ///
    // cite(RFC 9651 § 4.2): "If parsing fails, either the entire field value MUST be ignored (i.e., treated as if the field were not present in the section), or alternatively the complete HTTP message MUST be treated as malformed."
    STRUCTURED_FIELD_MALFORMED = {
        id: "structured_field_malformed",
        title: "Structured field value derives from no structured type",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9651_4_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry is the production's rather than any field's, which is what
    /// lets two documents' fields report it with one id — and the rank is the
    /// subject's, argued from what a parse failure costs.
    #[test]
    fn the_key_entry_belongs_to_the_production() {
        assert_eq!(STRUCTURED_FIELD_KEY_MALFORMED.spec, [RFC_9651_4_2_3_3]);
        assert_eq!(
            STRUCTURED_FIELD_KEY_MALFORMED.default_severity,
            Severity::Warn
        );
    }
}
