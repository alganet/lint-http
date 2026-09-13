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

defects! {
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
    /// is the whole field — § 4.2 has a recipient ignore a field it cannot
    /// parse, so the members written correctly go with the one that was not —
    /// and that is more than any octet-level entry costs. It is still not the
    /// exchange: a request or a response missing a field it meant to send is
    /// answerable, so `error` would claim something the finding cannot show.
    ///
    // cite(RFC 9651 § 3.1.2): "Note that parameters are ordered, and parameter keys cannot contain uppercase letters."
    STRUCTURED_FIELD_KEY_MALFORMED = {
        id: "structured_field_key_malformed",
        title: "Structured field key is not a key production",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9651_4_2_3_3],
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
