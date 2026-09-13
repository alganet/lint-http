// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Digest defects — what a member of a digest field says about the bytes it
//! stands for.
//!
//! One subject over two generations of fields, because the thing they carry is
//! one thing: an algorithm and the digest it produced. RFC 3230 wrote it as a
//! `#rule` of `token "=" <encoded digest>`; RFC 9530 obsoleted that and wrote
//! the same pairing as a Structured Field Dictionary, whose keys are
//! [`structured_fields`](crate::violations::structured_fields)' `key` and whose
//! values are Byte Sequences and Integers. **What is shared is the claim, not
//! the grammar**, so an entry here names the generation's sentence where one
//! exists and the message names the field.
//!
//! **The encoding is [`base64`](crate::violations::base64)'s in both
//! generations**, and neither document restates a character of it — a digest
//! that does not decode is the same defect a mangled `Sec-WebSocket-Key` is,
//! which is exactly what that subject was opened for.
//!
//! **One entry is uncited and it is the interesting one.** A digest of no bytes
//! — the legacy `sha-256=` and the structured `sha-256=::` — is well formed in
//! both documents: `::` is a Byte Sequence carrying zero octets, and RFC 3230
//! bounds its encoded output nowhere. Neither document says a digest must
//! identify something, so what refuses it is this crate's reading and the entry
//! carries no reference.
//
// cite(RFC 9530 § 2, label: content-digest dictionary): "It is a Dictionary (see Section 3.2 of [STRUCTURED-FIELDS]), where each:"

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// `Content-Digest` and `Repr-Digest`: what a member's two halves must be.
/// The two fields differ in *what* is hashed and not in syntax, so one section
/// answers for both.
pub const RFC_9530_2: SpecRef = SpecRef {
    spec: "RFC 9530",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc9530.html#section-2",
    note:
        "`Content-Digest`: a Dictionary keyed by hashing algorithm whose values are Byte Sequences",
};

/// `Want-Content-Digest` and `Want-Repr-Digest`: the same Dictionary with a
/// weight where the digest goes.
pub const RFC_9530_4: SpecRef = SpecRef {
    spec: "RFC 9530",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc9530.html#section-4",
    note: "`Want-Content-Digest` / `Want-Repr-Digest`: a Dictionary whose values are Integers in the range 0 to 10 inclusive",
};

defects! {
    /// A digest field member whose value is not a Byte Sequence:
    /// `Content-Digest: sha-256=YWJj`, where the `:` delimiters are missing.
    ///
    /// The delimiters are the type. Without them the value parses as a Token
    /// or a String or nothing at all, and § 2 says what a member's value *is*
    /// — so a recipient reading this field against its definition finds a
    /// member it cannot use, whatever a permissive parser would have made of
    /// the characters.
    ///
    /// **The spelling this catches is the one a migration produces**: RFC
    /// 3230's `Digest` carried bare base64 with no delimiters at all, so a
    /// deployment that renamed the field and kept the value writes exactly
    /// this.
    ///
    /// `warn`, with the rest of the subject: a field a recipient discards is
    /// an integrity check that silently did not happen, and it is not the
    /// exchange.
    ///
    // cite(RFC 9530 § 2): "value is a Byte Sequence (Section 3.3.5 of [STRUCTURED-FIELDS]) that conveys an encoded version of the byte output produced by the digest calculation."
    DIGEST_VALUE_MALFORMED = {
        id: "digest_value_malformed",
        title: "Digest field member's value is not a Byte Sequence",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9530_2],
    }

    /// A member that names an algorithm and carries no digest: the legacy
    /// `Digest: sha-256=` and the structured `Content-Digest: sha-256=::`.
    ///
    /// **One entry for both generations, and it is uncited in both.** `::` is a
    /// Byte Sequence carrying zero octets and derives perfectly; RFC 3230
    /// bounds its encoded output nowhere. Neither document says that a digest
    /// must identify something, so what refuses this is the reading that a
    /// digest of no bytes distinguishes no content from any other — this
    /// crate's, which is the first of the three reasons an entry carries no
    /// reference.
    ///
    /// The two spellings are one defect because the sender's mistake is one
    /// mistake — a hash that was never computed, or a variable that was empty
    /// when the field was written — and the fix is the same in both.
    ///
    /// `warn`. What it costs is the whole point of the field: a recipient can
    /// compare its own digest against nothing.
    DIGEST_VALUE_EMPTY = {
        id: "digest_value_empty",
        title: "Digest field member carries no digest",
        message: "",
        default_severity: Severity::Warn,
        spec: &[],
    }

    /// A `Want-*` weight that is not an Integer: `sha-256=1.5`, `sha-256=high`.
    ///
    /// § 4 gives the value a type, and a Dictionary value that is not of the
    /// type the field defines is a member a recipient cannot read. **Separate
    /// from [`DIGEST_PREFERENCE_INVALID`] because the two fail at different
    /// levels**: this one derives from no Integer, so a parser stops here and
    /// the field goes with it, where a weight of `11` parses and is refused by
    /// the sentence beside the type.
    ///
    /// `warn`, with the other entry that costs the field.
    ///
    // cite(RFC 9530 § 4, label: want-digest preference type): "value is an Integer (Section 3.3.1 of [STRUCTURED-FIELDS]) that conveys an ascending, relative, weighted preference. It must be in the range 0 to 10 inclusive."
    DIGEST_PREFERENCE_MALFORMED = {
        id: "digest_preference_malformed",
        title: "Want-Digest preference is not an Integer",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9530_4],
    }

    /// A `Want-*` weight outside 0 to 10: `sha-256=11`, `sha-256=-1`.
    ///
    /// Every octet is an Integer's and the field parses; what the value fails
    /// is the range written in the same sentence that gives it its type. That
    /// is `_invalid` exactly — grammatical, refused past the grammar.
    ///
    /// **`info`, alone in this subject, and the reason is that nothing is
    /// lost.** A preference is an ordering: a recipient reading `11` beside a
    /// `5` learns which algorithm the sender would rather have, which is the
    /// whole content of the member. The field is not discarded, no digest is
    /// unreadable, and what the sender wrote is still usable for the purpose it
    /// was written for.
    ///
    // cite(RFC 9530 § 4): "value is an Integer (Section 3.3.1 of [STRUCTURED-FIELDS]) that conveys an ascending, relative, weighted preference. It must be in the range 0 to 10 inclusive."
    DIGEST_PREFERENCE_INVALID = {
        id: "digest_preference_invalid",
        title: "Want-Digest preference is outside the range 0 to 10",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9530_4],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry with no sentence, and why it may not gain one: both documents
    /// derive a digest of no bytes without a word against it.
    #[test]
    fn the_digest_of_nothing_states_no_sentence() {
        assert!(DIGEST_VALUE_EMPTY.spec.is_empty());
    }

    /// The two halves of § 4's one sentence are two entries, split by the
    /// vocabulary rather than by the wording: a value deriving from no Integer
    /// and a value deriving from one and refused past it.
    #[test]
    fn the_preference_fails_at_two_levels_under_one_sentence() {
        assert_eq!(DIGEST_PREFERENCE_MALFORMED.spec, [RFC_9530_4]);
        assert_eq!(DIGEST_PREFERENCE_INVALID.spec, [RFC_9530_4]);
        assert_ne!(DIGEST_PREFERENCE_MALFORMED.id, DIGEST_PREFERENCE_INVALID.id);
        // And they rank apart for the same reason they split: one costs the
        // field, the other costs nothing a recipient was going to use.
        assert!(
            DIGEST_PREFERENCE_INVALID.default_severity
                < DIGEST_PREFERENCE_MALFORMED.default_severity
        );
    }
}
