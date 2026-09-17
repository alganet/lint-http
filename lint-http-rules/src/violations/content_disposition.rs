// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Content-Disposition` defects — what the field says past its parameters.
//!
//! Almost all of this field is borrowed and reports elsewhere: a parameter
//! name is a [`token`](crate::violations::token), a `filename` is a `token` or
//! a [`quoted_string`](crate::violations::quoted_string), a `filename*` is an
//! [`ext_value`](crate::violations::ext_value), and the halves a sender left
//! out are [`parameter`](crate::violations::parameter)'s. What is here is what
//! three documents say about the *set* of parameters and about two names it
//! inherited.
//!
//! **The entries sit either side of a line worth naming**: two quote a sentence
//! from a document in force, and two quote nothing — one because RFC 6266
//! deliberately dropped the parameter it is about, one because no document
//! refuses the value it reports.
//!
//! **The `name` pair is RFC 7578's requirement read at RFC 6266's position, and
//! the subject is still the field.** § 4.2 states its MUST about a *part* of a
//! `multipart/form-data` body, where this field is MIME's; what a linter with
//! no body parser can read is a message-level `Content-Disposition`. The day
//! one parses parts, it is the same field being read somewhere else — so the
//! entries are the field's, and only the position an operator sees them at
//! changes.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The `form-data` disposition's own requirement: the parameter that must be
/// there, and what its value is for.
pub const RFC_7578_4_2: SpecRef = SpecRef {
    spec: "RFC 7578",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc7578.html#section-4.2",
    note: "Each multipart/form-data *part* MUST contain a `Content-Disposition` header with disposition-type `form-data` and MUST also contain a `name` parameter — a requirement on parts, which this rule approximates at the message level",
};

/// The grammar, and the sentence about a parameter name written twice.
pub const RFC_6266_4_1: SpecRef = SpecRef {
    spec: "RFC 6266",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6266.html#section-4.1",
    note: "Grammar — `disposition-type *( \";\" disposition-parm )`, the `filename`/`filename*` pair, the `ext-token` convention, and the sentence declaring a value with two instances of one parameter name invalid",
};

defects! {
    /// A `Content-Disposition` naming the same parameter twice, matched
    /// case-insensitively and counting `filename` and `filename*` as the names
    /// they are written as.
    ///
    /// **The grammar does not forbid it and a sentence does**, which is the
    /// same shape `link_attribute_duplicated` has: `*( ";" disposition-parm )`
    /// repeats freely, and § 4.1 then says in one line that a value with
    /// multiple instances of one parameter name is invalid. So the finding is
    /// prose-based, and `_duplicated` is still the word an operator wants — it
    /// names what was written, not which layer refused it.
    ///
    /// `warn`: a recipient given two `filename`s has no rule telling it which
    /// to save under, and the document calls the whole value invalid rather
    /// than the second parameter.
    ///
    // cite(RFC 6266 § 4.1): "Content-Disposition header field values with multiple instances of the same parameter name are invalid."
    CONTENT_DISPOSITION_PARAMETER_DUPLICATED = {
        id: "content_disposition_parameter_duplicated",
        title: "Content-Disposition names one parameter twice",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6266_4_1],
    }

    /// A `size` parameter whose value is not a run of digits.
    ///
    /// **Uncited, and the reason is that the document defining this field for
    /// HTTP threw the parameter away.** RFC 6266 Appendix B lists `size`
    /// among the RFC 2183 parameters it omitted — "the majority of user agents
    /// do not implement these" — so under RFC 6266 a `size` is an ordinary
    /// `disp-ext-parm` whose value is a `token` or a `quoted-string`, and
    /// `size=abc` conforms to every sentence in force.
    ///
    /// What the check is about is the name's inherited meaning: a recipient
    /// that does implement RFC 2183's `size` reads a byte count, and a value
    /// that is not one tells it nothing. That is a judgement about deployed
    /// behaviour rather than about a requirement, so it carries no reference —
    /// the same footing as
    /// [`keep_alive_timeout_invalid`](crate::violations::keep_alive::KEEP_ALIVE_TIMEOUT_INVALID).
    ///
    /// `info`, which is where a finding lands when the document in force
    /// permits what it reports.
    CONTENT_DISPOSITION_SIZE_INVALID = {
        id: "content_disposition_size_invalid",
        title: "A Content-Disposition size parameter is not a number",
        message: "",
        default_severity: Severity::Info,
        spec: &[],
    }

    /// A `form-data` disposition carrying no `name` parameter at all — whether
    /// it carries no parameters or carries others.
    ///
    /// **The MUST is about the *set* of parameters, which is why the entry is
    /// the field's and not [`crate::violations::parameter`]'s.** That subject
    /// holds the two halves of a `name=value` a sender wrote short; this is a
    /// pair that was never written, and no production is short of anything —
    /// `*( ";" disposition-parm )` generates the value exactly as it stands.
    ///
    /// **Not reported when the quoting never closes**, which is the rule's
    /// judgement and worth keeping beside the entry: after a stray DQUOTE no
    /// separator past it is a separator, so a value that plainly carries a
    /// `name` was announced as missing one. The gate applies to *absence*
    /// alone — whether that text is a parameter is exactly what the broken
    /// quoting makes unknowable — and a `name` the scan did find is judged
    /// either way.
    ///
    /// `error`: § 4.2 says the field MUST also carry a `name` parameter. A
    /// receiving application has nothing to associate the part's data with, so
    /// the data arrives and belongs to no field of the form.
    ///
    // cite(RFC 7578 § 4.2): "The Content-Disposition header field MUST also contain an additional parameter of "name"; the value of the "name" parameter is the original field name from the form"
    CONTENT_DISPOSITION_NAME_MISSING = {
        id: "content_disposition_name_missing",
        title: "A form-data Content-Disposition names no form field",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7578_4_2],
        strength: Strength::Must,
    }

    /// A `name` parameter written as a pair of DQUOTEs around nothing:
    /// `form-data; name=""`.
    ///
    /// **Uncited, and the production is why.** `""` is the `quoted-string`
    /// § 5.6.4 writes, satisfied exactly, carrying a form field name of
    /// nothing; § 4.2 spends its MUST on the parameter being *there* and then
    /// *defines* what the value is rather than constraining it. So no sentence
    /// refuses this value, and what does is this crate reading the definition
    /// as a purpose — a name is what a receiving application associates the
    /// data with, and nothing associates nothing.
    ///
    /// **Level with [`CONTENT_DISPOSITION_NAME_MISSING`] and deliberately not
    /// below it**, though the usual rule is that an entry standing on a reading
    /// does not outrank one standing on a document. It does not outrank it — it
    /// ranks *with* it, because the receiving application is in the same
    /// position either way, and saying a name of nothing is milder than no name
    /// would describe the documents rather than the form.
    ///
    /// **The unquoted spelling is a different entry and that is not an
    /// inconsistency.** `name=` with nothing after it derives from no
    /// production at all, which is
    /// [`crate::violations::parameter::PARAMETER_VALUE_EMPTY`] — one sentence
    /// for every `name=value` in HTTP. Here the grammar is satisfied and only
    /// the purpose is not, so the two spellings genuinely fail in two places.
    CONTENT_DISPOSITION_NAME_EMPTY = {
        id: "content_disposition_name_empty",
        title: "A form-data Content-Disposition names an empty form field",
        message: "",
        default_severity: Severity::Error,
        spec: &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line the subject is built on: one entry quotes the document that
    /// defines this field for HTTP, the other quotes nothing because that
    /// document dropped the parameter it is about.
    #[test]
    fn only_the_parameter_the_document_kept_carries_a_reference() {
        assert!(!CONTENT_DISPOSITION_PARAMETER_DUPLICATED.spec.is_empty());
        assert!(CONTENT_DISPOSITION_SIZE_INVALID.spec.is_empty());
        assert!(
            CONTENT_DISPOSITION_SIZE_INVALID.default_severity
                < CONTENT_DISPOSITION_PARAMETER_DUPLICATED.default_severity
        );
    }

    /// The `name` pair's argument, asserted: the uncited entry ranks *with* its
    /// cited sibling rather than below it, because a receiving application is
    /// in the same position for both. The rule elsewhere in this catalogue —
    /// that a reading does not outrank a document — is satisfied by "not
    /// above", and this is the entry that shows the difference.
    #[test]
    fn the_two_ways_to_name_no_form_field_rank_together() {
        assert!(!CONTENT_DISPOSITION_NAME_MISSING.spec.is_empty());
        assert!(CONTENT_DISPOSITION_NAME_EMPTY.spec.is_empty());
        assert_eq!(
            CONTENT_DISPOSITION_NAME_EMPTY.default_severity,
            CONTENT_DISPOSITION_NAME_MISSING.default_severity
        );
    }
}
