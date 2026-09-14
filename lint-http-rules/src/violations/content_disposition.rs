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
//! RFC 6266 says about the *set* of parameters and about one name it inherited.
//!
//! **The two entries sit either side of a line worth naming**: one quotes a
//! sentence from the document that defines this field for HTTP, and the other
//! quotes nothing because that document deliberately dropped the parameter it
//! is about.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

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
}
