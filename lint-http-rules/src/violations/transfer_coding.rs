// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `transfer-coding` defects — the name of a transformation applied to a
//! message, and what may be hung off it.
//!
//! The production is `token *( OWS ";" OWS transfer-parameter )`, read from two
//! fields: `Transfer-Encoding`, which states what a sender applied, and `TE`,
//! which states what a client will accept. Its name half is a `token` and its
//! parameters are `parameter`s, so a mangled octet or a missing `=` answers
//! under those subjects — what is left here is which names exist and which of
//! them may carry anything at all.
//!
//! **The mirror of [`content_coding`](crate::violations::content_coding), with
//! one asymmetry worth keeping in view.** There the two fields differ in
//! *vocabulary* — `*` and `identity` are words one field has and the other does
//! not — so the entries live on the production. Here the two fields differ in
//! what they may say about a name they both have: `chunked` is a real transfer
//! coding, perfectly ordinary in `Transfer-Encoding`, and forbidden in `TE`
//! because a client cannot decline it. **That is a defect of the field and not
//! of the coding**, so it lives in [`crate::violations::te`] and not here.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;
use crate::violations::te::RFC_9110_A;

/// Where the coding names are registered, and the sentence making them
/// case-insensitive and asking that they be registered at all.
pub const RFC_9112_7: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("7"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7",
    note: "Transfer Codings — names are case-insensitive and ought to be registered; §7.3 puts registration behind IETF Review, which is why an unrecognised name is a configuration question",
};

/// The compression codings, defined by the algorithm of the content coding of
/// the same name — and defining no parameters of their own.
pub const RFC_9112_7_2: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("7.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7.2",
    note: "The compression transfer codings, and the sentence saying they define no parameters and that a parameter's presence SHOULD be treated as an error",
};

defects! {
    /// A `;` written with nothing after it. The repetition prints the
    /// delimiter and a `transfer-parameter` together — `*( OWS ";" OWS
    /// transfer-parameter )` brackets neither half — so a member ending in a
    /// semicolon, or holding two in a row, generates no `transfer-coding` at
    /// all.
    ///
    /// **This is where the production differs from `parameters`**, and it is
    /// the reason the defect exists here rather than under
    /// [`parameter`](crate::violations::parameter): § 5.6.6 writes
    /// `*( OWS ";" OWS [ parameter ] )`, whose brackets make `text/plain;` a
    /// conforming zero-parameter repetition. The same three characters are a
    /// defect after a coding name and are not one after a media type.
    ///
    /// The production is written inside `TE`'s section, and RFC 9112 § 7 says
    /// so in as many words — which is why a defect of `Transfer-Encoding`'s
    /// grammar quotes a sentence from a field it does not use.
    ///
    // cite(RFC 9110 § A, label: transfer-coding): "transfer-coding = token *( OWS ";" OWS transfer-parameter )"
    TRANSFER_CODING_PARAMETER_MISSING = {
        id: "transfer_coding_parameter_missing",
        title: "A coding writes a ';' with no parameter after it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_A],
    }

    /// A parameter hung off a coding that defines none. § 7.2 says so of the
    /// five compression codings in one sentence and § 7.1 says it of `chunked`
    /// in two, so the six that this crate can check are covered; a coding an
    /// operator adds to the allowed list answers to whatever registered it.
    ///
    /// The exception is `TE`'s `q`, and it is an exception of the *grammar*
    /// rather than a tolerance: § 10.1.4 puts the `weight` outside
    /// `transfer-coding` and § 7.3 calls it a pseudo-parameter, so `q` there is
    /// not a parameter of the coding at all. `Transfer-Encoding` has no weight
    /// in its grammar, so a `q` written there is an ordinary parameter and is
    /// reported like any other.
    ///
    // cite(RFC 9112 § 7.2): "The compression codings do not define any parameters."
    // cite(RFC 9112 § 7.2): "The presence of parameters with any of these compression codings SHOULD be treated as an error."
    TRANSFER_CODING_PARAMETER_FORBIDDEN = {
        id: "transfer_coding_parameter_forbidden",
        title: "A coding that defines no parameters carries one",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9112_7_2],
    }

    /// A coding name the deployment does not recognise — the fifth registry
    /// entry of the catalogue, and the one whose sentence is weakest: § 7 says
    /// names *ought to* be registered, which is neither a MUST nor a SHOULD.
    ///
    /// What gives the finding its point is not disobedience but consequence: a
    /// recipient meeting a coding it does not understand cannot frame or decode
    /// the message, and § 6.1 tells a server to answer `501 (Not Implemented)`.
    /// The comparison is against the operator's `allowed` list, matched
    /// case-insensitively, and never against the registry — § 7.3 puts
    /// registration behind IETF Review, which no linter stands in for.
    ///
    // cite(RFC 9112 § 7, label: transfer-coding names): "All transfer-coding names are case-insensitive and ought to be registered within the HTTP Transfer Coding registry, as defined in Section 7.3."
    TRANSFER_CODING_UNREGISTERED = {
        id: "transfer_coding_unregistered",
        title: "Transfer coding is not one the deployment recognises",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9112_7],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Neither entry is spelled for a field: both `Transfer-Encoding` and `TE`
    /// carry this production, and a coding that defines no parameters defines
    /// none in either of them. The entry that *is* field-specific is `TE`'s,
    /// and it is deliberately in another file.
    #[test]
    fn no_entry_here_is_spelled_for_one_of_the_two_fields() {
        for def in [
            &TRANSFER_CODING_PARAMETER_FORBIDDEN,
            &TRANSFER_CODING_UNREGISTERED,
        ] {
            assert!(def.id.starts_with("transfer_coding_"), "{}", def.id);
            assert!(!def.id.contains("_te_"), "{}", def.id);
            assert!(!def.id.contains("encoding"), "{}", def.id);
        }
    }
}
