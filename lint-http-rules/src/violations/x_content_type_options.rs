// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `X-Content-Type-Options` defects — the one value that turns sniffing off,
//! and the responses that do not carry it.
//!
//! The field has a single conformant value and a single effect, so the two
//! entries here are the only two things that can be wrong with it: a value
//! that is not `nosniff`, and no value at all.
//!
//! **Neither is a conformance finding**, and the entries rank apart for the
//! reason that follows from it. Nothing requires a server to send the field —
//! it is a defence a deployment opts into — so an absence is advice. A value
//! that is *not* `nosniff` is different: a server that wrote the field meant to
//! opt in, and did not.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field: its one conformant value, and the algorithm that reads it.
pub const FETCH_3_6: SpecRef = SpecRef {
    spec: "Fetch",
    section: Some("3.6"),
    url: "https://fetch.spec.whatwg.org/#x-content-type-options-header",
    note: "`X-Content-Type-Options`: the conformance value ABNF (`\"nosniff\" ; case-insensitive`) and the determine-nosniff algorithm",
};

defects! {
    /// The field is present and its value is not `nosniff`.
    ///
    /// **`_invalid` rather than `_malformed`**: the grammar admits one literal
    /// and the comparison is a case-insensitive match against it, so there is
    /// no production to break — a value that is not that literal is simply one
    /// the algorithm reads as "not nosniff" and moves past.
    ///
    /// `error`, from the production, which generates one value. The difference
    /// from the entry below is intent: a server that wrote this field meant to
    /// turn sniffing off, and has not — the deployment believes it has a
    /// protection it does not have.
    ///
    // cite(Fetch § 3.6): "X-Content-Type-Options = "nosniff" ; case-insensitive"
    X_CONTENT_TYPE_OPTIONS_INVALID = {
        id: "x_content_type_options_invalid",
        title: "X-Content-Type-Options carries a value that is not nosniff",
        message: "",
        default_severity: Severity::Error,
        spec: &[FETCH_3_6],
        strength: Strength::Grammar,
    }

    /// A response that does not carry the field at all.
    ///
    /// Nothing requires it: the field is a defence a deployment opts into, and
    /// a server that has never opted in is doing nothing wrong. What the
    /// finding says is that the recipient is left to check the `Content-Type`
    /// against the request's destination itself, or not to.
    ///
    /// `info`, with every other absence in this catalogue that no sentence
    /// asks about.
    ///
    // cite(Fetch § 3.6): "If values[0] is an ASCII case-insensitive match for "nosniff", then return true."
    X_CONTENT_TYPE_OPTIONS_MISSING = {
        id: "x_content_type_options_missing",
        title: "A response does not ask for its content type to be respected",
        message: "Missing X-Content-Type-Options: nosniff header",
        default_severity: Severity::Info,
        spec: &[FETCH_3_6],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server that wrote the field meant to opt in; a server that wrote
    /// nothing never did. That difference in intent is the whole ranking.
    #[test]
    fn the_field_written_wrong_outranks_the_field_not_written() {
        assert!(
            X_CONTENT_TYPE_OPTIONS_MISSING.default_severity
                < X_CONTENT_TYPE_OPTIONS_INVALID.default_severity
        );
    }
}
