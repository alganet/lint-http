// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `charset` defects — the name that says which character encoding scheme a
//! textual representation was written in.
//!
//! A charset name is not a production of its own in RFC 9110: § 8.3.2 says it
//! appears *"either in parameters (Content-Type), or, for Accept-Encoding, in
//! the form of a plain token"*, so the carrier's grammar has already been
//! measured by the time these entries are reached — a `parameter` that is
//! missing its `=`, a `quoted-string` that never closes, an octet no `token`
//! admits, all answer under those subjects. **What is left is the name.**
//!
//! Which is exactly the distinction the empty entry below exists for, and it
//! was written down in `charset_registered` before there was anywhere to put
//! it: `charset=""` is a *well-formed* `parameter` whose value is a
//! *well-formed* `quoted-string`, and the thing that is empty is the charset
//! name inside it. Under § 5.6.6 nothing is wrong; under § 8.3.2 the
//! representation states no encoding at all.
//!
//! The third registry entry of the catalogue, after
//! [`auth_scheme_unregistered`](crate::violations::auth_scheme::AUTH_SCHEME_UNREGISTERED)
//! and
//! [`media_type_unregistered`](crate::violations::media_type::MEDIA_TYPE_UNREGISTERED),
//! and the same shape as both: an *ought to* addressed to whoever defines the
//! name, measured against a list the operator wrote.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Where a charset name appears, how it is matched, and the registry it ought
/// to be in.
pub const RFC_9110_8_3_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2",
    note: "Charset: what the parameter means, that names are matched case-insensitively, and the \"ought to be registered\" guidance that motivates this rule — guidance, not a requirement, and not something this rule verifies",
};

defects! {
    /// A charset parameter carrying no name: `charset=""`. The parameter is
    /// there, the quoting is closed, and the representation still says nothing
    /// about how its characters are encoded — which is worse than omitting the
    /// parameter, because a recipient reading the field sees an answer.
    ///
    // cite(RFC 9110 § 8.3.2): "In the fields defined by this document, charset names appear either in parameters (Content-Type), or, for Accept-Encoding, in the form of a plain token."
    CHARSET_EMPTY = {
        id: "charset_empty",
        title: "Charset parameter carries no name",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_8_3_2),
    }

    /// A charset name the deployment does not recognise. Matched
    /// case-insensitively, because that is how § 8.3.2 says charset names are
    /// matched, and against the operator's `allowed` list rather than IANA's
    /// table — the stand-in the other two registry entries make, for the same
    /// reason: this crate carries no snapshot of a registry it cannot keep
    /// current.
    ///
    /// `warn`. The consequence of an unknown name is a recipient guessing at
    /// the encoding, which is a decoding risk rather than a malformed message.
    ///
    // cite(RFC 9110 § 8.3.2): "Charset names ought to be registered in the IANA "Character Sets" registry (<https://www.iana.org/assignments/character-sets>) according to the procedures defined in Section 2 of [RFC2978]."
    CHARSET_UNREGISTERED = {
        id: "charset_unregistered",
        title: "Charset name is not one the deployment recognises",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_8_3_2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two entries that look like one finding. The empty name reaches its own
    /// id rather than `parameter_value_empty`, because `charset=""` has a
    /// perfectly good parameter value — the emptiness is one level in.
    #[test]
    fn the_empty_name_is_not_the_empty_parameter_value() {
        assert_eq!(CHARSET_EMPTY.id, "charset_empty");
        assert_ne!(CHARSET_EMPTY.id, "parameter_value_empty");
        assert_eq!(CHARSET_EMPTY.spec, Some(RFC_9110_8_3_2));
        assert_eq!(CHARSET_UNREGISTERED.spec, Some(RFC_9110_8_3_2));
    }
}
