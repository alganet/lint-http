// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `media-type` defects — what a type/subtype pair can be wrong about once it
//! is well formed.
//!
//! The grammar half of this production is already spoken for and deliberately
//! not here: a `media-type` is `type "/" subtype parameters`, all of it built
//! from `token`, `parameter` and `quoted-string`, so a malformed one answers
//! under those subjects wherever it is read — `Content-Type`, `Accept`,
//! `Accept-Patch`, a multipart body's part. What is left over is the pair
//! *itself*: two well-formed tokens naming something.
//!
//! Which is why the one entry below is a registry entry, and why it is the
//! second of that shape after
//! [`auth_scheme_unregistered`](crate::violations::auth_scheme::AUTH_SCHEME_UNREGISTERED).
//! Both are an `ought to` addressed to whoever defines the name, measured
//! against a list the operator wrote — and in both cases naming the id after
//! the sentence rather than after the list is what keeps an operator's
//! configuration meaningful when the list changes.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The production, the case-insensitivity of its two tokens, and the
/// registration guidance the entry below carries.
pub const RFC_9110_8_3_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1",
    note: "`media-type` syntax, the case-insensitivity of its tokens, and the \"ought to be registered with IANA\" guidance that motivates this rule — guidance, not a requirement, and not something this rule verifies",
};

defects! {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry carries the registration sentence and not the suffix one.
    /// Before it existed, the finding cited RFC 6838 § 4.2.8 — the sentence
    /// defining `+json` as a structured syntax suffix, which is how one
    /// *allowlist entry* is matched and says nothing about whether a type is
    /// registered.
    #[test]
    fn the_entry_quotes_the_registration_sentence() {
        assert_eq!(MEDIA_TYPE_UNREGISTERED.spec, Some(RFC_9110_8_3_1));
        assert_eq!(
            MEDIA_TYPE_UNREGISTERED.spec.map(|s| s.spec),
            Some("RFC 9110")
        );
    }
}
