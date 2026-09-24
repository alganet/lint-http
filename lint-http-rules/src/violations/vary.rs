// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Vary` defects — the dimensions a cache key was told to carry.
//!
//! The field names the request fields a stored response was selected on, and
//! RFC 9111 § 4.1 makes reuse conditional on all of them matching. What a proxy
//! watching the exchanges can say about that is on the *sending* side: a
//! response whose selection depended on a request field it does not name.
//!
//! **Whether a cache honoured the field is not here, and cannot be.** A request
//! that reaches the wire is one no cache answered, and one that revalidates a
//! stored response under a request whose selecting fields differ is § 4.3.1's
//! permission — "a cache is allowed to validate a response that it cannot choose
//! with the request header fields it is sending" — rather than a breach of it.
//!
//! **What the *value* may be is not here either.** `Vary = #field-name` is
//! `vary_header_valid`'s, over [`list`](crate::violations::list) and
//! [`token`](crate::violations::token), and a `Vary: *` beside a directive
//! advertising reuse is [`cache_control`](crate::violations::cache_control)'s —
//! the field whose statement that pairing kills.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Preferences and caching: the MUST that puts `Prefer` in a `Vary` whenever a
/// preference could change what a cache holds.
pub const RFC_7240_2: SpecRef = SpecRef {
    spec: "RFC 7240",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-2",
    note: "The `Vary` MUST for a server that applies a preference which might vary a cache's handling of the response entity, and the `Vary: *` alternative it offers instead",
};

defects! {
    /// A response saying it applied a preference that changes what the entity
    /// is, without nominating `Prefer` in its `Vary`.
    ///
    /// **The subject is `Vary` and not `Prefer`, because the MUST is addressed
    /// to the `Vary`**: RFC 7240 § 2 tells a server that supports such a
    /// preference to list the `Prefer` field in the response's `Vary`
    /// *regardless of whether the client used it*, so what is absent is a
    /// dimension of the cache key rather than anything about the preference.
    /// The pairing rule this catalogue already follows — the subject is
    /// whichever field the requirement is addressed to — decides it.
    ///
    /// **`Vary: *` satisfies it and so does nothing else.** § 2 offers that
    /// alternative by name, and it works because a `*` makes the response
    /// unreusable rather than because it names the field.
    ///
    /// `error`: § 2 says a `Vary` listing `Prefer` MUST be included, whether or
    /// not the client used the field. Every message involved is well formed and
    /// the exchange that produced the finding was answered correctly; what is
    /// wrong is that a later request can be answered from this response when it
    /// should not be.
    ///
    // cite(RFC 7240 § 2): "If a server supports the optional application of a preference that might result in a variance to a cache's handling of a response entity, a Vary header field MUST be included in the response listing the Prefer header field regardless of whether the client actually used Prefer in the request."
    VARY_PREFER_MISSING = {
        id: "vary_prefer_missing",
        title: "A response applied a preference its Vary does not nominate",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7240_2],
        strength: Strength::Must,
    }
}
