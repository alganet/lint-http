// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Vary` defects — the dimensions a cache key was told to carry.
//!
//! The field names the request fields a stored response was selected on, and
//! § 4.1 makes reuse conditional on all of them matching. What is here is the
//! one thing a proxy watching an exchange can say about that: a stored response
//! came back for a request that differs in a field the response itself
//! nominated.
//!
//! **What the *value* may be is not here.** `Vary = #field-name` is
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

/// Calculating Cache Keys with the Vary Header Field: what all the nominated
/// fields matching buys, and what their not matching forbids.
pub const RFC_9111_4_1: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1",
    note: "Calculating Cache Keys with the Vary Header Field — a stored response may only be reused without revalidation where every request field the response nominated matches the original request's",
};

defects! {
    /// A stored response reused for a request that differs in a field its own
    /// `Vary` nominated.
    ///
    /// **`_ignored` is the ending**: the response stated the dimensions its
    /// selection depends on, correctly, and something reused it across one of
    /// them. That is a requirement honoured by nobody rather than stated
    /// wrongly — the same reading
    /// [`http3_goaway_ignored`](crate::violations::http3_goaway) is on, at a
    /// field instead of a frame.
    ///
    /// **The comparison is stricter than § 4.1's** and the direction is
    /// deliberate: the section's "match" additionally permits whitespace,
    /// line-combining and semantic normalization, none of which is applied
    /// here, so this can report a pair that § 4.1 would call matching. An
    /// over-report, chosen because the alternative is to guess which
    /// normalization a particular cache implements.
    ///
    // cite(RFC 9111 § 4.1): "the cache MUST NOT use that stored response without revalidation unless all the presented request header fields nominated by that Vary field value match those fields in the original request"
    VARY_IGNORED = {
        id: "vary_ignored",
        title: "A response is reused across a dimension its Vary nominated",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_4_1],
        strength: Strength::Unstated,
    }

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
    /// **The other entry here is its consequence, one exchange later.**
    /// [`VARY_IGNORED`] reports a cache reusing a response across a dimension
    /// the response *did* nominate; this reports the dimension never being
    /// nominated, which is the case no cache can be blamed for. An operator
    /// seeing the second and then the first is watching one mistake become a
    /// wrong answer.
    ///
    /// **`Vary: *` satisfies it and so does nothing else.** § 2 offers that
    /// alternative by name, and it works because a `*` makes the response
    /// unreusable rather than because it names the field.
    ///
    /// `warn`. Every message involved is well formed and the exchange that
    /// produced the finding was answered correctly; what is wrong is that a
    /// later request can be answered from this response when it should not be.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The ending says who is at fault: the response stated its dimensions
    /// correctly and something else did not honour them.
    #[test]
    fn the_ending_names_the_party_that_did_not_honour_the_field() {
        assert!(VARY_IGNORED.id.ends_with("_ignored"));
        assert_eq!(VARY_IGNORED.default_severity, Severity::Warn);
    }
}
