// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Expires` defects — one entry, about a field a modern cache does not read.
//!
//! The value's own syntax is [`http_date`](crate::violations::http_date)'s and
//! is reported by the rules that measure a date. What is here is what `Expires`
//! *says* beside a `Cache-Control`, which RFC 9111 § 5.3 settles in a direction
//! that makes the disagreement worth reporting rather than harmless: a
//! recipient MUST ignore `Expires` when `max-age` is present, and the section
//! adds that the field "is only intended for recipients that have not yet
//! implemented the Cache-Control header field".
//!
//! **So the two values are read by two different populations of cache**, and a
//! response whose `Expires` and whose freshness directives disagree is a
//! response with two answers, sorted by how old the cache is. That is the whole
//! content of the entry below, and it is why nothing here is a conformance
//! finding: the specification resolves the disagreement by precedence and calls
//! nothing an error.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field, the precedence that retires it, and the sentence about which
/// recipients it is still for.
pub const RFC_9111_5_3: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("5.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.3",
    note: "`Expires` — a recipient MUST ignore it when `max-age` is present and a shared cache when `s-maxage` is, an invalid date (\"0\" above all) MUST be read as already expired, and the field is only intended for recipients that have not implemented Cache-Control",
};

defects! {
    /// An `Expires` that says something the response's `Cache-Control`
    /// freshness directives do not: an unreadable date (which a cache must
    /// treat as already expired) beside a positive `max-age`, a future
    /// `Expires` beside `no-cache`, `no-store` or `max-age=0`, an already-past
    /// `Expires` beside a positive `max-age`, or a date more than a second away
    /// from `Date` plus `max-age`.
    ///
    /// **Four shapes, one entry, and the population is why.** Every one of them
    /// is the same message read two ways: a cache that implements
    /// `Cache-Control` uses the directive and ignores this field, and a cache
    /// that does not uses this field. The repair is the same in all four —
    /// make them agree, or drop the field — and so is the loss, which is that
    /// the response has two expiry answers sorted by the age of the cache
    /// reading it. The message says which shape was in front of it.
    ///
    /// **Not a conformance finding, and § 5.3 is why it is worth making
    /// anyway.** The specification resolves the disagreement by precedence and
    /// calls nothing an error, so no message reported here is malformed. What
    /// the entry says is that a deployment maintaining both wrote them to
    /// disagree, which is almost never what it meant and is invisible from
    /// either field alone.
    ///
    /// `warn`. The divergence is real for every recipient that has not
    /// implemented the directive, and those recipients are exactly the ones the
    /// field exists for.
    ///
    // cite(RFC 9111 § 5.3): "If a response includes a Cache-Control header field with the max-age directive (Section 5.2.2.1), a recipient MUST ignore the Expires header field."
    EXPIRES_CONFLICTING = {
        id: "expires_conflicting",
        title: "Expires and the Cache-Control freshness directives disagree",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_5_3],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one thing a single-entry subject can settle on its own, and here it
    /// is a claim rather than a preference: this is a disagreement between two
    /// readings of one message, not a defect in either field, so it never
    /// reaches `error`.
    #[test]
    fn a_disagreement_the_specification_resolves_is_a_warning() {
        assert_eq!(EXPIRES_CONFLICTING.default_severity, Severity::Warn);
    }
}
