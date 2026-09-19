// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Expires` defects — two entries about a field a modern cache does not read.
//!
//! What `Expires` *says* beside a `Cache-Control` is the first of them, and
//! RFC 9111 § 5.3 settles it in a direction that makes the disagreement worth
//! reporting rather than harmless: a recipient MUST ignore `Expires` when
//! `max-age` is present, and the section adds that the field "is only intended
//! for recipients that have not yet implemented the Cache-Control header
//! field".
//!
//! **So the two values are read by two different populations of cache**, and a
//! response whose `Expires` and whose freshness directives disagree is a
//! response with two answers, sorted by how old the cache is. That is the whole
//! content of [`EXPIRES_CONFLICTING`], and it is why it is not a conformance
//! finding: the specification resolves the disagreement by precedence and calls
//! nothing an error.
//!
//! **The second entry is here rather than in
//! [`http_date`](crate::violations::http_date) for the reason the field is
//! unlike every other one written as a timestamp**, and this module's doc
//! comment used to say the opposite in as many words — that the value's own
//! syntax was reported by the rules that measure a date. It was not reported by
//! anything: `Date`, `Last-Modified`, `Sunset` and the two conditional dates
//! each have a reader and `Expires` had none, so an `Expires` no format parses
//! passed in silence unless a `Cache-Control` happened to be beside it to make
//! the entry above fire. It has one now, and it draws
//! [`EXPIRES_MALFORMED`] rather than `http_date_malformed`, because § 5.3
//! answers for this field what "no format parses it" leaves open everywhere
//! else: the response is already expired.

use crate::lint::Severity;
use crate::lint::Strength;
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
    /// treat as already expired) beside a lifetime still unspent, a future
    /// `Expires` beside `no-cache`, `no-store` or a lifetime already spent, an
    /// already-past `Expires` beside a lifetime still unspent, or a date more
    /// than a second away from every instant `Date` and an unspent `max-age`
    /// can name.
    ///
    /// **"Unspent" is `max-age` minus the `Age` the response arrived with, and
    /// it is what makes `max-age=0` the ordinary case rather than the special
    /// one.** § 4.2.3 floors `current_age` at the stated `Age`, so a lifetime
    /// at or below that number is one no recipient has any of left: the
    /// response is stale on arrival for the cache that reads the directive
    /// exactly as `max-age=0` is. Beside an `Expires` already past, that is one
    /// answer written twice, and the distance between two instants behind
    /// `Date` is not a second answer. Beside a *future* `Expires` it is the
    /// second shape above — which is how a spent lifetime is reported, and it
    /// was reported as a distance until the age was read.
    ///
    /// **`Date` has two readings and the last shape allows for both.** Where it
    /// is the instant the origin generated the response, the directive
    /// population goes stale at `Date` plus `max-age`. Where it is the instant
    /// the cache in front of the origin served this copy — which is what an
    /// `Age` beside a `Date` at the observed instant means — the lifetime left
    /// is what has not been spent, and both populations meet at `Date` plus
    /// `max-age` minus `Age`. A sender who writes either has written one
    /// lifetime twice; only a value landing on neither has written two.
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
        strength: Strength::Unstated,
    }

    /// An `Expires` that derives from no `HTTP-date`, in a field whose own
    /// section has already settled what that means: every cache reads the
    /// response as stale on arrival.
    ///
    /// **Not [`HTTP_DATE_MALFORMED`](crate::violations::http_date::HTTP_DATE_MALFORMED),
    /// and § 5.3 is the whole of the difference.** That entry says the field
    /// names no instant, so everything downstream of it has nothing to work
    /// from — true of a `Date` or a `Last-Modified` that will not parse, and
    /// false here. § 5.3 hands a cache an answer for every value this entry
    /// names, in a `MUST`, and names the commonest of them while doing it:
    /// `Expires: 0` is a time already past. The field still states a freshness
    /// lifetime; what this reports is that the lifetime it states is zero.
    ///
    /// **Two populations, one finding, because one sentence is true of both.**
    /// A server writing `0` or `-1` asked for stale-on-arrival and got it. A
    /// server writing `Sun, 30 Aug 2026 00:27:20 UTC` asked for the ten minutes
    /// its `max-age` also asks for and got the same zero, because nothing sends
    /// a reader of `Expires` anywhere but the production — there is no § 5.1.1
    /// here, no lenient algorithm of the kind RFC 6265 defines for a cookie
    /// attribute spelled the same way, and so no
    /// [`COOKIE_EXPIRES_MALFORMED`](crate::violations::cookie::COOKIE_EXPIRES_MALFORMED)
    /// tier where the value works anyway. The message carries the value, which
    /// is what tells a reader which of the two is in front of them.
    ///
    /// `warn`, and `Unstated` is why that is argued here rather than derived.
    /// § 5.3's keyword binds the **recipient** — a cache MUST read an invalid
    /// date as already expired — so it obliges nothing of the sender being
    /// reported and states no level. What is left to weigh is a specification
    /// that standardised this spelling's handling rather than refusing it,
    /// against a freshness lifetime that is lost outright whenever the sender
    /// did mean one. `error` overstates the first; `info` understates the
    /// second.
    ///
    // cite(RFC 9111 § 5.3, label: expires): "The Expires field value is an HTTP-date timestamp, as defined in Section 5.6.7 of [HTTP]."
    // cite(RFC 9111 § 5.3): "A cache recipient MUST interpret invalid date formats, especially the value "0", as representing a time in the past (i.e., "already expired")."
    EXPIRES_MALFORMED = {
        id: "expires_malformed",
        title: "Expires derives from no HTTP-date, so a cache reads it as already expired",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_5_3],
        strength: Strength::Unstated,
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
