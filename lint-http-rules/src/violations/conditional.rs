// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Conditional request defects — a precondition the recipient must discard.
//!
//! RFC 9110 § 13 defines five conditional fields and, for the two date-based
//! ones, spells out when a recipient is required to ignore what it received.
//! Those sentences are addressed to the *recipient*, and no sentence forbids
//! the sender from writing the field — so nothing here is a broken requirement.
//! What each entry reports is a precondition that will not be evaluated, and
//! the sender has no way to tell from the response that it was not.
//!
//! **Two entries out of one predicate, split on what survives.** In both cases
//! a date conditional is discarded; the difference is whether the request still
//! carries a condition afterwards. Beside its entity-tag counterpart it does —
//! the stronger validator was going to decide the outcome either way, and the
//! date field did nothing. Because the method is not `GET` or `HEAD` it does
//! not, and a request the sender believed was conditional is answered
//! unconditionally.
//!
//! **What is not here is the syntax of any of these fields.** An
//! `If-Modified-Since` that is not an `HTTP-date`, an `If-Match` whose member
//! is no entity-tag, a second field line where the field is not a list: those
//! are [`http_date`](crate::violations::http_date)'s,
//! [`etag`](crate::violations::etag)'s and [`field`](crate::violations::field)'s,
//! reported by the rules that read each value.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// `If-Modified-Since`: the sentence that discards it beside an
/// `If-None-Match`, and the three-clause sentence that discards it for a method
/// it is not defined over.
pub const RFC_9110_13_1_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3",
    note: "`If-Modified-Since`: the recipient MUST ignore it when an `If-None-Match` is present, and MUST ignore it when the value is no HTTP-date, has more than one member, or the method is neither GET nor HEAD",
};

/// `If-Unmodified-Since`: the mirror sentence, discarding it beside an
/// `If-Match`.
pub const RFC_9110_13_1_4: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.4",
    note: "`If-Unmodified-Since`: the recipient MUST ignore it when an `If-Match` is present, and when the value is no HTTP-date",
};

defects! {
    /// A date conditional sent beside the entity-tag conditional that
    /// supersedes it: `If-Modified-Since` with `If-None-Match`, or
    /// `If-Unmodified-Since` with `If-Match`.
    ///
    /// **`_redundant`, which is the ending that condemns nothing.** The request
    /// stated one condition twice, in two strengths, and the recipient is
    /// required to evaluate the stronger — so the outcome is the outcome the
    /// entity-tag conditional was always going to produce, and the date field
    /// changed nothing about it. `_conflicting` would claim the two disagree
    /// when they need not; `_invalid` would claim the value is unacceptable
    /// when it is a perfectly good `HTTP-date`.
    ///
    /// **One entry for the mirror pair.** § 13.1.3 and § 13.1.4 write the same
    /// sentence once per field, and a sender that paired
    /// `If-Modified-Since`/`If-None-Match` and one that paired
    /// `If-Unmodified-Since`/`If-Match` made the same mistake and take the same
    /// repair. Neither section governs a finding of the other, so the entry
    /// names both and carries a citation onto neither; the message says which
    /// pair was in front of it.
    ///
    /// `info`, which is where `_redundant` starts and where nothing here argues
    /// for more: the message is conforming, the condition is evaluated, and
    /// what is left is a field nobody read.
    ///
    /// Both sentences are quoted here, where neither is claimed as the one:
    ///
    // cite(RFC 9110 § 13.1.3): "A recipient MUST ignore If-Modified-Since if the request contains an If-None-Match header field"
    // cite(RFC 9110 § 13.1.4): "A recipient MUST ignore If-Unmodified-Since if the request contains an If-Match header field"
    CONDITIONAL_DATE_REDUNDANT = {
        id: "conditional_date_redundant",
        title: "A date conditional is sent beside the entity-tag conditional that supersedes it",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_13_1_3, RFC_9110_13_1_4],
    }

    /// An `If-Modified-Since` on a method that is neither `GET` nor `HEAD`.
    ///
    /// The same discard as [`CONDITIONAL_DATE_REDUNDANT`] and a different
    /// outcome, which is the whole reason the two are two: there is no stronger
    /// validator standing behind this one. The recipient drops the field, the
    /// precondition is never evaluated, and a request the sender believed was
    /// conditional is answered as though it had carried no condition at all.
    ///
    /// `warn` rather than `info` for exactly that: what is lost is not a
    /// redundant field but the condition itself, and nothing in the response
    /// says so.
    ///
    // cite(RFC 9110 § 13.1.3): "A recipient MUST ignore the If-Modified-Since header field if the received field value is not a valid HTTP-date, the field value has more than one member, or if the request method is neither GET nor HEAD."
    CONDITIONAL_DATE_IGNORED = {
        id: "conditional_date_ignored",
        title: "A date conditional is sent where the recipient must discard it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_13_1_3],
    }

    /// A precondition naming a validator this exchange never provided: a
    /// conditional request with no stored response for the resource, one whose
    /// stored response was never observed, an entity-tag conditional after a
    /// response with no `ETag`, or a date conditional after one with no
    /// `Last-Modified`.
    ///
    /// **The one entry in this subject that names no sentence, and the reason
    /// is that there is none.** RFC 9110 states no requirement that a client
    /// have previously received the validator it conditions on — `If-None-Match:
    /// *` legitimately needs no prior tag at all, and a client may carry a
    /// validator from a cache this observer never saw fill. The heuristic is
    /// this crate's, and a reference on it would dress a stateful guess as a
    /// requirement.
    ///
    /// **Four situations, one entry, and two of them are about the observer
    /// rather than the sender.** "No stored response for this resource" and
    /// "a stored transaction whose response was never recorded" are statements
    /// about what reached the proxy; "the response carried no `ETag`" and "no
    /// `Last-Modified`" are statements about what the server sent. They share
    /// the claim that matters — the precondition was built from something this
    /// exchange cannot account for — and the message says which of the four it
    /// was, which is where the difference belongs when the repair is the same
    /// in all four: none, unless the validator was invented.
    ///
    /// `info`, for a finding with no sentence behind it and a legitimate
    /// explanation available in every case.
    CONDITIONAL_VALIDATOR_MISSING = {
        id: "conditional_validator_missing",
        title: "A precondition names a validator this exchange never provided",
        message: "",
        default_severity: Severity::Info,
        spec: &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The split is the subject's argument and the ranking is what carries it:
    /// one discard leaves a condition standing and the other does not. If these
    /// ever level, the reason for two entries has gone with it.
    #[test]
    fn losing_a_redundant_field_ranks_below_losing_the_condition() {
        assert!(
            CONDITIONAL_DATE_REDUNDANT.default_severity < CONDITIONAL_DATE_IGNORED.default_severity
        );
        assert_eq!(CONDITIONAL_DATE_REDUNDANT.default_severity, Severity::Info);
    }

    /// One entry names two sections and one names a single sentence, which is
    /// the difference between a mirror pair and a clause of one sentence.
    #[test]
    fn the_mirror_pair_names_both_sections_and_the_method_clause_names_one() {
        assert_eq!(CONDITIONAL_DATE_REDUNDANT.spec.len(), 2);
        assert_eq!(CONDITIONAL_DATE_IGNORED.spec, [RFC_9110_13_1_3]);
    }
}
