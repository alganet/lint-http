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
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// `If-Modified-Since`: the sentence that discards it beside an
/// `If-None-Match`, and the three-clause sentence that discards it for a method
/// it is not defined over.
pub const RFC_9110_13_1_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3",
    note: "`If-Modified-Since`: the recipient MUST ignore it when an `If-None-Match` is present, MUST ignore it when the value is no HTTP-date or has more than one member or the method is neither GET nor HEAD, and SHOULD answer a false condition with a 304 rather than performing the method",
};

/// `If-Unmodified-Since`: the mirror sentence, discarding it beside an
/// `If-Match`.
/// Sending a validation request: which validator a cache must put in one, and
/// which fields it belongs in.
pub const RFC_9111_4_3_1: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("4.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.1",
    note: "Sending a Validation Request — a cache MUST send the entity tags of the stored responses it is validating, in `If-Match`, `If-None-Match` or `If-Range`, and SHOULD send the `Last-Modified` value where the conditions for it hold",
};

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
        strength: Strength::Unstated,
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
        strength: Strength::Unstated,
    }

    /// An `If-Modified-Since` naming a time later than the `Date` of the
    /// request carrying it.
    ///
    /// **Uncited: no sentence says a client may not do this.** § 13.1.3 defines
    /// the field and says nothing about how its value relates to the request's
    /// own clock, and a client is not obliged to send a `Date` at all — so what
    /// refuses the pair is this crate's reading, and a reference would dress it
    /// as a requirement.
    ///
    /// **The reading is that a precondition about the future evaluates as
    /// none.** The field asks a server to answer only if the representation
    /// changed *since* a moment, and a moment the request itself says has not
    /// arrived is one nothing can have changed since — so the condition is
    /// always false and the client gets a `304` it could have predicted.
    ///
    /// **A skew is allowed**, because clocks disagree by seconds and a rule
    /// reporting that would report the world.
    ///
    /// `info`, with the rest of this subject's reconstructions: the exchange
    /// works, and what the finding buys is a client learning that its
    /// conditional never had a chance to be true.
    CONDITIONAL_DATE_CONFLICTING = {
        id: "conditional_date_conflicting",
        title: "A date precondition names a time after the request's own Date",
        message: "",
        default_severity: Severity::Info,
        spec: &[],
    }

    /// An entity-tag precondition written with no validator in it: an
    /// `If-Match` or an `If-None-Match` whose value is empty or is only
    /// whitespace.
    ///
    /// **Uncited, and the grammar is the reason rather than a gap.** Both
    /// fields are `"*" / #entity-tag`, and a plain `#` construct *generates the
    /// empty list* — so no sentence refuses this value and
    /// [`list_member_missing`](crate::violations::list) would be the wrong
    /// entry, since that one carries the floor a `1#` spelling has and these
    /// fields do not have one. What refuses it is this crate's reading: a
    /// precondition naming no validator states no condition.
    ///
    /// **The two fields evaluate it differently and neither outcome is what the
    /// sender meant**, which is the argument for reporting it at all. An
    /// `If-Match` with nothing to match fails and the server answers `412`; an
    /// `If-None-Match` with nothing to match succeeds and the request proceeds
    /// as the unconditional one it now is. A sender that wrote the field wanted
    /// neither.
    ///
    /// **Distinct from [`CONDITIONAL_VALIDATOR_MISSING`]**: there a validator
    /// was named and this exchange cannot account for it, here none was named
    /// at all.
    ///
    /// `warn`. Nothing is malformed and the request is answerable; what is lost
    /// is the condition.
    CONDITIONAL_EMPTY = {
        id: "conditional_empty",
        title: "A precondition is written with no validator in it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[],
    }

    /// A request revalidating a stored response that carries none of the three
    /// fields the entity tags of that response belong in.
    ///
    /// `error`, and the only entry in this subject that is one: the sentence is
    /// a `MUST` on the cache building the request, and the cache is what built
    /// this one. The request is still answerable and the server will still send
    /// something correct, so what is lost is the revalidation — and with it the
    /// stored response the cache was trying to keep.
    ///
    // cite(RFC 9111 § 4.3.1): "MUST send the relevant entity tags (using If-Match, If-None-Match, or If-Range) if the entity tags were provided in the stored response(s) being validated."
    CONDITIONAL_ENTITY_TAG_MISSING = {
        id: "conditional_entity_tag_missing",
        title: "A revalidating request omits the entity tags it holds",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9111_4_3_1],
        strength: Strength::Must,
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
    /// A precondition naming a validator other than the most recent one this
    /// exchange saw for the resource.
    ///
    /// **Uncited beside its sibling, and for the same reason widened by one
    /// more**: no sentence requires a client to condition on the *latest*
    /// validator, and holding an older one is exactly what a cache that has not
    /// revalidated looks like. So the legitimate explanation is not merely
    /// available, it is the common case, and the finding is worth making only
    /// because the alternative — a validator assembled rather than kept — looks
    /// identical from here.
    ///
    /// **Separate from
    /// [`CONDITIONAL_VALIDATOR_MISSING`] because the exchange did provide
    /// one.** That entry is about a precondition this observer cannot account
    /// for at all; this one is about a precondition it can account for and
    /// which does not line up, which is a different thing for an operator to
    /// look at and a different thing to silence.
    ///
    /// `info`, with everything else in this subject that rests on a
    /// reconstruction rather than a sentence.
    CONDITIONAL_VALIDATOR_CONFLICTING = {
        id: "conditional_validator_conflicting",
        title: "A precondition names a validator older than the last one seen",
        message: "",
        default_severity: Severity::Info,
        spec: &[],
    }

    /// A repeated request for a resource whose stored response carried a
    /// validator, sent with no precondition on it.
    ///
    /// The mirror of the two entries above: there a client conditions on
    /// something this exchange cannot place, here it declines to condition on
    /// something the exchange handed it. **Nothing requires a client to make a
    /// request conditional** — an `ETag` is an offer — so the entry names no
    /// sentence and reports a round trip that could have been a `304`.
    ///
    /// `info`. What is lost is a body that need not have been sent, and the
    /// client may have had every reason to want a fresh one.
    ///
    /// **An offer no cache was allowed to accept is not one that was
    /// declined.** RFC 9111 § 3 decides whether the earlier exchange left a
    /// stored response at all, and a `no-store` on either of its two messages
    /// answers no — so the `ETag` beside it reached no store and the round
    /// trip named here could not have been a `304`. The entry is about a
    /// validator the server provided; on such a response nothing was provided
    /// to decline.
    CONDITIONAL_MISSING = {
        id: "conditional_missing",
        title: "A repeat request declines a validator the server provided",
        message: "",
        default_severity: Severity::Info,
        spec: &[],
    }

    /// A precondition sent for a stored response that had not expired: the
    /// round trip revalidates something the client could have used without
    /// asking.
    ///
    /// **[`CONDITIONAL_MISSING`]'s mirror at the other end of the freshness
    /// lifetime.** There a client declined a validator it was offered; here it
    /// spends a request confirming a copy nothing had made doubtful. Both are
    /// round trips that need not have happened, in opposite directions, and
    /// both are reconstructions: the freshness this rests on is estimated from
    /// a stored `max-age`, an `Age` and the time between two captures, not read
    /// off the wire.
    ///
    /// **Uncited, and for [`CONDITIONAL_MISSING`]'s reason.** RFC 9111 § 4.2
    /// says a fresh response *can* be reused without contacting the origin —
    /// an efficiency a cache is offered, not one it owes — so no sentence is
    /// broken by asking anyway. A client with a reason to distrust its copy is
    /// doing something reasonable, and nothing on the wire distinguishes it.
    ///
    /// **Not [`cache_control_immutable_ignored`](crate::violations::cache_control),
    /// which is the same request against a stronger promise.** RFC 8246 turns
    /// early revalidation of an `immutable` response into a SHOULD NOT; without
    /// that extension there is no such sentence, and the two entries are the
    /// difference between a requirement missed and an opportunity passed up.
    ///
    /// `info`, with the rest of this subject.
    CONDITIONAL_REDUNDANT = {
        id: "conditional_redundant",
        title: "A still-fresh stored response is revalidated anyway",
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
