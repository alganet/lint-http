// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `If-Range` defects — the three things only this field says.
//!
//! `If-Range = entity-tag / HTTP-date`, so what a value *is* belongs to
//! [`etag`](crate::violations::etag) and
//! [`http_date`](crate::violations::http_date), and this is an alternation
//! whose committing delimiter the document names itself: a DQUOTE among the
//! first three characters picks the entity-tag half, and each half is then
//! measured against the production it chose. What is left over is this subject.
//!
//! **All three entries are MUST NOTs on the client, and none of them is about a
//! value being unreadable.** Two are about a perfectly well-formed value the
//! field refuses anyway — a weak entity-tag, and a field written where nothing
//! conditions it — and one is about the alternation having no empty
//! alternative. § 13.1.5 pairs each of its client-side MUST NOTs with the
//! recipient behaviour it produces, and those pairings are what rank the
//! entries: in every case the recipient is told to ignore something, so what
//! the sender loses is the short-circuit the field exists to provide, and never
//! the correctness of what comes back.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field: its grammar, the DQUOTE that tells the two alternatives apart,
/// the two client-side MUST NOTs, and the recipient behaviour each of them
/// produces.
pub const RFC_9110_13_1_5: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5",
    note: "`If-Range`: `entity-tag / HTTP-date`, the first-three-characters DQUOTE test that tells them apart, the MUST NOT on a request with no `Range`, the MUST NOT on a weak entity-tag, and the strong comparison a recipient evaluates the condition with",
};

defects! {
    /// An `If-Range` in a request that carries no `Range`.
    ///
    /// The field's whole purpose is to say what to do *with the `Range`* — send
    /// the parts if the representation is unchanged, the whole thing otherwise
    /// — so with no `Range` beside it there is nothing for the condition to
    /// govern. § 13.1.5 states that twice, once per side: a client MUST NOT
    /// generate it, and a server MUST ignore it.
    ///
    /// `error`: § 13.1.5 says a client MUST NOT generate the field in a request
    /// with no `Range`. The recipient's half of the sentence is what the
    /// finding costs rather than what ranks it — the field is discarded and the
    /// request proceeds as the unconditional one it already was, so nothing
    /// about the response changes, and what is reported is a client that
    /// believes it sent a conditional request.
    ///
    // cite(RFC 9110 § 13.1.5): "A client MUST NOT generate an If-Range header field in a request that does not contain a Range header field."
    IF_RANGE_FORBIDDEN = {
        id: "if_range_forbidden",
        title: "If-Range is sent in a request with no Range",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_13_1_5],
        strength: Strength::Must,
    }

    /// An `If-Range` carrying a weak entity-tag: `W/"abc"`.
    ///
    /// A well-formed `entity-tag` — [`etag`](crate::violations::etag) has
    /// nothing to say about it — that this field refuses for what it means. A
    /// weak validator says two representations are equivalent, not that their
    /// octets are identical, and the range being asked for is octets. So the
    /// document forbids the client from sending one and evaluates the condition
    /// with the *strong* comparison function, which a weak tag can never
    /// satisfy.
    ///
    /// `warn`, and the evaluation rule is why it is not `error`: the condition
    /// is simply false, the recipient ignores the `Range`, and the whole
    /// representation comes back. The cost is a transfer the field existed to
    /// avoid — the same cost as writing no `If-Range` at all — rather than a
    /// range spliced out of the wrong representation.
    ///
    // cite(RFC 9110 § 13.1.5): "A client MUST NOT generate an If-Range header field containing an entity tag that is marked as weak."
    IF_RANGE_VALIDATOR_WEAK_FORBIDDEN = {
        id: "if_range_validator_weak_forbidden",
        title: "If-Range carries a weak entity-tag",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_13_1_5],
        strength: Strength::Must,
    }

    /// An `If-Range` carrying an `HTTP-date` for a representation the client
    /// was given an entity tag for.
    ///
    /// **The alternation is not a free choice**, and this is the sentence that
    /// says so: a date is permitted there only when the client has no entity
    /// tag for the representation *and* the date is a strong validator. A
    /// client holding a tag has one of those conditions against it, so the
    /// alternative it picked is the one it was not allowed to pick.
    ///
    /// **Third of the field's `_forbidden` entries and the only one needing a
    /// second message to make.** That an `If-Range` sits on a request with no
    /// `Range`, or carries a weak tag, is visible in the request alone; that
    /// the client *had* a tag is visible only in what the server sent it
    /// earlier — so a rule reporting this needs the history, and a capture
    /// beginning after the `206` cannot produce it.
    ///
    /// `warn`, with its siblings, and for the same reason: the recipient's
    /// answer to a validator it cannot honour is the whole representation,
    /// which costs the transfer the field existed to avoid rather than the
    /// wrong bytes.
    ///
    // cite(RFC 9110 § 13.1.5): "Range header field containing an HTTP-date unless the client has no entity tag for the corresponding representation and the date is a strong validator in the sense defined by Section 8.8.2.2."
    IF_RANGE_VALIDATOR_DATE_FORBIDDEN = {
        id: "if_range_validator_date_forbidden",
        title: "If-Range carries a date for a representation with an entity tag",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_13_1_5],
    }

    /// An `If-Range` written and left blank.
    ///
    /// **The one finding here that neither half of the alternation can make**,
    /// which is why it is the field's own: an `entity-tag` is at least two
    /// DQUOTEs and an `HTTP-date` is a fixed twenty-nine characters, so the
    /// empty string derives from neither — and a reader handed it cannot even
    /// say which alternative was meant, because the DQUOTE test that commits a
    /// value to one half has nothing to look at. *An alternation owns no defect
    /// until the reading cannot commit, and this is the case where it cannot.*
    ///
    /// `error`, with the others: `If-Range` generates an entity-tag or an
    /// HTTP-date and nothing else. A validator the recipient cannot read is a
    /// condition that evaluates false, and false means the whole
    /// representation.
    ///
    // cite(RFC 9110 § 13.1.5, label: If-Range grammar): "If-Range = entity-tag / HTTP-date"
    IF_RANGE_EMPTY = {
        id: "if_range_empty",
        title: "If-Range is written with no validator in it",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_13_1_5],
        strength: Strength::Grammar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One level for all three, and the subject's doc says why: every one of
    /// § 13.1.5's client-side MUST NOTs is paired with a recipient told to
    /// ignore something, so each costs the short-circuit and none costs
    /// correctness. A split here would have to name a consequence the section
    /// does not describe.
    #[test]
    fn every_way_of_losing_the_short_circuit_sits_at_one_level() {
        for def in [
            &IF_RANGE_FORBIDDEN,
            &IF_RANGE_VALIDATOR_WEAK_FORBIDDEN,
            &IF_RANGE_EMPTY,
        ] {
            assert_eq!(def.default_severity, Severity::Error, "{}", def.id);
        }
    }
}
