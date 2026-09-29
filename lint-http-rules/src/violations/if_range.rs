// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `If-Range` defects — the five things only this field says.
//!
//! `If-Range = entity-tag / HTTP-date`, so what a value *is* belongs to
//! [`etag`](crate::violations::etag) and
//! [`http_date`](crate::violations::http_date), and this is an alternation
//! whose committing delimiter the document names itself: a DQUOTE among the
//! first three characters picks the entity-tag half, and each half is then
//! measured against the production it chose. What is left over is this subject.
//!
//! **Three of the five entries are § 13.1.5's three client-side MUST NOTs, and
//! none of them is about a value being unreadable.** All three are about a
//! perfectly well-formed value the field refuses anyway — a weak entity-tag, a
//! date where the client holds a tag, and a field written where nothing
//! conditions it — and the fourth is about the alternation having no empty
//! alternative. § 13.1.5 pairs each of its client-side MUST NOTs with the
//! recipient behaviour it produces, and those pairings are what rank the
//! entries: in every case the recipient is told to ignore something, so what
//! the sender loses is the short-circuit the field exists to provide, and never
//! the correctness of what comes back.
//!
//! **The fifth is that recipient behaviour, not performed**, and it is the one
//! entry here whose cost is the correctness of what comes back: a server that
//! sends the range when the condition was false hands the client a part of a
//! representation it does not hold, to be joined to the part it does.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field: its grammar, the DQUOTE that tells the two alternatives apart,
/// the three client-side MUST NOTs, and the recipient behaviour each of them
/// produces.
pub const RFC_9110_13_1_5: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5",
    note: "`If-Range`: `entity-tag / HTTP-date`, the first-three-characters DQUOTE test that tells them apart, the MUST NOT on a request with no `Range`, the MUST NOT on a weak entity-tag, the MUST NOT on a date where the client holds an entity tag, the strong comparison and the exact date match a recipient evaluates the condition with, and the recipient's MUST to ignore the `Range` when it is false",
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
    /// `error`, off the keyword: a MUST NOT binding the client that wrote the
    /// field, and the test below keeps every one of § 13.1.5's client-side MUST
    /// NOTs at one level. What the evaluation rule bounds is the cost and not
    /// the rank — the condition is simply false, the recipient ignores the
    /// `Range`, and the whole representation comes back, which is a transfer the
    /// field existed to avoid rather than a range spliced out of the wrong
    /// representation.
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
    /// beginning after the response that carried the tag cannot produce it.
    ///
    /// **Any response that carried one will do, and the sentence is what says
    /// so.** A 200 hands the client an entity tag as surely as a 206 does. The
    /// partial copy is § 4.3.1's premise — that a *cache* completing one send
    /// the tag back — and while this entry was asked behind it, a client that
    /// had never been sent a 206 could write the forbidden date in silence.
    ///
    /// **A weak tag counts, and it is the case that leaves the client nothing
    /// to send.** § 8.8.3 writes `entity-tag = [ weak ] opaque-tag`, so a client
    /// answered `W/"v1"` has an entity tag; the MUST NOT beside this one refuses
    /// it the weak tag in the field, and this one refuses it the date, so the
    /// only conforming `If-Range` is no `If-Range`. That a weak validator lets
    /// no fragments be combined is a true sentence about a different entry.
    ///
    /// `error`, with its siblings and off the same keyword: this is § 13.1.5's
    /// third client-side MUST NOT, and the quote below carries it. It did not,
    /// and that is worth knowing — the document wraps the field name at its
    /// hyphen, so a quote of this sentence beginning at *Range header field*
    /// reads as text that obliges nobody, which is what the entry then declared
    /// and what its published page said. The recipient's answer to a validator
    /// it cannot honour is the whole representation, which costs the transfer
    /// the field existed to avoid rather than the wrong bytes: a bound on what
    /// the finding costs and not on its rank.
    ///
    // cite(RFC 9110 § 13.1.5): "A client MUST NOT generate an If-Range header field containing an HTTP-date unless the client has no entity tag for the corresponding representation and the date is a strong validator in the sense defined by Section 8.8.2.2."
    IF_RANGE_VALIDATOR_DATE_FORBIDDEN = {
        id: "if_range_validator_date_forbidden",
        title: "If-Range carries a date for a representation with an entity tag",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_13_1_5],
        strength: Strength::Must,
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

    /// A `206` answering a range request whose `If-Range` the response's own
    /// validator says was false.
    ///
    /// **The server's half of the field, and the half the field exists for.**
    /// § 13.1.5 says what the condition asks — "if the representation is
    /// unchanged, send me the part(s) that I am requesting in Range;
    /// otherwise, send me the entire representation" — and has the recipient
    /// evaluate it: an entity tag by the strong comparison against the
    /// selected representation's `ETag`, a date by exact match against its
    /// `Last-Modified`. The validator compared is the one the `206` carries,
    /// because § 8.8.3 makes a response's `ETag` the current tag "as
    /// determined at the conclusion of handling the request". A `206` whose
    /// tag is not the one the client sent, or is weak on either side, or whose
    /// `Last-Modified` is not the date the client sent, answered a condition
    /// that was false with the range anyway.
    ///
    /// **Only the `206`.** § 13.2.1 has a server ignore every precondition
    /// where the same request without them would have been answered with
    /// neither a `2xx` nor a `412`, and a range no representation satisfies is
    /// a `416` whatever the `If-Range` said, so a `416` answering a false
    /// condition is the status the section prescribes.
    ///
    /// `error`, off the keyword: the sentence is a MUST binding the recipient.
    /// Unlike its four siblings, what it costs is the octets: a download
    /// resumed this way joins the tail of one representation onto the head of
    /// another, and nothing in the response tells the client so except the
    /// validator it was sent to check.
    ///
    // cite(RFC 9110 § 13.1.5): "A recipient of an If-Range header field MUST ignore the Range header field if the If-Range condition evaluates to false."
    IF_RANGE_IGNORED = {
        id: "if_range_ignored",
        title: "A range is sent though the If-Range condition was false",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_13_1_5],
        strength: Strength::Must,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One level for the whole subject, and the subject's doc says why: every
    /// one of § 13.1.5's client-side MUST NOTs is paired with a recipient told
    /// to ignore something, so each costs the short-circuit and none costs
    /// correctness. A split here would have to name a consequence the section
    /// does not describe. The fifth entry, the recipient's own MUST, costs
    /// correctness and sits at the same level off its own keyword, so the
    /// subject is one level for two reasons and not for one.
    ///
    /// **Over every entry of the subject rather than a list of them**, because
    /// the list is how one escaped: written when there were three entries, it
    /// went on asserting three after a fourth arrived, and that fourth —
    /// § 13.1.5's third client-side MUST NOT — sat at `warn` for as long as the
    /// list did not name it, under a doc claiming it ranked *with its siblings*.
    /// A claim about "every one" of something cannot be held by naming some of
    /// them. The count is asserted too, so a sixth entry fails here and is
    /// ranked on purpose.
    #[test]
    fn every_entry_of_the_subject_sits_at_one_level() {
        let subject: Vec<&&crate::violations::ViolationDef> = crate::violations::VIOLATIONS
            .iter()
            .filter(|def| def.id.starts_with("if_range"))
            .collect();
        assert_eq!(
            subject.iter().map(|def| def.id).collect::<Vec<_>>(),
            [
                "if_range_empty",
                "if_range_forbidden",
                "if_range_ignored",
                "if_range_validator_date_forbidden",
                "if_range_validator_weak_forbidden",
            ],
        );
        for def in subject {
            assert_eq!(def.default_severity, Severity::Error, "{}", def.id);
        }
    }
}
