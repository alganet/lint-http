// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Accept-Ranges` defects — a field made entirely of advice.
//!
//! `acceptable-ranges = 1#range-unit` and `range-unit = token`, so the reading
//! of the value belongs to [`list`](crate::violations::list) and
//! [`token`](crate::violations::token) and nothing about the syntax is here.
//! What is here is what the *names* mean once they are read, and § 14.3 says
//! that in modals no stronger than MAY: a server that supports range requests
//! **can** send the field, a server that supports none **MAY** send `none`, and
//! a client **MAY** generate range requests regardless of having received the
//! field at all.
//!
//! **So every entry below is advice, and the ranking is a claim about how far
//! each one misleads rather than about what it breaks.** Two of them are
//! `info`: a response that says nothing, and a response whose advice is
//! incomplete. The third is `warn`, because there the field does not merely
//! omit something — it states the opposite of what the same message did, and a
//! client that reads it stops asking.
//!
//! The subject is the field and not the rule, and three rules read it: one
//! judges the value on its own, one reads it beside the `206` that carries it,
//! and one reads a stored response's advice beside the next request's `Range`.
//! Two of the three arrive at the same defect from different evidence, which is
//! the reason the entry naming `none` is one entry and not two.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The whole field: the production, what sending it is *for*, the reservation
/// of `none`, and the sentences that keep all of it advisory.
pub const RFC_9110_14_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("14.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3",
    note: "`Accept-Ranges`: `acceptable-ranges = 1#range-unit`, what advertising a unit is for, the reservation of `none` for a server supporting no kind of range request, and the MAYs on both sides that make every finding here advice rather than a broken requirement",
};

defects! {
    /// A `206 (Partial Content)` carrying no `Accept-Ranges` at all.
    ///
    /// The response proves the server supports range requests for this
    /// resource — it just served one — and says nothing about which units, to a
    /// client whose next act is likely to be resuming the transfer. That is
    /// exactly what the field is for, and the quoted sentence is the only place
    /// the specification says so.
    ///
    /// **`info`, and nothing here is close to a requirement.** § 15.3.7 does
    /// list the fields a 206 MUST generate — `Date`, `Cache-Control`, `ETag`,
    /// `Expires`, `Content-Location`, `Vary` — and this field is not among
    /// them. So the finding is a suggestion with a sentence behind it, which is
    /// the weakest thing this catalogue holds an entry for and worth saying out
    /// loud: an operator who wants advisory findings silenced silences this one.
    ///
    // cite(RFC 9110 § 14.3): "to indicate that it supports byte range requests for that target resource, thereby encouraging its use by the client for future partial requests on the same request path."
    ACCEPT_RANGES_MISSING = {
        id: "accept_ranges_missing",
        title: "A partial response advertises no range units",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_14_3],
    }

    /// `none` written where the same message shows range requests working:
    /// beside a real unit in one field value, or in a `206` that has just
    /// fulfilled a range request.
    ///
    /// **One entry for both, because the claim is one claim.** The permission
    /// to send `none` is granted to a server that "does not support any kind of
    /// range request for the target resource", and the name is *reserved* for
    /// saying that — so a message carrying it beside evidence to the contrary
    /// says both things at once. The two sites differ only in where that
    /// evidence sits: in the field value itself, or in the status code around
    /// it. Splitting them would give one defect two ids and one fix — delete
    /// `none` — two names.
    ///
    /// `warn` and not `info` like its neighbours: the other two entries leave a
    /// client under-informed, and this one sends it away. A client that reads
    /// `none` and believes it stops making range requests on a path where they
    /// work.
    ///
    // cite(RFC 9110 § 14.3): "to advise the client not to attempt a range request on the same request path.  The range unit "none" is reserved for this purpose."
    ACCEPT_RANGES_NONE_CONFLICTING = {
        id: "accept_ranges_none_conflicting",
        title: "Accept-Ranges says 'none' where range requests demonstrably work",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_14_3],
    }

    /// A response transferring a range in a unit its own `Accept-Ranges` does
    /// not list: a `Content-Range` in `bytes` beside an `Accept-Ranges` naming
    /// something else.
    ///
    /// The advice is not wrong so much as incomplete — nothing says the
    /// advertised list is exhaustive, and a client that reads it and asks in a
    /// listed unit gets what it asked for. What it loses is the unit this very
    /// response used, which is the one the client has the best reason to ask
    /// for next.
    ///
    /// `info`, for that reason: the message is consistent about what it *did*
    /// and merely thin about what it will do again. Distinct from
    /// [`ACCEPT_RANGES_NONE_CONFLICTING`] on exactly that line — a list that
    /// omits a unit and a list that denies every unit are not the same
    /// statement.
    ///
    // cite(RFC 9110 § 14.3, label: what advertising a unit is for): "to indicate that it supports byte range requests for that target resource, thereby encouraging its use by the client for future partial requests on the same request path."
    ACCEPT_RANGES_UNIT_MISSING = {
        id: "accept_ranges_unit_missing",
        title: "A range unit in use is absent from what the response advertises",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_14_3],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ranking is the subject's whole argument, so it is asserted rather
    /// than left to three separate readings: saying the opposite of what the
    /// message did outranks saying too little about it.
    #[test]
    fn stating_the_opposite_outranks_saying_too_little() {
        assert!(
            ACCEPT_RANGES_MISSING.default_severity
                < ACCEPT_RANGES_NONE_CONFLICTING.default_severity
        );
        assert_eq!(
            ACCEPT_RANGES_MISSING.default_severity,
            ACCEPT_RANGES_UNIT_MISSING.default_severity
        );
        assert_eq!(ACCEPT_RANGES_MISSING.default_severity, Severity::Info);
    }
}
