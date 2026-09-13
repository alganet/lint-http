// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Accept` defects — one entry, about a preference nobody had to honour.
//!
//! Everything the field's *value* can be wrong about belongs to a production it
//! borrowed — [`media_range`](crate::violations::media_range),
//! [`media_type`](crate::violations::media_type),
//! [`token`](crate::violations::token),
//! [`parameter`](crate::violations::parameter),
//! [`quoted_string`](crate::violations::quoted_string) and
//! [`qvalue`](crate::violations::qvalue) between them cover the whole member.
//! What is left is the field's *purpose*: it states which media types a client
//! would accept, and this subject holds the one finding about a response that
//! sends something else.
//!
//! **The entry is advice and the specification says so in as many words.**
//! § 12.4.1 gives the origin server the choice outright — honour the field with
//! a `406`, or disregard it and treat the response as not subject to
//! negotiation — and § 12.1 says the same from the client's side, that a user
//! agent cannot rely on proactive negotiation preferences being consistently
//! honoured. So a message reported here may be perfectly conforming, and the
//! finding is worth making anyway: a response the client cannot use is rarely
//! what the server meant to send.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Absence, and the sentence that makes disregarding a negotiation field one of
/// two permitted answers rather than a defect.
pub const RFC_9110_12_4_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("12.4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.1",
    note: "Absence: what a missing negotiation field means, and the origin server's explicit choice between sending a 406 and disregarding the field — which is why a finding about an unhonoured preference is advice and never a violation",
};

defects! {
    /// A response whose `Content-Type` matches no `media-range` the request's
    /// `Accept` listed with a non-zero weight.
    ///
    /// **`_ignored`, which is the ending for a directive that was not
    /// honoured** — and here the specification names *not honouring* as one of
    /// the two answers a server may give. The quoted sentence is the whole
    /// argument for the severity: an origin server may disregard the field and
    /// treat the response as not subject to negotiation, so nothing about the
    /// message is broken. What the finding says is that a client asked for one
    /// thing and got another, which is usually a mistake and never a violation.
    ///
    /// **Not reported against a `406`**: that status is the server taking the
    /// other branch of the same sentence, so a response that says "nothing I
    /// have is acceptable" has honoured the field rather than ignored it.
    ///
    /// `info`, and it sits with
    /// [`accept_ranges_ignored`](crate::violations::accept_ranges::ACCEPT_RANGES_IGNORED)
    /// — the two entries in this catalogue for advice one side gave and the
    /// other did not take, in both directions of the exchange.
    ///
    // cite(RFC 9110 § 12.4.1): "If a content negotiation header field is present in a request and none of the available representations for the response can be considered acceptable according to it, the origin server can either honor the header field by sending a 406 (Not Acceptable) response or disregard the header field by treating the response as if it is not subject to content negotiation for that request header field."
    ACCEPT_IGNORED = {
        id: "accept_ignored",
        title: "Response sends a media type the request did not accept",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_12_4_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::accept_ranges::ACCEPT_RANGES_IGNORED;

    /// Two fields, two directions, one shape: advice given and not taken. They
    /// are ranked together on purpose, because what separates them is which
    /// side spoke and not how much was lost.
    #[test]
    fn advice_not_taken_ranks_the_same_in_both_directions() {
        assert_eq!(
            ACCEPT_IGNORED.default_severity,
            ACCEPT_RANGES_IGNORED.default_severity
        );
        assert_eq!(ACCEPT_IGNORED.default_severity, Severity::Info);
    }
}
