// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Cache-behaviour defects — what a cache did with what it stored, where no
//! field on the wire says it.
//!
//! **The subject is a cache and not a field**, which separates it from
//! [`cache_control`](crate::violations::cache_control) next door: every entry
//! there is a directive somebody wrote and somebody else did not honour, and
//! the id names the directive. RFC 9111 also states requirements on a cache
//! that no message carries — what it may serve, and when — and those are here.
//!
//! **Everything in this subject is read across exchanges, and therefore
//! against a reconstruction.** A proxy watching traffic sees responses, not
//! cache contents: it cannot compute § 4.2 freshness, it does not know which
//! hop answered, and it cannot tell a cache from an origin that changed its
//! mind. So the entries stand on observable *consequences* of the requirements
//! rather than on the requirements being checked directly, and nothing here
//! outranks `warn`.
//
// cite(RFC 9111 § 4.2.4): "A cache MUST NOT generate a stale response unless it is disconnected or doing so is explicitly permitted by the client or origin server"

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Serving stale responses: the MUST NOT, and the two conditions that lift it.
pub const RFC_9111_4_2_4: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("4.2.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.4",
    note: "Serving Stale Responses — a cache MUST NOT generate one unless it is disconnected or a client or origin server explicitly permitted it",
};

defects! {
    /// Two responses for one target URI whose representations run backwards:
    /// the later message describes an older representation than a message
    /// already seen.
    ///
    /// **The observable shape of a stale response**, which is as close as a
    /// proxy can get to § 4.2.4's MUST NOT. Freshness is not computable from
    /// here — there is no stored age and no lifetime to compare it against — so
    /// what stands in for "stale" is a representation time that went down, read
    /// from `Last-Modified` where the response carries one and from `Date`
    /// where it does not.
    ///
    /// **`_conflicting` because that is what the evidence supports.** Two
    /// responses for one resource disagree about which version is current, and
    /// the finding is that disagreement rather than a demonstration that any
    /// particular hop broke a requirement — a proxy cannot tell a cache serving
    /// something stale from an origin that reverted a deployment, and the
    /// entry does not claim to.
    ///
    /// **The comparison is deliberately blind to `Vary`**, which is the known
    /// cost of the reading: two responses that legitimately differ on
    /// `Accept-Language` are compared as though they were one representation.
    /// The alternative is to reconstruct every cache key an intermediary might
    /// have used, and the finding is worth having without that.
    ///
    /// `warn`, and the subject's ceiling: everything above rests on what a
    /// proxy could see rather than on what a cache holds.
    ///
    // cite(RFC 9111 § 4.2.4): "A cache MUST NOT generate a stale response unless it is disconnected or doing so is explicitly permitted by the client or origin server"
    CACHE_RESPONSE_CONFLICTING = {
        id: "cache_response_conflicting",
        title: "Two responses for one URI disagree about which version is current",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_4_2_4],
        strength: Strength::Unstated,
    }
}
