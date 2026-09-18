// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Date` defects — the field that says when the message was written.
//!
//! Separate from [`crate::violations::http_date`], which is the *production*
//! every dated field carries. That module answers whether a value states an
//! instant; this one answers whether the field is there at all, which is a
//! question about one field and not about eighteen.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field, the origin server's obligation to send it, the counter-obligation
/// on a server without a clock, and the repair a recipient is required to make.
pub const RFC_9110_6_6_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("6.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1",
    note: "`Date` — when the message was originated, who must generate it, who must not, and what a recipient does when it is absent",
};

defects! {
    /// A 2xx, 3xx or 4xx response carrying no `Date`.
    ///
    /// **The sentence is a MUST and the entry is not an `error`, and the reason
    /// is that the sentence has a condition this observer cannot see.** § 6.6.1
    /// binds *an origin server with a clock*, and the very next sentence binds
    /// the other kind in the opposite direction — an origin server without a
    /// clock MUST NOT generate the field. So a response with no `Date` is
    /// either a server breaking a requirement or a server obeying one, and
    /// nothing on the wire distinguishes them. Reporting it at `error` would
    /// condemn the conformant half of a pair the message cannot tell apart.
    ///
    /// **What the absence costs is real even where it is permitted**, which is
    /// why the entry exists at all rather than being left unsaid. § 6.6.1 makes
    /// the recipient repair it: a recipient with a clock MUST record the time
    /// and append a `Date` before caching or forwarding. Every freshness
    /// calculation downstream is then anchored to when the response *arrived*
    /// rather than to when it was written, and the difference is the whole of
    /// the transit time. Nothing is malformed; the message simply does not say
    /// when it was written, and everyone after it has to guess.
    ///
    /// **1xx and 5xx are not asked**, because § 6.6.1 says `MAY` for those and
    /// a permission not taken up is not a defect worth a line in a report about
    /// a server error.
    ///
    /// `warn`, and `Unstated` is the honest strength: the `MUST` is quoted
    /// below and it binds a sender this rule cannot identify as the sender it
    /// binds. The level is argued here rather than derived.
    ///
    // cite(RFC 9110 § 6.6.1): "An origin server with a clock (as defined in Section 5.6.7) MUST generate a Date header field in all 2xx (Successful), 3xx (Redirection), and 4xx (Client Error) responses, and MAY generate a Date header field in 1xx (Informational) and 5xx (Server Error) responses."
    // cite(RFC 9110 § 6.6.1): "An origin server without a clock MUST NOT generate a Date header field."
    // cite(RFC 9110 § 6.6.1): "A recipient with a clock that receives a response message without a Date header field MUST record the time it was received and append a corresponding Date header field to the message's header section if it is cached or forwarded downstream."
    DATE_MISSING = {
        id: "date_missing",
        title: "A response does not say when it was written",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_6_6_1],
        strength: Strength::Unstated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry quotes a `MUST` and does not claim one, which is the whole
    /// reading: the keyword binds *an origin server with a clock*, and a
    /// message does not say whether its sender had one.
    #[test]
    fn a_must_with_a_condition_off_the_wire_is_not_a_stated_strength() {
        assert_eq!(DATE_MISSING.strength, Strength::Unstated);
        assert_eq!(DATE_MISSING.default_severity, Severity::Warn);
    }
}
