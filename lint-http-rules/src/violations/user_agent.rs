// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `User-Agent` defects — a field whose absence is asked about and excused in
//! one sentence.
//!
//! § 10.1.5 asks a user agent to send the field *unless specifically
//! configured not to do so*, and § 17.13 says why one is: the value can help
//! identify a specific device. Both halves matter here, and the second is why
//! the single entry below is ranked the way it is.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// User-Agent: what the field carries, the SHOULD, and the exception written
/// into the same sentence.
pub const RFC_9110_10_1_5: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("10.1.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5",
    note: "`A user agent SHOULD send a User-Agent header field in each request unless specifically configured not to do so.` The exception is a fact about the sender's configuration rather than about the request, so a conforming suppression and a plain omission are the same absence here and both are reported",
};

defects! {
    /// A request with no `User-Agent`.
    ///
    /// **The SHOULD and its exception are one sentence, and only the SHOULD is
    /// on the wire.** A client specifically configured not to send the field is
    /// conforming; a client that simply omitted it is not; and the two produce
    /// byte-identical requests. So the entry reports the absence and leaves the
    /// distinction to the operator, who is the one who knows how the client is
    /// configured.
    ///
    /// **`info`, because the conforming case has a good reason behind it.**
    /// § 17.13 says a `User-Agent` can carry enough to identify a specific
    /// device, so suppressing it is a deliberate privacy choice this rule
    /// cannot see — ranking the absence higher would rank that choice as a
    /// defect.
    ///
    // cite(RFC 9110 § 10.1.5): "The "User-Agent" header field contains information about the user agent originating the request"
    USER_AGENT_MISSING = {
        id: "user_agent_missing",
        title: "A request does not say what sent it",
        message: "Request missing User-Agent header",
        default_severity: Severity::Info,
        spec: &[RFC_9110_10_1_5],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The conforming case and the defect are the same bytes, and the
    /// conforming case is a privacy choice — which is the argument for the
    /// severity, and the reason it is written on the entry.
    #[test]
    fn the_absence_is_ranked_for_the_conforming_case_it_cannot_be_told_from() {
        assert_eq!(USER_AGENT_MISSING.default_severity, Severity::Info);
    }
}
