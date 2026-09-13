// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Proxy-Authenticate` defects — one entry, about a field with nowhere to go.
//!
//! What the value *is* belongs to [`challenge`](crate::violations::challenge),
//! which is the production and not the field carrying it, and a `407` that
//! carries no challenge at all is the status code's defect and lives in
//! [`status`](crate::violations::status). What is left is the field arriving
//! where its own definition leaves a client with nothing to do.
//!
//! **The asymmetry with `WWW-Authenticate` is the whole subject.** § 11.6.1
//! spends a sentence permitting its field on any response — a server hinting
//! that credentials would change the answer is doing what the document says it
//! may — and § 11.7.1 spends none. A permission that was never written is not a
//! prohibition either, so nothing here is a conformance finding; what § 11.7.1
//! does say is that this field addresses the client that chose this proxy, and
//! outside a `407` nothing tells that client what to do with the challenge.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field: at least one in every `407` a proxy generates, and the sentence
/// limiting it to the next outbound client.
pub const RFC_9110_11_7_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("11.7.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7.1",
    note: "`Proxy-Authenticate` — at least one field in each 407 a proxy generates, and the sentence limiting the field to the next outbound client on the response chain, which is all that stands behind an advisory finding on any other status",
};

defects! {
    /// A `Proxy-Authenticate` on a response that is not a `407`.
    ///
    /// **`_redundant`, the ending that condemns nothing.** No sentence forbids
    /// the field here — the definition puts no condition on the status code —
    /// so `_forbidden` would claim a prohibition that does not exist and
    /// `_invalid` a value that is fine. What the finding says is that the
    /// header was avoidable: it addresses the next outbound client, and outside
    /// the one status that tells that client to authenticate there is nothing
    /// for it to do with a challenge.
    ///
    /// **Deliberately not reported for `WWW-Authenticate`**, and the difference
    /// is a sentence rather than a judgement: § 11.6.1 explicitly permits that
    /// field on other responses, to hint that credentials might change the
    /// answer. This rule used to report every such response, with a published
    /// example and two tests asserting it.
    ///
    /// `info`, which is where `_redundant` starts.
    ///
    // cite(RFC 9110 § 11.7.1): "Unlike WWW-Authenticate, the Proxy-Authenticate header field applies only to the next outbound client on the response chain."
    PROXY_AUTHENTICATE_REDUNDANT = {
        id: "proxy_authenticate_redundant",
        title: "Proxy-Authenticate arrives on a status that gives it nothing to do",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_11_7_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim the ending carries, asserted because it is easy to mistake
    /// this for a prohibition: nothing forbids the field here, so the entry
    /// never rises above the level `_redundant` starts at.
    #[test]
    fn a_field_nothing_forbids_stays_advisory() {
        assert_eq!(
            PROXY_AUTHENTICATE_REDUNDANT.default_severity,
            Severity::Info
        );
    }
}
