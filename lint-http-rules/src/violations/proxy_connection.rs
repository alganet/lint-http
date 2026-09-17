// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Proxy-Connection` defects — a field the core specifications describe only
//! in order to discourage it.
//!
//! There is one entry, and the subject exists to hold the reason it is not
//! `_forbidden`: RFC 9112 App. C.2.2 is the only place either core document
//! describes the field, it is written in the past tense, and what it says is
//! that clients are *encouraged* not to send it. Nothing prohibits it.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Keep-Alive Connections: what the field was for, why it did not work, and
/// the encouragement not to send it.
pub const RFC_9112_C_2_2: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("C.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#appendix-C.2.2",
    note: "Keep-Alive Connections — the only description of the field in either core document: an attempted fix for HTTP/1.0 proxies that did not understand Connection, recorded as unworkable, with clients encouraged not to send it in any request",
};

defects! {
    /// A request carrying `Proxy-Connection`.
    ///
    /// **`_obsolete` beside [`pragma_obsolete`](crate::violations::pragma)**,
    /// and for the same kind of reason read from a different angle: `Pragma`
    /// was defined and then deprecated, while this field was never defined by
    /// either core document at all — App. C.2.2 describes it in the past tense,
    /// as an attempt that did not work, and asks clients not to send it.
    ///
    /// **Not `_forbidden`**: "encouraged not to" is the strongest thing said
    /// about it anywhere, and an entry claiming a prohibition would be
    /// inventing one. Not `_redundant` either — the field is not doing
    /// something twice, it is doing something no recipient is required to
    /// understand.
    ///
    /// `info`. A proxy that ignores it is behaving correctly, and the risk the
    /// appendix records is about what a proxy that *does* honour it does to a
    /// connection it should have closed.
    ///
    /// **Induced, and it is the entry the marker was written for.** The field
    /// exists to be sent *to a proxy*: curl writes it only when configured with
    /// one, so a session run through this proxy provokes precisely what it then
    /// reports, and a capture taken with no proxy in the path cannot contain
    /// it. The finding stays true and stays the client's — it says something
    /// real about that client, and a client author can act on it — but a reader
    /// deserves to be told they are looking at a reflection before they go
    /// hunting for a bug in traffic that would not exist unmeasured.
    ///
    // cite(RFC 9112 § C.2.2): "As a result, clients are encouraged not to send the Proxy-Connection header field in any requests."
    PROXY_CONNECTION_OBSOLETE = {
        id: "proxy_connection_obsolete",
        title: "A request carries a field the specification asks clients not to send",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9112_C_2_2],
        induced: crate::violations::Induced::ByTheProxy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The strongest thing said about this field anywhere is "encouraged not
    /// to", so the entry claims no prohibition and is ranked accordingly.
    #[test]
    fn the_entry_claims_no_prohibition() {
        assert!(!PROXY_CONNECTION_OBSOLETE.id.ends_with("_forbidden"));
        assert_eq!(PROXY_CONNECTION_OBSOLETE.default_severity, Severity::Info);
    }

    /// The one entry in the catalogue that exists because a proxy is in the
    /// path. Asserted here, beside the reasoning, rather than only in the
    /// ceiling that counts them.
    #[test]
    fn the_entry_is_induced_by_the_instrument() {
        assert_eq!(
            PROXY_CONNECTION_OBSOLETE.induced,
            crate::violations::Induced::ByTheProxy,
        );
    }
}
