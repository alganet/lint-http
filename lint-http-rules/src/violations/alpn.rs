// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! ALPN protocol name defects — the octets that identify an application
//! protocol during the TLS handshake, and what an HTTP field can say wrongly
//! about them.
//!
//! The name is not an HTTP production at all: RFC 7301 defines it as a TLS
//! vector of octets, and HTTP fields carry it in whatever spelling their own
//! grammar allows — `Alt-Svc` writes a `protocol-id`, which is the name with
//! every non-`tchar` octet percent-encoded, so `http/1.1` travels as
//! `http%2F1.1`. **The entries here are about the name after that spelling is
//! undone**; how it was spelled is the carrying field's grammar and answers
//! under `token`, `uri` and the field's own rule.
//!
//! Which is why the length entry below can be stated at all: a limit measured
//! in octets means nothing against an escaped form, where one octet may be
//! three characters.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Where the name is defined, and the vector that carries it.
pub const RFC_7301_3_1: SpecRef = SpecRef {
    spec: "RFC 7301",
    section: Some("3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1",
    note: "The Application-Layer Protocol Negotiation Extension: protocol names are IANA-registered opaque byte strings, carried in a `ProtocolName` vector of at most 255 octets; §3.2 is the fatal alert a server sends when nothing is in common",
};

/// What an alternative service's protocol identifier is *for*, and what a
/// client does when the name it negotiated is not the one advertised.
pub const RFC_7838_2: SpecRef = SpecRef {
    spec: "RFC 7838",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-2",
    note: "Alternative Services Concepts: an alternative service is identified by an ALPN protocol name as per RFC 7301, a host and a port; §2.4 requires a client to treat a connection that does not negotiate the expected protocol as failed",
};

defects! {
    /// A name that cannot fit the vector carrying it. `ProtocolName` is length
    /// prefixed with one octet, so 255 is the ceiling, and a longer name is not
    /// something any ClientHello or ServerHello can express — the alternative
    /// is identified by nothing.
    ///
    /// No list is consulted for this one, which makes it the only entry in the
    /// subject that holds without configuration: it is arithmetic on the wire
    /// format rather than a question about which names a deployment serves.
    ///
    // cite(RFC 7301 § 3.1): "opaque ProtocolName<1..2^8-1>;"
    // cite(RFC 7301 § 3.1): ""ProtocolNameList" contains the list of protocols advertised by the client, in descending order of preference."
    ALPN_PROTOCOL_NAME_LENGTH_INVALID = {
        id: "alpn_protocol_name_length_invalid",
        title: "ALPN protocol name is longer than the vector that carries it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7301_3_1],
    }

    /// A well-formed name that this deployment does not serve. The sixth
    /// registry entry of the catalogue and the one whose list is *narrower*
    /// than the registry on purpose: IANA's table is Expert Review and gains
    /// entries between releases, while the useful question about an
    /// advertisement is whether the alternative answers to that name here.
    ///
    /// The comparison is byte-exact, because an ALPN protocol name is its
    /// precise octets — `H2` is not `h2` — which is the one place a registry
    /// entry in this catalogue does *not* fold case.
    ///
    /// `warn`: an advertisement nobody can use costs a client one failed
    /// connection and a fallback, which is a deployment defect rather than a
    /// malformed message.
    ///
    // cite(RFC 7838 § 2): "The ALPN protocol name is used to identify the application protocol or suite of protocols used by the alternative service."
    ALPN_PROTOCOL_NAME_UNREGISTERED = {
        id: "alpn_protocol_name_unregistered",
        title: "ALPN protocol name is not one this deployment serves",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7838_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One entry needs configuration and the other does not, which is the whole
    /// difference between them: 255 octets is a fact about the wire format, and
    /// membership is a fact about a deployment.
    #[test]
    fn the_length_entry_is_the_one_that_needs_no_list() {
        assert_eq!(ALPN_PROTOCOL_NAME_LENGTH_INVALID.spec, [RFC_7301_3_1]);
        assert_eq!(ALPN_PROTOCOL_NAME_UNREGISTERED.spec, [RFC_7838_2]);
        assert_eq!(
            ALPN_PROTOCOL_NAME_LENGTH_INVALID.default_severity,
            Severity::Warn
        );
    }
}
