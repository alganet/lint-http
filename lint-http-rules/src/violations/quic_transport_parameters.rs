// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! QUIC transport parameter defects — limits that block what HTTP/3 needs.
//!
//! The third subject in this catalogue that is a protocol element rather than a
//! field or a production, after [`status`](crate::violations::status) and the
//! rest of the control data: these are the contents of the
//! `quic_transport_parameters` TLS extension, read out of a connection rather
//! than out of a message.
//!
//! **Every entry here is about a value that is legal.** RFC 9000 § 18.2 permits
//! zero for each of these limits and says what a zero means — the peer waits
//! for a `MAX_STREAMS` or `MAX_DATA` frame before it may proceed — and RFC 9114
//! asks for non-zero minimums in a SHOULD. So the endings are all `_invalid`,
//! the row for a value that is grammatical and unacceptable past the grammar,
//! and the ranking is by what an endpoint is prevented from doing rather than
//! by any prohibition.
//!
//! **What is deliberately not here is the window HTTP/3 does not use.**
//! `initial_max_stream_data_bidi_local` bounds streams the *sender* of these
//! parameters initiates, and these are always a server's — so it bounds
//! server-initiated bidirectional streams, which § 6.1 says in as many words
//! that HTTP/3 does not use. A zero there is a correct configuration, and the
//! rule reporting it quoted that very sentence one line above the finding.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Transport Parameter Definitions: what each limit means, and that zero is a
/// permitted value with a defined effect.
pub const RFC_9000_18_2: SpecRef = SpecRef {
    spec: "RFC 9000",
    section: Some("18.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2",
    note: "Transport Parameter Definitions — what each initial limit means, and that a zero or absent value is legal with a defined effect rather than a defect",
};

/// Bidirectional Streams: the SHOULD asking a server for non-zero minimums on
/// both the count of request streams and their window.
pub const RFC_9114_6_1: SpecRef = SpecRef {
    spec: "RFC 9114",
    section: Some("6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1",
    note: "Bidirectional Streams — an HTTP/3 server SHOULD configure non-zero minimums for the number of permitted streams and the initial stream flow-control window, and HTTP/3 does not use server-initiated bidirectional streams",
};

/// Unidirectional Streams: the control and QPACK streams, and what restricting
/// their window costs.
pub const RFC_9114_6_2: SpecRef = SpecRef {
    spec: "RFC 9114",
    section: Some("6.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2",
    note: "Unidirectional Streams — restricting the number or the flow-control window of these streams makes the peer reach the limit early and block, which for HTTP/3 means the control and QPACK streams",
};

defects! {
    /// A server advertising no room for request streams: either
    /// `initial_max_streams_bidi` or `initial_max_stream_data_bidi_remote` set
    /// to zero.
    ///
    /// **One entry for both, because § 6.1 asks for them in one breath** — "the
    /// number of permitted streams and the initial stream flow-control window"
    /// — and a client meets the same wall either way: no request may proceed
    /// until a `MAX_STREAMS` or `MAX_STREAM_DATA` frame arrives. The message
    /// names which limit was zero.
    ///
    /// The `_remote` half is the one worth being careful about. These
    /// parameters are a server's, so the *peer*-initiated bidirectional window
    /// is the one bounding the client's request streams; the locally initiated
    /// one bounds streams HTTP/3 never opens and is not reported at all.
    ///
    /// `warn`: the SHOULD is real and so is the stall, but a server that sends
    /// the frame promptly is conforming and working.
    ///
    // cite(RFC 9114 § 6.1): "In order to permit these streams to open, an HTTP/3 server SHOULD configure non-zero minimum values for the number of permitted streams and the initial stream flow-control window."
    QUIC_REQUEST_STREAM_LIMIT_INVALID = {
        id: "quic_request_stream_limit_invalid",
        title: "QUIC parameters leave no room for an HTTP/3 request stream",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9114_6_1],
        strength: Strength::Should,
    }

    /// `initial_max_data` set to zero: no data may be sent on the connection
    /// until a `MAX_DATA` frame raises the limit.
    ///
    /// Broader than the entry above — this is connection-level, so it stalls
    /// the control and QPACK streams along with the request ones — and weaker
    /// evidence, which is why it ranks below. § 6.1's SHOULD is about *stream*
    /// limits and does not reach this parameter; what is quoted here is § 18.2
    /// defining it, and § 18.2 permits the zero. The finding is this crate's
    /// judgement that a server which advertises no connection window and then
    /// has to raise it has configured something it did not mean.
    ///
    /// `warn`, for a heuristic with a definition behind it and no requirement.
    ///
    // cite(RFC 9000 § 18.2): "the initial value for the maximum amount of data that can be sent on the connection"
    QUIC_CONNECTION_FLOW_CONTROL_INVALID = {
        id: "quic_connection_flow_control_invalid",
        title: "QUIC parameters advertise no connection-level flow control",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9000_18_2],
    }

    /// `initial_max_stream_data_uni` set to zero, which for HTTP/3 is the
    /// window on the control and QPACK streams.
    ///
    /// § 6.2 does not phrase this as a limit to configure but as a consequence
    /// to avoid: an endpoint that restricts these streams makes its peer reach
    /// the limit early and block. A zero window is that restriction at its
    /// extreme, and the streams it starves are the ones HTTP/3 needs before any
    /// request can be encoded — `SETTINGS` on the control stream, the dynamic
    /// table on the QPACK ones.
    ///
    /// `warn`, with the request-stream entry: the connection is not broken, and
    /// nothing moves until a frame raises the limit.
    ///
    // cite(RFC 9114 § 6.2): "Endpoints that excessively restrict the number of streams or the flow-control window of these streams will increase the chance that the remote peer reaches the limit early and becomes blocked."
    QUIC_CONTROL_STREAM_LIMIT_INVALID = {
        id: "quic_control_stream_limit_invalid",
        title: "QUIC parameters leave no room for HTTP/3's control streams",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9000_18_2],
    }

    /// An idle timeout that reclaims nothing: absent, zero, or larger than the
    /// ceiling this crate considers reasonable.
    ///
    /// **Uncited, and both halves are the reason.** § 18.2 says outright that
    /// omitting the parameter or sending zero *disables* the idle timeout, so
    /// the first half reports a documented behaviour rather than a defect; and
    /// no sentence anywhere sets a maximum, so the second half measures against
    /// a bound that belongs to this crate. The same shape as
    /// [`keep_alive_timeout_invalid`](crate::violations::keep_alive::KEEP_ALIVE_TIMEOUT_INVALID),
    /// and a reference on either half would dress a deployment's policy as a
    /// requirement.
    ///
    /// One entry over both, because what the finding says is one thing: idle
    /// connections on this endpoint are not being reclaimed. The message says
    /// whether the timeout was disabled or merely long.
    ///
    /// `info`.
    QUIC_IDLE_TIMEOUT_INVALID = {
        id: "quic_idle_timeout_invalid",
        title: "QUIC idle timeout reclaims nothing",
        message: "",
        default_severity: Severity::Info,
        spec: &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ranking, which is by what an endpoint cannot do and never by a
    /// prohibition — there is none to rank by. A timeout that reclaims nothing
    /// costs memory; a limit of zero costs the exchange.
    #[test]
    fn a_stalled_exchange_outranks_an_unreclaimed_connection() {
        assert!(
            QUIC_IDLE_TIMEOUT_INVALID.default_severity
                < QUIC_REQUEST_STREAM_LIMIT_INVALID.default_severity
        );
        assert_eq!(
            QUIC_CONTROL_STREAM_LIMIT_INVALID.default_severity,
            QUIC_REQUEST_STREAM_LIMIT_INVALID.default_severity
        );
    }

    /// The one entry with no reference, and the assertion keeps the reason
    /// honest: § 18.2 permits the disabled timeout and no section bounds a long
    /// one, so both halves are this crate's judgement.
    #[test]
    fn the_timeout_entry_names_nothing_because_nothing_states_it() {
        assert!(QUIC_IDLE_TIMEOUT_INVALID.spec.is_empty());
    }
}
