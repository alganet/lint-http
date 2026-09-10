// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Status-code defects — a response whose status describes an exchange that did
//! not happen.
//!
//! **The subject is the status code**, which is neither a field nor a
//! production: it is the response's own control data, and a status code that
//! contradicts its request is wrong in a way no field on either message is.
//! Both entries below are read out of *two* messages — the status the server
//! sent and the field the client did not — which is what separates them from
//! every other subject in this catalogue, where the defect is visible inside
//! one message.
//!
//! **What the entries have in common is the word that names them.** A status
//! code whose definition is written in terms of a request field says that
//! field arrived; where it did not, nothing is malformed, nothing is
//! prohibited, and nothing was done twice — the server answered a question
//! nobody asked. `_unsolicited` is the ending for that, and
//! `docs/development.md` carries the argument for it beside the rest of the
//! closed vocabulary.
//!
//! Both default to `warn`, which is the severity the rule reporting them had
//! already chosen for itself: a client that asked for no part of a
//! representation and is handed one has to notice that on its own, and the
//! documents describe the status codes rather than forbidding them here.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// What a 206 says it is doing, and the field a single-part one has to carry
/// while it does.
pub const RFC_9110_15_3_7: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.3.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7",
    note: "206 Partial Content: the status code is a range request being fulfilled, and a single-part 206 MUST carry a `Content-Range` describing the enclosed range",
};

/// What a 416 says it is doing — a rejection of the ranges the request named —
/// and the field a server answering a byte-range request ought to send with it.
pub const RFC_9110_15_5_17: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.5.17"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.17",
    note: "416 Range Not Satisfiable: the status code is the rejection of the ranges in the request's `Range` field; a server answering a *byte*-range request SHOULD include `Content-Range: bytes */<complete-length>`",
};

defects! {
    /// A 206 answering a request that named no range. The status code is
    /// defined as a range request being fulfilled, so a response carrying it
    /// asserts a request that is not there to read — and the client, which
    /// asked for a representation and is being handed a part of one, has no
    /// field of its own to blame.
    ///
    /// **No sentence prohibits this**, and none is needed: the definition says
    /// what the code indicates, and here it indicates something that did not
    /// happen. The finding stands whatever the response's `Content-Range` says,
    /// including when it says nothing — a 206 to a request with no `Range` is
    /// already wrong before its fields are read.
    ///
    // cite(RFC 9110 § 15.3.7): "The 206 (Partial Content) status code indicates that the server is successfully fulfilling a range request for the target resource by transferring one or more parts of the selected representation."
    STATUS_206_UNSOLICITED = {
        id: "status_206_unsolicited",
        title: "206 Partial Content answers a request that asked for no range",
        message: "206 Partial Content response received but request did not include a Range header",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_15_3_7),
    }

    /// A 416 answering a request that named no range. The status code is the
    /// rejection of a set of ranges the request wrote, so with no `Range` field
    /// there is no set for it to have rejected.
    ///
    /// The one request that names a range elsewhere is not this defect: a
    /// partial `PUT` writes its range in the request's own `Content-Range`, and
    /// a server refusing *that* has something to be about. § 14.5 leaves the
    /// exchange to private agreement between the two parties, so the rule
    /// reading this entry excludes it at the site — a condition on when the
    /// defect exists, rather than a second defect.
    ///
    // cite(RFC 9110 § 15.5.17): "The 416 (Range Not Satisfiable) status code indicates that the set of ranges in the request's Range header field (Section 14.2) has been rejected either because none of the requested ranges are satisfiable or because the client has requested an excessive number of small or overlapping ranges (a potential denial of service attack)."
    STATUS_416_UNSOLICITED = {
        id: "status_416_unsolicited",
        title: "416 Range Not Satisfiable answers a request that named no range",
        message: "416 Range Not Satisfiable response sent to a request with no Range header",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_15_5_17),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The status code is the subject, and neither `Range` nor `Content-Range`
    /// is: both fields are well-formed or absent in these findings, and an
    /// operator silencing `status_206_unsolicited` is silencing a status code
    /// sent where nothing invited it — not anything about a range field.
    #[test]
    fn each_id_names_the_status_and_not_the_field_it_is_read_against() {
        for def in [&STATUS_206_UNSOLICITED, &STATUS_416_UNSOLICITED] {
            assert!(def.id.starts_with("status_"), "{} is not a status", def.id);
            assert!(!def.id.contains("range"), "{} names a field", def.id);
        }
    }

    /// Both entries carry their whole message, which is the shape of the defect
    /// rather than a convenience: what is wrong is that a field is *absent*, so
    /// there is no value the site could interpolate and no wording that varies
    /// between one finding and the next.
    #[test]
    fn neither_entry_leaves_its_message_to_the_site() {
        for def in [&STATUS_206_UNSOLICITED, &STATUS_416_UNSOLICITED] {
            assert!(!def.message.is_empty(), "{} holds no message", def.id);
        }
    }
}
