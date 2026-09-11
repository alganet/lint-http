// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Status-code defects — a response whose status describes an exchange that did
//! not happen.
//!
//! **The subject is the status code**, which is neither a field nor a
//! production: it is the response's own control data, and a status code that
//! contradicts its request is wrong in a way no field on either message is.
//! Every entry below is read out of *two* messages — what the server sent and
//! what the client asked for — which is what separates this subject from every
//! other one in this catalogue, where the defect is visible inside one message.
//!
//! **The first two share the word that names them.** A status code whose
//! definition is written in terms of a request field says that field arrived;
//! where it did not, nothing is malformed, nothing is prohibited, and nothing
//! was done twice — the server answered a question nobody asked.
//! `_unsolicited` is the ending for that, and `docs/development.md` carries the
//! argument for it beside the rest of the closed vocabulary.
//!
//! **The third is the same subject and a different word**, which is what keeps
//! the first two honest: a multipart 206 answering a single-range request is a
//! MUST NOT written out, about a response the client did invite. Where a
//! sentence prohibits the message, the entry is `_forbidden`; `_unsolicited` is
//! for the ones no sentence prohibits and the exchange refutes.
//!
//! All three default to `warn`, which is the severity the rule reporting them
//! had already chosen for itself: a client handed a response it did not ask
//! for, or cannot parse, has to notice that on its own, and only one of the
//! three documents a prohibition.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::content_range::RFC_9110_15_3_7_2;
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
        spec: &[RFC_9110_15_3_7],
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
        spec: &[RFC_9110_15_5_17],
    }

    /// A 206 in its multipart form, answering a request that asked for one
    /// range. The status is right and the request did ask for something — what
    /// is prohibited is the *form*, and the sentence gives the reason with the
    /// prohibition: a client that did not ask for multiple parts might have no
    /// way to read them, so a response it cannot parse is what it gets for
    /// asking correctly.
    ///
    /// `_forbidden` rather than `_unsolicited`, and the difference is worth
    /// keeping straight beside its neighbours: those two entries are a status
    /// code answering a request that named no range at all, with no sentence
    /// prohibiting them; this one is a MUST NOT, written out, about a message
    /// the client did invite.
    ///
    /// The section is `Content-Range`'s as well — § 15.3.7.2 states two
    /// prohibitions, one about the field in the header section and one about
    /// the response's form — and the [`SpecRef`] sits beside the entry that was
    /// written first.
    ///
    // cite(RFC 9110 § 15.3.7.2): "A server MUST NOT generate a multipart response to a request for a single range, since a client that does not request multiple parts might not support multipart responses."
    STATUS_206_MULTIPART_FORBIDDEN = {
        id: "status_206_multipart_forbidden",
        title: "A multipart 206 answers a request that asked for a single range",
        message: "multipart/byteranges 206 response sent to a request for a single range",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_15_3_7_2],
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
        for def in [
            &STATUS_206_UNSOLICITED,
            &STATUS_416_UNSOLICITED,
            &STATUS_206_MULTIPART_FORBIDDEN,
        ] {
            assert!(def.id.starts_with("status_"), "{} is not a status", def.id);
            assert!(!def.id.contains("range"), "{} names a field", def.id);
        }
    }

    /// The two words this subject uses are not interchangeable: a sentence
    /// prohibiting the message makes the entry `_forbidden`, and `_unsolicited`
    /// is for the ones no sentence prohibits — where what refutes the message is
    /// the request it answers.
    #[test]
    fn only_the_entry_a_sentence_prohibits_is_the_forbidden_one() {
        assert!(STATUS_206_MULTIPART_FORBIDDEN.id.ends_with("_forbidden"));
        for def in [&STATUS_206_UNSOLICITED, &STATUS_416_UNSOLICITED] {
            assert!(def.id.ends_with("_unsolicited"), "{}", def.id);
        }
    }

    /// Every entry carries its whole message, which is the shape of the defect
    /// rather than a convenience: what is wrong here is the pairing of two
    /// messages and never a value one of them wrote, so there is nothing for a
    /// site to interpolate and no wording that varies between one finding and
    /// the next.
    #[test]
    fn no_entry_leaves_its_message_to_the_site() {
        for def in [
            &STATUS_206_UNSOLICITED,
            &STATUS_416_UNSOLICITED,
            &STATUS_206_MULTIPART_FORBIDDEN,
        ] {
            assert!(!def.message.is_empty(), "{} holds no message", def.id);
        }
    }
}
