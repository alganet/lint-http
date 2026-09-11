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
//! **The fourth widens what "the other message" can be evidence of.** A `101`
//! is read against the request's *version*, not against a field on it: three
//! documents each say their version has no place for the code, and none of them
//! prohibits it in so many words. So the word is `_unsolicited` for the same
//! reason the first two carry it — what refutes the response is the exchange —
//! and the piece of the exchange doing the refuting is control data on the
//! request line rather than a header field. **A version that withholds the
//! mechanism a client would ask with is a client that could not have asked.**
//!
//! **The fifth is the first entry here that ranks above the rule reporting it**,
//! and the line it draws is worth having: a `101` that switches to a protocol
//! the client never named is not a status code describing an exchange wrongly —
//! it is a connection that has *left HTTP* for something the client cannot
//! speak. There is no later message to repair it in, which is the argument
//! `upgrade_missing` and `upgrade_empty` already make for `error`.
//!
//! So four of the five default to `warn`, which is the severity the rules
//! reporting them had already chosen for themselves: a client handed a response
//! it did not ask for, or cannot parse, has to notice that on its own, and the
//! exchange carries on around it. **The question that separates the levels is
//! not how strong the sentence is but whether the exchange can continue** — two
//! of the five quote a prohibition, and only one of those two ends the
//! conversation.

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

/// The `Upgrade` mechanism, and the one sentence in it about HTTP/1.0: the
/// version that has the field and may not act on it.
pub const RFC_9110_7_8: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("7.8"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8",
    note: "Upgrade — the mechanism a 101 answers, the MUST NOT on switching to a protocol the client did not indicate, and the MUST that a server ignore an `Upgrade` received in an HTTP/1.0 request",
};

/// HTTP/2's account of the field and the status code: neither is part of the
/// version.
pub const RFC_9113_8_6: SpecRef = SpecRef {
    spec: "RFC 9113",
    section: Some("8.6"),
    url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.6",
    note: "The Upgrade Header Field — HTTP/2 does not support the 101 status code, and says why: its semantics are not applicable to a multiplexed protocol",
};

/// HTTP/3's, which withholds the mechanism and the code in one sentence.
pub const RFC_9114_4_5: SpecRef = SpecRef {
    spec: "RFC 9114",
    section: Some("4.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.5",
    note: "HTTP Upgrade — the only place RFC 9114 mentions 101, withholding the upgrade mechanism and the status code together",
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

    /// A `101` carried by a version that has no upgrade mechanism to answer.
    /// The status code announces a connection changing protocol *via the
    /// `Upgrade` field*, and each of the three versions below takes one of the
    /// two halves away: HTTP/1.0 has the field and requires a server to ignore
    /// it, HTTP/2 keeps the mechanism out and says the code's semantics do not
    /// apply to a multiplexed protocol, HTTP/3 withholds both in one sentence.
    /// Whatever such a request wrote, it could not have invited this answer.
    ///
    /// **Three documents, one defect, and this is the entry that argued for
    /// `spec` being a slice.** All three sections are named and no finding
    /// carries any of them: the version is known at the site, which names its
    /// own governing section in the message. Splitting the entry per version
    /// would give one defect three ids for an operator to silence separately,
    /// which is the duplication this catalogue exists to remove — and the ids
    /// would name the versions rather than the defect.
    ///
    /// **`_unsolicited` rather than `_forbidden`, and the sentences are the
    /// reason.** Only the HTTP/1.0 one carries a keyword at all, and its MUST is
    /// addressed to what a server does with a *field* rather than to the status
    /// code; the other two state that a version does not support the code, which
    /// is a definition withheld and not a prohibition. That is the test
    /// `status_206_unsolicited` was written against and
    /// `status_206_multipart_forbidden` fails: where a sentence prohibits the
    /// message the entry is `_forbidden`, and here none does.
    ///
    /// `warn`, with the rest of the subject. A `101` is an interim response, and
    /// a recipient of a 1xx it does not expect is entitled to read past it and
    /// wait for the final one — so an exchange carrying this defect is confused
    /// rather than stuck, which is the line the `upgrade_*` entries sit on the
    /// other side of.
    ///
    // cite(RFC 9110 § 7.8): "A server that receives an Upgrade header field in an HTTP/1.0 request MUST ignore that Upgrade field."
    // cite(RFC 9113 § 8.6): "HTTP/2 does not support the 101 (Switching Protocols) informational status code (Section 15.2.2 of [HTTP])."
    // cite(RFC 9114 § 4.5): "HTTP/3 does not support the HTTP Upgrade mechanism (Section 7.8 of [HTTP]) or the 101 (Switching Protocols) informational status code (Section 15.2.2 of [HTTP])."
    STATUS_101_UNSOLICITED = {
        id: "status_101_unsolicited",
        title: "101 Switching Protocols is sent on a version with no upgrade mechanism",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_7_8, RFC_9113_8_6, RFC_9114_4_5],
    }

    /// A `101` switching to a protocol the client did not name. The version has
    /// the mechanism and the exchange used it; what is wrong is *which* protocol
    /// the connection now speaks.
    ///
    /// **One entry for three faces of one sentence**, which is how the rule
    /// reporting it already described them: the request carried no `Upgrade`
    /// field at all, or carried one with no protocol on it, or named protocols
    /// and the response chose a different one. In all three the response's
    /// protocol is one the request did not indicate, which is the whole of the
    /// MUST NOT — and an operator silencing this is silencing a server that
    /// switches to protocols of its own choosing, not three separate policies.
    ///
    /// `_forbidden`, because § 7.8 states it as a MUST NOT addressed to the
    /// server. That is the line
    /// [`STATUS_101_UNSOLICITED`] sits on the other side of: there, three
    /// documents withhold a definition and none prohibits the message.
    ///
    /// **`error`, one level above the rule that reports it**, and the reason is
    /// not the strength of the sentence. A `101` hands the connection over:
    /// everything after the response's empty line is spoken in the new protocol,
    /// so a client that never named it has nothing to say and nothing to wait
    /// for. That is the same argument
    /// [`upgrade_missing`](crate::violations::upgrade::UPGRADE_MISSING) makes,
    /// and it is what separates this entry from the four `warn`s beside it,
    /// where the exchange survives the defect.
    ///
    // cite(RFC 9110 § 7.8): "A server MUST NOT switch to a protocol that was not indicated by the client in the corresponding request's Upgrade header field."
    STATUS_101_PROTOCOL_FORBIDDEN = {
        id: "status_101_protocol_forbidden",
        title: "A 101 switches to a protocol the client did not indicate",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_7_8],
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
            &STATUS_101_UNSOLICITED,
            &STATUS_101_PROTOCOL_FORBIDDEN,
        ] {
            assert!(def.id.starts_with("status_"), "{} is not a status", def.id);
            assert!(!def.id.contains("range"), "{} names a field", def.id);
            assert!(!def.id.contains("upgrade"), "{} names a field", def.id);
        }
    }

    /// One defect stated by three documents: the id names none of the versions,
    /// because the same server sending the same response over any of them has
    /// made one mistake and an operator silencing it silences one thing.
    #[test]
    fn the_version_entry_names_three_sections_and_no_version() {
        assert_eq!(
            STATUS_101_UNSOLICITED.spec,
            [RFC_9110_7_8, RFC_9113_8_6, RFC_9114_4_5]
        );
        for word in ["http", "1_0", "2", "3"] {
            assert!(
                !STATUS_101_UNSOLICITED.id.contains(word),
                "{} names a version",
                STATUS_101_UNSOLICITED.id,
            );
        }
    }

    /// The two words this subject uses are not interchangeable: a sentence
    /// prohibiting the message makes the entry `_forbidden`, and `_unsolicited`
    /// is for the ones no sentence prohibits — where what refutes the message is
    /// the request it answers.
    #[test]
    fn only_the_entry_a_sentence_prohibits_is_the_forbidden_one() {
        assert!(STATUS_206_MULTIPART_FORBIDDEN.id.ends_with("_forbidden"));
        assert!(STATUS_101_PROTOCOL_FORBIDDEN.id.ends_with("_forbidden"));
        for def in [
            &STATUS_206_UNSOLICITED,
            &STATUS_416_UNSOLICITED,
            &STATUS_101_UNSOLICITED,
        ] {
            assert!(def.id.ends_with("_unsolicited"), "{}", def.id);
        }
    }

    /// The range entries carry their whole message, which is the shape of the
    /// defect rather than a convenience: what is wrong there is the pairing of
    /// two messages and never a value one of them wrote, so there is nothing for
    /// a site to interpolate and no wording that varies between findings.
    ///
    /// **The 101 entry is the exception and its reason is the slice.** It names
    /// three sections, so its findings carry no citation and the message has to
    /// say which version's sentence governs — a value the request line did
    /// write. An entry naming one sentence has nothing to interpolate; an entry
    /// naming several always does.
    #[test]
    fn only_the_entry_with_several_sentences_leaves_its_message_to_the_site() {
        for def in [
            &STATUS_206_UNSOLICITED,
            &STATUS_416_UNSOLICITED,
            &STATUS_206_MULTIPART_FORBIDDEN,
        ] {
            assert_eq!(def.spec.len(), 1, "{}", def.id);
            assert!(!def.message.is_empty(), "{} holds no message", def.id);
        }
        assert!(STATUS_101_UNSOLICITED.spec.len() > 1);
        assert!(STATUS_101_UNSOLICITED.message.is_empty());
    }

    /// The level is decided by whether the exchange can continue, and not by
    /// which entries quote a prohibition. Two of the five do; one of those two
    /// hands the connection to a protocol the client cannot speak, and it is the
    /// only `error` here.
    #[test]
    fn the_entry_that_ends_the_conversation_is_the_only_error() {
        assert_eq!(
            STATUS_101_PROTOCOL_FORBIDDEN.default_severity,
            Severity::Error
        );
        for def in [
            &STATUS_206_UNSOLICITED,
            &STATUS_416_UNSOLICITED,
            &STATUS_206_MULTIPART_FORBIDDEN,
            &STATUS_101_UNSOLICITED,
        ] {
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
        }
    }
}
