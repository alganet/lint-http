// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `TE` defects — the one member the versions that have no connection-specific
//! fields still let a request write.
//!
//! `TE` states what transfer codings a client will accept, which is hop-by-hop
//! control and is therefore a connection-specific field: over HTTP/2 and HTTP/3
//! its presence would be
//! [`field_connection_specific_forbidden`](crate::violations::field::FIELD_CONNECTION_SPECIFIC_FORBIDDEN)
//! like `Connection`'s. Both version documents then take it back out, for one
//! direction and one value — a *request* may carry it, and when it does it may
//! hold nothing but `trailers`. That narrowing is what the entry below is for,
//! and it exists only on those versions: over HTTP/1.1 a `TE: gzip` is an
//! ordinary well-formed value.
//!
//! **A second entry arrived from a different direction**: RFC 9112 § 7.4
//! forbids a client from naming `chunked` here, on every version, because
//! chunked is not something a recipient may decline. Both entries are about
//! what this field may say rather than about the productions it says it in —
//! which is what makes them the field's and not
//! [`transfer_coding`](crate::violations::transfer_coding)'s.
//!
//! **The subject is the field, and only the part of it those two documents
//! narrow.** Whether a member derives from `t-codings` at all — its `token`, its
//! `weight`, its `transfer-parameter` — is `te_header_valid`'s reading and is
//! reported under the `token`, `qvalue` and `parameter` subjects, on every
//! version. What is here is the value being *permitted and yet not `trailers`*,
//! which no other rule asks.
//!
//! **Two later entries are the field's for a different reason: they are what
//! RFC 9110 § 10.1.4 says about `TE` and about nothing else.** The keyword
//! occupies the whole of its alternative, so a parameter or a weight hung off
//! it derives from no `t-codings`; and a sender of the field owes a `TE`
//! connection option beside it, which is a requirement on the *message* rather
//! than on any value in it. Neither is a production's defect — every
//! production involved is intact — which is what keeps them here.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;
use crate::violations::field::{RFC_9113_8_2_2, RFC_9114_4_2};

/// The field's own section in RFC 9112: what it is for, the ranking `q` it
/// admits, and the one coding name it may not carry.
pub const RFC_9112_7_4: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("7.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7.4",
    note: "TE — the codings a client will accept, the `q` pseudo-parameter that ranks them, and the MUST NOT on naming `chunked`",
};

/// The field's own definition in RFC 9110: what a member is, and the
/// connection option a sender owes beside it.
pub const RFC_9110_10_1_4: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("10.1.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4",
    note: "TE — what a member states, the grammar of its parameters, and the `TE` connection option a sender of the field MUST also send",
};

/// The collected grammar, where `t-codings` is written out as the alternation
/// the keyword occupies half of.
pub const RFC_9110_A: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("A"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A",
    note: "The collected grammar, where the list construct is expanded for a sender and `t-codings` is written out — the alternation that gives the `trailers` keyword neither a parameter nor a weight",
};

defects! {
    /// A member of a request's `TE` that is not `trailers`, on a version whose
    /// document permits the field for that one keyword and nothing else. The
    /// member may be a perfectly good transfer coding — `gzip`, `deflate`,
    /// `chunked;q=0` — and that is beside the point: the field is present by an
    /// exception, and the exception is written with its own limit.
    ///
    /// `error`, with the rest of the connection-specific reading: both
    /// documents put this sentence inside the paragraph whose MUST NOT makes
    /// such a message malformed.
    ///
    /// **Both sentences, for the reason
    /// [`field_connection_specific_forbidden`](crate::violations::field::FIELD_CONNECTION_SPECIFIC_FORBIDDEN)
    /// holds both**: the exception is written once per version, by two
    /// documents in force at the same time, and neither is *the* one. They are
    /// the same two sections that entry names — the exception is a clause of
    /// the paragraph the prohibition is in — so the references are imported
    /// from there rather than spelled a second time. No finding carries either;
    /// each names the governing section in its own message. The comparison
    /// against the keyword folds case because `t-codings` writes it as an ABNF
    /// string, which is RFC 5234 § 2.3's sentence and the rule's own reading
    /// rather than this defect's.
    ///
    // cite(RFC 9113 § 8.2.2, label: the TE exception): "The only exception to this is the TE header field, which MAY be present in an HTTP/2 request; when it is, it MUST NOT contain any value other than "trailers"."
    // cite(RFC 9114 § 4.2, label: the TE exception): "The only exception to this is the TE header field, which MAY be present in an HTTP/3 request header; when it is, it MUST NOT contain any value other than "trailers"."
    TE_MEMBER_FORBIDDEN = {
        id: "te_member_forbidden",
        title: "A request's TE holds a member other than trailers",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9113_8_2_2, RFC_9114_4_2],
    }

    /// `chunked` named in a `TE`. The name is a real transfer coding and is
    /// ordinary in `Transfer-Encoding`; what makes it wrong here is that the
    /// field states what a client is *willing* to accept, and chunked is not
    /// something a client may decline — so naming it states nothing and
    /// occupies a list a recipient reads for preferences.
    ///
    /// The entry is the field's rather than the coding's, which is the line
    /// [`crate::violations::transfer_coding`] draws: a coding that defines no
    /// parameters defines none in either field, but this word is admissible in
    /// one field and forbidden in the other.
    ///
    // cite(RFC 9112 § 7.4): "A client MUST NOT send the chunked transfer coding name in TE; chunked is always acceptable for HTTP/1.1 recipients."
    TE_CHUNKED_FORBIDDEN = {
        id: "te_chunked_forbidden",
        title: "TE names the chunked coding, which cannot be declined",
        message: "A client must not send the chunked transfer coding name in TE; chunked is always acceptable for HTTP/1.1 recipients",
        default_severity: Severity::Warn,
        spec: &[RFC_9112_7_4],
    }

    /// A parameter or a weight written on the `trailers` keyword. The
    /// alternation gives the keyword the whole of its first alternative, and
    /// the alternative that admits either of those is the other one — so
    /// `TE: trailers;q=0.5` derives from neither, however ordinary it looks.
    ///
    /// **The nearest thing to a real reading behind it**: a weight ranks
    /// codings a client is willing to receive, and the keyword is not a coding.
    /// There is nothing for a preference to be *between*, which is why the
    /// grammar puts them in different alternatives rather than making the
    /// weight optional everywhere.
    ///
    /// The entry is the field's because `t-codings` is: no other field writes
    /// this alternation, and the coding half of it answers to
    /// [`transfer_coding`](crate::violations::transfer_coding) as it does
    /// everywhere else.
    ///
    // cite(RFC 9110 § A, label: t-codings): "t-codings = "trailers" / ( transfer-coding [ weight ] )"
    TE_TRAILERS_PARAMETER_FORBIDDEN = {
        id: "te_trailers_parameter_forbidden",
        title: "TE hangs a parameter or a weight off the trailers keyword",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_A],
    }

    /// A request carrying `TE` and no `TE` connection option in `Connection`.
    /// The field applies to one hop; the option is what tells an intermediary
    /// not to forward it. Without the option a proxy that does not implement
    /// the field passes it on, and a server two hops away reads a statement
    /// about a connection it is not on.
    ///
    /// **Asked only of the versions that have a `Connection` field**, which is
    /// the rule's reading and not this entry's: over HTTP/2 and HTTP/3 the
    /// option cannot be sent at all, so an entry demanding it would ask a
    /// sender to make its own message malformed.
    ///
    /// `warn` rather than `error` despite the MUST: nothing about this message
    /// is unreadable, and the defect is a guard that was not set rather than a
    /// statement that is wrong. What it risks is a *later* hop being misled,
    /// which no recipient of this message can detect.
    ///
    // cite(RFC 9110 § 10.1.4): "A sender of TE MUST also send a "TE" connection option within the Connection header field (Section 7.6.1) to inform intermediaries not to forward this field."
    TE_CONNECTION_OPTION_MISSING = {
        id: "te_connection_option_missing",
        title: "TE is sent without a TE connection option beside it",
        message: "Request carries a TE header field without a 'TE' connection option in Connection; TE applies to the immediate connection only, and the option is what stops an intermediary from forwarding it",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_10_1_4],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry names the member, not the version — the same request written
    /// over HTTP/2 and over HTTP/3 breaks the same narrowing, and the two
    /// documents differ in nothing but which version they name.
    #[test]
    fn one_entry_serves_both_versions_and_neither_names_it() {
        assert_eq!(TE_MEMBER_FORBIDDEN.id, "te_member_forbidden");
        assert!(!TE_MEMBER_FORBIDDEN.id.contains("http"));
        assert_eq!(TE_MEMBER_FORBIDDEN.spec, [RFC_9113_8_2_2, RFC_9114_4_2]);
        assert_eq!(TE_MEMBER_FORBIDDEN.default_severity, Severity::Error);
    }
}
