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
//! The exception, in the two documents that write it:
//
// cite(RFC 9113 § 8.2.2, label: the TE exception): "The only exception to this is the TE header field, which MAY be present in an HTTP/2 request; when it is, it MUST NOT contain any value other than "trailers"."
// cite(RFC 9114 § 4.2, label: the TE exception): "The only exception to this is the TE header field, which MAY be present in an HTTP/3 request header; when it is, it MUST NOT contain any value other than "trailers"."

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field's own section in RFC 9112: what it is for, the ranking `q` it
/// admits, and the one coding name it may not carry.
pub const RFC_9112_7_4: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("7.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-7.4",
    note: "TE — the codings a client will accept, the `q` pseudo-parameter that ranks them, and the MUST NOT on naming `chunked`",
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
    /// **No `spec`, for the reason
    /// [`field_connection_specific_forbidden`](crate::violations::field::FIELD_CONNECTION_SPECIFIC_FORBIDDEN)
    /// carries none**: the sentence is written once per version, by two
    /// documents in force at the same time, and an entry holds one reference.
    /// Both are quoted above the entry instead, where neither is being claimed
    /// as *the* sentence, and the finding names the governing section itself.
    /// The comparison against the keyword folds case because `t-codings` writes
    /// it as an ABNF string, which is RFC 5234 § 2.3's sentence and the rule's
    /// own reading rather than this defect's.
    TE_MEMBER_FORBIDDEN = {
        id: "te_member_forbidden",
        title: "A request's TE holds a member other than trailers",
        message: "",
        default_severity: Severity::Error,
        spec: None,
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
        spec: Some(RFC_9112_7_4),
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
        assert_eq!(TE_MEMBER_FORBIDDEN.spec, None);
        assert_eq!(TE_MEMBER_FORBIDDEN.default_severity, Severity::Error);
    }
}
