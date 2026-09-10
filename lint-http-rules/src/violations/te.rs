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
use crate::violations::defects;

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
