// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Transfer-Encoding` defects — the sequence of codings a sender applied, and
//! the one coding that has to be last.
//!
//! The field is framing, the way `Content-Length` is: the codings are applied
//! in the order written and undone in reverse, and `chunked` is the one that
//! delimits the result. So a sequence is not a description that happens to be
//! in an awkward order — it is where the message ends, stated wrongly.
//!
//! **Three entries out of one paragraph.** RFC 9112 § 6.1 says `chunked` may be
//! applied at most once, and that a sender applying any other coding must apply
//! `chunked` last. The first is a sentence of its own and gets an entry of its
//! own. The second is written twice, once per direction — unconditionally for a
//! request, and for a response with the alternative of closing the connection —
//! and the two directions are *not* what the ids split on. **What splits them is
//! what the sender wrote**: `chunked` applied and something applied after it, or
//! `chunked` never applied at all. Those are two different messages to a
//! sender, two different fixes, and one shared requirement — so each entry
//! quotes the direction of § 6.1 that states it most plainly and the other
//! direction is the sibling entry's quote.
//!
//! **What is deliberately not here.** Whether a coding name is registered, and
//! whether a member parses at all, are `transfer_coding_registered`'s findings
//! and the `token` subject's ids; a value whose quoting never closes is declined
//! by the ordering rule rather than reported by it, because members that cannot
//! be delimited have no order to judge.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The whole of the ordering requirement: `chunked` at most once, and
/// `chunked` last — unconditionally for a request, or the connection closes for
/// a response.
pub const RFC_9112_6_1: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1",
    note: "Transfer-Encoding — every requirement this rule enforces is here: chunked at most once, and chunked last (unconditionally for requests, or the connection closes for responses)",
};

defects! {
    /// `chunked` applied twice to one body. Chunking an already chunked message
    /// frames it twice, and a recipient undoing one layer finds chunk headers
    /// where the content should be.
    ///
    /// **The one entry in this subject a closed connection cannot excuse.** The
    /// sentence below offers no alternative — unlike the ordering requirement,
    /// where a response may frame by closing instead — so it is answered before
    /// the message direction is even considered.
    ///
    // cite(RFC 9112 § 6.1): "A sender MUST NOT apply the chunked transfer coding more than once to a message body (i.e., chunking an already chunked message is not allowed)."
    TRANSFER_ENCODING_CHUNKED_DUPLICATED = {
        id: "transfer_encoding_chunked_duplicated",
        title: "The chunked transfer coding is applied more than once",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9112_6_1),
    }

    /// `chunked` is in the sequence and something is applied after it, so the
    /// message is not chunk-framed on the wire — whatever the later coding
    /// produced is, and the chunk boundaries are inside it.
    ///
    /// Quoted from the response's half of § 6.1 because that is the half a
    /// response reaches this entry under, once it has been found not to
    /// announce a close. A request reaches it under the stricter half, which is
    /// quoted on [`TRANSFER_ENCODING_CHUNKED_MISSING`] — one requirement, two
    /// directions, and the entry names the sequence rather than the direction.
    ///
    // cite(RFC 9112 § 6.1, label: chunked last or the connection closes): "If any transfer coding other than chunked is applied to a response's content, the sender MUST either apply chunked as the final transfer coding or terminate the message by closing the connection."
    TRANSFER_ENCODING_CHUNKED_POSITION_INVALID = {
        id: "transfer_encoding_chunked_position_invalid",
        title: "The chunked transfer coding is not the final one",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9112_6_1),
    }

    /// A coding was applied and `chunked` was not, so nothing frames the
    /// result. `Transfer-Encoding: gzip` on a request states that the content
    /// is compressed and says nothing about where it ends.
    ///
    /// The sentence quoted here is unconditional, which is why the site
    /// reporting it reads requests only: a response has the second alternative
    /// of closing the connection, and this crate reads that from
    /// `Connection: close` — an announcement RFC 9112 § 9.6 makes a SHOULD, so
    /// a response that closes silently is left alone rather than reported here
    /// on an inference.
    ///
    // cite(RFC 9112 § 6.1, label: chunked last, unconditionally): "If any transfer coding other than chunked is applied to a request's content, the sender MUST apply chunked as the final transfer coding to ensure that the message is properly framed."
    TRANSFER_ENCODING_CHUNKED_MISSING = {
        id: "transfer_encoding_chunked_missing",
        title: "A coding is applied and chunked never is",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9112_6_1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every entry names the sequence a sender wrote, and none of them names a
    /// message direction — the requirement is written twice in § 6.1 and is one
    /// requirement, so `transfer_encoding_request_*` would split the catalogue
    /// where the document does not.
    #[test]
    fn no_entry_is_spelled_for_a_message_direction() {
        for def in [
            &TRANSFER_ENCODING_CHUNKED_DUPLICATED,
            &TRANSFER_ENCODING_CHUNKED_POSITION_INVALID,
            &TRANSFER_ENCODING_CHUNKED_MISSING,
        ] {
            assert!(
                def.id.starts_with("transfer_encoding_chunked_"),
                "{}",
                def.id
            );
            assert!(!def.id.contains("request"), "{}", def.id);
            assert!(!def.id.contains("response"), "{}", def.id);
            assert_eq!(def.spec, Some(RFC_9112_6_1), "{}", def.id);
        }
    }

    /// Each message names the codings that were found, so none of the entries
    /// carries a whole message of its own.
    #[test]
    fn every_message_is_formatted_where_the_codings_are() {
        for def in [
            &TRANSFER_ENCODING_CHUNKED_DUPLICATED,
            &TRANSFER_ENCODING_CHUNKED_POSITION_INVALID,
            &TRANSFER_ENCODING_CHUNKED_MISSING,
        ] {
            assert!(def.message.is_empty(), "{}", def.id);
        }
    }
}
