// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Pragma` defects — a field HTTP kept only to read what HTTP/1.0 wrote.
//!
//! § 5.4 defines the field for HTTP/1.0 caches, gives `Cache-Control` the same
//! job, and then deprecates it. So the whole subject is about a field that
//! still arrives and no longer says anything a recipient acts on — which is
//! why both entries here are about the field's *presence* and neither reads
//! its value. What the value may be is `pragma_token_valid`'s, over
//! [`list`](crate::violations::list) and [`token`](crate::violations::token).

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Pragma: what the field was for, that `Cache-Control` replaced it, and the
/// sentence deprecating it.
pub const RFC_9111_5_4: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("5.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.4",
    note: "Pragma — defined for HTTP/1.0 caches so a client could ask for `no-cache`, superseded by `Cache-Control`, deprecated by this specification, and never given a meaning in a response at all",
};

defects! {
    /// A `Pragma` on a response.
    ///
    /// **`_obsolete`, the vocabulary's rarest ending, used for exactly what it
    /// names**: a later specification retired the field. And the response
    /// direction makes it the clearest case — § 5.4 defines `Pragma` as a
    /// *request* header field, so a response carrying one is not even the
    /// deprecated thing being done, it is a field with no definition in the
    /// direction it arrived in.
    ///
    /// `info`. No recipient is misled: a field nothing defines is a field
    /// nothing acts on, and what the finding buys is that the sender learns it
    /// is writing into a void.
    ///
    // cite(RFC 9111 § 5.4): "However, support for Cache-Control is now widespread.  As a result, this specification deprecates Pragma."
    PRAGMA_OBSOLETE = {
        id: "pragma_obsolete",
        title: "A response carries a field this specification deprecates",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9111_5_4],
    }

    /// A request asking for `no-cache` through `Pragma` while its
    /// `Cache-Control` says `only-if-cached`.
    ///
    /// **The subject is `Pragma` because `Pragma` is the statement that dies.**
    /// § 5.4 has a cache read the `no-cache` pragma-directive only where
    /// `Cache-Control` is absent, and it is present here — so the client asked
    /// for a fresh copy in the field nobody reads and for a cached copy only in
    /// the field everybody does. The repair is to delete the `Pragma` or to
    /// mean the other thing; either way it is this field that goes.
    ///
    /// `warn` rather than the `info` beside it: the entry above reports a field
    /// that does nothing, and this one reports a request that gets the opposite
    /// of what it asked for.
    ///
    // cite(RFC 9111 § 5.4): "The "Pragma" request header field was defined for HTTP/1.0 caches, so that clients could specify a "no-cache" request"
    PRAGMA_CONFLICTING = {
        id: "pragma_conflicting",
        title: "A request asks for no-cache in the field its Cache-Control overrides",
        message: "Request contains 'Pragma: no-cache' and 'Cache-Control: only-if-cached' which are contradictory (RFC 9111 §5.4)",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_5_4],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One entry reports a field that does nothing and the other a request that
    /// gets the opposite of what it asked for, which is the whole of the
    /// ranking.
    #[test]
    fn the_contradiction_outranks_the_field_nothing_reads() {
        assert!(PRAGMA_OBSOLETE.default_severity < PRAGMA_CONFLICTING.default_severity);
    }

    /// Both entries are about the field being there; neither reads its value,
    /// so neither names one.
    #[test]
    fn neither_entry_names_a_value() {
        assert!(PRAGMA_OBSOLETE.message.is_empty());
        assert!(!PRAGMA_CONFLICTING.message.is_empty());
    }
}
