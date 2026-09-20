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
//! [`list`](crate::violations::list) and [`token`](crate::violations::token) —
//! and that rule defers the question of whether the field belongs here, which
//! is why a direction left out of these entries is a direction nothing asks
//! about at all.

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
    /// A `Pragma` on either side of the exchange.
    ///
    /// **`_obsolete`, the vocabulary's rarest ending, used for exactly what it
    /// names**: a later specification retired the field.
    ///
    /// **The title used to say "a response", and the direction it left out is
    /// the one § 5.4 is written about.** The section opens by naming the
    /// *request* header field and closes by deprecating it, and the registry
    /// table in § 11 records the field's status as `deprecated` with no
    /// direction attached — so a request carrying a `Pragma` is the deprecated
    /// thing being done, and was the one direction nothing reported. What the
    /// response direction adds is a second argument on top of the first: § 5.4
    /// never defined the field there at all, which is why the gutter Note says
    /// `Pragma: no-cache` cannot stand in for `Cache-Control: no-cache` in a
    /// response. Two arguments, one retired field, one entry — the message
    /// names which side wrote it.
    ///
    /// `info`. No recipient is misled: a deprecated field is one nothing acts
    /// on, and what the finding buys is that the sender learns it is writing
    /// into a void.
    ///
    // cite(RFC 9111 § 5.4): "The "Pragma" request header field was defined for HTTP/1.0 caches, so that clients could specify a "no-cache" request"
    // cite(RFC 9111 § 5.4): "However, support for Cache-Control is now widespread.  As a result, this specification deprecates Pragma."
    PRAGMA_OBSOLETE = {
        id: "pragma_obsolete",
        title: "A message carries a field this specification deprecates",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9111_5_4],
    }

    /// A request asking for `no-cache` through `Pragma` while its
    /// `Cache-Control` says `only-if-cached`.
    ///
    /// **The title used to state a cache behaviour RFC 9111 does not have.** It
    /// said the `Cache-Control` *overrides* the `Pragma`, and the reasoning
    /// under it said § 5.4 has a cache read the `no-cache` pragma-directive only
    /// where `Cache-Control` is absent. Both sentences are RFC 7234 § 5.4's —
    /// "When the Cache-Control header field is also present and understood in a
    /// request, Pragma is ignored", with its companion for the absent case —
    /// and RFC 9111 dropped the whole mechanism when it superseded that
    /// document. § 5.4 in force is three sentences and a Note, none of them
    /// about overriding, and the field appears nowhere else in the
    /// specification. An entry may not rest on a sentence its cite does not
    /// carry, whichever way the reading would have gone.
    ///
    /// So what is left is the two directives meaning opposite things, which is
    /// what the rule has always reported and what its own comment already called
    /// a heuristic: § 5.2.1.4's `no-cache` asks a cache to go to the origin,
    /// and § 5.2.1.7's `only-if-cached` asks it to answer from what it holds or
    /// return 504, and the rule quotes both where it reads them. The
    /// client asked for both. The repair is to delete one; which one is the
    /// client's to decide, and the finding does not say.
    ///
    /// `warn` rather than the `info` beside it: the entry above reports a field
    /// that does nothing, and this one reports a request whose two halves ask
    /// for opposite things.
    ///
    // cite(RFC 9111 § 5.4): "The "Pragma" request header field was defined for HTTP/1.0 caches, so that clients could specify a "no-cache" request"
    PRAGMA_CONFLICTING = {
        id: "pragma_conflicting",
        title: "A request asks for no-cache and only-if-cached at once",
        message: "Request contains 'Pragma: no-cache' and 'Cache-Control: only-if-cached' which are contradictory",
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
