// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Alt-Svc` defects — what an alternative service advertisement says beyond
//! its grammar.
//!
//! The field is `1#alt-value`, an `alt-value` is `alternative *( OWS ";" OWS
//! parameter )`, and almost all of that is borrowed: the list floors are
//! [`list`](crate::violations::list)'s, the protocol identifier is an
//! [`alpn`](crate::violations::alpn) name, and a parameter's halves are
//! [`token`](crate::violations::token) and
//! [`quoted_string`](crate::violations::quoted_string). The `ma` parameter's
//! value is a [`delta_seconds`](crate::violations::delta_seconds), read at both
//! ends of that production.
//!
//! **What is left for this subject is what the numbers mean**, and the first
//! entry is the whole of it: a freshness lifetime that conforms to its
//! production and cannot be what the sender intended. RFC 7838 sets no bound in
//! either direction — zero is a legal `delta-seconds` and so is a run of forty
//! digits — so the entry carries no reference, and the message says which end of
//! the range the value fell off.
//!
//! What `ma` states is the one sentence this subject rests on, and it states a
//! meaning rather than a bound — which is the whole of the argument for the
//! entry below carrying no reference.
//!
//! **The field's own grammar is not written here yet.** `alt_svc_header_syntax`
//! reads it in both directions — an `alternative` with no `=`, an empty
//! `protocol-id`, a percent-encoding this field's one-spelling constraint
//! forbids, an unterminated DQUOTE — and those are this subject's entries when
//! that rule converts.
//
// cite(RFC 7838 § 3.1): "The delta-seconds value indicates the number of seconds since the response was generated for which the alternative service is considered fresh."

use crate::lint::Severity;
use crate::violations::defects;

defects! {
    /// A freshness lifetime that derives from `delta-seconds` and states
    /// nothing a client can use: `ma=0`, which is stale on arrival, or a value
    /// so far above any deployment's horizon that it is a typo.
    ///
    /// **One entry for both ends, because the sender's mistake is one mistake**
    /// — the number written is not the number meant — and an operator who wants
    /// to hear about implausible lifetimes wants to hear about both. The message
    /// says which end, and for the upper one it names the bound it compared
    /// against rather than advising a smaller number.
    ///
    /// **Uncited, and this is the pair of reasons for it.** RFC 7838 § 3.1 gives
    /// `ma` a meaning and no bound: zero seconds is a conforming value that says
    /// the advertisement is already stale, which a sender is entitled to write,
    /// and nothing published states a maximum — so the upper end is this
    /// crate's own reading of where a policy stops being one. Both halves are
    /// sentences that do not exist, which is what an entry with no reference is
    /// for.
    ///
    /// `_invalid` rather than `_malformed`: every octet is a DIGIT and the
    /// production is satisfied. What fails is the value's usefulness, one level
    /// past the grammar.
    ///
    /// `warn`. Nothing is unreadable and no request is affected — the
    /// advertisement is simply not one a client will act on, which is a cost to
    /// the sender rather than to the exchange.
    ALT_SVC_MA_INVALID = {
        id: "alt_svc_ma_invalid",
        title: "Alt-Svc states a freshness lifetime that cannot be what was meant",
        message: "",
        default_severity: Severity::Warn,
        spec: &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry that carries no sentence, and the reason it may not gain one
    /// later: what it reports is a value both of whose ends conform.
    #[test]
    fn the_only_entry_here_states_no_sentence() {
        assert!(ALT_SVC_MA_INVALID.spec.is_empty());
        assert_eq!(ALT_SVC_MA_INVALID.default_severity, Severity::Warn);
    }
}
