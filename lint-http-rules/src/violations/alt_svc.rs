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
//! **What is left is what the field states above its grammar**, and the two
//! entries below are at opposite ends of it. One is the top production's
//! alternation, where the document names the state it forbids and says what a
//! recipient does about it. The other is what a number means: a freshness
//! lifetime that conforms to `delta-seconds` and cannot be what the sender
//! intended. RFC 7838 sets no bound in either direction — zero is a legal
//! `delta-seconds` and so is a run of forty digits — so that entry carries no
//! reference, and the message says which end of the range the value fell off.
//!
//! What `ma` states is a meaning rather than a bound, which is the whole of the
//! argument for the uncited entry; the alternation, by contrast, is a sentence,
//! and the entry naming it is cited on every finding.
//!
//! **The field's own grammar is only partly written here.** The top
//! production's alternation is, because a value holding both of its halves is
//! a state the document names in its own words. The rest —
//! `alt_svc_header_syntax`'s reading of an `alternative` with no `=`, a
//! percent-encoding this field's one-spelling constraint forbids, an
//! `alt-authority` naming no port — is this subject's too and is not written
//! yet.
//
// cite(RFC 7838 § 3.1): "The delta-seconds value indicates the number of seconds since the response was generated for which the alternative service is considered fresh."

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field: its grammar, the `clear` keyword, and what a recipient does with
/// a value carrying that keyword beside an alternative service.
pub const RFC_7838_3: SpecRef = SpecRef {
    spec: "RFC 7838",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-3",
    note: "The Alt-Svc HTTP Header Field: `Alt-Svc = clear / 1#alt-value` and the productions under it, the case-sensitive `clear` keyword, the three percent-encoding constraints on a `protocol-id`, and the prose requiring a colon and a port inside the `alt-authority`",
};

defects! {
    /// The keyword and an alternative service in one field value.
    ///
    /// `Alt-Svc = clear / 1#alt-value` is an alternation, so a value holding
    /// both halves derives from neither — and the document does not leave that
    /// to a reader to work out. It names the state in a parenthetical, calls it
    /// an invalid reply, and says what a client does with it: invalidate every
    /// alternative for the origin, *including the ones written beside the
    /// keyword*.
    ///
    /// `_conflicting` because both halves are readable and each one contradicts
    /// the other. Nothing is malformed at the octet level, nothing is missing,
    /// and neither half is forbidden on its own — what fails is that one field
    /// value says two things a recipient cannot both act on.
    ///
    /// **`error`, and it is the one entry in this subject that outranks its
    /// rule.** Every other defect in an `Alt-Svc` costs the sender the one
    /// alternative it is written in; this one costs the sender all of them,
    /// because the recipient's defined answer is to discard the alternatives
    /// this very response was sent to advertise. A field that is otherwise a
    /// hint here does the opposite of what its sender meant.
    ///
    // cite(RFC 7838 § 3): "A field value containing the special value "clear" indicates that the origin requests all alternatives for that origin to be invalidated (including those specified in the same response, in case of an invalid reply containing both "clear" and alternative services)."
    ALT_SVC_CLEAR_CONFLICTING = {
        id: "alt_svc_clear_conflicting",
        title: "Alt-Svc carries the clear keyword beside an alternative service",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7838_3],
    }

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
    fn the_uncited_entry_states_no_sentence() {
        assert!(ALT_SVC_MA_INVALID.spec.is_empty());
        assert_eq!(ALT_SVC_MA_INVALID.default_severity, Severity::Warn);
    }

    /// The two entries are the subject's two ends, and they rank apart for a
    /// reason the file argues rather than assumes: a value nobody meant costs
    /// its own alternative, and a value the document calls an invalid reply
    /// costs every alternative the response carried.
    #[test]
    fn the_alternation_outranks_the_lifetime_and_names_its_sentence() {
        assert_eq!(ALT_SVC_CLEAR_CONFLICTING.default_severity, Severity::Error);
        assert_eq!(ALT_SVC_CLEAR_CONFLICTING.spec, [RFC_7838_3]);
        assert!(ALT_SVC_MA_INVALID.default_severity < ALT_SVC_CLEAR_CONFLICTING.default_severity);
    }
}
