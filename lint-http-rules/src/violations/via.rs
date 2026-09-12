// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Via` defects — what a member says about its own parts.
//!
//! `Via = #( received-protocol RWS received-by [ RWS comment ] )` names five
//! things and defines none of them: the list construct, the two `token`s a
//! `received-protocol` is, the `token` a `pseudonym` is, the `port` RFC 3986
//! writes, and § 5.6.5's comment with the escape inside it. Every octet-level
//! defect a `Via` can hold is therefore some other subject's, and a bad
//! character here answers with the id an `Upgrade`, a `Server` or a
//! `Content-Type` parameter would.
//!
//! **What is left is the assembly, and that is this subject.** A member with a
//! protocol and no recipient after it, a member that goes on past the point
//! where it ended, a second comment where the production writes one, and a
//! `received-by` spelled as the host form a later document took out of the
//! production — none of those is a defect of any part; each is a statement
//! about how the parts go together, and the field's own section is where all of
//! it is written.
//!
//! **The subject is flat at `warn`, which is worth saying rather than
//! assuming.** Nothing here is an `error`: `Via` is a trace, so a member that
//! does not derive costs a recipient the identity of one hop and never the
//! exchange — the question [`status`](crate::violations::status) ranks by is
//! answered the same way for all four. And nothing here is `info` either,
//! because each of them leaves a member a strict recipient cannot split: the
//! chain a proxy is required to append to is the thing that stops being
//! readable, whichever of the four went wrong.
//!
//! **The obsolete spelling is the entry to read twice.** It is the third use of
//! the `_obsolete` ending and the first where no sentence obliges a recipient to
//! accept the retired form — which is exactly why it does *not* default to
//! `info` the way [`http_date`](crate::violations::http_date)'s does. An RFC 850
//! timestamp is a spelling every recipient must still read; a bracketed IPv6
//! literal in a `received-by` is one that no current production generates and
//! nothing asks a recipient to parse.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field's own section: the grammar every entry here is measured against,
/// what each of the three parts is for, and the forwarding requirements a
/// single captured message cannot answer.
pub const RFC_9110_7_6_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("7.6.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.3",
    note: "The `Via` grammar — `Via = #( received-protocol RWS received-by [ RWS comment ] )` — \
           the sentence that puts the field in both directions, and the requirements about \
           forwarding and combining that a single captured message cannot answer",
};

/// The change that makes one host spelling a defect rather than a choice.
/// RFC 7230's `received-by` admitted a `uri-host`; this one does not, and the
/// appendix that removed it is the only place the removal is stated.
pub const RFC_9110_B_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("B.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#appendix-B.2",
    note: "Why a `received-by` is a token: RFC 9110 removed `uri-host` from the \
           production, which is what makes a bracketed IPv6 literal a finding here and \
           not under RFC 7230",
};

defects! {
    /// A member that names the protocol it was received over and no recipient
    /// after it — `Via: 1.1`, or `Via: 1.1, 1.0 fred` where the comma arrives
    /// before the `RWS` does.
    ///
    /// The `received-by` is the half the field exists for: it is what says
    /// *who* forwarded the message, and a chain of hops that cannot be named is
    /// a chain no loop detection can walk. The optional half is the comment,
    /// and the production writes the `RWS` between the two required ones with
    /// no brackets around either.
    ///
    /// `_missing` and not `_empty`: there is no delimiter here to write and
    /// leave blank. `RWS` is the separator, so a sender who stopped after the
    /// protocol stopped before anything announced the recipient was coming —
    /// which is the line `docs/development.md` draws between the two words.
    ///
    // cite(RFC 9110 § 7.6.3): "Via = #( received-protocol RWS received-by [ RWS comment ] )"
    VIA_RECEIVED_BY_MISSING = {
        id: "via_received_by_missing",
        title: "Via member names no received-by",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_7_6_3],
    }

    /// A member that has ended and is followed by something that is neither the
    /// list's comma nor the whitespace before it: `Via: 1.1 exa mple`, where a
    /// space inside what was meant as a pseudonym ends the member two
    /// characters early, or a member whose comment is followed by more text.
    ///
    /// The catalogue cannot say which of the two the sender meant — a missing
    /// comma or a `pseudonym` holding an octet no `token` admits — and neither
    /// can a recipient. What both have in common is the only thing the finding
    /// claims: from here on, the value does not derive from the production, so
    /// the hops after this point are not readable either.
    ///
    // cite(RFC 9110 § 7.6.3): "Via = #( received-protocol RWS received-by [ RWS comment ] )"
    VIA_MEMBER_MALFORMED = {
        id: "via_member_malformed",
        title: "Via member does not end where the production ends it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_7_6_3],
    }

    /// Two comments in one member: `Via: 1.1 fred (a) (b)`. The optional group
    /// is written once and is not repeated, so the second one derives from
    /// nothing — most often a chain where one intermediary appended its
    /// software identification beside another's instead of adding a hop.
    ///
    /// Ranked with its siblings rather than below them, though the construct is
    /// the one part of a member a recipient is licensed to *delete*. What is
    /// reported is not the comment's content but the member it stopped: a
    /// parser that has taken the optional group has taken the whole member, and
    /// what follows is outside the production either way.
    ///
    // cite(RFC 9110 § 7.6.3): "Via = #( received-protocol RWS received-by [ RWS comment ] )"
    VIA_COMMENT_DUPLICATED = {
        id: "via_comment_duplicated",
        title: "Via member carries more than one comment",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_7_6_3],
    }

    /// A `received-by` written as a bracketed IPv6 literal —
    /// `Via: 1.1 [2001:db8::1]:8080` — which RFC 7230's grammar admitted as a
    /// `uri-host` and this one does not: `pseudonym = token`, and `[` is not a
    /// `tchar`.
    ///
    /// **The defect is which production the sender wrote, not which octet.** A
    /// bracket reported as a character outside `token` would send an operator
    /// to a typo; what happened is that an intermediary is generating the field
    /// against a document that was replaced, and the fix is a name or a bare
    /// address rather than a different character.
    ///
    /// **`warn`, where the catalogue's other obsolete spellings are `info`.**
    /// An RFC 850 timestamp is retired for senders and every recipient is still
    /// required to read it, so the message works; nothing anywhere requires a
    /// recipient to parse a host form this production no longer generates. The
    /// ending says the sender was conforming under a document that has been
    /// replaced — it does not promise that the value still arrives.
    ///
    // cite(RFC 9110 § B.2): "For simplicity, we have removed uri-host from the received-by production because it can be encompassed by the existing grammar for pseudonym."
    VIA_RECEIVED_BY_OBSOLETE = {
        id: "via_received_by_obsolete",
        title: "Via received-by is spelled as a uri-host",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_B_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The subject is flat, and both directions of the flatness are the
    /// reading: no entry ends the exchange, and no entry leaves a member a
    /// strict recipient can still split.
    #[test]
    fn every_entry_ranks_with_its_siblings() {
        for def in [
            &VIA_RECEIVED_BY_MISSING,
            &VIA_MEMBER_MALFORMED,
            &VIA_COMMENT_DUPLICATED,
            &VIA_RECEIVED_BY_OBSOLETE,
        ] {
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
        }
    }

    /// The one entry whose sentence is not the grammar: the removal is stated
    /// in the appendix that records what changed, and nowhere else.
    #[test]
    fn the_retired_spelling_cites_the_document_that_retired_it() {
        assert_eq!(VIA_RECEIVED_BY_OBSOLETE.spec, [RFC_9110_B_2]);
        assert_eq!(VIA_RECEIVED_BY_MISSING.spec, [RFC_9110_7_6_3]);
    }
}
