// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Warning` defects — how a `warning-value`'s four parts go together.
//!
//! `warning-value = warn-code SP warn-agent SP warn-text [ SP warn-date ]`
//! names four things and defines one of them. The list is
//! [`list`](crate::violations::list)'s, the `warn-agent` is a
//! [`uri`](crate::violations::uri) host with a port or a
//! [`token`](crate::violations::token), the `warn-text` and the `warn-date`'s
//! wrapper are [`quoted_string`](crate::violations::quoted_string)s, and what
//! sits inside that wrapper is an
//! [`http_date`](crate::violations::http_date). Only `warn-code = 3DIGIT` is
//! written here and nowhere else.
//!
//! **So this subject is the assembly and one terminal**, which is the shape
//! [`via`](crate::violations::via) has: a member whose parts arrive in the
//! order the production writes them, separated by the single SPs it prints,
//! ending where it ends. What is left over is not a defect of any part.
//!
//! **Two readings were borrowed rather than written, and both are worth
//! knowing.** A `warn-text` or a `warn-date` that does not open with a DQUOTE
//! is `quoted_string_delimiter_missing` — the production *is* its two
//! delimiters and what they enclose, which is the same answer an unquoted
//! `alt-authority` gets. And a `warn-agent` holding an octet at or above %x80
//! is `uri_host_character_forbidden`: the octet derives from neither
//! alternative, and this rule's own policy is that a `warn-agent` failing both
//! is read against the host, which is the alternative carrying a port. **An
//! alternation owns no defect, so the id is whichever alternative the reading
//! committed to** — the message still names both.
//!
//! **Four at `error` and one at `info`, and the split is the subject's whole
//! ranking.** The four that read a `warning-value` are
//! [`Strength::Grammar`](crate::lint::Strength): RFC 9110 § 2.2 obliges a
//! sender not to generate a protocol element matching no ABNF rule, which is
//! the sentence every grammar entry in this catalogue ranks off, and none of
//! them is `info` either because each leaves a member a strict recipient
//! cannot split. [`WARNING_OBSOLETE`] is not about a `warning-value` at all
//! and ranks with the deprecation family instead, at `info`.
//!
//! **The argument this paragraph used to make was that a `Warning` is
//! advisory, so no member of it can cost an exchange anything, which ruled out
//! `error`.** That is a reading of the *consequence*, and it is how
//! [`Strength::Unstated`](crate::lint::Strength) entries are ranked — not how
//! a value that derives from nothing is. It was written before the catalogue
//! read every entry against the keyword that binds its sender, and it survived
//! that pass as prose while the four defaults below moved under it.
//
// cite(RFC 7234 § 5.5, label: warning-value assembly): "warning-value = warn-code SP warn-agent SP warn-text [ SP warn-date ]"

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Where the field is obsoleted, and the only statement about it a current
/// document makes.
///
/// § 5.4 deprecates `Pragma` in the same voice one section earlier, and § 8.1's
/// Table 1 records both outcomes side by side: `Pragma` `deprecated`, `Warning`
/// `obsoleted`. Neither sentence carries a BCP 14 keyword, which is what
/// [`Strength::Unstated`](crate::lint::Strength) is for and not a
/// reason to say nothing.
pub const RFC_9111_5_5: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("5.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.5",
    note: "Where `Warning` is obsoleted, and where the field's status is read from. The \
           section states no requirement and keeps none of RFC 7234 § 5.5's grammar — it \
           says the field was used, that this specification obsoletes it, and where the \
           information it carried can be found instead",
};

/// The last statement of the `Warning` grammar, which is where every entry
/// here is read from.
pub const RFC_7234_5_5: SpecRef = SpecRef {
    spec: "RFC 7234",
    section: Some("5.5"),
    url: "https://www.rfc-editor.org/rfc/rfc7234.html#section-5.5",
    note: "The last statement of the `Warning` grammar, and the requirements about \
           warn-codes and warn-dates that go with it. Obsoleted by RFC 9111, which \
           removed the field rather than restating it — so this is where the \
           productions are read from, and RFC 9111 §5.5 is where the field's status \
           is read from",
};

defects! {
    /// A `warn-code` that is not three digits: `Warning: 11x agent "text"`, or
    /// a member shorter than the code itself.
    ///
    /// `warn-code = 3DIGIT` is the one production a `warning-value` writes for
    /// itself, and it is exact in both directions — a digit missing and a
    /// non-digit present are the same three characters failing to derive, which
    /// is why they are one entry and the message says which happened.
    ///
    /// **A fourth digit is not this entry**, and the reason is where the
    /// evidence stops: what follows a three-digit code is a SP, so `1104` is
    /// either a code with a digit too many or a code and an agent with no
    /// separator between them. The catalogue cannot tell those apart and
    /// neither can a recipient, so it reports as
    /// [`WARNING_MEMBER_MALFORMED`] — the same line `Via` draws where a member
    /// stops deriving and the sender's intent is unrecoverable.
    ///
    // cite(RFC 7234 § 5.5, label: warn-code grammar): "warn-code = 3DIGIT warn-agent = ( uri-host [ ":" port ] ) / pseudonym"
    WARNING_CODE_MALFORMED = {
        id: "warning_code_malformed",
        title: "Warning member's warn-code is not three digits",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7234_5_5],
        strength: Strength::Grammar,
    }

    /// A member that is a `warn-code` and nothing else: `Warning: 110`.
    ///
    /// The production writes three mandatory parts and brackets only the
    /// fourth, so a member ending after its code names no one — and a warning
    /// with no agent is a warning whose origin a recipient cannot record. **The
    /// entry names the first part that is absent**, not every part after the
    /// code: a sender that wrote nothing made one mistake, and the fix is the
    /// rest of the member.
    ///
    // cite(RFC 7234 § 5.5, label: warn-agent position): "warning-value = warn-code SP warn-agent SP warn-text [ SP warn-date ]"
    WARNING_AGENT_MISSING = {
        id: "warning_agent_missing",
        title: "Warning member names no warn-agent",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7234_5_5],
        strength: Strength::Grammar,
    }

    /// A member that ends after its `warn-agent`: `Warning: 110 example.com`.
    ///
    /// The `warn-text` is the part a human reads — the whole reason the field
    /// exists — and nothing brackets it. A member reaching this entry has an
    /// agent and a code and says nothing about what it is warning of.
    ///
    /// Separate from [`WARNING_AGENT_MISSING`] because the senders differ and
    /// so do the fixes: one stopped at the code and the other wrote everything
    /// but the message.
    ///
    // cite(RFC 7234 § 5.5, label: warn-text position): "warn-text = quoted-string"
    WARNING_TEXT_MISSING = {
        id: "warning_text_missing",
        title: "Warning member carries no warn-text",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7234_5_5],
        strength: Strength::Grammar,
    }

    /// A member whose parts do not go together the way the production writes
    /// them: something other than a SP at a seam, or content after the part
    /// that ends the member.
    ///
    /// Three readings arrive here and they share the only claim the finding
    /// makes — from this point on, the member does not derive. A `1104` is a
    /// code with a digit too many or a code and an agent unseparated; a
    /// `"text"x` is a `warn-text` with a typo behind it or a member missing its
    /// comma; a member with content after its `warn-date` has run past the last
    /// part it is allowed to have. **The catalogue does not guess between two
    /// senders where a recipient cannot**, which is `via_member_malformed`'s
    /// line and the reason this entry exists at all rather than being three.
    ///
    // cite(RFC 7234 § 5.5, label: warning-value seams): "warning-value = warn-code SP warn-agent SP warn-text [ SP warn-date ]"
    WARNING_MEMBER_MALFORMED = {
        id: "warning_member_malformed",
        title: "Warning member does not derive where the production continues it",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7234_5_5],
        strength: Strength::Grammar,
    }

    /// A message carrying the field at all, whatever its value derives from.
    ///
    /// **The one entry here that is not about a `warning-value`**, and the
    /// reason the other four now read as a repair to a field that should not
    /// be sent. A `Warning` whose `warn-text` is a bare token draws
    /// `quoted_string_delimiter_missing` at `error`, and a sender acting on
    /// that alone puts the value in DQUOTEs and ships a well-formed instance
    /// of a field RFC 9111 removed. The grammar findings stay true — a
    /// recipient still cannot split the member — but the sentence a sender
    /// most needs is that the field itself is the thing to drop.
    ///
    /// **Reported for the same reason [`PRAGMA_OBSOLETE`](crate::violations::pragma::PRAGMA_OBSOLETE) is**, and the two
    /// sentences are one section apart in one document. Neither carries a BCP
    /// 14 keyword; both say what the specification does rather than what a
    /// sender must. That is [`Strength::Unstated`](crate::lint::Strength),
    /// which 261 entries in this catalogue are built on, and § 8.1's Table 1
    /// puts the two fields in adjacent rows — `Pragma` `deprecated`, `Warning`
    /// `obsoleted`. The field with the weaker status was the one being
    /// reported.
    ///
    /// **`info`, at the deprecation family's level and for its argument.** No
    /// recipient is misled: a field nothing acts on costs the exchange
    /// nothing, and what the finding buys is that the sender learns it is
    /// writing into a void. § 5.5 names where the information goes instead —
    /// other header fields, `Age` among them — so the message can say what to
    /// do rather than only what to stop.
    ///
    /// **Both directions, one entry**, which is [`PRAGMA_OBSOLETE`](crate::violations::pragma::PRAGMA_OBSOLETE)'s shape
    /// too: § 5.5 obsoletes a field of a *message* and attaches no direction,
    /// § 8.1 records the status with none either, and the message names the
    /// side that wrote it.
    ///
    // cite(RFC 9111 § 5.5): "The "Warning" header field was used to carry additional information about the status or transformation of a message that might not be reflected in the status code."
    // cite(RFC 9111 § 5.5, label: the obsoletion): "This specification obsoletes it, as it is not widely generated or surfaced to users."
    WARNING_OBSOLETE = {
        id: "warning_obsolete",
        title: "A message carries a field this specification obsoletes",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9111_5_5],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::via::VIA_MEMBER_MALFORMED;

    /// The subject is flat, and the argument is the field's: advisory in the
    /// first place, obsolete in the second, and never `info` because each of
    /// these leaves a member a strict recipient cannot split.
    #[test]
    fn every_entry_ranks_with_its_siblings_and_names_the_same_section() {
        for def in [
            &WARNING_CODE_MALFORMED,
            &WARNING_AGENT_MISSING,
            &WARNING_TEXT_MISSING,
            &WARNING_MEMBER_MALFORMED,
        ] {
            assert_eq!(def.default_severity, Severity::Error, "{}", def.id);
            assert_eq!(def.spec, [RFC_7234_5_5], "{}", def.id);
        }
    }

    /// The member that stops deriving is the same defect `Via` names, in a
    /// field whose parts are separated by a SP instead of by `RWS` — two
    /// entries because the two documents write two productions, one rank
    /// because a trace and a warning cost a recipient the same thing.
    #[test]
    fn the_member_that_stops_deriving_is_two_entries_of_one_rank() {
        assert_ne!(WARNING_MEMBER_MALFORMED.id, VIA_MEMBER_MALFORMED.id);
        assert_eq!(
            WARNING_MEMBER_MALFORMED.default_severity,
            VIA_MEMBER_MALFORMED.default_severity
        );
    }
}
