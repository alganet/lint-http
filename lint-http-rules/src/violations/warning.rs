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
//! **Flat at `warn`, for the reason `Via`'s subject is.** A `Warning` is
//! advisory in the first place and obsolete in the second — RFC 9111 § 5.5
//! removed the field rather than restating it — so no member of it can cost an
//! exchange anything, which rules out `error`. And none of these is `info`
//! either: each leaves a member a strict recipient cannot split, so what stops
//! being readable is the warning itself.
//
// cite(RFC 7234 § 5.5, label: warning-value assembly): "warning-value = warn-code SP warn-agent SP warn-text [ SP warn-date ]"

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

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
        default_severity: Severity::Warn,
        spec: &[RFC_7234_5_5],
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
        default_severity: Severity::Warn,
        spec: &[RFC_7234_5_5],
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
        default_severity: Severity::Warn,
        spec: &[RFC_7234_5_5],
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
        default_severity: Severity::Warn,
        spec: &[RFC_7234_5_5],
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
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
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
