// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `auth-param` defects — one entry, and it exists because a lookalike does.
//!
//! `auth-param = token BWS "=" BWS ( token / quoted-string )` is RFC 9110
//! § 11.2's, read from both sides of the framework: a `WWW-Authenticate`
//! challenge and an `Authorization` credential are made of these, and
//! [`crate::helpers::auth::parse_auth_params`] is the one walk over them.
//!
//! Three of what that walk can report belong elsewhere and say so —
//! [`list`](crate::violations::list) for an empty member,
//! [`token`](crate::violations::token) for a name that is empty or holds a
//! character the production does not admit. **The fourth is here, and it was
//! refused for a year rather than borrowed**, which is the whole reason this
//! subject is a file of its own.
//!
//! **The lookalike is [`parameter`](crate::violations::parameter).** § 5.6.6's
//! `parameter = parameter-name "=" parameter-value` has no `OWS` anywhere
//! inside it and a Note saying so a second time; § 11.2's `auth-param` prints
//! `BWS` on both sides of its `=`. Two documents' worth of the same-looking
//! construct, and a member with no `=` breaks a different sentence in each — so
//! reporting an `Authorization` under `parameter_equals_missing` would carry a
//! requirement about whitespace this production explicitly admits.
//!
//! The subject file sits beside [`token68`](crate::violations::token68) for the
//! same reason that one does: § 11.2 defines three things, and each of them is
//! its own production with its own callers.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::violations::auth_scheme::RFC_9110_11_2;
use crate::violations::defects;

defects! {
    /// A member of an `#auth-param` list with no `=` in it: `Digest username`,
    /// a `WWW-Authenticate` challenge whose second parameter is a bare word.
    ///
    /// The `=` is written between the two halves and nothing brackets it, so a
    /// bare word among the parameters is not a flag whose value is implied — it
    /// derives from `auth-param` not at all. The `BWS` on either side of the
    /// delimiter is what a recipient parses away, and it cannot parse away a
    /// delimiter that is not there.
    ///
    /// **Not
    /// [`PARAMETER_EQUALS_MISSING`](crate::violations::parameter::PARAMETER_EQUALS_MISSING),
    /// and the module doc above is the argument.** The two productions are
    /// written in two documents and differ in exactly the whitespace one of
    /// them prints; borrowing that id would put § 5.6.6's Note behind a finding
    /// about a construct § 5.6.6 does not describe.
    ///
    /// `error`, from `auth-param`'s own production, which prints the `=`
    /// between the two halves. What follows is the cost and not the rank: the
    /// member is unreadable and the scheme's own definition decides what
    /// happens next, which for `Digest` is a credential no verifier can compute
    /// a response over and for a challenge is a parameter the client never
    /// sees.
    ///
    // cite(RFC 9110 § 11.2, label: auth-param grammar): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
    AUTH_PARAM_EQUALS_MISSING = {
        id: "auth_param_equals_missing",
        title: "An authentication parameter is written without its '='",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_11_2],
        strength: Strength::Grammar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::parameter::PARAMETER_EQUALS_MISSING;

    /// The two ids for the two productions, and the assertion is the claim:
    /// they are never interchangeable, because the sections they name say
    /// different things about the whitespace beside the delimiter.
    #[test]
    fn the_two_missing_delimiters_are_two_ids() {
        assert_ne!(AUTH_PARAM_EQUALS_MISSING.id, PARAMETER_EQUALS_MISSING.id);
        let [auth] = AUTH_PARAM_EQUALS_MISSING.spec else {
            panic!("one sentence")
        };
        let [parameter] = PARAMETER_EQUALS_MISSING.spec else {
            panic!("one sentence")
        };
        assert_ne!(auth.section, parameter.section);
    }
}
