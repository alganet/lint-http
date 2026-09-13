// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Content-Security-Policy` defects — the policy and its directive names.
//!
//! CSP3 writes a policy as a semicolon-delimited series of directives, and this
//! part of the subject holds what can be wrong at that level: a field carrying
//! no policy, a position that names no directive, and a directive whose name
//! holds a character the production does not admit.
//!
//! **The bracketing is what makes two of those different findings.**
//! `serialized-policy` puts the *first* `serialized-directive` outside any
//! optional group and every later one inside one, so `script-src 'self';` and
//! `a;;b` are conforming — a trailing or doubled semicolon is a zero-directive
//! repetition, exactly the way `text/plain;` is a zero-parameter one in
//! [`parameter`](crate::violations::parameter). A policy that *opens* with a
//! semicolon is the case the grammar does not bracket. The rule reading this
//! reported every empty position, which is one of the two shapes a `;` has and
//! the wrong one.
//!
//! **The character-class pair is deliberately not drawn here, and the reason is
//! a derivation rather than a preference.** `docs/development.md` asks a
//! subject that separates the octets nobody typed from the ones a sender chose
//! to spell them `_whitespace_or_control_forbidden` and `_character_forbidden`.
//! A CSP directive is cut apart on `required-ascii-whitespace`, which is what a
//! recipient splits on too — so every octet a recipient would read as
//! whitespace is already a separator by the time a name exists to check. What
//! is left inside a name is by construction a character the sender put there,
//! which is the half the second id names, and the first half has no case to
//! report.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Policies: the serialization of one, whose later directives are bracketed
/// and whose first is not.
pub const CSP3_2_2: SpecRef = SpecRef {
    spec: "CSP3",
    section: Some("2.2"),
    url: "https://www.w3.org/TR/CSP3/#framework-policy",
    note: "Policies: `serialized-policy = serialized-directive *( optional-ascii-whitespace \";\" [ optional-ascii-whitespace serialized-directive ] )` — one unbracketed directive and any number of bracketed ones, which is what decides whether a given `;` names anything",
};

/// Directives: the name production, which is narrower than the HTTP `token`.
pub const CSP3_2_3: SpecRef = SpecRef {
    spec: "CSP3",
    section: Some("2.3"),
    url: "https://www.w3.org/TR/CSP3/#framework-directives",
    note: "Directives: `directive-name = 1*( ALPHA / DIGIT / \"-\" )`, letters, digits and a hyphen and nothing else — where an HTTP `token` also admits `_`, `.` and a dozen other marks",
};

defects! {
    /// A `Content-Security-Policy` field written and left blank.
    ///
    /// `serialized-policy` opens with a `serialized-directive` that nothing
    /// brackets, and a `directive-name` is one character or more — so a policy
    /// with nothing in it derives from the production not at all.
    ///
    /// **`warn`, and higher than the two entries below it, because of what the
    /// field is.** A blank `Content-Security-Policy` is a security control that
    /// is present in the response, visible to anyone auditing the headers, and
    /// enforcing nothing whatsoever. The other two leave a policy that still
    /// restricts something.
    ///
    // cite(CSP3 § 2.2): "A serialized CSP is an ASCII string consisting of a semicolon-delimited series of serialized directives, adhering to the following ABNF grammar [RFC5234]:"
    CONTENT_SECURITY_POLICY_EMPTY = {
        id: "content_security_policy_empty",
        title: "Content-Security-Policy is written with no policy in it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[CSP3_2_2],
    }

    /// A policy that opens with a semicolon, so its first position names no
    /// directive.
    ///
    /// **Only the first**, and that is the whole content of this entry.
    /// `serialized-policy = serialized-directive *( optional-ascii-whitespace
    /// ";" [ optional-ascii-whitespace serialized-directive ] )` brackets every
    /// directive after the first, so a trailing `;`, a doubled `;;` and a `; ;`
    /// are all zero-directive repetitions the grammar produces. Only the
    /// opening one has no bracket around it.
    ///
    /// The same reading [`link`](crate::violations::link) made from the other
    /// side, where a `Link` writes two separators answering to two documents:
    /// what a `;` means is decided by whether the production brackets what
    /// follows it, and nothing else.
    ///
    /// `info`. The policy still enforces every directive it does name, and a
    /// user agent parsing it discards the empty position exactly as the grammar
    /// says it may; what is left is a stray character in a header a person will
    /// read.
    ///
    // cite(CSP3 § 2.2, label: serialized-policy grammar): "serialized-policy = serialized-directive *( optional-ascii-whitespace ";" [ optional-ascii-whitespace serialized-directive ] )"
    CONTENT_SECURITY_POLICY_DIRECTIVE_EMPTY = {
        id: "content_security_policy_directive_empty",
        title: "A policy opens with a semicolon and names no first directive",
        message: "",
        default_severity: Severity::Info,
        spec: &[CSP3_2_2],
    }

    /// A character in a `directive-name` that the production does not admit:
    /// `default_src`, `script–src` with an en dash, a name carrying an
    /// `obs-text` octet.
    ///
    /// **`directive-name` is narrower than the HTTP `token`, which is the trap
    /// this entry exists for.** `_` is a perfectly good `tchar`, so a check
    /// borrowed from [`token`](crate::violations::token) calls `default_src`
    /// well formed — and a user agent that does not recognise the name ignores
    /// the directive, so the policy silently drops whatever that line was
    /// supposed to restrict.
    ///
    /// `warn` for exactly that: the finding is about a restriction that is not
    /// being applied, and nothing in the response says so.
    ///
    // cite(CSP3 § 2.3): "directive-name = 1*( ALPHA / DIGIT / "-" )"
    CONTENT_SECURITY_POLICY_DIRECTIVE_NAME_CHARACTER_FORBIDDEN = {
        id: "content_security_policy_directive_name_character_forbidden",
        title: "A CSP directive name holds a character the production does not admit",
        message: "",
        default_severity: Severity::Warn,
        spec: &[CSP3_2_3],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ranking is what the rule's one severity could not express: a header
    /// enforcing nothing at all, a directive that will be ignored, and a stray
    /// semicolon are three different amounts of security policy.
    #[test]
    fn a_policy_that_enforces_nothing_outranks_a_stray_semicolon() {
        assert!(
            CONTENT_SECURITY_POLICY_DIRECTIVE_EMPTY.default_severity
                < CONTENT_SECURITY_POLICY_EMPTY.default_severity
        );
        assert_eq!(
            CONTENT_SECURITY_POLICY_DIRECTIVE_NAME_CHARACTER_FORBIDDEN.default_severity,
            CONTENT_SECURITY_POLICY_EMPTY.default_severity
        );
    }
}
