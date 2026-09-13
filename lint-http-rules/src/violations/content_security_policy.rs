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

/// Source Lists: the source expressions a directive value is made of, and the
/// two of them whose single quotes are part of the production.
pub const CSP3_2_3_1: SpecRef = SpecRef {
    spec: "CSP3",
    section: Some("2.3.1"),
    url: "https://www.w3.org/TR/CSP3/#framework-directive-source-list",
    note: "Source Lists: `source-expression`, the `nonce-source` and `hash-source` productions whose single quotes are written *inside* them, and the `base64-value` both of them carry",
};

/// `frame-ancestors`, and the sentence that makes it the authority when an
/// `X-Frame-Options` says something else.
pub const CSP3_6_4_2: SpecRef = SpecRef {
    spec: "CSP3",
    section: Some("6.4.2"),
    url: "https://www.w3.org/TR/CSP3/#directive-frame-ancestors",
    note: "`frame-ancestors` — which URLs may embed the resource, the rough equivalences between its source expressions and `X-Frame-Options`' values, and § 6.4.2.2's statement that an enforced `frame-ancestors` overrides that header outright",
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

    /// A nonce or hash source written without the single quotes the production
    /// prints, or with only the opening one: `nonce-abc123`, `sha256-xyz`,
    /// `'nonce-abc123`.
    ///
    /// **The quotes are inside the production, not around it.**
    /// `nonce-source = "'nonce-" base64-value "'"` opens with a literal that
    /// includes the quote, and `hash-source` prints one on each side of the
    /// algorithm and digest — so an unquoted `nonce-abc` is not a badly
    /// punctuated nonce, it is a `host-source` naming a host called
    /// `nonce-abc`. A user agent parses it as one, matches nothing against it,
    /// and the inline script the nonce was minted for is blocked.
    ///
    /// The unterminated case is the same defect from the other end and shares
    /// the id: a value that opens with `'` and never closes derives from no
    /// source expression at all.
    ///
    // cite(CSP3 § 2.3.1, label: nonce-source grammar): "nonce-source  = "'nonce-" base64-value "'""
    // cite(CSP3 § 2.3.1, label: hash-source grammar): "hash-source    = "'" hash-algorithm "-" base64-value "'""
    CONTENT_SECURITY_POLICY_SOURCE_DELIMITER_MISSING = {
        id: "content_security_policy_source_delimiter_missing",
        title: "A nonce or hash source is written without its single quotes",
        message: "",
        default_severity: Severity::Warn,
        spec: &[CSP3_2_3_1],
    }

    /// A quoted source expression with nothing between the quotes: `''`.
    ///
    /// Every quoted form the grammar has puts something inside the quotes — a
    /// keyword, `nonce-` and a value, an algorithm and a digest — so two
    /// quotes with nothing between them derive from none of them. Separate
    /// from [`CONTENT_SECURITY_POLICY_SOURCE_DELIMITER_MISSING`] for the reason
    /// `docs/development.md` gives for every `_missing`/`_empty` pair: one
    /// sender never wrote the delimiter and the other wrote it and put nothing
    /// in it.
    ///
    // cite(CSP3 § 2.3.1, label: source-expression alternatives): "source-expression      = scheme-source / host-source / keyword-source / nonce-source / hash-source"
    CONTENT_SECURITY_POLICY_SOURCE_EMPTY = {
        id: "content_security_policy_source_empty",
        title: "A quoted source expression is written with nothing in it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[CSP3_2_3_1],
    }

    /// A nonce or hash source naming no value: `'nonce-'`, `'sha256-'`,
    /// `nonce-`, `sha256-`.
    ///
    /// **One entry over both, because one production fails.** `base64-value`
    /// is written once and carried by `nonce-source` and all three
    /// `hash-source` algorithms, and `1*( ALPHA / DIGIT / "+" / "/" / "-" /
    /// "_" )` has a one-character floor — so a nonce with no nonce in it and a
    /// `sha256-` with no digest after it are the same arithmetic. The rule
    /// reporting this had four messages for it, one per algorithm and one for
    /// the nonce; the message still names which was written.
    ///
    /// **Where the quotes are missing too, this is the finding.** An unquoted
    /// `nonce-` fails both this and the entry above, and naming the value is
    /// the useful half: putting quotes around nothing fixes nothing.
    ///
    // cite(CSP3 § 2.3.1, label: base64-value grammar): "base64-value  = 1*( ALPHA / DIGIT / "+" / "/" / "-" / "_" )*2( "=" )"
    CONTENT_SECURITY_POLICY_BASE64_VALUE_EMPTY = {
        id: "content_security_policy_base64_value_empty",
        title: "A nonce or hash source names no value",
        message: "",
        default_severity: Severity::Warn,
        spec: &[CSP3_2_3_1],
    }

    /// A nonce whose value holds a character `base64-value` does not admit —
    /// in practice an octet like %xA0, since a source list is cut apart on
    /// ASCII whitespace and an ordinary space can never reach the inside of one.
    ///
    /// `_malformed` rather than the `_character_forbidden` half of the pair,
    /// and it is the directive-name reasoning run the other way: here the octet
    /// that *can* arrive is precisely the one nobody typed, so naming the
    /// character class would draw the id whose case does not occur. What the
    /// finding says is that the value does not derive.
    ///
    // cite(CSP3 § 2.3.1, label: base64-value grammar): "base64-value  = 1*( ALPHA / DIGIT / "+" / "/" / "-" / "_" )*2( "=" )"
    CONTENT_SECURITY_POLICY_BASE64_VALUE_MALFORMED = {
        id: "content_security_policy_base64_value_malformed",
        title: "A nonce value holds a character base64-value does not admit",
        message: "",
        default_severity: Severity::Warn,
        spec: &[CSP3_2_3_1],
    }

    /// A response whose `X-Frame-Options` and whose `frame-ancestors` say
    /// different things about who may embed it: `DENY` beside a policy that
    /// permits framing, `SAMEORIGIN` beside `'none'`, an `ALLOW-FROM` naming an
    /// origin the policy does not list.
    ///
    /// **One entry over five shapes, because the claim, the sender and the
    /// repair are one.** A server wrote two framing policies into one response
    /// and they disagree; the fix is to make them agree, whichever way. The
    /// message says which pair was in front of it.
    ///
    /// **The disagreement is real even though the specification resolves it**,
    /// which is the whole reason the entry is worth having. § 6.4.2.2 says an
    /// enforced `frame-ancestors` overrides `X-Frame-Options`, so a modern user
    /// agent is never confused — it reads the CSP and ignores the other header.
    /// What the finding reports is the *deployment*: two policies maintained in
    /// one response, one of which is dead on arrival at every browser that
    /// implements CSP and live at every one that does not. An operator reading
    /// the headers cannot tell which is in force without knowing that sentence.
    ///
    /// `warn`, and the direction of the mistake is why it is not `info`: the
    /// header that loses is the legacy one, so a `DENY` that a policy overrides
    /// is a framing restriction the deployment believes it has and does not.
    ///
    // cite(CSP3 § 6.4.2): "The frame-ancestors directive restricts the URLs which can embed the resource using frame, iframe, object, or embed."
    // cite(CSP3 § 6.4.2.2, label: frame-ancestors overrides X-Frame-Options): "In order to allow backwards-compatible deployment, the frame-ancestors directive overrides the"
    CONTENT_SECURITY_POLICY_FRAME_ANCESTORS_CONFLICTING = {
        id: "content_security_policy_frame_ancestors_conflicting",
        title: "frame-ancestors and X-Frame-Options state different framing policies",
        message: "",
        default_severity: Severity::Warn,
        spec: &[CSP3_6_4_2],
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
