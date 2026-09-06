// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Mailbox defects — the ways a value is not RFC 5322's `mailbox`.
//!
//! The subject is the production, not the field: RFC 9110 § 10.1.2 gives `From`
//! a value of `mailbox` and imports it by reference, so every defect here is
//! answered by a document HTTP does not own and by a sentence that says nothing
//! about which field carried the value.
//!
//! Eighteen entries, because the grammar refuses a value in eighteen places and
//! each one has its own line of ABNF behind it. That is the shape a fan-out
//! site takes when it converts: one call site cited RFC 5322 § 3.4 — the
//! greatest common sentence over everything the reader can find — and each
//! defect now carries the production that actually stopped.
//!
//! Two things this subject does *not* split, both deliberate. There is no
//! whitespace-or-control entry beside the character ones: RFC 5322 writes
//! `atext`, `qtext`, `ctext` and `dtext` as ranges that stop at %x7E, so the
//! octet nobody typed and the special nobody may write are refused by the same
//! sentence, in the same construct, and an operator fixing one fixes the other.
//! And the two `quoted-pair` failures — a backslash quoting nothing, a
//! backslash quoting an octet the pair does not admit — are one def, because
//! the fix is one fix: the escape.
//!
//! The severities are all `warn`, which is the first subject where that is
//! true. Nothing here is a value a user agent quietly discards (the cookie's
//! `Path`) and nothing is an octet a US-ASCII grammar admits and this crate
//! refuses anyway (the cookie's whitespace): every entry is one production
//! refusing one value, and RFC 9110 § 2.2's MUST NOT reaches all of them
//! equally.

use crate::helpers::mailbox::MailboxSyntaxDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The `quoted-pair`, which is one production and one defect.
pub const RFC_5322_3_2_1: SpecRef = SpecRef {
    spec: "RFC 5322",
    section: Some("3.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.1",
    note: "`quoted-pair` — the backslash and the one `VCHAR` or `WSP` it owes",
};

/// `CFWS`, and the `comment` inside it: folding whitespace and nested
/// parenthesised comments, admitted around nearly every token of a mailbox.
pub const RFC_5322_3_2_2: SpecRef = SpecRef {
    spec: "RFC 5322",
    section: Some("3.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.2",
    note: "`CFWS`, `comment` and `ctext` — the comment names itself, so what it holds is balanced and its character class stops at %x7E",
};

/// `atext` and the `dot-atom` built on it — the `1*atext` floor either side of
/// every dot.
pub const RFC_5322_3_2_3: SpecRef = SpecRef {
    spec: "RFC 5322",
    section: Some("3.2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.3",
    note: "`atext`, `atom` and `dot-atom-text` — the printable US-ASCII an atom is made of, and the floor a dot may not leave empty",
};

/// The `quoted-string`, the alternative a local-part or a display-name's word
/// may take instead of an atom.
pub const RFC_5322_3_2_4: SpecRef = SpecRef {
    spec: "RFC 5322",
    section: Some("3.2.4"),
    url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.4",
    note: "`quoted-string` and `qtext` — the quoted alternative, and the class it admits between the two DQUOTEs",
};

/// The `phrase` a display-name is, and the `word` it is made of.
pub const RFC_5322_3_2_5: SpecRef = SpecRef {
    spec: "RFC 5322",
    section: Some("3.2.5"),
    url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.5",
    note: "`phrase = 1*word` — a display-name holds at least one atom or quoted-string, and `obs-phrase`'s bare `.` is not one",
};

/// `mailbox` itself: the two alternatives, and `mailbox-list` printed two lines
/// below the one a field imports.
pub const RFC_5322_3_4: SpecRef = SpecRef {
    spec: "RFC 5322",
    section: Some("3.4"),
    url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4",
    note: "`mailbox = name-addr / addr-spec`, `angle-addr` beside it, and `mailbox-list` — the neighbouring production a top-level comma derives from",
};

/// The `addr-spec`: the at-sign, the two halves it separates, and the bracketed
/// literal a domain may be instead of a name.
pub const RFC_5322_3_4_1: SpecRef = SpecRef {
    spec: "RFC 5322",
    section: Some("3.4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4.1",
    note: "`addr-spec = local-part \"@\" domain`, and the `domain-literal` alternative with the `dtext` inside it",
};

defects! {
    /// A field that is present and carries nothing. Both of `mailbox`'s
    /// alternatives contain an `addr-spec`, and `addr-spec` writes a literal
    /// `"@"`, so the shortest value the production generates is not the empty
    /// one — whichever alternative each half takes.
    ///
    /// The argument is deliberately about the at-sign and not about a `1*atext`
    /// floor: a `quoted-string` local-part has no such floor (`""` derives), and
    /// neither does a `domain-literal` (`[]` derives). Only the literal
    /// character between them is owed by every derivation.
    ///
    // cite(RFC 5322 § 3.4.1): "addr-spec = local-part "@" domain"
    MAILBOX_EMPTY = {
        id: "mailbox_empty",
        title: "Mailbox field is present with an empty value",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_4_1),
    }

    /// A comma outside every `quoted-string`, `comment` and `angle-addr`. The
    /// one defect here whose answer is a *neighbouring production*: the value
    /// derives from `mailbox-list`, printed two lines below `mailbox` in the
    /// same section, so what happened is not a stray character but a list
    /// written where one address goes.
    ///
    // cite(RFC 5322 § 3.4): "mailbox-list = (mailbox *("," mailbox)) / obs-mbox-list"
    MAILBOX_LIST_SEPARATOR_FORBIDDEN = {
        id: "mailbox_list_separator_forbidden",
        title: "Mailbox holds a comma where one address goes",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_4),
    }

    /// An octet inside a parenthesised `comment` that `ctext` does not admit.
    ///
    // cite(RFC 5322 § 3.2.2): "ctext = %d33-39 / ; Printable US-ASCII %d42-91 / ; characters not including %d93-126 / ; "(", ")", or "\" obs-ctext"
    MAILBOX_COMMENT_CHARACTER_FORBIDDEN = {
        id: "mailbox_comment_character_forbidden",
        title: "Mailbox comment holds a character outside ctext",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_2_2),
    }

    /// A `comment` opened and never closed. The count is the production and
    /// not a convenience — `comment` names itself — so this is a parenthesis
    /// missing at whatever depth the value reached.
    ///
    // cite(RFC 5322 § 3.2.2): "comment = "(" *([FWS] ccontent) [FWS] ")""
    MAILBOX_COMMENT_TERMINATOR_MISSING = {
        id: "mailbox_comment_terminator_missing",
        title: "Mailbox comment is never closed",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_2_2),
    }

    /// An octet between two DQUOTEs that `qtext` does not admit — and that no
    /// `quoted-pair` escaped, since the backslash form is checked first.
    ///
    // cite(RFC 5322 § 3.2.4): "qtext = %d33 / ; Printable US-ASCII %d35-91 / ; characters not including %d93-126 / ; "\" or the quote character obs-qtext"
    MAILBOX_QUOTED_STRING_CHARACTER_FORBIDDEN = {
        id: "mailbox_quoted_string_character_forbidden",
        title: "Mailbox quoted-string holds a character outside qtext",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_2_4),
    }

    /// A `quoted-string` opened and never closed — the closing DQUOTE is not
    /// there, so everything after the opening one was read as quoted text.
    ///
    // cite(RFC 5322 § 3.2.4): "quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]"
    MAILBOX_QUOTED_STRING_TERMINATOR_MISSING = {
        id: "mailbox_quoted_string_terminator_missing",
        title: "Mailbox quoted-string is never closed",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_2_4),
    }

    /// A backslash quoting nothing, or quoting an octet that is neither
    /// `VCHAR` nor `WSP`. One def for both, because the fix is one fix — the
    /// escape — wherever the pair sits.
    ///
    // cite(RFC 5322 § 3.2.1): "quoted-pair = ("\" (VCHAR / WSP)) / obs-qp"
    MAILBOX_QUOTED_PAIR_MALFORMED = {
        id: "mailbox_quoted_pair_malformed",
        title: "Mailbox escape is not a quoted-pair",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_2_1),
    }

    /// An octet in a `dot-atom` — the `local-part` or the `domain` — that
    /// `atext` does not admit. Every `special` is here as well as every octet
    /// above %x7E: `@` inside a local-part reports as this and not as a missing
    /// at-sign, because the at-sign the `addr-spec` wants is the one *after*
    /// the atom.
    ///
    // cite(RFC 5322 § 3.2.3): "atext = ALPHA / DIGIT / ; Printable US-ASCII "!" / "#" / ; characters not including "$" / "%" / ; specials. Used for atoms. "&" / "'" / "*" / "+" / "-" / "/" / "=" / "?" / "^" / "_" / "`" / "{" / "|" / "}" / "~""
    MAILBOX_ATOM_CHARACTER_FORBIDDEN = {
        id: "mailbox_atom_character_forbidden",
        title: "Mailbox atom holds a character outside atext",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_2_3),
    }

    /// A `.` with no `atext` after it: a trailing dot, or two of them in a row.
    /// The dot separates atoms and every atom has a `1*atext` floor, so a dot
    /// at either end of nothing describes an atom that is not there.
    ///
    // cite(RFC 5322 § 3.2.3): "dot-atom-text = 1*atext *("." 1*atext)"
    MAILBOX_ATOM_EMPTY = {
        id: "mailbox_atom_empty",
        title: "Mailbox atom is empty beside a dot",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_2_3),
    }

    /// The value ends where the `addr-spec` has its `local-part` — the half
    /// before the at-sign, which is either a `dot-atom` or a `quoted-string`
    /// and cannot be nothing.
    ///
    // cite(RFC 5322 § 3.4.1): "local-part = dot-atom / quoted-string / obs-local-part"
    MAILBOX_LOCAL_PART_MISSING = {
        id: "mailbox_local_part_missing",
        title: "Mailbox has no local-part",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_4_1),
    }

    /// No `"@"` where the `addr-spec` writes one — the defect a value with no
    /// address in it at all comes to, `not-an-email` being the shortest
    /// example.
    ///
    // cite(RFC 5322 § 3.4.1): "An addr-spec is a specific Internet identifier that contains a locally interpreted string followed by the at-sign character ("@", ASCII value 64) followed by an Internet domain."
    MAILBOX_AT_SIGN_MISSING = {
        id: "mailbox_at_sign_missing",
        title: "Mailbox has no at-sign",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_4_1),
    }

    /// The value ends where the `addr-spec` has its `domain` — `alice@` and
    /// nothing after it.
    ///
    // cite(RFC 5322 § 3.4.1): "domain = dot-atom / domain-literal / obs-domain"
    MAILBOX_DOMAIN_MISSING = {
        id: "mailbox_domain_missing",
        title: "Mailbox has no domain",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_4_1),
    }

    /// An octet inside a bracketed `domain-literal` that `dtext` does not
    /// admit. The literal is an address written where a name would go, and its
    /// class is its own — wider than `atext`, and stopping at %x7E like the
    /// rest.
    ///
    // cite(RFC 5322 § 3.4.1): "dtext = %d33-90 / ; Printable US-ASCII %d94-126 / ; characters not including obs-dtext ; "[", "]", or "\""
    MAILBOX_DOMAIN_LITERAL_CHARACTER_FORBIDDEN = {
        id: "mailbox_domain_literal_character_forbidden",
        title: "Mailbox domain-literal holds a character outside dtext",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_4_1),
    }

    /// A `domain-literal` opened and never closed: the `]` is missing, so the
    /// address inside it runs to the end of the value.
    ///
    // cite(RFC 5322 § 3.4.1): "domain-literal = [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]"
    MAILBOX_DOMAIN_LITERAL_TERMINATOR_MISSING = {
        id: "mailbox_domain_literal_terminator_missing",
        title: "Mailbox domain-literal is never closed",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_4_1),
    }

    /// Something between the display-name and the `angle-addr` that no `word`
    /// admits — `John Q. Public <jqp@example.com>`, where the bare `.` is
    /// `obs-phrase` and § 4 forbids generating it.
    ///
    // cite(RFC 5322 § 3.4): "name-addr = [display-name] angle-addr"
    MAILBOX_ANGLE_ADDR_MISSING = {
        id: "mailbox_angle_addr_missing",
        title: "Mailbox has no angle-addr where the name-addr wants one",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_4),
    }

    /// An `angle-addr` opened and never closed — the `>` is missing, or
    /// something else is where it must be.
    ///
    // cite(RFC 5322 § 3.4): "angle-addr = [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr"
    MAILBOX_ANGLE_ADDR_TERMINATOR_MISSING = {
        id: "mailbox_angle_addr_terminator_missing",
        title: "Mailbox angle-addr is never closed",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_4),
    }

    /// A display-name that was opened and holds no `word` at all. The
    /// display-name is optional — `<alice@example.com>` is a whole `name-addr`
    /// — so this is a value that started one and put nothing an atom or a
    /// quoted-string admits in it.
    ///
    // cite(RFC 5322 § 3.2.5): "phrase = 1*word / obs-phrase"
    MAILBOX_DISPLAY_NAME_WORD_MISSING = {
        id: "mailbox_display_name_word_missing",
        title: "Mailbox display-name holds no word",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_2_5),
    }

    /// A complete `mailbox` with something after it that is not a comma. One
    /// address is the whole production, so whatever follows derives from
    /// nothing — a space inside a domain is the usual way to reach this.
    ///
    // cite(RFC 5322 § 3.4): "mailbox = name-addr / addr-spec"
    MAILBOX_TRAILING_CHARACTER_FORBIDDEN = {
        id: "mailbox_trailing_character_forbidden",
        title: "Mailbox is followed by something else",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_5322_3_4),
    }
}

/// The defect a parsed [`MailboxSyntaxDefect`] reports as.
///
/// The reader answers *what the grammar refused* and this answers *what it is
/// called*, matched in one place rather than at every field that carries a
/// mailbox. Exhaustive on purpose: a new variant in the reader does not compile
/// until it is named here, which is the only way a defect can fail to reach the
/// catalogue.
pub fn syntax_defect(defect: MailboxSyntaxDefect) -> &'static ViolationDef {
    match defect {
        MailboxSyntaxDefect::CommentCharacter(_) => &MAILBOX_COMMENT_CHARACTER_FORBIDDEN,
        MailboxSyntaxDefect::CommentUnterminated => &MAILBOX_COMMENT_TERMINATOR_MISSING,
        MailboxSyntaxDefect::QuotedStringCharacter(_) => &MAILBOX_QUOTED_STRING_CHARACTER_FORBIDDEN,
        MailboxSyntaxDefect::QuotedStringUnterminated => &MAILBOX_QUOTED_STRING_TERMINATOR_MISSING,
        MailboxSyntaxDefect::QuotedPairAtEnd { .. }
        | MailboxSyntaxDefect::QuotedPairCharacter { .. } => &MAILBOX_QUOTED_PAIR_MALFORMED,
        MailboxSyntaxDefect::AtomCharacter { .. } => &MAILBOX_ATOM_CHARACTER_FORBIDDEN,
        MailboxSyntaxDefect::AtomEmpty { .. } => &MAILBOX_ATOM_EMPTY,
        MailboxSyntaxDefect::LocalPartMissing => &MAILBOX_LOCAL_PART_MISSING,
        MailboxSyntaxDefect::AtSignMissing(_) => &MAILBOX_AT_SIGN_MISSING,
        MailboxSyntaxDefect::DomainMissing => &MAILBOX_DOMAIN_MISSING,
        MailboxSyntaxDefect::DomainLiteralCharacter(_) => {
            &MAILBOX_DOMAIN_LITERAL_CHARACTER_FORBIDDEN
        }
        MailboxSyntaxDefect::DomainLiteralUnterminated => {
            &MAILBOX_DOMAIN_LITERAL_TERMINATOR_MISSING
        }
        MailboxSyntaxDefect::AngleAddrMissing(_) => &MAILBOX_ANGLE_ADDR_MISSING,
        MailboxSyntaxDefect::AngleAddrUnterminated(_) => &MAILBOX_ANGLE_ADDR_TERMINATOR_MISSING,
        MailboxSyntaxDefect::DisplayNameWordMissing(_) => &MAILBOX_DISPLAY_NAME_WORD_MISSING,
        MailboxSyntaxDefect::TrailingCharacter(_) => &MAILBOX_TRAILING_CHARACTER_FORBIDDEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping, spelled out — including the one place two variants answer
    /// with one def, which is a decision and not an oversight. A variant
    /// answering with its neighbour's def would report the right sentence under
    /// the wrong name at the wrong configured severity, and every other gate
    /// here would pass.
    #[test]
    fn each_syntax_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (
                MailboxSyntaxDefect::CommentCharacter('\u{e9}'),
                "mailbox_comment_character_forbidden",
            ),
            (
                MailboxSyntaxDefect::CommentUnterminated,
                "mailbox_comment_terminator_missing",
            ),
            (
                MailboxSyntaxDefect::QuotedStringCharacter('\u{e9}'),
                "mailbox_quoted_string_character_forbidden",
            ),
            (
                MailboxSyntaxDefect::QuotedStringUnterminated,
                "mailbox_quoted_string_terminator_missing",
            ),
            (
                MailboxSyntaxDefect::QuotedPairAtEnd {
                    inside: "quoted-string",
                },
                "mailbox_quoted_pair_malformed",
            ),
            (
                MailboxSyntaxDefect::QuotedPairCharacter {
                    inside: "comment",
                    character: '\u{e9}',
                },
                "mailbox_quoted_pair_malformed",
            ),
            (
                MailboxSyntaxDefect::AtomCharacter {
                    what: "local-part",
                    character: '@',
                },
                "mailbox_atom_character_forbidden",
            ),
            (
                MailboxSyntaxDefect::AtomEmpty { what: "domain" },
                "mailbox_atom_empty",
            ),
            (
                MailboxSyntaxDefect::LocalPartMissing,
                "mailbox_local_part_missing",
            ),
            (
                MailboxSyntaxDefect::AtSignMissing(None),
                "mailbox_at_sign_missing",
            ),
            (MailboxSyntaxDefect::DomainMissing, "mailbox_domain_missing"),
            (
                MailboxSyntaxDefect::DomainLiteralCharacter('\u{e9}'),
                "mailbox_domain_literal_character_forbidden",
            ),
            (
                MailboxSyntaxDefect::DomainLiteralUnterminated,
                "mailbox_domain_literal_terminator_missing",
            ),
            (
                MailboxSyntaxDefect::AngleAddrMissing(Some('.')),
                "mailbox_angle_addr_missing",
            ),
            (
                MailboxSyntaxDefect::AngleAddrUnterminated(None),
                "mailbox_angle_addr_terminator_missing",
            ),
            (
                MailboxSyntaxDefect::DisplayNameWordMissing(Some('.')),
                "mailbox_display_name_word_missing",
            ),
            (
                MailboxSyntaxDefect::TrailingCharacter('m'),
                "mailbox_trailing_character_forbidden",
            ),
        ] {
            assert_eq!(syntax_defect(defect).id, id);
        }
    }

    /// Every defect here formats its message at the site — the reader holds the
    /// octet and the production, and neither fits in a catalogue entry. This is
    /// the half of the `report`/`report_with` invariant a subject can assert on
    /// its own.
    #[test]
    fn no_mailbox_defect_holds_its_own_message() {
        for def in crate::violations::VIOLATIONS
            .iter()
            .filter(|d| d.id.starts_with("mailbox_"))
        {
            assert!(def.message.is_empty(), "{} holds a message", def.id);
        }
    }
}
