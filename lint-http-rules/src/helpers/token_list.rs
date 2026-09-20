// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `#token` — a comma-separated list whose every member is a bare `token`, and
//! the two ways a sender writes one that no such list generates.
//!
//! **A shelf keyed by the question, not by the field.** `Vary = #( "*" /
//! field-name )`, `Allow = #method`, `Access-Control-Allow-Methods = #method`
//! and `Access-Control-Expose-Headers = #field-name` are four fields, three
//! documents and one construct: a list whose members carry no parameters, no
//! quoting and no weight, so the only things that can be wrong with one are
//! § 5.6.1.1's empty element and an octet `tchar` does not admit. What the
//! field then adds is what the tokens *mean*, which is the rule's and never
//! this module's.
//!
//! **`*` needs no arm here, and that is the production's doing rather than an
//! omission.** Three of the fields above give the asterisk a meaning of its
//! own, and `tchar` admits it — `"!" / "#" / "$" / "%" / "&" / "'" / "*" / …`
//! — so a wildcard is a `token` before it is a wildcard and this walk has
//! nothing to say about it. A `wildcard` argument would have been a second
//! spelling of the same answer, and one the caller could get wrong.
//!
//! **Every member is answered, not the first.** A value is one line and the
//! sender wrote each member separately, so `X-Foo:, X B` is two mistakes and
//! reporting one of them tells an operator to fix half a header. The empty
//! element is the exception and is the list's rather than a member's: what
//! § 5.6.1.1 forbids generating is an empty *element*, so a line with three
//! gaps in it is one list written with gaps.
//!
//! **What is not here is the `1#` floor.** A plain `#element` derives the empty
//! list and a `1#element` does not, and which of the two a field writes is a
//! fact about that field's own grammar — so the caller reads it, declares
//! [`crate::violations::list::LIST_MEMBER_MISSING`] if it has a floor, and this
//! walk stays the same function for both.

use crate::helpers::headers::trim_ows;
use crate::helpers::list::list_members;
use crate::helpers::token::find_invalid_token_char;

/// What one reading of a `#token` list found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenListDefect<'a> {
    /// A leading, trailing or doubled comma: § 5.6.1.1's empty element.
    /// Answered once for the line however many gaps it holds.
    EmptyMember,
    /// A member holding an octet `tchar` does not admit, and the octet. The
    /// member is carried because the octet alone does not identify it: a value
    /// offending in two members would otherwise say one sentence twice.
    Character {
        /// The member as the sender wrote it, `OWS` taken.
        member: &'a str,
        /// The first octet in it that is no `tchar`.
        offending: char,
    },
}

/// Read `value` as `#token`, answering for every member.
///
/// The order is the list's own: the empty-element finding comes first because
/// it is a statement about the line, and the member findings follow in the
/// order the sender wrote them.
///
/// An entirely empty value yields nothing. `#element` derives the empty list,
/// so the value is legal here; a field spelled `1#element` has a floor its own
/// rule reads, and the caller reports that rather than this function inventing
/// a defect the production does not have.
// cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
// cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
pub fn token_list_defects(value: &str) -> Vec<TokenListDefect<'_>> {
    let mut out = Vec::new();
    let s = trim_ows(value);
    if s.is_empty() {
        return out;
    }

    // Read off the raw split rather than off `list_members`, which drops the
    // empty member — a walk over the members cannot see the sender's comma,
    // so asking it about gaps would answer `no` for every value there is.
    if s.split(',').any(|raw| trim_ows(raw).is_empty()) {
        out.push(TokenListDefect::EmptyMember);
    }

    for member in list_members(s) {
        if let Some(offending) = find_invalid_token_char(member) {
            out.push(TokenListDefect::Character { member, offending });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_of_tokens_has_nothing_wrong_with_it() {
        for value in [
            "GET, HEAD, POST",
            "Accept-Encoding,Content-Type",
            // `tchar` admits the asterisk, so a wildcard needs no arm.
            "*",
            "*, X-Foo",
            // `#element` derives the empty list.
            "",
            "   ",
        ] {
            assert_eq!(token_list_defects(value), Vec::new(), "for {value:?}");
        }
    }

    #[test]
    fn a_gap_is_the_lists_defect_and_is_answered_once() {
        assert_eq!(
            token_list_defects("X-Foo,,X-Baz"),
            vec![TokenListDefect::EmptyMember]
        );
        // Three gaps, one list written with gaps in it.
        assert_eq!(
            token_list_defects(",X-Foo,,X-Baz,"),
            vec![TokenListDefect::EmptyMember]
        );
    }

    /// The whole point of carrying the member: two offending members are two
    /// findings and an operator has to be able to tell them apart.
    #[test]
    fn every_member_is_answered_and_each_names_itself() {
        assert_eq!(
            token_list_defects("Acc@pt, Us@r"),
            vec![
                TokenListDefect::Character {
                    member: "Acc@pt",
                    offending: '@'
                },
                TokenListDefect::Character {
                    member: "Us@r",
                    offending: '@'
                },
            ]
        );
    }

    /// A space *inside* a member is the octet class the two entries split on,
    /// and it survives the `OWS` taken off the member's edges.
    #[test]
    fn whitespace_inside_a_member_is_the_members_octet() {
        assert_eq!(
            token_list_defects("  X-Foo X-Bar  "),
            vec![TokenListDefect::Character {
                member: "X-Foo X-Bar",
                offending: ' '
            }]
        );
    }

    /// A value can be wrong in both ways at once, and the line's finding comes
    /// before the members'.
    #[test]
    fn a_gap_and_a_bad_member_are_both_reported() {
        assert_eq!(
            token_list_defects("X-Foo,,X B"),
            vec![
                TokenListDefect::EmptyMember,
                TokenListDefect::Character {
                    member: "X B",
                    offending: ' '
                },
            ]
        );
    }
}
