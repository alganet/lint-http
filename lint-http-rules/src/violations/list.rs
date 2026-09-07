// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! List defects — the `#` construct HTTP writes its comma-separated fields in.
//!
//! Twenty-three rules in this tree quote the same sentence: a sender must not
//! generate an empty list element. It is one requirement, written once, about a
//! construct that every list-valued field borrows unchanged — so the stray
//! comma in `Accept-Encoding: gzip,,br`, in `Vary: ,`, in a `Cache-Control` and
//! in a `Pragma` is one defect with one name, however differently each rule
//! words the finding.
//!
//! **Two entries, and they are the pair the id convention warns about.**
//! `list_member_empty` is a member a sender wrote and left blank;
//! `list_member_missing` is a `1#` list with no non-empty member at all. Two
//! sentences, two fixes — remove the comma, or name the thing.
//!
//! **A value of nothing but commas breaks both, and the catalogue records that
//! rather than resolving it.** `Warning: ,` has two empty elements § 5.6.1.1
//! forbids *and* no element the `1#` floor requires, and § 5.6.1.2 prints that
//! very value among the ones the production does not generate. Which id a rule
//! answers with is therefore its branch order, and the rules here differ:
//! `warning_header_syntax` and `sec_websocket_headers_consistent` ask the floor
//! first, `accept_ranges_values_valid` asks the members. Both statements are
//! true of the value; picking one for the whole tree would mean changing what a
//! rule *says*, which is a rule's decision and not a catalogue's.
//!
//! What is deliberately *not* here is the recipient's half. § 5.6.1.2 tells a
//! recipient to ignore empty elements, and this catalogue reports the sender's
//! requirement: a rule that drops the member rather than reporting it is doing
//! the recipient's job, which is the correction several of those rules already
//! carry in their own comments. **The floor's sentence nonetheless lives in that
//! same recipient section**, printed as an example of what the production does
//! not generate — so the section a sentence sits in is not what decides whose
//! requirement it states.

use crate::helpers::cache_control::MemberDefect as CacheControlMemberDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::token::{token_character, TOKEN_EMPTY};
use crate::violations::{defects, ViolationDef};

/// The list construct: what `#` expands to, and the one thing a sender may not
/// do with it.
pub const RFC_9110_5_6_1_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1",
    note: "The list construct — `1#element => element *( OWS \",\" OWS element )`, and the sender's MUST NOT against an empty element",
};

/// Where the `1#` floor is written down, in the worked examples rather than in
/// a requirement of its own.
pub const RFC_9110_5_6_1_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2",
    note: "The values a `1#element` production does not generate — the empty value among them — beside the recipient's instruction to ignore empty elements",
};

defects! {
    /// A member that contributes nothing to the list: two commas in a row, a
    /// leading one, a trailing one, or a member holding only whitespace. The
    /// grammar generates the comma *between* elements, so an element that is
    /// not there is a comma that should not be.
    ///
    /// One id for every list-valued field, because it is one sentence for every
    /// list-valued field — and the fix is the same comma either way.
    ///
    // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
    LIST_MEMBER_EMPTY = {
        id: "list_member_empty",
        title: "List holds an empty element",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_5_6_1_1),
    }

    /// A list written with a floor under it and nothing above the floor: a
    /// `1#element` field whose value is empty, or holds only whitespace. The
    /// field line exists and states none of the thing it is defined to state.
    ///
    /// **The `#` half of the construct is not this defect and must not be
    /// reported as one.** A plain `#element` generates the empty list, and
    /// several fields here say so on the record — an empty `Vary` and an empty
    /// `Allow` are legal values with meanings of their own. Only the `1#`
    /// spelling has a floor, so a rule declaring this one is a rule that has
    /// read which of the two its field uses.
    ///
    /// Level with [`LIST_MEMBER_EMPTY`] on purpose. Both are the sender failing
    /// the same construct, no sentence ranks them, and manufacturing a split
    /// between them would be the catalogue inventing a preference the
    /// specification does not state. It also keeps the value that breaks both —
    /// a field of nothing but commas — reporting at one level whichever branch
    /// a rule happens to ask first.
    ///
    // cite(RFC 9110 § 5.6.1.2): "In contrast, the following values would be invalid, since at least one non-empty element is required by the example-list production:"
    LIST_MEMBER_MISSING = {
        id: "list_member_missing",
        title: "List with a one-element floor holds no element",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_5_6_1_2),
    }
}

/// The defect one `Cache-Control` list member reports as.
///
/// The reader is [`crate::helpers::cache_control::read_member`], shared by the
/// two rules that measure that field's syntax, and none of its three defects is
/// the field's: the first is this subject's, and the other two are the `token`
/// a directive name has to be. The mapping lives here rather than beside the
/// name's subject because the first thing the reader measures is the list
/// member — and there is no `cache_control` subject file for it to live in,
/// since a file holding no defect has no statement to cite and the citation
/// ratchet reads every file under `violations/`.
pub fn cache_directive_member(defect: CacheControlMemberDefect<'_>) -> &'static ViolationDef {
    match defect {
        CacheControlMemberDefect::Empty => &LIST_MEMBER_EMPTY,
        CacheControlMemberDefect::NameEmpty(_) => &TOKEN_EMPTY,
        CacheControlMemberDefect::NameCharacter(c) => token_character(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three variants, three subjects' answers — and only the first of them is
    /// this file's, which is the finding worth pinning: a `Cache-Control`
    /// member that fails does so at the list, at the token, or not at all.
    #[test]
    fn a_cache_control_member_answers_with_the_production_it_failed() {
        for (defect, id) in [
            (CacheControlMemberDefect::Empty, "list_member_empty"),
            (CacheControlMemberDefect::NameEmpty("=abc"), "token_empty"),
            (
                CacheControlMemberDefect::NameCharacter('@'),
                "token_character_forbidden",
            ),
            (
                CacheControlMemberDefect::NameCharacter(' '),
                "token_whitespace_or_control_forbidden",
            ),
        ] {
            assert_eq!(cache_directive_member(defect).id, id);
        }
    }

    /// The whole of this subject so far, and the assertion that matters about
    /// it: the id names the construct and no field.
    #[test]
    fn the_empty_member_is_named_after_the_list_and_not_after_a_field() {
        assert_eq!(LIST_MEMBER_EMPTY.id, "list_member_empty");
        assert_eq!(LIST_MEMBER_EMPTY.default_severity, Severity::Warn);
    }
}
