// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Cache-Control` defects — what a *named* directive means by its argument.
//!
//! Nothing about this field's grammar is its own. RFC 9111 § 1.2.1 imports
//! `token`, `quoted-string` and `field-name` from RFC 9110 by reference and
//! takes the list construct from § 5.6.1, so a directive name holding a `@`, a
//! member written blank and an unterminated quoted argument all report the ids
//! any other field written out of those productions reports.
//!
//! **What is left is the layer above the grammar: a directive whose definition
//! says what its argument must say.** `cache-directive = token [ "=" ( token /
//! quoted-string ) ]` is satisfied by `private=""` — the argument derives, and
//! the empty interior of a `quoted-string` is a `quoted-string`. What fails is
//! the sentence in the directive's own subsection, which is where the
//! qualified form is defined as listing one or more field names.
//!
//! **Two entries, one per directive, because the requirement is written once
//! per directive and every site knows which it read.** The two senders wrote
//! the same mistake and would apply the same fix, so this is 2 sentences rather
//! than 2 defects — and the line the catalogue draws is that folding them would
//! cost a citation both halves can carry: an entry naming § 5.2.2.4 and
//! § 5.2.2.7 together governs neither finding, where an entry per directive
//! sends an operator to the paragraph that defines what they wrote.
//!
//! **Both are `info`, and the two Notes are the argument.** A cache that cannot
//! read the qualification handles the directive as if the unqualified form had
//! arrived — which both sections say is the common implementation anyway — and
//! the unqualified form of each of these is the *stricter* one: an unqualified
//! `private` keeps the whole response out of a shared cache, an unqualified
//! `no-cache` revalidates the whole response. So nothing a recipient does with
//! the value is wrong, and what the sender loses is the exemption they asked
//! for. The exchange continues, and continues conservatively.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The `no-cache` directive: its argument syntax, the qualified form defined as
/// listing field names, and the Note that caches commonly treat that form as
/// the unqualified one.
pub const RFC_9111_5_2_2_4: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("5.2.2.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.4",
    note: "no-cache — argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified no-cache",
};

/// The `private` directive, written to the same shape: an argument syntax, a
/// qualified form that lists field names, and the same Note about how the form
/// is handled in practice.
pub const RFC_9111_5_2_2_7: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("5.2.2.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.7",
    note: "private — argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified private",
};

defects! {
    /// `no-cache=""`: the qualified form written with an argument that lists no
    /// field name at all.
    ///
    /// The grammar has nothing to say about it — `cache-directive = token [ "="
    /// ( token / quoted-string ) ]` derives the empty `quoted-string`, and
    /// `#field-name` is a plain `#`, which generates a list of none. What the
    /// value contradicts is the paragraph that defines the form the sender
    /// reached for: an argument that lists *one or more* field names.
    ///
    /// Not the empty *element*: `no-cache=","` is a list with two blanks in it,
    /// which is [`list_member_empty`](crate::violations::list)'s sender MUST
    /// NOT and a different mistake. And not `no-cache=` either — a `=` with
    /// nothing after it is the leniency the two `Cache-Control` rules record
    /// between them, one level below this entry.
    ///
    // cite(RFC 9111 § 5.2.2.4): "The qualified form of the no-cache response directive, with an argument that lists one or more field names"
    CACHE_CONTROL_NO_CACHE_ARGUMENT_EMPTY = {
        id: "cache_control_no_cache_argument_empty",
        title: "Cache-Control no-cache is qualified by no field name",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9111_5_2_2_4],
    }

    /// `private=""`: the same shape under the other directive that takes a
    /// `#field-name` argument, and its own section states the requirement in
    /// its own words.
    ///
    /// The sibling entry's reading applies unchanged, which is why the two are
    /// worded alike and ranked alike: what separates them is the sentence a
    /// finding names, and a site always knows which directive it read.
    ///
    // cite(RFC 9111 § 5.2.2.7): "If a qualified private response directive is present, with an argument that lists one or more field names"
    CACHE_CONTROL_PRIVATE_ARGUMENT_EMPTY = {
        id: "cache_control_private_argument_empty",
        title: "Cache-Control private is qualified by no field name",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9111_5_2_2_7],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair is two sentences and one defect, which is the whole reason the
    /// ids differ and nothing else about them does.
    #[test]
    fn the_pair_differs_only_in_the_sentence_it_names() {
        assert_eq!(
            CACHE_CONTROL_NO_CACHE_ARGUMENT_EMPTY.default_severity,
            CACHE_CONTROL_PRIVATE_ARGUMENT_EMPTY.default_severity,
        );
        assert_eq!(
            CACHE_CONTROL_NO_CACHE_ARGUMENT_EMPTY.default_severity,
            Severity::Info,
        );
        assert_eq!(
            CACHE_CONTROL_NO_CACHE_ARGUMENT_EMPTY.spec,
            [RFC_9111_5_2_2_4]
        );
        assert_eq!(
            CACHE_CONTROL_PRIVATE_ARGUMENT_EMPTY.spec,
            [RFC_9111_5_2_2_7]
        );
    }
}
