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

/// Freshness and age calculations, and the sentence about a directive given
/// more than one value.
pub const RFC_9111_4_2_1: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("4.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.1",
    note: "Calculating Freshness Lifetime — the order a cache consults `s-maxage`, `max-age` and `Expires` in, and what it may do when one directive is present more than once",
};

/// The `public` response directive.
pub const RFC_9111_5_2_2_9: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("5.2.2.9"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.9",
    note: "`public` — a cache MAY store the response even where it would otherwise be prohibited",
};

/// The `no-store` response directive.
pub const RFC_9111_5_2_2_5: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("5.2.2.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.5",
    note: "`no-store` — a cache MUST NOT store any part of the request or the response, and MUST NOT use the response to satisfy another request",
};

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

/// Calculating Cache Keys with the Vary Header Field: what a `Vary: *` does to
/// every stored response of a resource.
pub const RFC_9111_4_1: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1",
    note: "Calculating Cache Keys with the Vary Header Field — a `Vary: *` never matches, so no stored response of that resource can be selected and a directive advertising reuse has nothing to act on",
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

    /// Two directives in one field value that say opposite things about
    /// storing the response: `public` beside an unqualified `private`, or
    /// `no-store` beside either of them.
    ///
    /// **One entry over both pairs, because a sender fixes either by deleting
    /// one directive** and a cache resolves either the same way — § 4.2.1 has
    /// it honour the most restrictive, so the response is stored less than one
    /// of the two directives asked for and the server does not know which of
    /// them it meant. The entry names the three sections that define the
    /// directives involved and carries a citation onto neither pair; the
    /// message says which two were written.
    ///
    /// **Only the *unqualified* `private` contradicts `public`.** A
    /// `private="Set-Cookie"` lets a shared cache store the rest of the
    /// response, so it says nothing `public` disagrees with — which is why this
    /// is a reading of the argument and not a name comparison.
    ///
    /// `warn`: nothing is malformed and no cache is confused, but one of the
    /// two directives is dead text in every deployment that reads the field.
    ///
    // cite(RFC 9111 § 5.2.2.9): "The public response directive indicates that a cache MAY store the response even if it would otherwise be prohibited, subject to the constraints defined in Section 3."
    // cite(RFC 9111 § 5.2.2.5): "The no-store response directive indicates that a cache MUST NOT store any part of either the immediate request or the response and MUST NOT use the response to satisfy any other request."
    CACHE_CONTROL_STORAGE_CONFLICTING = {
        id: "cache_control_storage_conflicting",
        title: "Two Cache-Control directives disagree about storing the response",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_5_2_2_9, RFC_9111_5_2_2_7, RFC_9111_5_2_2_5],
    }

    /// A `max-age` or `s-maxage` written more than once in one field section
    /// with more than one value.
    ///
    /// **The field is a list, so the repetition itself derives** — this is not
    /// `_duplicated`, which is for appearing more times than a grammar allows.
    /// What fails is that a freshness lifetime is one number and the response
    /// states two, and § 4.2.1 does not choose between them: it offers a cache
    /// the first occurrence *or* treating the response as stale. Two caches
    /// reading the same response may therefore keep it for different lengths of
    /// time, or one of them may not keep it at all.
    ///
    /// `_conflicting` and not `_ambiguous` for that reason. The ambiguity
    /// ending is for a value that derives from two productions with nothing to
    /// choose between them; here one construct is written twice and the two
    /// writings disagree, which is the plainer of the two claims.
    ///
    // cite(RFC 9111 § 4.2.1): "When there is more than one value present for a given directive (e.g., two Expires header field lines or multiple Cache-Control: max-age directives), either the first occurrence should be used or the response should be considered stale."
    CACHE_CONTROL_FRESHNESS_CONFLICTING = {
        id: "cache_control_freshness_conflicting",
        title: "A Cache-Control freshness directive is given more than one value",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_4_2_1],
    }
    /// A directive advertising reuse — `max-age`, `s-maxage`, `public` — on a
    /// response whose `Vary` is `*`.
    ///
    /// **The subject is this field because this field is the one that is
    /// dead.** A `Vary: *` alone is a server saying its responses are never to
    /// be selected from a cache, which is a coherent thing to say; the
    /// directive alone is a server saying how long they may be. Together, § 4.1
    /// makes the wildcard never match, so no stored response is ever selected
    /// and the directive has nothing to act on — the tie-break
    /// [`access_control_allow_credentials`](crate::violations::access_control_allow_credentials)
    /// used, applied to a cache.
    ///
    /// **`_redundant`, because no sentence is broken**: nothing forbids the
    /// pairing and both fields are well-formed. `warn` rather than the `info`
    /// the ending starts at, and the argument is the size of the surprise — an
    /// operator reading `max-age=86400` believes the deployment has a cache,
    /// and it has none.
    ///
    /// `no-cache` is not this entry: it promises no reuse, so pairing it with
    /// the wildcard states the same thing twice rather than contradicting it.
    ///
    // cite(RFC 9111 § 4.1): "A stored response with a Vary header field value containing a member "*" always fails to match."
    CACHE_CONTROL_REDUNDANT = {
        id: "cache_control_redundant",
        title: "A reuse directive sits on a response no cache may select",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_4_1],
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
