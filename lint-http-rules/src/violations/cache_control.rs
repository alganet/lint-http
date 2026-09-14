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
    note: "no-cache — the unqualified form's prohibition on reuse without forwarding for validation, the argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified no-cache",
};

/// The `private` directive, written to the same shape: an argument syntax, a
/// qualified form that lists field names, and the same Note about how the form
/// is handled in practice.
pub const RFC_9111_5_2_2_7: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("5.2.2.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.7",
    note: "private — the unqualified form's prohibition on a shared cache storing the response at all, the argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified private",
};

/// Calculating Cache Keys with the Vary Header Field: what a `Vary: *` does to
/// every stored response of a resource.
pub const RFC_9111_4_1: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1",
    note: "Calculating Cache Keys with the Vary Header Field — a `Vary: *` never matches, so no stored response of that resource can be selected and a directive advertising reuse has nothing to act on",
};

/// The `must-revalidate` response directive.
pub const RFC_9111_5_2_2_2: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("5.2.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.2",
    note: "`must-revalidate` — once the response is stale, a cache MUST NOT reuse it until it has been successfully validated by the origin",
};

/// The `s-maxage` response directive, and the cache it is addressed to.
pub const RFC_9111_5_2_2_10: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("5.2.2.10"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.10",
    note: "`s-maxage` — the directive is defined for a shared cache, where it overrides the maximum age given by `max-age` or `Expires`; it says nothing to any other kind of cache",
};

/// The `immutable` extension: what it asks of a client, and the window it
/// applies in.
pub const RFC_8246_2: SpecRef = SpecRef {
    spec: "RFC 8246",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc8246.html#section-2",
    note: "`immutable` — clients SHOULD NOT revalidate during the response's freshness lifetime, and the extension applies during that lifetime only, so a response with none is outside it entirely",
};

/// Calculating Heuristic Freshness: what a cache may do when the origin server
/// says nothing.
pub const RFC_9111_4_2_2: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("4.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.2",
    note: "Calculating Heuristic Freshness — without an explicit expiration time a cache MAY assign one of its own, estimated from other field values",
};

/// Overview of Status Codes: which status codes a cache may reuse on a
/// heuristic alone.
pub const RFC_9110_15_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.1",
    note: "Overview of Status Codes — the status codes defined as heuristically cacheable, which is the set a response outside it has to state its own freshness to join",
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

    /// A validator from a `no-store` response used on a later conditional
    /// request.
    ///
    /// **One entry, two pieces of evidence** — an `ETag` or a `Last-Modified`
    /// carried forward — because which validator gave it away is a fact about
    /// what the response happened to carry, not about the defect: something
    /// kept part of a response the directive said to keep no part of. 2.226's
    /// line, at a cache instead of at a body.
    ///
    /// **The finding is about a store this proxy cannot see**, and reconstructs
    /// it from the only evidence on the wire: a validator can only be sent back
    /// by a client that kept the response it came from. That makes it a
    /// heuristic about a third party rather than a claim about either endpoint,
    /// which is why the message names the value it recognised.
    ///
    // cite(RFC 9111 § 5.2.2.5): "The no-store response directive indicates that a cache MUST NOT store any part of either the immediate request or the response and MUST NOT use the response to satisfy any other request."
    CACHE_CONTROL_NO_STORE_IGNORED = {
        id: "cache_control_no_store_ignored",
        title: "A validator from a no-store response comes back on a later request",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_5_2_2_5],
    }

    /// A stale response carrying `must-revalidate`, reused without a
    /// conditional request.
    ///
    /// The directive's whole content is what happens *after* the response goes
    /// stale, so freshness is the antecedent and the finding needs both: an age
    /// past the freshness lifetime, and a reuse that carried no validator.
    ///
    // cite(RFC 9111 § 5.2.2.2): "The must-revalidate response directive indicates that once the response has become stale, a cache MUST NOT reuse that response to satisfy another request until it has been successfully validated by the origin, as defined by Section 4.3."
    CACHE_CONTROL_MUST_REVALIDATE_IGNORED = {
        id: "cache_control_must_revalidate_ignored",
        title: "A stale must-revalidate response is reused without validation",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_5_2_2_2],
    }

    /// A response marked `no-cache` reused without forwarding the later request
    /// for validation.
    ///
    /// **The unqualified form is the one this entry is about.** § 5.2.2.4's
    /// qualified form — an argument listing field names — permits a cache to
    /// use the response, so a finding against it would report a permission.
    ///
    // cite(RFC 9111 § 5.2.2.4): "The no-cache response directive, in its unqualified form (without an argument), indicates that the response MUST NOT be used to satisfy any other request without forwarding it for validation and receiving a successful response"
    CACHE_CONTROL_NO_CACHE_IGNORED = {
        id: "cache_control_no_cache_ignored",
        title: "A no-cache response is reused without being revalidated",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_5_2_2_4],
    }

    /// A validator from an unqualified-`private` response arriving from a
    /// different client.
    ///
    /// The directive says the response is intended for a single user, so a
    /// shared cache must not store it at all — and a validator reaching a
    /// second client is the shape that shows one did. Like the `no-store`
    /// entry, this is a reconstruction of a store nobody here can see, and the
    /// second client is the whole of the evidence.
    ///
    // cite(RFC 9111 § 5.2.2.7): "The unqualified private response directive indicates that a shared cache MUST NOT store the response (i.e., the response is intended for a single user)."
    CACHE_CONTROL_PRIVATE_IGNORED = {
        id: "cache_control_private_ignored",
        title: "A validator from a private response reaches a second client",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_5_2_2_7],
    }

    /// A response revalidated at its `s-maxage` boundary by a cache the
    /// directive does not address.
    ///
    /// **What went unhonoured is the directive's scope, not its value.** § 5.2.2.10
    /// defines `s-maxage` *for a shared cache*, where it overrides `max-age`
    /// and `Expires`; it says nothing to any other kind, so a cache outside
    /// that description has `max-age` as its freshness lifetime and this one
    /// used a shorter number that was never addressed to it.
    ///
    /// The part names the directive an operator would search for, and the
    /// ending says a stated requirement was not honoured — here the sentence
    /// that says *which* caches the directive is for.
    ///
    // cite(RFC 9111 § 5.2.2.10): "The s-maxage response directive indicates that, for a shared cache, the maximum age specified by this directive overrides the maximum age specified by either the max-age directive or the Expires header field."
    CACHE_CONTROL_S_MAXAGE_IGNORED = {
        id: "cache_control_s_maxage_ignored",
        title: "A cache s-maxage does not address used it for freshness",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_5_2_2_10],
    }

    /// `immutable` beside a directive that leaves the response no freshness
    /// lifetime at all — `no-store`, `no-cache`, `max-age=0`, `s-maxage=0`.
    ///
    /// **`_redundant`, and the extension's own scope is the argument**: it
    /// applies during the freshness lifetime and there is none, so the word is
    /// on the wire and does nothing. Nothing is broken — the paired directive
    /// is the stronger statement and the deployment behaves as it says.
    ///
    /// `info`, the ending's starting point, and the difference from
    /// [`CACHE_CONTROL_REDUNDANT`] is what the mistake costs: there an operator
    /// believes the deployment has a cache and it has none, here an operator
    /// believes reloads skip a round trip and they do not.
    ///
    // cite(RFC 8246 § 2): "The immutable extension only applies during the freshness lifetime of the stored response."
    CACHE_CONTROL_IMMUTABLE_REDUNDANT = {
        id: "cache_control_immutable_redundant",
        title: "immutable sits on a response with no freshness lifetime",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_8246_2],
    }

    /// A conditional request for an `immutable` response that is still fresh.
    ///
    /// The extension exists to stop exactly this, and the client did it anyway.
    /// `_ignored` with the four directive entries above, and **`info` where
    /// those are `warn`**, because the ranking follows what the miss costs: a
    /// cache reusing a `no-store` response keeps something it was told to keep
    /// no part of, and this spends one conditional request.
    ///
    /// A user's explicit reload is the case the sentence exempts, and nothing
    /// on the wire distinguishes it — which is a second reason not to rank this
    /// higher.
    ///
    // cite(RFC 8246 § 2): "Clients SHOULD NOT issue a conditional request during the response's freshness lifetime (e.g., upon a reload) unless explicitly overridden by the user (e.g., a force reload)."
    CACHE_CONTROL_IMMUTABLE_IGNORED = {
        id: "cache_control_immutable_ignored",
        title: "A still-fresh immutable response is revalidated anyway",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_8246_2],
    }

    /// A `200` carrying no `Cache-Control` at all.
    ///
    /// **Nothing requires the field**, and the entry is about what its absence
    /// hands to somebody else: § 4.2.2 lets a cache assign an expiration time
    /// of its own, estimated from whatever other fields it can see. So the
    /// origin has not declined to be cached — it has left the lifetime to be
    /// guessed, by each cache separately.
    ///
    /// `_missing` rather than `_empty`: the field was never written.
    ///
    /// `info`. No sentence is broken, the guess is permitted, and the finding
    /// is worth making only because the guess is invisible from the origin.
    ///
    // cite(RFC 9111 § 4.2.2): "Since origin servers do not always provide explicit expiration times, a cache MAY assign a heuristic expiration time when an explicit time is not specified, employing algorithms that use other field values (such as the Last-Modified time) to estimate a plausible expiration time."
    CACHE_CONTROL_MISSING = {
        id: "cache_control_missing",
        title: "A 200 leaves its freshness lifetime to be guessed",
        message: "Response 200 without Cache-Control header",
        default_severity: Severity::Info,
        spec: &[RFC_9111_4_2_2],
    }

    /// A response on a status outside the heuristically cacheable set, carrying
    /// no explicit freshness of its own.
    ///
    /// **The opposite outcome to the entry above, from the same silence.**
    /// There a cache invents a lifetime; here § 15.1's list does not cover the
    /// status, so nothing stores the response at all unless it says how long it
    /// is good for. Two entries because a sender reading one of them learns the
    /// wrong thing about the other.
    ///
    /// `info`, and for the plainest of reasons: not being cached is a perfectly
    /// good outcome, and the finding says only that it was not chosen.
    ///
    // cite(RFC 9110 § 15.1): "Responses with status codes that are defined as heuristically cacheable (e.g., 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, and 501 in this specification) can be reused by a cache with heuristic expiration unless otherwise indicated by the method definition or explicit cache controls"
    CACHE_CONTROL_FRESHNESS_MISSING = {
        id: "cache_control_freshness_missing",
        title: "A status no cache stores by default states no freshness",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_15_1],
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
