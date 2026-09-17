// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Prefer` and `Preference-Applied` defects — what a client asks for, and what
//! a server says it did.
//!
//! **One subject for two fields, because they are one exchange.** RFC 7240
//! writes `Preference-Applied` as the `Prefer` grammar without parameters and
//! defines it entirely in terms of what the request asked, so three of the
//! entries here can only be made by reading both messages — and an operator
//! configuring one end of that exchange is configuring the other.
//!
//! **What the productions own is not here.** A preference name is a `token`, a
//! value is a `word`, and the `BWS` around the `=` is RFC 9110 § 5.6.3's — so
//! those report through [`token`](crate::violations::token),
//! [`quoted_string`](crate::violations::quoted_string) and
//! [`bws`](crate::violations::bws) as they do for every other field written out
//! of the same three. What is left is what RFC 7240 says past the grammar.
//!
//! **The `word` with nothing in it is the exception, and the reason is on
//! record.** `( token / quoted-string )` derives no empty string, but what a
//! *field* does about one is a per-field verdict — six callers of that reader
//! answered it four different ways — so the catalogue declines to answer for
//! all of them and each field keeps an entry of its own. `Link` already has
//! one; these are the second and third.
//
// cite(RFC 7240 § 3): "The syntax of the Preference-Applied header differs from that of the Prefer header in that parameters are not included."

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// `Prefer`: the grammar, the multi-line equivalence, the case rules, and the
/// SHOULD NOT against repeating a token.
pub const RFC_7240_2: SpecRef = SpecRef {
    spec: "RFC 7240",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-2",
    note: "`Prefer` — the grammar, the equivalence of several field lines with one, the equivalence of an empty value with no value, the case rules for names and values, the SHOULD NOT against repeating a token, and the server's MUST to ignore a preference it does not recognize",
};

/// `Preference-Applied`: the field, and the grammar it shares minus the
/// parameters.
pub const RFC_7240_3: SpecRef = SpecRef {
    spec: "RFC 7240",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-3",
    note: "`Preference-Applied` — the field's definition, its grammar, and the sentence saying it is the `Prefer` grammar without parameters",
};

/// The four preferences the document defines, each with a production of its
/// own naming the values it admits.
pub const RFC_7240_4: SpecRef = SpecRef {
    spec: "RFC 7240",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-4",
    note: "The four preferences this document defines, each with its own production: `respond-async` (§4.1), `return` (§4.2), `wait` (§4.3) and `handling` (§4.4). §4.2 and §4.4 add that the two values of `return` and of `handling` are mutually exclusive",
};

defects! {
    /// A `Prefer` member or parameter written `name=` with nothing after the
    /// `=`.
    ///
    /// **The catalogue declines to answer this for every field and each field
    /// answers for itself**, which is why the entry is here rather than on
    /// `word`: `( token / quoted-string )` derives no empty string, but what a
    /// field *does* about one differs — and § 2 says outright that an empty
    /// value is equivalent to no value at all, so nothing is lost here. What
    /// the sender wrote is an `=` that means nothing, on a member the
    /// production had no room for it in.
    ///
    /// `warn`, with the rest: the preference is still read, and what is wrong
    /// is a grammar the member does not derive from.
    ///
    // cite(RFC 7240 § 2): "preference = token [ BWS "=" BWS word ]"
    PREFER_VALUE_EMPTY = {
        id: "prefer_value_empty",
        title: "A Prefer member writes an = with no word after it",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7240_2],
        strength: Strength::Grammar,
    }

    /// A preference RFC 7240 defines, carrying a value its own production does
    /// not admit: `return=other`, `handling=whatever`, `wait=soon`.
    ///
    /// **Only the four the document defines**, and § 5.1 is why: the "HTTP
    /// Preferences" registry is open under Specification Required and a
    /// registration carries its own enumeration of values, so a preference this
    /// crate does not hold has its value left unjudged rather than assumed
    /// wrong.
    ///
    /// `_invalid`: the value derives from `word` and what refuses it is the
    /// enumeration the preference's own production writes past it.
    ///
    // cite(RFC 7240 § 4): "The following subsections define an initial set of preferences."
    PREFER_PREFERENCE_INVALID = {
        id: "prefer_preference_invalid",
        title: "A defined preference carries a value its production does not admit",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7240_4],
    }

    /// One preference token written more than once in a single request.
    ///
    /// **`_duplicated` on a SHOULD NOT with a resolution beside it**, which is
    /// `structured_field_key_duplicated`'s shape: § 2 asks a client not to do
    /// it *and* says what happens when it does — only the first instance is
    /// considered — so the second is not an addition a server merges, it is
    /// text nobody reads. A request meaning to say two things says one and
    /// looks like it said two.
    ///
    /// The count is over the whole field however many lines carry it, because
    /// § 2 makes several `Prefer` lines equivalent to one.
    ///
    // cite(RFC 7240 § 2): "To avoid any possible ambiguity, individual preference tokens SHOULD NOT appear multiple times within a single request."
    PREFER_PREFERENCE_DUPLICATED = {
        id: "prefer_preference_duplicated",
        title: "A Prefer names one preference more than once",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7240_2],
        strength: Strength::Should,
    }

    /// A `Preference-Applied` member written `name=` with nothing after it.
    ///
    /// [`PREFER_VALUE_EMPTY`]'s twin, and two entries rather than one because
    /// the senders are two: a client wrote the first and a server the second,
    /// and an operator chasing one reads a client's request builder while one
    /// chasing the other reads a server's response path.
    ///
    // cite(RFC 7240 § 3): "applied-pref = token [ BWS "=" BWS word ]"
    PREFERENCE_APPLIED_VALUE_EMPTY = {
        id: "preference_applied_value_empty",
        title: "A Preference-Applied member writes an = with no word after it",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7240_3],
        strength: Strength::Grammar,
    }

    /// A `Preference-Applied` member carrying a `;` parameter.
    ///
    /// **The one place the two grammars differ, and § 3 says so in a sentence
    /// rather than only in its ABNF.** `Prefer` writes `*( OWS ";" [ OWS
    /// parameter ] )` after its token and `applied-pref` writes nothing, so a
    /// server echoing the client's parameters back has echoed something the
    /// response field has no production for.
    ///
    /// The search for the `;` is quote-aware, because a `;` inside the `word`'s
    /// quoted-string is `qdtext` and not a parameter.
    ///
    // cite(RFC 7240 § 3): "The syntax of the Preference-Applied header differs from that of the Prefer header in that parameters are not included."
    PREFERENCE_APPLIED_PARAMETER_FORBIDDEN = {
        id: "preference_applied_parameter_forbidden",
        title: "A Preference-Applied member carries a parameter its grammar has none of",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7240_3],
    }

    /// A `Preference-Applied` naming a preference the request's `Prefer` did
    /// not ask for.
    ///
    /// **`_unsolicited`, and this is the ending's own case**: the field is
    /// defined as an indication of which `Prefer` tokens were honored, so a
    /// member naming one nobody sent describes a request that did not happen.
    /// Nothing is malformed and no sentence prohibits the token — what refutes
    /// it is the exchange, which is exactly what the ending is for.
    ///
    /// **The evidence is the other message**, so a capture holding only the
    /// response cannot produce this finding, and a request whose `Prefer` this
    /// observer never saw produces it wrongly. That is the same limit every
    /// two-message entry in this catalogue carries.
    ///
    // cite(RFC 7240 § 3): "The Preference-Applied response header MAY be included within a response message as an indication as to which Prefer tokens were honored by the server and applied to the processing of a request."
    PREFERENCE_APPLIED_UNSOLICITED = {
        id: "preference_applied_unsolicited",
        title: "A Preference-Applied names a preference nobody asked for",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7240_3],
        strength: Strength::Unstated,
    }

    /// A `Preference-Applied` reporting a preference applied with a value other
    /// than the one the request asked for.
    ///
    /// **Separate from [`PREFERENCE_APPLIED_UNSOLICITED`] because the server
    /// answered the right question wrongly rather than a question nobody
    /// asked**, and the two have different repairs: one is a response naming a
    /// token it should not, the other a response whose value does not match.
    ///
    /// **The comparison is on the `word`'s content and not its spelling**, so
    /// `return="representation"` honors `return=representation` — § 2 says
    /// values are compared case-sensitively "regardless of whether token or
    /// quoted-string values are used", which is the same sentence that makes
    /// the two written forms one value.
    ///
    // cite(RFC 7240 § 2): "For both preference token names and parameter names, comparison is case insensitive while values are case sensitive regardless of whether token or quoted-string values are used."
    PREFERENCE_APPLIED_CONFLICTING = {
        id: "preference_applied_conflicting",
        title: "A Preference-Applied reports a value the request did not ask for",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7240_2],
    }
}
