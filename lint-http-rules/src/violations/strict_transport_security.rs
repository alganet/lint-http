// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Strict-Transport-Security` defects — what a policy can be wrong about once
//! its directives are spelled correctly.
//!
//! The field is a semicolon-separated list of `directive = token [ "=" ( token
//! / quoted-string ) ]`, so every spelling question already has an owner: a
//! directive name that is not a `token`, a value that is neither a `token` nor
//! a well-formed `quoted-string`, an octet no `tchar` admits. What is left is
//! the *policy* — whether the directives that are there add up to one.
//!
//! **The time is not this field's.** RFC 6797 § 6.1.1 writes `max-age-value =
//! delta-seconds` and says outright that the production is specified elsewhere,
//! so a `max-age` with no digits or with a sign answers under
//! [`delta_seconds`](crate::violations::delta_seconds) exactly as `Age`'s value
//! and `Alt-Svc`'s `ma` do. What stays here is the directive: that it is
//! required, that it may appear once, and that it has to carry a value at all.
//!
//! **A value a reader cannot hold is not an entry**, for the reason
//! `delta_seconds` records: the production sets no ceiling and a recipient
//! meeting an unrepresentable value is told to clamp it, so a forty-digit
//! `max-age` is a conforming policy and this crate's inability to store it is
//! this crate's problem.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field's own grammar, the once-only rule for its directives, and the
/// extension mechanism that makes an unknown one acceptable.
pub const RFC_6797_6_1: SpecRef = SpecRef {
    spec: "RFC 6797",
    section: Some("6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1",
    note: "Strict-Transport-Security header",
};

/// The required directive, and what its value is a count of.
pub const RFC_6797_6_1_1: SpecRef = SpecRef {
    spec: "RFC 6797",
    section: Some("6.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.1",
    note: "The max-age Directive",
};

/// The valueless directive, and what asserting it means.
pub const RFC_6797_6_1_2: SpecRef = SpecRef {
    spec: "RFC 6797",
    section: Some("6.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.2",
    note: "The includeSubDomains Directive",
};

defects! {
    /// A field line with no policy on it at all.
    ///
    /// **No `spec`, and the grammar is the reason.** § 6.1 writes
    /// `[ directive ] *( ";" [ directive ] )`, whose optional brackets make the
    /// empty value derive — so this is not a sentence being broken but this
    /// crate saying that a policy declaring nothing is not a policy. The
    /// missing `max-age` is the same message from the document's side, and a
    /// value that is empty never reaches it: the two are ordered, and this one
    /// is answered first because it is the one the operator can see.
    STRICT_TRANSPORT_SECURITY_EMPTY = {
        id: "strict_transport_security_empty",
        title: "The policy is written with nothing in it",
        message: "Strict-Transport-Security header must not be empty",
        default_severity: Severity::Warn,
        spec: &[],
    }

    /// A semicolon with no directive on one side of it. The same optional
    /// brackets generate this too, so the refusal is again this crate's —
    /// kept because a stray separator is nearly always a directive that was
    /// deleted or never expanded, and a policy is small enough that the
    /// difference is worth showing.
    STRICT_TRANSPORT_SECURITY_DIRECTIVE_EMPTY = {
        id: "strict_transport_security_directive_empty",
        title: "The policy holds a separator with no directive",
        message: "Empty directive in Strict-Transport-Security header",
        default_severity: Severity::Warn,
        spec: &[],
    }

    /// The policy does not state how long it lasts. `max-age` is the one
    /// required directive, and without it a user agent has nothing to note the
    /// host for — the rest of the field is qualification of a duration that was
    /// never given.
    ///
    // cite(RFC 6797 § 6.1.1, label: max-age is required): "The REQUIRED "max-age" directive specifies the number of seconds, after the reception of the STS header field, during which the UA regards the host (from whom the message was received) as a Known HSTS Host."
    STRICT_TRANSPORT_SECURITY_MAX_AGE_MISSING = {
        id: "strict_transport_security_max_age_missing",
        title: "The policy states no max-age",
        message: "Strict-Transport-Security header missing required 'max-age' directive",
        default_severity: Severity::Warn,
        spec: &[RFC_6797_6_1_1],
    }

    /// One directive written twice in one field. § 6.1 admits no such thing,
    /// and the reason is that the field is not a list of preferences: two
    /// `max-age` directives are two durations for one policy, and nothing tells
    /// a user agent which of them it is being asked to note.
    ///
    // cite(RFC 6797 § 6.1): "All directives MUST appear only once in an STS header field."
    STRICT_TRANSPORT_SECURITY_DIRECTIVE_DUPLICATED = {
        id: "strict_transport_security_directive_duplicated",
        title: "A directive is written more than once in one policy",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6797_6_1],
    }

    /// A directive whose definition requires a value, written without one —
    /// `max-age` with no `=` at all. Distinct from a `max-age=` that is written
    /// and empty, which is the [`delta_seconds`](crate::violations::delta_seconds)
    /// subject's `_empty`: different senders, different fixes, and the same
    /// `_missing`/`_empty` split the id convention draws everywhere else.
    ///
    // cite(RFC 6797 § 6.1.1, label: max-age carries a value): "The syntax of the max-age directive's REQUIRED value (after quoted-string unescaping, if necessary) is defined as:"
    STRICT_TRANSPORT_SECURITY_DIRECTIVE_VALUE_MISSING = {
        id: "strict_transport_security_directive_value_missing",
        title: "A directive that requires a value carries none",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6797_6_1_1],
    }

    /// A valueless directive carrying a value: `includeSubDomains=1`, or a
    /// `preload` with anything after an `=`. Asserting such a directive is the
    /// whole of its meaning, so a value says nothing a user agent can read and
    /// suggests the sender expected it to mean something.
    ///
    /// `preload` is not RFC 6797's directive at all — it is the de-facto
    /// extension § 6.1 anticipates being defined elsewhere — so what governs it
    /// here is the convention its consumers implement rather than the sentence
    /// quoted below, which is `includeSubDomains`'.
    ///
    // cite(RFC 6797 § 6.1.2): "The OPTIONAL "includeSubDomains" directive is a valueless directive which, if present (i.e., it is "asserted"), signals the UA that the HSTS Policy applies to this HSTS Host as well as any subdomains of the host's domain name."
    STRICT_TRANSPORT_SECURITY_DIRECTIVE_VALUE_FORBIDDEN = {
        id: "strict_transport_security_directive_value_forbidden",
        title: "A valueless directive is written with a value",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6797_6_1_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two entries with no sentence behind them are the two the grammar
    /// *generates*: `[ directive ]` is optional at both levels, so an empty
    /// field and an empty member both derive, and refusing them is this crate's
    /// own claim rather than a document's.
    #[test]
    fn the_two_entries_the_grammar_generates_carry_no_sentence() {
        assert!(STRICT_TRANSPORT_SECURITY_EMPTY.spec.is_empty());
        assert!(STRICT_TRANSPORT_SECURITY_DIRECTIVE_EMPTY.spec.is_empty());
        for def in [
            &STRICT_TRANSPORT_SECURITY_MAX_AGE_MISSING,
            &STRICT_TRANSPORT_SECURITY_DIRECTIVE_DUPLICATED,
            &STRICT_TRANSPORT_SECURITY_DIRECTIVE_VALUE_MISSING,
            &STRICT_TRANSPORT_SECURITY_DIRECTIVE_VALUE_FORBIDDEN,
        ] {
            assert!(!def.spec.is_empty(), "{}", def.id);
        }
    }
}
