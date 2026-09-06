// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `token68` defects — the credential-shaped alternative, wherever it is
//! carried.
//!
//! RFC 9110 § 11.2 writes `token68` for the whole authentication framework, and
//! RFC 6750 § 2.1 writes `b64token` for `Bearer` with the same alphabet and the
//! same trailing `*"="`. So a `WWW-Authenticate` challenge's bare word and an
//! `Authorization: Bearer` token are one production read by two rules, and the
//! defects are named after the production.
//!
//! The four entries split the way every other subject's character defects do —
//! the octets nobody typed above the octets a sender chose — and add the two
//! the padding makes possible: a value that is padding and nothing else, and
//! padding with something other than `=` in it.
//!
//! What is *not* here is the `Bearer` reader's own heuristic about a value that
//! looks like a forgotten parameter: that is a judgment about a challenge, and
//! it stays in [`crate::violations::challenge`] where it is not confusable with
//! the grammar.

use crate::helpers::auth::BearerTokenDefect;
use crate::lint::Severity;
use crate::violations::auth_scheme::RFC_9110_11_2;
use crate::violations::credentials::CREDENTIALS_MISSING;
use crate::violations::{defects, ViolationDef};

// The sentence behind all four entries is § 11.2's, which is
// [`crate::violations::auth_scheme`]'s `RFC_9110_11_2`: one section defines the
// scheme, the parameter and this alphabet, so the three subjects that split
// those defects share one reference rather than writing three that differ only
// in their prose. RFC 6750 repeats the alphabet as `b64token` and points at the
// obsolete RFC 2617 for the framework around it, which is why the live document
// is the anchor for a `Bearer` finding too.

defects! {
    /// Whitespace or a control octet in the token. `error` by default, the
    /// convention every subject with this pair follows: the alphabet is
    /// letters, digits, six punctuation marks and the padding, so neither is
    /// something a sender chose to write — a space is most often the value
    /// having been split or joined by something on the way.
    ///
    // cite(RFC 9110 § 11.2): "token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=""
    TOKEN68_WHITESPACE_OR_CONTROL_FORBIDDEN = {
        id: "token68_whitespace_or_control_forbidden",
        title: "token68 holds whitespace or a control character",
        message: "",
        default_severity: Severity::Error,
        spec: Some(RFC_9110_11_2),
    }

    /// A visible octet outside the alphabet — the `%` of a value that was
    /// percent-encoded by something that did not know what it was holding, most
    /// often, or the `:` of credentials that were never encoded at all.
    ///
    // cite(RFC 9110 § 11.2): "token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=""
    TOKEN68_CHARACTER_FORBIDDEN = {
        id: "token68_character_forbidden",
        title: "token68 holds a character outside its alphabet",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_11_2),
    }

    /// Padding and nothing before it. The production is `1*(…)` and then its
    /// `*"="`, so the body cannot be the empty string however much padding
    /// follows it.
    ///
    // cite(RFC 9110 § 11.2): "token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=""
    TOKEN68_BODY_EMPTY = {
        id: "token68_body_empty",
        title: "token68 is padding with no body",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_11_2),
    }

    /// Something other than `=` at or after the first `=`. Padding is the only
    /// thing that may follow the body, so a `=` in the middle makes everything
    /// after it padding by position — and whatever is not an `=` there derives
    /// from nothing.
    ///
    // cite(RFC 9110 § 11.2): "token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=""
    TOKEN68_PADDING_MALFORMED = {
        id: "token68_padding_malformed",
        title: "token68 padding holds something other than '='",
        message: "",
        default_severity: Severity::Warn,
        spec: Some(RFC_9110_11_2),
    }
}

/// The defect a parsed [`BearerTokenDefect`] reports as.
///
/// Two arms are worth reading. An empty token is not this production's defect
/// at all — `credentials = auth-scheme [ 1*SP … ]` is what says something has
/// to be there — so it reports as the framework's `credentials_missing`, the
/// same id `Basic` and the framework rule itself report. And the bad-character
/// arm is sorted by the character: the reader finds one octet outside the
/// alphabet, and *which* octet decides whether it is the one nobody typed.
pub fn bearer_token_defect(defect: BearerTokenDefect) -> &'static ViolationDef {
    match defect {
        BearerTokenDefect::Empty => &CREDENTIALS_MISSING,
        BearerTokenDefect::Whitespace => &TOKEN68_WHITESPACE_OR_CONTROL_FORBIDDEN,
        BearerTokenDefect::EmptyBody => &TOKEN68_BODY_EMPTY,
        BearerTokenDefect::BadCharacter(c) if c.is_whitespace() || c.is_control() => {
            &TOKEN68_WHITESPACE_OR_CONTROL_FORBIDDEN
        }
        BearerTokenDefect::BadCharacter(_) => &TOKEN68_CHARACTER_FORBIDDEN,
        BearerTokenDefect::BadPadding => &TOKEN68_PADDING_MALFORMED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping, spelled out — including the two arms that answer with a
    /// def this subject does not own, and the one variant that answers with
    /// either of two depending on what it carries.
    #[test]
    fn each_bearer_token_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (BearerTokenDefect::Empty, "credentials_missing"),
            (
                BearerTokenDefect::Whitespace,
                "token68_whitespace_or_control_forbidden",
            ),
            (BearerTokenDefect::EmptyBody, "token68_body_empty"),
            (
                BearerTokenDefect::BadCharacter('%'),
                "token68_character_forbidden",
            ),
            (
                BearerTokenDefect::BadCharacter('\u{1}'),
                "token68_whitespace_or_control_forbidden",
            ),
            (BearerTokenDefect::BadPadding, "token68_padding_malformed"),
        ] {
            assert_eq!(bearer_token_defect(defect).id, id);
        }
    }
}
