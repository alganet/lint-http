// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `content-coding` defects — the name of a transformation applied to a
//! representation, and the two words that are not one.
//!
//! `content-coding = token`, so the production adds nothing to the alphabet and
//! an octet no `token` admits answers under that subject rather than here. What
//! this subject holds is what a *name* can be wrong about, and the interesting
//! half of that is a distinction the grammar cannot make: **`Accept-Encoding`
//! and `Content-Encoding` do not accept the same vocabulary.**
//!
//! § 12.5.3 gives the request field `codings = content-coding / "identity" /
//! "*"` — three alternatives, of which only the first is a coding. The response
//! field is `#content-coding` and nothing else, because it states what was
//! actually applied rather than what would be welcome. So `*` and `identity`
//! are perfectly good `token`s that name no transformation, and each gets an
//! entry: a recipient meeting either in a `Content-Encoding` has been told the
//! representation was transformed by something that does not exist.
//!
//! The registry entry beneath them is the fourth of its shape — see
//! [`charset_unregistered`](crate::violations::charset::CHARSET_UNREGISTERED)
//! for the reasoning all four share.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The response field's grammar, and the sentence reserving `identity` away
/// from it.
pub const RFC_9110_8_4: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4",
    note: "`Content-Encoding = #content-coding`, and the reservation of `identity` for Accept-Encoding — the reason it is flagged here",
};

/// The production itself, its case-insensitivity, and the registry a name
/// ought to be in.
pub const RFC_9110_8_4_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("8.4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4.1",
    note: "`content-coding = token`, case-insensitive, and the \"ought to be registered\" guidance that motivates the rule without being what it checks",
};

/// The request field's wider vocabulary, which is what makes the two entries
/// below defects of the *response* field alone.
pub const RFC_9110_12_5_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("12.5.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3",
    note: "The wider Accept-Encoding grammar (`codings = content-coding / \"identity\" / \"*\"`), which is why the two headers are checked against different vocabularies",
};

defects! {
    /// `*` written where a coding that was actually applied belongs. The
    /// asterisk is how a request says "anything else"; a response saying it has
    /// named no transformation at all, and a recipient has nothing to undo.
    ///
    /// A `token` admits `*`, so nothing about the grammar refuses this — which
    /// is why the sentence quoted is the one that gives the symbol its only
    /// meaning, in the other field.
    ///
    // cite(RFC 9110 § 12.5.3): "The asterisk "*" symbol in an Accept-Encoding field matches any available content coding not explicitly listed in the field."
    CONTENT_CODING_WILDCARD_FORBIDDEN = {
        id: "content_coding_wildcard_forbidden",
        title: "The Accept-Encoding wildcard is written where a coding belongs",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_12_5_3],
    }

    /// `identity` written where a coding that was actually applied belongs. It
    /// is the request field's way of asking for *no* encoding, so a response
    /// naming it claims a transformation defined to do nothing — and the
    /// document reserves the name away from this field in as many words.
    ///
    // cite(RFC 9110 § 8.4): "Note that the coding named "identity" is reserved for its special role in Accept-Encoding and thus SHOULD NOT be included."
    CONTENT_CODING_IDENTITY_FORBIDDEN = {
        id: "content_coding_identity_forbidden",
        title: "The identity coding is named where a coding belongs",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_8_4],
    }

    /// One coding named twice in one field: `Content-Encoding: gzip, gzip`.
    /// Nothing forbids it — § 8.4 has the sender list the codings in the order
    /// they were applied, so a repeat is a well-formed way to say the same
    /// transformation ran twice — and the document's own aside is what makes it
    /// reportable: a coding is listed a second time only *for some bizarre
    /// reason*.
    ///
    /// `info`, with the catalogue's other `_redundant` entry, and for the same
    /// reason: the message is decodable and the work was avoidable. In practice
    /// it is two layers of a deployment each adding the field rather than a
    /// sender meaning it.
    ///
    // cite(RFC 9110 § 8.4, label: a coding listed twice): "Such a content coding would only be listed if, for some bizarre reason, it is applied a second time to form the representation."
    CONTENT_CODING_REDUNDANT = {
        id: "content_coding_redundant",
        title: "One coding is named twice in one field",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_8_4],
    }

    /// A coding name the deployment does not recognise, matched
    /// case-insensitively because the names are. Measured against the
    /// operator's `allowed` list and not against IANA's table, the stand-in
    /// every registry entry in this catalogue makes.
    ///
    /// `warn`: registration is an *ought to*, and the consequence of an unknown
    /// name is a recipient that cannot decode — which it discovers immediately
    /// rather than silently.
    ///
    // cite(RFC 9110 § 8.4.1): "All content codings are case-insensitive and ought to be registered within the "HTTP Content Coding Registry","
    CONTENT_CODING_UNREGISTERED = {
        id: "content_coding_unregistered",
        title: "Content coding is not one the deployment recognises",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_8_4_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two vocabulary entries quote the field that *does* admit the word,
    /// which is the only way to state what is wrong with writing it in the
    /// field that does not. Nothing here quotes `content-coding = token`: the
    /// grammar admits both words, and an entry citing it would be evidence
    /// against itself.
    #[test]
    fn each_vocabulary_entry_quotes_the_field_that_admits_the_word() {
        assert_eq!(CONTENT_CODING_WILDCARD_FORBIDDEN.spec, [RFC_9110_12_5_3]);
        assert_eq!(CONTENT_CODING_IDENTITY_FORBIDDEN.spec, [RFC_9110_8_4]);
        assert_eq!(CONTENT_CODING_UNREGISTERED.spec, [RFC_9110_8_4_1]);
    }
}
