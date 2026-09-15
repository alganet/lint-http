// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Forwarded` defects — §4's own grammar, and the direction the field travels.
//!
//! **Five productions meet in one `Forwarded` value and only one of them is
//! this field's.** A `for` or `by` value is RFC 7239 §6's node identifier, a
//! `host` is the `Host` field's ABNF, a `proto` is a URI scheme name, a
//! parameter name is HTTP's `token` and a quoted value is HTTP's
//! `quoted-string` — each of those has a subject here already, and the rule
//! reading the field borrows from all of them. What is left over is this
//! subject: the element, the pair, and the sentence saying which direction the
//! field is for.
//!
//! **The list is not here either, for the same reading one level up.** §3 says
//! outright that the field borrows HTTP's list rule extension rather than
//! defining one, so an empty element and a `1#` with nothing above its floor
//! are [`crate::violations::list`]'s two entries — asked of this field for the
//! reason they are asked of `Vary`, and not because the two fields resemble
//! each other.
//!
//! **What is here is therefore the residue, and it is a subject rather than a
//! leftover.** An operator tuning these is tuning how strictly one document's
//! `name=value` spelling is read, on a field whose *values* are all measured
//! somewhere else entirely.
//
// cite(RFC 7239 § 3): "This specification uses the Augmented Backus-Naur Form (ABNF) notation of [RFC5234] with the list rule extension defined in Section 7 of [RFC7230]."

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field's own section: the two productions, the MUST NOT on naming a
/// parameter twice, the case-insensitivity of the names, and the sentence
/// restricting the field to requests.
pub const RFC_7239_4: SpecRef = SpecRef {
    spec: "RFC 7239",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc7239.html#section-4",
    note: "The field's grammar, the case-insensitivity of parameter names, the MUST NOT on naming a parameter twice in one element, and the sentence restricting the field to requests",
};

defects! {
    /// Whitespace inside a `forwarded-element`, outside any quoted-string.
    ///
    /// Neither production writes `OWS` anywhere: an element is
    /// `[ forwarded-pair ] *( ";" [ forwarded-pair ] )` and a pair is
    /// `token "=" value`, so no space or HTAB an element carries derives from
    /// either. The *list's* whitespace, around its commas, is a different
    /// question with a different answer — §7.1 prints it as conforming — which
    /// is why this is asked of the element and never of the field line.
    ///
    /// **One id for every position it can sit in, because the check is one
    /// walk.** A space beside a `;`, a space beside an `=` and a space inside
    /// an unquoted value are the same octet in a production that generates
    /// none; the message names the character and prints the element it was
    /// found in.
    ///
    /// **`warn`, where
    /// [`crate::violations::parameter::PARAMETER_EQUALS_WHITESPACE_FORBIDDEN`]
    /// is `info`, and the third position is the whole of the difference.** That
    /// entry is confined to the two sides of a `=`, where trimming leaves the
    /// name the name and the value the value, so what is wrong is the spelling
    /// alone. This one also reports the space in `for=192.0.2.1 x`, where
    /// trimming does not recover the value the sender wrote — it invents one.
    ///
    /// Not the `<subject>_whitespace_or_control_forbidden` half of the pair
    /// `docs/development.md` mandates, and deliberately not spelled like it.
    /// That pair splits the octets nobody typed from the ones a sender chose
    /// *inside one value*; the value's own character class here is `token`'s,
    /// and [`crate::violations::token`] already holds both halves of it.
    ///
    // cite(RFC 7239 § 4, label: forwarded-element grammar): "forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )"
    FORWARDED_ELEMENT_WHITESPACE_FORBIDDEN = {
        id: "forwarded_element_whitespace_forbidden",
        title: "Forwarded element holds whitespace its grammar does not admit",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7239_4],
    }

    /// A segment of an element with no `=` in it: `for=192.0.2.1;proto`.
    ///
    /// `forwarded-pair = token "=" value` brackets no part of itself, so a name
    /// standing alone is not a valueless flag — it derives from nothing. **The
    /// pair as a whole is what the element makes optional**, at every position,
    /// which is what leaves `for=192.0.2.1;;proto=https` conforming and this
    /// value not: the grammar offers a sender the choice of writing no pair,
    /// never the choice of writing half of one.
    ///
    /// The shape [`crate::violations::parameter::PARAMETER_EQUALS_MISSING`]
    /// reports for RFC 9110's `parameters`, and a separate entry because it is
    /// a separate production — its own document, its own delimiter, its own
    /// rules about what may be left out. An operator silencing one has said
    /// nothing about the other.
    ///
    /// `warn`, level with the value that is not there.
    ///
    // cite(RFC 7239 § 4, label: forwarded-pair grammar): "forwarded-pair = token "=" value value          = token / quoted-string"
    FORWARDED_PAIR_EQUALS_MISSING = {
        id: "forwarded_pair_equals_missing",
        title: "Forwarded pair is written without its '='",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7239_4],
    }

    /// A pair that names a parameter and states nothing for it: `for=`, or
    /// `for=""`.
    ///
    /// **One entry for two spellings, and they fail in different places.** An
    /// empty unquoted value derives from neither alternative of
    /// `value = token / quoted-string`, while `""` is a perfectly good
    /// `quoted-string` that unescapes to nothing. What they share is the whole
    /// of the defect — a parameter was named and no value was given — and the
    /// repair; which of the two a sender wrote is what the message says.
    ///
    /// **The empty half of `word = token / quoted-string` is a per-field
    /// verdict, and this is this field's.**
    /// [`crate::violations::token::word_defect`] answers `None` there because
    /// six callers of the alternation had settled it four different ways, with
    /// `Pragma` and `Cache-Control` tolerating an empty directive argument on
    /// the record. `Forwarded` does not: §5 hands each of its four parameters
    /// to a production measured *after* unescaping, and no `node`, `Host` value
    /// or scheme name is the empty string.
    ///
    /// `warn`. The pair says nothing about the hop it was written to describe,
    /// and a recipient reading the chain is one element short of the answer.
    ///
    // cite(RFC 7239 § 4, label: forwarded-pair grammar): "forwarded-pair = token "=" value value          = token / quoted-string"
    FORWARDED_PAIR_VALUE_EMPTY = {
        id: "forwarded_pair_value_empty",
        title: "Forwarded pair is written with no value after its '='",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7239_4],
    }

    /// One element naming a parameter twice: `for=192.0.2.1;for=192.0.2.2`.
    ///
    /// **Per element, though the sentence says "per field-value", and the two
    /// are the same thing here for the reason that makes the field useful.** A
    /// chain of proxies is a list of elements each holding its own `for` —
    /// §7.1 prints that as the ordinary case and §7.4 builds it from the legacy
    /// fields — so what the MUST NOT can be refusing is one element describing
    /// one hop twice.
    ///
    /// The names are folded before they are compared, because §4 says they are
    /// case-insensitive: `for=...;FOR=...` is one parameter written twice and
    /// not two extension parameters.
    ///
    /// `warn`. Both values are well formed and a recipient will take one of
    /// them; nothing in the document says which, so what the finding reports is
    /// one hop that two readers may describe differently.
    ///
    // cite(RFC 7239 § 4): "Each parameter MUST NOT occur more than once per field-value."
    FORWARDED_PARAMETER_DUPLICATED = {
        id: "forwarded_parameter_duplicated",
        title: "Forwarded element names one parameter more than once",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7239_4],
    }

    /// A `Forwarded` in a response, in either of its field sections.
    ///
    /// **`_forbidden` and not `_misdirected`, which is the line
    /// `docs/development.md` draws between them.** `_misdirected` is for a
    /// field RFC 9110 §10 sorts onto one side of the exchange with no keyword
    /// attached to either arrival. This field has a sentence prohibiting the
    /// arrival outright, and a second sentence saying what the arrival costs —
    /// the value names every proxy between the client and the origin, and a
    /// response carries it back to the party it was hidden from.
    ///
    /// **The trailer section counts, because a copy is a copy wherever it
    /// lands.** §8.2 refuses the copying and not a placement, so which section
    /// carried it is the message's business rather than a second entry's.
    ///
    /// `warn`. Nothing is unreadable, and no requirement about the *request* —
    /// the message this field was written for — was missed. What leaked is the
    /// topology, to a recipient with no use for it.
    ///
    // cite(RFC 7239 § 4): ""Forwarded" is only for use in HTTP requests and is not to be used in HTTP responses."
    // cite(RFC 7239 § 8.2): "This header field should never be copied into response messages by origin servers or intermediaries, as it can reveal the whole proxy chain to the client."
    FORWARDED_RESPONSE_FORBIDDEN = {
        id: "forwarded_response_forbidden",
        title: "Response carries a Forwarded field",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7239_4],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The argument on [`FORWARDED_ELEMENT_WHITESPACE_FORBIDDEN`], asserted
    /// rather than only described: this entry reports a position the parameter
    /// subject's cannot reach, so it cannot rank level with it.
    #[test]
    fn an_elements_whitespace_outranks_a_parameters() {
        assert!(
            crate::violations::parameter::PARAMETER_EQUALS_WHITESPACE_FORBIDDEN.default_severity
                < FORWARDED_ELEMENT_WHITESPACE_FORBIDDEN.default_severity
        );
    }

    /// Nothing here outranks anything else here, and that is a decision. Each
    /// entry is one sender writing one element wrongly against one section, no
    /// sentence separates them, and a split manufactured to make the subject
    /// look considered would be the catalogue inventing a preference.
    #[test]
    fn the_subject_is_level_with_itself() {
        for def in [
            &FORWARDED_ELEMENT_WHITESPACE_FORBIDDEN,
            &FORWARDED_PAIR_EQUALS_MISSING,
            &FORWARDED_PAIR_VALUE_EMPTY,
            &FORWARDED_PARAMETER_DUPLICATED,
            &FORWARDED_RESPONSE_FORBIDDEN,
        ] {
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
        }
    }
}
