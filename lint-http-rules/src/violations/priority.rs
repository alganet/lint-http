// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Priority defects — what the two parameters RFC 9218 defines must be, and
//! what becomes of one that is not.
//!
//! A field subject sitting on top of a production one. `Priority` is a
//! Structured Fields Dictionary, so everything about *writing* one is
//! [`structured_fields`](crate::violations::structured_fields)' and answers to
//! RFC 9651; what is left for RFC 9218 to state is which keys mean something
//! and what type each of their values has. The entries here are that
//! remainder, and there are only two keys to have it.
//!
//! **Nothing here is an error, and the document says so before this catalogue
//! does.** § 4 adds exactly one requirement on top of a Dictionary that
//! parsed, it is addressed to receivers, and it is to *ignore* — so a parameter
//! these entries refuse is never a message that cannot be read, it is a signal
//! that will not arrive. What that costs is not the same in the two
//! directions, which is why every message names the one it was read from: a
//! request has defaults to fall back on, and a response has none, so an ignored
//! response parameter loses the server's opinion outright.
//!
//! **An unrecognised key is deliberately not here.** The "HTTP Priority"
//! registry is open, § 4.3 has a new parameter arrive precisely by being
//! ignored where it is not understood, and an entry for one would report the
//! extension mechanism working.
//
// cite(RFC 9218 § 4): "Where the Dictionary is successfully parsed, this document places the additional requirement that unknown priority parameters, priority parameters with out-of-range values, or values of unexpected types MUST be ignored."

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Urgency: the type its value has, and the bound past the type.
pub const RFC_9218_4_1: SpecRef = SpecRef {
    spec: "RFC 9218",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9218.html#section-4.1",
    note: "Urgency — an Integer between 0 and 7 inclusive, in descending order of priority, defaulting to 3",
};

/// Incremental: a Boolean, and nothing else to say about it.
pub const RFC_9218_4_2: SpecRef = SpecRef {
    spec: "RFC 9218",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9218.html#section-4.2",
    note: "Incremental — a Boolean saying whether the response can be processed as it arrives, defaulting to false",
};

defects! {
    /// A `u` whose value is not an Integer: `u=high`, `u=1.5`, or a bare `u`
    /// with no value at all.
    ///
    /// **The bare key belongs here rather than in an entry of its own**, and
    /// it is the one place in this field where leaving a value out is a defect
    /// instead of a shorthand. RFC 9651 § 4.2.2 reads a member with no `=` as
    /// the Boolean true, which is a perfectly good Dictionary member — so
    /// nothing is missing and nothing is empty; what the sender wrote is a
    /// Boolean where § 4.1 names an Integer, which is the same mistake `u=high`
    /// makes and takes the same repair. The message names which of the two was
    /// written. (`i` reaches the opposite conclusion from the same sentence:
    /// there the Boolean true is exactly the type the parameter is defined as,
    /// and `u=5, i` is the RFC's own spelling of it.)
    ///
    /// `_malformed`: an Integer is a production, and a Token or a Decimal
    /// derives from a different one. § 4 calls this a value of unexpected type
    /// and lists it apart from a value that is out of range, which is why
    /// [`PRIORITY_URGENCY_INVALID`] is a second entry rather than a second
    /// wording.
    ///
    /// `warn`. What it costs is one parameter and not the field, which is
    /// below every entry in the production subject — but a value deriving from
    /// the wrong type is a plain mistake rather than something permitted, so it
    /// is not `info` either.
    ///
    // cite(RFC 9218 § 4.1): "The urgency (u) parameter value is Integer (see Section 3.3.1 of [STRUCTURED-FIELDS]), between 0 and 7 inclusive, in descending order of priority."
    PRIORITY_URGENCY_MALFORMED = {
        id: "priority_urgency_malformed",
        title: "Priority urgency is not an Integer",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9218_4_1],
    }

    /// A `u` that is an Integer and is not one of the eight: `u=8`, `u=-1`.
    ///
    /// `_invalid` against [`PRIORITY_URGENCY_MALFORMED`]'s `_malformed`, and
    /// the split is § 4's own — it names a value out of range and a value of
    /// unexpected type in one sentence and separately. The value derives from
    /// the production the parameter is defined as; what refuses it is the bound
    /// § 4.1 writes past the type, which is the difference the two endings
    /// carry everywhere else in this catalogue.
    ///
    /// **The bound is read by parsing rather than by looking at the digit**,
    /// because an Integer may be written with leading zeros and a signed zero:
    /// `u=03` is 3 and `u=-0` is 0, and RFC 9651 § 3.3.1 says those spellings
    /// may not survive a round trip but does not make them defects.
    ///
    /// `warn`, with its sibling.
    ///
    // cite(RFC 9218 § 4.1): "between 0 and 7 inclusive, in descending order of priority. The default is 3."
    PRIORITY_URGENCY_INVALID = {
        id: "priority_urgency_invalid",
        title: "Priority urgency is outside 0 to 7",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9218_4_1],
    }

    /// An `i` whose value is not a Boolean: `i=1`, `i=yes`, `i=?2`.
    ///
    /// **No sibling, because a Boolean has no range past its type.** `u` needs
    /// two entries since § 4.1 states a production and then a bound inside it;
    /// § 4.2 states a production and stops, so every way of getting `i` wrong
    /// is one way.
    ///
    /// **A bare `i` is not this**, and the reason is the same sentence that
    /// makes a bare `u` a defect: RFC 9651 § 4.2.2 reads a member with no `=`
    /// as the Boolean true, which is exactly what this parameter is defined to
    /// carry. `Priority: u=5, i` is RFC 9218's own example.
    ///
    /// `warn`, with the urgency entries.
    ///
    // cite(RFC 9218 § 4.2): "The incremental (i) parameter value is Boolean (see Section 3.3.6 of [STRUCTURED-FIELDS])."
    PRIORITY_INCREMENTAL_MALFORMED = {
        id: "priority_incremental_malformed",
        title: "Priority incremental is not a Boolean",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9218_4_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two urgency entries are the two halves of one sentence, and both
    /// name it — the split is in the endings, not in the reference.
    #[test]
    fn urgency_splits_on_the_ending_and_not_on_the_section() {
        assert_eq!(PRIORITY_URGENCY_MALFORMED.spec, [RFC_9218_4_1]);
        assert_eq!(PRIORITY_URGENCY_INVALID.spec, [RFC_9218_4_1]);
        assert!(PRIORITY_URGENCY_MALFORMED.id.ends_with("_malformed"));
        assert!(PRIORITY_URGENCY_INVALID.id.ends_with("_invalid"));
    }

    /// Nothing in this subject outranks the production subject it sits on: an
    /// ignored parameter costs itself, where a parse failure costs the field.
    #[test]
    fn an_ignored_parameter_ranks_below_a_lost_field() {
        for def in [
            &PRIORITY_URGENCY_MALFORMED,
            &PRIORITY_URGENCY_INVALID,
            &PRIORITY_INCREMENTAL_MALFORMED,
        ] {
            assert_eq!(def.default_severity, Severity::Warn);
        }
    }
}
