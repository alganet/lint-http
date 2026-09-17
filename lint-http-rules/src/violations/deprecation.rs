// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Deprecation and sunset defects — when a resource stopped being recommended,
//! and when it stops answering.
//!
//! **Two fields and one document, and the second entry is about the pair.** RFC
//! 9745 defines `Deprecation` and then says what a `Sunset` beside it may not
//! be, so a response carrying both states an order the document requires — and
//! an operator configuring one of these is configuring the announcement of a
//! retirement, which is one thing.
//!
//! **`Deprecation` is a Structured Field Date and nothing else**, which is the
//! whole of its syntax entry. The field went through a draft era with two other
//! spellings in it, and both still appear on the wire; neither is a different
//! defect from any other non-Date, so they are messages rather than ids.
//
// cite(RFC 9745 § 2): "The Deprecation HTTP response header field allows a server to communicate to a client application that the resource in the context of the message will be or has been deprecated."

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field's syntax: an Item Structured Header Field whose value is a Date.
pub const RFC_9745_2_1: SpecRef = SpecRef {
    spec: "RFC 9745",
    section: Some("2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9745.html#section-2.1",
    note: "Syntax: `Deprecation` is an Item Structured Header Field whose value MUST be a `Date`",
};

/// `Sunset`: what the value is, and that it ought to name a future time.
pub const RFC_8594_3: SpecRef = SpecRef {
    spec: "RFC 8594",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc8594.html#section-3",
    note: "The `Sunset` HTTP header field — an `HTTP-date` timestamp that SHOULD be in the future",
};

/// The ordering the two fields have to state between them.
pub const RFC_9745_4: SpecRef = SpecRef {
    spec: "RFC 9745",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc9745.html#section-4",
    note: "The `Sunset` timestamp MUST NOT be earlier than the `Deprecation` one",
};

defects! {
    /// A `Deprecation` whose value is not a Structured Field Date: the legacy
    /// token `true`, an `HTTP-date`, or anything else at all.
    ///
    /// **One entry for three shapes, and the rule's own comment is the
    /// argument**: § 2.1 says the value MUST be a Date, and every other form
    /// fails that one sentence. The `true` and the `HTTP-date` are recognised
    /// only to say something more useful in the message — both are draft-era
    /// spellings that are still on the wire — and a sender writing either has
    /// made the same mistake as one writing `soon`, with the same repair.
    /// *A diagnostic is a message, not an id.*
    ///
    /// **A valid `HTTP-date` is a finding here**, which is worth stating
    /// because it is the one shape that looks right: this field asks for
    /// `@<seconds>`, and a timestamp in the format every other date-valued
    /// field uses is not one.
    ///
    /// `error`: § 2.1 says the value MUST be a Date. A recipient that cannot
    /// read it learns nothing about the deprecation, and the resource answers
    /// exactly as it did.
    ///
    // cite(RFC 9745 § 2.1): "Deprecation is an Item Structured Header Field; its value MUST be a Date as per Section 3.3.7 of [RFC9651]."
    DEPRECATION_MALFORMED = {
        id: "deprecation_malformed",
        title: "A Deprecation is not a Structured Field Date",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9745_2_1],
        strength: Strength::Must,
    }

    /// A `Sunset` at or before the `Date` of the response carrying it.
    ///
    /// **The field's whole purpose is to name a moment that has not arrived**,
    /// and § 3 says so in a SHOULD: a resource announcing a shutdown that has
    /// already happened is either still answering past its own deadline or
    /// publishing a stale announcement, and a client cannot tell which.
    ///
    /// **`_invalid` and not `_conflicting`, which its sibling below is.** That
    /// entry reports two timestamps whose *order* is wrong and either of which
    /// would be fine alone; this one reports a single value measured against the
    /// message's own clock and refused by what the field is for. The comparison
    /// needs a second timestamp only to know what "now" was.
    ///
    /// `warn`, and the SHOULD is why it is not more: the document asks rather
    /// than requires, and a deployment that left a past sunset in place has
    /// published something misleading rather than broken anything.
    ///
    // cite(RFC 8594 § 3): "The Sunset value is an HTTP-date timestamp, as defined in Section 7.1.1.1 of [RFC7231], and SHOULD be a timestamp in the future."
    SUNSET_INVALID = {
        id: "sunset_invalid",
        title: "A Sunset names a time that has already passed",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_8594_3],
        strength: Strength::Should,
    }

    /// A response whose `Sunset` names a time before its `Deprecation`.
    ///
    /// **The subject is `Sunset` because the MUST NOT is addressed to it**, not
    /// to the field the rule is named after first: § 4 says the timestamp given
    /// in the `Sunset` field must not be earlier than the one given in
    /// `Deprecation`, so the value the sentence constrains is the sunset.
    ///
    /// **`_conflicting`, and the pair is what conflicts**: each timestamp is
    /// well formed and either would be unremarkable alone. What the two say
    /// together is that a resource stopped answering before it stopped being
    /// recommended, which is an announcement no client can act on.
    ///
    /// `error`: § 4 says the `Sunset` timestamp MUST NOT be earlier than the
    /// `Deprecation` one. Nothing is unreadable and the resource behaves
    /// however it behaves; what is wrong is the schedule the response
    /// published.
    ///
    // cite(RFC 9745 § 4): "The timestamp given in the Sunset HTTP header field MUST NOT be earlier than the one given in the Deprecation header field."
    SUNSET_CONFLICTING = {
        id: "sunset_conflicting",
        title: "A Sunset names a time before the Deprecation beside it",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9745_4],
        strength: Strength::Must,
    }
}
