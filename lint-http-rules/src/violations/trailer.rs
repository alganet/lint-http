// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Trailer defects — what a field sent *after* the content answers for, and
//! what the declaration in front of it should have said.
//!
//! **A subject about a section rather than about a value**, which is the kind
//! [`field`](crate::violations::field) opened: nothing here reads what a field
//! carries, only whether it may be where it landed. A trailer section is the
//! one place in an HTTP message that arrives after the recipient has begun
//! acting on the message, and every entry below follows from that: a value that
//! had to be read *before* the content cannot be sent behind it, and a value
//! addressed to the connection rather than to the peer will be gone before it
//! arrives.
//!
//! **Deny-by-default, and this crate cannot enforce it.** § 6.5.1 permits a
//! trailer field only where the field's own definition says so, and § 16.3.2
//! tells authors of new fields that theirs is not allowable unless it says so —
//! but a rule can only report the definitions it holds. For `X-Checksum` or
//! `Grpc-Status`, only the sender knows, and reporting every unrecognised name
//! would report the senders that read their own specification. So a field these
//! entries stay silent about has not been approved by them.
//!
//! **The `Trailer` field's own syntax is not here.** That is a `#field-name`
//! list of `token`s, and both productions answer to their own subjects — the
//! two `member` entries are about *which names the list carries*, never about
//! how it is written: one for a name that should have been there and one for a
//! name that cannot be.
//
// cite(RFC 9110 § 16.3.2): "If the field is allowable in trailers; by default, it will not be"

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Trailer fields: the sender's MUST NOT, and the reason behind it.
pub const RFC_9110_6_5_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("6.5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1",
    note: "Limitations on use of trailers — a trailer field is permitted only where the field's own definition says so, which is deny-by-default and therefore reportable only for the definitions a linter holds",
};

/// The `Trailer` field: what it is for, and the SHOULD that asks for it.
pub const RFC_9110_6_6_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("6.6.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.2",
    note: "`Trailer = #field-name` — the list a sender is asked to write so a recipient can prepare for the metadata before it starts processing the content, and the note that the list is a hint rather than a promise",
};

/// `Connection`: what naming a field there means, and what every intermediary
/// then does about it.
pub const RFC_9110_7_6_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("7.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1",
    note: "`Connection` — naming a field as a connection-option declares it hop-by-hop, and every intermediary removes it from the header *and trailer* sections before forwarding",
};

defects! {
    /// A trailer field whose own definition does not permit the usage:
    /// `Content-Length`, `Host`, `Cache-Control`, `Date`, `Content-Type`.
    ///
    /// **The category is not what decides, which is why the message names the
    /// field's definition instead.** § 6.5.1 sorts examples into framing,
    /// routing, request modifiers, authentication, response control and content
    /// format — and `Authentication-Info` is an authentication field whose own
    /// definition permits it in a trailer section by name. A reader that
    /// enforced the categories would report a conforming sender.
    ///
    /// **What the defect costs is the value, not the message.** These are
    /// fields a recipient needs before it reads the content: it has already
    /// framed the message, routed it, chosen a cache entry and picked a parser
    /// by the time the trailer section arrives, so a `Content-Type` there
    /// describes a body already consumed. Nothing is malformed; something
    /// arrived too late to be used.
    ///
    /// `warn`. A MUST NOT, but the message is well formed and the recipient's
    /// escape — ignoring the trailer section, which § 6.5.1 permits — is the
    /// one deployments take.
    ///
    // cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
    TRAILER_FIELD_FORBIDDEN = {
        id: "trailer_field_forbidden",
        title: "A trailer field's definition does not permit the usage",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_6_5_1],
    }

    /// A trailer field this message's own `Connection` names as a
    /// connection-option.
    ///
    /// **The one case where the deny-by-default question is decidable for a
    /// field nobody defined**, and it is decidable because the sender answered
    /// it: listing a name in `Connection` says that field carries control
    /// information for *this* connection. So the answer does not depend on
    /// knowing what the field is — it depends on what this message said about
    /// it.
    ///
    /// **Separate from [`TRAILER_FIELD_FORBIDDEN`] because the loss is a
    /// different one.** There a value arrives too late to be used; here it does
    /// not arrive at all — an intermediary is required to strip it, by name,
    /// from the trailer section before forwarding. A sender fixing the first
    /// moves the field into the header section; a sender fixing this one learns
    /// that the field never reaches the peer at all, whichever section carries
    /// it.
    ///
    /// **Not [`field_connection_specific_forbidden`](crate::violations::field)**,
    /// which is HTTP/2's and HTTP/3's prohibition on the whole hop-by-hop
    /// mechanism. That entry answers for a version that has no `Connection`
    /// field; this one answers for a version that has one and used it.
    ///
    /// `warn`, with its sibling: the value is lost and the message is not.
    ///
    // cite(RFC 9110 § 7.6.1): "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself"
    TRAILER_CONNECTION_OPTION_FORBIDDEN = {
        id: "trailer_connection_option_forbidden",
        title: "A trailer field is named as a connection-option in this message",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_7_6_1],
    }

    /// A field arrives in the trailer section that the message's `Trailer`
    /// header did not name.
    ///
    /// **The defect is in the declaration, not in the field**, which is what
    /// the `member` part says: `Trailer` is a `#field-name` list, and a name
    /// that should have been one of its members is not there. The field itself
    /// may be perfectly entitled to the section.
    ///
    /// **Asked only of a message that wrote a `Trailer`**, because it is the
    /// declaration that creates the expectation there is something to fall
    /// short of — and an empty one still counts: `Trailer:` announces a list of
    /// no names, so every field that then arrives is one it did not indicate.
    ///
    /// `info`, and the document argues it in both directions. The `Trailer`
    /// field exists so a recipient can prepare for the metadata before it
    /// starts processing the content, which is a preparation lost rather than a
    /// value; and § 6.6.2 says outright that there is no guarantee a sender of
    /// `Trailer` follows through with the names it wrote. A list that is a hint
    /// when complete cannot be an error when short.
    ///
    // cite(RFC 9110 § 6.6.2): "A sender that intends to generate one or more trailer fields in a message SHOULD generate a Trailer header field in the header section of that message to indicate which fields might be present in the trailers."
    TRAILER_MEMBER_MISSING = {
        id: "trailer_member_missing",
        title: "A trailer field was not named in the Trailer declaration",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_6_6_2],
    }

    /// A `Trailer` declaration naming a field that cannot arrive in the section
    /// it announces: `Trailer` itself, or a field this message's own
    /// `Connection` lists as an option.
    ///
    /// **One entry for two shapes, because the loss is one loss.** § 6.6.2 says
    /// the list indicates which fields *might* be present in the trailers, and
    /// neither of these might: a `Trailer` field belongs to the header section
    /// by its own definition, so naming it announces a section the recipient has
    /// already finished reading; a connection-option is stripped by name at the
    /// first intermediary, so the field never survives the hop. *The defect is
    /// the announcement rather than the field — a recipient prepared for
    /// something that is not coming.* Which shape it was is what the message
    /// says.
    ///
    /// **`_invalid` and not `_forbidden`, and the sentence count is why.** The
    /// two MUST NOTs nearby are about *generating a trailer field*, not about
    /// writing a name in this list, so nothing prohibits the declaration — what
    /// refuses it is that the name is a well-formed `field-name` naming
    /// something the section cannot hold.
    ///
    /// **Below [`TRAILER_FIELD_FORBIDDEN`] and level with
    /// [`TRAILER_MEMBER_MISSING`]**, which puts the whole subject in one order:
    /// a field that arrived where it may not outranks a declaration that is out
    /// of step with what arrives, in either direction. § 6.6.2's own words are
    /// what cap both — a list that is a hint when it is short cannot be an error
    /// when it is wrong.
    ///
    // cite(RFC 9110 § 6.6.2): "A sender that intends to generate one or more trailer fields in a message SHOULD generate a Trailer header field in the header section of that message to indicate which fields might be present in the trailers."
    TRAILER_MEMBER_INVALID = {
        id: "trailer_member_invalid",
        title: "A Trailer declaration names a field that cannot arrive",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_6_6_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two prohibitions rank together and the two declaration entries below
    /// them, which is the split between a value that was lost and a preparation
    /// that was — in either direction, a list too short or a list naming
    /// something that cannot come.
    #[test]
    fn the_declaration_ranks_below_the_two_prohibitions() {
        assert_eq!(TRAILER_FIELD_FORBIDDEN.default_severity, Severity::Warn);
        assert_eq!(
            TRAILER_CONNECTION_OPTION_FORBIDDEN.default_severity,
            Severity::Warn
        );
        assert_eq!(TRAILER_MEMBER_MISSING.default_severity, Severity::Info);
        assert_eq!(
            TRAILER_MEMBER_INVALID.default_severity,
            TRAILER_MEMBER_MISSING.default_severity
        );
        assert!(TRAILER_MEMBER_INVALID.default_severity < TRAILER_FIELD_FORBIDDEN.default_severity);
    }
}
