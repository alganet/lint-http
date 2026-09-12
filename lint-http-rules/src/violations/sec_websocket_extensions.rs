// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Sec-WebSocket-Extensions` defects — what RFC 6455's own notation owns.
//!
//! Almost everything in this field is borrowed. `extension-token`,
//! `extension-param`'s name and an unquoted value are all `token`, a quoted
//! value is § 5.6.4's `quoted-string` with the escape inside it, and § 9.1 goes
//! further than most fields do by requiring the value *after* unescaping to
//! conform to `token` as well — one id at five positions of a single member.
//!
//! **What is left is what the 1997 notation says and RFC 9110's does not.**
//! § 9.1 imports RFC 2616's ABNF by name, and two of this subject's three
//! entries exist because of what that import changes: the `#rule` here *allows*
//! null elements, so an empty member is not [`list`](crate::violations::list)'s
//! MUST NOT and a value of nothing but commas is the finding instead; and the
//! parameter production is not § 5.6.6's `parameters`, so neither
//! [`parameter`](crate::violations::parameter) entry can be borrowed for the
//! same two absences here. **Same words, different document, different list** —
//! borrowing either would put a citation on a finding whose grammar the cited
//! sentence does not govern.
//!
//! **Every entry here is an `error`, and one sentence is why.** § 9.1 does not
//! leave the consequence of a malformed value to a recipient's judgement: *the
//! recipient of such malformed data MUST immediately _Fail the WebSocket
//! Connection_*. So the question [`status`](crate::violations::status) ranks by
//! — whether the exchange can continue — is answered by the document itself,
//! and answered the same way for all three.
//!
//! **The borrowed ids stay at their own rank, and that is not an
//! inconsistency to fix.** `token_empty` answers for eighty other fields and
//! cannot carry this field's consequence; an operator who wants the whole
//! handshake at `error` raises the entries this subject owns and leaves the
//! productions alone. A shared entry's rank belongs to its subject, which is the
//! whole reason a defect has an id rather than a severity per reader.
//!
// cite(RFC 6455 § 9.1): "If a value is received by either the client or the server during negotiation that does not conform to the ABNF below, the recipient of such malformed data MUST immediately _Fail the WebSocket Connection_."

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Negotiating Extensions: the grammar, the MUST that makes a non-conforming
/// value a failure of the connection, and the note that the notation is RFC
/// 2616's.
pub const RFC_6455_9_1: SpecRef = SpecRef {
    spec: "RFC 6455",
    section: Some("9.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-9.1",
    note: "Negotiating Extensions — the grammar, the MUST that makes a non-conforming \
           value a failure of the connection, the note that the notation is RFC \
           2616's, and the requirement on a quoted-string value after unescaping",
};

/// The notation § 9.1 imports by name, and the only place the list construct
/// this field uses is written. Obsolete and correct: the document in force is
/// what sends the reader here.
pub const RFC_2616_2_1: SpecRef = SpecRef {
    spec: "RFC 2616",
    section: Some("2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc2616.html#section-2.1",
    note: "Augmented BNF — the notation §9.1 imports by name: the `#rule` whose null \
           elements are allowed (RFC 9110 §5.6.1.1 forbids them) and the implied \
           *LWS rule that permits whitespace beside the separators. Obsolete and \
           correct: the current document is what sends the reader here",
};

defects! {
    /// A field naming no extension at all: written empty, or written as
    /// nothing but commas and the whitespace around them.
    ///
    /// **This is the `1#` floor and not an empty member**, which is the one
    /// place this field parts company with every other list in the catalogue.
    /// RFC 2616's `#rule` permits null elements — `foo,,bar` is two extensions
    /// and conforms — and pays for it by requiring one that is not null. So
    /// [`list_member_empty`](crate::violations::list) reports a MUST NOT this
    /// grammar does not make, and [`list_member_missing`](crate::violations::list)
    /// carries § 5.6.1.2's worked example for a construct this field does not
    /// use.
    ///
    /// `_empty` and not `_missing`: the sender wrote the field. A message with
    /// no `Sec-WebSocket-Extensions` at all is a client offering none, which is
    /// what most handshakes are.
    ///
    // cite(RFC 2616 § 2.1): "Therefore, where at least one element is required, at least one non-null element MUST be present."
    SEC_WEBSOCKET_EXTENSIONS_EMPTY = {
        id: "sec_websocket_extensions_empty",
        title: "Sec-WebSocket-Extensions names no extension",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_2616_2_1],
    }

    /// A `;` inside a member with no parameter after it. The repetition prints
    /// the delimiter and an `extension-param` together and brackets neither, so
    /// `permessage-deflate;` generates no `extension` at all.
    ///
    /// **The three characters that are a defect here and are not one after a
    /// media type**, which is the line
    /// [`transfer_coding`](crate::violations::transfer_coding) drew for the
    /// same shape: § 5.6.6 writes `*( OWS ";" OWS [ parameter ] )`, whose
    /// brackets make a trailing semicolon a conforming zero-parameter
    /// repetition. This production has no brackets to hide behind, and it is
    /// not § 5.6.6's production in the first place.
    ///
    // cite(RFC 6455 § 9.1, label: extension repetition): "extension = extension-token *( ";" extension-param )"
    SEC_WEBSOCKET_EXTENSIONS_PARAMETER_MISSING = {
        id: "sec_websocket_extensions_parameter_missing",
        title: "Sec-WebSocket-Extensions writes a ';' with no parameter after it",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_9_1],
    }

    /// An `=` with nothing after it. The value is optional in this production —
    /// `client_no_context_takeover` is a parameter and a whole one — but the
    /// `=` is what says a value was due, and neither arm of the alternation
    /// derives the empty string: a `token` has a one-character floor and the
    /// shortest `quoted-string` is its two DQUOTEs.
    ///
    /// **The catalogue declines the alternation's empty value in general and
    /// answers it per production**, which is what
    /// [`parameter_value_empty`](crate::violations::parameter) already is for
    /// § 5.6.6. `word_defect` leaves `WordDefect::Empty` unnamed because six
    /// fields had settled it four ways and two tolerate it outright; a
    /// production that writes the `=` outside the brackets settles it for
    /// itself, and this one does.
    ///
    /// `x=""` is a different value and conforms as far as this entry goes: it
    /// is a `quoted-string` the production derives. What it fails is § 9.1's
    /// trailing requirement that the *unescaped* value be a `token`, which is
    /// [`token_empty`](crate::violations::token)'s finding and not this one.
    ///
    // cite(RFC 6455 § 9.1, label: extension-param alternation): "extension-param = token [ "=" (token | quoted-string) ]"
    SEC_WEBSOCKET_EXTENSIONS_PARAMETER_VALUE_EMPTY = {
        id: "sec_websocket_extensions_parameter_value_empty",
        title: "Sec-WebSocket-Extensions writes a parameter '=' with no value after it",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6455_9_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rank is the document's rather than the subject's judgement: a value
    /// that does not conform to § 9.1's ABNF is a connection a recipient MUST
    /// fail, so nothing here can be the milder half of anything.
    #[test]
    fn a_value_this_field_cannot_read_ends_the_connection() {
        for def in [
            &SEC_WEBSOCKET_EXTENSIONS_EMPTY,
            &SEC_WEBSOCKET_EXTENSIONS_PARAMETER_MISSING,
            &SEC_WEBSOCKET_EXTENSIONS_PARAMETER_VALUE_EMPTY,
        ] {
            assert_eq!(def.default_severity, Severity::Error, "{}", def.id);
        }
    }

    /// The list floor is the 1997 notation's and the two parameter absences are
    /// § 9.1's own, which is why the first entry cites a document the field's
    /// section only points at.
    #[test]
    fn the_list_floor_cites_the_notation_and_the_parameters_cite_the_field() {
        assert_eq!(SEC_WEBSOCKET_EXTENSIONS_EMPTY.spec, [RFC_2616_2_1]);
        assert_eq!(
            SEC_WEBSOCKET_EXTENSIONS_PARAMETER_MISSING.spec,
            [RFC_6455_9_1]
        );
        assert_eq!(
            SEC_WEBSOCKET_EXTENSIONS_PARAMETER_VALUE_EMPTY.spec,
            [RFC_6455_9_1]
        );
    }
}
