// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Accept-Charset` defects — the one § 12.5 field whose subject is the field.
//!
//! § 12.5 defines four content-negotiation fields and three of them have
//! nothing to say about their own existence: an `Accept`, an `Accept-Encoding`
//! and an `Accept-Language` are ordinary fields and every entry about them
//! reads a value. This one is deprecated by the section that defines it, so it
//! has an entry that reads no value at all — which is the only thing the field
//! does not share with its siblings, and therefore the only thing filed here.
//!
//! What a value may be is [`qvalue`](crate::violations::qvalue),
//! [`list`](crate::violations::list), [`token`](crate::violations::token) and
//! [`charset`](crate::violations::charset), each shared with the field that
//! prints the same production. `accept_charset_valid` declares them and this
//! entry together, so the field's presence and the field's value are one rule's
//! two subjects.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Accept-Charset: the production, the charset names it carries, the `*`, and
/// the Note that deprecates the whole field.
pub const RFC_9110_12_5_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("12.5.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.2",
    note: "Accept-Charset: `#( ( token / \"*\" ) [ weight ] )` — the production that says a charset name may carry a weight and nothing else, the meaning given to the `*`, the pointer to §8.3.2 for the names themselves, and the Note that deprecates the field. Like §12.5.4 and unlike §12.5.1 and §12.5.3, it gives the field no meaning in a response",
};

defects! {
    /// An `Accept-Charset` on the request that defines it.
    ///
    /// **`_obsolete`, the vocabulary's rarest ending, used for exactly what it
    /// names**: the specification that defines the field deprecates it in the
    /// same section, and the IANA HTTP Field Name Registry records the status
    /// with this section as the field's only reference.
    ///
    /// **The direction is the one the section is written about**, which is the
    /// reading [`PRAGMA_OBSOLETE`](crate::violations::pragma::PRAGMA_OBSOLETE)
    /// was given for its own field: § 12.5.2 names a field a *user agent*
    /// sends, so a request carrying one is the deprecated thing being done. A
    /// response carrying an `Accept-Charset` is not this entry and is not any
    /// entry — § 12.5.2 gives the field no meaning there and forbids nothing
    /// either, exactly as § 12.5.4 does for `Accept-Language`, and
    /// `accept_charset_valid` reads such a value for syntax while claiming
    /// nothing about the direction.
    ///
    /// **`info`, and the Note's three harms do not move it.** Wasted bandwidth,
    /// added latency and passive fingerprinting are all costs the *sender*
    /// pays for writing the field; no recipient is misled by one, and nothing
    /// in the exchange stops working. What the finding buys is that the sender
    /// learns it is writing into a void — the same thing every other member of
    /// the deprecation family buys, at the same level.
    ///
    // cite(RFC 9110 § 12.5.2): "The "Accept-Charset" header field can be sent by a user agent to indicate its preferences for charsets in textual response content."
    // cite(RFC 9110 § 12.5.2, label: the deprecation): "Accept-Charset is deprecated because UTF-8 has become nearly ubiquitous and sending a detailed list of user-preferred charsets wastes bandwidth, increases latency, and makes passive fingerprinting far too easy"
    ACCEPT_CHARSET_OBSOLETE = {
        id: "accept_charset_obsolete",
        title: "A request carries a field this specification deprecates",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_12_5_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::pragma::PRAGMA_OBSOLETE;

    /// The family's level, asserted against the member it was modelled on
    /// rather than written down twice. A deprecation costs the exchange
    /// nothing, so if one of these ever moves the other has to be argued.
    #[test]
    fn a_deprecated_field_sits_where_the_family_sits() {
        assert_eq!(
            ACCEPT_CHARSET_OBSOLETE.default_severity,
            PRAGMA_OBSOLETE.default_severity
        );
        assert_eq!(ACCEPT_CHARSET_OBSOLETE.default_severity, Severity::Info);
    }

    /// The entry reads no value, so it states no grammar: its strength is the
    /// unstated one, as the section carries no RFC 2119 keyword binding the
    /// sender — "is deprecated" is a statement about the field, not an
    /// instruction to whoever writes it.
    #[test]
    fn a_deprecation_states_no_keyword() {
        assert_eq!(
            ACCEPT_CHARSET_OBSOLETE.strength,
            crate::lint::Strength::Unstated
        );
    }

    /// A single-entry subject cannot get its own id wrong twice, and the id is
    /// what a configuration names.
    #[test]
    fn the_id_is_the_field_and_the_ending() {
        assert_eq!(ACCEPT_CHARSET_OBSOLETE.id, "accept_charset_obsolete");
        assert!(!ACCEPT_CHARSET_OBSOLETE.spec.is_empty());
    }
}
