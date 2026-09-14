// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Content-Transfer-Encoding` defects — a MIME field HTTP never adopted.
//!
//! **One entry, and it is about the field being there at all.** That is the
//! answer to a question this campaign carried for a long time: the rule reading
//! this field was one of the five traps recorded against borrowing
//! [`token`](crate::violations::token)'s ids, because RFC 2045 § 5.1's `token`
//! is not `tchar` — it subtracts `tspecials` from the visible US-ASCII and
//! keeps `{` and `}`. The reader was fixed first; and then the *def* turned out
//! not to be about the value's character class, or about the value at all.
//!
//! RFC 9112 App. B.5 says HTTP does not use the field, and asks gateways from
//! MIME-compliant protocols to remove it. So whatever the value derives from,
//! the finding is that the field survived into HTTP — and the message says what
//! the value looked like because a `base64` that was never stripped is a
//! different problem from an `x-` token nobody recognises.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Why the field is reported at all: HTTP does not use it, and a gateway is
/// asked to strip it.
pub const RFC_9112_B_5: SpecRef = SpecRef {
    spec: "RFC 9112",
    section: Some("B.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#appendix-B.5",
    note: "Why the field is reported at all: HTTP does not use Content-Transfer-Encoding, and gateways from MIME-compliant protocols must remove it",
};

defects! {
    /// A `Content-Transfer-Encoding` on an HTTP message.
    ///
    /// **`_forbidden` for a sentence that prohibits nothing of a sender**, and
    /// the reading is worth stating: HTTP does not *use* the field, and the
    /// requirement that keeps it off the wire is addressed to the gateway in
    /// the middle rather than to whoever wrote it. So what the entry reports is
    /// a field that should not have survived the hop, and the party at fault is
    /// whichever intermediary let it through.
    ///
    /// **The value is not what is wrong**, which is why no part narrows this
    /// id. A `base64` that nothing stripped means the content is not what its
    /// `Content-Type` describes; an unrecognised `x-` token means the same
    /// thing less legibly; and a value deriving from no MIME `mechanism` at all
    /// is still just this field, present. The message carries which.
    ///
    /// `warn`: a recipient ignores the field, as HTTP tells it to, and reads
    /// content that may still be encoded.
    ///
    // cite(RFC 9112 § B.5): "HTTP does not use the Content-Transfer-Encoding field of MIME."
    CONTENT_TRANSFER_ENCODING_FORBIDDEN = {
        id: "content_transfer_encoding_forbidden",
        title: "A MIME field HTTP does not use survived into an HTTP message",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9112_B_5],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No part narrows the id, because the value is not what is wrong — the
    /// field's presence is.
    #[test]
    fn the_id_names_the_field_and_not_its_value() {
        assert_eq!(
            CONTENT_TRANSFER_ENCODING_FORBIDDEN.id,
            "content_transfer_encoding_forbidden"
        );
        assert!(CONTENT_TRANSFER_ENCODING_FORBIDDEN.message.is_empty());
    }
}
