// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The escape two constructs share.
//!
//! `quoted-pair` is one production and RFC 9110 § 5.6.4 says in one sentence
//! where it may be written: *within quoted-string and comment constructs*. So
//! the defect is neither construct's. It lived under the `quoted_string`
//! subject while the quoted-string reader was its only caller, and moved here
//! the moment a comment reader could name it — the correction
//! `cookie_path_percent_encoding_malformed` needed, made before the id had any
//! configuration naming it rather than four commits after.
//!
//! **What does not move is `mailbox_quoted_pair_malformed`.** RFC 5322 writes
//! its own `quoted-pair` with its own alphabet, and a sentence that says the
//! same thing in another document is not the same sentence — the axis is the
//! document, not the container.

use crate::lint::Severity;
use crate::violations::defects;

// The section is § 5.6.4, which the `quoted_string` subject is named for and
// declares. One `SpecRef` per section is the rule, so this subject imports it
// rather than writing a second with the escape's half of the note on it.
use crate::violations::quoted_string::RFC_9110_5_6_4;

defects! {
    /// An escape that is not a `quoted-pair`: a backslash before an octet the
    /// pair does not admit, or a backslash with nothing after it at all. One
    /// def for both, because the operator's fix is the escape either way.
    ///
    /// Read out of a `quoted-string` — an `auth-param` value, a `Warning` text,
    /// a `filename` — and out of a `comment`, which `Server`, `User-Agent` and
    /// `Via` all admit after their first element. Neither construct restates
    /// the production; § 5.6.4 writes it once and names them both.
    ///
    // cite(RFC 9110 § 5.6.4): "quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )"
    // cite(RFC 9110 § 5.6.4): "The backslash octet ("\") can be used as a single-octet quoting mechanism within quoted-string and comment constructs."
    QUOTED_PAIR_MALFORMED = {
        id: "quoted_pair_malformed",
        title: "Escape is not a quoted-pair",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_5_6_4],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The id names the production and not either construct that admits it,
    /// which is the whole point of the entry having moved.
    #[test]
    fn the_id_names_the_escape_and_not_its_container() {
        assert_eq!(QUOTED_PAIR_MALFORMED.id, "quoted_pair_malformed");
        assert_eq!(QUOTED_PAIR_MALFORMED.default_severity, Severity::Warn);
    }
}
