// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `X-XSS-Protection` defects — a field no specification ever defined, and the
//! one setting this crate accepts besides the one that turns it off.
//!
//! **One entry, and it names no document, because there is none to name.** The
//! field was a browser feature rather than a definition: three engines shipped
//! it, no standards body wrote it down, and the browsers that carried it have
//! since dropped it. What is left is a description of what those browsers did,
//! which is not a requirement anything can fail.
//!
//! **The value set this crate enforces is deliberately narrower than the one
//! the description records.** `1` and `1; report=<uri>` were real settings; the
//! rule reports them anyway, because the filter they switch on is the thing the
//! same description warns can introduce the vulnerability it was meant to
//! prevent. So the entry rests on a reading of deployed behaviour, on the
//! footing [`crate::violations::content_disposition::CONTENT_DISPOSITION_SIZE_INVALID`]
//! and [`crate::violations::keep_alive::KEEP_ALIVE_TIMEOUT_INVALID`] already
//! share — and a reference here would say a document refuses these values when
//! none does.
//
// cite(MDN X-XSS-Protection): "response header was a feature of Internet Explorer, Chrome and Safari that stopped pages from loading when they detected reflected cross-site scripting"

use crate::lint::Severity;
use crate::violations::defects;

defects! {
    /// A value that is neither `0` nor `1; mode=block`, matched without regard
    /// to case and tolerating whitespace around the `;`.
    ///
    /// **Two kinds of value report through it and they are one claim.** A `2`
    /// or a word is a setting the field never had; a bare `1`, or
    /// `1; report=<uri>`, is one it did have and this crate declines. The
    /// entry does not split them the way the cross-origin embedder policy's
    /// pair splits, and the test there is what decides it: that split put an
    /// entry standing on HTML beside one standing on a preference, where both
    /// halves here stand on the same preference and end at the same repair —
    /// *write `0`.* Two ids for one repair would be two names for one thing.
    ///
    /// **`info`, which is where a finding lands when nothing in force refuses
    /// what it reports.** No document defines this field, no current browser
    /// implements it, and the two values the rule declines are documented ones.
    /// What the finding says is that a deployment configured a defence that
    /// either does nothing or, in a browser old enough to read it, switches on
    /// a filter that can introduce a vulnerability into a page that had none.
    ///
    // cite(MDN X-XSS-Protection): "Even though this feature can protect users of older web browsers that don't support CSP, in some cases, X-XSS-Protection can create XSS vulnerabilities in otherwise safe websites."
    // cite(MDN X-XSS-Protection): "Disables XSS filtering."
    X_XSS_PROTECTION_INVALID = {
        id: "x_xss_protection_invalid",
        title: "X-XSS-Protection asks for something other than the filter off",
        message: "",
        default_severity: Severity::Info,
        spec: &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The subject's ceiling, asserted rather than described: nothing states a
    /// requirement about this field, so nothing here can outrank advice.
    #[test]
    fn the_entry_names_no_document_and_ranks_accordingly() {
        assert!(X_XSS_PROTECTION_INVALID.spec.is_empty());
        assert_eq!(X_XSS_PROTECTION_INVALID.default_severity, Severity::Info);
    }
}
