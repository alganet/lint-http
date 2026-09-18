// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `X-XSS-Protection` defects — a field no specification ever defined, and the
//! two settings this crate accepts out of the four the description spells.
//!
//! **One entry, and it names no document, because there is none to name.** The
//! field was a browser feature rather than a definition: three engines shipped
//! it, no standards body wrote it down, and the browsers that carried it have
//! since dropped it. What is left is a description of what those browsers did,
//! which is not a requirement anything can fail.
//!
//! **The value set this crate accepts is narrower than the spellings the
//! description lists, and the line between them is the description's own.**
//! `1` and `1; report=<uri>` were real settings, and the rule reports them —
//! but not because the filter they switch on is dangerous as such. `1;
//! mode=block` switches on the same filter and is accepted. What the worked
//! example shows introducing a vulnerability is the *sanitizing*: a filter
//! that rewrites the page can delete the very script that made the page safe.
//! So the line runs between the settings that rewrite the page and the
//! settings that do not, and the description draws it — `0` runs every script,
//! `1; mode=block` stops the page being processed at all, and those two are
//! exactly the pair this rule accepts. So the entry rests on a reading of
//! deployed behaviour, on the footing
//! [`crate::violations::content_disposition::CONTENT_DISPOSITION_SIZE_INVALID`]
//! and [`crate::violations::keep_alive::KEEP_ALIVE_TIMEOUT_INVALID`] already
//! share — and a reference here would still say a document refuses these
//! values when none does: the description says which settings prevent the
//! vulnerability, not that a sender may not write the others.
//
// cite(MDN X-XSS-Protection): "response header was a feature of Internet Explorer, Chrome and Safari that stopped pages from loading when they detected reflected cross-site scripting"
// cite(MDN X-XSS-Protection): "If a cross-site scripting attack is detected, the browser will sanitize the page"
// cite(MDN X-XSS-Protection): "would prevent the page from being processed at all"

use crate::lint::Severity;
use crate::violations::defects;

defects! {
    /// A value that is neither `0` nor `1; mode=block`, matched without regard
    /// to case and tolerating whitespace around the `;`.
    ///
    /// **Three kinds of value report through it and they are one claim.** A `2`
    /// or a word is a setting the field never had; a bare `1`, or
    /// `1; report=<uri>`, is one it did have and this crate declines; and
    /// `1; mode=block; report=<uri>` is the blocking spelling with a further
    /// setting beside it, which no reference defines and which several
    /// deployments behind one vendor's script send. The third is why the rule
    /// builds two sentences rather than one — the first two spell neither
    /// accepted setting and can be told so, while the third plainly spells one
    /// of them and only the *combination* is unaccounted for. The entry does
    /// not split them the way the cross-origin embedder policy's pair splits,
    /// and the test there is what decides it: that split put an entry standing
    /// on HTML beside one standing on a preference, where all three groups here
    /// stand on the same preference and end at the same repair — *write `0`, or
    /// `1; mode=block`.* Ids for one repair would be several names for one
    /// thing.
    ///
    /// **The id says `_invalid` and the title is what the entry actually
    /// claims.** A bare `1` was a real, documented setting, so "invalid" is
    /// false of it in the sense a reader first takes — the title says the true
    /// thing, that the value asks for neither the filter off nor the page
    /// blocked. The id is kept regardless: it is the key an operator writes in
    /// `[violations.<id>]`, and renaming it would break those files to gain
    /// precision in the one place nobody configures, for a field no standard
    /// defined and no current browser reads.
    ///
    /// **`info`, which is where a finding lands when nothing in force refuses
    /// what it reports.** No document defines this field, no current browser
    /// implements it, and the two values the rule declines are documented ones.
    /// What the finding says is that a deployment configured a defence that
    /// either does nothing or, in a browser old enough to read it, asks the
    /// filter to rewrite the page — the one behaviour that can introduce a
    /// vulnerability into a page that had none.
    ///
    // cite(MDN X-XSS-Protection): "Even though this feature can protect users of older web browsers that don't support CSP, in some cases, X-XSS-Protection can create XSS vulnerabilities in otherwise safe websites."
    // cite(MDN X-XSS-Protection): "Disables XSS filtering."
    X_XSS_PROTECTION_INVALID = {
        id: "x_xss_protection_invalid",
        title: "X-XSS-Protection asks for neither the filter off nor the page blocked",
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
