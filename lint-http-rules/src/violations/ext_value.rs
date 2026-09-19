// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `ext-value` defects — the parameter value that carries a charset.
//!
//! RFC 8187 § 3.2.1 writes `ext-value = charset "'" [ language ] "'"
//! value-chars`, the form a parameter whose name ends in an asterisk takes.
//! It is not [`parameter`](crate::violations::parameter)'s: § 5.6.6's
//! `parameter-value` is `( token / quoted-string )` and neither of those
//! derives an `ext-value`, which is why a field defining one has to say so in
//! its own grammar.
//!
//! **Two entries, and § 3.2.1 states them in consecutive paragraphs.** The
//! production is one claim and the encoding a producer may choose is another:
//! `iso-8859-1'en'%A3%20rates` derives from `ext-value` — `mime-charset` is an
//! alternative of `charset` and admits every octet in it — and the paragraph
//! after the ABNF forbids a producer to write it. So a value can be well formed
//! and still be one no sender may generate, which is why
//! [`EXT_VALUE_CHARSET_FORBIDDEN`] is not a verdict
//! [`EXT_VALUE_MALFORMED`] could carry.
//!
//! **One entry, and it is coarser than the reader behind it.**
//! [`crate::helpers::parameter::validate_ext_value`] distinguishes seven ways
//! the value can fail — no charset separator, no language separator, an empty
//! or non-ASCII charset, an incomplete or non-hex percent-escape, an octet no
//! `attr-char` admits — and returns them as prose. Typing that reader is what
//! would split this entry, and until it is typed a finer catalogue here would
//! be a claim the code cannot support: the ids would exist and no site could
//! choose between them.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The production, its three parts and the two separators between them.
pub const RFC_8187_3_2_1: SpecRef = SpecRef {
    spec: "RFC 8187",
    section: Some("3.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc8187.html#section-3.2.1",
    note: "`ext-value = charset \"'\" [ language ] \"'\" value-chars` — the charset that may not be empty, the language that may be, and the `value-chars` made of `pct-encoded` and `attr-char`. Obsoletes RFC 5987, which older references named; the production is unchanged",
};

defects! {
    /// A value in a `name*` parameter that is no `ext-value`: no charset
    /// separator, no language separator, an empty or non-ASCII charset, a
    /// percent-escape that is incomplete or not hexadecimal, or an octet
    /// `attr-char` does not admit.
    ///
    /// **One entry over the reader's seven verdicts**, because the reader
    /// returns prose rather than a type and a caller cannot tell them apart to
    /// report them separately. The message carries the reader's own words, so
    /// nothing an operator reads is lost; what is not yet available is
    /// configuring the parts of the production against each other, and that
    /// arrives when the reader is typed and not before.
    ///
    /// `error`, from `ext-value`'s production. A `filename*` a recipient cannot
    /// decode falls back to the plain `filename` where the field carries one
    /// and to the recipient's own default where it does not, so the download is
    /// named badly rather than not at all.
    ///
    // cite(RFC 8187 § 3.2.1): "ext-value     = charset  "'" [ language ] "'" value-chars"
    EXT_VALUE_MALFORMED = {
        id: "ext_value_malformed",
        title: "An extended parameter value is no ext-value",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_8187_3_2_1],
        strength: Strength::Grammar,
    }

    /// An `ext-value` whose `charset` is not `UTF-8`: a well-formed value in an
    /// encoding RFC 8187 § 3.2.1 reserves and forbids a producer to use.
    ///
    /// **Not [`EXT_VALUE_MALFORMED`], and the ABNF is why.** `charset` is
    /// `"UTF-8" / mime-charset`, and `mime-charset` derives `iso-8859-1`,
    /// `Shift_JIS` and every other registered name — so a value spelling one of
    /// them is a value the production generates, and calling it malformed says
    /// something the grammar contradicts. What is wrong with it is in the
    /// paragraph after the ABNF, addressed to the sender in its own sentence.
    ///
    /// **What it costs a recipient is real and it is not a lost value.** RFC
    /// 8187 obsoleted RFC 5987, which required every recipient to support
    /// ISO-8859-1 and UTF-8; the requirement that replaced it names UTF-8
    /// alone, so a recipient built to the document now in force may decode
    /// nothing here — and the section's own note offers three ways of failing,
    /// of which one is ignoring the parameter. A `filename*` in ISO-8859-1
    /// therefore falls back to a plain `filename` where the field carries one
    /// and to the recipient's default where it does not, exactly as a malformed
    /// one does. The value is legal and the outcome is the same, which is the
    /// argument for reporting it at all.
    ///
    /// The comparison folds case, because § 3.2.1 says character encoding names
    /// are matched case-insensitively: `utf-8` and `UTF-8` are one charset.
    ///
    /// `error`, from a `MUST` binding the producer of the message being
    /// reported — the addressee reading, not the keyword alone.
    ///
    // cite(RFC 8187 § 3.2.1, label: producers): "Producers MUST use the "UTF-8" ([RFC3629]) character encoding."
    // cite(RFC 8187 § 3.2.1, label: reserved): "Extension character encodings (mime-charset) are reserved for future use."
    // cite(RFC 8187 § 3.2.1, label: folding): "Note that both character encoding names and language tags are restricted to the US-ASCII coded character set and are matched case-insensitively"
    EXT_VALUE_CHARSET_FORBIDDEN = {
        id: "ext_value_charset_forbidden",
        title: "An extended parameter value names a character encoding reserved for future use",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_8187_3_2_1],
        strength: Strength::Must,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::parameter::PARAMETER_VALUE_EMPTY;

    /// The claim that keeps this subject separate from `parameter`: an
    /// `ext-value` is not a `parameter-value`, so the two productions'
    /// defects are two ids even where a field writes both.
    /// The two entries this subject carries are two claims about one value,
    /// and the split is only honest while their evidence differs: the
    /// production for one, the sentence addressed to the producer for the
    /// other. Both cite § 3.2.1, so the sentences are what has to differ.
    #[test]
    fn the_grammar_and_the_producer_are_two_claims() {
        assert_eq!(EXT_VALUE_MALFORMED.strength, Strength::Grammar);
        assert_eq!(EXT_VALUE_CHARSET_FORBIDDEN.strength, Strength::Must);
    }

    #[test]
    fn an_ext_value_is_not_a_parameter_value() {
        let [ext] = EXT_VALUE_MALFORMED.spec else {
            panic!("one sentence")
        };
        let [plain] = PARAMETER_VALUE_EMPTY.spec else {
            panic!("one sentence")
        };
        assert_ne!(ext.spec, plain.spec);
    }
}
