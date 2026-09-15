// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Refresh` defects — a delay, and the URL it may carry.
//!
//! **A field subject whose grammar lives in another organisation's document.**
//! `Refresh` is HTML's, not HTTP's: the field is three sentences in the
//! speculative-loading section saying it is the `meta` pragma's HTTP
//! equivalent, that it takes the same value, and that its processing model is
//! elsewhere. The only sentence anywhere saying what a *conforming* value looks
//! like is the authoring requirement written for the pragma's content
//! attribute, and these entries answer to it.
//!
//! **Which is why the processing model is not the measure.** That model reads
//! values the authoring requirement refuses — a quoted URL parses and is
//! silently truncated at its closing quote — so a reader that judged what a
//! browser *does* would report nothing at all and let the sender lose the tail
//! of its URL without a word.
//!
//! **The URL's alphabet is the URL Standard's and not RFC 3986's**, which is
//! the other place this subject leaves HTTP behind: a relative reference is a
//! conforming value, so nothing here asks for a scheme.
//
// cite(HTML Speculative Loading § 7.8): "It takes the same value and works largely the same."

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The authoring conformance requirement: the two forms a value may take, and
/// the prohibition on opening the URL with a quote.
pub const HTML_SEMANTICS_4_2_5_3: SpecRef = SpecRef {
    spec: "HTML Semantics",
    section: Some("4.2.5.3"),
    url: "https://html.spec.whatwg.org/multipage/semantics.html#attr-meta-http-equiv-refresh",
    note: "Refresh state: the shared declarative refresh steps, and the authoring conformance requirement this subject enforces — the only sentence in HTML that says what a conforming value looks like",
};

/// What a valid URL string is, in the standard that defines the alphabet this
/// value's URL is written in.
pub const URL_4_3: SpecRef = SpecRef {
    spec: "URL",
    section: Some("4.3"),
    url: "https://url.spec.whatwg.org/#url-writing",
    note: "URL writing: valid URL string, URL code points and URL units — the alphabet the `URL=` value is judged against, which is not RFC 3986's",
};

defects! {
    /// A value that is neither of the two forms the requirement admits: a delay
    /// that is not one or more ASCII digits, a `;` with nothing after it, a `;`
    /// not followed by whitespace, or a parameter that is not `URL=`.
    ///
    /// **One entry for the structure, because the requirement is one
    /// sentence** — a valid non-negative integer, or that integer followed by
    /// `;`, whitespace, `URL=` and a URL — and every way of missing it leaves
    /// the same repair: write one of the two forms. The message names the part
    /// that did not derive.
    ///
    /// **The delay is `1*DIGIT` and nothing more**, which is worth saying
    /// because the obvious reading is wrong: a parse into an integer accepts a
    /// leading `+`, and a valid non-negative integer does not.
    ///
    /// `warn`. Nothing else in the response is affected, and what is lost is
    /// the refresh the sender asked for.
    ///
    // cite(HTML Semantics § 4.2.5.3): "For meta elements with an http-equiv attribute in the Refresh state, the content attribute must have a value consisting either of:"
    REFRESH_VALUE_MALFORMED = {
        id: "refresh_value_malformed",
        title: "A Refresh value is neither of the two forms",
        message: "",
        default_severity: Severity::Warn,
        spec: &[HTML_SEMANTICS_4_2_5_3],
    }

    /// `URL=` with nothing after it.
    ///
    /// The structure derived — a delay, a `;`, whitespace and the one parameter
    /// name the form admits — and then the slot the whole second form exists
    /// for was left blank. `_empty` against
    /// [`REFRESH_VALUE_MALFORMED`]'s `_malformed` for the reason this catalogue
    /// always splits the two: a sender that wrote the thing and put nothing in
    /// it is not the sender that wrote it wrong.
    ///
    /// `warn`, with the rest.
    ///
    // cite(HTML Semantics § 4.2.5.3): "For meta elements with an http-equiv attribute in the Refresh state, the content attribute must have a value consisting either of:"
    REFRESH_URL_EMPTY = {
        id: "refresh_url_empty",
        title: "A Refresh value writes URL= with no URL",
        message: "",
        default_severity: Severity::Warn,
        spec: &[HTML_SEMANTICS_4_2_5_3],
    }

    /// A URL after `URL=` that is not a valid URL string: one opening with an
    /// apostrophe or a quotation mark, or one holding a code point URL units do
    /// not admit.
    ///
    /// **The quote is the case worth knowing, and it is the one the processing
    /// model hides.** A quoted URL parses: the model truncates the string at
    /// the matching quote and refreshes to what came before it, so a sender
    /// that wrote `URL='/a?b=c'` loses everything from the second quote onward
    /// and gets a redirect to somewhere it did not name. The authoring
    /// requirement refuses the leading quote for exactly this reason, and a
    /// reader measuring what a browser *does* would say nothing.
    ///
    /// **The alphabet is the URL Standard's**, so a relative reference is
    /// conforming and nothing here asks for a scheme: `1http://example/` names
    /// no scheme and is an ordinary relative path.
    ///
    /// `warn`, with the rest of the subject.
    ///
    // cite(URL § 4.3): "A valid URL string must be either a relative-URL-with-fragment string or an absolute-URL-with-fragment string."
    REFRESH_URL_MALFORMED = {
        id: "refresh_url_malformed",
        title: "A Refresh URL is not a valid URL string",
        message: "",
        default_severity: Severity::Warn,
        spec: &[URL_4_3],
    }
}
