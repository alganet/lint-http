// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `field` defects — what is wrong with a field *line* rather than with the
//! value written on it.
//!
//! **The first subject in this catalogue that is not a production.** Every
//! other one is a grammar somebody wrote down — a `token`, an `http_date`, a
//! `uri` — and the defect is a value that does not derive from it. This one is
//! a sentence about the *shape of a message*: RFC 9110 § 5.3 forbids a sender
//! from writing two field lines of one name unless that field's definition has
//! a comma-separated-list alternative, and a message breaking it carries values
//! that are each perfectly well formed.
//!
//! That is why it is shared as widely as it is. **Nineteen rules in this tree
//! report a repeated field line**, one field apiece, in nineteen wordings of one
//! sentence — and `singleton_fields_not_repeated` reports it for
//! sixteen more fields that have no rule of their own. The spread is
//! deliberate: that rule's own prose says eight singleton fields are left to the
//! rules that read their values, "with the joined value in the finding". So the
//! sentence was always one claim reported from many places, which is the
//! definition of a subject in this campaign.
//!
//! **What it is not.** It is not "this field appeared twice" as a matter of
//! counting: `#`-list fields are *meant* to arrive on several lines, and § 5.3's
//! own exception says so. The defect is a repetition the field's definition does
//! not admit, so every declarer is a rule that has read that definition — which
//! is also why no gate can find the next declarer for you.
//!
//! The second entry is the same kind of claim about the same object: a field
//! line that is there and should not be, because the version carrying it has no
//! use for the hop-by-hop control the field states. The third is the name on
//! that line being one nobody here expects. **No entry in this subject ever
//! reads a value** — which is what makes it a subject rather than a drawer.
//!
//! **The last two are the same claim about a direction rather than a version.**
//! RFC 9110 § 10 sorts nine fields into the ones that say something about a
//! request and the ones that say something about a response, and a sender that
//! writes one in the other direction has written a line that states nothing
//! where it landed. No sentence in either section forbids it — the split is how
//! the document says what each field is *about*, not a prohibition — so both
//! entries are `info`, and the word for them is neither `_forbidden` nor
//! `_invalid`. They are two entries rather than one because the senders are
//! two: a client leaking a server's field and a server echoing a client's are
//! different mistakes with different fixes. **Being two sentences is no longer
//! part of that argument** — the entry above them holds two — and what is left
//! is the only reason that was ever load-bearing.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Where field names are defined: case-insensitive, and ought to be
/// registered.
pub const RFC_9110_5_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1",
    note: "Field Names (case-insensitive, and registration is an \"ought to\"; the same paragraph makes a proxy forward what it does not recognize)",
};

/// The MUST NOT, its exception, and the recombination that makes the exception
/// the whole of the difference.
pub const RFC_9110_5_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("5.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3",
    note: "Field Order — a sender MUST NOT write multiple field lines of one name, in the \
           headers or the trailers, unless at least one alternative of the field's definition \
           allows the lines to be recombined as a comma-separated list",
};

/// HTTP/2's prohibition on connection-specific fields, and one half of the
/// pair [`FIELD_CONNECTION_SPECIFIC_FORBIDDEN`] holds. It lives here rather
/// than in the rule because the entry names it, and an entry's references are
/// the catalogue's.
pub const RFC_9113_8_2_2: SpecRef = SpecRef {
    spec: "RFC 9113",
    section: Some("8.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2",
    note: "Connection-Specific Header Fields — HTTP/2's prohibition, and the one \
           sentence of the two that closes the list of names",
};

/// The other half, and the reason the pair exists: HTTP/3 states the same
/// requirement in its own document, enumerating nothing.
pub const RFC_9114_4_2: SpecRef = SpecRef {
    spec: "RFC 9114",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2",
    note: "HTTP Fields — HTTP/3's prohibition, which enumerates nothing and defers \
           to RFC 9110 §7.6.1",
};

/// The request context fields, and what the section says they are about. The
/// half of § 10 that a response has no use for.
pub const RFC_9110_10_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("10.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1",
    note: "Request Context Fields — the five fields whose subjects are the user, user agent and resource behind a request; the section split the direction is read from",
};

/// The other half, and the same silence: neither section attaches a keyword to
/// a field arriving in the direction it does not describe.
pub const RFC_9110_10_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("10.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2",
    note: "Response Context Fields — the four whose subjects are the server, the target resource and related resources. No sentence in either section forbids the misdirection, which is why both entries are advice",
};

defects! {
    /// More field lines of one name than the field's definition admits.
    ///
    /// The values on them may each be well formed; what is wrong is that there
    /// are two. A recipient recombining them by § 5.3's rule gets one value the
    /// sender never wrote — `Content-Type: text/html` twice becomes
    /// `text/html, text/html`, which is not a `media-type` — and a recipient
    /// that takes the first, or the last, silently obeys one of two
    /// instructions.
    ///
    /// `warn` rather than `error`: every value is legible and most recipients
    /// resolve the ambiguity the same way, so this is a sender defect a
    /// deployment can carry rather than a message a recipient must reject.
    /// Where a document says otherwise about its own field — `Content-Length`'s
    /// framing, for one — the rule reading that field says so at its own site.
    ///
    // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
    FIELD_LINE_DUPLICATED = {
        id: "field_line_duplicated",
        title: "A field is written on more lines than its definition allows",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_5_3],
    }

    /// A field stating hop-by-hop control — `Connection` and the fields it
    /// governs, `TE` among them where no exception restores it — written into a
    /// field section carried by a version that conveys such metadata by other
    /// means. Presence is the whole defect: both documents call the message
    /// malformed without anyone reading the value.
    ///
    /// `error`, because malformed is the word the documents use and a recipient
    /// is entitled to reject the message rather than repair it.
    ///
    /// **This is the entry that made `spec` a slice.** The requirement is
    /// stated once per version — RFC 9113 § 8.2.2 for HTTP/2, RFC 9114 § 4.2
    /// for HTTP/3 — and the two are not copies of one another: HTTP/2 closes
    /// the list of names in the sentence after its MUST NOT, HTTP/3 enumerates
    /// nothing and defers to RFC 9110 § 7.6.1, whose own list is open. Naming
    /// either one alone would put an HTTP/2 citation on an HTTP/3 finding half
    /// the time — the wrong-document trap, arrived at from the other side.
    /// **The defect is one and the sentence is two**, so the entry holds both
    /// and no finding carries either: the version is known at the rule's sites,
    /// and the message names the governing section there.
    ///
    /// Splitting the entry per version was the alternative and it is refused:
    /// an operator silencing this is silencing a defect, not a document, and
    /// two ids for one defect is the duplication this whole campaign exists to
    /// remove.
    ///
    // cite(RFC 9113 § 8.2.2): "An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields."
    // cite(RFC 9113 § 8.2.2): "Any message containing connection-specific header fields MUST be treated as malformed (Section 8.1.1)."
    // cite(RFC 9114 § 4.2): "An endpoint MUST NOT generate an HTTP/3 field section containing connection-specific fields; any message containing connection-specific fields MUST be treated as malformed."
    FIELD_CONNECTION_SPECIFIC_FORBIDDEN = {
        id: "field_connection_specific_forbidden",
        title: "A connection-specific field is written on a version that has none",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9113_8_2_2, RFC_9114_4_2],
    }

    /// A field name the deployment does not expect. The seventh registry entry
    /// of the catalogue and the widest: every other one asks about a name
    /// inside a value, and this one asks about the name of the line itself.
    ///
    /// **The weakest reading in the family, and deliberately so.** § 5.1 says
    /// names *ought to* be registered, and the same paragraph tells a proxy to
    /// forward what it does not recognise and every other recipient to ignore
    /// it — so an unknown field is the extension mechanism working, not a
    /// message defect. What the finding buys is the inventory: a deployment
    /// that has written down the fields it expects gets told when something
    /// else appears, which is a question about that deployment and answerable
    /// by nothing else here.
    ///
    /// `warn`, and the comparison folds no case at the reading end because it
    /// cannot: every parser this crate reads through has already lowercased the
    /// name, and HTTP/3 makes an uppercase one malformed outright.
    ///
    // cite(RFC 9110 § 5.1): "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry""
    FIELD_NAME_UNREGISTERED = {
        id: "field_name_unregistered",
        title: "Field name is not one the deployment expects",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_5_1],
    }

    /// One of § 10.1's five request context fields — `Expect`, `From`,
    /// `Referer`, `TE`, `User-Agent` — written into a response. Each of them is
    /// defined as a fact about the request's side of the exchange: who the user
    /// is, what the user agent is, where the target URI came from, what the
    /// client can accept. A server writing one states none of those things
    /// about itself; it writes a line with no subject.
    ///
    /// **`info`, and the reason is the absence of a modal rather than a
    /// judgment about how much it matters.** § 10.1 says what the fields are
    /// for and stops. Nothing forbids the arrival, so `_forbidden` would invent
    /// a prohibition and `_invalid` would condemn a value that is perfectly
    /// well formed — the line is legible, and what is wrong is that it landed
    /// where its definition says nothing.
    ///
    // cite(RFC 9110 § 10.1): "The request header fields below provide additional information about the request context, including information about the user, user agent, and resource behind the request."
    FIELD_REQUEST_CONTEXT_MISDIRECTED = {
        id: "field_request_context_misdirected",
        title: "A request context field is written in a response",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_10_1],
    }

    /// The mirror: one of § 10.2's four response context fields — `Allow`,
    /// `Location`, `Retry-After`, `Server` — written into a request. Same
    /// reading, opposite sender, and the same absent modal.
    ///
    /// A separate entry rather than a shared one, and the reason is the
    /// sender. An operator watching what its own clients emit is watching this
    /// entry and not its sibling, and the fix for each is somewhere else. The
    /// two sections *would* both fit on one entry now that `spec` is a slice —
    /// which is exactly why the shape is worth stating: a pair of sentences is
    /// a reason to hold two references, never on its own a reason to hold two
    /// ids.
    ///
    // cite(RFC 9110 § 10.2): "The response header fields below provide additional information about the response, beyond what is implied by the status code, including information about the server, about the target resource, or about related resources."
    FIELD_RESPONSE_CONTEXT_MISDIRECTED = {
        id: "field_response_context_misdirected",
        title: "A response context field is written in a request",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_10_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One entry, and the shape of the id is the argument for it: the subject
    /// is `field`, the part is the `line`, and the defect is that there is more
    /// than one of them. Nothing here narrows to a field name — a def naming
    /// the field that noticed the defect is the campaign's own recorded error.
    #[test]
    fn the_subject_is_the_line_and_not_the_field_that_carried_it() {
        assert_eq!(FIELD_LINE_DUPLICATED.id, "field_line_duplicated");
        assert_eq!(FIELD_LINE_DUPLICATED.default_severity, Severity::Warn);
        assert_eq!(FIELD_LINE_DUPLICATED.spec, [RFC_9110_5_3]);
    }

    /// The entry with two sentences and no one of them governing. Pinned in
    /// both directions: dropping either reference would leave the survivor
    /// looking like *the* sentence, and a finding would then start carrying it
    /// — which is wrong on every message the other document governs.
    #[test]
    fn the_requirement_written_once_per_version_names_both_documents() {
        assert_eq!(
            FIELD_CONNECTION_SPECIFIC_FORBIDDEN.id,
            "field_connection_specific_forbidden"
        );
        assert_eq!(
            FIELD_CONNECTION_SPECIFIC_FORBIDDEN.spec,
            [RFC_9113_8_2_2, RFC_9114_4_2]
        );
        assert_eq!(
            FIELD_CONNECTION_SPECIFIC_FORBIDDEN.default_severity,
            Severity::Error
        );
    }
}
