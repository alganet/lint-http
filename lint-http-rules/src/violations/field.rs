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
        spec: Some(RFC_9110_5_3),
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
    /// **This is the first entry in the catalogue with no `spec`, whose
    /// sentence exists.** The requirement is stated once per version — RFC 9113
    /// § 8.2.2 for HTTP/2, RFC 9114 § 4.2 for HTTP/3 — and the two are not
    /// copies of one another: HTTP/2 closes the list of names in the sentence
    /// after its MUST NOT, HTTP/3 enumerates nothing and defers to RFC 9110
    /// § 7.6.1, whose own list is open. A `ViolationDef` carries one `SpecRef`,
    /// so naming either document here would put an HTTP/2 citation on an HTTP/3
    /// finding half the time — the wrong-document trap, arrived at from the
    /// other side. **The defect is one and the sentence is two**, so the
    /// citation stays where the version is known: at the rule's sites, and in
    /// the finding's own message, which names the governing section.
    ///
    /// Splitting the entry per version was the alternative and it is refused:
    /// an operator silencing this is silencing a defect, not a document, and
    /// two ids for one defect is the duplication this whole campaign exists to
    /// remove.
    FIELD_CONNECTION_SPECIFIC_FORBIDDEN = {
        id: "field_connection_specific_forbidden",
        title: "A connection-specific field is written on a version that has none",
        message: "",
        default_severity: Severity::Error,
        spec: None,
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
        spec: Some(RFC_9110_5_1),
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
        assert_eq!(FIELD_LINE_DUPLICATED.spec, Some(RFC_9110_5_3));
    }

    /// The entry with no sentence of its own, and the reason is that it has
    /// two: one per version document. Pinned so that a later commit adding a
    /// citation here has to answer which version's finding it would be wrong
    /// for.
    #[test]
    fn the_requirement_written_once_per_version_carries_no_single_spec() {
        assert_eq!(
            FIELD_CONNECTION_SPECIFIC_FORBIDDEN.id,
            "field_connection_specific_forbidden"
        );
        assert_eq!(FIELD_CONNECTION_SPECIFIC_FORBIDDEN.spec, None);
        assert_eq!(
            FIELD_CONNECTION_SPECIFIC_FORBIDDEN.default_severity,
            Severity::Error
        );
    }
}
