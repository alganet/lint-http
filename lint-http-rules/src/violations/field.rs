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

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

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
}
