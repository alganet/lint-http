// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Report-To` defects — the endpoint groups a response declares, in the field
//! that used to declare them.
//!
//! **No specification defines this field any more, and that is the subject.**
//! The W3C Reporting API defined `Report-To`; the document at that same URL now
//! defines `Reporting-Endpoints` and does not contain the string `Report-To`
//! anywhere. So there is neither a current specification to read the field
//! against nor a superseded one saying what replaced it, and the one document
//! that says both is MDN's page for it. That is the same footing
//! [`x_xss_protection`](crate::violations::x_xss_protection) stands on: a field
//! deployments still send in quantity and no standards document defines.
//!
//! **The syntax is HTTP-JFV, and it is `NEL`'s syntax.** MDN writes the value
//! as "a JSON array that omits the surrounding `[` and `]` markers", which is
//! the production [`nel`](crate::violations::nel) already reads through
//! [`JFV_4`](crate::violations::nel::JFV_4) — combine the field lines, bracket
//! the result, run a JSON parser. The two fields are not merely alike here:
//! they are written by the same deployments, in the same response, for the same
//! reporting pipeline, and the delimiter mistake that discards one discards the
//! other.
//!
//! **Two entries and no third.** MDN names `group`, `max_age` and `endpoints`
//! and marks none of them required; the draft that did state requirements is a
//! snapshot the W3C has replaced. An entry resting on that snapshot would claim
//! a requirement no document in force states, so what is read here is the parse
//! and nothing below it.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The one page that still describes the field: that it has been replaced,
/// what it was for, and the shape of its value.
pub const MDN_REPORT_TO: SpecRef = SpecRef {
    spec: "MDN Report-To",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Report-To",
    note: "Report-To — a response header marked Deprecated and Non-standard, replaced by `Reporting-Endpoints`, whose value is one or more endpoint-group definitions written as a JSON array with the surrounding brackets omitted",
};

/// The production MDN's `<json-field-value>` placeholder points at.
///
/// [`JFV_4`](crate::violations::nel::JFV_4) — the recipient algorithm — lives
/// beside `NEL`, which was the first field here to defer its syntax to this
/// draft. The grammar itself is declared here because this is the first entry
/// whose evidence *is* the production: `NEL` quotes `NEL = json-field-value`
/// from its own document, and `Report-To` has no document of its own left to
/// quote.
pub const JFV_2: SpecRef = SpecRef {
    spec: "draft-reschke-http-jfv-07",
    section: Some("2"),
    url: "https://datatracker.ietf.org/doc/html/draft-reschke-http-jfv-07#section-2",
    note: "Syntax — `json-field-value = #json-field-item`, the comma-separated list of JSON texts that a field deferring to this draft carries",
};

defects! {
    /// A response carrying `Report-To`.
    ///
    /// **`_obsolete`, the vocabulary's rarest ending, used for exactly what it
    /// names**: a later revision of the specification retired the field. This
    /// is [`pragma_obsolete`](crate::violations::pragma)'s shape read from the
    /// other side of the same fact — `Pragma` was deprecated by the document
    /// that defines it and is still in it, while `Report-To` was removed from
    /// the document outright, so the sentence recording the replacement is
    /// MDN's rather than the specification's.
    ///
    /// **Not `_forbidden`, and the repair is a move rather than a deletion.**
    /// The groups a sender declares here are the ones its `Content-Security-
    /// Policy` `report-to` directive and its `NEL` `report_to` member name, so
    /// telling an origin to drop the field without naming where the groups go
    /// would break the reporting it still has. The finding names
    /// `Reporting-Endpoints` because that is the field the groups move to.
    ///
    /// `info`. A browser that still reads `Report-To` behaves correctly and one
    /// that reads only `Reporting-Endpoints` behaves correctly; nothing is
    /// broken today, and what the sender learns is that the field it is
    /// configuring has no specification left to be right against.
    ///
    // cite(MDN Report-To): "This header has been replaced by the"
    // cite(MDN Report-To): "It is a deprecated part of an earlier iteration of the"
    // cite(MDN Report-To): "allows website administrators to define named groups of endpoints that can be used as the destination for warning and error reports"
    REPORT_TO_OBSOLETE = {
        id: "report_to_obsolete",
        title: "A response declares its endpoint groups in a field that has been replaced",
        message: "",
        default_severity: Severity::Info,
        spec: &[MDN_REPORT_TO],
    }

    /// A `Report-To` field value that does not parse as HTTP-JFV's list of
    /// endpoint-group objects, or that parses to an empty list.
    ///
    /// **Every group in the field goes, not the malformed one.** The value is
    /// one JSON document once bracketed, so a parser that refuses it has
    /// refused the whole array: the origin declares no endpoint group at all,
    /// and every field naming one of those groups — a `Content-Security-Policy`
    /// `report-to` directive, a `NEL` policy's `report_to` — is left pointing
    /// at a name nothing defines. Nothing downstream reports that it did not.
    ///
    /// **What a real origin gets wrong is the string delimiter**, and it gets
    /// it wrong in both fields at once: JSON writes a string with DQUOTE and an
    /// apostrophe starts nothing, so `{'group':'default','max_age':3600}` is
    /// refused entire. [`nel_malformed`](crate::violations::nel) is the same
    /// sentence about the field beside it, and an origin whose templating wrote
    /// one of them with apostrophes wrote both. **That pairing is why this
    /// entry is worth its `error`**: told only about the `NEL`, an operator
    /// repairs the policy and the reports still go nowhere, because the group
    /// the repaired policy names is declared in a field that still does not
    /// parse.
    ///
    /// **A list of two is not this defect.** The brackets make the comma form a
    /// well-formed list, and a response declaring two groups on two field lines
    /// is declaring two groups — the lines are joined before anything parses
    /// them, so reading one line alone would report half an array as a broken
    /// one.
    ///
    /// `Grammar`, and the production is `json-field-value = #json-field-item`.
    /// MDN prints the field's value as `<json-field-value>` and describes it as
    /// a JSON array with its brackets omitted; that placeholder is HTTP-JFV
    /// § 2's rule, and a value surviving neither the list nor the JSON text
    /// derives from it. The algorithm that decides so is § 4's, which is where
    /// `NEL` sends the identical question.
    ///
    // cite(MDN Report-To): "One or more endpoint-group definitions, defined as a JSON array that omits the surrounding"
    // cite(draft-reschke-http-jfv-07 § 2, label: Report-To grammar): "json-field-value = #json-field-item"
    REPORT_TO_MALFORMED = {
        id: "report_to_malformed",
        title: "Report-To does not parse, so none of the endpoint groups it declares exist",
        message: "",
        default_severity: Severity::Error,
        spec: &[MDN_REPORT_TO, JFV_2, crate::violations::nel::JFV_4],
        strength: Strength::Grammar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A field nothing defines any more is not a field anything prohibits: the
    /// entry claims a replacement, not a violation, and is ranked as advice.
    #[test]
    fn the_replacement_entry_claims_no_prohibition() {
        assert!(!REPORT_TO_OBSOLETE.id.ends_with("_forbidden"));
        assert_eq!(REPORT_TO_OBSOLETE.default_severity, Severity::Info);
    }

    /// The value nobody can read outranks the field everybody can: one costs
    /// the groups outright, the other costs the sender a specification.
    #[test]
    fn the_unreadable_value_outranks_the_retired_field() {
        assert!(REPORT_TO_OBSOLETE.default_severity < REPORT_TO_MALFORMED.default_severity);
    }

    /// Both entries are about the field rather than about a member of it, so
    /// neither carries a static message: what each finding says is the value
    /// the response wrote, which only the reading knows.
    #[test]
    fn neither_entry_names_a_value_statically() {
        assert!(REPORT_TO_OBSOLETE.message.is_empty());
        assert!(REPORT_TO_MALFORMED.message.is_empty());
    }

    /// The parse question is the same question `NEL` asks, and it is asked
    /// against the same pinned draft rather than a second copy of it.
    #[test]
    fn the_parse_rests_on_the_production_nel_reads() {
        assert!(REPORT_TO_MALFORMED
            .spec
            .iter()
            .any(|s| s.spec == crate::violations::nel::JFV_4.spec
                && s.url == crate::violations::nel::JFV_4.url));
    }
}
