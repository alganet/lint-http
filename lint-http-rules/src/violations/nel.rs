// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `NEL` defects — the four ways a network error logging policy is discarded
//! whole.
//!
//! **Every entry here costs the entire policy, and that is § 4.2's doing.** The
//! algorithm is a sequence of *abort these steps*: one member of the wrong type
//! and the user agent registers nothing at all, so the origin's error reporting
//! is off and no report says so. That is the same harm
//! [`structured_fields`](crate::violations::structured_fields) states for a
//! field a Structured Fields parse refuses, and the wording here is deliberately
//! its sibling — the finding is not that a member is wrong, it is that the
//! policy is gone.
//!
//! **The field's syntax is not this document's.** § 4.2 hands parsing to
//! Section 4 of HTTP-JFV, which combines the field lines, wraps them in `[` and
//! `]` and runs a JSON parser over the result — so the value is a *list* of
//! objects and only the first is read, and a bare object is that list with one
//! element. `nel_malformed` is that step's failure and carries `Grammar`; the
//! other three quote a `MUST` or a `REQUIRED` of NEL's own and carry `Must`.
//! Both land at `error`, and the split records which evidence each rests on.
//!
//! **`max_age` of 0 is not a defective policy but a withdrawal**, and it is why
//! `nel_report_to_missing` is conditional. § 4.2 removes any cached policy for
//! the origin at that point and *skips the remaining steps*, so the member
//! § 4.1.1 calls REQUIRED is expressly optional there — its own sentence says
//! so, "OPTIONAL if the intent is to remove a previous registration".
//!
//! **One member has no entry at all.** § 4.1.3 says a value of
//! `include_subdomains` that is not `true` simply does not enable the policy
//! for subdomains; no step aborts on it and nothing is discarded, so a
//! non-boolean there is not a finding however wrong it looks beside the others.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field's own production, and the two sentences that bound what an array
/// element has to be.
pub const NEL_4_1: SpecRef = SpecRef {
    spec: "Network Error Logging",
    section: Some("4.1"),
    url: "https://www.w3.org/TR/network-error-logging/#nel-response-header",
    note: "NEL response header — `NEL = json-field-value`, the array of JSON objects it is interpreted as, and the MUST that a valid field carries one object with every REQUIRED member",
};

/// The header, and the parse it defers to another document for.
pub const NEL_4_2: SpecRef = SpecRef {
    spec: "Network Error Logging",
    section: Some("4.2"),
    url: "https://www.w3.org/TR/network-error-logging/#process-policy-headers",
    note: "Process policy headers — the sequence of *abort these steps* that makes any one of these defects cost the whole policy, and the `max_age` of 0 that removes it and skips the rest",
};

/// `report_to`: required to register a policy, optional to remove one.
pub const NEL_4_1_1: SpecRef = SpecRef {
    spec: "Network Error Logging",
    section: Some("4.1.1"),
    url: "https://www.w3.org/TR/network-error-logging/#the-report_to-member",
    note: "The report_to member — REQUIRED to register a NEL policy, OPTIONAL to remove one, and a MUST that its value is a string",
};

/// `max_age`: required, a non-negative integer, and 0 means remove.
pub const NEL_4_1_2: SpecRef = SpecRef {
    spec: "Network Error Logging",
    section: Some("4.1.2"),
    url: "https://www.w3.org/TR/network-error-logging/#the-max_age-member",
    note: "The max_age member — REQUIRED, a MUST that its value is a non-negative integer, and the 0 that removes the policy",
};

/// The two sampling rates, and the closed interval their values live in.
pub const NEL_4_1_4: SpecRef = SpecRef {
    spec: "Network Error Logging",
    section: Some("4.1.4"),
    url: "https://www.w3.org/TR/network-error-logging/#the-success_fraction-member",
    note: "The success_fraction member — a MUST that its value is a number between 0.0 and 1.0 inclusive, \"any other value will result in a parse error\"",
};

/// The other sampling rate, written in the same words.
pub const NEL_4_1_5: SpecRef = SpecRef {
    spec: "Network Error Logging",
    section: Some("4.1.5"),
    url: "https://www.w3.org/TR/network-error-logging/#the-failure_fraction-member",
    note:
        "The failure_fraction member — the same MUST as success_fraction, for the other direction",
};

/// The two header-name lists a report may carry.
pub const NEL_4_1_6: SpecRef = SpecRef {
    spec: "Network Error Logging",
    section: Some("4.1.6"),
    url: "https://www.w3.org/TR/network-error-logging/#the-request_headers-member",
    note: "The request_headers member — a MUST that its value is a list of strings; `response_headers` in § 4.1.7 is the same sentence",
};

/// Where the field's syntax actually lives, pinned to the revision NEL names.
pub const JFV_4: SpecRef = SpecRef {
    spec: "draft-reschke-http-jfv-07",
    section: Some("4"),
    url: "https://datatracker.ietf.org/doc/html/draft-reschke-http-jfv-07#section-4",
    note: "Recipient Requirements — combine the field lines, add a leading \"[\" and a trailing \"]\", run a JSON parser; pinned to -07 because the unversioned draft is now a stub with no § 4 in it",
};

defects! {
    /// A `NEL` field value that does not parse as HTTP-JFV's list of JSON
    /// objects, or that parses to an empty list.
    ///
    /// **The whole policy goes, not the malformed part.** § 4.2's third step
    /// aborts on a parse error or an empty list, before any member is looked
    /// at, so the origin registers no network error logging at all and the
    /// response that carried the field is indistinguishable from one that
    /// never had it.
    ///
    /// **What a real origin gets wrong is the string delimiter**: JSON writes
    /// a string with DQUOTE and an apostrophe starts nothing, so
    /// `{'report_to':'default'}` is refused entire. That is the same mistake
    /// `structured_field_malformed` reports on `Reporting-Endpoints`, in the
    /// same corner of the same deployments.
    ///
    /// **A list of two is not this defect.** § 4 wraps the value in brackets,
    /// so the comma form is a well-formed list; § 4.2 reads its first element
    /// and ignores the rest, which is a policy that says less than its author
    /// meant and not a value a recipient refuses.
    ///
    /// `Grammar`, and the production is NEL's own: § 4.1 writes
    /// `NEL = json-field-value` and says the value is interpreted as an array
    /// of JSON objects. A value that survives neither derives from that
    /// production, and the delegated algorithm below is how it is decided.
    ///
    // cite(Network Error Logging § 4.1, label: NEL grammar): "NEL = json-field-value"
    // cite(Network Error Logging § 4.1): "The header's value is interpreted as an array of JSON objects, as defined"
    // cite(Network Error Logging § 4.2): "Let list be the result of executing the algorithm defined in Section 4 of [HTTP-JFV] on header. If that algorithm results in an error, or if list is empty, abort these steps."
    // cite(draft-reschke-http-jfv-07 § 4): "add a leading begin-array ("[") octet and a trailing end-array ("]") octet, then"
    NEL_MALFORMED = {
        id: "nel_malformed",
        title: "NEL does not parse, so the origin registers no policy",
        message: "",
        default_severity: Severity::Error,
        spec: &[NEL_4_1, NEL_4_2, JFV_4],
        strength: Strength::Grammar,
    }

    /// A `NEL` policy object with no `max_age` member.
    ///
    /// § 4.1.2 calls it REQUIRED and § 4.2 aborts where it is absent, so a
    /// policy without it is not a policy with a default lifetime — it is no
    /// policy.
    ///
    /// **Absence only.** A `max_age` a sender wrote and got wrong is
    /// [`NEL_MEMBER_INVALID`], because this entry's title is a claim about the
    /// value and a member that is present contradicts it.
    ///
    // cite(Network Error Logging § 4.2): "If item has no member named max_age, or that member's value is not a number, abort these steps."
    // cite(Network Error Logging § 4.1.2): "The REQUIRED max_age member specifies the"
    NEL_MAX_AGE_MISSING = {
        id: "nel_max_age_missing",
        title: "NEL states no max_age, and the policy is discarded",
        message: "",
        default_severity: Severity::Error,
        spec: &[NEL_4_1_2, NEL_4_2],
        strength: Strength::Must,
    }

    /// A `NEL` policy that registers a lifetime and names no endpoint group to
    /// send reports to.
    ///
    /// **Conditional on `max_age`, and the condition is the whole entry.**
    /// § 4.2 removes any cached policy for the origin when `max_age` is 0 and
    /// skips every remaining step, so nothing asks for `report_to` there —
    /// § 4.1.1 says as much in its own sentence, REQUIRED to register and
    /// OPTIONAL to remove. Asking unconditionally would report the documented
    /// way to withdraw a policy.
    ///
    /// **Absence only**, for [`NEL_MAX_AGE_MISSING`]'s reason.
    ///
    // cite(Network Error Logging § 4.2): "If item has no member named report_to, or that member's value is not a string, abort these steps."
    // cite(Network Error Logging § 4.1.1): "The report_to member is REQUIRED to register a NEL policy,"
    NEL_REPORT_TO_MISSING = {
        id: "nel_report_to_missing",
        title: "NEL registers a policy and names no endpoint group",
        message: "",
        default_severity: Severity::Error,
        spec: &[NEL_4_1_1, NEL_4_2],
        strength: Strength::Must,
    }

    /// A `NEL` member a sender wrote whose value is not what its own section
    /// requires — a `max_age` that is not a non-negative integer, a
    /// `report_to` that is not a string, a sampling fraction outside the
    /// closed interval `0.0` to `1.0`, or a header list that is not a list of
    /// strings.
    ///
    /// **One entry, because there is one repair**: give the member the value
    /// its definition prints. The message names which member and what it
    /// should have been, which is the half only the reading knows — the same
    /// division `structured_field_malformed` makes, and the reason that entry
    /// is one id for every way a Structured Field can fail.
    ///
    /// **Separate from the two `_missing` entries beside it, and that is not
    /// tidiness.** A `_missing` id is a claim about the value: told about a
    /// `max_age` of `-1`, it would name a member the sender did write and send
    /// its reader looking for an absence that is not there.
    ///
    /// **`max_age` is stricter here than the recipient's algorithm is.** § 4.2
    /// aborts only where the value "is not a number", which `1.5` is; § 4.1.2
    /// binds the *sender* to a non-negative integer, and it is the sender this
    /// catalogue reports. A fraction of a second of policy lifetime is a value
    /// no user agent was promised.
    ///
    // cite(Network Error Logging § 4.1.2): "Its value MUST be an non-negative integer; any other type will result in a parse error."
    // cite(Network Error Logging § 4.1.1): "If present, its value MUST be a string; any other type will result in a parse error."
    // cite(Network Error Logging § 4.1.4): "its value MUST be a number between 0.0 and"
    // cite(Network Error Logging § 4.1.6): "about this origin. If present, its value MUST be a list of"
    NEL_MEMBER_INVALID = {
        id: "nel_member_invalid",
        title: "A NEL member carries a value its definition refuses",
        message: "",
        default_severity: Severity::Error,
        spec: &[NEL_4_1_1, NEL_4_1_2, NEL_4_1_4, NEL_4_1_5, NEL_4_1_6, NEL_4_2],
        strength: Strength::Must,
    }
}
