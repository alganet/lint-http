// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! OAuth 2.0 authorization-code defects — the `state` parameter, and the
//! binding it exists to make.
//!
//! **A subject about a query parameter rather than a field**, which is a first
//! for this catalogue: `state` travels in the authorization request's query
//! string and back in the redirect, and no HTTP field carries it. What makes it
//! a subject anyway is what an operator does with the report — the two ends of
//! one flow, configured together.
//!
//! **The basis is § 10.12 and not § 4.1.1**, which is worth stating because the
//! obvious reading undersells it: § 4.1.1 lists `state` as RECOMMENDED, and a
//! rule resting there would be enforcing a recommendation. § 10.12 makes CSRF
//! protection on the redirection URI a MUST and names `state` as the mechanism
//! for it, so what these entries report is a MUST missed through the vehicle
//! the document itself picked.
//!
//! **Every entry here is bounded by what a capture holds.** The correlation
//! entry looks back through this client's history for the request a callback
//! answers, so a capture that begins mid-flow has the callback and not the
//! request — which is a limit of the recording rather than a verdict, and the
//! reason nothing in this subject outranks `warn`.
//
// cite(RFC 6749 § 10.12): "The client MUST implement CSRF protection for its redirection URI."

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The authorization request: what `response_type` must be, and the parameter
/// that carries the binding.
pub const RFC_6749_4_1_1: SpecRef = SpecRef {
    spec: "RFC 6749",
    section: Some("4.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1",
    note:
        "Authorization Request — response_type MUST be \"code\"; the state parameter is RECOMMENDED",
};

/// The authorization response: the code, and the exactness required of the
/// state echoed beside it.
pub const RFC_6749_4_1_2: SpecRef = SpecRef {
    spec: "RFC 6749",
    section: Some("4.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2",
    note: "Authorization Response — the callback carries the code, and echoes the exact state if the request had one",
};

/// Cross-site request forgery: the MUST these entries rest on, and the sentence
/// naming `state` as how it is met.
pub const RFC_6749_10_12: SpecRef = SpecRef {
    spec: "RFC 6749",
    section: Some("10.12"),
    url: "https://www.rfc-editor.org/rfc/rfc6749.html#section-10.12",
    note: "Cross-Site Request Forgery — the client MUST implement CSRF protection for its redirection URI and SHOULD use the state parameter for it (the basis for every entry in this subject)",
};

defects! {
    /// An authorization request with `response_type=code` and no usable
    /// `state`: the parameter absent, or present and empty.
    ///
    /// **The client has started a flow it cannot later recognise.** Whatever
    /// comes back to the redirection URI will carry no value to match, so the
    /// binding § 10.12 requires cannot be made afterwards by anyone.
    ///
    /// **Empty counts as absent, and the parameter's purpose is why**: an
    /// opaque value that is the empty string is one every attacker can also
    /// produce, so it distinguishes nothing.
    ///
    /// `_missing` and not `_empty`, which is a deliberate exception to the
    /// split this catalogue usually draws: the two senders are the same client
    /// making the same omission, and there is no separate repair for having
    /// written `state=` rather than nothing.
    ///
    // cite(RFC 6749 § 10.12): "The client SHOULD utilize the "state" request parameter to deliver this value"
    OAUTH2_REQUEST_STATE_MISSING = {
        id: "oauth2_request_state_missing",
        title: "An authorization request carries no state to bind against",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6749_10_12],
        strength: Strength::Should,
    }

    /// A callback carrying an authorization `code` and no usable `state`.
    ///
    /// **The mirror of [`OAUTH2_REQUEST_STATE_MISSING`], and two entries
    /// because the parties are two.** There a client omitted the value at the
    /// start of the flow; here a value arrives at the redirection URI with
    /// nothing to check, which is what an attacker's forged callback looks like
    /// from the outside. An operator chasing the first reads the client's
    /// authorization request builder, and one chasing this reads what the
    /// authorization server sent back.
    ///
    // cite(RFC 6749 § 4.1.2): "REQUIRED if the "state" parameter was present in the client authorization request.  The exact value received from the client."
    OAUTH2_CALLBACK_STATE_MISSING = {
        id: "oauth2_callback_state_missing",
        title: "An authorization callback carries a code and no state",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_6749_4_1_2],
        strength: Strength::Must,
    }

    /// A callback whose `state` matches no authorization request this client
    /// was seen to make.
    ///
    /// **`_conflicting` because the sentence is about exactness.** § 4.1.2 asks
    /// for the exact value received from the client, so a callback and the
    /// request it claims to answer are two things that must agree — and here
    /// there is no request they agree on. It is not `_unsolicited`: that ending
    /// is for a message answering a question nobody asked, and the question was
    /// asked, by somebody.
    ///
    /// **The strongest evidence in this subject and still `warn`**, because the
    /// evidence is a *reconstruction*: the correlation walks this client's
    /// captured history, so a recording that begins after the authorization
    /// request produces this finding about a flow that was entirely correct.
    /// The limit is the capture's and the entry does not pretend otherwise.
    ///
    // cite(RFC 6749 § 4.1.1): "RECOMMENDED.  An opaque value used by the client to maintain state between the request and callback."
    OAUTH2_STATE_CONFLICTING = {
        id: "oauth2_state_conflicting",
        title: "A callback's state matches no request that was seen",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6749_4_1_1],
        strength: Strength::Unstated,
    }
}
