// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Method-semantics defects — what a method's own definition says a message
//! carrying it may hold.
//!
//! The subject is the method token, which is a protocol element rather than a
//! field: what a method's *spelling* may be is
//! [`token`](crate::violations::token)'s, and what a message's fields say is
//! each field's own. Here are the requirements a method definition puts on the
//! message around it, and the part in each id is the method they belong to.
//!
//! **Two methods so far, and they are opposites in a useful way.** `TRACE`
//! loops the request back, so its definition is two prohibitions on what a
//! client may put in one; `OPTIONS` asks for capabilities, so its definition is
//! a requirement on a client that sends content and a recommendation to a
//! server about what to answer with.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// TRACE: the two client MUST NOTs, and the example naming credentials and
/// cookies.
pub const RFC_9110_9_3_8: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("9.3.8"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.8",
    note: "TRACE — the two client `MUST NOT`s, the example naming credentials and cookies, and the `SHOULD` to reflect the message, which is addressed to a recipient no message identifies",
};

/// OPTIONS: the client MUST about `Content-Type`, and the server SHOULD that
/// names a class of fields rather than a list.
pub const RFC_9110_9_3_7: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("9.3.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.7",
    note: "OPTIONS — the client `MUST` about `Content-Type`, and the `SHOULD` to advertise, which names a class ending \"including potential extensions not defined by this specification\" rather than a field",
};

/// POST: what a status says about a resource the request created, and the
/// SHOULD that names the field carrying its identifier.
pub const RFC_9110_9_3_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("9.3.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.3",
    note: "POST — the SHOULD asking an origin server that created a resource to answer 201 with a Location naming it, which is the sentence that makes a 201 without one a finding",
};

/// HEAD: identical to GET but for the content, with the exception that keeps
/// content-derived fields out of the comparison.
pub const RFC_9110_9_3_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("9.3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2",
    note: "HEAD — the SHOULD to send the same header fields a GET would have carried, and the MAY that excuses fields whose value is determined only while generating the content",
};

/// PATCH: the patch document is identified by a media type, and there is no
/// default format to fall back on.
pub const RFC_5789_2: SpecRef = SpecRef {
    spec: "RFC 5789",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc5789.html#section-2",
    note: "PATCH — the set of changes is represented in a format identified by a media type, and no single default patch document format exists for a recipient to assume",
};

defects! {
    /// Content on a `TRACE` request.
    ///
    /// The prohibition is flat and the reason is the method: a `TRACE` is
    /// looped back, so anything a client puts in one is asking for it to be
    /// returned.
    ///
    // cite(RFC 9110 § 9.3.8): "A client MUST NOT send content in a TRACE request."
    METHOD_TRACE_CONTENT_FORBIDDEN = {
        id: "method_trace_content_forbidden",
        title: "A TRACE request carries content",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_9_3_8],
    }

    /// A field carrying sensitive data on a `TRACE` request — credentials or
    /// cookies, which are the example § 9.3.8 gives.
    ///
    /// **Separate from the entry above although both are § 9.3.8's**, because
    /// the sender's mistake and the repair differ: one put a body on a request
    /// that may not have one, the other put a secret on a request that echoes.
    /// The prohibition is also *not* about a list of field names — it is about
    /// data that might be disclosed by the response — so the entry reports the
    /// two the section names and the message says which was seen.
    ///
    // cite(RFC 9110 § 9.3.8): "A client MUST NOT generate fields in a TRACE request containing sensitive data that might be disclosed by the response."
    METHOD_TRACE_DISCLOSURE_FORBIDDEN = {
        id: "method_trace_disclosure_forbidden",
        title: "A TRACE request carries a field that echoes back a secret",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_9_3_8],
    }

    /// An `OPTIONS` request carrying content with no `Content-Type`.
    ///
    /// The general field entry says a message with content should say what it
    /// is; this one is the method's own MUST, which turns that SHOULD into a
    /// requirement for this method alone — so it is on this subject rather than
    /// [`content_type`](crate::violations::content_type)'s.
    ///
    // cite(RFC 9110 § 9.3.7): "A client that generates an OPTIONS request containing content MUST send a valid Content-Type header field describing the representation media type."
    METHOD_OPTIONS_CONTENT_TYPE_MISSING = {
        id: "method_options_content_type_missing",
        title: "An OPTIONS request carries content without saying what it is",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_9_3_7],
    }

    /// A successful `OPTIONS` response advertising none of the fields a client
    /// asked about.
    ///
    /// **`info`, and the sentence's own shape is the argument.** The SHOULD
    /// names *any header that might indicate optional features*, ending
    /// "including potential extensions not defined by this specification" — a
    /// class, not a list — so a server may be advertising something this rule
    /// does not know to look for. What the finding reports is that none of the
    /// fields it does know about was there, which is weaker than the sentence
    /// and says so.
    ///
    // cite(RFC 9110 § 9.3.7): "A server generating a successful response to OPTIONS SHOULD send any header that might indicate optional features implemented by the server and applicable to the target resource (e.g., Allow), including potential extensions not defined by this specification."
    METHOD_OPTIONS_CAPABILITIES_MISSING = {
        id: "method_options_capabilities_missing",
        title: "A successful OPTIONS answers with none of the capabilities it was asked for",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_9_3_7],
    }
    /// A `201 (Created)` answering a `POST`, with no `Location`.
    ///
    /// **This is the sentence `location_missing` deliberately does not
    /// cover.** The five statuses that ask for `Location` ask in their own
    /// definitions; a `201` does not — § 15.3.2 describes it *without* the
    /// field, saying the resource created is then the target URI. The one
    /// sentence asking a `201` for one is § 9.3.3's, and it is about `POST`, so
    /// only a rule holding the request method can report it. The subject is the
    /// method for exactly that reason.
    ///
    // cite(RFC 9110 § 9.3.3): "If one or more resources has been created on the origin server as a result of successfully processing a POST request, the origin server SHOULD send a 201 (Created) response containing a Location header field that provides an identifier for the primary resource created"
    METHOD_POST_LOCATION_MISSING = {
        id: "method_post_location_missing",
        title: "A 201 answering a POST does not say what it created",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_9_3_3],
    }

    /// A `PATCH` request carrying content with no `Content-Type`.
    ///
    /// The same shape as the `OPTIONS` entry and a stronger reason: RFC 5789
    /// says the set of changes is represented in a format *identified by a
    /// media type*, and that **no single default patch document format
    /// exists** — so a recipient has nothing to fall back on and the content
    /// cannot be applied at all.
    ///
    // cite(RFC 5789 § 2): "Therefore, there is no single default patch document format that implementations are required to support."
    METHOD_PATCH_CONTENT_TYPE_MISSING = {
        id: "method_patch_content_type_missing",
        title: "A PATCH request does not name its patch document format",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_5789_2],
    }

    /// A `HEAD` response whose header fields differ from the `GET` response for
    /// the same resource.
    ///
    /// `_conflicting`, because what is reported is two answers about one
    /// resource that do not agree — and the comparison is narrower than the
    /// SHOULD on purpose, since § 9.3.2's own MAY excuses fields whose value is
    /// determined only while generating the content, which a `HEAD` never
    /// generates.
    ///
    // cite(RFC 9110 § 9.3.2): "The server SHOULD send the same header fields in response to a HEAD request as it would have sent if the request method had been GET."
    METHOD_HEAD_CONFLICTING = {
        id: "method_head_conflicting",
        title: "A HEAD response disagrees with the GET it stands in for",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_9_3_2],
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one entry whose sentence names a class rather than a list is the one
    /// ranked below the rest: the rule can only look for what it knows, and the
    /// SHOULD is deliberately open-ended.
    #[test]
    fn the_open_ended_should_is_the_only_entry_below_warn() {
        for def in [
            &METHOD_TRACE_CONTENT_FORBIDDEN,
            &METHOD_TRACE_DISCLOSURE_FORBIDDEN,
            &METHOD_OPTIONS_CONTENT_TYPE_MISSING,
        ] {
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
        }
        assert_eq!(
            METHOD_OPTIONS_CAPABILITIES_MISSING.default_severity,
            Severity::Info
        );
    }

    /// Every id names the method its requirement belongs to, because the
    /// subject is the method token and the requirements are per method.
    #[test]
    fn every_id_names_its_method() {
        assert!(METHOD_TRACE_CONTENT_FORBIDDEN
            .id
            .starts_with("method_trace_"));
        assert!(METHOD_OPTIONS_CONTENT_TYPE_MISSING
            .id
            .starts_with("method_options_"));
    }
}
