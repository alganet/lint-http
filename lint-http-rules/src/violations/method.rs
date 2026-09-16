// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Method-semantics defects — what a method's own definition says a message
//! carrying it may hold.
//!
//! The subject is the method token, which is a protocol element rather than a
//! field: which *characters* a spelling may hold is
//! [`token`](crate::violations::token)'s, and what a message's fields say is
//! each field's own. Here are the requirements a method definition puts on the
//! message around it, and the part in each id is the method they belong to.
//!
//! **One entry is about the spelling after all, and it is the one the `token`
//! production cannot hold.** `get` derives from `1*tchar` exactly as `GET`
//! does; what makes it a finding is that the token is compared case-sensitively
//! against method names, so a value that looks like a method names none. That
//! is a question about the method and not about its characters.
//!
//! **Two methods so far, and they are opposites in a useful way.** `TRACE`
//! loops the request back, so its definition is two prohibitions on what a
//! client may put in one; `OPTIONS` asks for capabilities, so its definition is
//! a requirement on a client that sends content and a recommendation to a
//! server about what to answer with.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// § 9.1: the method token's case-sensitivity, the all-uppercase convention,
/// and what a server does with a method it cannot place.
pub const RFC_9110_9_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("9.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1",
    note: "`method = token`, the token's case-sensitivity, the convention that standardized methods are defined in all-uppercase US-ASCII letters, and the 501 an origin server gives an unrecognized method",
};

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

/// GET: content in one has no defined semantics, and the paragraph saying so
/// is repeated word for word under HEAD and DELETE.
pub const RFC_9110_9_3_1: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("9.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.1",
    note: "GET — the client `SHOULD NOT` on content, its `unless` clause, the sentence declining to rely on the private agreement that clause describes, and the statement that framing is independent of the method",
};

/// HEAD: identical to GET but for the content, with the exception that keeps
/// content-derived fields out of the comparison — and the same content
/// paragraph GET carries.
pub const RFC_9110_9_3_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("9.3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2",
    note: "HEAD — the SHOULD to send the same header fields a GET would have carried, the MAY that excuses fields whose value is determined only while generating the content, and GET's content paragraph repeated word for word",
};

/// DELETE: GET's content paragraph a third time.
pub const RFC_9110_9_3_5: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("9.3.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.5",
    note: "DELETE — the same content paragraph as GET and HEAD, word for word again",
};

/// CONNECT: a definition rather than a modal, and the sentence that makes what
/// follows the header section tunnel traffic rather than content.
pub const RFC_9110_9_3_6: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("9.3.6"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6",
    note: "CONNECT — the request message does not have content, and the interpretation of anything after its header section is specific to the version of HTTP in use",
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

    /// Content on a `GET`, a `HEAD` or a `DELETE`.
    ///
    /// **One entry for three sections, because it is one paragraph printed
    /// three times.** § 9.3.1, § 9.3.2 and § 9.3.5 carry the same words, the
    /// same `unless` clause and the same reason — content received under these
    /// methods has no generally defined semantics — so a client that put a body
    /// on a `GET` and one that put a body on a `DELETE` made one mistake with
    /// one repair. The message names the method and the section.
    ///
    /// **Which is why no finding of it is cited.** The entry names all three,
    /// and a def naming several carries none onto its findings: no one of them
    /// governs a message, and choosing at the site would put § 9.3.1's number
    /// on a `DELETE`.
    ///
    /// **Separate from [`METHOD_TRACE_CONTENT_FORBIDDEN`], which is content on
    /// a method that says no for a different reason.** § 9.3.8's is a flat
    /// `MUST NOT` about a request that is *echoed*, so the body comes back;
    /// these three are a `SHOULD NOT` about a request whose body means nothing.
    /// A sender told to stop echoing secrets and a sender told its body will be
    /// ignored are reading different sentences.
    ///
    /// **The `unless` clause is not a way out, and the same paragraph says
    /// so.** It excuses content sent to an origin server that has previously
    /// indicated support "in or out of band" — a private agreement no observer
    /// can confirm — and the next sentence tells that origin server not to rely
    /// on one, because participants are often unaware of intermediaries along
    /// the request chain.
    ///
    /// `warn`, with the subject: the request is well formed and will be
    /// answered; what is lost is whatever the client meant by the body.
    ///
    METHOD_CONTENT_FORBIDDEN = {
        id: "method_content_forbidden",
        title: "A GET, HEAD or DELETE request carries content",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_9_3_1, RFC_9110_9_3_2, RFC_9110_9_3_5],
    }

    /// A `CONNECT` request declaring content in its header section.
    ///
    /// **The one entry in this subject standing on a definition rather than a
    /// modal.** § 9.3.6 does not tell a client not to send content; it says a
    /// CONNECT request message does not have any. So the finding is that the
    /// message contradicts the definition of the method it names, and
    /// `_forbidden` is the ending for a message holding what the specification
    /// does not admit — whether the sentence spends a MUST NOT on saying so.
    ///
    /// **The evidence is the header section and never the octets after it**,
    /// which is the same section's doing: what follows a CONNECT's header
    /// section is specific to the version of HTTP in use, and where the tunnel
    /// was established it is the tunnel's own traffic. A reader counting those
    /// bytes as content would report every successful CONNECT there is.
    ///
    /// `warn`, with the subject.
    ///
    // cite(RFC 9110 § 9.3.6): "A CONNECT request message does not have content."
    METHOD_CONNECT_CONTENT_FORBIDDEN = {
        id: "method_connect_content_forbidden",
        title: "A CONNECT request declares content its definition has no room for",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_9_3_6],
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

    /// A method token that is a registered method's name written in another
    /// case: `get`, `Post`, `DELETE ` folded to something the deployment
    /// expects to see spelled its own way.
    ///
    /// **`_invalid` because the grammar has no complaint.** `get` derives from
    /// `1*tchar` exactly as `GET` does, and both are `method`s. What refuses it
    /// is one level past the production: § 9.1 says the token is compared
    /// case-sensitively — because it might be a gateway to a system with
    /// case-sensitive method names — so a server matching method names sees an
    /// unrecognized method here, and § 9.1 says what it does about one.
    ///
    /// **The convention is the evidence and not the requirement.** *"By
    /// convention, standardized methods are defined in all-uppercase US-ASCII
    /// letters"* is what makes a lowercase spelling recognisable as a mistake
    /// rather than as somebody's private method; the finding rests on the
    /// case-sensitivity sentence beside it, which is flat.
    ///
    /// **Only the case-variant subset is reported, and the limit is
    /// deliberate.** An uppercase name absent from the deployment's list is very
    /// often a private method somebody defined — `PURGE` is nobody's registry
    /// entry — so reporting every unregistered spelling would report every
    /// extension there is. The rule leans on a configured set of names for
    /// exactly that reason, which is why this entry cannot be spelled
    /// `_unregistered`: it is not asking whether the registry holds the value.
    ///
    /// `warn`. The request parses and is well formed; what it asks for is a
    /// method nobody defined, and the answer it earns is a `501`.
    ///
    // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
    // cite(RFC 9110 § 9.1): "An origin server that receives a request method that is unrecognized or not implemented SHOULD respond with the 501 (Not Implemented) status code."
    METHOD_CASE_INVALID = {
        id: "method_case_invalid",
        title: "A method is a standardized name written in another case",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_9_1],
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
