// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Vary` defects — the dimensions a cache key was told to carry.
//!
//! The field names the request fields a stored response was selected on, and
//! RFC 9111 § 4.1 makes reuse conditional on all of them matching. What a proxy
//! watching the exchanges can say about that is on the *sending* side: a
//! response whose selection depended on a request field it does not name.
//!
//! **Whether a cache honoured the field is not here, and cannot be.** A request
//! that reaches the wire is one no cache answered, and one that revalidates a
//! stored response under a request whose selecting fields differ is § 4.3.1's
//! permission — "a cache is allowed to validate a response that it cannot choose
//! with the request header fields it is sending" — rather than a breach of it.
//!
//! **What the *value* may be is not here either.** `Vary = #field-name` is
//! `vary_header_valid`'s, over [`list`](crate::violations::list) and
//! [`token`](crate::violations::token), and a `Vary: *` beside a directive
//! advertising reuse is [`cache_control`](crate::violations::cache_control)'s —
//! the field whose statement that pairing kills.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Preferences and caching: the MUST that puts `Prefer` in a `Vary` whenever a
/// preference could change what a cache holds.
pub const RFC_7240_2: SpecRef = SpecRef {
    spec: "RFC 7240",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-2",
    note: "The `Vary` MUST for a server that applies a preference which might vary a cache's handling of the response entity, and the `Vary: *` alternative it offers instead",
};

/// Vary: what the field is for, the SHOULD that has an origin send it, and the
/// case § 12.5.5 lets it be left out.
pub const RFC_9110_12_5_5: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("12.5.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.5",
    note: "Vary — an origin SHOULD send it on a cacheable response whose content was tailored to the request's preferences, and might elide it where reuse is already limited by cache directives",
};

/// Calculating Cache Keys with the Vary Header Field: the default response
/// that omits `Vary`, which § 4.1 names as a mistake and says what it costs.
pub const RFC_9111_4_1: SpecRef = SpecRef {
    spec: "RFC 9111",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1",
    note: "Calculating Cache Keys with the Vary Header Field — a resource whose default response omits Vary has that response chosen for later requests even when a more preferable one is available",
};

/// Fetch's background note on caching a CORS response: the one place the
/// standard says when `Vary: Origin` is owed, and the failure without it.
pub const FETCH_CORS_HTTP_CACHES: SpecRef = SpecRef {
    spec: "Fetch",
    section: None,
    url: "https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches",
    note: "CORS protocol and HTTP caches (informative) — where Access-Control-Allow-Origin depends on the request's Origin, Vary is to be used, or a cached non-CORS response is handed to a later CORS request",
};

defects! {
    /// A response saying it applied a preference that changes what the entity
    /// is, without nominating `Prefer` in its `Vary`.
    ///
    /// **The subject is `Vary` and not `Prefer`, because the MUST is addressed
    /// to the `Vary`**: RFC 7240 § 2 tells a server that supports such a
    /// preference to list the `Prefer` field in the response's `Vary`
    /// *regardless of whether the client used it*, so what is absent is a
    /// dimension of the cache key rather than anything about the preference.
    /// The pairing rule this catalogue already follows — the subject is
    /// whichever field the requirement is addressed to — decides it.
    ///
    /// **`Vary: *` satisfies it and so does nothing else.** § 2 offers that
    /// alternative by name, and it works because a `*` makes the response
    /// unreusable rather than because it names the field.
    ///
    /// `error`: § 2 says a `Vary` listing `Prefer` MUST be included, whether or
    /// not the client used the field. Every message involved is well formed and
    /// the exchange that produced the finding was answered correctly; what is
    /// wrong is that a later request can be answered from this response when it
    /// should not be.
    ///
    // cite(RFC 7240 § 2): "If a server supports the optional application of a preference that might result in a variance to a cache's handling of a response entity, a Vary header field MUST be included in the response listing the Prefer header field regardless of whether the client actually used Prefer in the request."
    VARY_PREFER_MISSING = {
        id: "vary_prefer_missing",
        title: "A response applied a preference its Vary does not nominate",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7240_2],
        strength: Strength::Must,
    }

    /// A response whose content coding was chosen from the request's
    /// `Accept-Encoding`, cacheable, with no `Vary` naming that field.
    ///
    /// **The coding is the selection, and it is on the wire.** A server that
    /// answers `Accept-Encoding: gzip, br` with `Content-Encoding: br` has
    /// tailored the content to a preference the request expressed, which is
    /// the case § 12.5.5 describes, and the response's own header says so.
    /// Without `Accept-Encoding` in `Vary`, § 4.1 of RFC 9111 lets a cache
    /// hand the `br` body to the next request whatever it accepts — including
    /// one that cannot decode it.
    ///
    /// **The SHOULD has an antecedent, and the entry reads it as far as the
    /// wire shows it.** § 12.5.5 asks for `Vary` on a cacheable response "when
    /// it wishes that response to be selectively reused", and lets the field be
    /// elided where "reuse is already limited by cache response directives".
    /// So the response has to be one a cache could keep (RFC 9111 § 3), to a
    /// `GET` that carried `Accept-Encoding` — a request with none accepts any
    /// coding (§ 12.5.3), so a coded answer to it chose nothing — and it may
    /// not already limit reuse: an unqualified `no-cache`, a `private`, or a
    /// `max-age=0` with no `s-maxage` beside it is the origin having said
    /// what § 12.5.5 lets it say instead.
    ///
    /// **`Vary: *` satisfies it**: a response that fails every match is
    /// reused by no cache under any coding.
    ///
    /// `warn`: § 12.5.5's SHOULD, addressed to the server that sent the
    /// response this reads.
    ///
    // cite(RFC 9110 § 12.5.5): "An origin server SHOULD generate a Vary header field on a cacheable response when it wishes that response to be selectively reused for subsequent requests. Generally, that is the case when the response content has been tailored to better fit the preferences expressed by those selecting header fields"
    // cite(RFC 9110 § 12.5.5): "Vary might be elided when an origin server considers variance in content selection to be less significant than Vary's performance impact on caching, particularly when reuse is already limited by cache response directives"
    VARY_ACCEPT_ENCODING_MISSING = {
        id: "vary_accept_encoding_missing",
        title: "A response coded from Accept-Encoding does not name it in Vary",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_12_5_5],
        strength: Strength::Should,
    }

    /// Two responses for one resource, one naming a selecting field in `Vary`,
    /// and the other — sent to a request without that field — naming nothing
    /// of the kind.
    ///
    /// **This is the mistake § 4.1 describes by name.** "Some resources
    /// mistakenly omit the Vary header field from their default response (i.e.,
    /// the one sent when the request does not express any preferences)": the
    /// response to a request with no `Accept-Encoding`, no `Accept-Language`,
    /// no `Cookie`, sent without the `Vary` its siblings carry. A cache holding
    /// it has nothing to compare, so it answers every later request with it —
    /// the uncompressed body to a client that asked for `br`, the anonymous
    /// page to a signed-in one — "even when more preferable responses are
    /// available".
    ///
    /// **`_conflicting`: each response is well formed, and the two cannot
    /// both describe the resource.** One says the field selects its content;
    /// the other, sent when the field was absent, says nothing selects it.
    /// Absence is not a value a field can be compared on, so the response that
    /// omitted it is the one to change.
    ///
    /// **Reported once for each response that omits the field.** Where the
    /// omitting response comes second, it is the finding. Where it came first,
    /// the finding is on the first response that nominated the field, naming
    /// the earlier one, and not again on every response after it.
    ///
    /// `warn`, and `Unstated`: § 4.1 calls it a mistake and binds nobody, and
    /// the level is what the cache does with it.
    ///
    // cite(RFC 9111 § 4.1): "Some resources mistakenly omit the Vary header field from their default response (i.e., the one sent when the request does not express any preferences), with the effect of choosing it for subsequent requests to that resource even when more preferable responses are available."
    VARY_CONFLICTING = {
        id: "vary_conflicting",
        title: "A default response omits a field its siblings name in Vary",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9111_4_1],
        strength: Strength::Unstated,
    }

    /// A response whose `Access-Control-Allow-Origin` has been seen to follow
    /// the request's `Origin`, with no `Vary` naming `Origin`.
    ///
    /// **Fetch describes the failure step by step.** A server that sends
    /// `Access-Control-Allow-Origin` only in answer to a CORS request sends a
    /// response without it to a navigation; the user agent caches that, and
    /// answers the next CORS request for the resource from the cache — without
    /// the header, so the request fails. The same happens between two
    /// origins when the server echoes the one it was sent: the second is
    /// handed the first one's grant. "If CORS protocol requirements are more
    /// complicated than setting `Access-Control-Allow-Origin` to * or a static
    /// origin, `Vary` is to be used."
    ///
    /// **The evidence is two responses, not one.** An
    /// `Access-Control-Allow-Origin` equal to the request's `Origin` is what
    /// a static single-origin configuration sends too, whenever that origin is
    /// the one asking — and Fetch says a static origin needs no `Vary`. What
    /// shows the value is computed from the request is two responses for the
    /// resource, of the same status, to requests whose `Origin` differs — one
    /// may carry none — with different `Access-Control-Allow-Origin` values,
    /// one of which may be absent.
    ///
    /// **`Vary: *` satisfies it**, as it satisfies every selecting field.
    ///
    /// `warn`, and `Unstated`: the section is background reading, and "is to be
    /// used" states no keyword. The level is the failure it describes — a CORS
    /// request refused, or a grant given to the wrong origin, by a cache doing
    /// what the response told it.
    ///
    // cite(Fetch): "If CORS protocol requirements are more complicated than setting `Access-Control-Allow-Origin` to * or a static origin, `Vary` is to be used."
    // cite(Fetch): "When a user agent receives a response to a non-CORS request for that resource (for example, as the result of a navigation request), the response will lack `Access-Control-Allow-Origin` and the user agent will cache that response."
    VARY_ORIGIN_MISSING = {
        id: "vary_origin_missing",
        title: "An Access-Control-Allow-Origin chosen from the Origin is not keyed on it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[FETCH_CORS_HTTP_CACHES],
        strength: Strength::Unstated,
    }
}
