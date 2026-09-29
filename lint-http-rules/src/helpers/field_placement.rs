// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Where a field may appear, and whether it survives a hop.
//!
//! Two boundaries, one question in the shape it is asked: given a field *name*,
//! may it be here? [`is_prohibited_trailer_field`] answers it for the trailer
//! section, [`is_connection_specific_field`] for the next hop, and
//! [`is_nominated_by_connection`] is the part the sender controls — a field
//! becomes connection-specific by being named in `Connection`, so the answer
//! depends on the message and not on the name alone.
//!
//! None of these reads a value. That is why they are not in `headers`, which is
//! about getting a value out of a `HeaderMap`.

use crate::helpers::list::list_members;

/// Field names that cannot appear in a trailer section, by category.
///
/// This is the fixed half of the question "may this field be a trailer". The other
/// half is [`is_nominated_by_connection`], which depends on the message.
///
/// **This table is a subset, and deliberately so.** The requirement is stated the
/// other way round — a trailer field is forbidden *unless* the sender knows the
/// field's own definition permits it, and the registry guidance says that by default
/// no definition does. A table of names answers the opposite question, so every field
/// nobody thought of passes. It cannot be inverted here: for a field this codebase
/// holds no definition of (`X-Checksum`, `Grpc-Status`), only the sender knows whether
/// a definition permits the usage, and reporting all of them would report the senders
/// that read their own specification. What the table can hold honestly is the fields
/// whose definitions are in the specifications this crate cites and do *not* permit
/// trailers; `trailer_fields_valid` says so where an operator reads it.
///
/// The categories below are the ones §6.5.1 names, in its order. The last group is
/// here because a connection-specific field is, by definition, needed before the
/// content is read; `trailer` is here because a Trailer field inside a trailer
/// section announces nothing.
///
/// Membership is per field *definition*, never per category: RFC 9110 puts
/// `Authentication-Info` and `Proxy-Authentication-Info` under authentication and
/// then permits both in trailers, so neither is here. See
/// [`is_prohibited_trailer_field`] for where that is written down.
///
// cite(RFC 9110 § 6.5.1): "Many fields cannot be processed outside the header section because their evaluation is necessary prior to receiving the content, such as those that describe message framing, routing, authentication, request modifiers, response controls, or content format."
// cite(RFC 9110 § 6.5.1): "A sender MUST NOT generate a trailer field unless the sender knows the corresponding header field name's definition permits the field to be sent in trailers."
// cite(RFC 9110 § 16.3.2): "If the field is allowable in trailers; by default, it will not be (see Section 6.5.1)."
pub static PROHIBITED_TRAILER_FIELDS: &[&str] = &[
    // Message framing
    "content-length",
    "transfer-encoding",
    // Routing
    "host",
    // `Forwarded` is routing too, and RFC 7239 defines it for the header
    // section and nowhere else — so the sender does not know its definition
    // permits a trailer, because it does not.
    "forwarded",
    // Request modifiers — controls
    "cache-control",
    "expect",
    "max-forwards",
    "pragma",
    "range",
    "te",
    // Request modifiers — conditionals
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    // Request modifiers — content negotiation (RFC 9110 § 12.5)
    "accept",
    "accept-encoding",
    "accept-language",
    // Request context (RFC 9110 § 10.1), read to decide how to answer
    "from",
    "referer",
    "user-agent",
    // Authentication (RFC 9110 §11). `Authentication-Info` and
    // `Proxy-Authentication-Info` are the two that §11 takes back out again, and
    // they are not here.
    "authorization",
    "proxy-authenticate",
    "proxy-authorization",
    "www-authenticate",
    // Response control data. These are the fields §6.5.1's "response controls"
    // names in prose; §6.2 "Control Data" is the start line, not this.
    "age",
    "date",
    "expires",
    "location",
    "retry-after",
    "vary",
    "warning",
    // Response context (RFC 9110 § 10.2). `Accept-Ranges` is the one § 14.3
    // grants the trailer section, and it is not here.
    "allow",
    "server",
    // Payload processing
    "content-encoding",
    "content-range",
    "content-type",
    "trailer",
    // Representation metadata (RFC 9110 § 8). `ETag` is the one § 8.8.3 grants
    // the trailer section, and it is not here.
    "content-language",
    "content-location",
    "last-modified",
    // Forwarding (RFC 9110 § 7.6.3), appended by each hop as it passes the
    // message on, which is before the content.
    "via",
    // Connection-specific (RFC 9110 §7.6.1). The section's own list is bullets
    // too short to cite; the citable form is RFC 9113's parenthetical, a
    // published reading of that list, and it names `Proxy-Connection` in it —
    // the member this table omitted while `CONNECTION_SPECIFIC_FIELDS` below
    // held it, which is what made the omission a reading rather than a
    // decision (RULECITES P46). `transfer-encoding` and `te` are §7.6.1's too
    // and sit above under the framing and request-modifier categories §6.5.1
    // names them by.
    // cite(RFC 9113 § 8.2.2): "This includes the Connection header field and those listed as having connection-specific semantics in Section 7.6.1 of [HTTP] (that is, Proxy-Connection, Keep-Alive, Transfer-Encoding, and Upgrade)."
    "connection",
    "keep-alive",
    "proxy-connection",
    "upgrade",
    // The cleanest member of this list: § 6.5.1 asks whether the field's own
    // definition permits the usage, and this field's definition answers by name.
    // The same sentence forbids it in a response, which is
    // `early_data_header_safe_method`'s finding — a response *trailer* is
    // both, and is reported here.
    // cite(RFC 8470 § 5.1): "An Early-Data header field MUST NOT be included in responses or request trailers."
    "early-data",
    // The fields the other documents this crate cites define, each for the
    // header section and with no sentence about a trailer section. RFC 9530
    // grants the section to `Content-Digest` and `Repr-Digest` by name, and not
    // to the two preference fields beside them.
    "accept-patch",
    "alt-svc",
    "alt-used",
    "content-disposition",
    "cookie",
    "deprecation",
    "link",
    "origin",
    "prefer",
    "preference-applied",
    "priority",
    "sec-websocket-accept",
    "sec-websocket-extensions",
    "sec-websocket-key",
    "sec-websocket-protocol",
    "sec-websocket-version",
    "set-cookie",
    "strict-transport-security",
    "sunset",
    "want-content-digest",
    "want-repr-digest",
    // Retired fields, each defined by a document this crate cites and reported
    // as retired where it is written, as `pragma` and `warning` above are:
    // RFC 9110 § 12.5.2, RFC 1864 by way of RFC 2616, RFC 3230 twice, RFC 9163
    // and P3P. None of their definitions mentions a trailer section.
    "accept-charset",
    "content-md5",
    "digest",
    "expect-ct",
    "p3p",
    "want-digest",
    // And the ones the web platform's documents define: Fetch, Fetch Metadata,
    // HTML, CSP, Permissions Policy, Referrer Policy, Network Error Logging,
    // Resource Timing, Clear Site Data and Storage Access Headers. Fetch hands a
    // response's header list to the platform and has no trailer list at all.
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-origin",
    "access-control-expose-headers",
    "access-control-max-age",
    "access-control-request-headers",
    "access-control-request-method",
    "activate-storage-access",
    "clear-site-data",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-embedder-policy-report-only",
    "cross-origin-opener-policy",
    "cross-origin-opener-policy-report-only",
    "cross-origin-resource-policy",
    "nel",
    "origin-agent-cluster",
    "permissions-policy",
    "referrer-policy",
    "refresh",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-storage-access",
    "sec-fetch-user",
    "timing-allow-origin",
    "x-content-type-options",
    "x-frame-options",
];

/// Whether `name` cannot appear in a trailer section because of what it is.
///
/// See [`is_nominated_by_connection`] for the half that depends on the message.
///
/// Two fields this returns `false` for used to be in the table, on the strength of
/// the category §6.5.1 lists them under. Both definitions say the opposite in one
/// sentence each, and the sentence is the thing §6.5.1 asks the sender to know — so
/// a sender whose scheme allows it is conforming, and the rule that reports this
/// cannot tell which scheme is in use. The permission is conditional and the
/// condition is not on the wire; a name the RFC permits at all does not belong in a
/// table of names the RFC forbids.
///
/// Four more are granted the section outright, and a table that grew to every
/// field a cited document defines had to leave each of them out by name: `ETag`,
/// for a tag computed while the content streams; `Accept-Ranges`; and the two
/// digests RFC 9530 computes over content that has not finished arriving.
///
// cite(RFC 9110 § 11.6.3): "Authentication-Info can be sent as a trailer field (Section 6.5) when the authentication scheme explicitly allows this."
// cite(RFC 9110 § 11.7.3): "Proxy-Authentication-Info can be sent as a trailer field (Section 6.5) when the authentication scheme explicitly allows this."
// cite(RFC 9110 § 8.8.3): "A sender MAY send the ETag field in a trailer section"
// cite(RFC 9110 § 14.3): "The Accept-Ranges field MAY be sent in a trailer section"
// cite(RFC 9530 § 2): "Content-Digest can be sent in a trailer section."
// cite(RFC 9530 § 3): "Repr-Digest can be sent in a trailer section."
pub fn is_prohibited_trailer_field(name: &str) -> bool {
    let name_l = name.trim().to_ascii_lowercase();
    PROHIBITED_TRAILER_FIELDS.contains(&name_l.as_str())
}

/// Fields that are connection-specific whatever the message says.
///
/// The first six are RFC 9110 § 7.6.1's own list, plus `connection` itself, which the
/// same section has an intermediary remove after acting on it. The last two are not
/// § 7.6.1's: they are single-hop by their own definitions in § 11.7.1 and § 11.7.2.
///
/// `trailer` is deliberately not here — § 6.6.2 has it surviving the hop. It cannot be
/// a *trailer field*, but that is § 6.5.1's business and
/// [`PROHIBITED_TRAILER_FIELDS`] is where it says so.
// cite(RFC 9110 § 7.6.1): "Furthermore, intermediaries SHOULD remove or replace fields that are known to require removal before forwarding, whether or not they appear as a connection-option, after applying those fields' semantics."
static CONNECTION_SPECIFIC_FIELDS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
    // Single-hop by their own definitions, not by § 7.6.1's list.
    "proxy-authenticate",
    "proxy-authorization",
];

/// Whether `name` is connection-specific — either always, or because this message's
/// `Connection` header nominated it.
pub fn is_connection_specific_field(name: &str, connection_header_value: Option<&str>) -> bool {
    let name_l = name.trim().to_ascii_lowercase();
    CONNECTION_SPECIFIC_FIELDS.contains(&name_l.as_str())
        || is_nominated_by_connection(name, connection_header_value)
}

/// Whether `name` was named as a connection-option in this message's `Connection`
/// header, which disqualifies it from the trailer section for this message only.
///
/// The cited sentence says "header **or trailer** field(s)", and that is the whole
/// reason a connection-option reaches into a trailer section at all.
///
/// Every caller passes a value joined by [`combined_field_value_as_written`](crate::helpers::headers::combined_field_value_as_written), i.e.
/// one `char` per octet, so the member walk is the `OWS`-trimming one: a member
/// padded with an `obs-text` octet that renders like a space is not the
/// `connection-option` it resembles, and no sentence lets this function pretend it
/// is. The fold *is* licensed -- a `connection-option` is a field name, and those
/// are case-insensitive.
// cite(RFC 9110 § 5.1): "Field names are case-insensitive"
pub fn is_nominated_by_connection(name: &str, connection_header_value: Option<&str>) -> bool {
    // cite(RFC 9110 § 7.6.1): "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message)."
    let name_l = name.trim().to_ascii_lowercase();
    let Some(conn) = connection_header_value else {
        return false;
    };
    list_members(conn).any(|tok| tok.eq_ignore_ascii_case(name_l.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_prohibited_trailer_field() {
        // Fields the cited categories name, case-insensitively.
        assert!(is_prohibited_trailer_field("Connection"));
        assert!(is_prohibited_trailer_field("connection"));
        assert!(is_prohibited_trailer_field("keep-alive"));
        // The categories reach well past the connection-specific ones: framing,
        // routing, conditionals, response control data.
        assert!(is_prohibited_trailer_field("Content-Length"));
        assert!(is_prohibited_trailer_field("host"));
        assert!(is_prohibited_trailer_field("If-Match"));
        assert!(is_prohibited_trailer_field("date"));
        // A Trailer field inside a trailer section announces nothing.
        assert!(is_prohibited_trailer_field("trailer"));
        // Every field a cited document defines for the header section alone.
        for name in [
            "Last-Modified",
            "Set-Cookie",
            "Cookie",
            "User-Agent",
            "Via",
            "Link",
            "Content-MD5",
            "Digest",
        ] {
            assert!(is_prohibited_trailer_field(name), "{name}");
        }
        // The six whose own definitions grant the section.
        for name in [
            "ETag",
            "Accept-Ranges",
            "Authentication-Info",
            "Proxy-Authentication-Info",
            "Content-Digest",
            "Repr-Digest",
        ] {
            assert!(!is_prohibited_trailer_field(name), "{name}");
        }
        // An extension field is not prohibited by what it is.
        assert!(!is_prohibited_trailer_field("x-foo"));
        assert!(!is_prohibited_trailer_field("x-checksum"));
    }

    #[test]
    fn test_is_nominated_by_connection() {
        // Nomination is per-message: this field is disqualified only because this
        // message's Connection header names it.
        assert!(is_nominated_by_connection(
            "X-Special",
            Some("keep-alive, X-Special")
        ));
        // Not nominated if not listed.
        assert!(!is_nominated_by_connection("X-Special", Some("keep-alive")));
        // Both sides match case-insensitively.
        assert!(is_nominated_by_connection(
            "x-special",
            Some("KEEP-ALIVE, x-special")
        ));
        // No Connection header nominates nothing.
        assert!(!is_nominated_by_connection("x-special", None));
        // A substring is not a token.
        assert!(!is_nominated_by_connection(
            "upgrade",
            Some("super-upgrade")
        ));
    }
}
