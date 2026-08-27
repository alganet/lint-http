// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{describe_char, shown_in_finding};
use crate::helpers::uri::{
    extract_path_from_request_target, is_sub_delim, is_unreserved, normalize_path_and_query,
    scheme_authority_marker,
};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct WellKnownUriSyntax;

/// The one path segment RFC 8615 reserves. The prefix the document writes is
/// `"/.well-known/"` — this is that string with the delimiters that make it a
/// segment removed, because the checks below walk segments rather than match a
/// prefix: `/.well-knownfoo` begins with the same eleven characters and is an
/// ordinary path that has nothing to do with this document.
const WELL_KNOWN_SEGMENT: &str = ".well-known";

/// The first character of `name` that `pchar` does not generate, or `None`.
///
/// A `%` passes: it is the first character of a `pct-encoded` triplet, and
/// whether the two that follow it are `HEXDIG` is
/// `request_uri_percent_encoding_valid`'s question, asked of the whole
/// request target rather than of one segment.
///
/// This is narrower than [`crate::helpers::uri::find_non_uri_char`], which
/// measures the union of every component's alphabet: within a path segment the
/// only characters that union admits and `pchar` does not are `[` and `]`,
/// since `/`, `?` and `#` cannot reach a segment at all — the first delimits
/// segments and the other two terminate the path. So the two checks are the
/// same question asked at two widths, and the neighbour owns the wider one.
///
/// Still written privately, and the reason has moved: `pchar` has one reader in
/// the tree, but the two sets it is built out of had five and four, so what went
/// to `helpers::uri` is [`is_unreserved`] and [`is_sub_delim`] rather than this
/// function. The line below is now `pchar`'s own alternation and nothing else —
/// the two shared sets, then the two characters this production adds to them,
/// then the `%`. A second reader of the whole alphabet moves *this* to the
/// helper module; a fifth reader of either set changes nothing, because the sets
/// are already there.
///
/// The cardinality is the caller's: `segment-nz = 1*pchar`, and a character-set
/// predicate is never a floor — the empty name is reported one branch above,
/// against that `1*`.
// cite(RFC 3986 § 3.3, label: pchar): "pchar         = unreserved / pct-encoded / sub-delims / ":" / "@""
// cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
fn first_non_pchar(name: &str) -> Option<char> {
    name.chars()
        .find(|&c| !(is_unreserved(c) || is_sub_delim(c) || matches!(c, ':' | '@' | '%')))
}

/// Whether one path segment *is* the reserved segment.
///
/// The literal comparison first, and the decode only when there is a `%` to
/// decode: this predicate is asked of every segment of every request path, and
/// the decoding path allocates.
///
/// `%2Ewell-known` and `.well-known` are the same segment — the generic syntax
/// says so in as many words — and a comparison that misses it reads a well-known
/// URI as an ordinary path, which is the direction a path-confusion trick is
/// written in. Only `unreserved` octets are decoded, because decoding a
/// `sub-delims` or `gen-delims` octet would move the component boundaries; that
/// reasoning, and § 2.4's sentence, live with the shared decoder.
///
/// The decoder also puts a surviving triplet's hexadecimal in upper case, which
/// cannot change this answer: `WELL_KNOWN_SEGMENT` is made of `unreserved`
/// characters, so a segment still holding a `%` after the decode matches it in
/// no case at all.
// cite(RFC 3986 § 2.3): "URIs that differ in the replacement of an unreserved character with its corresponding percent-encoded US-ASCII octet are equivalent"
fn is_well_known_segment(segment: &str) -> bool {
    segment == WELL_KNOWN_SEGMENT
        || (segment.contains('%')
            && crate::helpers::uri::decode_unreserved(segment) == WELL_KNOWN_SEGMENT)
}

impl Rule for WellKnownUriSyntax {
    fn id(&self) -> &'static str {
        "well_known_uri_syntax"
    }

    /// Every finding here is about the path a client put in the request target,
    /// which is what makes this a client-scoped rule — but not because RFC 8615
    /// asks a client for anything. **The document holds five BCP 14 modals and
    /// every one of them is addressed to an application minting or registering a
    /// name**: register them, conform to `segment-nz`, be precise, specify an
    /// alternative port, and the MAY for additional path components. None is a
    /// requirement on a request target, so no finding below is worded as a
    /// violation — see `description()`.
    ///
    /// cite(RFC 8615 § 3): "Applications that wish to mint new well-known URIs MUST register them, following the procedures in Section 5.1, subject to the following requirements."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let target = tx.request.uri.as_str();

            // The proviso the definition ends in, and the half this rule's one cite
            // used to stop before. A path beginning with the reserved prefix is a
            // well-known URI only where the scheme's own definition says the scheme
            // carries them, and this document is what says it for the two schemes an
            // HTTP request can name: it updates `http` and `https` and nothing else.
            // An origin-form target names no scheme and needs none — the message is
            // HTTP, so its target URI is an `http` or an `https` one either way —
            // and an absolute-form target naming some other scheme, which is how a
            // request to a forward proxy is written, is left alone.
            //
            // `scheme_authority_marker` and not a colon search: it takes only a
            // `://` in the first component, so an authority-form CONNECT target
            // naming a host called `http` is not read as a scheme.
            //
            // cite(RFC 8615 § 3): "A well-known URI is a URI [RFC3986] whose path component begins with the characters "/.well-known/", provided that the scheme is explicitly defined to support well-known URIs."
            // cite(RFC 8615 § 3): "This specification updates the "http" [RFC7230] and "https" [RFC7230] schemes to support well-known URIs."
            // cite(RFC 8615 § 1): "Well-known URIs can also be used with other URI schemes, but only when those schemes' definitions explicitly allow it."
            // cite(RFC 8615 § 5.2): "If a URI scheme explicitly has been specified to use well-known URIs as per Section 3, the value changes to a reference to that specification."
            if let Some(marker) = scheme_authority_marker(target) {
                let scheme = &target[..marker];
                if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
                    return None;
                }
            }

            // The path component and only it. The two request-target forms that
            // carry none — `*` and the `host ":" port` of a CONNECT — draw nothing,
            // and the query and fragment are outside the component the definition
            // is about.
            //
            // cite(RFC 9112 § 3.2, label: request-target forms): "request-target = origin-form / absolute-form / authority-form / asterisk-form"
            // cite(RFC 3986 § 3.3): "The path is terminated by the first question mark ("?") or number sign ("#") character, or by the end of the URI."
            let written = extract_path_from_request_target(target)?;

            // Segments, not a prefix match — and compared as written apart from the
            // percent-encoding, because a path is case-sensitive: `/.WELL-KNOWN/x`
            // is a different path and is not a well-known URI.
            //
            // Asked of the value as written, and asked first, so that the
            // normalization below is skipped for every request but a handful. The
            // probe is complete because neither half of that normalization can
            // *create* this segment where the written path has none: removing dot
            // segments only deletes complete `.` and `..` segments, and the decode
            // can only turn `%2Ewell-known` into `.well-known` — which is the
            // spelling `is_well_known_segment` already recognises, and the reason it
            // decodes rather than comparing literally.
            //
            // cite(RFC 3986 § 3.3, label: path-absolute): "path-absolute = "/" [ segment-nz *( "/" segment ) ]"
            // cite(RFC 3986 § 6.2.2.1): "The other generic syntax components are assumed to be case-sensitive unless specifically defined otherwise by the scheme (see Section 6.2.3)."
            if !written.split('/').any(is_well_known_segment) {
                return None;
            }

            // Where in the hierarchy the segment sits is the whole question below,
            // and a dot segment moves it: `/a/../.well-known/x` names the same
            // resource as `/.well-known/x`, and reporting it as a prefix buried in
            // the path would be a finding about a spelling rather than about a path.
            //
            // **The order is the shared normalizer's and it is not the order this
            // rule used to run.** `remove_dot_segments` stood here on the value *as
            // written*, with the decode happening per segment afterwards — so
            // `%2E%2E` was never a `..` segment, and `/foo/%2E%2E/.well-known/x` was
            // reported as a buried prefix while `/foo/../.well-known/x`, the same
            // path, was clean. § 2.4's exception is what licenses decoding first:
            // an `unreserved` octet needs no component boundary established for it,
            // so it can be decoded before the boundaries are read.
            //
            // The function is `normalize_path_and_query` because this is one
            // question with one answer, and it owns all three of § 6.2.2's
            // normalizations including the case one it declines. The query half of
            // its name reaches nothing here: `extract_path_from_request_target`
            // has already ended the value at the `?`.
            let path = normalize_path_and_query(&written);

            let mut segments = path.split('/');
            if segments.next() != Some("") {
                return None;
            }
            let segments: Vec<&str> = segments.collect();
            let at = segments.iter().position(|s| is_well_known_segment(s))?;

            // The config after the probe: a request whose path holds no such segment
            // — every request but a handful — should not pay a map lookup and a hash
            // of the rule id to learn that there is nothing to say.
            let violation = |message: String| Some(self.violation(ctx.severity, message));

            // A path is reported as written; when normalizing it moved the segment
            // being talked about, the normalized form is named beside it, so the
            // reader can see which string the finding is about. **Not "whose dot
            // segments resolve to"** — that named one of the two normalizations, and
            // a value differing only in a `%2E` would have been described as having
            // dot segments it does not have written in it.
            let shown = if path == written {
                format!("'{}'", shown_in_finding(&written))
            } else {
                format!(
                    "'{}' (which normalizes to '{}')",
                    shown_in_finding(&written),
                    shown_in_finding(&path)
                )
            };

            if at > 0 {
                // The document states this case and its counter-example itself, and
                // it states it as a **definition**: such a path is not a well-known
                // URI. It does not forbid it, and nothing else does either — §1
                // names an origin's control over its own URI space as the thing
                // this memo is careful not to usurp. So the finding says what the
                // path is not, and says that this is advice.
                //
                // cite(RFC 8615 § 3): "Well-known URIs are rooted in the top of the path's hierarchy; they are not well-known by definition in other parts of the path."
                // cite(RFC 8615 § 3): "For example, "/.well-known/example" is a well-known URI, whereas "/foo/.well-known/example" is not."
                // cite(RFC 8615 § 1): "Furthermore, defining well-known locations usurps the origin's control over its own URI space [RFC7320]."
                return violation(format!(
                    "Request target path {shown} carries a `.well-known` segment inside the path rather than at the top of its hierarchy, so it is not a well-known URI: RFC 8615 §3 defines one as a URI whose path component *begins with* the characters \"/.well-known/\", and says of this exact shape that \"/.well-known/example\" is a well-known URI, whereas \"/foo/.well-known/example\" is not. The path names an ordinary resource the origin controls (RFC 8615 §1), and RFC 8615 states no requirement on a request target, so this is advice — an application looking for site-wide metadata will not find it here — and not a violation"
                ));
            }

            match segments.get(1) {
                // The prefix is `"/.well-known/"` and the trailing slash is one of
                // its characters, so a path that is the segment and nothing more
                // does not begin with it. Advice for the same reason as the branch
                // above: the sentence it fails is a definition.
                //
                // cite(RFC 8615 § 1): "To address these uses, this memo reserves a path prefix in HTTP, HTTPS, WebSocket (WS), and Secure WebSocket (WSS) URIs for these "well-known locations", "/.well-known/"."
                None => violation(format!(
                    "Request target path {shown} is the reserved prefix one character short: RFC 8615 §1 reserves \"/.well-known/\" with its trailing slash, and §3 defines a well-known URI as one whose path component begins with those characters, so this path names an ordinary resource rather than a well-known one. RFC 8615 states no requirement on a request target, so this is advice, not a violation"
                )),

                // The one requirement in the document a capture can decide, and it
                // had no reader. `segment-nz` is `1*pchar`: the floor is a
                // cardinality, so an empty name derives from no registration, and
                // the section adds that it defines nothing at the prefix itself.
                //
                // Reported for `/.well-known//x` too — the MAY below licenses path
                // components *appended to* a well-known URI, and there is no
                // well-known URI here to append them to.
                //
                // The MUST is addressed to the application registering the name, so
                // the finding names the party rather than blaming this client.
                //
                // cite(RFC 8615 § 3): "Registered names MUST conform to the "segment-nz" production in [RFC3986]."
                // cite(RFC 3986 § 3.3, label: segment-nz): "segment-nz    = 1*pchar"
                // cite(RFC 8615 § 3): "Also, this specification does not define a format or media type for the resource located at "/.well-known/", and clients should not expect a resource to exist at that location."
                Some(&"") => violation(format!(
                    "Request target path {shown} carries the reserved prefix with an empty name after it: a registered name MUST conform to `segment-nz` (RFC 8615 §3), which is `1*pchar` (RFC 3986 §3.3) and generates no empty segment, so no conforming registration could answer this path — and RFC 8615 §3 defines no format or media type for the resource located at \"/.well-known/\" either. That MUST is addressed to the application registering the name rather than to this client, so this is advice about the path, not a violation"
                )),

                // The same `segment-nz`, measured for what it holds rather than for
                // how long it is. Only the first segment after the prefix is the
                // name: the document's own "This means they cannot contain the "/"
                // character." is about the registered name, and the MAY beside it
                // licenses further path components appended to the well-known URI —
                // so `/.well-known/est/simpleenroll` names `est` and is not a
                // finding.
                //
                // cite(RFC 8615 § 3): "This means they cannot contain the "/" character."
                // cite(RFC 8615 § 3): "Registrations MAY also contain additional information, such as the syntax of additional path components, query strings, and/or fragment identifiers to be appended to the well-known URI"
                Some(name) => {
                    let c = first_non_pchar(name)?;
                    violation(format!(
                        "Request target path {shown} names the well-known resource '{}', which holds {}: a registered name MUST conform to `segment-nz` (RFC 8615 §3) — `segment-nz = 1*pchar` and `pchar = unreserved / pct-encoded / sub-delims / \":\" / \"@\"` (RFC 3986 §3.3) — so no conforming registration could hold this name. That MUST is addressed to the application registering the name rather than to this client, so this is advice about the name, not a violation",
                        shown_in_finding(name),
                        describe_char(c)
                    ))
                }
            }
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Well-Known URI Format")
    }

    fn description(&self) -> &'static str {
        "Reads the request target's path component against RFC 8615's definition of a well-known URI: *\"A well-known URI is a URI [RFC3986] whose path component begins with the characters \"/.well-known/\", provided that the scheme is explicitly defined to support well-known URIs.\"*\n\n**Every finding here is advice, and the rule says so in each message.** RFC 8615 states five BCP 14 requirements and all five are addressed to an application minting or registering a name — it MUST register it, the name MUST conform to `segment-nz`, the name SHOULD be precise, an alternative port MUST be specified by the application, and a registration MAY carry additional path components. **None of them is a requirement on a request target.** The sentences a request can be measured against are definitions, so what this rule reports is that a path is not a well-known URI, never that sending it was forbidden: §1 names an origin's control over its own URI space as the thing this memo takes care not to usurp, and the paths below are ordinary resources of that origin.\n\n**What is reported.**\n\n- **A `.well-known` segment that is not the first one.** §3: *\"Well-known URIs are rooted in the top of the path's hierarchy; they are not well-known by definition in other parts of the path.\"* — with the document's own counter-example, `/foo/.well-known/example`.\n- **A path that is exactly `/.well-known`.** The prefix §1 reserves includes its trailing slash, so this is one character short of it.\n- **An empty name after the prefix** (`/.well-known/`, and `/.well-known//name`). A registered name *\"MUST conform to the \"segment-nz\" production\"*, which is `1*pchar` — a cardinality floor an empty segment does not clear — and §3 adds that it defines no format or media type for the resource at the prefix itself.\n- **A name holding a character `pchar` does not generate.** The same `segment-nz`, read for its alphabet.\n\n**Only the first segment after the prefix is the name.** *\"This means they cannot contain the \"/\" character.\"* is about the registered name, and the MAY beside it licenses *\"the syntax of additional path components, query strings, and/or fragment identifiers to be appended to the well-known URI\"* — so `/.well-known/est/simpleenroll` names `est` and is not a finding.\n\n**The path is read as a path, not as a string.** It is walked as segments, so `/.well-knownfoo` — an ordinary path that happens to begin with the same characters — draws nothing. The percent-encoded `unreserved` octets are decoded first — RFC 3986 §2.4's exception says they can be decoded at any time, needing no component boundary established for them — and the dot segments are removed from the decoded path (§6.2.2.3), so `/a/../.well-known/x` and `/a/%2E%2E/.well-known/x` are the one path they both name, and `%2Ewell-known` and `.well-known` are the one segment §2.3 makes them. Nothing else is decoded, since decoding a delimiter would move the component boundaries (§2.4). Case is **not** normalized: §6.2.2.1 leaves path components case-sensitive, so `/.WELL-KNOWN/x` is a different path.\n\n**The scheme proviso is the second half of the definition.** RFC 8615 updates the `http` and `https` schemes to support well-known URIs and no others; other schemes carry them *\"only when those schemes' definitions explicitly allow it\"*, which the \"Well-Known URI Support\" column of the URI Schemes registry tracks (§5.2). An origin-form target names no scheme and needs none, because an HTTP request's target URI is an `http` or an `https` one either way. An **absolute-form target naming any other scheme** — how a request to a forward proxy is written — draws nothing: which schemes have been added to that column since 2019 is an open registry this rule does not read, so the effect is a finding not made, never a finding made wrongly.\n\n**What this rule declines, and why.**\n\n- **Whether the name is registered.** The registry is Specification Required and §3.1 lets third parties register a widely deployed name, so an unregistered name is a name awaiting a registration, not a defect. No sentence makes requesting one wrong, and there is no list to check it against that would not go stale between releases.\n- **The `SHOULD` for precise names.** *\"Registered names for a specific application SHOULD be correspondingly precise; \"squatting\" on generic terms is not encouraged.\"* — a judgement about a name's meaning, made by the registry's experts.\n- **The port.** *\"Typically, applications will use the default port for the given scheme; if an alternative port is used, it MUST be explicitly specified by the application in question.\"* Deciding it means reading the registration that named the port, which no capture carries.\n- **Whether a resource exists at the prefix.** §3's *\"clients should not expect a resource to exist at that location\"* is lowercase, and §2 makes the BCP 14 keywords apply *\"when, and only when, they appear in all capitals\"*.\n\n**What other rules own.** A malformed percent-encoding anywhere in the request target, and any character outside the set a URI is composed from, are `request_uri_percent_encoding_valid`'s findings, asked of the whole target; the `pchar` check here is the same question at a narrower width, and within a path segment the only characters it adds are `[` and `]`. A fragment on the request target is `request_target_no_fragment`'s, and which of the four request-target forms may carry a path is `request_target_form_valid`'."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 8615",
                section: Some("1"),
                url: "https://www.rfc-editor.org/rfc/rfc8615.html#section-1",
                note: "Introduction — the prefix this memo reserves, trailing slash included; that other schemes carry well-known URIs only where their definitions allow it; and the origin's control over its own URI space",
            },
            crate::rules::SpecRef {
                spec: "RFC 8615",
                section: Some("2"),
                url: "https://www.rfc-editor.org/rfc/rfc8615.html#section-2",
                note: "Notational Conventions — the BCP 14 keywords apply when, and only when, they appear in all capitals, which is why §3's lowercase \"should not expect a resource\" is declined",
            },
            crate::rules::SpecRef {
                spec: "RFC 8615",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc8615.html#section-3",
                note: "Well-Known URIs — the definition and its scheme proviso, the `segment-nz` MUST on a registered name, the MAY for additional path components, and the sentence saying a `.well-known` elsewhere in the path is not one",
            },
            crate::rules::SpecRef {
                spec: "RFC 8615",
                section: Some("3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc8615.html#section-3.1",
                note: "Registering Well-Known URIs — the registry, and that a widely deployed name may be registered by a third party, which is why an unregistered name is not a finding",
            },
            crate::rules::SpecRef {
                spec: "RFC 8615",
                section: Some("5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc8615.html#section-5.1",
                note: "The Well-Known URI Registry — Specification Required, on the advice of experts",
            },
            crate::rules::SpecRef {
                spec: "RFC 8615",
                section: Some("5.2"),
                url: "https://www.rfc-editor.org/rfc/rfc8615.html#section-5.2",
                note: "The URI Schemes Registry — the \"Well-Known URI Support\" column that tracks which schemes carry well-known URIs",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("3.3"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.3",
                note: "Path — `segment-nz = 1*pchar`, what a `pchar` is, and where the path component ends",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("2.3"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-2.3",
                note: "Unreserved Characters — the production, and the equivalence that makes `%2Ewell-known` and `.well-known` the same segment",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("6.2.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2.1",
                note: "Case Normalization — the components other than scheme and host are case-sensitive, so the prefix is matched as written",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("6.2.2.3"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2.3",
                note: "Path Segment Normalization — dot segments are removed before the path's hierarchy is read, and *after* the `unreserved` octets are decoded, so an encoded `%2E%2E` is the dot segment it stands for",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2",
                note: "Request Target — the four forms, two of which carry no path component",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The URI §3 prints for a registered name 'example'"),
                snippet: "GET /.well-known/example HTTP/1.1\nHost: www.example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "Additional path components appended to the name, which §3's MAY licenses",
                ),
                snippet: "GET /.well-known/est/simpleenroll HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("An ordinary path that merely begins with the same characters"),
                snippet: "GET /.well-knownfoo HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Dot segments resolve to the reserved prefix"),
                snippet: "GET /a/../.well-known/security.txt HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("§3's own counter-example — not at the top of the path's hierarchy"),
                snippet: "GET /foo/.well-known/example HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The reserved prefix without its trailing slash"),
                snippet: "GET /.well-known HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("No name after the prefix — `segment-nz` is `1*pchar`"),
                snippet: "GET /.well-known/ HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A name holding a character `pchar` does not generate"),
                snippet: "GET /.well-known/a[b] HTTP/1.1\nHost: example.com",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &WellKnownUriSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn check(uri: &str) -> Option<Violation> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = uri.into();
        let config =
            crate::test_helpers::make_test_config_with_severity("well_known_uri_syntax", "warn");
        crate::test_helpers::run_rule(
            &WellKnownUriSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
    }

    fn message(uri: &str) -> Option<String> {
        check(uri).map(|v| v.message)
    }

    #[rstest]
    // The document's own worked example, in both forms a target can be written.
    #[case("/.well-known/example")]
    #[case("http://www.example.com/.well-known/example")]
    #[case("https://example.com/.well-known/security.txt")]
    // §3's MAY: further path components are appended to the well-known URI, so
    // the name is `est` and the slash after it is not a defect.
    #[case("/.well-known/est/simpleenroll")]
    // A query is outside the path component the definition is about.
    #[case("/.well-known/openid-configuration?x=1")]
    // Dot segments resolve to the prefix.
    #[case("/a/../.well-known/security.txt")]
    // The characters of the segment, percent-encoded: `%2E` is `.` and `%2D` is
    // `-`, and RFC 3986 §2.3 makes the result the same segment.
    #[case("/%2Ewell%2Dknown/security.txt")]
    // Segment-aware: these merely begin with, or contain, the same characters.
    #[case("/.well-knownfoo")]
    #[case("/foo/.well-knownbar/baz")]
    // Not the reserved segment at all: the path component is case-sensitive.
    #[case("/.WELL-KNOWN/x")]
    // No path component to read.
    #[case("*")]
    #[case("example.com:443")]
    #[case("/")]
    #[case("/foo/bar")]
    // `pchar` admits every one of these in a name.
    #[case("/.well-known/a:b@c%20d")]
    #[case("/.well-known/a,b;c=d!e$f&g'h(i)j*k+l")]
    fn nothing_to_report(#[case] uri: &str) {
        assert_eq!(message(uri), None, "expected silence for {uri}");
    }

    #[test]
    fn a_segment_below_the_root_is_advice_not_a_violation() {
        let v = check("/foo/.well-known/example").expect("reported");
        assert_eq!(v.rule, "well_known_uri_syntax");
        assert_eq!(
            v.message,
            "Request target path '/foo/.well-known/example' carries a `.well-known` segment inside the path rather than at the top of its hierarchy, so it is not a well-known URI: RFC 8615 §3 defines one as a URI whose path component *begins with* the characters \"/.well-known/\", and says of this exact shape that \"/.well-known/example\" is a well-known URI, whereas \"/foo/.well-known/example\" is not. The path names an ordinary resource the origin controls (RFC 8615 §1), and RFC 8615 states no requirement on a request target, so this is advice — an application looking for site-wide metadata will not find it here — and not a violation"
        );
    }

    /// Both normalizations put a second string in the finding, which is why the
    /// parenthetical names normalization rather than dot segments: the second
    /// case here has no dot segment written in it.
    #[rstest]
    #[case("/foo/./.well-known/example", "/foo/.well-known/example")]
    #[case("/foo/%2Ewell-known/example", "/foo/.well-known/example")]
    fn a_normalized_path_is_named_beside_the_one_that_was_written(
        #[case] written: &str,
        #[case] normalized: &str,
    ) {
        let v = check(written).expect("reported");
        assert!(
            v.message.starts_with(&format!(
                "Request target path '{written}' (which normalizes to '{normalized}') carries a `.well-known` segment"
            )),
            "{}",
            v.message
        );
    }

    /// **Two spellings of one path used to get two answers.** § 2.4 lets an
    /// `unreserved` octet be decoded at any time, so `%2E` is the period it
    /// stands for and an encoded dot segment is a dot segment. The rule removed
    /// the dot segments from the value *as written* and decoded per segment
    /// afterwards, so `/foo/../.well-known/x` was clean and
    /// `/foo/%2E%2E/.well-known/x` — the same path — was reported as a prefix
    /// buried in the hierarchy.
    ///
    /// The claim is agreement, not silence: the third pair below is buried in
    /// both spellings, because removing its single `.` leaves the `a` in front.
    #[rstest]
    #[case("/foo/../.well-known/x", "/foo/%2E%2E/.well-known/x")]
    #[case("/foo/../.well-known/x", "/foo/%2e%2e/.well-known/x")]
    #[case("/foo/../%2Ewell-known/x", "/foo/%2E%2E/%2Ewell-known/x")]
    #[case("/a/./.well-known/x", "/a/%2E/.well-known/x")]
    #[case("/.well-known/", "/%2Ewell-known/")]
    fn an_encoded_dot_segment_is_the_dot_segment_it_stands_for(
        #[case] plain: &str,
        #[case] encoded: &str,
    ) {
        let (a, b) = (message(plain), message(encoded));
        assert_eq!(
            a.is_some(),
            b.is_some(),
            "{plain} and {encoded} are one path and got different verdicts:\n  {a:?}\n  {b:?}"
        );
    }

    #[test]
    fn the_prefix_without_its_trailing_slash_is_advice() {
        let v = check("/.well-known").expect("reported");
        assert_eq!(
            v.message,
            "Request target path '/.well-known' is the reserved prefix one character short: RFC 8615 §1 reserves \"/.well-known/\" with its trailing slash, and §3 defines a well-known URI as one whose path component begins with those characters, so this path names an ordinary resource rather than a well-known one. RFC 8615 states no requirement on a request target, so this is advice, not a violation"
        );
        // The query is stripped before the path is read, so this is the same
        // path and the same finding.
        assert_eq!(message("/.well-known?x=1"), message("/.well-known"));
    }

    #[rstest]
    #[case("/.well-known/")]
    #[case("/.well-known//name")]
    fn an_empty_name_names_no_registration(#[case] uri: &str) {
        let v = check(uri).expect("reported");
        assert!(
            v.message.contains(
                "carries the reserved prefix with an empty name after it: a registered name MUST conform to `segment-nz` (RFC 8615 §3), which is `1*pchar` (RFC 3986 §3.3) and generates no empty segment"
            ),
            "{}",
            v.message
        );
        assert!(
            v.message.contains("advice about the path, not a violation"),
            "{}",
            v.message
        );
    }

    #[test]
    fn a_name_no_registration_could_hold_is_reported_by_its_character() {
        let v = check("/.well-known/a[b]").expect("reported");
        assert_eq!(
            v.message,
            "Request target path '/.well-known/a[b]' names the well-known resource 'a[b]', which holds '[': a registered name MUST conform to `segment-nz` (RFC 8615 §3) — `segment-nz = 1*pchar` and `pchar = unreserved / pct-encoded / sub-delims / \":\" / \"@\"` (RFC 3986 §3.3) — so no conforming registration could hold this name. That MUST is addressed to the application registering the name rather than to this client, so this is advice about the name, not a violation"
        );
        // An octet outside the printable range is named by its value rather than
        // put into the message.
        let v = check("/.well-known/a\u{7f}b").expect("reported");
        assert!(v.message.contains("which holds 0x7F"), "{}", v.message);
    }

    #[test]
    fn only_the_first_segment_after_the_prefix_is_the_name() {
        // The offending character is in a later segment, which §3's MAY leaves
        // to the registration rather than to `segment-nz`.
        assert_eq!(message("/.well-known/est/a[b]"), None);
    }

    #[test]
    fn an_absolute_form_target_naming_another_scheme_is_not_measured() {
        // The proviso: RFC 8615 updates `http` and `https`, and this rule does
        // not read the registry column that would say which others were added.
        assert_eq!(message("ftp://example.com/foo/.well-known/example"), None);
        // A host called `http` in an authority-form target is not a scheme, and
        // that form carries no path either way.
        assert_eq!(message("http:443"), None);
        // The two schemes this document updates are matched without regard to
        // case, because a scheme is compared that way.
        assert!(check("HTTPS://example.com/foo/.well-known/example").is_some());
    }

    /// The predicate, not the decoder — that moved to `helpers::uri` with its
    /// own tests. What stays here is the question this rule asks of it: an
    /// escaped spelling of the reserved segment is the reserved segment, and an
    /// escaped delimiter does not make an ordinary segment into it.
    #[test]
    fn an_escaped_spelling_of_the_reserved_segment_is_the_reserved_segment() {
        assert!(is_well_known_segment(".well-known"));
        assert!(is_well_known_segment("%2Ewell%2Dknown"));
        assert!(is_well_known_segment("%2ewell-known"));
        // `%2F` is a `gen-delims` octet and stays encoded, so this is a segment
        // whose name merely contains the text — not the reserved one.
        assert!(!is_well_known_segment("%2Fwell-known"));
        assert!(!is_well_known_segment(".well-knownfoo"));
    }

    #[test]
    fn a_non_ascii_path_is_read_rather_than_panicked_on() {
        assert_eq!(message("/café/%é/x"), None);
        assert!(message("/.well-known/caf%é").is_some());
    }

    #[test]
    fn message_and_id() {
        let rule = WellKnownUriSyntax;
        assert_eq!(rule.id(), "well_known_uri_syntax");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["well_known_uri_syntax"]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
