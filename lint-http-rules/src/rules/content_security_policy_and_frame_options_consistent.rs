// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::content_security_policy::{
    CONTENT_SECURITY_POLICY_FRAME_ANCESTORS_CONFLICTING, CSP3_6_4_2,
};
use crate::violations::ViolationDef;

/// One entry for five shapes of the same disagreement.
///
/// `DENY` beside `'self'`, `SAMEORIGIN` beside `'none'`,
/// and three ways an `ALLOW-FROM` origin can fall outside what
/// `frame-ancestors` lists are one claim with one repair: a server wrote two
/// framing policies into one response and they do not agree. Which of the five
/// it was is the message's to say.
static DECLARED: &[&ViolationDef] = &[&CONTENT_SECURITY_POLICY_FRAME_ANCESTORS_CONFLICTING];

pub struct ContentSecurityPolicyAndFrameOptionsConsistent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const HTML_SPECULATIVE_LOADING: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "HTML Speculative Loading",
    section: None,
    url:
        "https://html.spec.whatwg.org/multipage/speculative-loading.html#the-x-frame-options-header",
    note: "HTML Living Standard — `X-Frame-Options` header and its relation to `frame-ancestors`",
};
const MDN_X_FRAME_OPTIONS: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN X-Frame-Options",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options",
    note: "`X-Frame-Options` — legacy header with values `DENY`, `SAMEORIGIN`, and the obsolete `ALLOW-FROM`. Note: `ALLOW-FROM` is deprecated and not supported by most modern browsers — prefer using CSP's `frame-ancestors` for origin-specific framing policies",
};

/// What a `frame-ancestors` directive permits, across every enforced policy in
/// the response.
#[derive(Default)]
struct FrameAncestors {
    /// `'none'` was listed: nothing may frame the resource.
    none: bool,
    /// `'self'` was listed: the resource's own origin may frame it.
    own_origin: bool,
    /// Every other source expression listed, as written: a host-source or a
    /// scheme-source, matched by [`source_matches`].
    origins: Vec<String>,
}

impl FrameAncestors {
    /// Read the directive from the response, or `None` where no enforced policy
    /// names it.
    ///
    /// Report-only policies are not read: they change no framing decision, so a
    /// disagreement with one is not a disagreement about what happens.
    // cite(CSP3 § 6.4.2): "The frame-ancestors directive restricts the URLs which can embed the resource using frame, iframe, object, or embed."
    fn of(headers: &hyper::HeaderMap) -> Option<Self> {
        let mut policy = Self::default();
        let mut named = false;

        // Policies before directives, and one directive per policy. A line is
        // a comma-delimited series of policies -- two lines a recipient joined
        // with a comma are one -- so a `;` split alone read the `'none'` of a
        // second policy's `default-src` as a frame-ancestors source. Within a
        // policy only the first `frame-ancestors` is kept: a user agent skips a
        // directive whose name the policy already holds.
        //
        // cite(CSP3 § 2.2): "a comma-delimited series of serialized CSPs"
        // cite(CSP3 § 2.2.1): "directive set contains a directive whose name is directive name"
        for directive in crate::helpers::headers::field_lines(headers, "content-security-policy")
            .flat_map(crate::helpers::list::list_members)
            .filter_map(|policy| {
                crate::helpers::list::parse_semicolon_list(policy).find(|directive| {
                    directive
                        .split_ascii_whitespace()
                        .next()
                        .is_some_and(|name| name.eq_ignore_ascii_case("frame-ancestors"))
                })
            })
        {
            let mut parts = directive.split_ascii_whitespace();
            parts.next();
            // The directive is named even when it lists nothing, and a
            // `frame-ancestors` with no source expression permits no framing at
            // all — which is a finding for the rule that owns the grammar, not a
            // reason to read the header as absent here.
            named = true;

            for member in parts {
                // Keyword sources are written in single quotes; a serialized
                // origin is not. An unbalanced quote is left as written, since
                // it matches no keyword either way.
                let source = member
                    .strip_prefix('\'')
                    .and_then(|rest| rest.strip_suffix('\''))
                    .unwrap_or(member);
                if source.eq_ignore_ascii_case("none") {
                    policy.none = true;
                } else if source.eq_ignore_ascii_case("self") {
                    policy.own_origin = true;
                } else {
                    policy.origins.push(source.to_string());
                }
            }
        }

        named.then_some(policy)
    }
}

/// The framing policy an `X-Frame-Options` field value states.
// cite(HTML Speculative Loading § 7.7): "The `X-Frame-Options` HTTP response header is a way of controlling whether and how a Document may be loaded inside of a child navigable."
enum FrameOptions<'a> {
    /// `DENY`.
    Deny,
    /// `SAMEORIGIN`.
    SameOrigin,
    /// `ALLOW-FROM <origin>`, carrying the origin exactly as written — which is
    /// what a finding quotes back, while the comparison uses it without its
    /// trailing slash.
    AllowFrom(&'a str),
    /// Anything else, including an `ALLOW-FROM` naming no origin.
    Unrecognized,
}

impl<'a> FrameOptions<'a> {
    fn of(value: &'a str) -> Self {
        if value.eq_ignore_ascii_case("DENY") {
            return Self::Deny;
        }
        if value.eq_ignore_ascii_case("SAMEORIGIN") {
            return Self::SameOrigin;
        }
        let Some(rest) = value
            .get(..10)
            .filter(|head| head.eq_ignore_ascii_case("ALLOW-FROM"))
            .map(|_| value[10..].trim_start())
        else {
            return Self::Unrecognized;
        };
        if rest.is_empty() {
            return Self::Unrecognized;
        }
        Self::AllowFrom(rest)
    }
}

impl ContentSecurityPolicyAndFrameOptionsConsistent {
    /// Whether the one origin `ALLOW-FROM` permits is an origin the policy
    /// permits too.
    ///
    /// **The comparison is CSP's own, run on the URL a user agent would match.**
    /// § 6.4.2.1 parses an ancestor's serialized origin into a URL and asks
    /// § 6.7.2.7 whether the source list matches it, so the question for an
    /// `ALLOW-FROM` origin is whether the policy would let that origin frame
    /// the resource -- and a wildcard host, a source naming no scheme, a scheme
    /// alone, a default port written out and an `http` self-origin upgraded to
    /// `https` all say yes to an origin no string in the list spells.
    ///
    /// **The self-origin is the target's, and the target may not say its
    /// scheme.** An origin-form target leaves it to the connection (RFC 9112
    /// § 3.3), so the policy is read under both schemes that could have been,
    /// and a disagreement is reported only when it holds under each.
    ///
    // cite(CSP3 § 6.4.2.1): "Let origin be the result of executing the URL parser on the ASCII serialization of document’s origin."
    // cite(CSP3 § 6.4.2.1): "If § 6.7.2.7 Does url match source list in origin with redirect count? returns Does Not Match when executed upon origin, this directive’s value, self-origin, and 0, return "Blocked"."
    fn allow_from_defect(
        &self,
        csp: &FrameAncestors,
        as_written: &str,
        tx: &crate::http_transaction::HttpTransaction,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        if csp.none {
            return Some(ctx.report_with(&CONTENT_SECURITY_POLICY_FRAME_ANCESTORS_CONFLICTING, format!(
                "X-Frame-Options: ALLOW-FROM {} permits framing but Content-Security-Policy frame-ancestors is 'none'",
                as_written
            )));
        }

        // A value naming no origin is the field's own finding, and there is no
        // URL here to match.
        let allowed = as_written.strip_suffix('/').unwrap_or(as_written);
        let url = OriginUrl::parse(allowed)?;
        let selves = OriginUrl::of_target(tx);

        // Three answers per self-origin: matched, not matched, and a source that
        // needs a self-origin the message does not name.
        let included = |self_origin: Option<&OriginUrl>| -> Option<bool> {
            let mut unknown = false;
            if csp.own_origin {
                match self_origin {
                    Some(origin) if origin.matches_as_self(&url) => return Some(true),
                    Some(_) => {}
                    None => unknown = true,
                }
            }
            for source in &csp.origins {
                match source_matches(source, &url, self_origin) {
                    Some(true) => return Some(true),
                    Some(false) => {}
                    None => unknown = true,
                }
            }
            (!unknown).then_some(false)
        };
        let excluded = match selves.as_slice() {
            [] => included(None) == Some(false),
            _ => selves
                .iter()
                .all(|origin| included(Some(origin)) == Some(false)),
        };
        if !excluded {
            return None;
        }

        if !csp.origins.is_empty() {
            return Some(ctx.report_with(&CONTENT_SECURITY_POLICY_FRAME_ANCESTORS_CONFLICTING, format!(
                "X-Frame-Options: ALLOW-FROM {} is not included in Content-Security-Policy frame-ancestors",
                as_written
            )));
        }
        let origin = match selves.as_slice() {
            [one] => one.to_string(),
            [first, ..] => format!("{} under either scheme", first.authority()),
            [] => return None,
        };
        Some(ctx.report_with(&CONTENT_SECURITY_POLICY_FRAME_ANCESTORS_CONFLICTING, format!(
            "X-Frame-Options: ALLOW-FROM {} does not match Content-Security-Policy frame-ancestors 'self' (origin {})",
            as_written, origin
        )))
    }
}

/// A URL parsed from a serialized origin, as CSP's matching algorithm reads
/// one: the scheme and host in lower case, and a port that is `None` where it
/// is the scheme's default. That last is the URL parser's normalization, and it
/// is what makes `https://a.example:443` and `https://a.example` one URL.
struct OriginUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl OriginUrl {
    fn parse(value: &str) -> Option<Self> {
        let serialized = crate::helpers::origin::ascii_serialized_origin(value)?;
        // `null` is an opaque origin, and no URL.
        let marker = crate::helpers::scheme::scheme_authority_marker(&serialized)?;
        let (host, port) =
            crate::helpers::authority::split_host_and_port(&serialized[marker + 3..]);
        let port = match port {
            Some(digits) => Some(crate::helpers::authority::port_number(digits)?),
            None => None,
        };
        Some(Self {
            scheme: serialized[..marker].to_string(),
            host: host.to_string(),
            port,
        })
    }

    /// The target's origin under each scheme the message allows it: the one an
    /// absolute-form target states, or both where it states none.
    fn of_target(tx: &crate::http_transaction::HttpTransaction) -> Vec<Self> {
        let Some(authority) = crate::helpers::request_target::target_uri_authority(
            &tx.request.uri,
            &tx.request.headers,
        ) else {
            return Vec::new();
        };
        let (_, host_and_port) = crate::helpers::authority::split_userinfo(&authority);
        let stated = crate::helpers::origin::extract_origin_if_absolute(&tx.request.uri)
            .and(crate::helpers::scheme::scheme_prefix(&tx.request.uri));
        let schemes: &[&str] = match stated {
            Some(ref scheme) => std::slice::from_ref(scheme),
            None => &["http", "https"],
        };
        schemes
            .iter()
            .filter_map(|scheme| Self::parse(&format!("{scheme}://{host_and_port}")))
            .collect()
    }

    fn default_port(scheme: &str) -> Option<u16> {
        match scheme {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            _ => None,
        }
    }

    fn authority(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{port}", self.host),
            None => self.host.clone(),
        }
    }

    /// § 6.7.2.8's `'self'` arm, with this origin as the self-origin.
    // cite(CSP3 § 6.7.2.8): "origin and url’s origin are same origin"
    // cite(CSP3 § 6.7.2.8): "origin’s host is the same as url’s host, origin’s port and url’s port are either the same or the default ports for their respective schemes, and one or more of the following conditions is met:"
    // cite(CSP3 § 6.7.2.8): "origin’s scheme is "http" and url’s scheme is "http" or "ws""
    fn matches_as_self(&self, url: &OriginUrl) -> bool {
        if self.scheme == url.scheme && self.host == url.host && self.port == url.port {
            return true;
        }
        // Both ports are `None` exactly where each is its own scheme's default.
        self.host == url.host
            && self.port == url.port
            && (matches!(url.scheme.as_str(), "https" | "wss")
                || (self.scheme == "http" && matches!(url.scheme.as_str(), "http" | "ws")))
    }
}

impl std::fmt::Display for OriginUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}", self.scheme, self.authority())
    }
}

/// § 6.7.2.8 for one source expression other than `'self'` and `'none'`, or
/// `None` where the answer needs a self-origin the message does not name.
// cite(CSP3 § 6.7.2.8): "If expression is the string "*", return "Matches" if one or more of the following conditions is met:"
// cite(CSP3 § 6.7.2.8): "If expression has a scheme-part, and it does not scheme-part match url’s scheme, return "Does Not Match"."
// cite(CSP3 § 6.7.2.8): "If expression matches the scheme-source grammar, return "Matches"."
// cite(CSP3 § 6.7.2.8): "If expression does not have a scheme-part, and origin’s scheme does not scheme-part match url’s scheme, return "Does Not Match"."
// cite(CSP3 § 6.7.2.8): "If expression’s host-part does not host-part match url’s host, return "Does Not Match"."
// cite(CSP3 § 6.7.2.8): "If port-part does not port-part match url, return "Does Not Match"."
fn source_matches(source: &str, url: &OriginUrl, self_origin: Option<&OriginUrl>) -> Option<bool> {
    if source == "*" {
        if matches!(url.scheme.as_str(), "http" | "https") {
            return Some(true);
        }
        return self_origin.map(|origin| origin.scheme == url.scheme);
    }
    // A keyword, a nonce or a hash matches no URL.
    if source.starts_with('\'') {
        return Some(false);
    }
    let (scheme, rest) = match source.find("://") {
        Some(i) => (Some(&source[..i]), &source[i + 3..]),
        None => match source.strip_suffix(':') {
            Some(scheme) if crate::helpers::scheme::validate_scheme_name(scheme).is_ok() => {
                return Some(scheme_part_matches(scheme, &url.scheme));
            }
            _ => (None, source),
        },
    };
    let host_end = rest.find([':', '/']).unwrap_or(rest.len());
    let (host, after_host) = rest.split_at(host_end);
    let (port, path) = match after_host.strip_prefix(':') {
        Some(port_and_path) => {
            let end = port_and_path.find('/').unwrap_or(port_and_path.len());
            (Some(&port_and_path[..end]), &port_and_path[end..])
        }
        None => (None, after_host),
    };
    if host.is_empty() {
        return Some(false);
    }
    match (scheme, self_origin) {
        (Some(scheme), _) if !scheme_part_matches(scheme, &url.scheme) => return Some(false),
        (None, Some(origin)) if !scheme_part_matches(&origin.scheme, &url.scheme) => {
            return Some(false)
        }
        (None, None) => return None,
        _ => {}
    }
    Some(
        host_part_matches(host, &url.host)
            && port_part_matches(port, url)
            && path_part_matches_root(path),
    )
}

/// § 6.7.2.9: a scheme matches itself, and an insecure scheme matches its
/// secure upgrade.
// cite(CSP3 § 6.7.2.9): "A is an ASCII case-insensitive match for "http", and B is an ASCII case-insensitive match for "https"."
fn scheme_part_matches(a: &str, b: &str) -> bool {
    let a = a.to_ascii_lowercase();
    a == b
        || (a == "http" && b == "https")
        || (a == "ws" && matches!(b, "wss" | "http" | "https"))
        || (a == "wss" && b == "https")
}

/// § 6.7.2.10: `*`, a `*.` suffix, or the host itself, and never an address.
// cite(CSP3 § 6.7.2.10): "If host is not a domain, return "Does Not Match"."
// cite(CSP3 § 6.7.2.10): "Let remaining be pattern with the leading U+002A (*) removed and ASCII lowercased."
fn host_part_matches(pattern: &str, host: &str) -> bool {
    let address = host.starts_with('[') || host.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    if address {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    match pattern.strip_prefix('*') {
        Some(remaining) if remaining.starts_with('.') => {
            host.ends_with(&remaining.to_ascii_lowercase())
        }
        _ => pattern.eq_ignore_ascii_case(host),
    }
}

/// § 6.7.2.11: `*`, the URL's port, or -- where the URL's is the default --
/// that default written out. A source naming no port matches only the default.
// cite(CSP3 § 6.7.2.11): "If input is equal to "*", return "Matches"."
// cite(CSP3 § 6.7.2.11): "If normalizedInput equals url’s port, return "Matches"."
// cite(CSP3 § 6.7.2.11): "If normalizedInput equals defaultPort, return "Matches"."
fn port_part_matches(input: Option<&str>, url: &OriginUrl) -> bool {
    let Some(input) = input else {
        return url.port.is_none();
    };
    if input == "*" {
        return true;
    }
    let Some(port) = crate::helpers::authority::port_number(input) else {
        return false;
    };
    url.port == Some(port)
        || (url.port.is_none() && OriginUrl::default_port(&url.scheme) == Some(port))
}

/// § 6.7.2.12 against the one path a URL parsed from an origin has, `/`: it
/// splits into two empty pieces, so a source's path matches only when every
/// piece it keeps is empty too -- `/` does, `/app/` does not.
// cite(CSP3 § 6.7.2.12): "If path A is the empty string, return "Matches"."
// cite(CSP3 § 6.7.2.12): "Let exact match be false if the final character of path A is the U+002F SOLIDUS character (/), and true otherwise."
// cite(CSP3 § 6.7.2.12): "If path list A has more items than path list B, return "Does Not Match"."
fn path_part_matches_root(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    let mut pieces: Vec<&str> = path.split('/').collect();
    if path.ends_with('/') {
        pieces.pop();
    } else if pieces.len() != 2 {
        return false;
    }
    // A percent-encoded piece decodes to at least one octet, so only an
    // empty piece matches the root's.
    pieces.len() <= 2 && pieces.iter().all(|piece| piece.is_empty())
}

impl RuleMeta for ContentSecurityPolicyAndFrameOptionsConsistent {
    fn id(&self) -> &'static str {
        "content_security_policy_and_frame_options_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Detect contradictory framing directives between `Content-Security-Policy` (the `frame-ancestors` directive) and `X-Frame-Options`. These headers express framing restrictions; when they conflict, they create ambiguity that may cause different user agents to allow or block framing inconsistently.\n\nA `DENY` beside a policy that names any origin other than `'self'` is not reported: no conforming `X-Frame-Options` value states such a policy, and `DENY` is the fallback that permits a user agent predating `frame-ancestors` nothing the policy forbids.\n\n**An `ALLOW-FROM` origin is matched the way CSP matches it**, not compared as text: a user agent parses the ancestor's origin into a URL and asks whether any source expression matches it (CSP3 §6.4.2.1, §6.7.2.8). So a wildcard host (`https://*.example.com`), a source with no scheme, a scheme alone (`https:`), `*`, a default port written out on either side, and a `'self'` whose `http` origin the `https` origin upgrades are all agreement, while a source carrying a path never matches an origin, whose path is `/`. `'self'` is the request target's origin; where the target does not state its scheme, a disagreement is reported only if it holds under both `http` and `https`.\n\nNote: this check considers only enforceable header-delivered CSP policies (`Content-Security-Policy`); `Content-Security-Policy-Report-Only` is ignored because it does not itself change framing enforcement."
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[CSP3_6_4_2, HTML_SPECULATIVE_LOADING, MDN_X_FRAME_OPTIONS]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Security-Policy: frame-ancestors 'none'\n# No X-Frame-Options header present",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Security-Policy: frame-ancestors https://example.com\nX-Frame-Options: ALLOW-FROM https://example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Security-Policy: frame-ancestors https://*.example.com\nX-Frame-Options: ALLOW-FROM https://cms.example.com\n# The wildcard host matches the origin ALLOW-FROM names, so both policies permit it",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Security-Policy: frame-ancestors 'self' https://cms.example\nX-Frame-Options: DENY\n# No X-Frame-Options value states a list of origins, so DENY is the fallback for user agents that predate frame-ancestors",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Security-Policy: frame-ancestors 'none'\nX-Frame-Options: SAMEORIGIN\n# CSP disallows all framing but XFO says allow same origin -> contradiction",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Security-Policy: frame-ancestors 'self'\nX-Frame-Options: DENY\n# CSP allows same-origin framing while XFO denies all framing -> contradiction",
            },
        ]
    }
}

impl Rule for ContentSecurityPolicyAndFrameOptionsConsistent {
    fn needs_response(&self) -> bool {
        true
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
            let resp = tx.response.as_ref()?;

            // With no frame-ancestors directive there is nothing to compare
            // X-Frame-Options against.
            let csp = FrameAncestors::of(&resp.headers)?;

            // The two headers answer the same question, and a browser that honours
            // `frame-ancestors` ignores `X-Frame-Options` — so when they disagree, one of
            // them is a statement of intent that nothing enforces. That precedence (and
            // why only enforced CSP counts, so report-only is skipped above) is
            // §6.4.2.2's; the two purpose cites give each header's own scope.
            // cite(CSP3 § 6.4.2.2): "the frame-ancestors directive overrides the ``X-Frame-Options`` header."
            // cite(CSP3 § 6.4.2): "The frame-ancestors directive restricts the URLs which can embed the resource using frame, iframe, object, or embed."
            // cite(HTML Speculative Loading § 7.7): "The `X-Frame-Options` HTTP response header is a way of controlling whether and how a Document may be loaded inside of a child navigable."
            //
            // A repeated X-Frame-Options is the duplicate-header rule's finding, and
            // an unreadable one belongs to the rule that owns the field: either way
            // there is no single policy here to compare.
            if resp.headers.get_all("x-frame-options").iter().count() != 1 {
                return None;
            }
            let xfo =
                crate::helpers::headers::get_header_str(&resp.headers, "x-frame-options")?.trim();

            match FrameOptions::of(xfo) {
                // DENY forbids framing, so it contradicts a policy that permits
                // any -- but only a policy of `'self'` alone has an
                // `X-Frame-Options` that states it. HTML gives the header two
                // conforming values, so a policy naming any other origin has
                // none, and `DENY` is the fallback that permits nothing the
                // policy forbids to a user agent that predates it: the
                // backwards-compatible deployment the override exists for.
                // cite(HTML Speculative Loading § 7.7): "X-Frame-Options = "DENY" / "SAMEORIGIN""
                // cite(CSP3 § 6.4.2.2): "In order to allow backwards-compatible deployment, the frame-ancestors directive overrides the ``X-Frame-Options`` header."
                FrameOptions::Deny => {
                    (!csp.none && csp.own_origin && csp.origins.is_empty()).then(|| {
                        ctx.report_with(&CONTENT_SECURITY_POLICY_FRAME_ANCESTORS_CONFLICTING, "X-Frame-Options: DENY forbids the same-origin framing Content-Security-Policy frame-ancestors 'self' permits; SAMEORIGIN states the same policy as 'self'".into())
                    })
                }
                // SAMEORIGIN permits same-origin framing, so only an outright
                // 'none' contradicts it.
                FrameOptions::SameOrigin => csp.none.then(|| {
                    ctx.report_with(&CONTENT_SECURITY_POLICY_FRAME_ANCESTORS_CONFLICTING, "Content-Security-Policy frame-ancestors: 'none' forbids framing while X-Frame-Options: SAMEORIGIN permits same-origin frames".into())
                }),
                FrameOptions::AllowFrom(as_written) => {
                    self.allow_from_defect(&csp, as_written, tx, ctx)
                }
                // A form no user agent implements says nothing to contradict;
                // reporting it belongs to the rule that owns the field.
                FrameOptions::Unrecognized => None,
            }
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentSecurityPolicyAndFrameOptionsConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&[
            "content_security_policy_and_frame_options_consistent",
        ])
    }

    #[rstest]
    #[case("frame-ancestors 'none'", "SAMEORIGIN", true)]
    #[case("frame-ancestors 'self'", "DENY", true)]
    #[case("frame-ancestors https://a", "ALLOW-FROM https://b", true)]
    #[case("frame-ancestors https://a https://b", "ALLOW-FROM https://b", false)]
    #[case("frame-ancestors 'none'", "DENY", false)]
    // No `X-Frame-Options` states a policy naming another origin, so `DENY`
    // is the nearest fallback for a user agent that predates the directive.
    #[case("frame-ancestors 'self' https://a https://*.b", "DENY", false)]
    #[case("frame-ancestors https://partner", "DENY", false)]
    #[case("frame-ancestors 'self' https://a", "SAMEORIGIN", false)]
    // The test target is `http://example/`, and CSP's `'self'` matches that
    // host's secure upgrade: the two agree.
    #[case("frame-ancestors 'self'", "ALLOW-FROM https://example", false)]
    #[case("frame-ancestors 'self'", "ALLOW-FROM https://other", true)]
    // A line holding two policies, which is what two lines become once a
    // recipient joins them. The second policy's sources are not the first's
    // directive's: `'none'` here belongs to `default-src`, and was read as
    // forbidding the framing `'self'` permits.
    #[case("frame-ancestors 'self', default-src 'none'", "SAMEORIGIN", false)]
    #[case("frame-ancestors 'self', script-src 'self'", "DENY", true)]
    #[case("default-src 'self', frame-ancestors 'self'", "DENY", true)]
    #[case("default-src 'self', frame-ancestors 'none'", "SAMEORIGIN", true)]
    // Only the first directive of a name counts in a policy.
    #[case("frame-ancestors 'self'; frame-ancestors 'none'", "SAMEORIGIN", false)]
    #[case("frame-ancestors 'none'; frame-ancestors 'self'", "SAMEORIGIN", true)]
    fn consistency_cases(#[case] csp: &str, #[case] xfo: &str, #[case] expect_violation: bool) {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", csp),
            ("x-frame-options", xfo),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for csp='{}' xfo='{}'",
                csp,
                xfo
            );
        } else {
            assert!(
                v.is_none(),
                "unexpected violation {:?} for csp='{}' xfo='{}'",
                v,
                csp,
                xfo
            );
        }
    }

    #[test]
    fn non_utf8_headers_are_ignored_by_this_rule() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        // make a non-utf8 header value for XFO
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "frame-ancestors 'self'",
        )]);
        headers.insert("x-frame-options", bad);
        tx.response.as_mut().unwrap().headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    /// The `ALLOW-FROM` origin is matched against `frame-ancestors` the way
    /// CSP § 6.7.2.8 matches the URL a user agent parses from an ancestor's
    /// origin: a default port is no port, a wildcard host, a source with no
    /// scheme, a scheme alone and `*` match, a secure upgrade matches and a
    /// downgrade does not, and a source with a path never matches an origin,
    /// whose path is `/`.
    #[rstest]
    #[case::default_port_on_the_source("https://a.example:443", "https://a.example", false)]
    #[case::default_port_on_the_origin("https://a.example", "https://a.example:443", false)]
    #[case::any_port("https://a.example:*", "https://a.example:8443", false)]
    #[case::other_port("https://a.example", "https://a.example:8443", true)]
    #[case::wildcard_host("https://*.example.com", "https://a.example.com", false)]
    #[case::wildcard_is_not_the_apex("https://*.example.com", "https://example.com", true)]
    #[case::wildcard_other("https://*.b.example", "https://a.example", true)]
    #[case::no_scheme_same_as_self("example", "http://example", false)]
    #[case::no_scheme_upgraded_from_self("example", "https://example", false)]
    #[case::scheme_only("https:", "https://a.example", false)]
    #[case::scheme_upgrade("http:", "https://a.example", false)]
    #[case::scheme_downgrade("https:", "http://a.example", true)]
    #[case::host_downgrade("https://a.example", "http://a.example", true)]
    #[case::star("*", "https://a.example", false)]
    #[case::root_path("https://a.example/", "https://a.example", false)]
    #[case::path("https://a.example/app/", "https://a.example", true)]
    #[case::keyword("'unsafe-inline'", "https://a.example", true)]
    #[case::address("*", "https://192.0.2.1", false)]
    #[case::address_by_wildcard_host("https://*", "https://192.0.2.1", true)]
    fn a_source_matches_the_origin_as_csp_matches_it(
        #[case] source: &str,
        #[case] allow_from: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let csp = format!("frame-ancestors {source}");
        let xfo = format!("ALLOW-FROM {allow_from}");
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", csp.as_str()),
            ("x-frame-options", xfo.as_str()),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{csp} / {xfo} -> {v:?}");
    }

    /// `'self'` is the target's origin, which an origin-form target states
    /// only in part: its scheme is the connection's. A disagreement is reported
    /// only where it holds under both schemes.
    #[rstest]
    #[case::stated_default_port("https://example.com:443/p", "https://example.com", false)]
    #[case::origin_form_secure_origin("/p", "https://example.com", false)]
    #[case::origin_form_insecure_origin("/p", "http://example.com", false)]
    #[case::origin_form_other_host("/p", "https://other.example", true)]
    #[case::secure_target_insecure_origin("https://example.com/p", "http://example.com", true)]
    fn self_is_the_target_origin(
        #[case] target: &str,
        #[case] allow_from: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = target.to_string();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("host", "example.com")]);
        let xfo = format!("ALLOW-FROM {allow_from}");
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'self'"),
            ("x-frame-options", xfo.as_str()),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{target} / {xfo} -> {v:?}");
    }

    #[test]
    fn mismatched_allow_from_vs_self_reports_violation() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        // request uri default origin from test is http://example
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'self'"),
            ("x-frame-options", "ALLOW-FROM http://example:8080"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("does not match"));
    }

    #[test]
    fn scope_and_id_expected() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        assert_eq!(
            rule.id(),
            "content_security_policy_and_frame_options_consistent"
        );
        assert!(rule.needs_response());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(
            &mut cfg,
            "content_security_policy_and_frame_options_consistent",
        );
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn multiple_csp_headers_handled() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        // two CSP headers, one has frame-ancestors
        let headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "default-src 'self'"),
            ("content-security-policy", "frame-ancestors https://a"),
            ("x-frame-options", "ALLOW-FROM https://a"),
        ]);
        tx.response.as_mut().unwrap().headers = headers;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn malformed_frame_ancestors_no_members_is_ignored() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors"),
            ("x-frame-options", "DENY"),
        ]);
        // since the directive is malformed (no members) we treat as absent and no violation
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_xfo_headers_are_ignored() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'self'"),
            ("x-frame-options", "DENY"),
        ]);
        // add a second XFO header to simulate duplicates
        headers.append("x-frame-options", "DENY".parse().unwrap());
        tx.response.as_mut().unwrap().headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn allow_from_trailing_slash_matches_csp_origin() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://example"),
            ("x-frame-options", "ALLOW-FROM https://example/"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn unsupported_xfo_form_is_ignored() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://example"),
            ("x-frame-options", "UNKNOWN https://example"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn allow_from_matches_request_origin_with_self() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        // request uri default origin from test is http://example
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "http://example/path".into();
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'self'"),
            ("x-frame-options", "ALLOW-FROM http://example"),
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn malformed_allow_from_is_ignored() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://a"),
            ("x-frame-options", "ALLOW-FROM"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn allow_from_with_csp_none_reports_violation() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'none'"),
            ("x-frame-options", "ALLOW-FROM https://example"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("permits framing") && msg.contains("'none'"));
    }

    #[test]
    fn allow_from_case_insensitive_match_with_csp_origin() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://EXample"),
            ("x-frame-options", "ALLOW-FROM https://example"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn csp_origin_trailing_slash_matches_allow_from() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            (
                "content-security-policy",
                "frame-ancestors https://example/",
            ),
            ("x-frame-options", "ALLOW-FROM https://example"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn sameorigin_with_csp_origin_is_compatible() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://example"),
            ("x-frame-options", "SAMEORIGIN"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_csp_headers_with_none_and_origin_allow_from_reports_violation() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'none'"),
            ("content-security-policy", "frame-ancestors https://a"),
            ("x-frame-options", "ALLOW-FROM https://a"),
        ]);
        tx.response.as_mut().unwrap().headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some(),
            "expected violation when CSP contains 'none' and also permits an origin"
        );
    }

    #[test]
    fn allow_from_lowercase_is_recognized() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors https://example"),
            ("x-frame-options", "allow-from https://example"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn csp_report_only_ignored() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            (
                "content-security-policy-report-only",
                "frame-ancestors 'none'",
            ),
            ("x-frame-options", "SAMEORIGIN"),
        ]);
        // report-only policies should not affect framing enforcement -> ignore
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn sameorigin_with_self_is_compatible() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-security-policy", "frame-ancestors 'self'"),
            ("x-frame-options", "SAMEORIGIN"),
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_csp_header_is_ignored() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        // make a non-utf8 header value for CSP
        let bad = hyper::header::HeaderValue::from_bytes(&[0xff]).unwrap();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers =
            crate::test_helpers::make_headers_from_pairs(&[("x-frame-options", "DENY")]);
        headers.insert("content-security-policy", bad);
        tx.response.as_mut().unwrap().headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn csp_present_but_no_xfo_returns_none() {
        let rule = ContentSecurityPolicyAndFrameOptionsConsistent;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "frame-ancestors https://example",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }
}
