// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Which of the four productions a request-target derives from.
///
/// The four are alternatives of one rule, so a target derives from exactly one
/// of them or from none, and "none" is a finding rather than a case to fall
/// through.
// cite(RFC 9112 § 3.2, label: request-target forms): "request-target = origin-form / absolute-form / authority-form / asterisk-form"
#[derive(Debug, PartialEq, Eq)]
enum TargetForm<'a> {
    Origin,
    Absolute,
    /// The port is carried because `port` is `*DIGIT`: `example.com:` derives
    /// from this production with no digits in it, and the sentences asking for
    /// a port number are prose beside the grammar rather than the grammar.
    Authority {
        port: &'a str,
    },
    Asterisk,
}

impl TargetForm<'_> {
    /// What to call the form in a finding, in the specification's own words.
    fn named(&self) -> &'static str {
        match self {
            TargetForm::Origin => "origin-form (an absolute path and query)",
            TargetForm::Absolute => "absolute-form (a full target URI)",
            TargetForm::Authority { .. } => "authority-form (a host and port)",
            TargetForm::Asterisk => "asterisk-form ('*')",
        }
    }
}

/// Which production this request-target derives from, or `None` when it derives
/// from no form at all.
///
/// The order is the reading order a recipient has: `"*"` and a leading `"/"` are
/// each unambiguous, and what is left is the pair a colon can open.
///
/// **`example.com:443` derives from two of the four**, because `example.com` is
/// a `scheme` (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` admits the dot) and
/// `443` is a `path-rootless`, so the value is an `absolute-URI` as well as a
/// `uri-host ":" port`. The grammar does not resolve it; § 3.2.3's sentence
/// naming the one method that uses the host-and-port form does, so the authority
/// reading is tried first and the caller measures it against the method. Reading
/// it the other way makes every `GET example.com:443` a request to a proxy for a
/// resource in a scheme named after a host -- the reading the sender is least
/// likely to have meant and the one no recipient on the chain is obliged to
/// share.
// cite(RFC 9112 § 3.2.1, label: origin-form): "origin-form    = absolute-path [ "?" query ]"
// cite(RFC 9112 § 3.2.2, label: absolute-form): "absolute-form  = absolute-URI"
// cite(RFC 9112 § 3.2.3, label: authority-form): "authority-form = uri-host ":" port"
// cite(RFC 9112 § 3.2.3): "The "authority-form" of request-target is only used for CONNECT requests"
//
// The asterisk's production is quoted from the collected grammar and brings its
// neighbour along: where § 3.2.4 prints it, `asterisk-form  = "*"` is nineteen
// characters once the double space is collapsed, below what a fragment can be.
// cite(RFC 9112 § A, label: asterisk-form): "asterisk-form = "*" authority = <authority, see [URI], Section 3.2>"
fn classify(target: &str) -> Option<TargetForm<'_>> {
    // The one-character production. What a method may do with it is the caller's
    // question; that it is the whole target is this one's.
    // cite(RFC 9112 § 3.2.4): "the client MUST send only "*" (%x2A) as the request-target"
    if target == "*" {
        return Some(TargetForm::Asterisk);
    }

    // `absolute-path` is `1*( "/" segment )`, so a target opening with any other
    // character derives from no `origin-form`. What is *inside* the path and
    // query is not read here: `client_request_target_no_fragment` and
    // `client_request_uri_percent_encoding_valid` are the rules that ask.
    // cite(RFC 9110 § 4.1, label: absolute-path): "absolute-path = 1*( "/" segment )"
    if target.starts_with('/') {
        return Some(TargetForm::Origin);
    }

    // The colon that could open either remaining form has to be in the first
    // component: past a "/", "?" or "#" a colon is ordinary data. A target with
    // none is a relative reference, which is not one of the four.
    // cite(RFC 3986 § 4.2): "A path segment that contains a colon character (e.g., "this:that") cannot be used as the first segment of a relative-path reference, as it would be mistaken for a scheme name."
    let first_component = &target[..target.find(['/', '?', '#']).unwrap_or(target.len())];
    let colon = first_component.find(':')?;

    // `uri-host ":" port` with both halves as their own productions say -- which
    // is `Host`'s reader, one bracket stricter: the colon is required here.
    if let (_, Some(port)) = crate::helpers::uri::split_host_and_port(target) {
        if crate::helpers::uri::validate_host_and_optional_port(target).is_ok() {
            return Some(TargetForm::Authority { port });
        }
    }

    // `absolute-URI = scheme ":" hier-part [ "?" query ]`, and the scheme is the
    // only part of it this rule reads: an `absolute-URI` may be rootless
    // (`mailto:user@example.com`), so requiring the "//" of an authority would
    // report a target the production generates.
    crate::helpers::uri::validate_scheme_name(&target[..colon])
        .ok()
        .map(|()| TargetForm::Absolute)
}

pub struct ClientRequestTargetFormChecks;

impl ClientRequestTargetFormChecks {
    fn violation(&self, severity: crate::lint::Severity, message: String) -> Violation {
        Violation {
            rule: self.id().into(),
            severity,
            message,
        }
    }
}

impl Rule for ClientRequestTargetFormChecks {
    fn id(&self) -> &'static str {
        "client_request_target_form_checks"
    }

    /// Every sentence read here is addressed to the client that generated the
    /// request-line, so the rule has to run on a capture whose upstream never
    /// answered as well as on a complete exchange. `Server` would skip exactly
    /// those, and the request-line was already wrong when it was sent.
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        // The four forms are a request-line's, and a request-line is what a
        // major version 1 message has. HTTP/2 and HTTP/3 send the same target
        // components as pseudo-header fields, where the asterisk is a `:path`
        // value and a CONNECT's destination is an `:authority` with no `:path`
        // beside it -- so `tx.request.uri` over those versions is not a
        // request-target at all but the target URI the transport reassembled:
        // an asterisk arrives glued to the authority (`https://example.com*`)
        // and a host and port arrives as an authority nothing distinguishes
        // from any other request's. Measuring either against these productions
        // reports the reassembly rather than the sender.
        //
        // The gate is the major digit alone, which is the digit the first
        // sentence below gives the meaning to: HTTP/1.0 and HTTP/1.1 both carry
        // a request-line.
        // cite(RFC 9110 § 2.5): "The first digit (major version) indicates the messaging syntax"
        // cite(RFC 9110 § 7.1): "For historical reasons, the parsed target URI components, collectively referred to as the "request target", are sent within the message control data and the Host header field"
        // cite(RFC 9110 § 7.1): "This reconstruction is specific to each major protocol version."
        // cite(RFC 9112 § 1): "This document specifies how HTTP semantics are conveyed using the HTTP/1.1 message syntax, framing, and connection management mechanisms."
        // cite(RFC 9112 § 2.3): "The version of an HTTP/1.x message is indicated by an HTTP-version field in the start-line."
        // cite(RFC 9113 § 8.3.1): "A request in asterisk form (for OPTIONS) includes the value '*' for the ":path" pseudo-header field."
        // cite(RFC 9113 § 8.3.1): "Note that request targets for CONNECT or asterisk-form OPTIONS requests never include authority information"
        // cite(RFC 9114 § 4.3.1): "An OPTIONS request that does not include a path component includes the value * (ASCII 0x2a) for the :path pseudo-header field"
        if !tx.request.version.starts_with("HTTP/1") {
            return None;
        }

        // The method decides which forms are open to this request, and it is
        // matched as written: a `connect` is not a CONNECT with a typo, it is a
        // method nobody has defined, and the two method-specific forms belong to
        // the two methods that are.
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        let method = tx.request.method.as_str();
        let target = tx.request.uri.as_str();

        // Whitespace is excluded by name, one paragraph under the four forms,
        // and it is excluded from all four at once -- no `segment`, `uri-host`,
        // `port` or `scheme` admits SP or HTAB either. Asked before the forms so
        // that the answer names the character rather than the production it fell
        // out of.
        // cite(RFC 9112 § 3.2): "No whitespace is allowed in the request-target."
        // cite(RFC 9112 § 3.2): "A recipient SHOULD NOT attempt to autocorrect and then process the request without a redirect, since the invalid request-line might be deliberately crafted to bypass security filters along the request chain."
        if crate::helpers::uri::contains_whitespace(target) {
            let severity = crate::rules::parse_rule_config(cfg, self.id())
                .ok()?
                .severity;
            // A request-target read back from a capture can hold characters that
            // print as nothing, and this finding is about exactly those; the
            // shared renderer is what keeps an HTAB visible in the message
            // instead of splitting it.
            return Some(self.violation(
                severity,
                format!(
                    "Request-target '{}' contains whitespace, which no request-target may contain. The request-line's own delimiters are spaces, so what a recipient reads as the target ends at the first one and the request-line is malformed",
                    crate::helpers::headers::shown_in_finding(target)
                ),
            ));
        }

        let form = classify(target);

        // Both method-specific forms are covered by one MUST NOT, written in the
        // version-independent document where the request target's components are
        // defined rather than in either version's syntax.
        // cite(RFC 9110 § 7.1): "There are two unusual cases for which the request target components are in a method-specific form"
        // cite(RFC 9110 § 7.1): "These forms MUST NOT be used with other methods."
        let message = match (&form, method) {
            // A CONNECT is judged against the one form it may be in, whichever
            // of the others it is in instead. The port is `*DIGIT`, so the
            // grammar is satisfied by the colon alone and the requirement for a
            // number is in the prose beside it -- twice, and RFC 3986 asks a
            // producer with no port not to write the delimiter either.
            // cite(RFC 9110 § 7.1): "For CONNECT (Section 9.3.6), the request target is the host name and port number of the tunnel destination, separated by a colon."
            // cite(RFC 9112 § 3.2.3): "When making a CONNECT request to establish a tunnel through one or more proxies, a client MUST send only the host and port of the tunnel destination as the request-target."
            // cite(RFC 9112 § 3.2.3): "The client obtains the host and port from the target URI's authority component, except that it sends the scheme's default port if the target URI elides the port."
            // cite(RFC 3986 § 3.2.3): "URI producers and normalizers should omit the port component and its ":" delimiter if port is empty or if its value would be the same as that of the scheme's default."
            (Some(TargetForm::Authority { port: "" }), "CONNECT") => format!(
                "CONNECT request-target '{target}' carries the port's delimiter and no port. A client sends the scheme's default port when the target URI elides one, so a recipient reading this has a host and no number to open the tunnel on"
            ),
            (Some(TargetForm::Authority { .. }), "CONNECT") => return None,
            (Some(other), "CONNECT") => format!(
                "CONNECT request-target '{target}' is {}, and a CONNECT sends only the host and port of the tunnel destination, separated by a colon. A recipient has nowhere to open the tunnel to",
                other.named()
            ),
            (None, "CONNECT") => format!(
                "CONNECT request-target '{target}' is not a host and port, and a CONNECT sends only the host and port of the tunnel destination, separated by a colon. A recipient has nowhere to open the tunnel to"
            ),

            // cite(RFC 9110 § 7.1): "For OPTIONS (Section 9.3.7), the request target can be a single asterisk ("*")."
            // cite(RFC 9112 § 3.2.4): "The "asterisk-form" of request-target is only used for a server-wide OPTIONS request"
            (Some(TargetForm::Asterisk), m) if m != "OPTIONS" => format!(
                "Asterisk-form request-target '*' was sent with method '{m}'. The asterisk is the request target of a server-wide OPTIONS request and of nothing else, and the two method-specific forms must not be used with other methods, so '{m} *' names nothing for the request to be applied to"
            ),

            // cite(RFC 9112 § 3.2.3): "The "authority-form" of request-target is only used for CONNECT requests"
            (Some(TargetForm::Authority { .. }), m) => format!(
                "Authority-form request-target '{target}' was sent with method '{m}'. A host and port is the request target of a CONNECT and of nothing else, and the two method-specific forms must not be used with other methods"
            ),

            // Neither remaining form is method-specific, and which of them a
            // client owes is decided by something no message states: origin-form
            // is what a request made directly to an origin server carries and
            // absolute-form is what a request made to a proxy carries, and a
            // capture does not say which the client believed it was addressing.
            // So both are accepted from every other method -- and a server is
            // required to accept the absolute-form whether or not it is a proxy,
            // which is the sentence that makes silence the right answer here
            // rather than a tolerance.
            // cite(RFC 9112 § 3.2.1): "When making a request directly to an origin server, other than a CONNECT or server-wide OPTIONS request (as detailed below), a client MUST send only the absolute path and query components of the target URI as the request-target."
            // cite(RFC 9112 § 3.2.2): "When making a request to a proxy, other than a CONNECT or server-wide OPTIONS request (as detailed below), a client MUST send the target URI in "absolute-form" as the request-target."
            // cite(RFC 9112 § 3.2.2): "A server MUST accept the absolute-form in requests even though most HTTP/1.1 clients will only send the absolute-form to a proxy."
            (Some(_), _) => return None,

            // The four are alternatives of one production, so a value deriving
            // from none of them is not an odd request-target: it is a
            // request-line a recipient is asked to answer 400 to.
            // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
            // cite(RFC 9112 § 3.2): "Recipients of an invalid request-line SHOULD respond with either a 400 (Bad Request) error or a 301 (Moved Permanently) redirect with the request-target properly encoded."
            (None, _) if target.is_empty() => {
                "Request carries an empty request-target. Every one of the four forms derives at least one character -- an absolute path opens with '/', an absolute-URI has a scheme and its colon, a host and port has both, and the asterisk is itself -- so the empty string is none of them and the request-line naming it is invalid".to_string()
            }
            (None, _) => format!(
                "Request-target '{target}' derives from none of the four forms: it is not an absolute path, not a full target URI with a scheme, not a host and port, and not the asterisk. The request-line carrying it is invalid, and a recipient is asked to answer 400 (Bad Request) rather than guess which was meant"
            ),
        };

        // Read last: every gate above ends the rule on its own and each costs a
        // scan or two of a short string, where `parse_rule_config` is several map
        // probes plus a hash over the rule id.
        let severity = crate::rules::parse_rule_config(cfg, self.id())
            .ok()?
            .severity;
        Some(self.violation(severity, message))
    }

    fn description(&self) -> &'static str {
        "Reads an HTTP/1.x request-line's request-target and asks two things: which of the four forms it derives from, and whether the method it was sent with may use that form.\n\n`request-target = origin-form / absolute-form / authority-form / asterisk-form` (RFC 9112 §3.2). The four are alternatives of one production, so a target derives from exactly one of them or from none — and \"none\" is reported: RFC 9110 §2.2 forbids a sender from generating a protocol element that matches no ABNF rule, and RFC 9112 §3.2 has the recipient of an invalid request-line answer 400 (Bad Request). An empty request-target is reported the same way; every one of the four derives at least one character.\n\n**Two of the forms belong to one method each.** RFC 9110 §7.1 states both and closes with \"These forms MUST NOT be used with other methods\": the asterisk is a server-wide OPTIONS request's target, and a host and port is a CONNECT's. So `GET *` and `GET example.com:443` are reported, and so is a CONNECT whose target is a path, a full URI, or anything else that is not a host and port. The method is compared as written, because the method token is case-sensitive (RFC 9110 §9.1) — `connect` is not CONNECT and owns neither form.\n\n**A CONNECT's port is required, and the grammar alone does not require it.** `authority-form = uri-host \":\" port` with `port = *DIGIT` (RFC 3986 §3.2.3) is satisfied by `example.com:`. The number is asked for in prose — RFC 9112 §3.2.3 has the client send the scheme's default port when the target URI elides one, and RFC 9110 §7.1 calls the target \"the host name and port number of the tunnel destination\" — so a colon with no digits after it is reported, while a target with no colon at all is reported as not being a host and port at all.\n\n**`example.com:443` derives from two forms and is read as one of them.** `example.com` is a valid `scheme` and `443` a `path-rootless`, so the value is an `absolute-URI` as well as a `uri-host \":\" port`; the grammar does not choose. RFC 9112 §3.2.3's \"only used for CONNECT requests\" is what makes the host-and-port reading the one worth reporting, because the alternative reading is a request to a proxy for a resource in a scheme named after a host — a reading no recipient along the chain is obliged to share, which is what makes the ambiguity worth a finding at all.\n\n**Whitespace is reported on its own.** RFC 9112 §3.2 excludes it from the request-target by name, one paragraph below the four forms, and gives the reason: the resulting request-line is malformed, and a recipient is asked not to autocorrect it because it might be deliberately crafted to bypass a security filter along the request chain.\n\n**What this rule does not decide.**\n\n- **Whether origin-form or absolute-form was the right choice.** §3.2.1 requires the absolute path and query when the request goes directly to an origin server, and §3.2.2 requires the full target URI when it goes to a proxy — and no captured message says which the client believed it was addressing. Both are therefore accepted from every method other than CONNECT. §3.2.2's \"A server MUST accept the absolute-form in requests even though most HTTP/1.1 clients will only send the absolute-form to a proxy\" is why that silence is the right answer rather than a tolerance.\n- **What is inside a path, query or scheme.** A leading `/` is the whole of the origin-form test here; `client_request_target_no_fragment` and `client_request_uri_percent_encoding_valid` read the characters. A scheme is checked for being a scheme, not for being one anybody serves.\n- **Anything sent over HTTP/2 or HTTP/3.** Those versions carry the request target's components in pseudo-header fields, where the asterisk is a `:path` value (RFC 9113 §8.3.1, RFC 9114 §4.3.1) and a CONNECT's destination is an `:authority` with no `:path` at all. A capture of such a request holds the target URI its transport reassembled, not a request-target, so an asterisk arrives inside an authority and measuring it against these productions would report the reassembly rather than the sender. `message_http2_pseudo_headers_validity` and `message_http3_pseudo_headers_validity` are the rules that read pseudo-header fields, and the second of them asks §7.1's question about the asterisk in its own version's terms.\n- **A CONNECT this proxy itself handled.** A CONNECT request is answered by the tunnel and never becomes a transaction here, so the CONNECT findings above are reachable only in a capture recorded elsewhere and read back in."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        use crate::rules::SpecRef;
        &[
            SpecRef {
                spec: "RFC 9112",
                section: Some("3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2",
                note: "Request Target: the four forms, and the exclusion of whitespace from all of them",
            },
            SpecRef {
                spec: "RFC 9112",
                section: Some("3.2.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.3",
                note: "authority-form: CONNECT's target, and where the port number is asked for in prose rather than in the grammar",
            },
            SpecRef {
                spec: "RFC 9112",
                section: Some("3.2.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.4",
                note: "asterisk-form: the server-wide OPTIONS request's target",
            },
            SpecRef {
                spec: "RFC 9110",
                section: Some("7.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1",
                note: "Determining the Target Resource: the two method-specific forms, the MUST NOT that keeps each to its method, and the reconstruction being specific to each major protocol version",
            },
            SpecRef {
                spec: "RFC 9110",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
                note: "The sender's MUST NOT against generating protocol elements outside the ABNF, which is what makes a target in none of the four forms a violation",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Request"),
                snippet: "OPTIONS * HTTP/1.1\nCONNECT www.example.com:80 HTTP/1.1\nGET /where?q=now HTTP/1.1\nGET http://www.example.org/pub/WWW/TheProject.html HTTP/1.1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Request"),
                snippet: "GET * HTTP/1.1\nGET example.com:443 HTTP/1.1\nCONNECT /not-a-host-and-port HTTP/1.1\nCONNECT www.example.com: HTTP/1.1",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientRequestTargetFormChecks;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn judge(method: &str, uri: &str, version: &str) -> Option<String> {
        let rule = ClientRequestTargetFormChecks;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.into();
        tx.request.uri = uri.into();
        tx.request.version = version.into();

        let config = crate::test_helpers::make_test_config_with_severity(rule.id(), "error");
        rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .map(|v| {
            assert_eq!(v.rule, "client_request_target_form_checks");
            v.message
        })
    }

    #[rstest]
    // The specification's own examples, which are what set the boundary here:
    // §3.2.1's, §3.2.2's, §3.2.3's and §3.2.4's request-lines all stay clean.
    #[case("GET", "/where?q=now")]
    #[case("GET", "http://www.example.org/pub/WWW/TheProject.html")]
    #[case("CONNECT", "www.example.com:80")]
    #[case("OPTIONS", "*")]
    // An OPTIONS naming a resource is not the server-wide form and is not asked
    // to be.
    #[case("OPTIONS", "/resource")]
    // An `absolute-URI` need not be hierarchical, so a rootless one derives from
    // absolute-form. It used to be reported as a host and port.
    #[case("GET", "mailto:user@example.com")]
    // A colon past the first component is data, and the value is a path.
    #[case("GET", "/v1/entities/x:batchGet")]
    // An empty segment is a segment: `absolute-path = 1*( "/" segment )`.
    #[case("GET", "//evil.example/p")]
    // A bracketed IPv6 literal with its port is a `uri-host ":" port`.
    #[case("CONNECT", "[2001:db8::1]:443")]
    fn accepted(#[case] method: &str, #[case] uri: &str) {
        assert_eq!(judge(method, uri, "HTTP/1.1"), None);
    }

    #[rstest]
    #[case("GET", "*", "server-wide OPTIONS")]
    #[case("POST", "*", "server-wide OPTIONS")]
    // The method is matched as written, so a lowercase spelling is a method that
    // owns neither of the two forms.
    #[case("options", "*", "server-wide OPTIONS")]
    #[case("GET", "example.com:443", "request target of a CONNECT")]
    #[case("connect", "example.com:443", "request target of a CONNECT")]
    #[case("CONNECT", "/path", "host and port of the tunnel destination")]
    #[case(
        "CONNECT",
        "https://example.com/",
        "host and port of the tunnel destination"
    )]
    #[case("CONNECT", "*", "host and port of the tunnel destination")]
    // No colon at all: not a `uri-host ":" port`, and not any other form either.
    #[case("CONNECT", "example.com", "host and port of the tunnel destination")]
    // The colon is there and the port is not. `port = *DIGIT` derives that; the
    // prose asking for a number is what does not.
    #[case("CONNECT", "example.com:", "delimiter and no port")]
    #[case("GET", "", "empty request-target")]
    #[case("GET", "resource/x", "none of the four forms")]
    #[case("GET", "foo|bar", "none of the four forms")]
    // A scheme has to begin with a letter, so this derives from no
    // `absolute-URI`, and `1foo` with a `bar` after the colon is no host and
    // port either.
    #[case("GET", "1foo:bar", "none of the four forms")]
    #[case("GET", "/pa th", "contains whitespace")]
    #[case("GET", "http://exa mple.org/", "contains whitespace")]
    fn reported(#[case] method: &str, #[case] uri: &str, #[case] expected: &str) {
        let message = judge(method, uri, "HTTP/1.1").expect("a finding");
        assert!(
            message.contains(expected),
            "expected {expected:?} in {message:?}"
        );
    }

    #[test]
    fn a_horizontal_tab_survives_into_the_finding() {
        // The finding is about characters that print as nothing, so the one in
        // the message has to stay readable.
        let message = judge("GET", "/pa\tth", "HTTP/1.1").expect("a finding");
        assert!(message.contains("\\t"), "{message}");
    }

    #[rstest]
    // Over HTTP/2 and HTTP/3 the capture holds the target URI the transport
    // reassembled from pseudo-header fields. An asterisk arrives inside it, and
    // measuring the result against the request-line's productions would report
    // the reassembly: `https://example.com*` is neither an authority-form nor an
    // asterisk-form, and the sender wrote neither.
    #[case("GET", "https://example.com*", "HTTP/2.0")]
    #[case("GET", "https://example.com*", "HTTP/3")]
    #[case("GET", "example.com:443", "HTTP/2.0")]
    #[case("GET", "example.com:443", "HTTP/3")]
    #[case("GET", "", "HTTP/3")]
    fn a_version_with_no_request_line_is_not_measured(
        #[case] method: &str,
        #[case] uri: &str,
        #[case] version: &str,
    ) {
        assert_eq!(judge(method, uri, version), None);
    }

    #[test]
    fn both_minor_versions_of_the_major_one_are_measured() {
        // The gate is the major digit, the one that indicates the messaging
        // syntax.
        assert!(judge("GET", "*", "HTTP/1.0").is_some());
        assert!(judge("GET", "*", "HTTP/1.1").is_some());
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientRequestTargetFormChecks;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        // Enable the rule as it would be in a user's config
        crate::test_helpers::enable_rule(&mut cfg, "client_request_target_form_checks");
        // Should validate and produce an engine without error
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    /// Each published request-line is judged the way its example is labelled.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        let rule = ClientRequestTargetFormChecks;
        for example in rule.examples() {
            let expect_violation =
                matches!(example.compliance, crate::rules::Compliance::NonCompliant);
            for line in example.snippet.lines() {
                let mut parts = line.split(' ');
                let method = parts.next().expect("a method");
                let target = parts.next().expect("a request-target");
                let version = parts.next().expect("an HTTP-version");
                assert_eq!(
                    judge(method, target, version).is_some(),
                    expect_violation,
                    "{line}"
                );
            }
        }
    }
}
