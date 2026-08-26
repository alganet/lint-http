// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct Http2PseudoHeadersValid;

/// What a basic CONNECT's `:authority` has to be, and what is wrong with this
/// one.
///
/// The pseudo-header carries a host and a port, and the document says so by
/// pointing at the request-target form that carries the same two things. That
/// production requires neither of them — `port` is `*DIGIT` and `reg-name` is
/// `*( ... )`, so `example.com:`, `:443` and `example.com` all derive from it —
/// and the port is asked for in prose instead, twice, once by the client's
/// requirement to send it and once by the server's to reject a request that
/// does not.
// cite(RFC 9113 § 8.5): "The ":authority" pseudo-header field contains the host and port to connect to (equivalent to the authority-form of the request-target of CONNECT requests; see Section 3.2.3 of [HTTP/1.1])."
// cite(RFC 9112 § 3.2.3, label: authority-form): "authority-form = uri-host ":" port"
// cite(RFC 9110 § 9.3.6): "CONNECT uses a special form of request target, unique to this method, consisting of only the host and port number of the tunnel destination, separated by a colon."
// cite(RFC 9110 § 9.3.6): "There is no default port; a client MUST send the port number even if the CONNECT request is based on a URI reference that contains an authority component with an elided port (Section 4.1)."
// cite(RFC 9110 § 9.3.6): "A server MUST reject a CONNECT request that targets an empty or invalid port number, typically by responding with a 400 (Bad Request) status code."
fn connect_authority_finding(authority: &str) -> Option<String> {
    let shown = crate::helpers::headers::shown_in_finding(authority);

    if authority.is_empty() {
        return Some(
            "CONNECT request carries no ':authority', and there is nothing else in the message \
             naming the host and port to open the tunnel to"
                .into(),
        );
    }

    // Asked before the grammar so the answer names what is wrong: a userinfo
    // makes the host look like a port to any reader splitting on the colon.
    // The form is a `uri-host` and a `port` and has no third component, and the
    // sentence naming the two is one paragraph above the grammar.
    //
    // What is shown is the elided form: a userinfo is where credentials
    // travel, and a report printing the password would be one more place they
    // are written down in clear. The elision is the shared helper's, with
    // RFC 3986 § 3.2.1's sentence on it.
    if authority.contains('@') {
        let shown = crate::helpers::uri::userinfo_password_withheld(authority)
            .map(|redacted| crate::helpers::headers::shown_in_finding(&redacted))
            .unwrap_or(shown);
        return Some(format!(
            "CONNECT ':authority' '{shown}' carries a userinfo subcomponent and its '@' \
             delimiter: the field is only the host and port number of the tunnel destination"
        ));
    }

    let (host, port) = crate::helpers::uri::split_host_and_port(authority);
    if let Err(msg) = crate::helpers::uri::validate_host_and_optional_port(authority) {
        return Some(format!(
            "CONNECT ':authority' '{shown}' is not a host and port: {msg}"
        ));
    }

    // Both halves of the production are `*`-quantified, so the emptiness of
    // either is a question for the prose rather than for the grammar. The port
    // is required outright; the host is what "the host and port number of the
    // tunnel destination" leaves nothing of if it is absent.
    match port {
        None => Some(format!(
            "CONNECT ':authority' '{shown}' names no port, and a CONNECT has no default port: a \
             client sends the port number even when the URI reference it started from elided one"
        )),
        Some("") => Some(format!(
            "CONNECT ':authority' '{shown}' ends at the colon with no port number, which a server \
             is required to reject"
        )),
        Some(port) if host.is_empty() => Some(format!(
            "CONNECT ':authority' '{shown}' names the port '{port}' and no host, so it names \
             nothing to open a tunnel to"
        )),
        Some(port) => connect_port_range_finding(port).map(|msg| {
            format!("CONNECT ':authority' '{shown}' targets an invalid port number: {msg}")
        }),
    }
}

/// The one numeric bound a port in a CONNECT `:authority` has, and where it
/// comes from.
///
/// `port = *DIGIT` states none, which is why `host_header` reports no
/// port for being out of range and says so in its `description()`. What is
/// different here is that a sentence names the transport: the proxy opens a TCP
/// connection to this host and port, TCP's port namespace is sixteen bits wide,
/// and a server is required to reject a CONNECT targeting an invalid port
/// number. A value above 65535 designates no port in that namespace.
///
/// `0` is **not** reported. It is inside the namespace — a reserved value at the
/// edge of a range, held back for extending the ranges later — and no sentence
/// in these documents makes a reserved port an invalid one. The check this
/// replaced rejected it under the same message as 70000.
// cite(RFC 9113 § 8.5): "A proxy that supports CONNECT establishes a TCP connection [TCP] to the host and port identified in the ":authority" pseudo-header field."
// cite(RFC 6335 § 6): "TCP, UDP, UDP-Lite, SCTP, and DCCP use 16-bit namespaces for their port number registries."
// cite(RFC 6335 § 6): "Reserved port numbers include values at the edges of each range, e.g., 0, 1023, 1024, etc., which may be used to extend these ranges or the overall port number space in the future."
fn connect_port_range_finding(port: &str) -> Option<String> {
    // The range itself is `helpers::uri::port_number`'s, shared with the two
    // other callers that have a sentence naming a transport. The sentences
    // above are what license *this* caller to ask it; the reader holds the
    // width and the reserved-value reading and nothing about CONNECT.
    crate::helpers::uri::port_number(port).is_none().then(|| {
        format!(
            "a TCP port number is one of 65536 values and '{port}' is not among them, so the \
             connection this CONNECT asks for cannot be opened to it"
        )
    })
}

impl Rule for Http2PseudoHeadersValid {
    fn id(&self) -> &'static str {
        "http2_pseudo_headers_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        // Only applies to HTTP/2 transactions. The gate is scoping, not a
        // normative check, so it carries no cite; each requirement below cites
        // the sentence it enforces. Four consecutive iterations recorded that
        // this gate was missing: without it every finding below was made of an
        // HTTP/1.1 or HTTP/3 message too, in the words of a version that
        // message was not, and on top of the report from whichever rule owns
        // the question there. What it reads is the major digit rather than a
        // string: this version has no version field on the wire, so the value
        // is one a writer chose, and `http_version` is where the production
        // lives.
        if !crate::http_version::is_major(&tx.request.version, 2) {
            return None;
        }

        // The pseudo-header fields themselves are not in the captured field
        // section — a transport that carries control data as `:method`,
        // `:scheme`, `:authority` and `:path` hands its library a method and a
        // reassembled target URI, and that is what the canonical transaction
        // records. So each check below reads the component the pseudo-header
        // conveyed, and the two `§ 8.3` requirements about the field block
        // itself (ordering, and one occurrence per name) are unenforceable
        // here; `description()` says so.

        // Read as written. `method = token` is `1*tchar`, which admits no
        // whitespace for a trim to find and no empty string, so a value failing
        // it derives from no `method` and names nothing for the branches below
        // to turn on -- neither the CONNECT restrictions nor the asterisk's one
        // method. `request_method_token_valid` reports it, of every
        // version, and reported it here too: trimming this value hid the
        // leading space from *this* rule without hiding it from that one.
        // cite(RFC 9113 § 8.3.1): "The ":method" pseudo-header field includes the HTTP method (Section 9 of [HTTP])."
        // The production stands alone in § 9.1 at fourteen characters, under the
        // extractor's floor; the collected grammar's copy is where it can be
        // quoted, at the cost of the neighbour that follows it there.
        // cite(RFC 9110 § A): "method = token minute = 2DIGIT"
        // cite(RFC 9113 § 8.3): "Endpoints MUST treat a request or response that contains undefined or invalid pseudo-header fields as malformed (Section 8.1.1)."
        let method = tx.request.method.as_str();
        if method.is_empty() || crate::helpers::token::find_invalid_token_char(method).is_some() {
            return None;
        }

        // The target as the transport reassembled it, read as written for the
        // same reason: a `:path` or `:authority` with whitespace around it
        // derives from no field value, and the character is
        // `request_uri_percent_encoding_valid`'s finding on every
        // version.
        // cite(RFC 9113 § 8.2.1): "A field value MUST NOT start or end with an ASCII whitespace character (ASCII SP or HTAB, 0x20 or 0x09)."
        let target = tx.request.uri.as_str();

        // Compared as written, because the method token is case-sensitive:
        // `connect` is a method this specification does not define and owns
        // none of CONNECT's restrictions. The fold this replaced *suppressed*
        // findings -- a lowercase `connect` took the tunnel branch and skipped
        // the `:path` requirement, and a lowercase `options` was handed the
        // asterisk -- and `request_target_form_valid` had already
        // settled the same question the same way one iteration earlier.
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        // cite(RFC 9113 § 8.5): "The ":method" pseudo-header field is set to CONNECT."
        let is_connect = method == "CONNECT";

        // Read once the two cheapest and most selective gates above have had
        // their say: `parse_rule_config` is several map probes and a hash of
        // the rule id, where a version comparison is nine characters and a
        // method comparison is seven.
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // Which of the three forms the transport reassembled is what says which
        // CONNECT this is, and it is the only thing that does: the capture
        // records no `:protocol`, so an absolute-form target -- `:scheme` and
        // `:path` present alongside `:authority` -- is a conforming extended
        // CONNECT and a malformed basic one, indistinguishable. `description()`
        // publishes that decline; the sibling HTTP/3 rule takes the same one.
        // cite(RFC 8441 § 4): "A new pseudo-header field :protocol MAY be included on request HEADERS indicating the desired protocol to be spoken on the tunnel created by CONNECT."
        // cite(RFC 8441 § 4): "On requests that contain the :protocol pseudo-header field, the :scheme and :path pseudo-header fields of the target URI (see Section 5) MUST also be included."
        let absolute_form = crate::helpers::uri::scheme_authority_marker(target);

        if is_connect {
            // cite(RFC 9113 § 8.5): "The ":authority" pseudo-header field contains the host and port to connect to (equivalent to the authority-form of the request-target of CONNECT requests; see Section 3.2.3 of [HTTP/1.1])."
            // cite(RFC 9113 § 8.5): "A CONNECT request that does not conform to these restrictions is malformed (Section 8.1.1)."
            if target.starts_with('/') {
                // An origin-form target is a `:path` with no `:scheme` and no
                // `:authority` beside it. That derives from neither CONNECT: a
                // basic one omits `:path`, an extended one carries `:scheme`
                // too. The authority a `Host` field can still supply is what
                // decides whether anything is missing, which is the sibling
                // HTTP/3 rule's reading of the same pair of documents.
                // cite(RFC 9110 § 7.2): "In HTTP/2 [HTTP/2] and HTTP/3 [HTTP/3], the Host header field is, in some cases, supplanted by the ":authority" pseudo-header field of a request's control data."
                if !tx.request.headers.contains_key("host") {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "CONNECT request carries a path and no authority: an extended \
                                  CONNECT sends ':scheme' and ':path' beside an ':authority', and \
                                  a basic one sends only the host and port to connect to"
                            .into(),
                    });
                }
            } else if absolute_form.is_none() {
                if let Some(msg) = connect_authority_finding(target) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: msg,
                    });
                }
            }
        } else {
            // The asterisk is a `:path` value on this version rather than a
            // request-target of its own, and the method that may send it is
            // the same one on all three.
            // cite(RFC 9113 § 8.3.1): "A request in asterisk form (for OPTIONS) includes the value '*' for the ":path" pseudo-header field."
            // cite(RFC 9110 § 7.1): "For OPTIONS (Section 9.3.7), the request target can be a single asterisk ("*")."
            // cite(RFC 9110 § 7.1): "These forms MUST NOT be used with other methods."
            if target == "*" {
                if method != "OPTIONS" {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Asterisk ('*') is the ':path' value of a server-wide OPTIONS request \
                             and of nothing else, and this request's ':method' is '{method}'"
                        ),
                    });
                }
            } else {
                // cite(RFC 9113 § 8.3.1): "This pseudo-header field MUST NOT be empty for "http" or "https" URIs; "http" or "https" URIs that do not contain a path component MUST include a value of '/'."
                // cite(RFC 9113 § 8.3.1): "All HTTP/2 requests MUST include exactly one valid value for the ":method", ":scheme", and ":path" pseudo-header fields, unless they are CONNECT requests (Section 8.5)."
                if crate::helpers::uri::extract_path_from_request_target(target).is_none() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Request target '{}' carries no path, and every non-CONNECT request \
                             sends exactly one ':path': an 'http' or 'https' URI with no path \
                             component sends '/'",
                            crate::helpers::headers::shown_in_finding(target)
                        ),
                    });
                }
            }
        }

        // What `:scheme` and `:authority` conveyed, in the one shape a capture
        // shows them: the transport reassembled them into the target URI, so a
        // target in absolute form is where they can still be read back. The
        // test is the marker rather than `contains("://")` -- a `://` past the
        // first component delimiter is ordinary query data, and reading an
        // authority out of `/r?next=http:///p` reported an origin-form target
        // for a missing authority it never claimed to have.
        // cite(RFC 9113 § 8.3.1): "The ":scheme" pseudo-header field includes the scheme portion of the request target."
        // cite(RFC 9113 § 8.3.1): "The ":authority" pseudo-header field conveys the authority portion (Section 3.2 of [RFC3986]) of the target URI (Section 7.1 of [HTTP])."
        if let Some(marker) = absolute_form {
            // The scheme is the characters before the marker, and the helper
            // carries the production. Nothing here asks whether it is one
            // anybody serves: this pseudo-header is deliberately open.
            // cite(RFC 9113 § 8.3.1): "":scheme" is not restricted to "http" and "https" schemed URIs."
            if let Some(msg) = crate::helpers::uri::validate_scheme_if_present(target) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Request target's scheme is not a scheme name: {msg}"),
                });
            }

            let scheme = &target[..marker];

            // The shared extractor already walks to the delimiter that
            // terminates an authority, and it answers `None` for an authority
            // of no characters. Inside this branch the target is in absolute
            // form, so that is the only `None` reachable — which is what makes
            // the conflation this rule could not live with elsewhere usable
            // here as the finding itself.
            let Some(authority) =
                crate::helpers::uri::extract_authority_from_request_target(target)
            else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Request target '{}' names the scheme '{scheme}' and then no authority",
                        crate::helpers::headers::shown_in_finding(target)
                    ),
                });
            };

            // The MUST NOT names the two schemes it is about, and the scheme is
            // the left half of the value being read -- so a userinfo under some
            // other scheme is outside it and is not reported.
            //
            // The password half is withheld from the finding: the elision is
            // the shared helper's, with RFC 3986 § 3.2.1's sentence on it.
            // cite(RFC 9113 § 8.3.1): "":authority" MUST NOT include the deprecated userinfo subcomponent for "http" or "https" schemed URIs."
            if authority.contains('@')
                && (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
            {
                let shown = crate::helpers::uri::userinfo_password_withheld(&authority)
                    .unwrap_or_else(|| authority.to_string());
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Authority '{}' of an '{scheme}' target carries the deprecated userinfo \
                         subcomponent and its '@' delimiter",
                        crate::helpers::headers::shown_in_finding(&shown)
                    ),
                });
            }

            // `uri-host [ ":" port ]` is one question with one answer, and the
            // shared reader is where it lives: the bracket that distinguishes
            // an IP literal, the address inside it, and a port of digits. The
            // copy this replaced guessed at an unbracketed IPv6 literal by
            // counting colons.
            if let Err(msg) = crate::helpers::uri::validate_host_and_optional_port(&authority) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Authority '{}' is not a host and port: {msg}",
                        crate::helpers::headers::shown_in_finding(&authority)
                    ),
                });
            }
        }

        // **The response half is not this rule's.** This branch used to report a
        // status outside 100–599 as a `:status` defect, and it ran on *every*
        // transaction: this rule has no version gate, so an out-of-range status in
        // an HTTP/1.1 status-line was reported here, as a pseudo-header the message
        // never carried, on top of the report from the rule that owns the question.
        // Two of this rule's own tests asserted it, both built on
        // `make_test_transaction_with_response`, whose responses are HTTP/1.1.
        //
        // The range is RFC 9110 § 15's and holds for every version. RFC 9113
        // § 8.3.2 defines `:status` as carrying "the HTTP status code field (see
        // Section 15 of [HTTP])" and states no range of its own, so there was never
        // an HTTP/2 sentence under the check; `status_code_valid_range` asks
        // it of every version. What § 8.3.2 does require — that the field be present
        // in all responses, including interim ones — cannot fail in this model:
        // `ResponseInfo.status` is a `u16` that always holds a value.
        //
        // cite(RFC 9113 § 8.3.2): "For HTTP/2 responses, a single ":status" pseudo-header field is defined that carries the HTTP status code field (see Section 15 of [HTTP])."
        // cite(RFC 9113 § 8.3.2): "This pseudo-header field MUST be included in all responses, including interim responses; otherwise, the response is malformed (Section 8.1.1)."

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("HTTP/2 Pseudo-Headers Validity")
    }

    fn description(&self) -> &'static str {
        "HTTP/2 carries a request's control data as pseudo-header fields — `:method`, `:scheme`, `:authority` and `:path` — and this rule reads what each of them conveyed. **It runs on HTTP/2 requests only.** It had no version gate at all until this audit, so every finding below was also made of HTTP/1.1 and HTTP/3 messages, described as HTTP/2, alongside the report from whichever rule owns the question on those versions.\n\n**The fields are not in the captured field section.** A transport that carries control data as pseudo-headers hands its library a method and a target URI reassembled from `:scheme`, `:authority` and `:path`, and that is what a capture records. So each check reads the component the pseudo-header conveyed, and the checks are shaped by which of the request-target forms the reassembly produced.\n\n- **A non-CONNECT request sends exactly one `:path`.** `*` is that value for a server-wide OPTIONS request and for no other method (RFC 9110 §7.1: \"These forms MUST NOT be used with other methods\"). Otherwise a target with no path at all is reported: an `http` or `https` URI without a path component sends `/`.\n- **A basic CONNECT's `:authority` is a host and a port.** `authority-form = uri-host \":\" port` requires neither — both halves are `*`-quantified — so the prose is what asks for them: RFC 9110 §9.3.6 has no default port, requires the client to send one even when the URI reference elided it, and requires a server to reject an empty or invalid port number.\n- **A port above 65535 is reported; `0` is not.** The bound is not the grammar's — `port = *DIGIT` has none, which is why `host_header` reports no port for being out of range. It is that RFC 9113 §8.5 has the proxy open a *TCP* connection to this host and port and TCP's port namespace is sixteen bits wide (RFC 6335 §6). `0` sits inside that namespace as a reserved edge value, and no sentence here makes a reserved port an invalid one.\n- **The reassembled `:scheme` and `:authority` are read when the target is in absolute form**: the scheme against `scheme = ALPHA *( ALPHA / DIGIT / \"+\" / \"-\" / \".\" )`, the authority against `uri-host [ \":\" port ]`, and — for an `http` or `https` target only, because that is how §8.3.1 writes the MUST NOT — a userinfo subcomponent. `:scheme` is deliberately not restricted to `http` and `https`, so nothing here asks whether it is a scheme anybody serves.\n\n**What this rule declines, and why.**\n\n- **Which CONNECT this is, when the target is in absolute form.** RFC 8441's extended CONNECT is marked by a `:protocol` pseudo-header, and on such a request `:scheme` and `:path` MUST be included — exactly what a basic CONNECT MUST omit. A capture records no `:protocol`, so a `CONNECT https://example.com/ws` is a conforming extended CONNECT and a malformed basic one with nothing to choose between them. It is accepted. An *origin-form* CONNECT target is reported when no `Host` field accompanies it, because that is neither CONNECT: it is a `:path` with no `:scheme` and no authority anywhere.\n- **The method token itself.** `method = token` admits no whitespace and no empty string, and a value failing it names nothing for the branches above to turn on, so the rule stops. `request_method_token_valid` reports it, on every version. The method is compared as written throughout — `connect` is not CONNECT and `options` is not OPTIONS (RFC 9110 §9.1) — where the case-folding this replaced *suppressed* findings.\n- **The characters inside the target.** Whitespace and a malformed percent-encoding triplet were both reported here and by `request_uri_percent_encoding_valid`, which reads the whole target on every version. Both duplicates are gone.\n- **Where the pseudo-headers sat, and how many there were.** RFC 9113 §8.3 requires them to precede every regular field line and forbids a repeated name. The capture holds no pseudo-header fields and no field order, so neither has a representation to check.\n- **Whether a `Host` field agrees with `:authority`.** §8.3.1 forbids a client from generating a request where they differ. `host_and_authority_consistent` asks it, of this version and of HTTP/3, and keeps the two documents apart on what comparing the values means.\n\n**Nothing here reads the response.** RFC 9113 §8.3.2 requires a response to carry exactly one `:status` pseudo-header field, which the canonical transaction model always supplies as a `u16`, so its absence has no representation to check; and the range that value must fall in is RFC 9110 §15's, which is the same for every HTTP version and is reported by `status_code_valid_range`."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3",
                note: "HTTP Control Data — what a pseudo-header field is, and that a request carrying an invalid one is malformed. Its two requirements about the field block itself (ordering before regular field lines, one occurrence per name) are not checked: a capture holds no pseudo-header fields and no field order.",
            },
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1",
                note: "Request Pseudo-Header Fields — what each of `:method`, `:scheme`, `:authority` and `:path` conveys, the `'*'` value for asterisk-form OPTIONS, the `:path`-must-not-be-empty MUST, and the userinfo MUST NOT written for `http` and `https` targets",
            },
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.2",
                note: "Response Pseudo-Header Fields — `:status` is always present in this model and its range is RFC 9110 §15's, so nothing here reads it",
            },
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5",
                note: "The CONNECT Method — `:method` is set to CONNECT, `:scheme` and `:path` are omitted, `:authority` carries the host and port, and the proxy opens a TCP connection to them",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1",
                note: "Overview of methods — `method = token`, and the token is case-sensitive, which is why CONNECT and OPTIONS are matched exactly",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6",
                note: "CONNECT — the host and port number of the tunnel destination, the absence of a default port, and the server's MUST to reject an empty or invalid one. This is where the port requirements come from; the grammar states none.",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1",
                note: "Determining the Target Resource — the asterisk is OPTIONS's target and the method-specific forms must not be used with other methods",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("3.2.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.3",
                note: "authority-form — the production RFC 9113 §8.5 points at for what `:authority` carries on a CONNECT, and where both halves turn out to be `*`-quantified",
            },
            crate::rules::SpecRef {
                spec: "RFC 8441",
                section: Some("4"),
                url: "https://www.rfc-editor.org/rfc/rfc8441.html#section-4",
                note: "The Extended CONNECT Method — `:protocol` is what distinguishes it, and on such a request `:scheme` and `:path` MUST be included. A capture records no `:protocol`, which is why an absolute-form CONNECT target is accepted.",
            },
            crate::rules::SpecRef {
                spec: "RFC 6335",
                section: Some("6"),
                url: "https://www.rfc-editor.org/rfc/rfc6335.html#section-6",
                note: "Port Number Ranges — the 16-bit namespace that bounds a CONNECT port above, and the reserved edge values that are why `0` is not reported",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: ":method: GET\n:scheme: https\n:authority: example.com\n:path: /",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: ":method: OPTIONS\n:scheme: https\n:authority: example.com\n:path: *",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: ":method: CONNECT\n:authority: example.com:443",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "Extended CONNECT: :protocol is not recorded in a capture, so a CONNECT \
                     carrying :scheme and :path is accepted",
                ),
                snippet: ":method: CONNECT\n:protocol: websocket\n:scheme: https\n:authority: example.com\n:path: /ws",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A non-CONNECT request with no :path"),
                snippet: ":method: GET\n:scheme: https\n:authority: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The asterisk is OPTIONS's :path value and no other method's"),
                snippet: ":method: GET\n:scheme: https\n:authority: example.com\n:path: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A CONNECT has no default port, so the port is sent"),
                snippet: ":method: CONNECT\n:authority: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("An 'https' target's authority carries no userinfo"),
                snippet: ":method: GET\n:scheme: https\n:authority: user:pass@example.com\n:path: /",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Http2PseudoHeadersValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn h2() -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/2.0".into();
        tx.request.headers = hyper::HeaderMap::new();
        tx
    }

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<String> {
        let rule = Http2PseudoHeadersValid;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .map(|v| v.message)
    }

    fn judge_request(method: &str, target: &str) -> Option<String> {
        let mut tx = h2();
        tx.request.method = method.into();
        tx.request.uri = target.into();
        judge(&tx)
    }

    /// Ask a named rule the same question, so a "not this rule's finding" test
    /// says who the finding *is* rather than only that it left.
    fn judge_by(
        rule: &dyn crate::rules::Rule,
        tx: &crate::http_transaction::HttpTransaction,
    ) -> Option<String> {
        crate::test_helpers::run_rule(
            rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .map(|v| v.message)
    }

    // --- The version gate ---

    /// Every finding this rule makes is about a message that arrived under
    /// HTTP/2. It had no gate at all, so each of these was reported — in the
    /// words of a version the message was not — on top of the report from the
    /// rule that owns the question on that version.
    #[rstest]
    #[case("HTTP/1.1", "CONNECT", "/tunnel")]
    #[case("HTTP/1.1", "GET", "*")]
    #[case("HTTP/1.0", "GET", "example.com:443")]
    #[case("HTTP/3.0", "CONNECT", "/tunnel")]
    #[case("HTTP/3.0", "GET", "*")]
    // A value that derives from no `HTTP-version` names no major version, so it
    // is not this one either.
    #[case("HTTP/2", "GET", "*")]
    #[case("http/2.0", "GET", "*")]
    fn another_version_is_not_this_rules_message(
        #[case] version: &str,
        #[case] method: &str,
        #[case] target: &str,
    ) {
        let mut tx = h2();
        tx.request.version = version.into();
        tx.request.method = method.into();
        tx.request.uri = target.into();
        assert_eq!(judge(&tx), None, "{version} {method} {target}");
    }

    /// The same two messages over HTTP/1.1 are still reported — by the rule
    /// whose sentences are about a request-line.
    #[rstest]
    #[case("CONNECT", "/tunnel")]
    #[case("GET", "*")]
    fn the_http1_owner_still_reports_them(#[case] method: &str, #[case] target: &str) {
        let mut tx = h2();
        tx.request.version = "HTTP/1.1".into();
        tx.request.method = method.into();
        tx.request.uri = target.into();
        let owner = crate::rules::request_target_form_valid::RequestTargetFormValid;
        assert!(judge_by(&owner, &tx).is_some(), "{method} {target}");
    }

    // --- The method token ---

    /// `method = token` is `1*tchar`. A value failing it names nothing for the
    /// branches to turn on, and it is reported — of every version — by the rule
    /// that owns the production. The trim this replaced hid the leading space
    /// from here and from nobody else.
    #[rstest]
    #[case("", "/x")]
    #[case(" GET", "/x")]
    #[case("GET ", "/x")]
    #[case("GE T", "/x")]
    #[case("GE\u{20AC}T", "/x")]
    fn a_value_that_is_no_method_stops_the_rule(#[case] method: &str, #[case] target: &str) {
        assert_eq!(judge_request(method, target), None, "{method:?}");

        let mut tx = h2();
        tx.request.method = method.into();
        tx.request.uri = target.into();
        let owner = crate::rules::request_method_token_valid::RequestMethodTokenValid;
        // That rule reads a required `registered_methods` array, and an absent
        // one stops the whole rule rather than only its case finding — so the
        // handover has to be exercised with a configuration a deployment would
        // actually have.
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[owner.id()]);
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        table.insert(
            "registered_methods".to_string(),
            toml::Value::Array(vec![toml::Value::String("GET".into())]),
        );
        cfg.rules
            .insert(owner.id().to_string(), toml::Value::Table(table));
        assert!(
            crate::test_helpers::run_rule(
                &owner,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .is_some(),
            "method {method:?} is reported by nobody"
        );
    }

    /// The method token is case-sensitive, and the fold this replaced
    /// *suppressed* both findings: a lowercase `connect` took the tunnel branch
    /// and skipped the `:path` requirement, and a lowercase `options` was
    /// handed the asterisk.
    #[test]
    fn a_lowercase_connect_is_not_connect() {
        let message = judge_request("connect", "example.com:443").expect("reported");
        assert!(message.contains("carries no path"), "{message}");
    }

    #[rstest]
    #[case("options")]
    #[case("Options")]
    #[case("GET")]
    #[case("POST")]
    #[case("HEAD")]
    fn the_asterisk_belongs_to_options_written_that_way(#[case] method: &str) {
        let message = judge_request(method, "*").expect("reported");
        assert!(message.contains("Asterisk"), "{message}");
        assert!(message.contains(method), "{message}");
    }

    #[test]
    fn options_asterisk_is_the_one_that_derives() {
        assert_eq!(judge_request("OPTIONS", "*"), None);
    }

    // --- :path ---

    #[rstest]
    #[case("GET", "https://example.com/p")]
    #[case("GET", "/p")]
    #[case("GET", "/")]
    #[case("GET", "/?q=search")]
    // `path-abempty` may be empty, and the reassembly supplies the `/` the
    // sentence asks for.
    #[case("GET", "https://example.com")]
    #[case("POST", "/submit")]
    fn a_path_is_there(#[case] method: &str, #[case] target: &str) {
        assert_eq!(judge_request(method, target), None, "{target}");
    }

    #[rstest]
    #[case("GET", "example.com:443")]
    #[case("GET", "")]
    #[case("POST", "example.com")]
    fn a_non_connect_request_with_no_path_is_reported(#[case] method: &str, #[case] target: &str) {
        let message = judge_request(method, target).expect("reported");
        assert!(message.contains("carries no path"), "{message}");
    }

    // --- CONNECT ---

    #[rstest]
    #[case("example.com:443")]
    #[case("[::1]:443")]
    #[case("192.0.2.1:80")]
    #[case("example.com:65535")]
    // `0` is inside TCP's namespace: a reserved value at the edge of a range,
    // not an invalid port number. The check this replaced reported it under the
    // same message as 70000.
    #[case("example.com:0")]
    fn a_basic_connect_names_a_host_and_a_port(#[case] target: &str) {
        assert_eq!(judge_request("CONNECT", target), None, "{target}");
    }

    #[rstest]
    #[case("example.com", "names no port")]
    #[case("example.com:", "ends at the colon")]
    #[case(":443", "and no host")]
    #[case("", "no ':authority'")]
    #[case("user:pass@example.com:443", "userinfo")]
    #[case("example.com:70000", "invalid port number")]
    #[case("example.com:99999999999999999999", "invalid port number")]
    #[case("[::1:443", "not a host and port")]
    #[case("fe80::1:80", "not a host and port")]
    #[case("exa mple.com:443", "not a host and port")]
    fn a_basic_connect_authority_that_is_not_one(#[case] target: &str, #[case] expected: &str) {
        let message = judge_request("CONNECT", target).expect("reported");
        assert!(message.contains(expected), "{target}: {message}");
    }

    /// RFC 8441's extended CONNECT sends `:scheme` and `:path` beside
    /// `:authority`, and the `:protocol` field that says so is not in a capture.
    /// So an absolute-form CONNECT target is a conforming extended CONNECT and
    /// a malformed basic one, with nothing to choose between them. Every one of
    /// these was reported as "must not include a path" before this audit — the
    /// WebSocket-over-HTTP/2 bootstrap among them.
    #[rstest]
    #[case("https://example.com/ws")]
    #[case("http://example.com/ws")]
    #[case("https://example.com:8443/chat?room=1")]
    fn an_extended_connect_is_indistinguishable_and_is_accepted(#[case] target: &str) {
        assert_eq!(judge_request("CONNECT", target), None, "{target}");
    }

    /// An origin-form CONNECT target is neither CONNECT: a `:path` with no
    /// `:scheme` and no `:authority`. The `Host` field is the other place the
    /// authority can come from, which is the sibling HTTP/3 rule's reading.
    #[test]
    fn an_origin_form_connect_with_no_authority_anywhere_is_reported() {
        let message = judge_request("CONNECT", "/ws").expect("reported");
        assert!(
            message.contains("carries a path and no authority"),
            "{message}"
        );
    }

    #[test]
    fn an_origin_form_connect_with_a_host_field_is_accepted() {
        let mut tx = h2();
        tx.request.method = "CONNECT".into();
        tx.request.uri = "/ws".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("host", "ex.com")]);
        assert_eq!(judge(&tx), None);
    }

    // --- The reassembled :scheme and :authority ---

    #[test]
    fn a_scheme_that_is_no_scheme_name_is_reported() {
        let message = judge_request("GET", "1http://example.com/").expect("reported");
        assert!(message.contains("not a scheme name"), "{message}");
    }

    #[rstest]
    #[case("https:///p")]
    #[case("https://")]
    #[case("https://?q=1")]
    fn an_absolute_target_with_no_authority_is_reported(#[case] target: &str) {
        let message = judge_request("GET", target).expect("reported");
        assert!(message.contains("then no authority"), "{target}: {message}");
    }

    /// A `://` past the first component delimiter is ordinary query data. The
    /// `contains("://")` this replaced read an authority out of it and reported
    /// an origin-form target for a missing authority it never claimed to have —
    /// the helper's own doc comment names `?next=` as the everyday case.
    #[rstest]
    #[case("/r?next=http:///p")]
    #[case("/r?redirect_uri=https://other.example/cb")]
    #[case("/r#frag://x")]
    fn a_url_inside_a_query_is_not_this_target_s_authority(#[case] target: &str) {
        assert_eq!(judge_request("GET", target), None, "{target}");
    }

    /// The MUST NOT names the two schemes it is about, so a userinfo under any
    /// other scheme is outside it.
    #[rstest]
    #[case("http://user:pass@example.com/p", true)]
    #[case("https://user@example.com/p", true)]
    #[case("HTTPS://user@example.com/p", true)]
    #[case("ftp://user:pass@example.com/p", false)]
    #[case("coap+ws://user@example.com/p", false)]
    fn userinfo_is_reported_for_http_and_https_targets(
        #[case] target: &str,
        #[case] reported: bool,
    ) {
        let message = judge_request("GET", target);
        assert_eq!(
            message.as_deref().is_some_and(|m| m.contains("userinfo")),
            reported,
            "{target}: {message:?}"
        );
    }

    /// Both userinfo findings withhold the password: the finding is about
    /// credentials arriving where a server logs, and a lint report must not be
    /// one more place they are written down in clear (RFC 3986 § 3.2.1). A
    /// userinfo with no secret is shown as written — the same sentence exempts
    /// an empty tail.
    #[test]
    fn userinfo_findings_withhold_the_password() {
        let msg = judge_request("CONNECT", "user:s3cret@example.com:443").expect("reported");
        assert!(msg.contains("'user:...@example.com:443'"), "{msg}");
        assert!(!msg.contains("s3cret"), "{msg}");

        let msg = judge_request("GET", "http://user:s3cret@example.com/p").expect("reported");
        assert!(msg.contains("'user:...@example.com'"), "{msg}");
        assert!(!msg.contains("s3cret"), "{msg}");

        let msg = judge_request("GET", "https://user@example.com/p").expect("reported");
        assert!(msg.contains("'user@example.com'"), "{msg}");
    }

    #[rstest]
    #[case("https://[::1]:8443/p", None)]
    #[case("https://[::1/p", Some("not a host and port"))]
    #[case("https://exa mple.com/p", Some("not a host and port"))]
    #[case("https://example.com:8443/p", None)]
    fn the_reassembled_authority_is_a_host_and_a_port(
        #[case] target: &str,
        #[case] expected: Option<&str>,
    ) {
        let message = judge_request("GET", target);
        match expected {
            None => assert_eq!(message, None, "{target}"),
            Some(sub) => assert!(
                message.as_deref().is_some_and(|m| m.contains(sub)),
                "{target}: {message:?}"
            ),
        }
    }

    // --- Two duplicates surrendered to the rule that owns the target's octets ---

    /// Whitespace and a malformed percent-encoding triplet were reported here
    /// *and* by the rule that reads the whole target on every version. Each case
    /// asserts the duplicate is gone and the owner still reports it.
    #[rstest]
    #[case("/foo bar")]
    #[case("/bad%2G")]
    #[case("/incomplete%2")]
    #[case("/a{b}c")]
    fn the_targets_octets_are_not_this_rules_finding(#[case] target: &str) {
        assert_eq!(judge_request("GET", target), None, "{target}");

        let mut tx = h2();
        tx.request.method = "GET".into();
        tx.request.uri = target.into();
        let owner =
            crate::rules::request_uri_percent_encoding_valid::RequestUriPercentEncodingValid;
        assert!(
            judge_by(&owner, &tx).is_some(),
            "target {target} is reported by nobody"
        );
    }

    // --- The response half ---

    /// The status range is RFC 9110 § 15's, is the same for every HTTP version,
    /// and is `status_code_valid_range`'s finding. Both statuses here
    /// were asserted as violations of *this* rule until the branch was removed —
    /// on HTTP/1.1 responses, which is what the shared fixture builds and what
    /// this then-ungated rule was reporting.
    #[rstest]
    #[case(99)]
    #[case(700)]
    fn out_of_range_status_is_not_this_rules_finding(#[case] status: u16) {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        tx.request.version = "HTTP/2.0".into();
        if let Some(ref mut resp) = tx.response {
            resp.version = "HTTP/2.0".into();
        }
        assert_eq!(judge(&tx), None);

        let owner = crate::rules::status_code_valid_range::StatusCodeValidRange;
        assert!(
            judge_by(&owner, &tx).is_some(),
            "status {status} is reported by nobody"
        );
    }

    // --- Scope, id and config ---

    #[test]
    fn scope_is_both() {
        assert_eq!(
            Http2PseudoHeadersValid.scope(),
            crate::rules::RuleScope::Both
        );
    }

    #[test]
    fn id_returns_correct_value() {
        assert_eq!(Http2PseudoHeadersValid.id(), "http2_pseudo_headers_valid");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "http2_pseudo_headers_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
