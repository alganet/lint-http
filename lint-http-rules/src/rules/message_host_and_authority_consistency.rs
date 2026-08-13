// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{shown_in_finding, trim_ows};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageHostAndAuthorityConsistency;

/// How a `Host` field value and an `:authority` compare — in three answers,
/// because the two documents that state this requirement define the comparison
/// differently and the middle answer is the one they disagree about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Comparison {
    /// The same octets.
    Same,
    /// Different as written, and one authority once each side is put in the
    /// normal form scheme-based normalization gives it.
    NormalizationApart,
    /// Different authorities under any normalization this rule performs.
    Different,
}

impl MessageHostAndAuthorityConsistency {
    /// One authority in the normal form scheme-based normalization gives it.
    ///
    /// RFC 9113 asks for that normalization by name and RFC 9110 § 4.2.3 is
    /// where what it involves for an "http" or "https" URI is written down, so
    /// this function is that list restricted to the one component an authority
    /// is: the host is lower-cased, a percent-encoded octet standing for an
    /// unreserved character is decoded, and a port that is empty or the scheme's
    /// default goes. The list's fourth item — an empty path being equivalent to
    /// `/` — is about a component no authority has.
    ///
    /// What is *not* folded is as cited as what is. The same sentence that makes
    /// the host case-insensitive says every other component is compared with
    /// case, so a userinfo subcomponent is carried through as written: the two
    /// versions forbid one only for "http" and "https" schemes, and `:scheme` is
    /// restricted to neither.
    ///
    /// The port is compared as the number § 3.2.3 says it is — so `:080` names
    /// the port "http" defaults to — but only where every character in it is a
    /// digit, because a value like `+443` parses as a number and derives from no
    /// `port`. An empty port is elided only where the scheme defines a default
    /// to elide it against, which is the last sentence below.
    ///
    /// cite(RFC 9110 § 4.2.3): "If the port is equal to the default port for a scheme, the normal form is to omit the port subcomponent."
    /// cite(RFC 9110 § 4.2.3): "The scheme and host are case-insensitive and normally provided in lowercase; all other components are compared in a case-sensitive manner."
    /// cite(RFC 9110 § 4.2.3): "Characters other than those in the "reserved" set are equivalent to their percent-encoded octets: the normal form is to not encode them (see Sections 2.1 and 2.2 of [URI])."
    /// cite(RFC 3986 § 3.2.3): "The port subcomponent of authority is designated by an optional port number in decimal following the host and delimited from it by a single colon (":") character."
    /// cite(RFC 9110 § 4.2.1): "If the port subcomponent is empty or not given, TCP port 80 (the reserved port for WWW services) is the default."
    /// cite(RFC 9110 § 4.2.2): "If the port subcomponent is empty or not given, TCP port 443 (the reserved port for HTTP over TLS) is the default."
    /// cite(RFC 3986 § 6.2.3): "Normalization should not remove delimiters when their associated component is empty unless licensed to do so by the scheme specification."
    fn normalized(value: &str, scheme: Option<&str>) -> String {
        // Where the userinfo ends is `authority`'s question and not this rule's;
        // the shared reader owns it, and this was the copy that hand-wrote it.
        let (userinfo, host_and_port) = crate::helpers::uri::split_userinfo(value);
        let (host, port) = crate::helpers::uri::split_host_and_port(host_and_port);

        // Only the two schemes RFC 9110 gives a default port to, matched without
        // regard to case because the scheme is case-insensitive by the sentence
        // above. A target in authority-form — a CONNECT — carries no scheme at
        // all, and § 9.3.6 gives that method no default port either, so nothing
        // is elided from one.
        let default_port = match scheme.map(str::to_ascii_lowercase).as_deref() {
            Some("http") => Some(80u32),
            Some("https") => Some(443u32),
            _ => None,
        };

        let mut out = String::with_capacity(value.len());
        if let Some(userinfo) = userinfo {
            out.push_str(userinfo);
            out.push('@');
        }
        out.push_str(&Self::decoded_unreserved(host).to_ascii_lowercase());

        if let Some(port) = port {
            let elided = match default_port {
                None => false,
                Some(default) => {
                    port.is_empty()
                        || (port.bytes().all(|b| b.is_ascii_digit())
                            && port.parse::<u32>().ok() == Some(default))
                }
            };
            if !elided {
                out.push(':');
                out.push_str(port);
            }
        }

        out
    }

    /// The value with every percent-encoded octet that stands for an unreserved
    /// character written as that character, and the hexadecimal of the triplets
    /// that stay in upper case.
    ///
    /// Both halves are one sentence each, and the second is why a triplet this
    /// leaves encoded still ends up in a normal form: the digits of a triplet
    /// are case-insensitive, so `%2F` and `%2f` are one octet.
    ///
    /// cite(RFC 3986 § 6.2.2.2): "These URIs should be normalized by decoding any percent-encoded octet that corresponds to an unreserved character, as described in Section 2.3."
    /// cite(RFC 3986 § 6.2.2.1): "For all URIs, the hexadecimal digits within a percent-encoding triplet (e.g., "%3a" versus "%3A") are case-insensitive and therefore should be normalized to use uppercase letters for the digits A-F."
    /// cite(RFC 3986 § 2.3, label: unreserved): "unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~""
    fn decoded_unreserved(value: &str) -> String {
        // The walk is over `char`s and not over `str::as_bytes`, because the
        // value carries one `char` per octet: an octet at or above %x80 is a
        // single `char` here and two UTF-8 bytes, and a byte walk would take it
        // apart into two octets that were never on the wire. The two characters
        // after a `%` are checked for being hexadecimal before they are read as
        // a number, because `from_str_radix` accepts a leading `+` and no
        // `pct-encoded` does.
        let chars: Vec<char> = value.chars().collect();
        let mut out = String::with_capacity(value.len());
        let mut i = 0;

        while i < chars.len() {
            let triplet = (chars[i] == '%' && i + 2 < chars.len())
                .then(|| {
                    let hex: String = chars[i + 1..i + 3].iter().collect();
                    hex.chars()
                        .all(|c| c.is_ascii_hexdigit())
                        .then(|| u8::from_str_radix(&hex, 16).ok())
                        .flatten()
                })
                .flatten();

            match triplet {
                Some(octet) => {
                    let unreserved =
                        octet.is_ascii_alphanumeric() || matches!(octet, b'-' | b'.' | b'_' | b'~');
                    if unreserved {
                        out.push(octet as char);
                    } else {
                        out.push('%');
                        out.push_str(&format!("{:02X}", octet));
                    }
                    i += 3;
                }
                None => {
                    out.push(chars[i]);
                    i += 1;
                }
            }
        }

        out
    }

    /// Compare the two values as written, and say separately when they are one
    /// authority under the normalization above.
    ///
    /// The exact comparison first is not an optimisation: it is the answer
    /// RFC 9114 asks for, and the caller decides per version whether the middle
    /// answer is a finding.
    fn compare(authority: &str, host: &str, scheme: Option<&str>) -> Comparison {
        if authority == host {
            return Comparison::Same;
        }

        if Self::normalized(authority, scheme) == Self::normalized(host, scheme) {
            return Comparison::NormalizationApart;
        }

        Comparison::Different
    }
}

impl Rule for MessageHostAndAuthorityConsistency {
    fn id(&self) -> &'static str {
        "message_host_and_authority_consistency"
    }

    /// A request-only check: both sentences are about what a request carries,
    /// and the HTTP/2 one names the party. `Client` is the scope that measures a
    /// request whether or not a response was ever captured.
    ///
    /// cite(RFC 9113 § 8.3.1): "Clients MUST NOT generate a request with a Host header field that differs from the ":authority" pseudo-header field."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        // Two fields can only disagree where both exist, and only HTTP/2 and
        // HTTP/3 carry an `:authority`. This is not a narrowing of either
        // sentence: over HTTP/1.1 an absolute-form request-target also holds an
        // authority beside a `Host`, and the sentence about that pair says the
        // recipient ignores the field rather than that the sender was wrong.
        //
        // The major digit is what "in HTTP/2 and HTTP/3" means; `http_version`
        // owns the production that reads it, and a version deriving from no
        // production names no syntax — `message_http_version_syntax_valid`'s
        // finding rather than a third answer here.
        //
        // cite(RFC 9110 § 7.2): "In HTTP/2 [HTTP/2] and HTTP/3 [HTTP/3], the Host header field is, in some cases, supplanted by the ":authority" pseudo-header field of a request's control data."
        // cite(RFC 9112 § 3.2.2): "When an origin server receives a request with an absolute-form of request-target, the origin server MUST ignore the received Host header field (if any) and instead use the host information of the request-target."
        let version = crate::http_version::major(&tx.request.version)?;
        if !matches!(version, 2 | 3) {
            return None;
        }

        // The capture keeps the authority of the request's target URI, which is
        // where the cited sentence says `:authority` came from. **What the two
        // transports put there is not the same thing, and `description()` says
        // so**: over HTTP/2 the recorded authority is the pseudo-header's value
        // and nothing else, while the HTTP/3 library builds the target from the
        // `Host` field when both are present and refuses the request outright
        // when the two differ — so on that version a mismatch this proxy
        // recorded itself cannot exist, and the finding is for captures written
        // elsewhere and read back.
        //
        // A target with no authority is nothing to compare against; whether a
        // request should have carried one is the two pseudo-header rules'
        // question rather than this one's.
        //
        // cite(RFC 9113 § 8.3.1): "The ":authority" pseudo-header field conveys the authority portion (Section 3.2 of [RFC3986]) of the target URI (Section 7.1 of [HTTP])."
        let authority =
            crate::helpers::uri::extract_authority_from_request_target(&tx.request.uri)?;

        // An asterisk-form OPTIONS is unreadable here, and the tell is that `*`
        // is a legal `sub-delim` — so `example.com*` is a `reg-name` and the
        // shared extractor is right not to stop at it. The target is recorded as
        // the string form of a URI rebuilt from the pseudo-headers, and a
        // `:path` of `*` leaves no delimiter between the authority and the path:
        // `https://example.com*` is what both an `OPTIONS *` for that authority
        // and an origin whose name ends in `*` come back as. Measuring it
        // reported the conforming request.
        //
        // The method is matched exactly, because the method token is
        // case-sensitive: a lowercase `options` is a method nothing defines and
        // its request-target is not the asterisk form.
        //
        // cite(RFC 9113 § 8.3.1): "A request in asterisk form (for OPTIONS) includes the value '*' for the ":path" pseudo-header field."
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        // cite(RFC 3986 § 3.2.2, label: reg-name): "reg-name    = *( unreserved / pct-encoded / sub-delims )"
        // cite(RFC 3986 § 2.2, label: sub-delims): "sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=""
        if tx.request.method == "OPTIONS" && authority.ends_with('*') {
            return None;
        }

        // `Host` is not a list field, so two field lines of it are not one value
        // and there is no way to pick the one the sender meant: the message is
        // `client_host_header`'s finding, and an authority that is unknown is a
        // different thing from one that disagrees. No line at all is the other
        // half of § 4.3.1's either-or, and equally nothing to compare.
        //
        // cite(RFC 9114 § 4.3.1): "If the :scheme pseudo-header field identifies a scheme that has a mandatory authority component (including "http" and "https"), the request MUST contain either an :authority pseudo-header field or a Host header field."
        // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
        let mut host_lines = tx.request.headers.get_all("host").iter();
        let (Some(_), None) = (host_lines.next(), host_lines.next()) else {
            return None;
        };

        // Every octet of that one field line as the `char` of the same value.
        // `to_str` refuses every octet outside visible US-ASCII, and the branch
        // under it announced a value "not valid UTF-8" — a claim about an
        // encoding, where an octet at or above %x80 is `obs-text`, which no
        // `uri-host` alternative admits and which is therefore a `Host` that
        // cannot be the `:authority` this request also carried. Folding it into
        // "no Host here" dropped the comparison entirely.
        //
        // The shared reader is the one that owns the octet-per-`char` walk, and
        // calling it here is exact rather than approximate *because* of the gate
        // above: with one field line in the section there is nothing for its
        // join to join, and `Host` is not a field whose lines may be combined.
        let value =
            crate::helpers::headers::combined_field_value_as_written(&tx.request.headers, "host")?;

        // `OWS` is SP and HTAB and nothing else, and `str::trim` is Unicode
        // whitespace: on a value read one `char` per octet, U+00A0 is the octet
        // %xA0, which is `obs-text` rather than whitespace of any kind. Trimming
        // it would turn a `Host` no production generates into one that matches.
        //
        // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace.  When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value."
        let host = trim_ows(&value);

        // Every gate above ends the rule, and a request carrying both fields is
        // the only one this can report; `parse_rule_config` is several map
        // probes plus a hash over the rule id.
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let violation = |message: String| {
            Some(Violation {
                rule: self.id().to_string(),
                severity: config.severity,
                message,
            })
        };

        // Both fields are present, and one of them names no authority — which
        // is a difference like any other, and is why this branch is about the
        // message rather than about the verdict.
        //
        // Over HTTP/3 there is also a sentence for exactly this, and it is
        // quoted with the sentence that supplies its antecedent, because the
        // antecedent does not always hold: the requirement is stated of a
        // request whose `:scheme` identifies a scheme with a mandatory authority
        // component, and a CONNECT sends no `:scheme` at all. On such a request
        // the finding is the difference, not the emptiness.
        //
        // cite(RFC 9114 § 4.3.1): "If the :scheme pseudo-header field identifies a scheme that has a mandatory authority component (including "http" and "https"), the request MUST contain either an :authority pseudo-header field or a Host header field."
        // cite(RFC 9114 § 4.3.1): "If these fields are present, they MUST NOT be empty."
        if host.is_empty() {
            return violation(format!(
                "The request's Host field value is empty while its ':authority' is '{}': both fields are present and one of them names no authority",
                shown_in_finding(&authority)
            ));
        }

        // The scheme decides which port is the one normalization elides, and it
        // is read from the same recorded target the authority came from. A
        // CONNECT's target is an authority and carries no scheme, which is why
        // this is an `Option` rather than a default.
        let scheme = crate::helpers::uri::scheme_authority_marker(&tx.request.uri)
            .map(|marker| &tx.request.uri[..marker]);

        match Self::compare(&authority, host, scheme) {
            Comparison::Same => None,

            // **The two documents do not define this comparison the same way,
            // and this is the case where they disagree.** RFC 9113 states the
            // requirement and then says the values are compared *normalized*,
            // naming scheme-based normalization as the floor for everyone except
            // an origin server. RFC 9114 asks for the same value and names no
            // normalization at all — the word appears nowhere in that document —
            // and the h3 library on this proxy's own capture path reads it that
            // way too, comparing the two as strings and refusing the request
            // when they differ. So one pair of values is conforming over one
            // version and malformed over the other, and harmonising them would
            // mean choosing which document to stop reading.
            //
            // The normal form is printed because it is the thing the two values
            // have in common, and because it names which of normalization's
            // steps the difference was: a case, a port, a percent-encoding.
            //
            // cite(RFC 9113 § 8.3.1): "The values of fields need to be normalized to compare them (see Section 6.2 of [RFC3986])."
            // cite(RFC 9113 § 8.3.1): "An origin server can apply any normalization method, whereas other servers MUST perform scheme-based normalization (see Section 6.2.3 of [RFC3986]) of the two fields."
            // cite(RFC 9114 § 4.3.1): "If both fields are present, they MUST contain the same value."
            Comparison::NormalizationApart => match version {
                3 => violation(format!(
                    "':authority' '{}' and Host '{}' are one authority only after scheme-based normalization, which puts both in the normal form '{}'. HTTP/3 asks the two fields to contain the same value and names no normalization; the same pair over HTTP/2 is not reported, because that version's requirement is defined over normalized values",
                    shown_in_finding(&authority),
                    shown_in_finding(host),
                    shown_in_finding(&Self::normalized(&authority, scheme))
                )),
                _ => None,
            },

            // The requirement itself. The two documents give it different
            // voices, and the finding uses the one whose document this message
            // was written under: over HTTP/2 a client MUST NOT generate it and a
            // server SHOULD treat it as malformed; over HTTP/3 the two fields
            // MUST contain the same value and a request that omits or invalidly
            // fills a mandatory pseudo-header field is malformed. Saying either
            // in the other's message would put one document's sentences into the
            // other's mouth.
            //
            // cite(RFC 9113 § 8.3.1): "Clients MUST NOT generate a request with a Host header field that differs from the ":authority" pseudo-header field."
            // cite(RFC 9113 § 8.3.1): "A server SHOULD treat a request as malformed if it contains a Host header field that identifies an entity that differs from the entity in the ":authority" pseudo-header field."
            // cite(RFC 9114 § 4.3.1): "If both fields are present, they MUST contain the same value."
            Comparison::Different => violation(format!(
                "':authority' '{}' and Host '{}' name different authorities: {}",
                shown_in_finding(&authority),
                shown_in_finding(host),
                match version {
                    3 => "HTTP/3 asks the two fields to contain the same value, and a recipient that trusts the other one routes this request elsewhere",
                    _ => "a client must not generate a request whose Host field differs from its ':authority', and a server may treat this request as malformed",
                }
            )),
        }
    }

    fn title(&self) -> Option<&'static str> {
        Some("Host and :authority Consistency")
    }

    fn description(&self) -> &'static str {
        "Reports an HTTP/2 or HTTP/3 request whose `Host` header field and `:authority` pseudo-header field do not name the same authority.\n\n**Two documents state this requirement, and neither is a copy of the other.** RFC 9113 §8.3.1: \"Clients MUST NOT generate a request with a Host header field that differs from the \\\":authority\\\" pseudo-header field.\" — followed by what such a message costs: \"A server SHOULD treat a request as malformed if it contains a Host header field that identifies an entity that differs from the entity in the \\\":authority\\\" pseudo-header field.\" RFC 9114 §4.3.1 puts it as a property of the request: \"If both fields are present, they MUST contain the same value.\" A mismatch is a routing disagreement inside one message — whichever field a recipient trusts decides which resource it serves, which is why this shape turns up in request-smuggling and cache-poisoning reports. Each finding is worded from the document that governs the version it was found on.\n\n**The two versions do not define the comparison the same way, and this rule does not harmonise them.** RFC 9113 continues: \"The values of fields need to be normalized to compare them (see Section 6.2 of [RFC3986]). An origin server can apply any normalization method, whereas other servers MUST perform scheme-based normalization (see Section 6.2.3 of [RFC3986]) of the two fields.\" RFC 9114 asks for the same value and names no normalization — the word appears nowhere in that document. So over **HTTP/2** two values that normalization makes one authority are the same value and are not reported, while over **HTTP/3** they are reported, with the finding printing the normal form both share and saying which sentence decided it. A difference no normalization removes is reported on both.\n\n**What scheme-based normalization is here.** RFC 9110 §4.2.3 is where the steps for an \"http\" or \"https\" URI are written down, and this rule performs the three that can apply to an authority: a port equal to the scheme's default is omitted, the host is compared without regard to case, and a percent-encoded octet standing for an unreserved character is decoded (\"Characters other than those in the 'reserved' set are equivalent to their percent-encoded octets\"). The fourth step is about a path component, which an authority does not have. So over HTTP/2 `example.com:443` and `example.com` on an `https` request are one authority, and so are `Example.COM` and `example.com`, and `exam%70le.com` and `example.com`.\n\n**What is never folded.** The same sentence says \"all other components are compared in a case-sensitive manner\", so a userinfo subcomponent is carried through as written. Both versions forbid one in an `:authority` only **for \"http\" and \"https\" schemed URIs**, and both say `:scheme` is not restricted to those two — so an authority under another scheme may carry userinfo, and its case is part of it. Where a userinfo does appear under `http` or `https`, `message_http2_pseudo_headers_validity` reports it; the HTTP/3 pseudo-header rule does not check it today.\n\n**An empty `Host` beside an `:authority`** is a difference like any other and is reported on both versions. RFC 9114 §4.3.1 also states it outright — \"If these fields are present, they MUST NOT be empty\" — though that sentence's antecedent is a request whose `:scheme` identifies a scheme with a mandatory authority component, which a CONNECT does not send.\n\n**Not reported, because the two fields are not both there.** A request whose target carries no authority is nothing to compare against, and whether it should have carried one is a question about the pseudo-header itself — `message_http2_pseudo_headers_validity` and `message_http3_pseudo_headers_validity` own it. A request with no `Host` field is the other half of §4.3.1's either-or and is `client_host_header`'s question. A request with **two** `Host` field lines names no single authority: `Host` is not a list field, so RFC 9110 §5.3 forbids the repetition and `client_host_header` reports the message.\n\n**Not reported: an asterisk-form OPTIONS.** The capture records the target as the string form of a URI rebuilt from the pseudo-headers, and a `:path` of `*` leaves no delimiter before it — `https://example.com*` is what both an `OPTIONS *` for `example.com` and an origin whose name ends in `*` come back as, since `*` is a `sub-delims` character a `reg-name` admits. An `OPTIONS` whose recorded authority ends in `*` is therefore left alone rather than reported for a difference the capture invented.\n\n**Not reported: whether either value is a well-formed authority.** `Host = uri-host [ \":\" port ]` is `client_host_header`'s check, and the `:authority`'s shape — its userinfo, and the port a CONNECT must name — belongs to the pseudo-header rule for each version. This rule asks only whether the two agree, so two values that are equally malformed agree and are silent here.\n\n**Scope and version.** Only HTTP/2 and HTTP/3 requests are measured, because only they have an `:authority` (RFC 9110 §7.2). That is not a narrowing of the requirement: over HTTP/1.1 an absolute-form request-target carries an authority beside a `Host` too, and RFC 9112 §3.2.2 answers that pair the other way round — \"the origin server MUST ignore the received Host header field (if any) and instead use the host information of the request-target\", with a proxy told to replace it. There the disagreement is a recipient's to resolve, not a sender's defect.\n\n**Where the values come from, and what that costs on HTTP/3.** A capture records the request target as the URI these versions reassemble. Over HTTP/2 the authority in it is the `:authority` and nothing else — the library this proxy uses builds it from that pseudo-header alone and never reads `Host`. **Over HTTP/3 it is not**: that library takes the authority from the `Host` field when both are present, and rejects the request at the transport when the two differ as strings. So no HTTP/3 mismatch this proxy captured itself can reach this rule, and its HTTP/3 findings are for captures written by other tools and read back through `lint` — while the same transport's byte comparison is itself a reading of RFC 9114's \"same value\" that agrees with this rule's. The `Host` field is read as octets rather than through a UTF-8 decode, so a value carrying `obs-text` is compared rather than skipped."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1",
                note: "HTTP/2's half: the client's MUST NOT, the server's SHOULD-treat-as-malformed, and the two sentences that define the comparison over *normalized* values — which is why a default or empty port is not a difference on this version",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1",
                note: "HTTP/3's half: both fields present MUST contain the same value and MUST NOT be empty, with no normalization named anywhere in the document — the sentence that makes one pair of values conforming over HTTP/2 and malformed here",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("4.2.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.3",
                note: "What scheme-based normalization involves for an \"http\" or \"https\" URI — the default port, the case of the host, the percent-encoded unreserved character, and the sentence that keeps every other component case-sensitive",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("6.2.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2.1",
                note: "Case normalization — including the hexadecimal digits of a percent-encoding triplet, which is why a triplet that stays encoded is still put in one form",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("6.2.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2.2",
                note: "Percent-encoding normalization — decode any triplet standing for an unreserved character",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("6.2.3"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.3",
                note: "Scheme-based normalization, and the sentence that keeps an empty delimiter where no scheme licenses removing it — which is why nothing is elided from an authority-form target",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("4.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.1",
                note: "The default port for an \"http\" URI is 80 — one of the two numbers scheme-based normalization needs, and the reason the scheme is read from the recorded target rather than assumed",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("4.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.2",
                note: "The default port for an \"https\" URI is 443",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2",
                note: "Which versions carry the two fields at once: in HTTP/2 and HTTP/3 the `Host` field is supplanted by `:authority`, which is why the rule is gated to those two",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("3.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2",
                note: "Why HTTP/1.1 is not measured: an absolute-form target beside a `Host` is answered by having the recipient ignore the field, not by calling the sender wrong",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The two fields carry one authority"),
                snippet: ":method: GET\n:scheme: https\n:authority: example.com\n:path: /resource\nhost: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "HTTP/2 only — the values are compared normalized, and scheme-based normalization elides an \"https\" default port",
                ),
                snippet: ":method: GET\n:scheme: https\n:authority: example.com:443\n:path: /resource\nhost: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "HTTP/2 only — the host is compared without regard to case, and a triplet standing for an unreserved character is decoded",
                ),
                snippet: ":method: GET\n:scheme: https\n:authority: Example.COM\n:path: /resource\nhost: exam%70le.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "HTTP/3 only — the same default port, where the document asks for the same value and names no normalization",
                ),
                snippet: ":method: GET\n:scheme: https\n:authority: example.com:443\n:path: /resource\nhost: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A CONNECT's authority-form target, matched exactly"),
                snippet: ":method: CONNECT\n:authority: example.com:443\nhost: example.com:443",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Two authorities in one request — the routing disagreement"),
                snippet: ":method: GET\n:scheme: https\n:authority: example.com\n:path: /resource\nhost: other.example",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A port neither scheme defaults to is part of the authority"),
                snippet: ":method: GET\n:scheme: https\n:authority: example.com:8080\n:path: /resource\nhost: example.com:9090",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Both fields present, one of them naming no authority"),
                snippet: ":method: GET\n:scheme: https\n:authority: example.com\n:path: /resource\nhost:",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageHostAndAuthorityConsistency;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Run the rule over a request carrying `uri` as its recorded target and the
    /// given `Host` field lines, at the given HTTP version.
    ///
    /// The lines are appended and given as raw octets: two field lines of a
    /// non-list field is a case the rule stands down on, and a value carrying
    /// `obs-text` is not a string any Rust source file can stand in for.
    fn check(version: &str, uri: &str, host_lines: &[&[u8]]) -> Option<Violation> {
        let rule = MessageHostAndAuthorityConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = version.into();
        tx.request.uri = uri.into();
        tx.request.headers = hyper::HeaderMap::new();
        for line in host_lines {
            tx.request.headers.append(
                hyper::header::HOST,
                hyper::header::HeaderValue::from_bytes(line).unwrap(),
            );
        }

        rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// The same octets are the same authority under either document's reading.
    #[rstest]
    #[case("https://example.com/path", "example.com")]
    #[case("https://example.com:8080/path", "example.com:8080")]
    #[case("https://[::1]:8080/path", "[::1]:8080")]
    #[case("example.com:443", "example.com:443")]
    fn the_same_authority_is_not_reported(#[case] uri: &str, #[case] host: &str) {
        for version in ["HTTP/2.0", "HTTP/3.0"] {
            assert!(
                check(version, uri, &[host.as_bytes()]).is_none(),
                "{} {} / {}",
                version,
                uri,
                host
            );
        }
    }

    /// Different authorities are reported on both versions, in the same words.
    #[rstest]
    #[case("https://example.com/path", "other.com")]
    #[case("https://example.com:8080/path", "example.com:9090")]
    #[case("https://example.com./path", "example.com")]
    #[case("example.com:443", "other.com:443")]
    fn different_authorities_are_reported(#[case] uri: &str, #[case] host: &str) {
        for version in ["HTTP/2.0", "HTTP/3.0"] {
            let violation = check(version, uri, &[host.as_bytes()])
                .unwrap_or_else(|| panic!("{} {} / {}", version, uri, host));
            assert!(
                violation.message.contains("name different authorities"),
                "{}",
                violation.message
            );
        }
    }

    /// **The two documents' comparisons differ, and this is every step where.**
    /// RFC 9113 § 8.3.1 has the values compared after scheme-based
    /// normalization, which RFC 9110 § 4.2.3 spells out for an "http" or "https"
    /// URI; RFC 9114 § 4.3.1 asks for the same value and names no normalization
    /// anywhere.
    #[rstest]
    // The default port for the scheme, in both directions and both schemes.
    #[case("https://example.com:443/path", "example.com")]
    #[case("https://example.com/path", "example.com:443")]
    #[case("http://example.com:80/path", "example.com")]
    // An empty port, where the scheme has a default for it to be empty against.
    #[case("http://example.com/path", "example.com:")]
    // A port number in decimal, so the leading zero names the same port.
    #[case("https://example.com:0443/path", "example.com")]
    // The case of the host, and of a hexadecimal address.
    #[case("https://Example.COM/path", "example.com")]
    #[case("https://[FE80::1]/path", "[fe80::1]")]
    // A triplet standing for an unreserved character, and the case of the
    // digits in one that does not.
    #[case("https://exam%70le.com/path", "example.com")]
    #[case("https://exam%2Fle.com/path", "exam%2fle.com")]
    fn a_difference_normalization_removes_is_reported_over_http3_only(
        #[case] uri: &str,
        #[case] host: &str,
    ) {
        assert!(
            check("HTTP/2.0", uri, &[host.as_bytes()]).is_none(),
            "HTTP/2 compares the values normalized: {} / {}",
            uri,
            host
        );

        let violation = check("HTTP/3.0", uri, &[host.as_bytes()])
            .expect("HTTP/3 asks the two fields to contain the same value");
        assert!(
            violation
                .message
                .contains("one authority only after scheme-based normalization"),
            "{}",
            violation.message
        );
    }

    /// The elision is of the *scheme's* default and not of a number: an "http"
    /// target naming 443, or a target whose scheme defines no default, keeps its
    /// port — and so does a port that is not a number at all.
    #[rstest]
    #[case("http://example.com:443/path", "example.com")]
    #[case("https://example.com:80/path", "example.com")]
    // `+443` parses as a number and derives from no `port`, so it is not the
    // scheme's default written another way.
    #[case("https://example.com/path", "example.com:+443")]
    // A CONNECT's target is an authority and carries no scheme, so nothing says
    // which port could be elided — and § 9.3.6 gives the method no default. An
    // empty port goes the same way: no scheme licenses removing the delimiter.
    #[case("example.com:443", "example.com")]
    #[case("example.com:443", "example.com:")]
    fn a_port_no_scheme_defaults_to_is_part_of_the_authority(
        #[case] uri: &str,
        #[case] host: &str,
    ) {
        for version in ["HTTP/2.0", "HTTP/3.0"] {
            let violation = check(version, uri, &[host.as_bytes()])
                .unwrap_or_else(|| panic!("{} {} / {}", version, uri, host));
            assert!(
                violation.message.contains("name different authorities"),
                "{}",
                violation.message
            );
        }
    }

    /// Both fields present and one of them naming no authority. RFC 9114
    /// § 4.3.1 says so outright; over HTTP/2 an empty value differs from the
    /// authority the target carried.
    #[rstest]
    #[case(b"")]
    #[case(b" ")]
    #[case(b"\t ")]
    fn an_empty_host_beside_an_authority_is_reported(#[case] host: &[u8]) {
        for version in ["HTTP/2.0", "HTTP/3.0"] {
            let violation = check(version, "https://example.com/path", &[host])
                .expect("both fields are present");
            assert!(
                violation.message.contains("names no authority"),
                "{}",
                violation.message
            );
        }
    }

    /// `str::trim` is Unicode whitespace, and on a value read one `char` per
    /// octet %xA0 is `obs-text` rather than a space. Trimming it would turn a
    /// `Host` no `uri-host` generates into one that matches the `:authority`.
    #[test]
    fn obs_text_is_compared_rather_than_trimmed_or_skipped() {
        let violation = check(
            "HTTP/2.0",
            "https://example.com/path",
            &[b"example.com\xA0"],
        )
        .expect("an octet no uri-host admits is not whitespace");
        assert!(
            violation.message.contains("name different authorities"),
            "{}",
            violation.message
        );

        // And the finding does not carry a raw control octet into the message.
        let control = check("HTTP/2.0", "https://example.com/path", &[b"exam\tple.com"])
            .expect("a control octet inside the value is a different authority");
        assert!(!control.message.contains('\t'), "{}", control.message);
    }

    /// The value is read one `char` per octet, and the percent-decoding walks it
    /// that way: an `obs-text` octet is one `char` and two UTF-8 bytes, so a
    /// byte walk would put two octets into the normal form where the wire had
    /// one. A triplet is also checked for being hexadecimal before it is read as
    /// a number, since `from_str_radix` accepts a leading `+`.
    #[test]
    fn the_normal_form_is_built_from_octets_and_from_hex_digits_only() {
        // Same octet on both sides, differing only in what precedes it, so the
        // comparison has to survive the walk rather than collapse.
        assert!(check("HTTP/2.0", "https://exam%70le.com/p", &[b"example.com"]).is_none());
        let violation = check("HTTP/2.0", "https://example.com/p", &[b"example.com\xA0"])
            .expect("an obs-text octet is not part of this authority");
        assert!(
            violation.message.contains("name different authorities"),
            "{}",
            violation.message
        );

        // The two halves of that, on the function itself, since the octets a
        // wrong walk would produce are ones no `HeaderValue` can carry: `%+A`
        // is not a `pct-encoded` and stays as written, and an `obs-text` octet
        // stays one character.
        assert_eq!(
            MessageHostAndAuthorityConsistency::normalized("exam%+Ale.com", Some("https")),
            "exam%+ale.com"
        );
        assert_eq!(
            MessageHostAndAuthorityConsistency::normalized("exam%70le.com:443", Some("https")),
            "example.com"
        );
        assert_eq!(
            MessageHostAndAuthorityConsistency::normalized("example.com\u{A0}", Some("https"))
                .chars()
                .count(),
            "example.com".len() + 1
        );
    }

    /// `OWS` around the value is not part of it, and both ends are trimmed.
    #[test]
    fn ows_around_the_value_is_not_part_of_it() {
        assert!(check(
            "HTTP/2.0",
            "https://example.com/path",
            &[b"  example.com\t"]
        )
        .is_none());
    }

    /// Nothing to compare: no `Host` line, two `Host` lines, or a target with no
    /// authority in it. Each is a neighbour's finding and none of them is a
    /// disagreement.
    #[test]
    fn a_pair_that_is_not_present_is_not_a_disagreement() {
        assert!(check("HTTP/2.0", "https://example.com/path", &[]).is_none());
        assert!(check(
            "HTTP/2.0",
            "https://example.com/path",
            &[b"example.com", b"other.com"]
        )
        .is_none());
        assert!(check("HTTP/2.0", "/path", &[b"example.com"]).is_none());
        assert!(check("HTTP/2.0", "*", &[b"example.com"]).is_none());
    }

    /// The versions that have no `:authority` are not measured, and the pair
    /// this rule reports is answered there by having the recipient ignore the
    /// field rather than by calling the sender wrong.
    #[rstest]
    #[case("HTTP/1.1")]
    #[case("HTTP/1.0")]
    // A version that derives from no production names no syntax; the rule that
    // reports the value is `message_http_version_syntax_valid`.
    #[case("HTTP/2x")]
    #[case("")]
    fn only_the_versions_with_an_authority_pseudo_header_are_measured(#[case] version: &str) {
        assert!(check(version, "https://example.com/path", &[b"other.com"]).is_none());
    }

    #[test]
    fn scope_is_client_because_the_requirement_is_on_a_request() {
        assert_eq!(
            MessageHostAndAuthorityConsistency.scope(),
            crate::rules::RuleScope::Client
        );
    }

    /// Every published example is a case this rule decides the way its label
    /// claims, on the version its label is about. The snippet is the
    /// pseudo-header form these versions actually carry, plus the `host` field
    /// line.
    #[test]
    fn published_examples_agree_with_the_rule() {
        use crate::rules::Compliance;

        let mut asserted_a_finding = false;

        for example in MessageHostAndAuthorityConsistency.examples() {
            let mut scheme = None;
            let mut authority = None;
            let mut path = None;
            let mut host: Option<&str> = None;

            for line in example.snippet.lines() {
                // Split on the colon that follows the name, not on the one
                // inside `:authority`'s port — and not on `": "`, or the `host:`
                // line with an empty value is dropped and that example silently
                // becomes a request with no `Host` at all.
                let (name, value) = line[1..]
                    .split_once(':')
                    .map(|(n, v)| (&line[..1 + n.len()], v))
                    .expect("every line names a field");
                let value = value.strip_prefix(' ').unwrap_or(value);
                match name {
                    ":scheme" => scheme = Some(value),
                    ":authority" => authority = Some(value),
                    ":path" => path = Some(value),
                    "host" => host = Some(value),
                    _ => {}
                }
            }

            // The capture records the target these versions reassemble.
            let uri = match (scheme, authority, path) {
                (Some(s), Some(a), Some(p)) => format!("{}://{}{}", s, a, p),
                (None, Some(a), None) => a.to_string(),
                _ => panic!("example carries no target: {}", example.snippet),
            };
            let host = host.expect("every example carries a host line");

            // An example about the versions' disagreement says so in its label
            // and is asserted on that version alone; every other example is
            // asserted on both. The marker is exact rather than a substring
            // search for a version name, so a label that merely mentions a
            // version cannot silently halve its own coverage.
            let versions: &[&str] = match example.label {
                Some(l) if l.starts_with("HTTP/2 only") => &["HTTP/2.0"],
                Some(l) if l.starts_with("HTTP/3 only") => &["HTTP/3.0"],
                _ => &["HTTP/2.0", "HTTP/3.0"],
            };

            for version in versions {
                let violation = check(version, &uri, &[host.as_bytes()]);
                match example.compliance {
                    Compliance::Compliant => assert!(
                        violation.is_none(),
                        "compliant example reported on {}: {} -> {:?}",
                        version,
                        example.snippet,
                        violation
                    ),
                    Compliance::NonCompliant => {
                        assert!(
                            violation.is_some(),
                            "non-compliant example not reported on {}: {}",
                            version,
                            example.snippet
                        );
                        asserted_a_finding = true;
                    }
                }
            }
        }

        assert!(
            asserted_a_finding,
            "the guard is vacuous unless at least one example produces a finding"
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_host_and_authority_consistency");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
